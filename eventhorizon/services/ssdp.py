"""Fake SSDP / UPnP discovery tarpit (UDP, port 1900).

Mirai-style scanners and IoT-discovery tools blast ``M-SEARCH`` multicast/unicast
datagrams to UDP/1900 looking for UPnP devices (routers, cameras, media servers)
they can fingerprint and exploit. This service answers those probes with a
*believable but entirely fake* device descriptor and logs the probe as
threat-intel.

Why this is shaped differently from the TCP tarpits:

* SSDP is **connectionless UDP**. There is no long-lived socket to "drip" bytes
  into, so the slow-drip primitive does not apply. Instead each ``M-SEARCH``
  datagram becomes a short, self-contained :class:`Session` that flows through
  the *same* logger / metrics / telemetry as the TCP services.
* We add a small, bounded ``response_delay`` before replying — a mild tarpit
  effect that slows aggressive scanners and lets us throttle a flood — and we
  rate-limit per source so a single host cannot make us amplify traffic.

SAFETY: the datagram payload is only logged and string-matched. We never parse a
``Location:`` header and fetch it, never act on a ``ST:`` (search target), and
the descriptor URL we advertise points at *our own* fake HTTP tarpit, never at
an attacker-controlled host. No outbound connections are ever made.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from typing import Optional

from ..config import TarpitConfig
from ..session import Session, SessionLogger
from ..telemetry import Telemetry

# A canned, fake UPnP root-device descriptor location + server banner. The
# advertised descriptor URL points back at our own HTTP tarpit so a follow-up
# GET is *also* held in the tarpit. None of this is attacker-controlled.
_FAKE_SERVER = "Linux/3.14 UPnP/1.0 IoT-Cam/1.0"
_FAKE_USN = "uuid:2f402f80-da50-11e1-9b23-00178843bced::upnp:rootdevice"


def _msearch_response(http_host: str, http_port: int) -> bytes:
    """Build a fake SSDP HTTP/1.1 200 OK M-SEARCH reply."""
    location = f"http://{http_host}:{http_port}/rootDesc.xml"
    return (
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=120\r\n"
        "EXT:\r\n"
        f"LOCATION: {location}\r\n"
        f"SERVER: {_FAKE_SERVER}\r\n"
        "ST: upnp:rootdevice\r\n"
        f"USN: {_FAKE_USN}\r\n"
        "\r\n"
    ).encode("ascii", "replace")


def _extract_st(payload: bytes) -> str:
    """Pull the (inert) ST: search-target header out of an M-SEARCH, if present."""
    try:
        for line in payload.split(b"\r\n"):
            if line[:3].upper() == b"ST:":
                return line[3:].decode("latin-1", "replace").strip()[:128]
    except Exception:
        pass
    return ""


def _is_msearch(payload: bytes) -> bool:
    return payload[:8].upper().startswith(b"M-SEARCH")


class _SsdpProtocol(asyncio.DatagramProtocol):
    """asyncio datagram protocol that logs probes and replies to M-SEARCH."""

    def __init__(self, service: "SsdpTarpit"):
        self._service = service
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        # Defensive: addr may be a 2- or 4-tuple depending on family.
        src_ip = str(addr[0]) if addr else "?"
        src_port = int(addr[1]) if addr and len(addr) >= 2 else 0
        # Schedule async handling so a slow reply never blocks the datagram loop.
        asyncio.ensure_future(
            self._service._handle_datagram(self.transport, data, src_ip, src_port)
        )


class SsdpTarpit:
    """Fake SSDP/UPnP discovery responder.

    Mirrors the constructor signature of :class:`BaseTarpitService` so the
    orchestrator can treat it uniformly, but it runs over a UDP datagram
    endpoint instead of an asyncio stream server.
    """

    name = "ssdp"

    # Per-source rate limit: do not answer more than this many probes/sec from a
    # single source. Prevents us being used as a UDP amplifier and bounds work
    # under a flood. Probes over the limit are still *logged* but not answered.
    _RATE_LIMIT_PER_SEC = 5
    # Bounded LRU-ish memory of recent senders (size cap = anti-exhaustion).
    _RATE_TABLE_MAX = 4096

    def __init__(
        self,
        config: TarpitConfig,
        logger: SessionLogger,
        telemetry: Telemetry,
        connection_semaphore: Optional[asyncio.Semaphore] = None,
    ):
        self.config = config
        self.logger = logger
        self.telemetry = telemetry
        self._sem = connection_semaphore  # unused for UDP; kept for symmetry
        self._transport: Optional[asyncio.DatagramTransport] = None
        # source-ip -> (window_start_monotonic, count)
        self._rate: dict[str, tuple[float, int]] = {}
        # Small bounded reply delay (mild UDP tarpit), derived from drip_delay
        # but capped so we never hold the datagram path open too long.
        self.response_delay = min(0.5, max(0.0, config.drip_delay * 4))

    @property
    def port(self) -> int:
        return self.config.ssdp_port

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _SsdpProtocol(self),
            local_addr=(self.config.host, self.port),
            reuse_port=False,
        )
        self._transport = transport  # type: ignore[assignment]
        return transport

    async def stop(self) -> None:
        if self._transport is not None:
            with contextlib.suppress(Exception):
                self._transport.close()

    def _allow(self, src_ip: str) -> bool:
        """Token-bucket-ish per-second rate check; True if we may reply."""
        now = time.monotonic()
        # Bound table size: if it grows too large, drop it wholesale (cheap,
        # rare, and prevents unbounded memory from spoofed-source floods).
        if len(self._rate) > self._RATE_TABLE_MAX:
            self._rate.clear()
        window_start, count = self._rate.get(src_ip, (now, 0))
        if now - window_start >= 1.0:
            window_start, count = now, 0
        count += 1
        self._rate[src_ip] = (window_start, count)
        return count <= self._RATE_LIMIT_PER_SEC

    async def _handle_datagram(
        self,
        transport: Optional[asyncio.DatagramTransport],
        data: bytes,
        src_ip: str,
        src_port: int,
    ) -> None:
        """Log one probe as a short Session and (rate-permitting) reply."""
        session = Session(service=self.name, src_ip=src_ip, src_port=src_port)
        if self.logger.metrics is not None:
            self.logger.metrics.session_opened(self.name)
        try:
            self.logger.log_event(session, session.add_event("open"))

            # Record the inert probe payload (bounded preview, never executed).
            recv_ev = session.record_recv(data[: self.config.max_session_bytes])
            self.logger.log_event(session, recv_ev)

            is_search = _is_msearch(data)
            st = _extract_st(data) if is_search else ""
            cmd = ("M-SEARCH ST=" + st) if is_search else "ssdp_other"
            self.logger.log_event(session, session.record_command(cmd))

            with self.telemetry.session_span(
                self.name, src_ip, src_port, session.session_id
            ) as span:
                try:
                    span.add_event("ssdp_probe", {"m_search": is_search, "st": st})
                except Exception:
                    pass

                if is_search and transport is not None:
                    if not self._allow(src_ip):
                        self.logger.log_event(
                            session, session.add_event("limit", reason="rate_limit")
                        )
                    else:
                        # Mild tarpit delay before answering the scanner.
                        if self.response_delay > 0:
                            await asyncio.sleep(self.response_delay)
                        reply = _msearch_response(self.config.host, self.config.http_port)
                        with contextlib.suppress(Exception):
                            transport.sendto(reply, (src_ip, src_port))
                        drip_ev = session.record_drip(len(reply), self.response_delay)
                        self.logger.log_event(session, drip_ev)
        except Exception as exc:  # never let one datagram kill the listener
            self.logger.log_event(
                session, session.add_event("error", error=type(exc).__name__)
            )
        finally:
            session.ended_at = time.time()
            self.logger.log_event(session, session.add_event("close"))
            self.logger.log_session(session)
            if self.logger.metrics is not None:
                self.logger.metrics.session_closed()
