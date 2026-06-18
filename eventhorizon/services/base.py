"""Base class for all tarpit services.

Centralises the parts every service shares:
  * asyncio server setup / teardown
  * per-connection :class:`Session` creation + structured logging
  * an OpenTelemetry span per session (no-op if OTel absent)
  * the **tarpit drip** primitive (slow byte-by-byte writes)
  * the **bio-inspired adaptive latency** hook
  * hard resource caps so the tarpit can never exhaust the host:
        - global concurrent-connection semaphore
        - per-session wall-clock cap
        - per-session bytes-read cap

Subclasses implement :meth:`handle` which receives a :class:`ConnectionContext`
and drives the fake protocol conversation using ``ctx.drip_line`` /
``ctx.read`` helpers.

SAFETY: attacker bytes are only ever logged, measured, and pattern-matched for
*emulation* purposes. They are never passed to a shell, eval, or subprocess.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Optional

from ..adaptive import AdaptiveLatency, AdaptiveState
from ..config import TarpitConfig
from ..session import Session, SessionLogger
from ..telemetry import Telemetry


@dataclass
class ConnectionContext:
    """Everything a service handler needs for one connection."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    session: Session
    config: TarpitConfig
    logger: SessionLogger
    span: object  # OTel span or _NoopSpan
    adaptive: AdaptiveLatency
    adaptive_state: AdaptiveState
    deadline: float  # loop.time() value after which the session is reaped

    def time_left(self) -> float:
        # get_running_loop() is correct inside a coroutine and is not deprecated
        # (get_event_loop() is deprecated in 3.12+ when called this way).
        return self.deadline - asyncio.get_running_loop().time()

    async def drip(self, data: bytes) -> None:
        """Write ``data`` to the attacker slowly, chunk by chunk.

        The delay between chunks is the configured base delay multiplied by the
        bio-inspired adaptive factor for this session. This is the core tarpit
        behaviour: it holds the connection open and wastes attacker time.
        """
        cfg = self.config
        chunk = max(1, cfg.drip_chunk)
        for i in range(0, len(data), chunk):
            if self.writer.is_closing():
                break
            if self.time_left() <= 0:
                break
            piece = data[i : i + chunk]
            delay = self.adaptive.delay_for(cfg.drip_delay, self.adaptive_state)
            ev = self.session.record_drip(len(piece), delay)
            self.logger.log_event(self.session, ev)
            try:
                self.span.add_event(
                    "drip", {"bytes": len(piece), "delay": round(delay, 4)}
                )
            except Exception:
                pass
            try:
                self.writer.write(piece)
                await self.writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                break
            await asyncio.sleep(delay)

    async def drip_line(self, text: str) -> None:
        """Convenience: drip a text line with CRLF terminator."""
        await self.drip(text.encode("utf-8", "replace") + b"\r\n")

    async def read(self, limit: int = 1024) -> bytes:
        """Read attacker bytes with idle-timeout + byte-cap enforcement.

        Returns b"" on EOF, timeout, or when the per-session byte cap is hit.
        Updates the adaptive state so persistence makes future drips slower.
        """
        cfg = self.config
        remaining_bytes = cfg.max_session_bytes - self.session.bytes_received
        if remaining_bytes <= 0:
            ev = self.session.add_event("limit", reason="max_session_bytes")
            self.logger.log_event(self.session, ev)
            return b""

        timeout = min(cfg.idle_timeout, max(0.0, self.time_left()))
        if timeout <= 0:
            return b""
        try:
            data = await asyncio.wait_for(
                self.reader.read(min(limit, remaining_bytes)), timeout=timeout
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return b""
        except ConnectionError:
            return b""
        if not data:
            return b""

        ev = self.session.record_recv(data)
        self.logger.log_event(self.session, ev)
        try:
            self.span.add_event("recv", {"bytes": len(data)})
        except Exception:
            pass
        # Feed the immune-system signals.
        self.adaptive_state.observe(
            nbytes=len(data),
            interaction=True,
            age=self.session.duration,
        )
        return data


class BaseTarpitService:
    """Common asyncio server scaffolding for a tarpit service."""

    name: str = "base"

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
        self._sem = connection_semaphore
        self._server: Optional[asyncio.AbstractServer] = None
        # active_sessions is only mutated from the single asyncio event-loop
        # thread (no awaits between the read-modify-write below), so a plain
        # dict is race-free here.
        self.active_sessions: dict[str, Session] = {}

    @property
    def port(self) -> int:  # overridden per service
        raise NotImplementedError

    async def handle(self, ctx: ConnectionContext) -> None:
        """Subclasses implement the fake protocol conversation."""
        raise NotImplementedError

    async def start(self) -> asyncio.AbstractServer:
        self._server = await asyncio.start_server(
            self._on_connect, host=self.config.host, port=self.port
        )
        return self._server

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        src_ip, src_port = (peer[0], peer[1]) if len(peer) >= 2 else ("?", 0)

        # Global host-protection: refuse immediately if we are already at the
        # concurrent-connection cap. ``locked()`` is True exactly when the
        # semaphore's value has reached 0, i.e. ``max_connections`` are in
        # flight. We refuse rather than queue so a flood can never make us hold
        # an unbounded backlog of half-open sockets (slow-loris protection).
        acquired = False
        if self._sem is not None:
            if self._sem.locked():
                with contextlib.suppress(Exception):
                    writer.close()
                return
            # Not locked => a permit is available right now; acquire is immediate
            # and will not block (single-threaded event loop, no await gap above).
            await self._sem.acquire()
            acquired = True

        session = Session(service=self.name, src_ip=str(src_ip), src_port=int(src_port))
        self.active_sessions[session.session_id] = session
        if self.logger.metrics is not None:
            self.logger.metrics.session_opened(self.name)
        open_ev = session.add_event("open")
        self.logger.log_event(session, open_ev)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.config.max_session_seconds

        with self.telemetry.session_span(
            self.name, session.src_ip, session.src_port, session.session_id
        ) as span:
            ctx = ConnectionContext(
                reader=reader,
                writer=writer,
                session=session,
                config=self.config,
                logger=self.logger,
                span=span,
                adaptive=AdaptiveLatency(
                    enabled=self.config.adaptive_enabled,
                    max_multiplier=self.config.adaptive_max_multiplier,
                ),
                adaptive_state=AdaptiveState(),
                deadline=deadline,
            )
            try:
                await asyncio.wait_for(
                    self.handle(ctx), timeout=self.config.max_session_seconds + 5
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                ev = session.add_event("limit", reason="max_session_seconds")
                self.logger.log_event(session, ev)
            except ConnectionError:
                pass
            except Exception as exc:  # never let one connection kill the server
                ev = session.add_event("error", error=type(exc).__name__)
                self.logger.log_event(session, ev)
                try:
                    span.record_exception(exc)
                except Exception:
                    pass
            finally:
                from time import time as _wall_clock

                session.ended_at = _wall_clock()
                close_ev = session.add_event("close")
                self.logger.log_event(session, close_ev)
                self.logger.log_session(session)
                self.active_sessions.pop(session.session_id, None)
                if self.logger.metrics is not None:
                    self.logger.metrics.session_closed()
                with contextlib.suppress(Exception):
                    writer.close()
                if acquired and self._sem is not None:
                    self._sem.release()
