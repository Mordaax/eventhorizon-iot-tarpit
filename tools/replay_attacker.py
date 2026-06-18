#!/usr/bin/env python3
"""Replayable lab traffic generator.

Simulates several attacker sessions against the running tarpit so you can test
and demo it without real malware. It opens connections to each service, sends
benign-but-attacker-shaped probes, reads whatever the tarpit dribbles back, and
reports timing so you can *see* the tarpit slowing the attacker down.

This is a CLIENT only. It connects to localhost by default and sends harmless
canned payloads. It does not exploit anything.

Usage::

    python tools/replay_attacker.py --host 127.0.0.1 \
        --telnet-port 2323 --http-port 8080 --ssh-port 2222 \
        --duration 4
"""

from __future__ import annotations

import argparse
import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class SessionResult:
    name: str
    bytes_received: int = 0
    elapsed: float = 0.0
    error: str = ""
    sample: str = ""
    events: list[str] = field(default_factory=list)


async def _drain_for(
    reader: asyncio.StreamReader, max_seconds: float, max_bytes: int = 8192
) -> bytes:
    """Read whatever drips in for up to max_seconds."""
    deadline = time.monotonic() + max_seconds
    out = bytearray()
    while time.monotonic() < deadline and len(out) < max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(256), timeout=remaining)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


async def attack_telnet(host: str, port: int, duration: float) -> SessionResult:
    res = SessionResult(name="telnet")
    start = time.monotonic()
    try:
        reader, writer = await asyncio.open_connection(host, port)
        await _drain_for(reader, duration / 2)
        # Mirai-style default creds.
        for user, pw in (("root", "xc3511"), ("admin", "admin")):
            writer.write((user + "\n").encode())
            await writer.drain()
            await _drain_for(reader, 0.5)
            writer.write((pw + "\n").encode())
            await writer.drain()
            data = await _drain_for(reader, duration / 2)
            res.bytes_received += len(data)
            res.sample = data.decode("latin-1", "replace")[:80]
        writer.close()
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
    res.elapsed = time.monotonic() - start
    return res


async def attack_http(host: str, port: int, duration: float) -> SessionResult:
    res = SessionResult(name="http")
    start = time.monotonic()
    try:
        reader, writer = await asyncio.open_connection(host, port)
        # A classic router-admin probe.
        req = (
            "GET /login.cgi HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Hello-World/scanner\r\n"
            "\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        data = await _drain_for(reader, duration)
        res.bytes_received = len(data)
        res.sample = data.decode("latin-1", "replace")[:80]
        writer.close()
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
    res.elapsed = time.monotonic() - start
    return res


async def attack_http_soap(host: str, port: int, duration: float) -> SessionResult:
    res = SessionResult(name="http-soap")
    start = time.monotonic()
    try:
        reader, writer = await asyncio.open_connection(host, port)
        body = (
            "<?xml version=\"1.0\"?><s:Envelope><s:Body>"
            "<u:GetExternalIPAddress/></s:Body></s:Envelope>"
        )
        req = (
            "POST /upnp/control/WANIPConn1 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n"
            "Content-Type: text/xml\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n" + body
        )
        writer.write(req.encode())
        await writer.drain()
        data = await _drain_for(reader, duration)
        res.bytes_received = len(data)
        res.sample = data.decode("latin-1", "replace")[:80]
        writer.close()
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
    res.elapsed = time.monotonic() - start
    return res


async def attack_ssh(host: str, port: int, duration: float) -> SessionResult:
    res = SessionResult(name="ssh")
    start = time.monotonic()
    try:
        reader, writer = await asyncio.open_connection(host, port)
        # A real client sends its own ident; we mimic that, then wait for banner.
        writer.write(b"SSH-2.0-libssh2_1.9.0\r\n")
        await writer.drain()
        data = await _drain_for(reader, duration)
        res.bytes_received = len(data)
        res.sample = data.decode("latin-1", "replace")[:80]
        writer.close()
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
    res.elapsed = time.monotonic() - start
    return res


class _SsdpClientProtocol(asyncio.DatagramProtocol):
    """Tiny UDP client protocol that captures the first SSDP reply."""

    def __init__(self) -> None:
        self.future: asyncio.Future = asyncio.get_event_loop().create_future()

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        if not self.future.done():
            self.future.set_exception(exc)


async def attack_ssdp(host: str, port: int, duration: float) -> SessionResult:
    """Send a Mirai-style SSDP M-SEARCH discovery probe (UDP) and read the reply."""
    res = SessionResult(name="ssdp")
    start = time.monotonic()
    transport = None
    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            _SsdpClientProtocol, remote_addr=(host, port)
        )
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {host}:{port}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        ).encode()
        transport.sendto(msearch)
        try:
            data = await asyncio.wait_for(protocol.future, timeout=max(1.0, duration))
        except asyncio.TimeoutError:
            data = b""
        res.bytes_received = len(data)
        res.sample = data.decode("latin-1", "replace")[:80]
    except Exception as exc:  # noqa: BLE001
        res.error = f"{type(exc).__name__}: {exc}"
    finally:
        if transport is not None:
            transport.close()
    res.elapsed = time.monotonic() - start
    return res


async def run_all(args: argparse.Namespace) -> list[SessionResult]:
    tasks = [
        attack_telnet(args.host, args.telnet_port, args.duration),
        attack_http(args.host, args.http_port, args.duration),
        attack_http_soap(args.host, args.http_port, args.duration),
        attack_ssh(args.host, args.ssh_port, args.duration),
        attack_ssdp(args.host, args.ssdp_port, args.duration),
    ]
    return list(await asyncio.gather(*tasks))


def main() -> int:
    p = argparse.ArgumentParser(description="EventHorizon replay attacker (client).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--telnet-port", type=int, default=2323)
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--ssh-port", type=int, default=2222)
    p.add_argument("--ssdp-port", type=int, default=1900)
    p.add_argument(
        "--duration",
        type=float,
        default=4.0,
        help="approx seconds to spend draining drip per session",
    )
    args = p.parse_args()

    print(f"[replay] attacking {args.host} for ~{args.duration}s per service\n")
    results = asyncio.run(run_all(args))

    print(f"{'service':<12}{'elapsed(s)':>12}{'bytes':>10}  sample / error")
    print("-" * 72)
    total_elapsed = 0.0
    for r in results:
        total_elapsed = max(total_elapsed, r.elapsed)
        info = r.error if r.error else repr(r.sample)
        print(f"{r.name:<12}{r.elapsed:>12.2f}{r.bytes_received:>10}  {info}")
    print("-" * 72)
    print(f"wall time (concurrent): ~{total_elapsed:.2f}s")
    print(
        "\nNOTE: the elapsed time per service reflects the tarpit dripping "
        "responses slowly\n      (that is the point: the attacker is held / "
        "slowed)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
