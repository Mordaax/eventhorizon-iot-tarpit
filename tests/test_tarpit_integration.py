"""End-to-end tarpit tests over real localhost asyncio sockets.

These assert the core promises:
  * the server holds the connection open and drips bytes slowly (timing),
  * session events are recorded to the structured logger,
  * resource caps (bytes/time) actually bound a session.

No external network, no Docker required.
"""

import asyncio
import io
import json
import time

import pytest

from eventhorizon.config import TarpitConfig
from eventhorizon.services import HttpTarpit, SshTarpit, TelnetTarpit
from eventhorizon.session import SessionLogger
from eventhorizon.telemetry import Telemetry


def make_config(**overrides) -> TarpitConfig:
    cfg = TarpitConfig()
    cfg.host = "127.0.0.1"
    cfg.telnet_port = 0  # ephemeral; we read the real port from the server
    cfg.http_port = 0
    cfg.ssh_port = 0
    cfg.drip_delay = 0.02
    cfg.drip_chunk = 1
    cfg.adaptive_enabled = False  # deterministic timing for assertions
    cfg.otel_enabled = False  # tests must not depend on a running collector
    cfg.max_session_seconds = 5.0
    cfg.idle_timeout = 1.0
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


async def _start(service_cls, cfg, logger):
    tel = Telemetry.from_config(cfg)
    svc = service_cls(cfg, logger, tel)
    server = await svc.start()
    host, port = server.sockets[0].getsockname()[:2]
    return svc, server, host, port


def _parse_log(buf: io.StringIO):
    recs = []
    for line in buf.getvalue().splitlines():
        line = line.strip()
        if line:
            recs.append(json.loads(line))
    return recs


@pytest.mark.asyncio
async def test_http_drips_slowly_and_records_session():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf)
    cfg = make_config(drip_delay=0.02, drip_chunk=1)
    svc, server, host, port = await _start(HttpTarpit, cfg, logger)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(b"GET /login.cgi HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()

        start = time.monotonic()
        # Read enough bytes that byte-by-byte dripping must take measurable time.
        data = await asyncio.wait_for(reader.readexactly(40), timeout=5.0)
        elapsed = time.monotonic() - start

        assert data.startswith(b"HTTP/1.1")
        # 40 bytes at >=0.02s/byte ⇒ should take noticeably more than instant.
        # Use a conservative lower bound to avoid flakiness.
        assert elapsed >= 0.15, f"drip too fast: {elapsed:.3f}s for 40 bytes"

        writer.close()
        await asyncio.sleep(0.1)
    finally:
        server.close()
        await server.wait_closed()

    recs = _parse_log(buf)
    kinds = {r.get("kind") for r in recs if r.get("record_type") == "event"}
    assert "open" in kinds
    assert "recv" in kinds
    assert "command" in kinds  # the parsed "GET /login.cgi"
    assert "drip" in kinds
    # A final session summary record must exist.
    sess = [r for r in recs if r.get("record_type") == "session"]
    assert len(sess) == 1
    assert sess[0]["service"] == "http"
    assert sess[0]["bytes_sent"] > 0


@pytest.mark.asyncio
async def test_telnet_never_authenticates_and_logs_credentials():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf)
    cfg = make_config(drip_delay=0.005)
    svc, server, host, port = await _start(TelnetTarpit, cfg, logger)

    async def read_until(reader, needle: bytes, timeout: float) -> bytes:
        """Accumulate dripped bytes until ``needle`` appears or timeout."""
        collected = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                chunk = await asyncio.wait_for(reader.read(64), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            collected.extend(chunk)
            if needle in collected.lower():
                break
        return bytes(collected)

    try:
        reader, writer = await asyncio.open_connection(host, port)
        # Wait for the "login:" prompt (banner is dripped slowly).
        banner = await read_until(reader, b"login:", timeout=8.0)
        assert b"login:" in banner.lower()
        writer.write(b"root\n")
        await writer.drain()

        # Wait for the password prompt before sending the password.
        pw_prompt = await read_until(reader, b"password:", timeout=8.0)
        assert b"password:" in pw_prompt.lower()
        writer.write(b"xc3511\n")
        await writer.drain()

        # The tarpit must reject and never hand out a shell.
        rejection = await read_until(reader, b"incorrect", timeout=8.0)
        assert b"incorrect" in rejection.lower()
        assert b"# " not in rejection[-4:]  # no root shell prompt
        writer.close()
        await asyncio.sleep(0.1)
    finally:
        server.close()
        await server.wait_closed()

    recs = _parse_log(buf)
    commands = [r["detail"].get("command", "") for r in recs
                if r.get("record_type") == "event" and r.get("kind") == "command"]
    joined = " ".join(commands)
    assert "login:root" in joined
    assert "pass:xc3511" in joined


@pytest.mark.asyncio
async def test_byte_cap_terminates_session():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf)
    # Tiny byte cap; SSH tarpit reads client data, so the cap should trip.
    cfg = make_config(drip_delay=0.005, max_session_bytes=16, max_session_seconds=5.0)
    svc, server, host, port = await _start(SshTarpit, cfg, logger)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        # Send more than the cap.
        writer.write(b"A" * 200)
        await writer.drain()
        # Let the server process and (eventually) hit the cap / idle.
        await asyncio.sleep(1.5)
        writer.close()
        await asyncio.sleep(0.2)
    finally:
        server.close()
        await server.wait_closed()

    recs = _parse_log(buf)
    sess = [r for r in recs if r.get("record_type") == "session"]
    assert len(sess) == 1
    # The session recorded receiving data but capped bytes_received at the limit.
    assert sess[0]["bytes_received"] <= 16
    limit_events = [r for r in recs
                    if r.get("record_type") == "event" and r.get("kind") == "limit"]
    assert any(e["detail"].get("reason") == "max_session_bytes" for e in limit_events)


@pytest.mark.asyncio
async def test_connection_held_open_for_ssh_banner():
    """SSH tarpit should keep dripping (connection stays open) over time."""
    buf = io.StringIO()
    logger = SessionLogger(stream=buf)
    cfg = make_config(drip_delay=0.02, max_session_seconds=2.0)
    svc, server, host, port = await _start(SshTarpit, cfg, logger)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(b"SSH-2.0-libssh2_1.9.0\r\n")
        await writer.drain()
        start = time.monotonic()
        total = bytearray()
        while time.monotonic() - start < 1.0:
            try:
                chunk = await asyncio.wait_for(reader.read(32), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            if not chunk:
                break
            total.extend(chunk)
        # Over ~1s the banner tarpit should have produced multiple bytes but the
        # connection stayed open the whole time (we never got EOF early).
        assert len(total) > 0
        assert time.monotonic() - start >= 0.9
        writer.close()
        await asyncio.sleep(0.1)
    finally:
        server.close()
        await server.wait_closed()
