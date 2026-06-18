"""Robustness / malformed-input / resource-exhaustion tests.

Assert the tarpit stays safe and bounded under hostile or malformed input:
  * malformed / binary / oversized HTTP requests are parsed without raising,
  * the per-session byte cap and the global connection cap actually bound us,
  * config validation clamps dangerous values,
  * telnet handles binary credential bytes without crashing.
"""

import asyncio
import io
import json

import pytest

from eventhorizon.config import TarpitConfig
from eventhorizon.services import HttpTarpit, TelnetTarpit
from eventhorizon.services.http import HttpTarpit as _Http
from eventhorizon.session import Metrics, SessionLogger
from eventhorizon.telemetry import Telemetry


def make_config(**overrides) -> TarpitConfig:
    cfg = TarpitConfig()
    cfg.host = "127.0.0.1"
    cfg.telnet_port = 0
    cfg.http_port = 0
    cfg.ssh_port = 0
    cfg.ssdp_port = 0
    cfg.drip_delay = 0.002
    cfg.drip_chunk = 8
    cfg.adaptive_enabled = False
    cfg.otel_enabled = False
    cfg.max_session_seconds = 4.0
    cfg.idle_timeout = 0.5
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _parse_log(buf: io.StringIO):
    return [json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]


async def _start(service_cls, cfg, logger):
    tel = Telemetry.from_config(cfg)
    svc = service_cls(cfg, logger, tel)
    server = await svc.start()
    host, port = server.sockets[0].getsockname()[:2]
    return svc, server, host, port


# --------------------------------------------------------------------------- #
# Config validation
# --------------------------------------------------------------------------- #
def test_config_clamps_dangerous_values():
    cfg = TarpitConfig()
    cfg2 = TarpitConfig()
    # Directly construct with nonsense — __post_init__ runs on construction, but
    # we also re-run it after manual mutation to prove the clamps hold.
    cfg.drip_chunk = 0
    cfg.max_connections = -5
    cfg.idle_timeout = -1.0
    cfg.adaptive_max_multiplier = 0.1
    cfg.max_session_bytes = 0
    cfg.__post_init__()
    assert cfg.drip_chunk >= 1
    assert cfg.max_connections >= 1
    assert cfg.idle_timeout > 0
    assert cfg.adaptive_max_multiplier >= 1.0
    assert cfg.max_session_bytes >= 1
    assert cfg2.host  # default still sane


# --------------------------------------------------------------------------- #
# HTTP request-line parsing (never raises)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw,exp_method",
    [
        (b"", "GET"),
        (b"\xff\xfe\x00garbage", "\xff\xfe\x00garbage"[:16] if False else None),
        (b"GET", "GET"),
        (b"POST /upnp/control HTTP/1.1\r\n", "POST"),
        (b"GET " + b"/A" * 10000 + b" HTTP/1.1\r\n", "GET"),  # absurd path
        (b"\n\n\n", "GET"),
    ],
)
def test_http_parse_request_line_never_raises(raw, exp_method):
    method, path = _Http._parse_request_line(raw)
    assert isinstance(method, str) and isinstance(path, str)
    assert len(method) <= 16
    assert len(path) <= 512
    if exp_method:
        assert method == exp_method


@pytest.mark.asyncio
async def test_http_handles_binary_garbage_request():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf, metrics=Metrics())
    cfg = make_config()
    svc, server, host, port = await _start(HttpTarpit, cfg, logger)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(b"\x00\x01\x02\xff\xfe random binary \x90\x90\r\n\r\n")
        await writer.drain()
        # Server must still answer (canned) and not crash.
        data = await asyncio.wait_for(reader.read(64), timeout=4.0)
        assert data.startswith(b"HTTP/1.1")
        writer.close()
        await asyncio.sleep(0.1)
    finally:
        server.close()
        await server.wait_closed()
    recs = _parse_log(buf)
    # No 'error' events — the malformed request was handled gracefully.
    errors = [r for r in recs if r.get("kind") == "error"]
    assert errors == []
    sessions = [r for r in recs if r.get("record_type") == "session"]
    assert len(sessions) == 1


@pytest.mark.asyncio
async def test_http_slowloris_head_is_bounded_by_byte_cap():
    """A client that dribbles head bytes without the blank line is still reaped."""
    buf = io.StringIO()
    logger = SessionLogger(stream=buf, metrics=Metrics())
    # Tiny byte cap so the never-terminating head trips the cap quickly.
    cfg = make_config(max_session_bytes=64, idle_timeout=0.4, max_session_seconds=3.0)
    svc, server, host, port = await _start(HttpTarpit, cfg, logger)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        # Send a partial header and never the terminating CRLF CRLF.
        writer.write(b"GET /slow HTTP/1.1\r\nX-Pad: " + b"A" * 200)
        await writer.drain()
        # The session must end (cap or idle), not hang forever.
        data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        # Either it answered after cap, or closed; either way no hang.
        writer.close()
        await asyncio.sleep(0.2)
    finally:
        server.close()
        await server.wait_closed()
    recs = _parse_log(buf)
    sessions = [r for r in recs if r.get("record_type") == "session"]
    assert len(sessions) == 1
    assert sessions[0]["bytes_received"] <= 64  # byte cap held


# --------------------------------------------------------------------------- #
# Global connection cap (host protection)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_connection_cap_refuses_excess_connections():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf, metrics=Metrics())
    cfg = make_config(max_session_seconds=5.0, idle_timeout=5.0, drip_delay=0.05)
    tel = Telemetry.from_config(cfg)
    sem = asyncio.Semaphore(2)  # cap at 2 concurrent connections
    svc = TelnetTarpit(cfg, logger, tel, sem)
    server = await svc.start()
    host, port = server.sockets[0].getsockname()[:2]
    conns = []
    try:
        # Open 2 connections that will be held by the slow telnet banner.
        for _ in range(2):
            r, w = await asyncio.open_connection(host, port)
            conns.append((r, w))
        await asyncio.sleep(0.2)  # let them acquire slots
        assert len(svc.active_sessions) == 2

        # A 3rd connection must be refused (closed promptly with no session).
        r3, w3 = await asyncio.open_connection(host, port)
        conns.append((r3, w3))
        # The server closes it: read returns EOF quickly.
        eof = await asyncio.wait_for(r3.read(16), timeout=2.0)
        assert eof == b""  # refused at the door
        assert len(svc.active_sessions) == 2  # still only 2 active
    finally:
        for _, w in conns:
            w.close()
        server.close()
        await server.wait_closed()


# --------------------------------------------------------------------------- #
# Telnet handles binary / non-utf8 credential bytes
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_telnet_handles_binary_credentials():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf, metrics=Metrics())
    cfg = make_config(drip_delay=0.001)
    svc, server, host, port = await _start(TelnetTarpit, cfg, logger)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        await asyncio.sleep(0.2)
        writer.write(b"\xff\xfd\x18\xff\xfa root\n")  # telnet IAC + binary
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.write(b"\x80\x81\x82\n")  # non-utf8 password
        await writer.drain()
        await asyncio.sleep(0.3)
        writer.close()
        await asyncio.sleep(0.1)
    finally:
        server.close()
        await server.wait_closed()
    recs = _parse_log(buf)
    errors = [r for r in recs if r.get("kind") == "error"]
    assert errors == []  # binary creds handled, no crash
    sessions = [r for r in recs if r.get("record_type") == "session"]
    assert len(sessions) == 1
