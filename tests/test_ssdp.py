"""SSDP/UPnP UDP tarpit tests.

Assert the new IoT protocol: it answers M-SEARCH discovery with a fake device
descriptor, logs the probe as a Session, updates metrics, rate-limits floods,
and never executes / fetches anything.
"""

import asyncio
import io
import json

import pytest

from eventhorizon.config import TarpitConfig
from eventhorizon.services import SsdpTarpit
from eventhorizon.session import Metrics, SessionLogger


def make_config(**overrides) -> TarpitConfig:
    cfg = TarpitConfig()
    cfg.host = "127.0.0.1"
    cfg.ssdp_port = 0  # ephemeral
    cfg.http_port = 8080
    cfg.drip_delay = 0.0  # no tarpit delay -> fast tests
    cfg.otel_enabled = False
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _parse_log(buf: io.StringIO):
    return [json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]


class _ClientProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.future = asyncio.get_event_loop().create_future()

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)


async def _start_ssdp(cfg, logger, metrics=None):
    from eventhorizon.telemetry import Telemetry

    tel = Telemetry.from_config(cfg)
    if metrics is not None:
        logger.metrics = metrics
    svc = SsdpTarpit(cfg, logger, tel)
    transport = await svc.start()
    port = transport.get_extra_info("sockname")[1]
    return svc, transport, port


_MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 2\r\n"
    b"ST: upnp:rootdevice\r\n"
    b"\r\n"
)


@pytest.mark.asyncio
async def test_msearch_gets_fake_descriptor_and_is_logged():
    buf = io.StringIO()
    metrics = Metrics()
    logger = SessionLogger(stream=buf, metrics=metrics)
    cfg = make_config(http_port=8080)
    svc, transport, port = await _start_ssdp(cfg, logger)
    try:
        loop = asyncio.get_event_loop()
        ctrans, cproto = await loop.create_datagram_endpoint(
            _ClientProto, remote_addr=("127.0.0.1", port)
        )
        try:
            ctrans.sendto(_MSEARCH)
            reply = await asyncio.wait_for(cproto.future, timeout=3.0)
        finally:
            ctrans.close()
        # Fake UPnP descriptor response.
        assert reply.startswith(b"HTTP/1.1 200 OK")
        assert b"LOCATION:" in reply
        assert b"rootDesc.xml" in reply  # points at our own HTTP tarpit
        assert b"8080" in reply  # the configured http_port
        # Give the close path a moment to flush the session summary.
        await asyncio.sleep(0.1)
    finally:
        await svc.stop()

    recs = _parse_log(buf)
    kinds = {r.get("kind") for r in recs if r.get("record_type") == "event"}
    assert "open" in kinds and "recv" in kinds and "command" in kinds
    assert "drip" in kinds  # we replied
    commands = [r["detail"].get("command", "") for r in recs
                if r.get("kind") == "command"]
    assert any("M-SEARCH" in c for c in commands)
    sessions = [r for r in recs if r.get("record_type") == "session"]
    assert len(sessions) == 1
    assert sessions[0]["service"] == "ssdp"
    # Metrics reflect the probe.
    snap = metrics.snapshot()
    assert snap["total_sessions"] >= 1
    assert snap["sessions_per_protocol"].get("ssdp", 0) >= 1
    assert snap["active_sessions"] == 0  # closed cleanly


@pytest.mark.asyncio
async def test_non_msearch_is_logged_but_not_answered():
    buf = io.StringIO()
    metrics = Metrics()
    logger = SessionLogger(stream=buf, metrics=metrics)
    cfg = make_config()
    svc, transport, port = await _start_ssdp(cfg, logger)
    try:
        loop = asyncio.get_event_loop()
        ctrans, cproto = await loop.create_datagram_endpoint(
            _ClientProto, remote_addr=("127.0.0.1", port)
        )
        try:
            ctrans.sendto(b"NOTIFY * HTTP/1.1\r\n\r\n")  # not an M-SEARCH
            try:
                await asyncio.wait_for(cproto.future, timeout=0.6)
                answered = True
            except asyncio.TimeoutError:
                answered = False
        finally:
            ctrans.close()
        assert answered is False  # we do not reply to non-M-SEARCH probes
        await asyncio.sleep(0.1)
    finally:
        await svc.stop()

    recs = _parse_log(buf)
    commands = [r["detail"].get("command", "") for r in recs
                if r.get("kind") == "command"]
    assert any("ssdp_other" in c for c in commands)
    # No drip event because we did not answer.
    drips = [r for r in recs if r.get("kind") == "drip"]
    assert drips == []


@pytest.mark.asyncio
async def test_rate_limit_blocks_flood():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf, metrics=Metrics())
    cfg = make_config()
    svc, transport, port = await _start_ssdp(cfg, logger)
    try:
        loop = asyncio.get_event_loop()
        ctrans, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
        )
        try:
            # Blast well over the per-source rate limit in one window.
            for _ in range(svc._RATE_LIMIT_PER_SEC + 8):
                ctrans.sendto(_MSEARCH)
            await asyncio.sleep(0.5)
        finally:
            ctrans.close()
        await asyncio.sleep(0.1)
    finally:
        await svc.stop()

    recs = _parse_log(buf)
    limit_events = [r for r in recs
                    if r.get("kind") == "limit"
                    and r.get("detail", {}).get("reason") == "rate_limit"]
    assert len(limit_events) >= 1  # some probes were rate-limited (not answered)


def test_msearch_helpers_are_inert():
    from eventhorizon.services.ssdp import _extract_st, _is_msearch

    assert _is_msearch(_MSEARCH) is True
    assert _is_msearch(b"GET / HTTP/1.1") is False
    assert _extract_st(_MSEARCH) == "upnp:rootdevice"
    # Garbage / binary must not raise.
    assert _extract_st(b"\xff\x00\x01") == ""
    assert _is_msearch(b"") is False
