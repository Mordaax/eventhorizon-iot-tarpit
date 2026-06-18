"""Live dashboard server tests (stdlib backend): /, /metrics, /healthz, SSE.

These hit a real loopback HTTP server so the SSE tailing + Prometheus endpoint
are exercised end to end. FastAPI is optional; the stdlib path is what runs in
CI, so that is what we assert.
"""

import asyncio
import socket
import time
import urllib.request

import pytest

from eventhorizon.config import TarpitConfig
from eventhorizon.dashboard_server import (
    JsonlTailer,
    render_dashboard_html,
    start_dashboard,
)
from eventhorizon.session import Metrics


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_config(port: int) -> TarpitConfig:
    cfg = TarpitConfig()
    cfg.host = "127.0.0.1"
    cfg.dashboard_port = port
    return cfg


def test_dashboard_html_is_self_contained():
    doc = render_dashboard_html()
    assert "<!DOCTYPE html>" in doc
    assert "EventSource('/events')" in doc
    # No external CDN / framework dependency.
    assert "http://" not in doc.split("<script>")[0] or "cdn" not in doc.lower()
    assert "cdn" not in doc.lower()


@pytest.mark.asyncio
async def test_metrics_and_health_endpoints(tmp_path):
    port = _free_port()
    metrics = Metrics()
    metrics.session_opened("telnet")
    metrics.record_event("telnet", "drip", {"bytes": 5})
    log_path = str(tmp_path / "sessions.jsonl")
    handle = await start_dashboard(make_config(port), metrics, log_path)
    try:
        base = f"http://127.0.0.1:{port}"
        # /healthz
        with urllib.request.urlopen(base + "/healthz", timeout=3) as r:
            assert r.read() == b"ok"
        # /metrics (Prometheus)
        with urllib.request.urlopen(base + "/metrics", timeout=3) as r:
            body = r.read().decode()
            ctype = r.headers.get("Content-Type", "")
        assert "eventhorizon_active_sessions 1" in body
        assert "eventhorizon_bytes_dripped_total 5" in body
        assert "version=0.0.4" in ctype
        # / (HTML dashboard)
        with urllib.request.urlopen(base + "/", timeout=3) as r:
            html = r.read().decode()
        assert "Live Attacker Feed" in html
        # 404 for unknown.
        try:
            urllib.request.urlopen(base + "/nope", timeout=3)
            assert False, "expected 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        await handle.stop()


@pytest.mark.asyncio
async def test_sse_stream_tails_log(tmp_path):
    port = _free_port()
    metrics = Metrics()
    log_path = tmp_path / "sessions.jsonl"
    log_path.write_text("")  # exists, empty
    handle = await start_dashboard(make_config(port), metrics, str(log_path))
    try:
        # Open a raw SSE connection.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"GET /events HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"
        )
        await writer.drain()

        # Read response headers.
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
        assert b"text/event-stream" in header

        # Now append a new event line to the log; SSE must push it.
        await asyncio.sleep(0.3)  # let the tailer reach EOF first
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(
                '{"record_type":"event","service":"ssdp","kind":"command",'
                '"src_ip":"9.9.9.9","src_port":1900,'
                '"detail":{"command":"M-SEARCH ST=upnp:rootdevice"}}\n'
            )
            fh.flush()

        # Read streamed data for up to a few seconds, looking for our payload.
        deadline = time.monotonic() + 4.0
        got = b""
        while time.monotonic() < deadline and b"M-SEARCH" not in got:
            try:
                chunk = await asyncio.wait_for(reader.read(512), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if not chunk:
                break
            got += chunk
        assert b"data:" in got
        assert b"M-SEARCH" in got
        assert b"ssdp" in got
        writer.close()
    finally:
        await handle.stop()


def test_jsonl_tailer_handles_missing_file_then_appears(tmp_path):
    """Tailer must not crash if the file does not exist yet."""
    path = tmp_path / "later.jsonl"
    tailer = JsonlTailer(str(path), from_start=True)
    results = []

    def consume():
        for rec in tailer.lines(poll=0.05):
            results.append(rec)
            break

    import threading

    t = threading.Thread(target=consume, daemon=True)
    t.start()
    time.sleep(0.2)
    path.write_text('{"record_type":"event","kind":"open","service":"http"}\n')
    t.join(timeout=3)
    tailer.stop()
    assert results and results[0]["kind"] == "open"


def test_tailer_with_none_path_yields_nothing():
    tailer = JsonlTailer(None)
    assert list(tailer.lines(poll=0.01)) == []
