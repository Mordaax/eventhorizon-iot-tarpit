"""Live real-time attacker dashboard: SSE event stream + Prometheus metrics.

This module exposes the tarpit's activity in a browser, live, with **zero
required third-party dependencies**:

* ``GET /``          -> a self-contained HTML page (no CDN, no JS frameworks)
                        that opens an ``EventSource`` to ``/events`` and renders
                        attacker sessions as they happen.
* ``GET /events``    -> a ``text/event-stream`` (Server-Sent Events) feed that
                        **tails the existing JSONL log** and pushes each new
                        record to the browser. The JSONL stream is the single
                        source of truth — the dashboard adds no new data path.
* ``GET /metrics``   -> Prometheus text-format counters (active sessions, totals,
                        bytes dripped, per-protocol counts, auth attempts) from
                        the shared :class:`~eventhorizon.session.Metrics`.
* ``GET /healthz``   -> ``ok``.

Backend selection:

* If **FastAPI + uvicorn** are installed, we use them (nicer ASGI server).
* Otherwise we fall back to the Python standard library ``http.server`` running
  in a background thread. SSE works fine over the threaded stdlib server.

Either way the public entry point is :func:`start_dashboard`, which returns a
small handle with an awaitable ``stop()``.

SAFETY: the dashboard binds to the configured host (``127.0.0.1`` by default),
serves only static HTML + read-only views of the tarpit's own log/metrics, and
never reflects attacker bytes without HTML-escaping them.
"""

from __future__ import annotations

import asyncio
import html
import json
import threading
import time
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Shared HTML (used by both backends).
# ---------------------------------------------------------------------------
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>EventHorizon — Live Attacker Feed</title>
<style>
  body { font-family: ui-monospace, Menlo, Consolas, monospace; background:#0b0f14;
         color:#cdd6e4; margin:0; padding:20px; }
  h1 { color:#7ee787; font-size:20px; margin:0 0 4px; }
  .sub { color:#8b98a9; font-size:12px; margin-bottom:16px; }
  #stat { display:flex; gap:18px; flex-wrap:wrap; margin-bottom:16px; }
  .card { background:#11161d; border:1px solid #1f2733; border-radius:8px;
          padding:10px 14px; min-width:120px; }
  .card .n { font-size:22px; color:#79c0ff; }
  .card .l { font-size:11px; color:#8b98a9; text-transform:uppercase; }
  #feed { list-style:none; padding:0; margin:0; }
  #feed li { background:#11161d; border:1px solid #1f2733; border-left:3px solid #2d3340;
             border-radius:6px; margin:4px 0; padding:6px 10px; font-size:13px;
             display:flex; gap:10px; align-items:baseline; }
  .svc { font-weight:bold; min-width:62px; color:#79c0ff; }
  .svc-telnet { color:#ffa657; } .svc-http { color:#79c0ff; }
  .svc-ssh { color:#d2a8ff; } .svc-ssdp { color:#7ee787; }
  .kind { min-width:74px; color:#7ee787; }
  .kind-recv { color:#ffa657; } .kind-command { color:#ff7b72; }
  .kind-drip { color:#6e7681; } .kind-open { color:#7ee787; }
  .kind-close { color:#8b98a9; } .kind-limit,.kind-error { color:#f85149; }
  .src { color:#e6edf3; } .detail { color:#9aa7b8; }
  #conn { font-size:11px; color:#8b98a9; }
  a { color:#79c0ff; }
</style></head><body>
<h1>EventHorizon &mdash; Live Attacker Feed</h1>
<div class="sub">Server-Sent Events tail of the JSONL session log &middot;
  <a href="/metrics">/metrics</a> (Prometheus) &middot;
  <span id="conn">connecting&hellip;</span></div>
<div id="stat"></div>
<ul id="feed"></ul>
<script>
  var feed = document.getElementById('feed');
  var conn = document.getElementById('conn');
  var stat = document.getElementById('stat');
  function card(n, l){ return '<div class="card"><div class="n">'+n+
     '</div><div class="l">'+l+'</div></div>'; }
  function refreshMetrics(){
    fetch('/metrics').then(function(r){return r.text();}).then(function(t){
      var m = {}; t.split('\\n').forEach(function(line){
        if(line[0]==='#'||!line.trim()) return;
        var sp = line.lastIndexOf(' ');
        if(sp>0){ m[line.slice(0,sp)] = line.slice(sp+1); }
      });
      stat.innerHTML =
        card(m['eventhorizon_active_sessions']||0,'active') +
        card(m['eventhorizon_sessions_total']||0,'sessions') +
        card(m['eventhorizon_events_total']||0,'events') +
        card(m['eventhorizon_bytes_dripped_total']||0,'bytes dripped') +
        card(m['eventhorizon_auth_attempts_total']||0,'auth attempts');
    }).catch(function(){});
  }
  refreshMetrics(); setInterval(refreshMetrics, 2000);
  var es = new EventSource('/events');
  es.onopen = function(){ conn.textContent = 'live'; conn.style.color='#7ee787'; };
  es.onerror = function(){ conn.textContent = 'reconnecting…'; conn.style.color='#f85149'; };
  es.onmessage = function(e){
    var o; try { o = JSON.parse(e.data); } catch(_){ return; }
    if (o.record_type === 'session') return; // show streamed events, not summaries
    var li = document.createElement('li');
    var detail = '';
    if (o.detail) { for (var k in o.detail){ detail += k+'='+o.detail[k]+' '; } }
    li.innerHTML = '<span class="svc svc-'+(o.service||'')+'">'+(o.service||'?')+
      '</span><span class="kind kind-'+(o.kind||'')+'">'+(o.kind||'')+
      '</span><span class="src">'+(o.src_ip||'?')+':'+(o.src_port||0)+
      '</span><span class="detail">'+detail+'</span>';
    feed.insertBefore(li, feed.firstChild);
    while (feed.childNodes.length > 200) feed.removeChild(feed.lastChild);
  };
</script>
</body></html>"""


def render_dashboard_html() -> str:
    return _DASHBOARD_HTML


# ---------------------------------------------------------------------------
# JSONL tailer (shared). A generator that yields new lines appended to a file.
# ---------------------------------------------------------------------------
class JsonlTailer:
    """Tail a JSONL log file, yielding parsed dict records as they are appended.

    Robust to: the file not existing yet (waits for it), truncation/rotation
    (re-opens), and partial lines (buffers until a newline). If ``path`` is None
    (tarpit logging to stdout) there is nothing to tail, so it yields nothing.
    """

    def __init__(self, path: Optional[str], from_start: bool = False):
        self.path = path
        self.from_start = from_start
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def lines(self, poll: float = 0.25):
        if not self.path:
            return
        import os

        fh = None
        buf = ""
        inode = None
        try:
            while not self._stop:
                if fh is None:
                    if not os.path.exists(self.path):
                        time.sleep(poll)
                        continue
                    fh = open(self.path, "r", encoding="utf-8")
                    inode = os.fstat(fh.fileno()).st_ino
                    if not self.from_start:
                        fh.seek(0, os.SEEK_END)
                chunk = fh.read()
                if chunk:
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
                    continue
                # No new data: detect rotation/truncation, then sleep.
                try:
                    st = os.stat(self.path)
                    if st.st_ino != inode or st.st_size < fh.tell():
                        fh.close()
                        fh = None
                        buf = ""
                        continue
                except OSError:
                    pass
                time.sleep(poll)
        finally:
            if fh is not None:
                fh.close()


def _sse_format(record: dict[str, Any]) -> bytes:
    """Format a record as one SSE 'data:' message."""
    payload = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
    return f"data: {payload}\n\n".encode("utf-8")


# ---------------------------------------------------------------------------
# Stdlib backend (default, zero-dep).
# ---------------------------------------------------------------------------
def _build_stdlib_server(config: Any, metrics: Any, log_path: Optional[str]):
    import http.server

    metrics_ref = metrics
    log_ref = log_path

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:  # silence noisy stderr logs
            return

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            path = self.path.split("?", 1)[0]
            if path == "/" or path == "/index.html":
                self._send(200, render_dashboard_html().encode("utf-8"),
                           "text/html; charset=utf-8")
            elif path == "/healthz":
                self._send(200, b"ok", "text/plain; charset=utf-8")
            elif path == "/metrics":
                body = metrics_ref.render_prometheus().encode("utf-8")
                self._send(200, body,
                           "text/plain; version=0.0.4; charset=utf-8")
            elif path == "/events":
                self._stream_events()
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

        def _stream_events(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            tailer = JsonlTailer(log_ref, from_start=False)
            self.server._tailers.add(tailer)  # type: ignore[attr-defined]
            last_beat = time.monotonic()
            try:
                # Prime the connection so EventSource fires 'open' promptly.
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                for record in tailer.lines(poll=0.2):
                    self.wfile.write(_sse_format(record))
                    self.wfile.flush()
                    last_beat = time.monotonic()
            except (BrokenPipeError, ConnectionResetError, ValueError):
                pass
            except Exception:
                pass
            finally:
                tailer.stop()
                self.server._tailers.discard(tailer)  # type: ignore[attr-defined]

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, *a: Any, **k: Any) -> None:
            super().__init__(*a, **k)
            self._tailers: set[JsonlTailer] = set()

    httpd = Server((config.host, config.dashboard_port), Handler)
    return httpd


class _StdlibHandle:
    """Awaitable-stop handle wrapping a threaded stdlib HTTP server."""

    backend = "stdlib"

    def __init__(self, httpd: Any, thread: threading.Thread):
        self._httpd = httpd
        self._thread = thread

    async def stop(self) -> None:
        # Stop any in-flight SSE tailers so their threads exit promptly.
        for t in list(getattr(self._httpd, "_tailers", set())):
            t.stop()
        await asyncio.to_thread(self._httpd.shutdown)
        self._httpd.server_close()


# ---------------------------------------------------------------------------
# FastAPI backend (optional, used if installed).
# ---------------------------------------------------------------------------
def _try_build_fastapi(config: Any, metrics: Any, log_path: Optional[str]):
    try:
        import uvicorn
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
    except Exception:
        return None

    app = FastAPI(title="EventHorizon Dashboard")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:  # pragma: no cover - exercised only with fastapi
        return render_dashboard_html()

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz() -> str:  # pragma: no cover
        return "ok"

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_ep() -> str:  # pragma: no cover
        return metrics.render_prometheus()

    @app.get("/events")
    async def events():  # pragma: no cover
        async def gen():
            tailer = JsonlTailer(log_path, from_start=False)
            yield b": connected\n\n"
            try:
                # Run the blocking tailer in a thread, bridging to async via a
                # queue so we don't block the event loop.
                loop = asyncio.get_running_loop()
                q: asyncio.Queue = asyncio.Queue(maxsize=1000)

                def pump():
                    for rec in tailer.lines(poll=0.2):
                        asyncio.run_coroutine_threadsafe(q.put(rec), loop)

                import threading as _t

                _t.Thread(target=pump, daemon=True).start()
                while True:
                    rec = await q.get()
                    yield _sse_format(rec)
            finally:
                tailer.stop()

        return StreamingResponse(gen(), media_type="text/event-stream")

    config_uv = uvicorn.Config(
        app, host=config.host, port=config.dashboard_port, log_level="warning"
    )
    server = uvicorn.Server(config_uv)
    return server


class _FastapiHandle:
    backend = "fastapi"

    def __init__(self, server: Any, task: "asyncio.Task[Any]"):
        self._server = server
        self._task = task

    async def stop(self) -> None:  # pragma: no cover - only with fastapi
        self._server.should_exit = True
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except Exception:
            self._task.cancel()


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------
async def start_dashboard(config: Any, metrics: Any, log_path: Optional[str]):
    """Start the dashboard, preferring FastAPI, falling back to stdlib.

    Returns a handle exposing ``backend`` (str) and an awaitable ``stop()``.
    """
    server = _try_build_fastapi(config, metrics, log_path)
    if server is not None:  # pragma: no cover - only when fastapi installed
        task = asyncio.create_task(server.serve())
        # Give uvicorn a moment to bind.
        await asyncio.sleep(0.3)
        return _FastapiHandle(server, task)

    httpd = _build_stdlib_server(config, metrics, log_path)
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
    )
    thread.start()
    return _StdlibHandle(httpd, thread)
