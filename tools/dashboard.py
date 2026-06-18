#!/usr/bin/env python3
"""Attacker-session dashboard / timeline renderer (stdlib only).

Reads the JSON-lines session log produced by the tarpit and renders:
  * a CLI summary table of sessions over time, and
  * a self-contained static HTML timeline (no JS frameworks, no external CDN),

optionally serving it via the stdlib ``http.server``.

This deliberately uses zero third-party deps so it always runs, even offline.
(FastAPI/Flask were considered; we chose stdlib for reliability per the brief.)

Usage::

    # render HTML to a file
    python tools/dashboard.py --log sessions.jsonl --out dashboard.html

    # print a CLI summary
    python tools/dashboard.py --log sessions.jsonl --cli

    # serve it on http://127.0.0.1:8088
    python tools/dashboard.py --log sessions.jsonl --serve --serve-port 8088
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LoadedSession:
    session_id: str
    service: str
    src_ip: str
    src_port: int
    started_at: float = 0.0
    ended_at: float | None = None
    duration: float = 0.0
    bytes_received: int = 0
    bytes_sent: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)


def load_sessions(path: str) -> list[LoadedSession]:
    """Load sessions from a JSON-lines log.

    Prefers ``record_type == 'session'`` summary records; if only streamed event
    records are present it reconstructs sessions from them.
    """
    summaries: dict[str, LoadedSession] = {}
    reconstructed: dict[str, LoadedSession] = {}

    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rtype = obj.get("record_type")
            if rtype == "session":
                summaries[obj["session_id"]] = LoadedSession(
                    session_id=obj["session_id"],
                    service=obj.get("service", "?"),
                    src_ip=obj.get("src_ip", "?"),
                    src_port=obj.get("src_port", 0),
                    started_at=obj.get("started_at", 0.0),
                    ended_at=obj.get("ended_at"),
                    duration=obj.get("duration", 0.0),
                    bytes_received=obj.get("bytes_received", 0),
                    bytes_sent=obj.get("bytes_sent", 0),
                    events=obj.get("events", []),
                )
            elif rtype == "event":
                sid = obj.get("session_id", "")
                sess = reconstructed.get(sid)
                if sess is None:
                    sess = LoadedSession(
                        session_id=sid,
                        service=obj.get("service", "?"),
                        src_ip=obj.get("src_ip", "?"),
                        src_port=obj.get("src_port", 0),
                        started_at=obj.get("ts", 0.0),
                    )
                    reconstructed[sid] = sess
                sess.events.append(
                    {"ts": obj.get("ts"), "kind": obj.get("kind"), "detail": obj.get("detail", {})}
                )
                if obj.get("kind") == "recv":
                    sess.bytes_received += int(obj.get("detail", {}).get("bytes", 0))
                if obj.get("kind") == "drip":
                    sess.bytes_sent += int(obj.get("detail", {}).get("bytes", 0))

    # Merge: summaries win; add any reconstructed-only sessions.
    merged = dict(summaries)
    for sid, sess in reconstructed.items():
        if sid not in merged:
            if sess.events:
                last_ts = sess.events[-1].get("ts") or sess.started_at
                sess.duration = round(last_ts - sess.started_at, 4)
            merged[sid] = sess

    out = list(merged.values())
    out.sort(key=lambda s: s.started_at)
    return out


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "-"
    return _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def render_cli(sessions: list[LoadedSession]) -> str:
    lines = []
    lines.append(f"{'started':<10}{'service':<9}{'src':<22}{'dur(s)':>8}{'rx':>7}{'tx':>7}  events")
    lines.append("-" * 78)
    for s in sessions:
        src = f"{s.src_ip}:{s.src_port}"
        lines.append(
            f"{_fmt_ts(s.started_at):<10}{s.service:<9}{src:<22}"
            f"{s.duration:>8.2f}{s.bytes_received:>7}{s.bytes_sent:>7}  {len(s.events)}"
        )
    lines.append("-" * 78)
    lines.append(f"{len(sessions)} session(s)")
    return "\n".join(lines)


def render_html(sessions: list[LoadedSession]) -> str:
    rows = []
    total_rx = sum(s.bytes_received for s in sessions)
    total_tx = sum(s.bytes_sent for s in sessions)
    total_dur = sum(s.duration for s in sessions)

    for s in sessions:
        ev_items = []
        for ev in s.events:
            detail = ev.get("detail", {})
            detail_str = ", ".join(f"{k}={v}" for k, v in detail.items())
            ev_items.append(
                "<li><span class='ts'>{ts}</span> "
                "<span class='kind kind-{kind}'>{kind}</span> "
                "<span class='detail'>{detail}</span></li>".format(
                    ts=html.escape(_fmt_ts(ev.get("ts"))),
                    kind=html.escape(str(ev.get("kind", ""))),
                    detail=html.escape(detail_str),
                )
            )
        rows.append(
            """
            <details class="session svc-{service}">
              <summary>
                <span class="svc">{service}</span>
                <span class="src">{src}</span>
                <span class="meta">start {start} &middot; {dur:.2f}s &middot;
                  rx {rx}B / tx {tx}B &middot; {nev} events</span>
              </summary>
              <ul class="timeline">{events}</ul>
            </details>
            """.format(
                service=html.escape(s.service),
                src=html.escape(f"{s.src_ip}:{s.src_port}"),
                start=html.escape(_fmt_ts(s.started_at)),
                dur=s.duration,
                rx=s.bytes_received,
                tx=s.bytes_sent,
                nev=len(s.events),
                events="".join(ev_items),
            )
        )

    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>EventHorizon - Attacker Sessions</title>
<style>
  body {{ font-family: ui-monospace, Menlo, Consolas, monospace; background:#0b0f14;
         color:#cdd6e4; margin:0; padding:24px; }}
  h1 {{ color:#7ee787; font-size:20px; }}
  .stats {{ color:#8b98a9; margin-bottom:20px; }}
  .session {{ background:#11161d; border:1px solid #1f2733; border-radius:8px;
             margin:8px 0; padding:8px 12px; }}
  summary {{ cursor:pointer; display:flex; gap:12px; flex-wrap:wrap; align-items:baseline; }}
  .svc {{ font-weight:bold; color:#79c0ff; min-width:64px; }}
  .svc-telnet .svc {{ color:#ffa657; }}
  .svc-http .svc {{ color:#79c0ff; }}
  .svc-ssh .svc {{ color:#d2a8ff; }}
  .svc-ssdp .svc {{ color:#7ee787; }}
  .src {{ color:#e6edf3; }}
  .meta {{ color:#8b98a9; font-size:12px; }}
  .timeline {{ list-style:none; padding-left:8px; margin-top:10px;
              border-left:2px solid #1f2733; }}
  .timeline li {{ margin:3px 0; font-size:13px; }}
  .ts {{ color:#6e7681; }}
  .kind {{ display:inline-block; min-width:70px; color:#7ee787; }}
  .kind-recv {{ color:#ffa657; }}
  .kind-command {{ color:#ff7b72; }}
  .kind-drip {{ color:#6e7681; }}
  .kind-limit, .kind-error {{ color:#f85149; }}
  .detail {{ color:#cdd6e4; }}
</style></head><body>
<h1>EventHorizon &mdash; Attacker Session Timeline</h1>
<div class="stats">{n} sessions &middot; total dwell {dur:.2f}s &middot;
  rx {rx}B / tx {tx}B (attacker time wasted &asymp; total dwell)</div>
{rows}
</body></html>""".format(
        n=len(sessions),
        dur=total_dur,
        rx=total_rx,
        tx=total_tx,
        rows="".join(rows) if rows else "<p>No sessions recorded yet.</p>",
    )


def serve(html_path: str, host: str, port: int) -> None:
    import http.server
    import functools
    import os

    directory = os.path.dirname(os.path.abspath(html_path)) or "."
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    fname = os.path.basename(html_path)
    with http.server.ThreadingHTTPServer((host, port), handler) as httpd:
        print(f"[dashboard] serving http://{host}:{port}/{fname}  (Ctrl-C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def main() -> int:
    p = argparse.ArgumentParser(description="EventHorizon session dashboard.")
    p.add_argument("--log", required=True, help="path to sessions JSON-lines log")
    p.add_argument("--out", default="dashboard.html", help="HTML output path")
    p.add_argument("--cli", action="store_true", help="print CLI summary")
    p.add_argument("--serve", action="store_true", help="serve the HTML")
    p.add_argument("--serve-host", default="127.0.0.1")
    p.add_argument("--serve-port", type=int, default=8088)
    args = p.parse_args()

    sessions = load_sessions(args.log)

    if args.cli:
        print(render_cli(sessions))

    html_doc = render_html(sessions)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"[dashboard] wrote {args.out} ({len(sessions)} sessions)")

    if args.serve:
        serve(args.out, args.serve_host, args.serve_port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
