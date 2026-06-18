"""Session model and structured JSON logging.

Each TCP connection to a tarpit service becomes a :class:`Session`. A session
holds an id, source ip/port, the service name, and a timeline of
:class:`Event` records (bytes received, commands seen, drip timing, lifecycle).

Logs are emitted as JSON-lines (one JSON object per line). This is intentionally
dependency-free so it works whether or not OpenTelemetry is installed, and is
trivially ingestible by the dashboard renderer and by log shippers.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional, TextIO


def _now() -> float:
    return time.time()


class Metrics:
    """In-process counters that back the Prometheus ``/metrics`` endpoint.

    Kept thread/async safe with a lock so it can be updated from the asyncio
    event loop and read from the dashboard's HTTP server thread. Counters are
    monotonic; ``active_sessions`` is a gauge. We derive everything from the
    same lifecycle that writes JSONL, so the numbers always agree with the log.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active_sessions = 0
        self.total_sessions = 0
        self.total_events = 0
        self.bytes_dripped = 0
        self.bytes_received = 0
        self.auth_attempts = 0
        self.sessions_per_protocol: dict[str, int] = defaultdict(int)
        self.events_per_protocol: dict[str, int] = defaultdict(int)

    def session_opened(self, service: str) -> None:
        with self._lock:
            self.active_sessions += 1
            self.total_sessions += 1
            self.sessions_per_protocol[service] += 1

    def session_closed(self) -> None:
        with self._lock:
            if self.active_sessions > 0:
                self.active_sessions -= 1

    def record_event(self, service: str, kind: str, detail: dict[str, Any]) -> None:
        with self._lock:
            self.total_events += 1
            self.events_per_protocol[service] += 1
            if kind == "drip":
                self.bytes_dripped += int(detail.get("bytes", 0) or 0)
            elif kind == "recv":
                self.bytes_received += int(detail.get("bytes", 0) or 0)
            elif kind == "command":
                cmd = str(detail.get("command", ""))
                # Telnet login/password attempts and HTTP login posts count as
                # auth attempts (cheap heuristic on our own canned command tags).
                if cmd.startswith(("pass:", "login:")):
                    self.auth_attempts += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_sessions": self.active_sessions,
                "total_sessions": self.total_sessions,
                "total_events": self.total_events,
                "bytes_dripped": self.bytes_dripped,
                "bytes_received": self.bytes_received,
                "auth_attempts": self.auth_attempts,
                "sessions_per_protocol": dict(self.sessions_per_protocol),
                "events_per_protocol": dict(self.events_per_protocol),
            }

    def render_prometheus(self) -> str:
        """Render counters in Prometheus text exposition format (v0.0.4)."""
        snap = self.snapshot()
        lines: list[str] = []

        def metric(name: str, mtype: str, help_text: str, value: Any,
                   labels: str = "") -> None:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {mtype}")
            lines.append(f"{name}{labels} {value}")

        metric("eventhorizon_active_sessions", "gauge",
               "Currently open attacker sessions.", snap["active_sessions"])
        metric("eventhorizon_sessions_total", "counter",
               "Total attacker sessions accepted.", snap["total_sessions"])
        metric("eventhorizon_events_total", "counter",
               "Total session timeline events recorded.", snap["total_events"])
        metric("eventhorizon_bytes_dripped_total", "counter",
               "Total bytes slowly dripped to attackers.", snap["bytes_dripped"])
        metric("eventhorizon_bytes_received_total", "counter",
               "Total bytes received from attackers.", snap["bytes_received"])
        metric("eventhorizon_auth_attempts_total", "counter",
               "Total credential / login attempts captured.", snap["auth_attempts"])

        # Per-protocol session counts (one help/type block, many label rows).
        lines.append("# HELP eventhorizon_protocol_sessions_total "
                     "Total sessions per emulated protocol.")
        lines.append("# TYPE eventhorizon_protocol_sessions_total counter")
        for proto, count in sorted(snap["sessions_per_protocol"].items()):
            lines.append(
                f'eventhorizon_protocol_sessions_total{{protocol="{proto}"}} {count}'
            )
        lines.append("# HELP eventhorizon_protocol_events_total "
                     "Total events per emulated protocol.")
        lines.append("# TYPE eventhorizon_protocol_events_total counter")
        for proto, count in sorted(snap["events_per_protocol"].items()):
            lines.append(
                f'eventhorizon_protocol_events_total{{protocol="{proto}"}} {count}'
            )
        return "\n".join(lines) + "\n"


@dataclass
class Event:
    """A single thing that happened during a session."""

    ts: float
    kind: str  # e.g. "recv", "command", "drip", "open", "close", "limit"
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"ts": self.ts, "kind": self.kind, "detail": self.detail}


@dataclass
class Session:
    """One attacker connection and its event timeline."""

    service: str
    src_ip: str
    src_port: int
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=_now)
    ended_at: Optional[float] = None
    bytes_received: int = 0
    bytes_sent: int = 0
    events: list[Event] = field(default_factory=list)

    def add_event(self, kind: str, **detail: Any) -> Event:
        ev = Event(ts=_now(), kind=kind, detail=detail)
        self.events.append(ev)
        return ev

    def record_recv(self, data: bytes) -> Event:
        self.bytes_received += len(data)
        # Store a safe, bounded, repr of attacker bytes. We NEVER execute these.
        preview = data[:200]
        return self.add_event(
            "recv",
            bytes=len(data),
            preview=preview.decode("latin-1", "replace"),
        )

    def record_command(self, command: str) -> Event:
        return self.add_event("command", command=command[:200])

    def record_drip(self, nbytes: int, delay: float) -> Event:
        self.bytes_sent += nbytes
        return self.add_event("drip", bytes=nbytes, delay=round(delay, 4))

    @property
    def duration(self) -> float:
        end = self.ended_at if self.ended_at is not None else _now()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "service": self.service,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration": round(self.duration, 4),
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "events": [e.to_dict() for e in self.events],
        }


class SessionLogger:
    """Thread/async-safe JSON-lines logger for sessions and events.

    Writes one JSON object per line. ``record_type`` distinguishes between
    per-event records (streamed live) and the final session summary record.

    A :class:`Metrics` instance, if supplied, is updated as records flow through
    so the dashboard never has to re-parse the log.

    Flushing: ``flush_every`` batches stdout/file flushes off the asyncio hot
    path (a 1 byte/50 ms drip would otherwise force a flush per byte). Session
    summaries always force a flush so a tail/SSE consumer sees completed
    sessions promptly.
    """

    def __init__(
        self,
        stream: Optional[TextIO] = None,
        path: Optional[str] = None,
        metrics: Optional[Metrics] = None,
        flush_every: int = 1,
    ):
        self._lock = threading.Lock()
        self._own_stream = False
        self._closed = False
        self.metrics = metrics
        self._flush_every = max(1, int(flush_every))
        self._since_flush = 0
        if path:
            self._stream: TextIO = open(path, "a", encoding="utf-8")
            self._own_stream = True
        else:
            self._stream = stream if stream is not None else sys.stdout

    def _write(self, obj: dict[str, Any], force_flush: bool = False) -> None:
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            if self._closed:
                return
            self._stream.write(line + "\n")
            self._since_flush += 1
            if force_flush or self._since_flush >= self._flush_every:
                self._stream.flush()
                self._since_flush = 0

    def log_event(self, session: Session, event: Event) -> None:
        if self.metrics is not None:
            self.metrics.record_event(session.service, event.kind, event.detail)
        self._write(
            {
                "record_type": "event",
                "session_id": session.session_id,
                "service": session.service,
                "src_ip": session.src_ip,
                "src_port": session.src_port,
                **event.to_dict(),
            }
        )

    def log_session(self, session: Session) -> None:
        # A completed session is a milestone — always flush so consumers see it.
        self._write({"record_type": "session", **session.to_dict()}, force_flush=True)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._stream.flush()
            except Exception:
                pass
            if self._own_stream:
                self._stream.close()
