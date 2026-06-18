"""Configuration for the EventHorizon tarpit.

All values can be overridden via environment variables (prefix ``EH_``) so the
same image works locally and in Docker without code changes. Defaults are
intentionally safe: bind to ``127.0.0.1`` so the demo never exposes the tarpit
to a real network unless the operator explicitly opts in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Any


def _env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class TarpitConfig:
    """Runtime configuration for all tarpit services.

    Attributes:
        host: Interface to bind. Default ``127.0.0.1`` for safe local demos.
              Set ``EH_HOST=0.0.0.0`` ONLY in an isolated honeynet.
        telnet_port / http_port / ssh_port / ssdp_port: per-service listen ports.
              SSDP is UDP; the others are TCP.
        drip_delay: base seconds between dripped bytes/chunks.
        drip_chunk: bytes emitted per drip step.
        max_session_seconds: hard cap on how long a session may live.
        max_session_bytes: hard cap on bytes read from a single attacker.
        max_connections: global concurrent-connection cap (host protection).
        idle_timeout: seconds to wait for attacker input before nudging.
        adaptive_enabled: enable the bio-inspired latency adaptation.
        adaptive_max_multiplier: ceiling on how much the drip can slow down.
        log_file: path for structured JSON-lines session log (None = stdout).
        log_flush_every: flush the JSONL stream after at most this many writes
              (1 = flush every write; >1 batches flushes to keep disk I/O off the
              event loop's hot path). A session-summary write always forces a
              flush so consumers never miss a completed session.
        otel_enabled: attempt to wire OpenTelemetry (no-ops if not installed).
        otel_endpoint: OTLP collector endpoint (gRPC).
        service_name: OTel ``service.name`` resource attribute.
        dashboard_enabled: start the optional live SSE + Prometheus dashboard.
        dashboard_port: port for the dashboard HTTP server.
    """

    host: str = field(default_factory=lambda: _env_str("EH_HOST", "127.0.0.1"))
    telnet_port: int = field(default_factory=lambda: _env_int("EH_TELNET_PORT", 2323))
    http_port: int = field(default_factory=lambda: _env_int("EH_HTTP_PORT", 8080))
    ssh_port: int = field(default_factory=lambda: _env_int("EH_SSH_PORT", 2222))
    ssdp_port: int = field(default_factory=lambda: _env_int("EH_SSDP_PORT", 1900))

    drip_delay: float = field(default_factory=lambda: _env_float("EH_DRIP_DELAY", 0.05))
    drip_chunk: int = field(default_factory=lambda: _env_int("EH_DRIP_CHUNK", 1))

    max_session_seconds: float = field(
        default_factory=lambda: _env_float("EH_MAX_SESSION_SECONDS", 120.0)
    )
    max_session_bytes: int = field(
        default_factory=lambda: _env_int("EH_MAX_SESSION_BYTES", 65536)
    )
    max_connections: int = field(
        default_factory=lambda: _env_int("EH_MAX_CONNECTIONS", 200)
    )
    idle_timeout: float = field(
        default_factory=lambda: _env_float("EH_IDLE_TIMEOUT", 30.0)
    )

    adaptive_enabled: bool = field(
        default_factory=lambda: _env_bool("EH_ADAPTIVE_ENABLED", True)
    )
    adaptive_max_multiplier: float = field(
        default_factory=lambda: _env_float("EH_ADAPTIVE_MAX_MULTIPLIER", 8.0)
    )

    log_file: str | None = field(
        default_factory=lambda: os.environ.get("EH_LOG_FILE")
    )
    log_flush_every: int = field(
        default_factory=lambda: _env_int("EH_LOG_FLUSH_EVERY", 1)
    )

    otel_enabled: bool = field(
        default_factory=lambda: _env_bool("EH_OTEL_ENABLED", True)
    )
    otel_endpoint: str = field(
        default_factory=lambda: _env_str(
            "EH_OTEL_ENDPOINT", "http://localhost:4317"
        )
    )
    service_name: str = field(
        default_factory=lambda: _env_str("EH_SERVICE_NAME", "eventhorizon-tarpit")
    )

    dashboard_enabled: bool = field(
        default_factory=lambda: _env_bool("EH_DASHBOARD_ENABLED", False)
    )
    dashboard_port: int = field(
        default_factory=lambda: _env_int("EH_DASHBOARD_PORT", 8090)
    )

    def __post_init__(self) -> None:
        # Defensive clamps: an operator (or a bad env var) can never configure
        # the tarpit into a host-dangerous or nonsensical state.
        self.drip_delay = max(0.0, float(self.drip_delay))
        self.drip_chunk = max(1, int(self.drip_chunk))
        self.max_session_seconds = max(0.1, float(self.max_session_seconds))
        self.max_session_bytes = max(1, int(self.max_session_bytes))
        self.max_connections = max(1, int(self.max_connections))
        self.idle_timeout = max(0.1, float(self.idle_timeout))
        self.adaptive_max_multiplier = max(1.0, float(self.adaptive_max_multiplier))
        self.log_flush_every = max(1, int(self.log_flush_every))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
