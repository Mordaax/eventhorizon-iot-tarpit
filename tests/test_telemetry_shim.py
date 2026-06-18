"""Telemetry must work whether or not OpenTelemetry is installed.

These tests assert the no-op shim behaviour so the core tarpit + tests run with
zero third-party deps.
"""

from eventhorizon.config import TarpitConfig
from eventhorizon.telemetry import Telemetry, otel_available


def _no_endpoint_config() -> TarpitConfig:
    # Clear the OTLP endpoint so, when OTel IS installed, tests use the console
    # exporter and never try to reach a (non-existent) collector during CI.
    cfg = TarpitConfig()
    cfg.otel_endpoint = ""
    return cfg


def test_telemetry_constructs_without_otel():
    # Even if OTel is absent, from_config must return a usable object.
    tel = Telemetry.from_config(_no_endpoint_config())
    assert tel is not None
    assert tel.backend in {"noop", "otel-console", "otel-otlp"}


def test_session_span_is_context_manager_and_records_events():
    tel = Telemetry.from_config(_no_endpoint_config())
    # Should never raise regardless of backend.
    with tel.session_span("telnet", "10.0.0.1", 4444, "abc123") as span:
        span.add_event("recv", {"bytes": 12})
        span.set_attribute("k", "v")
        span.add_event("command")


def test_disabled_telemetry_is_noop():
    cfg = TarpitConfig()
    cfg.otel_enabled = False
    tel = Telemetry.from_config(cfg)
    assert tel.enabled is False
    assert tel.backend == "noop"
    with tel.session_span("http", "1.2.3.4", 80) as span:
        # No-op span swallows everything.
        span.add_event("x", {"a": 1})


def test_otel_available_returns_bool():
    assert isinstance(otel_available(), bool)
