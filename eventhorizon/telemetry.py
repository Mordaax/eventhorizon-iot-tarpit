"""OpenTelemetry integration with a graceful no-op shim.

The whole point of this module is that the core tarpit + tests run with **zero
third-party dependencies**. If the ``opentelemetry`` packages are not installed
(e.g. the build host is offline), every call here degrades to a cheap no-op so
nothing crashes and the tarpit keeps recording sessions to its JSON log.

Usage::

    from eventhorizon.telemetry import Telemetry
    tel = Telemetry.from_config(config)
    with tel.session_span("telnet", "10.0.0.1", 5555) as span:
        span.add_event("recv", {"bytes": 12})

When OTel *is* installed and ``otel_enabled`` is true, this emits one span per
attacker session with child span-events per interaction.
"""

from __future__ import annotations

import contextlib
from typing import Any, Iterator, Optional

# ---------------------------------------------------------------------------
# Optional import. We probe for the OTel API/SDK and remember whether it worked.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised implicitly depending on environment
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.resources import Resource as _Resource
    from opentelemetry.sdk.trace import TracerProvider as _TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor as _BatchSpanProcessor,
        ConsoleSpanExporter as _ConsoleSpanExporter,
        SimpleSpanProcessor as _SimpleSpanProcessor,
    )

    _OTEL_AVAILABLE = True
except Exception:  # ImportError or partial install
    _OTEL_AVAILABLE = False


def otel_available() -> bool:
    """Return True if the OpenTelemetry SDK is importable."""
    return _OTEL_AVAILABLE


class _NoopSpan:
    """A span that records nothing but satisfies the span protocol we use."""

    __slots__ = ()

    def add_event(self, name: str, attributes: Optional[dict[str, Any]] = None) -> None:
        return None

    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        return None

    def record_exception(self, *args: Any, **kwargs: Any) -> None:
        return None


class Telemetry:
    """Facade over OpenTelemetry that is safe to use even when OTel is absent.

    Construct via :meth:`from_config`. The object is cheap and thread/async safe
    for the operations we perform (span creation + event recording).
    """

    def __init__(self, tracer: Any = None, enabled: bool = False, backend: str = "noop"):
        self._tracer = tracer
        self._enabled = enabled
        self.backend = backend  # "otel-console", "otel-otlp", or "noop"

    @property
    def enabled(self) -> bool:
        return self._enabled

    @classmethod
    def from_config(cls, config: Any) -> "Telemetry":
        """Build a Telemetry instance from a TarpitConfig-like object.

        Falls back to the no-op shim if OTel is unavailable, disabled, or if any
        part of SDK setup raises.
        """
        if not getattr(config, "otel_enabled", False) or not _OTEL_AVAILABLE:
            return cls(tracer=None, enabled=False, backend="noop")

        try:
            resource = _Resource.create(
                {"service.name": getattr(config, "service_name", "eventhorizon-tarpit")}
            )
            provider = _TracerProvider(resource=resource)

            backend = "otel-console"
            exporter: Any = None
            # OTLP uses an async BatchSpanProcessor (correct for production);
            # the console exporter uses a synchronous SimpleSpanProcessor so it
            # never flushes to stdout from a background thread at shutdown.
            processor: Any = None
            endpoint = getattr(config, "otel_endpoint", "")
            if endpoint:
                # OTLP exporter is itself optional; fall back to console.
                try:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )

                    exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
                    processor = _BatchSpanProcessor(exporter)
                    backend = "otel-otlp"
                except Exception:
                    exporter = _ConsoleSpanExporter()
                    processor = _SimpleSpanProcessor(exporter)
                    backend = "otel-console"
            else:
                exporter = _ConsoleSpanExporter()
                processor = _SimpleSpanProcessor(exporter)

            provider.add_span_processor(processor)
            _otel_trace.set_tracer_provider(provider)
            tracer = _otel_trace.get_tracer("eventhorizon")
            return cls(tracer=tracer, enabled=True, backend=backend)
        except Exception:
            # Never let telemetry setup take down the honeypot.
            return cls(tracer=None, enabled=False, backend="noop")

    @contextlib.contextmanager
    def session_span(
        self, service: str, src_ip: str, src_port: int, session_id: str = ""
    ) -> Iterator[Any]:
        """Yield a span representing one attacker session.

        If OTel is unavailable this yields a :class:`_NoopSpan` so callers can
        unconditionally call ``span.add_event(...)``.
        """
        if not self._enabled or self._tracer is None:
            yield _NoopSpan()
            return

        with self._tracer.start_as_current_span(f"session.{service}") as span:
            try:
                span.set_attribute("eventhorizon.service", service)
                span.set_attribute("eventhorizon.src.ip", src_ip)
                span.set_attribute("eventhorizon.src.port", src_port)
                if session_id:
                    span.set_attribute("eventhorizon.session.id", session_id)
            except Exception:
                pass
            yield span
