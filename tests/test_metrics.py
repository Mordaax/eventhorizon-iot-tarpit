"""Metrics counter + Prometheus exposition tests."""

import io

from eventhorizon.session import Metrics, Session, SessionLogger


def test_metrics_count_via_logger():
    metrics = Metrics()
    buf = io.StringIO()
    logger = SessionLogger(stream=buf, metrics=metrics)

    s = Session(service="telnet", src_ip="1.2.3.4", src_port=5555)
    metrics.session_opened(s.service)
    logger.log_event(s, s.add_event("open"))
    logger.log_event(s, s.record_recv(b"root\n"))
    logger.log_event(s, s.record_command("login:root"))
    logger.log_event(s, s.record_command("pass:xc3511"))
    logger.log_event(s, s.record_drip(120, 0.05))
    logger.log_session(s)
    metrics.session_closed()

    snap = metrics.snapshot()
    assert snap["total_sessions"] == 1
    assert snap["active_sessions"] == 0
    assert snap["bytes_received"] == 5
    assert snap["bytes_dripped"] == 120
    # login: + pass: both count as auth attempts.
    assert snap["auth_attempts"] == 2
    assert snap["sessions_per_protocol"]["telnet"] == 1
    assert snap["events_per_protocol"]["telnet"] >= 5


def test_active_sessions_gauge_never_negative():
    metrics = Metrics()
    metrics.session_closed()  # close with nothing open
    assert metrics.snapshot()["active_sessions"] == 0
    metrics.session_opened("http")
    metrics.session_opened("http")
    assert metrics.snapshot()["active_sessions"] == 2
    metrics.session_closed()
    assert metrics.snapshot()["active_sessions"] == 1


def test_prometheus_text_format_is_wellformed():
    metrics = Metrics()
    metrics.session_opened("ssdp")
    metrics.record_event("ssdp", "drip", {"bytes": 64})
    metrics.record_event("ssdp", "recv", {"bytes": 100})
    metrics.record_event("telnet", "command", {"command": "pass:admin"})
    text = metrics.render_prometheus()

    # Every metric line must have a HELP and TYPE comment.
    assert "# HELP eventhorizon_active_sessions" in text
    assert "# TYPE eventhorizon_active_sessions gauge" in text
    assert "eventhorizon_bytes_dripped_total 64" in text
    assert "eventhorizon_bytes_received_total 100" in text
    assert "eventhorizon_auth_attempts_total 1" in text
    assert 'eventhorizon_protocol_sessions_total{protocol="ssdp"} 1' in text
    assert 'eventhorizon_protocol_events_total{protocol="ssdp"}' in text
    # Counter naming convention: *_total suffix on counters.
    for line in text.splitlines():
        if line.startswith("# TYPE") and line.endswith("counter"):
            name = line.split()[2]
            assert name.endswith("_total"), name


def test_metrics_robust_to_missing_detail_fields():
    metrics = Metrics()
    # bytes key absent / None must not raise.
    metrics.record_event("http", "drip", {})
    metrics.record_event("http", "recv", {"bytes": None})
    metrics.record_event("http", "command", {})
    snap = metrics.snapshot()
    assert snap["bytes_dripped"] == 0
    assert snap["bytes_received"] == 0
    assert snap["total_events"] == 3
