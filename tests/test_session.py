"""Session model + structured JSON logging tests."""

import io
import json

from eventhorizon.session import Session, SessionLogger


def test_session_records_events_and_bytes():
    s = Session(service="telnet", src_ip="10.0.0.5", src_port=5555)
    s.record_recv(b"root\n")
    s.record_command("login:root")
    s.record_drip(10, 0.05)
    kinds = [e.kind for e in s.events]
    assert "recv" in kinds
    assert "command" in kinds
    assert "drip" in kinds
    assert s.bytes_received == 5
    assert s.bytes_sent == 10


def test_session_never_executes_input_just_records_preview():
    s = Session(service="telnet", src_ip="x", src_port=1)
    ev = s.record_recv(b"; rm -rf / #")
    # The dangerous string is stored as an inert preview only.
    assert ev.detail["preview"] == "; rm -rf / #"
    assert ev.detail["bytes"] == len(b"; rm -rf / #")


def test_session_to_dict_is_json_serialisable():
    s = Session(service="http", src_ip="1.1.1.1", src_port=80)
    s.record_recv(b"GET / HTTP/1.1")
    d = s.to_dict()
    json.dumps(d)  # must not raise
    assert d["service"] == "http"
    assert d["src_ip"] == "1.1.1.1"
    assert "events" in d


def test_logger_emits_jsonlines():
    buf = io.StringIO()
    logger = SessionLogger(stream=buf)
    s = Session(service="ssh", src_ip="2.2.2.2", src_port=22)
    ev = s.record_recv(b"hello")
    logger.log_event(s, ev)
    logger.log_session(s)

    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    event_rec = json.loads(lines[0])
    sess_rec = json.loads(lines[1])
    assert event_rec["record_type"] == "event"
    assert event_rec["kind"] == "recv"
    assert sess_rec["record_type"] == "session"
    assert sess_rec["session_id"] == s.session_id
