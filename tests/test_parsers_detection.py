from app.parsers import parse_event
from app.detection import DetectionEngine

def raw(message):
    return {"source": "test", "raw_message": message, "collected_at": "2026-09-26T00:10:00Z"}

def test_failed_login_normalization():
    event = parse_event(raw("Sep 26 00:10:15 server01 sshd[1234]: Failed password for admin from 192.168.1.50 port 22 ssh2"))
    assert event["event_type"] == "login_failure"
    assert event["user"] == "admin"
    assert event["source_ip"] == "192.168.1.50"
    assert event["process"] == "sshd"

def test_brute_force_threshold_triggers_at_five():
    engine = DetectionEngine(suspicious_processes=[])
    alerts = []
    for i in range(5):
        event = parse_event(raw(f"Sep 26 00:10:{10+i:02d} server01 sshd[1234]: Failed password for admin from 192.168.1.50 port 22 ssh2"))
        alerts.extend(engine.evaluate(event))
        if i < 3:
            assert not alerts
    assert any(a["rule_id"] == "BRUTE_FORCE_001" for a in alerts)

def test_sources_are_not_combined():
    engine = DetectionEngine(suspicious_processes=[])
    for i in range(4):
        engine.evaluate(parse_event(raw(f"Sep 26 00:10:{10+i:02d} server01 sshd[1234]: Failed password for admin from 192.168.1.50 port 22 ssh2")))
    for i in range(4):
        alerts = engine.evaluate(parse_event(raw(f"Sep 26 00:11:{10+i:02d} server01 sshd[1234]: Failed password for admin from 192.168.1.51 port 22 ssh2")))
    assert not any(a["rule_id"] == "BRUTE_FORCE_001" for a in alerts)

def test_suspicious_process_rule():
    engine = DetectionEngine(suspicious_processes=["nc"])
    event = parse_event(raw("Sep 26 00:10:15 server01 sudo[1234]: user : COMMAND=/usr/bin/nc -l 4444"))
    alerts = engine.evaluate(event)
    assert any(a["rule_id"] == "SUSPICIOUS_PROCESS_003" for a in alerts)
