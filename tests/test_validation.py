import pytest
from app.validation import validate_raw_event, parse_timestamp, validate_ip

def test_valid_raw_event():
    event = validate_raw_event({"source": "file", "raw_message": "hello", "collected_at": "2026-09-26T00:00:00Z"})
    assert event["source"] == "file"
    assert event["raw_message"] == "hello"

@pytest.mark.parametrize("event", [
    None, {}, {"source": "file", "raw_message": ""},
    {"source": "", "raw_message": "message"},
    {"source": "file", "raw_message": "x" * 20000},
    {"source": "file", "raw_message": "message", "collected_at": "not-a-time"},
])
def test_invalid_raw_events(event):
    with pytest.raises(ValueError):
        validate_raw_event(event)

def test_invalid_ip():
    with pytest.raises(ValueError):
        validate_ip("999.1.1.1", optional=False)

def test_naive_timestamp_becomes_utc():
    assert parse_timestamp("2026-09-26T00:00:00").endswith("Z")
