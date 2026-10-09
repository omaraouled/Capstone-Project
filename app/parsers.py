import hashlib
import json
import re
import socket
from datetime import datetime, timezone
from .validation import parse_timestamp, validate_ip, validate_raw_event

SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")

def _timestamp_from_syslog(month: str, day: str, clock: str) -> str:
    now = datetime.now(timezone.utc)
    try:
        parsed = datetime.strptime(f"{now.year} {month} {day} {clock}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return now.isoformat().replace("+00:00", "Z")

def parse_event(raw_event: dict) -> dict:
    """Convert raw log input to a normalized event. Malformed input raises ValueError."""
    raw = validate_raw_event(raw_event)
    message = raw["raw_message"]
    timestamp = raw["collected_at"]
    event_category, event_type = "system", "log_message"
    host, process, user, source_ip = socket.gethostname(), None, None, None
    severity = "info"
    event_message = message

    match = SYSLOG_RE.match(message)
    if match:
        host = match.group("host")
        process = match.group("process")
        event_message = match.group("message")
        timestamp = _timestamp_from_syslog(match.group("month"), match.group("day"), match.group("clock"))

    failed = FAILED_RE.search(event_message)
    accepted = ACCEPTED_RE.search(event_message)
    if failed:
        event_category, event_type, severity = "authentication", "login_failure", "medium"
        user = failed.group("user")
        source_ip = validate_ip(failed.group("ip"), optional=False)
    elif accepted:
        event_category, event_type, severity = "authentication", "login_success", "info"
        user = accepted.group("user")
        source_ip = validate_ip(accepted.group("ip"), optional=False)

    lowered = event_message.lower()
    if any(word in lowered for word in ("error", "failed", "denied", "unauthorized")) and severity == "info":
        severity = "medium"

    event_id = hashlib.sha256(
        f'{raw["source"]}|{timestamp}|{message}'.encode("utf-8", errors="replace")
    ).hexdigest()[:24]

    return {
        "event_id": event_id,
        "timestamp": parse_timestamp(timestamp),
        "event_category": event_category,
        "event_type": event_type,
        "source_device": host,
        "user": user,
        "process": process,
        "source_ip": source_ip,
        "destination_ip": None,
        "severity": severity,
        "message": event_message[:16384],
        "source": raw["source"],
        "detection_status": "new",
    }

def parse_cloudwatch_message(message: str, source: str = "cloudwatch") -> dict:
    """Parse JSON-formatted CloudWatch messages when possible; otherwise parse as text."""
    try:
        data = json.loads(message)
    except (json.JSONDecodeError, TypeError):
        data = None
    if isinstance(data, dict):
        timestamp = data.get("timestamp") or data.get("@timestamp")
        msg = data.get("message") or data.get("log") or message
        raw = {"source": source, "raw_message": str(msg)}
        if isinstance(timestamp, str):
            raw["collected_at"] = timestamp
        return parse_event(raw)
    return parse_event({"source": source, "raw_message": message})
