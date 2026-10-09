from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any

MAX_MESSAGE_LENGTH = 16_384
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical", "info", "unknown"}
ALLOWED_STATUSES = {"new", "acknowledged", "resolved", "false_positive"}

def parse_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def validate_ip(value: Any, *, optional: bool = True):
    if value is None or value == "":
        if optional:
            return None
        raise ValueError("IP address is required")
    if not isinstance(value, str):
        raise ValueError("IP address must be a string")
    try:
        return str(ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc

def validate_raw_event(raw_event: Any) -> dict:
    if not isinstance(raw_event, dict):
        raise ValueError("raw event must be an object")
    source = raw_event.get("source")
    message = raw_event.get("raw_message")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")
    if not isinstance(message, str) or not message.strip():
        raise ValueError("raw_message must be a non-empty string")
    if len(message) > MAX_MESSAGE_LENGTH:
        raise ValueError(f"raw_message exceeds {MAX_MESSAGE_LENGTH} characters")
    collected_at = raw_event.get("collected_at")
    if collected_at is None:
        collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "source": source.strip()[:100],
        "raw_message": message,
        "collected_at": parse_timestamp(collected_at),
    }
