from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from .validation import validate_raw_event

def collect_file(path: str, source: str = "file") -> Iterator[dict]:
    """Read an existing log file line by line; each line becomes a raw event."""
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                yield validate_raw_event({
                    "source": source,
                    "raw_message": line.rstrip("\r\n"),
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                })

def collect_linux_syslog(paths=("/var/log/syslog", "/var/log/auth.log")) -> Iterator[dict]:
    """Read available Linux syslog files. Permission/missing-file errors are skipped."""
    for path in paths:
        try:
            yield from collect_file(path, source="linux_syslog")
        except (OSError, UnicodeError):
            continue

def collect_cloudwatch(log_group: str, start_minutes: int = 60, region: str | None = None) -> Iterator[dict]:
    """Retrieve recent CloudWatch log events using boto3 and the default AWS credential chain."""
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("Install boto3 to use CloudWatch collection") from exc
    if not log_group or not log_group.strip():
        raise ValueError("log_group is required")
    if not 1 <= start_minutes <= 10080:
        raise ValueError("start_minutes must be between 1 and 10080")
    kwargs = {}
    if region:
        kwargs["region_name"] = region
    client = boto3.client("logs", **kwargs)
    start_ms = int((datetime.now(timezone.utc) - timedelta(minutes=start_minutes)).timestamp() * 1000)
    paginator = client.get_paginator("filter_log_events")
    for page in paginator.paginate(logGroupName=log_group, startTime=start_ms):
        for event in page.get("events", []):
            message = event.get("message", "")
            if message.strip():
                yield validate_raw_event({
                    "source": "cloudwatch",
                    "raw_message": message,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                })
