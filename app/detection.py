from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from .config import SUSPICIOUS_PROCESSES

RULES = [
    {"id": "BRUTE_FORCE_001", "name": "Multiple Failed Logins", "severity": "high",
     "threshold": 5, "window_minutes": 5},
    {"id": "LOGIN_AFTER_FAILURES_002", "name": "Successful Login After Repeated Failures",
     "severity": "high", "threshold": 5, "window_minutes": 5},
    {"id": "SUSPICIOUS_PROCESS_003", "name": "Suspicious Process Observed", "severity": "high"},
]

class DetectionEngine:
    def __init__(self, suspicious_processes=None):
        self.failures_by_ip = defaultdict(deque)
        self.failures_by_account_ip = defaultdict(deque)
        self.suspicious_processes = {
            p.lower() for p in (suspicious_processes if suspicious_processes is not None else SUSPICIOUS_PROCESSES)
        }
        self._already_alerted = set()

    @staticmethod
    def _event_time(event):
        value = event.get("timestamp")
        if not value:
            return datetime.now(timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def evaluate(self, event: dict) -> list[dict]:
        alerts = []
        now = self._event_time(event)
        source_ip = event.get("source_ip")
        user = event.get("user")
        event_type = event.get("event_type")
        message = event.get("message", "")
        process = (event.get("process") or "").lower()

        if event_type == "login_failure" and source_ip:
            cutoff = now - timedelta(minutes=5)
            queue = self.failures_by_ip[source_ip]
            queue.append(now)
            while queue and queue[0] < cutoff:
                queue.popleft()
            key = ("BRUTE_FORCE_001", source_ip, now.strftime("%Y%m%d%H%M"))
            if len(queue) >= 5 and key not in self._already_alerted:
                self._already_alerted.add(key)
                alerts.append(self._alert(
                    "BRUTE_FORCE_001", "Possible Brute Force Attack",
                    f"{len(queue)} failed logins from {source_ip} within five minutes.",
                    "high", 0.90, event, source_ip
                ))
            if user:
                account_queue = self.failures_by_account_ip[(source_ip, user)]
                account_queue.append(now)
                while account_queue and account_queue[0] < cutoff:
                    account_queue.popleft()

        elif event_type == "login_success" and source_ip and user:
            key = (source_ip, user)
            failures = self.failures_by_account_ip.get(key, deque())
            cutoff = now - timedelta(minutes=5)
            while failures and failures[0] < cutoff:
                failures.popleft()
            if len(failures) >= 5:
                alerts.append(self._alert(
                    "LOGIN_AFTER_FAILURES_002", "Successful Login After Repeated Failures",
                    f"Successful login for {user} from {source_ip} followed at least five failures within five minutes.",
                    "high", 0.85, event, source_ip
                ))
                failures.clear()

        if process and process in self.suspicious_processes:
            alerts.append(self._alert(
                "SUSPICIOUS_PROCESS_003", "Suspicious Process Observed",
                f"Configured suspicious process '{process}' was observed.",
                "high", 0.75, event, source_ip
            ))
        else:
            tokens = [token.strip("'\\";,()[]{}") for token in message.lower().split()]
            basenames = {token.rsplit("/", 1)[-1] for token in tokens}
            found = next((p for p in self.suspicious_processes if p in basenames), None)
            if found:
                alerts.append(self._alert(
                    "SUSPICIOUS_PROCESS_003", "Suspicious Process Observed",
                    f"Configured suspicious process '{found}' was mentioned in the event.",
                    "high", 0.70, event, source_ip
                ))
        return alerts

    @staticmethod
    def _alert(rule_id, title, description, severity, confidence, event, source_ip):
        return {
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "rule_id": rule_id,
            "related_event_id": event.get("event_id"),
            "timestamp": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "status": "new",
            "analyst_notes": None,
        }
