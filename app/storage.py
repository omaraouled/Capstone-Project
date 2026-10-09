import json
import sqlite3
from .config import DATABASE_PATH

def connect(db_path=None):
    connection = sqlite3.connect(db_path or DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection

def init_db(db_path=None):
    with connect(db_path) as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT NOT NULL,
            source_ip TEXT,
            user TEXT,
            severity TEXT NOT NULL,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            rule_id TEXT NOT NULL,
            related_event_id TEXT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            analyst_notes TEXT,
            FOREIGN KEY(related_event_id) REFERENCES events(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        """)

def save_event(event, db_path=None):
    with connect(db_path) as con:
        con.execute("""INSERT OR IGNORE INTO events
            (event_id, timestamp, event_type, source, source_ip, user, severity, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event["event_id"], event["timestamp"], event["event_type"], event["source"],
             event.get("source_ip"), event.get("user"), event["severity"],
             json.dumps(event, ensure_ascii=False)))

def save_alert(alert, db_path=None):
    with connect(db_path) as con:
        cur = con.execute("""INSERT INTO alerts
            (title, description, severity, confidence, rule_id, related_event_id,
             timestamp, source_ip, status, analyst_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert["title"], alert["description"], alert["severity"], alert["confidence"],
             alert["rule_id"], alert.get("related_event_id"), alert["timestamp"],
             alert.get("source_ip"), alert.get("status", "new"), alert.get("analyst_notes")))
        return cur.lastrowid

def list_events(limit=100, db_path=None):
    limit = max(1, min(int(limit), 1000))
    with connect(db_path) as con:
        rows = con.execute("SELECT payload FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [json.loads(row["payload"]) for row in rows]

def list_alerts(limit=100, db_path=None):
    limit = max(1, min(int(limit), 1000))
    with connect(db_path) as con:
        rows = con.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]

def update_alert_status(alert_id: int, status: str, db_path=None):
    with connect(db_path) as con:
        cur = con.execute("UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id))
        return cur.rowcount > 0
