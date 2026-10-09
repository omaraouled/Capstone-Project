from .parsers import parse_event
from .detection import DetectionEngine
from .storage import init_db, save_event, save_alert

def process_raw_events(raw_events, db_path=None, engine=None):
    """Process raw events independently; malformed events are skipped without stopping the batch."""
    init_db(db_path)
    engine = engine or DetectionEngine()
    result = {"processed": 0, "invalid": 0, "alerts": []}
    for raw in raw_events:
        try:
            event = parse_event(raw)
            save_event(event, db_path)
            result["processed"] += 1
            for alert in engine.evaluate(event):
                save_alert(alert, db_path)
                result["alerts"].append(alert)
        except (ValueError, TypeError, KeyError):
            result["invalid"] += 1
    return result
