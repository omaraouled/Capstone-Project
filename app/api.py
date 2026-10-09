from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from .storage import init_db, list_events, list_alerts, update_alert_status
from .validation import ALLOWED_STATUSES

app = FastAPI(title="Security Analysis and Detection API", version="0.1.0")

class AlertStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=30)

    @field_validator("status")
    @classmethod
    def valid_status(cls, value):
        if value not in ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(ALLOWED_STATUSES)}")
        return value

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/events")
def get_events(limit: int = Query(default=100, ge=1, le=1000)):
    return list_events(limit)

@app.get("/alerts")
def get_alerts(limit: int = Query(default=100, ge=1, le=1000)):
    return list_alerts(limit)

@app.patch("/alerts/{alert_id}/status")
def patch_alert_status(alert_id: int, update: AlertStatusUpdate):
    if alert_id < 1:
        raise HTTPException(status_code=422, detail="alert_id must be positive")
    if not update_alert_status(alert_id, update.status):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_id": alert_id, "status": update.status}
