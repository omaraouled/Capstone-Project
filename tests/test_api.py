from fastapi.testclient import TestClient
from app.api import app

def test_health():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_status_validation():
    client = TestClient(app)
    response = client.patch("/alerts/1/status", json={"status": 123456})
    assert response.status_code == 422
