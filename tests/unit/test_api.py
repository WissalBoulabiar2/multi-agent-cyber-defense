from fastapi.testclient import TestClient

from mcd.api.main import app


def test_health_and_no_simulation_yet():
    with TestClient(app) as c:
        assert c.get("/health").json()["ok"] is True
        assert c.get("/simulation/status").json()["running"] is False
        assert c.get("/agents").json() == []
        assert c.get("/alerts").status_code == 404
        assert c.post("/approvals/x", json={"approved": True}).status_code == 404


def test_start_request_validation():
    with TestClient(app) as c:
        assert c.post("/simulation/start", json={"strategy": "nonsense"}).status_code == 422
