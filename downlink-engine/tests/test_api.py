"""Integration tests for FastAPI REST endpoints and WebSocket stream."""

import pytest
import json
from fastapi.testclient import TestClient

from app.utils.hashing import compute_telemetry_hash


def test_health_endpoint(client: TestClient):
    """GET /health returns healthy status and module metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["module"] == "downlink-engine"
    assert data["model_loaded"] is True
    assert data["database"] == "connected"


def test_analyze_normal_telemetry(client: TestClient):
    """POST /downlink/analyze with normal telemetry packet."""
    payload = {
        "timestamp": "2026-08-25T02:14:30Z",
        "satellite_id": "SAT-EO-01",
        "sequence_number": 1001,
        "temperature": 23.5,
        "battery": 88.0,
        "signal_strength": -70.5,
        "latitude": 11.0168,
        "longitude": 76.9558
    }
    payload["packet_hash"] = compute_telemetry_hash(payload)

    response = client.post("/downlink/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "PROCESSED"
    assert data["integrity"]["integrity_status"] == "VALID"
    assert data["anomaly"]["is_anomaly"] is False
    assert data["security_event"] is None


def test_analyze_anomalous_telemetry(client: TestClient):
    """POST /downlink/analyze with thermal anomaly generates a SecurityEvent."""
    payload = {
        "timestamp": "2026-08-25T02:14:30Z",
        "satellite_id": "SAT-EO-01",
        "sequence_number": 1002,
        "temperature": 82.0,
        "battery": 88.0,
        "signal_strength": -70.5,
        "latitude": 11.0168,
        "longitude": 76.9558
    }
    payload["packet_hash"] = compute_telemetry_hash(payload)

    response = client.post("/downlink/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["anomaly"]["is_anomaly"] is True
    assert data["security_event"] is not None
    assert data["security_event"]["source"] == "DOWNLINK"
    assert data["security_event"]["severity"] in ("HIGH", "CRITICAL")
    assert data["security_event"]["action"] == "REVIEW"


def test_get_events_endpoint(client: TestClient):
    """GET /downlink/events returns recorded security events with filtering."""
    # Trigger an anomalous packet to store an event
    payload = {
        "timestamp": "2026-08-25T02:14:30Z",
        "satellite_id": "SAT-EO-01",
        "sequence_number": 2001,
        "temperature": 85.0,
        "battery": 88.0,
        "signal_strength": -70.5
    }
    client.post("/downlink/analyze", json=payload)

    # Query events
    response = client.get("/downlink/events?satellite_id=SAT-EO-01")
    assert response.status_code == 200
    events = response.json()
    assert len(events) >= 1
    assert events[0]["satellite_id"] == "SAT-EO-01"


def test_get_daily_report_endpoint(client: TestClient):
    """GET /downlink/report generates comprehensive summary report."""
    # Submit one normal and one anomaly
    p1 = {
        "timestamp": "2026-08-25T02:00:00Z",
        "satellite_id": "SAT-EO-01",
        "sequence_number": 3001,
        "temperature": 23.0,
        "battery": 88.0,
        "signal_strength": -70.0
    }
    p2 = {
        "timestamp": "2026-08-25T02:00:06Z",
        "satellite_id": "SAT-EO-01",
        "sequence_number": 3002,
        "temperature": 85.0,
        "battery": 88.0,
        "signal_strength": -70.0
    }
    client.post("/downlink/analyze", json=p1)
    client.post("/downlink/analyze", json=p2)

    response = client.get("/downlink/report?satellite_id=SAT-EO-01&date=2026-08-25")
    assert response.status_code == 200
    report = response.json()

    assert report["satellite_id"] == "SAT-EO-01"
    assert report["total_telemetry_packets"] >= 2
    assert "severity_distribution" in report
    assert "recommendations" in report
    assert len(report["recommendations"]) > 0


def test_status_endpoint(client: TestClient):
    """GET /downlink/status returns operational statistics."""
    response = client.get("/downlink/status")
    assert response.status_code == 200
    data = response.json()
    assert "satellite_id" in data
    assert "total_packets_processed" in data
    assert "model_loaded" in data


def test_validation_error_handling(client: TestClient):
    """POST /downlink/analyze with invalid schema returns 422 error."""
    # Missing required temperature, battery, signal_strength
    invalid_payload = {
        "timestamp": "invalid_date_format",
        "satellite_id": "SAT-EO-01",
        "sequence_number": -5  # ge=0 violation
    }
    response = client.post("/downlink/analyze", json=invalid_payload)
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "VALIDATION_ERROR"


def test_websocket_streaming(client: TestClient):
    """WS /downlink/stream establishes connection and processes streaming telemetry."""
    payload = {
        "timestamp": "2026-08-25T02:00:00Z",
        "satellite_id": "SAT-EO-01",
        "sequence_number": 4001,
        "temperature": 23.5,
        "battery": 88.0,
        "signal_strength": -70.0
    }

    with client.websocket_connect("/downlink/stream") as websocket:
        websocket.send_text(json.dumps(payload))
        data_text = websocket.receive_text()
        data = json.loads(data_text)

        assert data["status"] == "PROCESSED"
        assert data["telemetry"]["sequence_number"] == 4001
        assert data["integrity"]["integrity_status"] == "VALID"
