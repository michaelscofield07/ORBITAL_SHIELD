import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone
import uuid
import sys
import sqlite3
from pathlib import Path

# Add audit-service to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app
from schemas import SecurityEvent, Severity, Action
import storage

client = TestClient(app)

@pytest.fixture(autouse=True, scope="module")
def setup_test_db(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("audit_test")
    test_db = tmp_dir / "test_audit.db"
    orig_db = storage.DB_PATH
    storage.DB_PATH = test_db
    storage.init_db()
    yield test_db
    storage.DB_PATH = orig_db

def test_audit_health_and_root():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "running" in r_root.json()["status"].lower()

def test_ingest_and_retrieve_event():
    evt_id = f"EVT-TEST-{uuid.uuid4().hex[:6].upper()}"
    payload = {
        "event_id": evt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "DOWNLINK",
        "satellite_id": "SAT-TEST-01",
        "event_type": "TELEMETRY_ANOMALY",
        "severity": "HIGH",
        "confidence": 0.95,
        "description": "Integration test anomaly",
        "action": "REVIEW",
        "evidence": {"temperature": 85.0}
    }

    r_post = client.post("/audit/events", json=payload)
    assert r_post.status_code == 200
    data = r_post.json()
    assert data["status"] == "stored"
    assert data["event_id"] == evt_id
    assert "record_hash" in data

    r_get = client.get("/audit/events")
    assert r_get.status_code == 200
    events = r_get.json()
    assert any(e["event_id"] == evt_id for e in events)

def test_audit_hash_chain_verify():
    # Verify chain is intact
    r = client.get("/audit/verify")
    assert r.status_code == 200
    data = r.json()
    assert "valid" in data
    assert data["valid"] is True
    assert "Chain intact" in data["message"]

def test_review_and_status():
    evt_id = f"EVT-REV-{uuid.uuid4().hex[:6].upper()}"
    client.post("/audit/events", json={
        "event_id": evt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "UPLINK",
        "satellite_id": "SAT-TEST-01",
        "event_type": "UNAUTHORIZED_COMMAND",
        "severity": "CRITICAL",
        "confidence": 1.0,
        "description": "Unauthorized command review test",
        "action": "ALERT",
        "evidence": {}
    })

    r_rev = client.post(
        f"/audit/{evt_id}/review",
        params={
            "status": "RESOLVED",
            "reviewed_by": "lead_soc_analyst",
            "notes": "Reviewed and acknowledged by analyst"
        }
    )
    assert r_rev.status_code == 200
    assert r_rev.json()["review_status"] == "RESOLVED"

    r_stat = client.get(f"/audit/{evt_id}/status")
    assert r_stat.status_code == 200
    assert r_stat.json()["review_status"] == "RESOLVED"

def test_tampering_detection():
    # Temporarily tamper a record
    conn = sqlite3.connect(storage.DB_PATH)
    conn.execute("UPDATE audit_events SET event_json = REPLACE(event_json, 'Integration test anomaly', 'Tampered data')")
    conn.commit()
    conn.close()

    r = client.get("/audit/verify")
    assert r.status_code == 200
    assert r.json()["valid"] is False
    assert "Tampering detected" in r.json()["message"]

    # Revert tampering
    conn = sqlite3.connect(storage.DB_PATH)
    conn.execute("UPDATE audit_events SET event_json = REPLACE(event_json, 'Tampered data', 'Integration test anomaly')")
    conn.commit()
    conn.close()

    r_restored = client.get("/audit/verify")
    assert r_restored.status_code == 200
    assert r_restored.json()["valid"] is True
