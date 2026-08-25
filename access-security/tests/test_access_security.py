"""
ORBITAL SHIELD — Access Security Module Unit & Integration Tests.
Tests all 7 required detection & operational scenarios:
1. Normal successful login
2. Repeated failed logins (Brute force detection)
3. Unknown / Untrusted device detection
4. Suspicious login time (Off-hours access)
5. Privilege escalation detection
6. Suspicious command / sensitive resource access
7. SecurityEvent schema validation & ML Brain graceful fallback
8. Invalid / missing input handling
"""

from __future__ import annotations
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

import sys
BASE_DIR = Path(__file__).parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from models.schemas import (
    AccessLogRecord,
    SecurityEvent,
    SeverityLevel,
    ActionType,
    AccessAnalysisRequest,
)
from core.engine import AccessSecurityEngine
from core.adapter import (
    MockJSONInputAdapter,
    Person1APIInputAdapter,
    Person1APIAdapterPlaceholder,
    map_api_record_to_access_log,
)
from core.event_generator import EventGenerator
from main import app, MOCK_DATA_PATH


@pytest.fixture
def engine():
    eng = AccessSecurityEngine()
    eng.reset_state()
    return eng


# ─────────────────────────────────────────────────────────────
# 1. NORMAL SUCCESSFUL LOGIN TEST
# ─────────────────────────────────────────────────────────────

def test_normal_login(engine):
    record = AccessLogRecord(
        timestamp="2026-08-25T09:30:00Z",
        user_id="operator_01",
        source_ip="10.0.0.15",
        device_id="GS-DEVICE-01",
        action="LOGIN",
        result="SUCCESS",
        role="operator"
    )
    result = engine.evaluate_record(record)
    assert result.is_suspicious is False
    assert result.event_type == "AUTHENTICATION_SUCCESS"
    assert result.severity == SeverityLevel.INFO
    assert result.action == ActionType.LOG
    
    event = EventGenerator.generate_security_event(result)
    assert event.source == "ACCESS"
    assert event.severity == "INFO"
    assert event.action == "LOG"


# ─────────────────────────────────────────────────────────────
# 2. REPEATED FAILED LOGINS (BRUTE FORCE) TEST
# ─────────────────────────────────────────────────────────────

def test_repeated_failed_logins(engine):
    attacker_ip = "192.168.1.100"
    user = "user_attacker"
    
    # 2 failures below threshold (threshold is 3)
    rec1 = AccessLogRecord(timestamp="2026-08-25T10:00:00Z", user_id=user, source_ip=attacker_ip, device_id="GS-DEVICE-01", action="LOGIN", result="FAILURE", role="operator")
    rec2 = AccessLogRecord(timestamp="2026-08-25T10:00:05Z", user_id=user, source_ip=attacker_ip, device_id="GS-DEVICE-01", action="LOGIN", result="FAILURE", role="operator")
    
    res1 = engine.evaluate_record(rec1)
    res2 = engine.evaluate_record(rec2)
    assert res1.is_suspicious is False
    assert res2.is_suspicious is False
    
    # 3rd failure reaches threshold
    rec3 = AccessLogRecord(timestamp="2026-08-25T10:00:10Z", user_id=user, source_ip=attacker_ip, device_id="GS-DEVICE-01", action="LOGIN", result="FAILURE", role="operator")
    res3 = engine.evaluate_record(rec3)
    
    assert res3.is_suspicious is True
    assert res3.event_type == "BRUTE_FORCE"
    assert res3.severity == SeverityLevel.HIGH
    assert res3.action == ActionType.REVIEW
    assert res3.evidence["failed_attempts"] == 3


# ─────────────────────────────────────────────────────────────
# 3. UNKNOWN / UNTRUSTED DEVICE TEST
# ─────────────────────────────────────────────────────────────

def test_unknown_device(engine):
    record = AccessLogRecord(
        timestamp="2026-08-25T11:20:00Z",
        user_id="operator_03",
        source_ip="172.16.4.55",
        device_id="UNTRUSTED-DEVICE-999",
        action="LOGIN",
        result="SUCCESS",
        role="operator"
    )
    result = engine.evaluate_record(record)
    assert result.is_suspicious is True
    assert result.event_type == "UNKNOWN_DEVICE"
    assert result.severity == SeverityLevel.MEDIUM
    assert result.action == ActionType.REVIEW


# ─────────────────────────────────────────────────────────────
# 4. SUSPICIOUS LOGIN TIME TEST
# ─────────────────────────────────────────────────────────────

def test_suspicious_login_time(engine):
    # 02:15 UTC is off-hours (default normal is 06:00 to 21:00 UTC)
    record = AccessLogRecord(
        timestamp="2026-08-25T02:15:00Z",
        user_id="operator_night",
        source_ip="10.0.0.22",
        device_id="GS-DEVICE-01",
        action="LOGIN",
        result="SUCCESS",
        role="operator"
    )
    result = engine.evaluate_record(record)
    assert result.is_suspicious is True
    assert result.event_type == "SUSPICIOUS_LOGIN_TIME"
    assert result.severity == SeverityLevel.MEDIUM
    assert result.action == ActionType.MONITOR


# ─────────────────────────────────────────────────────────────
# 5. PRIVILEGE ESCALATION TEST
# ─────────────────────────────────────────────────────────────

def test_privilege_escalation(engine):
    record = AccessLogRecord(
        timestamp="2026-08-25T12:00:00Z",
        user_id="operator_rogue",
        source_ip="10.0.0.45",
        device_id="GS-DEVICE-01",
        action="ROLE_ELEVATION",
        result="SUCCESS",
        role="sysadmin",
        previous_role="operator"
    )
    result = engine.evaluate_record(record)
    assert result.is_suspicious is True
    assert result.event_type == "PRIVILEGE_ESCALATION"
    assert result.severity == SeverityLevel.CRITICAL
    assert result.action == ActionType.HUMAN_REVIEW
    assert result.evidence["previous_role"] == "operator"
    assert result.evidence["new_role"] == "sysadmin"


# ─────────────────────────────────────────────────────────────
# 6. SUSPICIOUS COMMAND ACCESS TEST
# ─────────────────────────────────────────────────────────────

def test_suspicious_command_access(engine):
    record = AccessLogRecord(
        timestamp="2026-08-25T13:45:00Z",
        user_id="operator_05",
        source_ip="10.0.0.50",
        device_id="GS-DEVICE-01",
        action="PAYLOAD_SHUTDOWN",
        resource="SAT-PAYLOAD-01",
        result="SUCCESS",
        role="operator"
    )
    result = engine.evaluate_record(record)
    assert result.is_suspicious is True
    assert result.event_type == "UNAUTHORIZED_COMMAND"
    assert result.severity == SeverityLevel.CRITICAL
    assert result.action == ActionType.ALERT


# ─────────────────────────────────────────────────────────────
# 7. SECURITY EVENT GENERATION & ML BRAIN FALLBACK TEST
# ─────────────────────────────────────────────────────────────

def test_security_event_generation(engine):
    record = AccessLogRecord(
        timestamp="2026-08-25T09:30:00Z",
        user_id="operator_01",
        source_ip="10.0.0.15",
        device_id="GS-DEVICE-01",
        action="LOGIN",
        result="SUCCESS",
        role="operator",
        satellite_id="SAT-EO-01"
    )
    detection = engine.evaluate_record(record)
    event = EventGenerator.generate_security_event(detection, satellite_id="SAT-EO-01")

    assert event.event_id.startswith("EVT-ACC-")
    assert event.source == "ACCESS"
    assert event.satellite_id == "SAT-EO-01"
    assert event.event_type == "AUTHENTICATION_SUCCESS"
    assert event.confidence >= 0.90
    assert "user_id" in event.evidence
    assert event.operator_id == "operator_01"


def test_ml_brain_forwarding_fallback(engine):
    record = AccessLogRecord(
        timestamp="2026-08-25T12:00:00Z",
        user_id="operator_rogue",
        source_ip="10.0.0.45",
        device_id="GS-DEVICE-01",
        action="ROLE_ELEVATION",
        result="SUCCESS",
        role="sysadmin",
        previous_role="operator"
    )
    detection = engine.evaluate_record(record)
    event = EventGenerator.generate_security_event(detection)
    
    # Forwarding to non-existent port 8999 should gracefully return offline status
    res = EventGenerator.forward_to_ml_brain_sync(event, ml_brain_url="http://localhost:8999/events/ingest", timeout=0.5)
    assert res["forwarded"] is False
    assert res["status"] == "OFFLINE"
    assert "ML Brain unavailable" in res["message"]


# ─────────────────────────────────────────────────────────────
# 8. INVALID & MISSING INPUT HANDLING TEST
# ─────────────────────────────────────────────────────────────

def test_invalid_input_handling():
    # Missing required field user_id
    with pytest.raises(ValidationError):
        AccessLogRecord(
            timestamp="2026-08-25T09:30:00Z",
            source_ip="10.0.0.15",
            device_id="GS-DEVICE-01"
        )
    
    # Blank user_id
    with pytest.raises(ValidationError):
        AccessLogRecord(
            timestamp="2026-08-25T09:30:00Z",
            user_id="   ",
            source_ip="10.0.0.15",
            device_id="GS-DEVICE-01"
        )


# ─────────────────────────────────────────────────────────────
# 9. DATA ADAPTER & FASTAPI ENDPOINTS INTEGRATION TEST
# ─────────────────────────────────────────────────────────────

def test_mock_json_adapter():
    adapter = MockJSONInputAdapter(MOCK_DATA_PATH)
    records = adapter.fetch_records()
    assert len(records) > 0
    assert records[0].user_id == "operator_01"


def test_person1_placeholder_adapter():
    placeholder = Person1APIAdapterPlaceholder()
    raw = [
        {
            "id": "P1-REC-01",
            "event_time": "2026-08-25T09:30:00Z",
            "operator_name": "person1_op",
            "ip_address": "10.0.0.99",
            "terminal_id": "GS-DEVICE-01",
            "action": "LOGIN",
            "status": "SUCCESS"
        }
    ]
    parsed = placeholder.parse_raw_records(raw)
    assert len(parsed) == 1
    assert parsed[0].user_id == "person1_op"
    assert parsed[0].source_ip == "10.0.0.99"


# ─────────────────────────────────────────────────────────────
# 10. PERSON 1 API ADAPTER UNIT & MOCK SERVER TESTS
# ─────────────────────────────────────────────────────────────

def test_p1_api_adapter_configuration(monkeypatch):
    monkeypatch.delenv("P1_ACCESS_API_URL", raising=False)
    monkeypatch.delenv("P1_ACCESS_API_KEY", raising=False)
    monkeypatch.delenv("P1_ACCESS_API_KEY_HEADER", raising=False)

    adapter_unconfig = Person1APIInputAdapter()
    assert adapter_unconfig.is_configured() is False
    # Unconfigured adapter returns empty list without error
    assert adapter_unconfig.fetch_records() == []

    monkeypatch.setenv("P1_ACCESS_API_URL", "http://localhost:8001/api/telemetry")
    monkeypatch.setenv("P1_ACCESS_API_KEY", "secret_key_123")
    monkeypatch.setenv("P1_ACCESS_API_KEY_HEADER", "X-Custom-Key")

    adapter_config = Person1APIInputAdapter()
    assert adapter_config.is_configured() is True
    assert adapter_config.api_url == "http://localhost:8001/api/telemetry"
    assert adapter_config.api_key == "secret_key_123"
    assert adapter_config.header_name == "X-Custom-Key"


def test_map_api_record_to_access_log():
    raw_api_item = {
        "id": "REC-999",
        "event_time": "2026-08-25T14:00:00Z",
        "operator_name": "sat_operator_1",
        "ip_address": "10.0.0.77",
        "terminal_id": "GS-CONTROL-WORKSTATION-01",
        "event_type": "ROLE_ELEVATION",
        "status": "SUCCESS",
        "role": "sysadmin",
        "previous_role": "operator"
    }
    rec = map_api_record_to_access_log(raw_api_item)
    assert isinstance(rec, AccessLogRecord)
    assert rec.record_id == "REC-999"
    assert rec.timestamp == "2026-08-25T14:00:00Z"
    assert rec.user_id == "sat_operator_1"
    assert rec.source_ip == "10.0.0.77"
    assert rec.device_id == "GS-CONTROL-WORKSTATION-01"
    assert rec.action == "ROLE_ELEVATION"
    assert rec.result == "SUCCESS"
    assert rec.role == "sysadmin"
    assert rec.previous_role == "operator"


def test_p1_api_adapter_mock_server(engine):
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading

    received_headers = {}

    class MockP1Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal received_headers
            received_headers = dict(self.headers)
            if self.path == "/api/access-logs":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                payload = [
                    {
                        "id": "P1-API-REC-01",
                        "event_time": "2026-08-25T15:00:00Z",
                        "operator_name": "p1_user",
                        "ip_address": "10.0.0.88",
                        "terminal_id": "GS-DEVICE-01",
                        "action": "LOGIN",
                        "status": "SUCCESS",
                        "role": "operator"
                    },
                    {
                        "invalid_record": True  # Missing required fields
                    }
                ]
                self.wfile.write(json.dumps(payload).encode("utf-8"))
            elif self.path == "/api/malformed-json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"NOT_VALID_JSON{")
            elif self.path == "/api/500-error":
                self.send_response(500)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), MockP1Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"
        
        # Test 1: Successful response parsing & header verification
        adapter = Person1APIInputAdapter(
            api_url=f"{base_url}/api/access-logs",
            api_key="test_api_key_abc",
            header_name="X-API-Key"
        )
        records = adapter.fetch_records()
        assert len(records) == 1
        assert records[0].user_id == "p1_user"
        assert received_headers.get("X-API-Key") == "test_api_key_abc"

        # Verify Rule Engine compatibility
        detections = engine.evaluate_batch(records)
        assert len(detections) == 1
        assert detections[0].is_suspicious is False
        assert detections[0].event_type == "AUTHENTICATION_SUCCESS"

        # Test 2: Invalid JSON handling (no crash)
        adapter_malformed = Person1APIInputAdapter(
            api_url=f"{base_url}/api/malformed-json",
            api_key="test_api_key_abc"
        )
        records_malformed = adapter_malformed.fetch_records()
        assert records_malformed == []

        # Test 3: HTTP 500 server error handling (no crash)
        adapter_500 = Person1APIInputAdapter(
            api_url=f"{base_url}/api/500-error",
            api_key="test_api_key_abc"
        )
        records_500 = adapter_500.fetch_records()
        assert records_500 == []

        # Test 4: Connection failure / offline endpoint (no crash)
        adapter_offline = Person1APIInputAdapter(
            api_url="http://127.0.0.1:59999/api/offline",
            api_key="test_api_key_abc"
        )
        records_offline = adapter_offline.fetch_records()
        assert records_offline == []

    finally:
        server.shutdown()
        server.server_close()


def test_fastapi_endpoints():
    client = TestClient(app)
    
    # GET /health
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["module"] == "access_security"

    # POST /access/mock/run
    mock_run_resp = client.post("/access/mock/run")
    assert mock_run_resp.status_code == 200
    data = mock_run_resp.json()
    assert data["analyzed_count"] >= 8
    assert data["suspicious_count"] > 0
    assert len(data["events"]) == data["analyzed_count"]

    # GET /access/events
    events_resp = client.get("/access/events")
    assert events_resp.status_code == 200
    assert len(events_resp.json()) >= data["analyzed_count"]

