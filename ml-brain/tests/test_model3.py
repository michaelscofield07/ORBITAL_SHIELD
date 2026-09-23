"""
ORBITAL SHIELD — MODEL 3 TEST SUITE
Verification of:
  1. core/llm_client:
     - strip_thinking (<think>...</think> stripping for DeepSeek-R1)
     - extract_json (handles raw, markdown fenced, and nested JSON)
     - generate_with_fallback (mocked Ollama primary success, fallback success, both fail)
  2. core/model3_recovery:
     - _deterministic_recovery_guidance across security domains (UPLINK, FIRMWARE, ACCESS, DOWNLINK)
     - generate_recovery_guidance (LLM path vs. deterministic fallback)
     - run_model3_pipeline (coordination of retrain + recovery guidance generation)
  3. API Endpoints via FastAPI TestClient:
     - POST /brain/model3/run
     - GET /correlations/{id}/recovery-guidance
     - POST /correlations/{id}/recovery-guidance/review
"""

import importlib
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import llm_client, model3_recovery, ingestion
from db import database


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Provides an isolated SQLite database and in-memory sliding window for each test."""
    db_file = tmp_path / "model3_test.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    importlib.reload(database)
    database.init_db()
    ingestion.init_window(window_seconds=1800, max_events=5000)
    yield


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """Provides a TestClient connected to an isolated test database."""
    db_file = tmp_path / "model3_api_test.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    importlib.reload(database)
    database.init_db()
    ingestion.init_window(window_seconds=1800, max_events=5000)

    import main as app_module
    importlib.reload(app_module)
    with TestClient(app_module.app) as client:
        yield client


# ─────────────────────────────────────────────────────────────
# 1. UNIT TESTS: core/llm_client
# ─────────────────────────────────────────────────────────────

class TestLLMClient:
    """Verifies reasoning tag stripping, JSON extraction, and fallback logic."""

    def test_strip_thinking_tags(self):
        sample = "<think>Analyzing TT&C command sequence drift...\nDeep reasoning here</think>{\"affected_domain\": \"UPLINK\"}"
        cleaned = llm_client.strip_thinking(sample)
        assert cleaned == '{"affected_domain": "UPLINK"}'
        assert "<think>" not in cleaned
        assert "</think>" not in cleaned

    def test_strip_thinking_unclosed_tag(self):
        sample = "<think>Model reasoning was cut off..."
        cleaned = llm_client.strip_thinking(sample)
        assert cleaned == ""

    def test_extract_json_direct(self):
        data = {"affected_domain": "DOWNLINK", "residual_risk": "LOW"}
        raw = json.dumps(data)
        extracted = llm_client.extract_json(raw)
        assert extracted == data

    def test_extract_json_markdown_fenced(self):
        raw = "```json\n{\n  \"affected_domain\": \"FIRMWARE\",\n  \"residual_risk\": \"HIGH\"\n}\n```"
        extracted = llm_client.extract_json(raw)
        assert extracted["affected_domain"] == "FIRMWARE"
        assert extracted["residual_risk"] == "HIGH"

    def test_extract_json_with_think_and_preamble(self):
        raw = (
            "<think>Investigating cross-module privilege escalation</think>\n"
            "Here is the recommended guidance:\n"
            "```json\n"
            "{\"affected_domain\": \"ACCESS\", \"confidence\": \"HIGH\"}\n"
            "```\n"
            "End of report."
        )
        extracted = llm_client.extract_json(raw)
        assert extracted["affected_domain"] == "ACCESS"
        assert extracted["confidence"] == "HIGH"

    def test_extract_json_invalid_raises_value_error(self):
        with pytest.raises(ValueError):
            llm_client.extract_json("Not a valid json response at all.")

    @patch("core.llm_client.chat_json")
    def test_generate_with_fallback_primary_success(self, mock_chat):
        mock_chat.return_value = {"affected_domain": "UPLINK", "confidence": "HIGH"}
        result, model_used = llm_client.generate_with_fallback("sys", "user")
        assert result["affected_domain"] == "UPLINK"
        assert model_used == "deepseek-r1:14b"
        mock_chat.assert_called_once()

    @patch("core.llm_client.chat_json")
    def test_generate_with_fallback_secondary_success(self, mock_chat):
        # First call fails (primary), second call succeeds (fallback)
        mock_chat.side_effect = [
            RuntimeError("Primary deepseek-r1:14b connection refused"),
            {"affected_domain": "FIRMWARE", "confidence": "MEDIUM"}
        ]
        result, model_used = llm_client.generate_with_fallback("sys", "user")
        assert result["affected_domain"] == "FIRMWARE"
        assert model_used == "qwen3:14b"
        assert mock_chat.call_count == 2

    @patch("core.llm_client.chat_json")
    def test_generate_with_fallback_both_fail_raises(self, mock_chat):
        mock_chat.side_effect = [
            RuntimeError("Primary model offline"),
            RuntimeError("Fallback model offline")
        ]
        with pytest.raises(llm_client.LLMUnavailableError):
            llm_client.generate_with_fallback("sys", "user")
        assert mock_chat.call_count == 2


# ─────────────────────────────────────────────────────────────
# 2. UNIT TESTS: core/model3_recovery
# ─────────────────────────────────────────────────────────────

class TestModel3RecoveryLogic:
    """Verifies deterministic plan synthesis and LLM fallback routing."""

    def test_deterministic_guidance_for_uplink_and_firmware(self):
        incident = {
            "event_id": "INC-TEST-001",
            "rule_id": "RULE_003",
            "rule_name": "firmware_plus_access_anomaly",
            "event_type": "SUPPLY_CHAIN_RISK",
            "severity": "CRITICAL",
            "satellite_id": "SAT-TEST-99",
            "operator_id": "OP-ROGUE",
            "session_id": "S-999"
        }
        events = [
            {
                "event_id": "EVT-1",
                "source": "UPLINK",
                "event_type": "UNAUTHORIZED_COMMAND",
                "severity": "HIGH",
                "description": "Unauthorized attitude burn"
            },
            {
                "event_id": "EVT-2",
                "source": "FIRMWARE",
                "event_type": "FIRMWARE_TAMPERING",
                "severity": "CRITICAL",
                "description": "Flash memory integrity check mismatch"
            }
        ]

        plan = model3_recovery._deterministic_recovery_guidance(incident, events)

        assert plan["affected_domain"] == "MULTI_DOMAIN"
        assert len(plan["secure_actions"]) >= 2
        assert len(plan["recovery_actions"]) >= 2
        assert len(plan["verification_steps"]) >= 2
        assert any("uplink" in act.lower() for act in plan["secure_actions"])
        assert any("firmware" in act.lower() or "bootloader" in act.lower() for act in plan["secure_actions"])
        assert any("sha-256" in v.lower() for v in plan["verification_steps"])
        assert plan["confidence"] == "HIGH"

    @patch("core.llm_client.generate_with_fallback")
    def test_generate_recovery_guidance_llm_success(self, mock_llm):
        mock_llm.return_value = (
            {
                "affected_domain": "ACCESS",
                "isolation_summary": "Isolate compromised ground console.",
                "secure_actions": ["Revoke session token", "Lock operator console"],
                "recovery_actions": ["Rotate operator keys", "Re-authenticate using FIDO2 token"],
                "verification_steps": ["Check active connections in access log"],
                "residual_risk": "LOW",
                "confidence": "HIGH",
                "rationale": "Compromised credential contained."
            },
            "deepseek-r1:14b"
        )

        incident = {"event_id": "INC-1", "satellite_id": "SAT-1", "severity": "HIGH"}
        events = [{"source": "ACCESS", "event_type": "SUSPICIOUS_LOGIN", "severity": "HIGH"}]

        guidance, model_used, llm_used = model3_recovery.generate_recovery_guidance(incident, events)

        assert llm_used is True
        assert model_used == "deepseek-r1:14b"
        assert guidance["affected_domain"] == "ACCESS"
        assert len(guidance["secure_actions"]) == 2

    @patch("core.llm_client.generate_with_fallback")
    def test_generate_recovery_guidance_fallback_on_llm_error(self, mock_llm):
        mock_llm.side_effect = llm_client.LLMUnavailableError("Both models offline")

        incident = {"event_id": "INC-2", "satellite_id": "SAT-2", "severity": "CRITICAL"}
        events = [{"source": "DOWNLINK", "event_type": "TELEMETRY_ANOMALY", "severity": "CRITICAL"}]

        guidance, model_used, llm_used = model3_recovery.generate_recovery_guidance(incident, events)

        # Must fall back seamlessly to deterministic engine
        assert llm_used is False
        assert model_used == "deterministic_fallback"
        assert guidance["affected_domain"] == "DOWNLINK"
        assert len(guidance["secure_actions"]) >= 1
        assert len(guidance["recovery_actions"]) >= 1
        assert len(guidance["verification_steps"]) >= 1


# ─────────────────────────────────────────────────────────────
# 3. INTEGRATION TESTS: End-to-End API Endpoints
# ─────────────────────────────────────────────────────────────

class TestModel3APIEndpoints:
    """Verifies POST /brain/model3/run, GET guidance, and POST review."""

    @patch("core.llm_client.generate_with_fallback")
    def test_full_model3_api_workflow_with_llm(self, mock_llm, api_client):
        mock_llm.return_value = (
            {
                "affected_domain": "MULTI_DOMAIN",
                "isolation_summary": "Coordinated space-ground breach detected.",
                "secure_actions": ["Emergency uplink freeze", "Terminate rogue session"],
                "recovery_actions": ["Rotate operator keys", "Resync sequence counters"],
                "verification_steps": ["Verify OBC telemetry integrity", "Check access logs"],
                "residual_risk": "MEDIUM",
                "confidence": "HIGH",
                "rationale": "Multi-module attack successfully contained via LLM guidance."
            },
            "deepseek-r1:14b"
        )

        base = datetime.now(timezone.utc)
        events = [
            {
                "event_id": "EVT-M3-01",
                "timestamp": base.isoformat(),
                "source": "ACCESS",
                "satellite_id": "SAT-M3-DEMO",
                "event_type": "SUSPICIOUS_LOGIN",
                "severity": "MEDIUM",
                "confidence": 0.85,
                "description": "Unusual login outside mission shift",
                "action": "REVIEW",
                "evidence": {},
                "related_events": [],
                "operator_id": "OP-M3-99",
                "session_id": "S-M3-SESSION-1",
            },
            {
                "event_id": "EVT-M3-02",
                "timestamp": (base + timedelta(seconds=45)).isoformat(),
                "source": "UPLINK",
                "satellite_id": "SAT-M3-DEMO",
                "event_type": "UNAUTHORIZED_COMMAND",
                "severity": "HIGH",
                "confidence": 0.95,
                "description": "Attempted payload sensor recalibration command",
                "action": "BLOCK_ADVISORY",
                "evidence": {},
                "related_events": [],
                "operator_id": "OP-M3-99",
                "session_id": "S-M3-SESSION-1",
            }
        ]

        for ev in events:
            r = api_client.post("/events/ingest", json=ev)
            assert r.status_code == 201

        # Check active incident created
        corr_resp = api_client.get("/correlations/active")
        assert corr_resp.status_code == 200
        incidents = corr_resp.json()
        assert len(incidents) >= 1
        inc_id = incidents[0]["event_id"]

        # 2. Call POST /brain/model3/run
        run_payload = {
            "incident_ids": [inc_id],
            "run_retrain": True
        }
        run_resp = api_client.post("/brain/model3/run", json=run_payload)
        assert run_resp.status_code == 200
        run_data = run_resp.json()

        assert run_data["status"] == "COMPLETED"
        assert run_data["guidance_count"] >= 1
        assert "retrain_result" in run_data

        record = run_data["guidance_records"][0]
        assert record["incident_id"] == inc_id
        assert record["model_used"] == "deepseek-r1:14b"
        assert record["llm_used"] is True
        assert record["review_status"] == "PENDING_REVIEW"
        assert "secure_actions" in record["guidance"]

        # 3. Call GET /correlations/{id}/recovery-guidance
        get_resp = api_client.get(f"/correlations/{inc_id}/recovery-guidance")
        assert get_resp.status_code == 200
        guidance_data = get_resp.json()
        assert guidance_data["incident_id"] == inc_id
        assert guidance_data["guidance_id"] == record["guidance_id"]
        assert guidance_data["review_status"] == "PENDING_REVIEW"

        # 4. Call POST /correlations/{id}/recovery-guidance/review (CISO ACCEPTED)
        review_payload = {
            "review_status": "ACCEPTED",
            "reviewer": "ciso_commander",
            "notes": "Plan approved. Ground station uplink channel frozen; operator session terminated."
        }
        rev_resp = api_client.post(f"/correlations/{inc_id}/recovery-guidance/review", json=review_payload)
        assert rev_resp.status_code == 200
        rev_data = rev_resp.json()
        assert rev_data["review_status"] == "ACCEPTED"
        assert rev_data["reviewed_by"] == "ciso_commander"
        assert "Plan approved" in rev_data["review_notes"]

        # 5. Verify GET reflects updated review status
        get_resp2 = api_client.get(f"/correlations/{inc_id}/recovery-guidance")
        assert get_resp2.status_code == 200
        assert get_resp2.json()["review_status"] == "ACCEPTED"

    @patch("core.llm_client.generate_with_fallback")
    def test_api_workflow_with_deterministic_fallback(self, mock_llm, api_client):
        # Force LLM unavailable to exercise fallback through the API
        mock_llm.side_effect = llm_client.LLMUnavailableError("Ollama offline")

        base = datetime.now(timezone.utc)
        events = [
            {
                "event_id": "EVT-FB-01",
                "timestamp": base.isoformat(),
                "source": "FIRMWARE",
                "satellite_id": "SAT-FB-TEST",
                "event_type": "FIRMWARE_TAMPERING",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "description": "Firmware digest mismatch on bootloader partition",
                "action": "REVIEW",
                "evidence": {},
                "related_events": [],
                "operator_id": "OP-ADMIN",
                "session_id": "S-FB-001",
            },
            {
                "event_id": "EVT-FB-02",
                "timestamp": (base + timedelta(seconds=30)).isoformat(),
                "source": "ACCESS",
                "satellite_id": "SAT-FB-TEST",
                "event_type": "ACCESS_VIOLATION",
                "severity": "HIGH",
                "confidence": 0.90,
                "description": "Direct memory write attempt without dual approval",
                "action": "REVIEW",
                "evidence": {},
                "related_events": [],
                "operator_id": "OP-ADMIN",
                "session_id": "S-FB-001",
            }
        ]

        for ev in events:
            r = api_client.post("/events/ingest", json=ev)
            assert r.status_code == 201

        corr_resp = api_client.get("/correlations/active")
        assert corr_resp.status_code == 200
        inc_id = corr_resp.json()[0]["event_id"]

        # Run pipeline — should fall back to deterministic plan
        run_resp = api_client.post("/brain/model3/run", json={"incident_ids": [inc_id]})
        assert run_resp.status_code == 200
        rec = run_resp.json()["guidance_records"][0]
        assert rec["llm_used"] is False
        assert rec["model_used"] == "deterministic_fallback"
        assert len(rec["guidance"]["secure_actions"]) >= 2
        assert len(rec["guidance"]["recovery_actions"]) >= 2
        assert len(rec["guidance"]["verification_steps"]) >= 2

        # CISO dismisses guidance
        dismiss_resp = api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/review",
            json={"review_status": "DISMISSED", "reviewer": "ciso_secops", "notes": "False alarm from authorized drill."}
        )
        assert dismiss_resp.status_code == 200
        assert dismiss_resp.json()["review_status"] == "DISMISSED"

    def test_invalid_review_status_returns_400(self, api_client):
        resp = api_client.post("/correlations/INC-NONEXISTENT/recovery-guidance/review", json={
            "review_status": "INVALID_STATUS",
            "reviewer": "ciso"
        })
        assert resp.status_code == 400

    def test_guidance_for_nonexistent_incident_returns_404(self, api_client):
        resp = api_client.get("/correlations/INC-DOES-NOT-EXIST/recovery-guidance")
        assert resp.status_code == 404

    _MOCK_PLAN = (
        {
            "affected_domain": "UPLINK",
            "isolation_summary": "Command uplink isolation active.",
            "secure_actions": ["Emergency uplink freeze", "Terminate rogue session"],
            "recovery_actions": ["Rotate operator keys", "Resync sequence counters"],
            "verification_steps": ["Verify OBC telemetry integrity", "Check access logs"],
            "residual_risk": "MEDIUM",
            "confidence": "HIGH",
            "rationale": "Uplink anomaly contained."
        },
        "deepseek-r1:14b"
    )

    @patch("core.llm_client.generate_with_fallback")
    def test_edit_recovery_guidance(self, mock_llm, api_client):
        mock_llm.return_value = self._MOCK_PLAN
        # 1. Setup incident in DB
        now_iso = datetime.now(timezone.utc).isoformat()
        inc_id = "INC-EDIT-TEST"
        inc = {
            "event_id": inc_id,
            "timestamp": now_iso,
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "description": "Unauthorized command injection",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 85,
            "rule_id": "RULE-001",
            "rule_name": "Unauthorized Command Uplink",
            "rule_score": 75,
            "ml_adjustment": 10,
            "satellite_id": "SAT-TEST-01",
            "operator_id": "OP-COMPROMISED",
            "session_id": "SESS-99",
            "status": "OPEN",
            "created_at": now_iso,
        }
        database.insert_incident(inc)

        # 2. Generate guidance via GET
        get_resp = api_client.get(f"/correlations/{inc_id}/recovery-guidance")
        assert get_resp.status_code == 200
        original_guidance = get_resp.json()["guidance"]

        # 3. Edit guidance via PUT
        edit_payload = {
            "reviewer": "ciso_director",
            "secure_actions": [
                "1. Freeze ground station RF power amplifier",
                "2. Force revoke OP-COMPROMISED session token"
            ],
            "recovery_actions": [
                "1. Re-key spacecraft TT&C link with secondary key set",
                "2. Clear uncommitted OBC command queue"
            ],
            "verification_steps": [
                "1. Confirm no rejected frames in telemetry stream for 10 min",
                "2. Validate primary receiver lock signal"
            ],
            "notes": "Flight director approved custom recovery procedure."
        }
        edit_resp = api_client.put(f"/correlations/{inc_id}/recovery-guidance/edit", json=edit_payload)
        assert edit_resp.status_code == 200
        rec = edit_resp.json()
        assert rec["review_status"] == "EDITED"
        assert rec["edited_by"] == "ciso_director"
        assert rec["ciso_edited"]["secure_actions"] == edit_payload["secure_actions"]
        assert rec["ciso_edited"]["recovery_actions"] == edit_payload["recovery_actions"]
        assert rec["ciso_edited"]["verification_steps"] == edit_payload["verification_steps"]
        # Original plan remains preserved
        assert rec["guidance"]["affected_domain"] == original_guidance["affected_domain"]

        # 4. Verify GET returns edited information
        get_resp2 = api_client.get(f"/correlations/{inc_id}/recovery-guidance")
        assert get_resp2.status_code == 200
        assert get_resp2.json()["review_status"] == "EDITED"
        assert get_resp2.json()["ciso_edited"] is not None

    @patch("core.llm_client.generate_with_fallback")
    def test_verify_rectification_passed(self, mock_llm, api_client):
        mock_llm.return_value = self._MOCK_PLAN
        # 1. Setup incident and guidance
        now = datetime.now(timezone.utc)
        inc_id = "INC-RECT-PASS"
        inc = {
            "event_id": inc_id,
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "HIGH",
            "confidence": 0.90,
            "description": "Cross-subsystem anomaly",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 80,
            "rule_id": "RULE-001",
            "rule_name": "Unauthorized Command Uplink",
            "rule_score": 70,
            "ml_adjustment": 10,
            "satellite_id": "SAT-PASS-01",
            "operator_id": "OP-PASS",
            "session_id": "SESS-PASS",
            "status": "OPEN",
            "created_at": (now - timedelta(minutes=10)).isoformat(),
        }
        database.insert_incident(inc)

        # Generate guidance and accept it
        api_client.get(f"/correlations/{inc_id}/recovery-guidance")
        api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/review",
            json={"review_status": "ACCEPTED", "reviewer": "ciso_ops", "notes": "Approved"}
        )

        # Mark remediation applied with a timestamp safely in the past so observation window passes
        past_applied = (now - timedelta(seconds=60)).isoformat()
        guid = database.fetch_recovery_guidance_by_incident(inc_id)
        database.mark_remediation_applied(guid["guidance_id"], reviewer="ciso_ops", applied_at=past_applied)

        # Ingest a benign telemetry event post-remediation that does NOT match the rule
        benign_event = {
            "event_id": "EVT-BENIGN-01",
            "timestamp": (now + timedelta(seconds=10)).isoformat(),
            "source": "DOWNLINK",
            "satellite_id": "SAT-PASS-01",
            "event_type": "TELEMETRY_FRAME_VALID",
            "severity": "LOW",
            "confidence": 0.99,
            "description": "Nominal telemetry frames received",
            "action": "NONE",
            "evidence": {},
            "related_events": [],
            "operator_id": "OP-NOMINAL",
            "session_id": "SESS-NOMINAL",
        }
        database.insert_event(benign_event)

        # 2. Call verify endpoint
        verif_resp = api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/verify",
            params={"reviewer": "ciso_verifier", "notes": "Clean telemetry confirmed"}
        )
        assert verif_resp.status_code == 200
        vdata = verif_resp.json()
        assert vdata["verification_result"] == "PASSED"
        assert vdata["status_updated_to"] == "RECTIFIED"
        assert "PASSED" in vdata["message"]

        # 3. Verify incident status in database is RECTIFIED
        updated_inc = database.fetch_incident_by_id(inc_id)
        assert updated_inc["status"] == "RECTIFIED"

        # 4. Verify feedback log recorded rectification
        with database.get_connection() as conn:
            fb = conn.execute("SELECT * FROM feedback_log WHERE incident_id=?", (inc_id,)).fetchone()
            assert fb is not None
            assert fb["verdict"] == "RECTIFIED"
            assert fb["is_rectified"] == 1

    @patch("core.llm_client.generate_with_fallback")
    def test_verify_rectification_failed(self, mock_llm, api_client):
        mock_llm.return_value = self._MOCK_PLAN
        # 1. Setup incident and guidance
        now = datetime.now(timezone.utc)
        inc_id = "INC-RECT-FAIL"
        sat_id = "SAT-FAIL-01"
        inc = {
            "event_id": inc_id,
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "description": "Uplink and Access breach",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 90,
            "rule_id": "RULE_001",
            "rule_name": "Unauthorized Command Uplink",
            "rule_score": 80,
            "ml_adjustment": 10,
            "satellite_id": sat_id,
            "operator_id": "OP-ROGUE",
            "session_id": "SESS-ROGUE",
            "status": "OPEN",
            "created_at": (now - timedelta(minutes=10)).isoformat(),
        }
        database.insert_incident(inc)

        # Generate guidance and accept it
        api_client.get(f"/correlations/{inc_id}/recovery-guidance")
        rev_resp = api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/review",
            json={"review_status": "ACCEPTED", "reviewer": "ciso_ops", "notes": "Approved"}
        )
        assert rev_resp.status_code == 200

        # Mark remediation applied with timestamp 60s in the past
        past_applied = (now - timedelta(seconds=60)).isoformat()
        guid = database.fetch_recovery_guidance_by_incident(inc_id)
        database.mark_remediation_applied(guid["guidance_id"], reviewer="ciso_ops", applied_at=past_applied)
        ref_dt = datetime.fromisoformat(past_applied)

        # Inject post-remediation events that re-fire RULE_001:
        ev1 = {
            "event_id": "EVT-FAIL-01",
            "timestamp": (ref_dt + timedelta(seconds=1)).isoformat(),
            "source": "UPLINK",
            "satellite_id": sat_id,
            "event_type": "REPLAY_ATTACK",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "description": "Replay uplink detected post-remediation",
            "action": "REVIEW",
            "evidence": {},
            "related_events": [],
            "operator_id": "OP-ROGUE",
            "session_id": "SESS-ROGUE",
        }
        ev2 = {
            "event_id": "EVT-FAIL-02",
            "timestamp": (ref_dt + timedelta(seconds=2)).isoformat(),
            "source": "ACCESS",
            "satellite_id": sat_id,
            "event_type": "UNAUTHORIZED_COMMAND",
            "severity": "HIGH",
            "confidence": 0.90,
            "description": "Unauthorized access attempt post-remediation",
            "action": "REVIEW",
            "evidence": {},
            "related_events": [],
            "operator_id": "OP-ROGUE",
            "session_id": "SESS-ROGUE",
        }
        database.insert_event(ev1)
        database.insert_event(ev2)

        # 2. Call verify endpoint
        verif_resp = api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/verify",
            params={"reviewer": "ciso_verifier", "notes": "Telemetry re-test"}
        )
        assert verif_resp.status_code == 200
        vdata = verif_resp.json()
        assert vdata["verification_result"] == "FAILED"
        assert vdata["status_updated_to"] == "VERIFICATION_FAILED"
        assert "FAILED" in vdata["message"]

        # 3. Verify incident status in database is VERIFICATION_FAILED
        updated_inc = database.fetch_incident_by_id(inc_id)
        assert updated_inc["status"] == "VERIFICATION_FAILED"

        # 4. Verify config_audit contains the failure audit entry
        with database.get_connection() as conn:
            audit = conn.execute(
                "SELECT * FROM config_audit WHERE change_type='RECTIFICATION_VERIFICATION_FAILED'"
            ).fetchone()
            assert audit is not None
            assert audit["rule_id"] == "RULE_001"
            assert audit["after_value"] == "VERIFICATION_FAILED"

    @patch("core.llm_client.generate_with_fallback")
    def test_verify_rectification_guards_400_and_409(self, mock_llm, api_client):
        """Tests the strict State Machine guards for breach verification."""
        mock_llm.return_value = self._MOCK_PLAN
        now = datetime.now(timezone.utc)
        inc_id = "INC-GUARDS-TEST"
        inc = {
            "event_id": inc_id,
            "timestamp": now.isoformat(),
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "HIGH",
            "confidence": 0.90,
            "description": "Guard test incident",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 75,
            "rule_id": "RULE-001",
            "rule_name": "Unauthorized Command Uplink",
            "rule_score": 70,
            "ml_adjustment": 5,
            "satellite_id": "SAT-GUARD-01",
            "status": "OPEN",
            "created_at": now.isoformat(),
        }
        database.insert_incident(inc)

        # 1. Generate guidance (remains PENDING_REVIEW)
        api_client.get(f"/correlations/{inc_id}/recovery-guidance")

        # Guard Test A: Calling /mark-applied on PENDING_REVIEW must return 400
        apply_resp_err = api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/mark-applied",
            json={"reviewer": "ciso_ops", "notes": "Applied without review"}
        )
        assert apply_resp_err.status_code == 400
        assert "ACCEPTED or EDITED" in apply_resp_err.json()["detail"]

        # Guard Test B: Calling /verify before /mark-applied must return 400
        verif_pre_resp = api_client.post(f"/correlations/{inc_id}/recovery-guidance/verify")
        assert verif_pre_resp.status_code == 400
        assert "Cannot verify before CISO confirms remediation was applied" in verif_pre_resp.json()["detail"]

        # 2. CISO approves guidance
        api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/review",
            json={"review_status": "ACCEPTED", "reviewer": "ciso_ops"}
        )

        # 3. CISO calls /mark-applied (sets remediation_applied_at to NOW)
        apply_resp = api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/mark-applied",
            json={"reviewer": "ciso_ops", "notes": "Remediation verified deployed"}
        )
        assert apply_resp.status_code == 200
        assert apply_resp.json()["review_status"] == "REMEDIATION_APPLIED"

        # Guard Test C: Calling /verify immediately before observation window elapses must return 409
        verif_early_resp = api_client.post(f"/correlations/{inc_id}/recovery-guidance/verify")
        assert verif_early_resp.status_code == 409
        detail = verif_early_resp.json()["detail"]
        assert "retry_after_seconds" in detail
        assert detail["retry_after_seconds"] > 0

    @patch("core.model3_recovery.check_llm_reachability")
    def test_model3_status_endpoint(self, mock_reachability, api_client):
        mock_reachability.return_value = True

        resp = api_client.get("/brain/model3/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["llm_reachable"] is True
        assert "counts" in data
        assert "pending_review" in data["counts"]
        assert "rectified" in data["counts"]
        assert "verification_failed" in data["counts"]
        assert "remediation_applied" in data["counts"]

    @patch("core.llm_client.generate_with_fallback")
    def test_incident_model3_status_stepper(self, mock_llm, api_client):
        mock_llm.return_value = self._MOCK_PLAN
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        inc_id = "INC-STEPPER-TEST"
        inc = {
            "event_id": inc_id,
            "timestamp": now_iso,
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "HIGH",
            "confidence": 0.85,
            "description": "Stepper test incident",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 75,
            "rule_id": "RULE-002",
            "rule_name": "Multi-stage Escalation",
            "rule_score": 70,
            "ml_adjustment": 5,
            "satellite_id": "SAT-STEP-01",
            "operator_id": "OP-01",
            "session_id": "SESS-01",
            "status": "OPEN",
            "created_at": now_iso,
        }
        database.insert_incident(inc)

        # Stage 1: CORRELATED (before guidance generated)
        s1 = api_client.get(f"/correlations/{inc_id}/model3-status").json()
        assert s1["current_stage"] == "CORRELATED"
        assert s1["guidance_id"] is None

        # Stage 2: GUIDANCE_GENERATED (after recovery guidance fetched)
        api_client.get(f"/correlations/{inc_id}/recovery-guidance")
        s2 = api_client.get(f"/correlations/{inc_id}/model3-status").json()
        assert s2["current_stage"] == "GUIDANCE_GENERATED"
        assert s2["guidance_id"] is not None

        # Stage 3: CISO_REVIEWED (after ACCEPTED review)
        api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/review",
            json={"review_status": "ACCEPTED", "reviewer": "ciso_stepper"}
        )
        s3 = api_client.get(f"/correlations/{inc_id}/model3-status").json()
        assert s3["current_stage"] == "CISO_REVIEWED"
        assert s3["review_status"] == "ACCEPTED"

        # Stage 4: REMEDIATION_APPLIED (after mark-applied)
        api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/mark-applied",
            json={"reviewer": "ciso_stepper", "notes": "Applied to flight station"}
        )
        s4 = api_client.get(f"/correlations/{inc_id}/model3-status").json()
        assert s4["current_stage"] == "REMEDIATION_APPLIED"
        assert s4["timestamps"]["remediation_applied_at"] is not None

        # Set remediation_applied_at safely in past to pass window check
        guid = database.fetch_recovery_guidance_by_incident(inc_id)
        database.mark_remediation_applied(
            guid["guidance_id"],
            reviewer="ciso_stepper",
            applied_at=(now - timedelta(seconds=60)).isoformat()
        )

        # Stage 5: RECTIFIED (after verification succeeds)
        verif_r = api_client.post(f"/correlations/{inc_id}/recovery-guidance/verify")
        assert verif_r.status_code == 200
        s5 = api_client.get(f"/correlations/{inc_id}/model3-status").json()
        assert s5["current_stage"] == "RECTIFIED"
        assert s5["verification_result"] == "PASSED"
        assert s5["timestamps"]["verified_at"] is not None

        # Stage 5b: Verify idempotency - second call to /verify on already-rectified incident
        verif_r2 = api_client.post(f"/correlations/{inc_id}/recovery-guidance/verify")
        assert verif_r2.status_code == 200
        data2 = verif_r2.json()
        assert data2["verification_result"] == "PASSED"
        assert "idempotent" in data2.get("message", "").lower()

    def test_review_endpoint_nonexistent_incident_returns_404(self, api_client):
        """Asserts HTTP 404 when CISO submits review for an incident without guidance."""
        resp = api_client.post(
            "/correlations/INC-DOES-NOT-EXIST-404/recovery-guidance/review",
            json={"review_status": "ACCEPTED", "reviewer": "ciso_ops"}
        )
        assert resp.status_code == 404
        assert "no recovery guidance found" in resp.json()["detail"].lower()


    @patch("core.llm_client.generate_with_fallback")
    def test_edit_endpoint_empty_action_list_returns_400(self, mock_llm, api_client):
        """Asserts HTTP 400 when CISO submits an empty edit action list."""
        mock_llm.return_value = self._MOCK_PLAN
        now_iso = datetime.now(timezone.utc).isoformat()
        inc_id = "INC-EMPTY-EDIT"
        inc = {
            "event_id": inc_id,
            "timestamp": now_iso,
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "MEDIUM",
            "confidence": 0.8,
            "description": "Anomaly to test empty edit validation",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 50,
            "status": "OPEN",
            "created_at": now_iso,
        }
        database.insert_incident(inc)
        api_client.get(f"/correlations/{inc_id}/recovery-guidance")

        resp = api_client.put(
            f"/correlations/{inc_id}/recovery-guidance/edit",
            json={
                "reviewer": "ciso_ops",
                "secure_actions": [],
                "recovery_actions": [],
                "verification_steps": [],
                "notes": "Empty edit payload",
            }
        )
        assert resp.status_code == 400
        assert "at least one secure or recovery action" in resp.json()["detail"].lower()

    @patch("core.llm_client.generate_with_fallback")
    def test_terminal_state_guards_for_review_and_edit(self, mock_llm, api_client):
        """Asserts HTTP 400 when attempting to review or edit guidance in terminal or applied states."""
        mock_llm.return_value = self._MOCK_PLAN
        now_iso = datetime.now(timezone.utc).isoformat()
        inc_id = "INC-TERMINAL-GUARDS"
        inc = {
            "event_id": inc_id,
            "timestamp": now_iso,
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "HIGH",
            "confidence": 0.9,
            "description": "Incident for terminal state testing",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 80,
            "status": "OPEN",
            "created_at": now_iso,
        }
        database.insert_incident(inc)
        api_client.get(f"/correlations/{inc_id}/recovery-guidance")

        # 1. Dismiss guidance
        api_client.post(
            f"/correlations/{inc_id}/recovery-guidance/review",
            json={"review_status": "DISMISSED", "reviewer": "ciso_ops"}
        )

        # 2. Attempting to edit a dismissed guidance should return HTTP 400
        edit_resp = api_client.put(
            f"/correlations/{inc_id}/recovery-guidance/edit",
            json={"reviewer": "ciso_ops", "secure_actions": ["Action 1"]}
        )
        assert edit_resp.status_code == 400
        assert "dismissed" in edit_resp.json()["detail"].lower()

