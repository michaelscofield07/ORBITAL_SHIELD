"""
ORBITAL SHIELD — MODEL 1 TEST SUITE
Verification of:
  1. Multi-source normalization (DOWNLINK, UPLINK, FIRMWARE, ACCESS, CISO_NOTES, CERT_IN)
  2. Authorization classification & rationale determination
  3. Reconstructed full unauthorized event chain
  4. Section 13: Historical repeated pattern detection & associated data access correlation
  5. Section 14: Verified / rectified feedback handling & false alarm suppression
  6. Document and report generation (CISO dashboard & CERT-In 6-hour regulatory report)
  7. API Endpoints:
     - GET /correlations/{id}/document
     - GET /correlations/{id}/cert-in
     - POST /ciso/notes
     - POST /cert-in/summary
     - GET /patterns/historical
"""

import os
import sys
import json
import importlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.schemas import IncomingEvent, SourceModule, AuthorizationStatus, ActionType, VerdictType
from core import normalization, model1_understanding, ingestion, correlation_engine
from db import database


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Provides an isolated SQLite database and sliding window for each test."""
    db_file = tmp_path / "model1_test.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    importlib.reload(database)
    database.init_db()
    ingestion.init_window(window_seconds=1800, max_events=5000)
    yield


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """Provides a TestClient connected to an isolated database and sliding window."""
    db_file = tmp_path / "model1_api_test.db"
    monkeypatch.setenv("DB_PATH", str(db_file))
    importlib.reload(database)
    database.init_db()
    ingestion.init_window(window_seconds=1800, max_events=5000)

    import main as app_module
    importlib.reload(app_module)
    with TestClient(app_module.app) as client:
        yield client


# ─────────────────────────────────────────────────────────────
# 1. TEST SUITE: Multi-Source Ingestion & Normalization
# ─────────────────────────────────────────────────────────────

class TestNormalization:
    """Verifies Common Event Model normalization across all 6 input sources."""

    def test_downlink_normalization(self):
        raw = {
            "event_id": "EVT-DL-001",
            "timestamp": "2026-09-18T10:00:00Z",
            "source": "DOWNLINK",
            "satellite_id": "SAT-TEST-01",
            "event_type": "TELEMETRY_ANOMALY",
            "severity": "HIGH",
            "confidence": 0.88,
            "description": "Anomalous power subsystem telemetry spike",
            "action": "FLAG",
            "signal_dbm": -84.5,
            "frequency_mhz": 2245.0,
            "station_id": "GS-BANGALORE",
        }
        event = IncomingEvent(**raw)
        norm = normalization.normalize_security_event(event)

        assert norm["source"] == "DOWNLINK"
        assert norm["packet_info"]["frequency_mhz"] == 2245.0
        assert norm["packet_info"]["station_id"] == "GS-BANGALORE"
        assert "raw_log" in norm
        assert norm["raw_log"]["signal_dbm"] == -84.5
        assert norm["authorization_status"] == AuthorizationStatus.SUSPICIOUS.value

    def test_firmware_normalization(self):
        raw = {
            "event_id": "EVT-FW-001",
            "timestamp": "2026-09-18T10:05:00Z",
            "source": "FIRMWARE",
            "satellite_id": "SAT-TEST-01",
            "event_type": "FIRMWARE_TAMPERING",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "description": "Cryptographic signature mismatch on TT&C payload",
            "action": "QUARANTINE",
            "component": "ttc_crypto_core",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "previous_version": "v1.4.2",
            "new_version": "v1.4.3-unverified",
        }
        event = IncomingEvent(**raw)
        norm = normalization.normalize_security_event(event)

        assert norm["source"] == "FIRMWARE"
        assert norm["firmware_info"]["component"] == "ttc_crypto_core"
        assert norm["firmware_info"]["sha256"] == raw["sha256"]
        assert norm["authorization_status"] == AuthorizationStatus.UNAUTHORIZED.value

    def test_access_normalization_with_data_access(self):
        raw = {
            "event_id": "EVT-ACC-001",
            "timestamp": "2026-09-18T10:10:00Z",
            "source": "ACCESS",
            "satellite_id": "SAT-TEST-01",
            "event_type": "UNAUTHORIZED_DATA_ACCESS",
            "severity": "HIGH",
            "confidence": 0.92,
            "description": "Operator accessed classified payload flight telemetry table without clearance",
            "action": "FLAG",
            "operator_id": "OP-SEC-99",
            "ip": "192.168.1.105",
            "database": "telemetry_db",
            "tables": ["orbit_keys", "classified_telemetry"],
            "records_accessed": 1420,
            "sensitivity": "TOP_SECRET",
        }
        event = IncomingEvent(**raw)
        norm = normalization.normalize_security_event(event)

        assert norm["source"] == "ACCESS"
        assert norm["actor"] == "OP-SEC-99"
        assert norm["source_ip"] == "192.168.1.105"
        assert norm["data_access"]["database"] == "telemetry_db"
        assert "orbit_keys" in norm["data_access"]["tables"]
        assert norm["data_access"]["records_accessed"] == 1420
        assert norm["authorization_status"] == AuthorizationStatus.UNAUTHORIZED.value

    def test_ciso_notes_normalization(self):
        raw = {
            "event_id": "EVT-CISO-001",
            "timestamp": "2026-09-18T10:15:00Z",
            "source": "CISO_NOTES",
            "satellite_id": "SAT-TEST-01",
            "event_type": "CISO_ANNOTATION",
            "severity": "INFO",
            "confidence": 1.0,
            "description": "Routine scheduled orbit station keeping maneuver authorized by CISO",
            "action": "LOG",
            "ciso_notes": "Flight dynamics test approved under CR-2026-0918",
            "operator_id": "ciso_dr_rao",
        }
        event = IncomingEvent(**raw)
        norm = normalization.normalize_security_event(event)

        assert norm["source"] == "CISO_NOTES"
        assert norm["ciso_notes"] == "Flight dynamics test approved under CR-2026-0918"
        assert norm["authorization_status"] == AuthorizationStatus.AUTHORIZED.value


# ─────────────────────────────────────────────────────────────
# 2. TEST SUITE: Authorization Context & Explanation Rationale
# ─────────────────────────────────────────────────────────────

class TestAuthorizationClassification:
    """Verifies that unauthorized, suspicious, authorized, and verified/rectified states have explicit rationale."""

    def test_unauthorized_classification_with_rationale(self):
        incident = {
            "event_id": "INC-001",
            "timestamp": "2026-09-18T11:00:00Z",
            "rule_id": "RULE_001",
            "rule_name": "Cross-Module Session Correlation",
            "event_type": "CROSS_MODULE_ATTACK",
            "severity": "HIGH",
            "risk_score": 85,
        }
        contributing = [
            {
                "event_id": "E1",
                "timestamp": "2026-09-18T10:58:00Z",
                "source": "ACCESS",
                "event_type": "SUSPICIOUS_LOGIN",
                "severity": "MEDIUM",
                "authorization_status": "SUSPICIOUS",
                "operator_id": "attacker",
            },
            {
                "event_id": "E2",
                "timestamp": "2026-09-18T10:59:00Z",
                "source": "UPLINK",
                "event_type": "UNAUTHORIZED_COMMAND",
                "severity": "HIGH",
                "authorization_status": "UNAUTHORIZED",
                "operator_id": "attacker",
            },
        ]
        enriched = model1_understanding.understand_incident(incident, contributing)

        assert enriched["authorization_status"] == AuthorizationStatus.UNAUTHORIZED.value
        assert "UNAUTHORIZED" in enriched["authorization_reason"]
        assert len(enriched["unauthorized_chain"]) == 2
        assert enriched["unauthorized_chain"][1]["chain_role"] == "PRIMARY_UNAUTHORIZED_ACTIVITY"

    def test_suspicious_classification_without_explicit_unauth(self):
        incident = {
            "event_id": "INC-002",
            "timestamp": "2026-09-18T11:05:00Z",
            "rule_id": "RULE_002",
            "rule_name": "Escalating Severity Anomaly Pattern",
            "event_type": "ESCALATING_SEVERITY_ATTACK",
            "severity": "HIGH",
            "risk_score": 65,
        }
        contributing = [
            {"event_id": "E1", "timestamp": "2026-09-18T11:01:00Z", "source": "DOWNLINK", "event_type": "TELEMETRY_ANOMALY", "severity": "LOW", "authorization_status": "SUSPICIOUS"},
            {"event_id": "E2", "timestamp": "2026-09-18T11:02:00Z", "source": "DOWNLINK", "event_type": "TELEMETRY_ANOMALY", "severity": "MEDIUM", "authorization_status": "SUSPICIOUS"},
            {"event_id": "E3", "timestamp": "2026-09-18T11:03:00Z", "source": "DOWNLINK", "event_type": "SIGNAL_INTERFERENCE", "severity": "HIGH", "authorization_status": "SUSPICIOUS"},
        ]
        enriched = model1_understanding.understand_incident(incident, contributing)

        assert enriched["authorization_status"] == AuthorizationStatus.SUSPICIOUS.value
        assert "SUSPICIOUS" in enriched["authorization_reason"]


# ─────────────────────────────────────────────────────────────
# 3. TEST SUITE: Section 13 — Same Pattern + Data Access Correlation
# ─────────────────────────────────────────────────────────────

class TestSection13HistoricalPatternAndDataAccess:
    """
    Verifies Section 13 requirements:
    When a previously observed unauthorized pattern appears again:
    1. Search historical logs/database.
    2. Identify the matching pattern.
    3. Determine whether the pattern accessed data.
    4. Retrieve ALL relevant associated data-access details.
    5. Correlate historical information with current incident.
    """

    def test_identical_pattern_detects_prior_data_access(self):
        # 1. Store historical incident #1 with database access
        base_time = datetime.now(timezone.utc) - timedelta(days=2)
        ev_hist1 = {
            "event_id": "EVT-HIST-001",
            "timestamp": base_time.isoformat(),
            "source": "ACCESS",
            "satellite_id": "SAT-HIST-01",
            "event_type": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "confidence": 0.9,
            "description": "Privilege escalation to root operator",
            "action": "FLAG",
            "actor": "compromised_admin",
            "authorization_status": "UNAUTHORIZED",
            "data_access": {
                "database": "satellite_telemetry_db",
                "tables": ["orbital_ephemeris", "ground_command_log"],
                "records_accessed": 520,
                "classification": "CONFIDENTIAL"
            }
        }
        ev_hist2 = {
            "event_id": "EVT-HIST-002",
            "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
            "source": "ACCESS",
            "satellite_id": "SAT-HIST-01",
            "event_type": "UNAUTHORIZED_DATA_ACCESS",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "description": "Bulk exfiltration dump of ground command log",
            "action": "QUARANTINE",
            "actor": "compromised_admin",
            "authorization_status": "UNAUTHORIZED",
            "data_access": {
                "database": "satellite_telemetry_db",
                "tables": ["ground_command_log"],
                "records_accessed": 10000,
                "classification": "SECRET"
            }
        }
        database.insert_event(ev_hist1)
        database.insert_event(ev_hist2)

        past_incident = {
            "event_id": "INC-PAST-001",
            "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
            "source": "ML_BRAIN",
            "satellite_id": "SAT-HIST-01",
            "event_type": "PRIVILEGE_ESCALATION_DATA_ACCESS",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "description": "Historical incident: Privilege escalation then unauthorized data access",
            "action": "HUMAN_REVIEW",
            "risk_score": 95,
            "rule_id": "RULE_006",
            "rule_name": "Privilege Escalation Followed by Unauthorized Data Access",
            "rule_score": 90,
            "related_events": ["EVT-HIST-001", "EVT-HIST-002"],
            "status": "RESOLVED",
        }
        database.insert_incident(past_incident)

        # 2. Now simulate current incident matching the same rule RULE_006
        curr_time = datetime.now(timezone.utc)
        curr_ev1 = {
            "event_id": "EVT-CURR-001",
            "timestamp": curr_time.isoformat(),
            "source": "ACCESS",
            "satellite_id": "SAT-HIST-01",
            "event_type": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "confidence": 0.92,
            "description": "Current privilege escalation attempt detected",
            "action": "FLAG",
            "actor": "rogue_operator_2",
            "authorization_status": "UNAUTHORIZED",
            "data_access": {
                "database": "satellite_telemetry_db",
                "tables": ["orbital_ephemeris"],
                "records_accessed": 150,
                "classification": "CONFIDENTIAL"
            }
        }
        database.insert_event(curr_ev1)

        curr_incident = {
            "event_id": "INC-CURR-002",
            "timestamp": curr_time.isoformat(),
            "source": "ML_BRAIN",
            "satellite_id": "SAT-HIST-01",
            "event_type": "PRIVILEGE_ESCALATION_DATA_ACCESS",
            "severity": "CRITICAL",
            "confidence": 0.93,
            "description": "Current recurrence of privilege escalation then data access",
            "action": "HUMAN_REVIEW",
            "risk_score": 92,
            "rule_id": "RULE_006",
            "rule_name": "Privilege Escalation Followed by Unauthorized Data Access",
            "rule_score": 90,
            "related_events": ["EVT-CURR-001"],
            "status": "OPEN",
        }

        enriched = model1_understanding.understand_incident(curr_incident, [curr_ev1])

        # Verify historical detection
        assert enriched["historical_pattern_matched"] is True
        hist_details = enriched["historical_pattern_details"]
        assert hist_details["pattern_matched"] is True
        assert hist_details["matching_rule_id"] == "RULE_006"
        assert hist_details["historical_matches_count"] >= 1
        assert hist_details["historical_had_data_access"] is True
        assert "satellite_telemetry_db" in hist_details["historical_databases_accessed"]
        assert "ground_command_log" in hist_details["historical_tables_accessed"]
        assert hist_details["historical_total_records_accessed"] >= 10520

        # Verify document contains section 13 historical correlation details
        doc = enriched["incident_document_md"]
        assert "HISTORICAL REPEATED ATTACK PATTERN" in doc
        assert "Previous Incident" in doc
        assert "satellite_telemetry_db" in doc


# ─────────────────────────────────────────────────────────────
# 4. TEST SUITE: Section 14 — Verified / Rectified Feedback Handling
# ─────────────────────────────────────────────────────────────

class TestSection14VerifiedRectifiedSuppression:
    """
    Verifies Section 14 requirements:
    - Segregate verified/rectified feedback so recurring legitimate/rectified operations
      do not continue triggering redundant false alarms.
    """

    def test_rectified_feedback_prevents_false_positive_reflagging(self):
        # 1. Submit CISO RECTIFIED verdict for a specific maintenance operator
        database.insert_feedback(
            incident_id="INC-PREV-099",
            verdict="RECTIFIED",
            reviewer="ciso_isro",
            notes="Routine Thruster Calibration authorized by Flight Dynamics Directorate",
            rule_id="RULE_001",
            risk_score=75,
            is_rectified=1,
            verified_pattern_json=json.dumps({
                "rule_id": "RULE_001",
                "actor": "chief_flight_controller",
                "event_type": "CROSS_MODULE_ATTACK"
            })
        )

        # 2. Check is_event_or_pattern_rectified
        is_rect, reason = database.is_event_or_pattern_rectified({
            "actor": "chief_flight_controller",
            "rule_id": "RULE_001",
        })
        assert is_rect is True
        assert "verified legitimate baseline" in reason or "previously rectified" in reason

        # 3. Model 1 evaluation assigns VERIFIED_RECTIFIED status
        incident = {
            "event_id": "INC-NEW-100",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule_id": "RULE_001",
            "rule_name": "Cross-Module Session Correlation",
            "event_type": "CROSS_MODULE_ATTACK",
            "severity": "HIGH",
            "risk_score": 70,
        }
        events = [{
            "event_id": "E100",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ACCESS",
            "event_type": "SUSPICIOUS_LOGIN",
            "severity": "MEDIUM",
            "actor": "chief_flight_controller",
        }]

        enriched = model1_understanding.understand_incident(incident, events)
        assert enriched["authorization_status"] == AuthorizationStatus.VERIFIED_RECTIFIED.value
        assert "PREVIOUSLY VERIFIED/RECTIFIED" in enriched["authorization_reason"]


# ─────────────────────────────────────────────────────────────
# 5. TEST SUITE: Incident Document & CERT-In Reporting Endpoints
# ─────────────────────────────────────────────────────────────

class TestModel1APIEndpoints:
    """Verifies all new Model 1 REST API endpoints."""

    def test_incident_document_and_cert_in_endpoints(self, api_client):
        base = datetime.now(timezone.utc)
        # Ingest events to trigger RULE_001
        events = [
            {
                "event_id": "EVT-E2E-M1-01", "timestamp": base.isoformat(),
                "source": "ACCESS", "satellite_id": "SAT-INSAT-4B",
                "event_type": "SUSPICIOUS_LOGIN", "severity": "MEDIUM",
                "confidence": 0.85, "description": "Unusual night shift login",
                "action": "REVIEW", "evidence": {}, "related_events": [],
                "operator_id": "OP-901", "session_id": "S-MOD1-001",
            },
            {
                "event_id": "EVT-E2E-M1-02",
                "timestamp": (base + timedelta(seconds=45)).isoformat(),
                "source": "UPLINK", "satellite_id": "SAT-INSAT-4B",
                "event_type": "UNAUTHORIZED_COMMAND", "severity": "HIGH",
                "confidence": 0.95, "description": "Attempt to alter attitude control quaternion",
                "action": "BLOCK_ADVISORY", "evidence": {}, "related_events": [],
                "operator_id": "OP-901", "session_id": "S-MOD1-001",
            }
        ]
        for ev in events:
            r = api_client.post("/events/ingest", json=ev)
            assert r.status_code == 201

        # Check correlations
        corr_resp = api_client.get("/correlations/active")
        assert corr_resp.status_code == 200
        incidents = corr_resp.json()
        assert len(incidents) >= 1

        inc_id = incidents[0]["event_id"]

        # 1. Fetch Human-Readable Markdown Document
        doc_resp = api_client.get(f"/correlations/{inc_id}/document")
        assert doc_resp.status_code == 200
        doc_data = doc_resp.json()
        assert doc_data["incident_id"] == inc_id
        assert "INCIDENT UNDERSTANDING & FORENSIC DOSSIER" in doc_data["incident_document_md"]
        assert "CISO DASHBOARD" in doc_data["incident_document_md"]
        assert "CERT-In" in doc_data["incident_document_md"]

        # 2. Fetch Structured CERT-In Report
        cert_resp = api_client.get(f"/correlations/{inc_id}/cert-in")
        assert cert_resp.status_code == 200
        cert_data = cert_resp.json()
        assert cert_data["incident_id"] == inc_id
        assert cert_data["cert_in_regulatory_window_hours"] == 6
        assert cert_data["affected_entity_type"] == "Space Ground Station / Satellite TT&C Infrastructure"
        assert cert_data["satellite_id"] == "SAT-INSAT-4B"
        assert len(cert_data["impacted_systems"]) >= 1

    def test_ciso_notes_and_certin_summary_endpoints(self, api_client):
        # 1. POST /ciso/notes
        ciso_payload = {
            "incident_id": "INC-DEMO-001",
            "satellite_id": "SAT-GSAT-7A",
            "notes": "Emergency key rotation ordered by CISO team",
            "operator_id": "CISO-OPERATOR-1",
            "action_recommended": "ISOLATE_UPLINK_CONSOLE",
        }
        ciso_resp = api_client.post("/ciso/notes", json=ciso_payload)
        assert ciso_resp.status_code == 201
        data = ciso_resp.json()
        assert data["status"] == "ACCEPTED"
        assert data["event_id"].startswith("NOTE-")

        # 2. POST /cert-in/summary
        cert_payload = {
            "incident_id": "INC-DEMO-001",
            "satellite_id": "SAT-GSAT-7A",
            "cert_in_reference": "CERTIN-ADV-2026-9041",
            "summary": "Coordinated cyber probe against Indian space ground infrastructure",
            "mandate_actions": ["Isolate ground terminal", "Preserve audit logs", "Notify CERT-In within 6h"],
        }
        cert_resp = api_client.post("/cert-in/summary", json=cert_payload)
        assert cert_resp.status_code == 201
        data = cert_resp.json()
        assert data["status"] == "ACCEPTED"
        assert data["event_id"].startswith("CERTIN-")

        # 3. GET /patterns/historical
        pat_resp = api_client.get("/patterns/historical")
        assert pat_resp.status_code == 200
        assert "matched_incidents" in pat_resp.json()
