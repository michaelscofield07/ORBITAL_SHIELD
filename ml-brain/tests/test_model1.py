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


# ─────────────────────────────────────────────────────────────
# 8. TEST SUITE: First-Class CERT-In Integration & Reporting
# ─────────────────────────────────────────────────────────────

class TestCertInIntegration:
    """
    Verifies full CERT-In integration in Model 1:
      1. Ingestion via POST /events/ingest with source="CERT_IN" and via POST /cert-in/summary
      2. Normalization and canonical cert_in_info preservation
      3. Authorization status evaluation for CERT-In events
      4. Model 1 Understanding enriched with CERT-In intelligence in Markdown (Sections 1, 2, 5)
      5. Forensic dossier isolation of unauthorized events alongside threat intelligence
      6. GET /correlations/{id}/cert-in and GET /correlations/{id}/document API payload validation
    """

    def test_cert_in_event_ingest_and_normalization(self, api_client):
        # Ingest CERT-In event directly through POST /events/ingest
        cert_in_event = {
            "event_id": "CERTIN-EVT-2026-001",
            "timestamp": "2026-09-18T12:00:00Z",
            "source": "CERT_IN",
            "satellite_id": "SAT-GSAT-7A",
            "event_type": "CERT_IN_ADVISORY",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "description": "CERT-In National Advisory: Critical unauthorized ground station command injection threat",
            "action": "REVIEW",
            "cert_in_reference": "CERTIN-ADV-2026-9041",
            "title": "Unauthorized Ground Station Command Injection",
            "threat_vectors": ["UNAUTHORIZED_COMMAND_INJECTION", "TELEMETRY_SPOOFING"],
            "recommended_actions": ["Isolate ground terminal", "Invalidate active session tokens"],
            "mandate_actions": ["Notify CERT-In within 6h"],
            "cert_in_details": "Coordinated cyber probe targeting TT&C telemetry uplink",
        }
        resp = api_client.post("/events/ingest", json=cert_in_event)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "ACCEPTED"
        assert data["event_id"] == "CERTIN-EVT-2026-001"

        # Verify DB storage and cert_in_info extraction
        advisories = database.fetch_cert_in_advisories(satellite_id="SAT-GSAT-7A")
        assert len(advisories) >= 1
        adv = next(a for a in advisories if a["event_id"] == "CERTIN-EVT-2026-001")
        assert adv["source"] == "CERT_IN"
        assert adv["cert_in_info"]["cert_in_reference"] == "CERTIN-ADV-2026-9041"
        assert "UNAUTHORIZED_COMMAND_INJECTION" in adv["cert_in_info"]["threat_vectors"]
        assert adv["authorization_status"] == "UNAUTHORIZED"

    def test_cert_in_authorization_classification(self):
        # Case A: Breach / unauthorized keyword -> UNAUTHORIZED
        event_a = IncomingEvent(
            event_id="CERTIN-A-01",
            timestamp=datetime.now(timezone.utc),
            source=SourceModule.CERT_IN,
            satellite_id="SAT-01",
            event_type="CERT_IN_ADVISORY",
            severity="HIGH",
            confidence=0.9,
            description="CERT-In alert: Unauthorized credential compromise and intrusion detected",
            action=ActionType.REVIEW,
        )
        norm_a = normalization.normalize_security_event(event_a)
        assert norm_a["authorization_status"] == AuthorizationStatus.UNAUTHORIZED.value
        assert "unauthorized" in norm_a["authorization_reason"].lower()

        # Case B: High severity advisory without breach keyword -> SUSPICIOUS
        event_b = IncomingEvent(
            event_id="CERTIN-B-01",
            timestamp=datetime.now(timezone.utc),
            source=SourceModule.CERT_IN,
            satellite_id="SAT-01",
            event_type="CERT_IN_ADVISORY",
            severity="HIGH",
            confidence=0.9,
            description="CERT-In vulnerability notice: Potential signal interference vulnerability",
            action=ActionType.REVIEW,
        )
        norm_b = normalization.normalize_security_event(event_b)
        assert norm_b["authorization_status"] == AuthorizationStatus.SUSPICIOUS.value

    def test_cert_in_in_model1_understanding_and_markdown(self):
        # Construct incident and contributing events
        incident = {
            "event_id": "INC-CERTIN-TEST-01",
            "timestamp": "2026-09-18T12:30:00Z",
            "satellite_id": "SAT-ORBITAL-01",
            "event_type": "CROSS_MODULE_ATTACK",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "risk_score": 140,
            "rule_id": "RULE_001",
            "rule_name": "cross_module_same_session",
            "rule_score": 100,
            "related_events": ["EVT-ACT-01", "EVT-CMD-01", "CERTIN-ADV-01"],
            "description": "Multi-stage attack with correlated CERT-In advisory",
        }

        contributing_events = [
            {
                "event_id": "EVT-ACT-01",
                "timestamp": "2026-09-18T12:20:00Z",
                "source": "ACCESS",
                "satellite_id": "SAT-ORBITAL-01",
                "event_type": "ACCESS_VIOLATION",
                "severity": "HIGH",
                "actor": "OP-ROGUE",
                "operator_id": "OP-ROGUE",
                "session_id": "S-ROGUE-01",
                "resource": "OBC_TELEMETRY_BUS",
                "authorization_status": "UNAUTHORIZED",
                "authorization_reason": "Operator outside authorized boundary",
                "description": "Access violation on OBC bus",
            },
            {
                "event_id": "EVT-CMD-01",
                "timestamp": "2026-09-18T12:22:00Z",
                "source": "UPLINK",
                "satellite_id": "SAT-ORBITAL-01",
                "event_type": "UNAUTHORIZED_COMMAND",
                "severity": "CRITICAL",
                "actor": "OP-ROGUE",
                "operator_id": "OP-ROGUE",
                "session_id": "S-ROGUE-01",
                "resource": "ATTITUDE_THRUSTER",
                "authorization_status": "UNAUTHORIZED",
                "authorization_reason": "Dual authorization missing",
                "description": "Unauthorized attitude adjustment command",
            },
            {
                "event_id": "CERTIN-ADV-01",
                "timestamp": "2026-09-18T12:25:00Z",
                "source": "CERT_IN",
                "satellite_id": "SAT-ORBITAL-01",
                "event_type": "CERT_IN_ADVISORY",
                "severity": "CRITICAL",
                "actor": "CERT_IN_DESK",
                "operator_id": "CERT_IN_DESK",
                "authorization_status": "UNAUTHORIZED",
                "authorization_reason": "CERT-In advisory flagged unauthorized threat",
                "description": "CERT-In Advisory ADV-2026-8801: Active threat campaign targeting satellite TT&C",
                "cert_in_info": {
                    "cert_in_reference": "CERTIN-ADV-2026-8801",
                    "title": "Active TT&C Ground Cyber Threat",
                    "threat_vectors": ["UNAUTHORIZED_UPLINK_COMMAND", "SESSION_HIJACKING"],
                    "recommended_actions": ["Emergency uplink freeze", "Dual-key authorization enforcement"],
                    "mandate_actions": ["Submit 6-Hour preliminary report to CERT-In"],
                }
            }
        ]

        enriched = model1_understanding.understand_incident(incident, contributing_events)

        # 1. cert_in_context populated
        ctx = enriched["cert_in_context"]
        assert ctx["has_advisory"] is True
        assert "CERTIN-ADV-2026-8801" in ctx["references"]
        assert "UNAUTHORIZED_UPLINK_COMMAND" in ctx["threat_vectors"]
        assert "Emergency uplink freeze" in ctx["recommended_actions"]

        # 2. Forensic dossier isolates primary unauthorized events vs intelligence
        chain = enriched["unauthorized_chain"]
        primary = [s for s in chain if s["chain_role"] == "PRIMARY_UNAUTHORIZED_ACTIVITY"]
        intel = [s for s in chain if s["chain_role"] == "EXTERNAL_THREAT_INTELLIGENCE"]
        assert len(primary) == 2  # ACCESS_VIOLATION and UNAUTHORIZED_COMMAND
        assert len(intel) == 1    # CERT-In advisory

        # 3. Markdown content verification
        doc = enriched["incident_document_md"]
        assert "CERTIN-ADV-2026-8801" in doc
        assert "CERT-In Threat Advisory Intelligence" in doc
        assert "Emergency uplink freeze" in doc
        assert "EXTERNAL_THREAT_INTELLIGENCE" in doc
        assert "CERT-In Intelligence Advisory (CERTIN-ADV-2026-8801)" in doc
        assert "CERT-In 6-HOUR COMPLIANCE & REGULATORY AUDIT REPORT" in doc
        assert "Correlated CERT-In Advisory Reference(s):** `CERTIN-ADV-2026-8801`" in doc

        # 4. CERT-In compliance report verification
        report = enriched["cert_in_report"]
        assert "CERTIN-ADV-2026-8801" in report["matched_advisories"]
        assert "UNAUTHORIZED_UPLINK_COMMAND" in report["matched_threat_vectors"]
        assert "Emergency uplink freeze" in report["recommended_remediation_actions"]

    def test_cert_in_summary_api_and_incident_refresh(self, api_client):
        # 1. Ingest normal events creating an incident
        base = datetime.now(timezone.utc)
        events = [
            {
                "event_id": "EVT-C-01",
                "timestamp": (base - timedelta(seconds=60)).isoformat(),
                "source": "ACCESS", "satellite_id": "SAT-MEGHAT-01",
                "event_type": "ACCESS_VIOLATION", "severity": "HIGH",
                "confidence": 0.9, "description": "Unauthorized access to telemetry module",
                "action": "FLAG", "evidence": {}, "related_events": [],
                "operator_id": "OP-TEST-01", "session_id": "S-CERT-TEST",
            },
            {
                "event_id": "EVT-C-02",
                "timestamp": base.isoformat(),
                "source": "UPLINK", "satellite_id": "SAT-MEGHAT-01",
                "event_type": "UNAUTHORIZED_COMMAND", "severity": "HIGH",
                "confidence": 0.95, "description": "Unauthorized payload test command",
                "action": "BLOCK_ADVISORY", "evidence": {}, "related_events": [],
                "operator_id": "OP-TEST-01", "session_id": "S-CERT-TEST",
            }
        ]
        for ev in events:
            r = api_client.post("/events/ingest", json=ev)
            assert r.status_code == 201

        # Fetch active incident
        corr_resp = api_client.get("/correlations/active")
        assert corr_resp.status_code == 200
        incidents = corr_resp.json()
        assert len(incidents) >= 1
        inc_id = incidents[0]["event_id"]

        # 2. Ingest CERT-In summary referencing this incident
        summary_payload = {
            "incident_id": inc_id,
            "satellite_id": "SAT-MEGHAT-01",
            "cert_in_reference": "CERTIN-ADV-2026-MEGHAT",
            "title": "Targeted Space Ground Telemetry Exploit",
            "summary": "Confirmed external exploitation campaign targeting GS telemetry channels",
            "severity": "CRITICAL",
            "threat_vectors": ["GROUND_COMMAND_INJECTION", "TELEMETRY_OVERRIDE"],
            "recommended_actions": ["Terminate active uplink sessions", "Enable MAC verification on all frames"],
            "mandate_actions": ["Dispatch statutory notification under Rule 12"],
        }
        sum_resp = api_client.post("/cert-in/summary", json=summary_payload)
        assert sum_resp.status_code == 201

        # 3. Verify GET /correlations/{id}/document has updated CERT-In context
        doc_resp = api_client.get(f"/correlations/{inc_id}/document")
        assert doc_resp.status_code == 200
        doc_json = doc_resp.json()
        assert "cert_in_context" in doc_json
        assert doc_json["cert_in_context"]["has_advisory"] is True
        assert "CERTIN-ADV-2026-MEGHAT" in doc_json["cert_in_context"]["references"]
        assert "CERTIN-ADV-2026-MEGHAT" in doc_json["incident_document_md"]

        # 4. Verify GET /correlations/{id}/cert-in has updated CERT-In fields
        cert_resp = api_client.get(f"/correlations/{inc_id}/cert-in")
        assert cert_resp.status_code == 200
        cert_json = cert_resp.json()
        assert "CERTIN-ADV-2026-MEGHAT" in cert_json["matched_advisories"]
        assert "GROUND_COMMAND_INJECTION" in cert_json["matched_threat_vectors"]
        assert "Terminate active uplink sessions" in cert_json["recommended_remediation_actions"]


# ─────────────────────────────────────────────────────────────
# 9. TEST SUITE: Model 1 Verification Gaps & Edge Cases
# ─────────────────────────────────────────────────────────────

class TestModel1CoverageGaps:
    """Verifies edge cases identified in verification audit for Model 1."""

    def test_authorized_classification_with_rationale(self):
        """Asserts that engine classifies as AUTHORIZED when contributing events are routine operations."""
        incident = {
            "event_id": "INC-AUTH-001",
            "timestamp": "2026-09-18T14:00:00Z",
            "rule_id": "RULE_001",
            "rule_name": "Cross-Module Session Correlation",
            "event_type": "OPERATIONAL_CORRELATION",
            "severity": "INFO",
            "risk_score": 15,
            "satellite_id": "SAT-ROUTINE-01",
        }
        contributing = [
            {
                "event_id": "E-AUTH-1",
                "timestamp": "2026-09-18T13:58:00Z",
                "source": "DOWNLINK",
                "event_type": "TELEMETRY_LOG",
                "severity": "INFO",
                "action": "LOG",
                "authorization_status": "AUTHORIZED",
                "operator_id": "mission_ops",
            },
            {
                "event_id": "E-AUTH-2",
                "timestamp": "2026-09-18T13:59:00Z",
                "source": "UPLINK",
                "event_type": "SCHEDULED_TELECOMMAND",
                "severity": "INFO",
                "action": "LOG",
                "authorization_status": "AUTHORIZED",
                "operator_id": "mission_ops",
            },
        ]
        enriched = model1_understanding.understand_incident(incident, contributing)
        assert enriched["authorization_status"] == AuthorizationStatus.AUTHORIZED.value
        assert "AUTHORIZED" in enriched["authorization_reason"]
        assert "normal operational parameters" in enriched["authorization_reason"]

    def test_unknown_authorization_status_handling(self):
        """Verifies normalization and understanding of UNKNOWN authorization status."""
        raw = {
            "event_id": "EVT-UNK-001",
            "timestamp": "2026-09-18T14:10:00Z",
            "source": "DOWNLINK",
            "satellite_id": "SAT-TEST-01",
            "event_type": "TELEMETRY_ANOMALY",
            "severity": "MEDIUM",
            "confidence": 0.70,
            "description": "Anomalous thermal sensor deviation with missing header auth",
            "action": "MONITOR",
            "authorization_status": "UNKNOWN",
        }
        event = IncomingEvent(**raw)
        norm = normalization.normalize_security_event(event)
        assert norm["authorization_status"] == AuthorizationStatus.UNKNOWN.value

        incident = {
            "event_id": "INC-UNK-001",
            "timestamp": "2026-09-18T14:12:00Z",
            "rule_id": "RULE_002",
            "rule_name": "Escalating Severity Anomaly Pattern",
            "event_type": "SUSPICIOUS_ACTIVITY",
            "severity": "MEDIUM",
            "risk_score": 50,
        }
        enriched = model1_understanding.understand_incident(incident, [norm])
        assert enriched["authorization_status"] == AuthorizationStatus.SUSPICIOUS.value
        assert "SUSPICIOUS" in enriched["authorization_reason"]

    def test_cert_in_report_zero_related_events(self, api_client):
        """Asserts that CERT-In report generates cleanly when incident has zero related events."""
        now_iso = datetime.now(timezone.utc).isoformat()
        inc_id = "INC-ZERO-EVTS"
        inc = {
            "event_id": inc_id,
            "timestamp": now_iso,
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "LOW",
            "confidence": 0.60,
            "description": "Correlated anomaly without populated events",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 30,
            "rule_id": "RULE-001",
            "rule_name": "Isolated Alert",
            "satellite_id": "SAT-ZERO-01",
            "status": "OPEN",
            "created_at": now_iso,
        }
        database.insert_incident(inc)

        resp = api_client.get(f"/correlations/{inc_id}/cert-in")
        assert resp.status_code == 200
        report = resp.json()
        assert report["incident_id"] == inc_id
        assert report["cert_in_regulatory_window_hours"] == 6
        assert report["affected_entity_type"] is not None

    def test_cert_in_report_nonexistent_incident_returns_404(self, api_client):
        """Asserts HTTP 404 when querying CERT-In report for an unknown incident."""
        resp = api_client.get("/correlations/INC-DOES-NOT-EXIST-404/cert-in")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_incident_document_missing_optional_fields(self, api_client):
        """Verifies markdown report formatting doesn't fail when optional fields are omitted."""
        now_iso = datetime.now(timezone.utc).isoformat()
        inc_id = "INC-SPARSE-001"
        inc = {
            "event_id": inc_id,
            "timestamp": now_iso,
            "source": "ML_BRAIN",
            "event_type": "SECURITY_INCIDENT",
            "severity": "HIGH",
            "confidence": 0.85,
            "description": "Sparse incident missing optional fields",
            "related_events": [],
            "action": "HUMAN_REVIEW",
            "risk_score": 70,
            "status": "OPEN",
            "created_at": now_iso,
        }
        database.insert_incident(inc)

        resp = api_client.get(f"/correlations/{inc_id}/document")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["incident_id"] == inc_id
        assert len(doc["incident_document_md"]) > 100
        assert "INCIDENT UNDERSTANDING & FORENSIC DOSSIER" in doc["incident_document_md"]


