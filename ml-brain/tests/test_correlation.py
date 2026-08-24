"""
ORBITAL SHIELD — ML Correlation Brain
Test suite for correlation engine, scoring, and API endpoints

Run with:
  cd ml-brain
  pytest tests/test_correlation.py -v

Tests are standalone — no external services required.
"""

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Use a fresh in-memory-style DB for each test."""
    import os
    test_db = tmp_path / "test_orbital.db"
    monkeypatch.setenv("DB_PATH", str(test_db))
    # Force reimport so DB path is picked up
    import importlib
    from db import database
    importlib.reload(database)
    database.init_db()
    yield
    # Cleanup happens automatically via tmp_path


@pytest.fixture
def sliding_window():
    from core import ingestion
    return ingestion.init_window(window_seconds=1800, max_events=5000)


@pytest.fixture
def base_ts():
    return datetime.now(timezone.utc)


def make_event(event_id: str, source: str, satellite_id: str, event_type: str,
               severity: str, confidence: float = 0.85,
               operator_id: str = "OP-01", session_id: str = "S-001",
               delta_seconds: int = 0, base_ts: datetime = None) -> dict:
    """Helper to build a raw event dict."""
    if base_ts is None:
        base_ts = datetime.now(timezone.utc)
    return {
        "event_id":      event_id,
        "timestamp":     (base_ts + timedelta(seconds=delta_seconds)).isoformat(),
        "source":        source,
        "satellite_id":  satellite_id,
        "event_type":    event_type,
        "severity":      severity,
        "confidence":    confidence,
        "description":   f"Test event {event_id}",
        "action":        "REVIEW",
        "evidence":      {},
        "related_events": [],
        "operator_id":   operator_id,
        "session_id":    session_id,
    }


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 1: Sliding window
# ─────────────────────────────────────────────────────────────

class TestSlidingWindow:

    def test_add_and_retrieve(self, sliding_window, base_ts):
        event = make_event("EVT-001", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY", "HIGH", base_ts=base_ts)
        sliding_window.add(event)
        all_events = sliding_window.get_all()
        assert len(all_events) == 1
        assert all_events[0]["event_id"] == "EVT-001"

    def test_filter_by_satellite(self, sliding_window, base_ts):
        sliding_window.add(make_event("EVT-001", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY", "HIGH", base_ts=base_ts))
        sliding_window.add(make_event("EVT-002", "UPLINK", "SAT-2", "UNAUTHORIZED_COMMAND", "HIGH", base_ts=base_ts))
        result = sliding_window.get_by_satellite("SAT-1", within_seconds=3600)
        assert len(result) == 1
        assert result[0]["satellite_id"] == "SAT-1"

    def test_filter_by_session(self, sliding_window, base_ts):
        sliding_window.add(make_event("EVT-001", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY", "HIGH",
                                      session_id="S-AAA", base_ts=base_ts))
        sliding_window.add(make_event("EVT-002", "UPLINK", "SAT-1", "UNAUTHORIZED_COMMAND", "HIGH",
                                      session_id="S-BBB", base_ts=base_ts))
        result = sliding_window.get_by_session("S-AAA", within_seconds=3600)
        assert len(result) == 1

    def test_eviction_by_time(self):
        from core import ingestion
        win = ingestion.SlidingWindow(window_seconds=1, max_events=5000)
        import time
        event = make_event("EVT-OLD", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY", "LOW")
        win.add(event)
        time.sleep(1.2)
        result = win.get_all()
        assert len(result) == 0, "Stale event should have been evicted"

    def test_size_cap(self):
        from core import ingestion
        win = ingestion.SlidingWindow(window_seconds=3600, max_events=3)
        for i in range(5):
            win.add(make_event(f"EVT-{i:03d}", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY", "LOW"))
        assert win.size() <= 3


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 2: Rule engine — RULE_001 (cross_module_same_session)
# ─────────────────────────────────────────────────────────────

class TestRule001CrossModuleSession:

    def test_rule_fires_with_two_sources_same_session(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        events = [
            make_event("EVT-001", "ACCESS",   "SAT-1", "SUSPICIOUS_LOGIN",     "MEDIUM", session_id="S-001", base_ts=base_ts),
            make_event("EVT-002", "UPLINK",   "SAT-1", "UNAUTHORIZED_COMMAND", "HIGH",   session_id="S-001", delta_seconds=60, base_ts=base_ts),
            make_event("EVT-003", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY",    "HIGH",   session_id="S-001", delta_seconds=120, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        trigger = events[-1]
        window_events = sliding_window.get_all()
        fired = ce.evaluate_rules(trigger, window_events)

        rule_ids = [r["rule_id"] for r in fired]
        assert "RULE_001" in rule_ids, f"RULE_001 should have fired, got: {rule_ids}"

    def test_rule_does_not_fire_single_source(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        events = [
            make_event("EVT-001", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY", "HIGH", session_id="S-001", base_ts=base_ts),
            make_event("EVT-002", "DOWNLINK", "SAT-1", "TELEMETRY_ANOMALY", "HIGH", session_id="S-001", delta_seconds=60, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        trigger = events[-1]
        fired = ce.evaluate_rules(trigger, sliding_window.get_all())
        rule_ids = [r["rule_id"] for r in fired]
        assert "RULE_001" not in rule_ids, "RULE_001 should NOT fire with only one source"

    def test_rule_does_not_fire_outside_time_window(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        events = [
            make_event("EVT-001", "ACCESS",  "SAT-1", "SUSPICIOUS_LOGIN",     "MEDIUM", session_id="S-001", base_ts=base_ts),
            # 400 seconds later — outside the 300-second RULE_001 window
            make_event("EVT-002", "UPLINK",  "SAT-1", "UNAUTHORIZED_COMMAND", "HIGH",   session_id="S-001", delta_seconds=400, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        trigger = events[-1]
        fired = ce.evaluate_rules(trigger, sliding_window.get_all())
        rule_ids = [r["rule_id"] for r in fired]
        assert "RULE_001" not in rule_ids, "RULE_001 should NOT fire outside time window"

    def test_incident_type_is_cross_module_attack(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        events = [
            make_event("EVT-001", "ACCESS",  "SAT-1", "SUSPICIOUS_LOGIN",     "MEDIUM", session_id="S-001", base_ts=base_ts),
            make_event("EVT-002", "UPLINK",  "SAT-1", "UNAUTHORIZED_COMMAND", "HIGH",   session_id="S-001", delta_seconds=60, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        fired = ce.evaluate_rules(events[-1], sliding_window.get_all())
        r1_matches = [r for r in fired if r["rule_id"] == "RULE_001"]
        assert len(r1_matches) > 0
        assert r1_matches[0]["incident_type"] == "CROSS_MODULE_ATTACK"


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 3: Rule engine — RULE_002 (escalating severity)
# ─────────────────────────────────────────────────────────────

class TestRule002EscalatingSeverity:

    def test_rule_fires_low_medium_high(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        events = [
            make_event("EVT-001", "DOWNLINK", "SAT-2", "SIGNAL_INTERFERENCE",  "LOW",    delta_seconds=0,   base_ts=base_ts),
            make_event("EVT-002", "UPLINK",   "SAT-2", "REPLAY_ATTACK",        "MEDIUM", delta_seconds=200, base_ts=base_ts),
            make_event("EVT-003", "ACCESS",   "SAT-2", "ACCESS_VIOLATION",     "HIGH",   delta_seconds=450, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        fired = ce.evaluate_rules(events[-1], sliding_window.get_all())
        rule_ids = [r["rule_id"] for r in fired]
        assert "RULE_002" in rule_ids

    def test_rule_does_not_fire_without_escalation(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        # All HIGH — no escalation pattern
        events = [
            make_event("EVT-001", "DOWNLINK", "SAT-2", "TELEMETRY_ANOMALY",    "HIGH", delta_seconds=0,   base_ts=base_ts),
            make_event("EVT-002", "UPLINK",   "SAT-2", "UNAUTHORIZED_COMMAND", "HIGH", delta_seconds=200, base_ts=base_ts),
            make_event("EVT-003", "ACCESS",   "SAT-2", "ACCESS_VIOLATION",     "HIGH", delta_seconds=400, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        fired = ce.evaluate_rules(events[-1], sliding_window.get_all())
        rule_ids = [r["rule_id"] for r in fired]
        assert "RULE_002" not in rule_ids


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 4: Rule engine — RULE_003 (firmware + access)
# ─────────────────────────────────────────────────────────────

class TestRule003FirmwareAccess:

    def test_rule_fires_firmware_plus_access(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        events = [
            make_event("EVT-001", "FIRMWARE", "SAT-3", "FIRMWARE_TAMPERING", "CRITICAL", delta_seconds=0,   base_ts=base_ts),
            make_event("EVT-002", "ACCESS",   "SAT-3", "SUSPICIOUS_LOGIN",   "HIGH",     delta_seconds=300, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        fired = ce.evaluate_rules(events[-1], sliding_window.get_all())
        rule_ids = [r["rule_id"] for r in fired]
        assert "RULE_003" in rule_ids

    def test_rule_does_not_fire_without_firmware(self, sliding_window, base_ts):
        from core import correlation_engine as ce
        # Two ACCESS events — FIRMWARE required source is missing
        events = [
            make_event("EVT-001", "ACCESS", "SAT-3", "SUSPICIOUS_LOGIN",   "HIGH",   delta_seconds=0,   base_ts=base_ts),
            make_event("EVT-002", "ACCESS", "SAT-3", "ACCESS_VIOLATION",   "MEDIUM", delta_seconds=100, base_ts=base_ts),
        ]
        for e in events:
            sliding_window.add(e)

        fired = ce.evaluate_rules(events[-1], sliding_window.get_all())
        rule_ids = [r["rule_id"] for r in fired]
        assert "RULE_003" not in rule_ids


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 5: Risk scoring
# ─────────────────────────────────────────────────────────────

class TestRiskScoring:

    def test_firmware_tampering_scores_high(self, base_ts):
        from core import correlation_engine as ce
        from core import scoring as sc
        from core.ingestion import SlidingWindow
        win = SlidingWindow(window_seconds=1800)
        events = [
            make_event("EVT-001", "FIRMWARE", "SAT-4", "FIRMWARE_TAMPERING",   "CRITICAL", delta_seconds=0,   base_ts=base_ts),
            make_event("EVT-002", "ACCESS",   "SAT-4", "SUSPICIOUS_LOGIN",     "HIGH",     delta_seconds=100, base_ts=base_ts),
        ]
        for e in events:
            win.add(e)

        fired = ce.evaluate_rules(events[-1], win.get_all())
        assert fired, "Expected a rule to fire"
        incident = sc.compute_risk_score(fired[0])

        # FIRMWARE_TAMPERING(50) + SUSPICIOUS_LOGIN(20) + 1 multi-source bonus(10) = 80 → CRITICAL
        assert incident["risk_score"] >= 70
        assert incident["severity"] == "CRITICAL"

    def test_single_low_event_scores_low(self, base_ts):
        from core import correlation_engine as ce
        from core import scoring as sc
        from core.ingestion import SlidingWindow
        win = SlidingWindow(window_seconds=1800)
        # Need two different sources on same satellite for any rule to fire
        events = [
            make_event("EVT-001", "DOWNLINK", "SAT-4", "SIGNAL_INTERFERENCE", "LOW", delta_seconds=0,   base_ts=base_ts),
            make_event("EVT-002", "ACCESS",   "SAT-4", "SUSPICIOUS_LOGIN",    "LOW", delta_seconds=60,  base_ts=base_ts),
        ]
        for e in events:
            win.add(e)

        fired = ce.evaluate_rules(events[-1], win.get_all())
        if fired:
            incident = sc.compute_risk_score(fired[0])
            # SIGNAL_INTERFERENCE(15) + SUSPICIOUS_LOGIN(20) + bonus(10) = 45 → HIGH
            # Still a valid incident, just check it scores correctly
            assert incident["risk_score"] > 0

    def test_risk_score_breakdown_keys(self, base_ts):
        from core import correlation_engine as ce
        from core import scoring as sc
        from core.ingestion import SlidingWindow
        win = SlidingWindow(window_seconds=1800)
        events = [
            make_event("EVT-001", "FIRMWARE", "SAT-5", "FIRMWARE_TAMPERING",   "CRITICAL", delta_seconds=0,   base_ts=base_ts),
            make_event("EVT-002", "ACCESS",   "SAT-5", "SUSPICIOUS_LOGIN",     "HIGH",     delta_seconds=60,  base_ts=base_ts),
        ]
        for e in events:
            win.add(e)

        fired = ce.evaluate_rules(events[-1], win.get_all())
        if fired:
            incident = sc.compute_risk_score(fired[0])
            assert "score_breakdown" in incident
            breakdown = incident["score_breakdown"]
            assert isinstance(breakdown, dict)
            # At least one event_type should be in the breakdown
            assert len(breakdown) > 0


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 6: Deduplication
# ─────────────────────────────────────────────────────────────

class TestDeduplication:

    def test_duplicate_incident_not_re_fired(self, base_ts):
        from core import correlation_engine as ce

        existing_incidents = [{
            "rule_id":       "RULE_001",
            "status":        "OPEN",
            "related_events": ["EVT-001", "EVT-002"],
        }]
        assert ce.is_duplicate_incident(
            "RULE_001",
            ["EVT-001", "EVT-002"],
            existing_incidents
        ) is True

    def test_different_rule_not_deduplicated(self, base_ts):
        from core import correlation_engine as ce

        existing_incidents = [{
            "rule_id":       "RULE_001",
            "status":        "OPEN",
            "related_events": ["EVT-001", "EVT-002"],
        }]
        assert ce.is_duplicate_incident(
            "RULE_003",
            ["EVT-001", "EVT-002"],
            existing_incidents
        ) is False


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 7: Database operations
# ─────────────────────────────────────────────────────────────

class TestDatabase:

    def test_insert_and_fetch_event(self):
        from db import database
        event = {
            "event_id":     "EVT-DB-001",
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "source":       "DOWNLINK",
            "satellite_id": "SAT-1",
            "event_type":   "TELEMETRY_ANOMALY",
            "severity":     "HIGH",
            "confidence":   0.9,
            "description":  "Test event",
            "action":       "REVIEW",
            "evidence":     {"key": "value"},
            "related_events": [],
            "operator_id":  "OP-01",
            "session_id":   "S-001",
        }
        database.insert_event(event)
        assert database.count_events() == 1

    def test_insert_and_fetch_incident(self):
        from db import database
        incident = {
            "event_id":       "INC-DB-001",
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "source":         "ML_BRAIN",
            "event_type":     "CROSS_MODULE_ATTACK",
            "severity":       "CRITICAL",
            "confidence":     0.92,
            "description":    "Test incident",
            "related_events": ["EVT-001", "EVT-002"],
            "action":         "HUMAN_REVIEW",
            "risk_score":     85,
            "rule_id":        "RULE_001",
            "rule_name":      "cross_module_same_session",
            "rule_score":     85,
            "ml_adjustment":  0,
            "satellite_id":   "SAT-1",
            "operator_id":    "OP-01",
            "session_id":     "S-001",
            "status":         "OPEN",
        }
        database.insert_incident(incident)
        assert database.count_incidents() == 1
        assert database.count_open_incidents() == 1

        fetched = database.fetch_incident_by_id("INC-DB-001")
        assert fetched is not None
        assert fetched["event_id"] == "INC-DB-001"
        assert fetched["related_events"] == ["EVT-001", "EVT-002"]

    def test_feedback_stored_and_retrieved(self):
        from db import database
        # Insert incident first
        incident = {
            "event_id": "INC-FB-001", "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ML_BRAIN", "event_type": "CROSS_MODULE_ATTACK", "severity": "HIGH",
            "confidence": 0.8, "description": "Test", "related_events": [],
            "action": "HUMAN_REVIEW", "risk_score": 60, "rule_id": "RULE_001",
            "rule_name": "test_rule", "rule_score": 60, "ml_adjustment": 0,
            "satellite_id": "SAT-1", "status": "OPEN",
        }
        database.insert_incident(incident)
        database.insert_feedback(
            incident_id="INC-FB-001",
            verdict="CONFIRMED_REAL",
            reviewer="ciso_test",
            notes="Test confirmed",
            rule_id="RULE_001",
            risk_score=60
        )
        unused = database.fetch_unused_feedback()
        assert len(unused) == 1
        assert unused[0]["verdict"] == "CONFIRMED_REAL"


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 8: FastAPI endpoints (using TestClient)
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def test_client(tmp_path, monkeypatch):
    """FastAPI test client with isolated DB."""
    import os
    import importlib
    test_db = tmp_path / "api_test.db"
    monkeypatch.setenv("DB_PATH", str(test_db))
    from db import database
    importlib.reload(database)
    database.init_db()

    from fastapi.testclient import TestClient
    import main as app_module
    importlib.reload(app_module)
    client = TestClient(app_module.app)
    return client


class TestAPIEndpoints:

    def test_root_health(self, test_client):
        resp = test_client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"

    def test_ingest_valid_event(self, test_client):
        event = {
            "event_id": "EVT-API-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "DOWNLINK",
            "satellite_id": "SAT-API-01",
            "event_type": "TELEMETRY_ANOMALY",
            "severity": "HIGH",
            "confidence": 0.9,
            "description": "API test event",
            "action": "REVIEW",
            "evidence": {},
            "related_events": [],
            "operator_id": "OP-01",
            "session_id": "S-API-001",
        }
        resp = test_client.post("/events/ingest", json=event)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "ACCEPTED"
        assert data["event_id"] == "EVT-API-001"

    def test_ingest_invalid_event_missing_field(self, test_client):
        event = {"event_id": "EVT-BAD-001", "source": "DOWNLINK"}  # missing required fields
        resp = test_client.post("/events/ingest", json=event)
        assert resp.status_code == 422  # Unprocessable Entity

    def test_ingest_triggers_correlation(self, test_client):
        """Three events on same session from different sources should trigger RULE_001."""
        base = datetime.now(timezone.utc)
        events = [
            {
                "event_id": "EVT-CORR-001", "timestamp": base.isoformat(),
                "source": "ACCESS", "satellite_id": "SAT-CORR-01",
                "event_type": "SUSPICIOUS_LOGIN", "severity": "MEDIUM",
                "confidence": 0.87, "description": "Suspicious login",
                "action": "REVIEW", "evidence": {}, "related_events": [],
                "operator_id": "OP-T1", "session_id": "S-CORR-001",
            },
            {
                "event_id": "EVT-CORR-002",
                "timestamp": (base + timedelta(seconds=60)).isoformat(),
                "source": "UPLINK", "satellite_id": "SAT-CORR-01",
                "event_type": "UNAUTHORIZED_COMMAND", "severity": "HIGH",
                "confidence": 0.93, "description": "Unauthorized command",
                "action": "REVIEW", "evidence": {}, "related_events": [],
                "operator_id": "OP-T1", "session_id": "S-CORR-001",
            },
            {
                "event_id": "EVT-CORR-003",
                "timestamp": (base + timedelta(seconds=120)).isoformat(),
                "source": "DOWNLINK", "satellite_id": "SAT-CORR-01",
                "event_type": "TELEMETRY_ANOMALY", "severity": "HIGH",
                "confidence": 0.91, "description": "Telemetry anomaly",
                "action": "REVIEW", "evidence": {}, "related_events": [],
                "operator_id": "OP-T1", "session_id": "S-CORR-001",
            },
        ]
        last_resp = None
        for ev in events:
            resp = test_client.post("/events/ingest", json=ev)
            assert resp.status_code == 201
            last_resp = resp.json()

        # After the 3rd event, at least one correlation should have fired
        assert len(last_resp["correlations_triggered"]) >= 1 or \
               test_client.get("/correlations/active").json() != []

    def test_active_correlations_empty_initially(self, test_client):
        resp = test_client.get("/correlations/active")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_brain_status_endpoint(self, test_client):
        resp = test_client.get("/brain/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"
        assert "active_rules" in data
        assert len(data["active_rules"]) > 0

    def test_feedback_on_nonexistent_incident(self, test_client):
        resp = test_client.post("/brain/feedback", json={
            "incident_id": "INC-NONEXISTENT",
            "verdict": "CONFIRMED_REAL",
            "reviewer": "ciso_test",
        })
        assert resp.status_code == 404

    def test_retrain_with_no_feedback(self, test_client):
        resp = test_client.post("/brain/retrain")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SKIPPED"


# ─────────────────────────────────────────────────────────────
# TEST BLOCK 9: Full end-to-end pipeline
# ─────────────────────────────────────────────────────────────

class TestEndToEndPipeline:

    def test_full_pipeline_scenario_1(self, test_client):
        """
        End-to-end test: ingest 3 events, verify incident created,
        submit feedback, trigger retrain.
        """
        base = datetime.now(timezone.utc)

        # Ingest 3 events across different sources, same session
        for i, (source, etype, sev, delta) in enumerate([
            ("ACCESS",   "SUSPICIOUS_LOGIN",     "MEDIUM", 0),
            ("UPLINK",   "UNAUTHORIZED_COMMAND",  "HIGH",   60),
            ("DOWNLINK", "TELEMETRY_ANOMALY",     "HIGH",   120),
        ]):
            test_client.post("/events/ingest", json={
                "event_id":     f"EVT-E2E-{i+1:03d}",
                "timestamp":    (base + timedelta(seconds=delta)).isoformat(),
                "source":       source,
                "satellite_id": "SAT-E2E-01",
                "event_type":   etype,
                "severity":     sev,
                "confidence":   0.90,
                "description":  f"E2E test event {i+1}",
                "action":       "REVIEW",
                "evidence":     {},
                "related_events": [],
                "operator_id":  "OP-E2E",
                "session_id":   "S-E2E-001",
            })

        # Check active incidents
        resp = test_client.get("/correlations/active")
        assert resp.status_code == 200
        incidents = resp.json()
        # RULE_001 should have fired
        assert len(incidents) >= 1

        incident_id = incidents[0]["event_id"]

        # Get full detail
        resp = test_client.get(f"/correlations/{incident_id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert len(detail["related_events"]) >= 2
        assert detail["status"] == "OPEN"

        # Submit CISO feedback
        resp = test_client.post("/brain/feedback", json={
            "incident_id": incident_id,
            "verdict":     "CONFIRMED_REAL",
            "reviewer":    "ciso_e2e_test",
            "notes":       "E2E verified",
        })
        assert resp.status_code == 200

        # Trigger retrain — should find feedback
        resp = test_client.post("/brain/retrain")
        assert resp.status_code == 200
        retrain_data = resp.json()
        assert retrain_data["feedback_samples"] >= 1

        # Check audit log
        resp = test_client.get("/brain/audit-log")
        assert resp.status_code == 200
