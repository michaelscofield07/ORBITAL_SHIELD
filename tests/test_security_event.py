"""Unit tests for Canonical SecurityEvent schema and event synthesis."""

import pytest
from app.schemas.security_event import SecurityEvent
from app.schemas.telemetry import TelemetryInput
from app.services.telemetry_processor import TelemetryProcessor
from app.utils.hashing import compute_telemetry_hash


def test_security_event_schema_conformance():
    """SecurityEvent adheres strictly to project-wide shared schema."""
    event = SecurityEvent(
        event_id="EVT-DL-000001",
        timestamp="2026-08-25T02:14:30Z",
        source="DOWNLINK",
        satellite_id="SAT-EO-01",
        event_type="TELEMETRY_ANOMALY",
        severity="HIGH",
        confidence=0.93,
        description="Unexpected thermal increase detected: 80.0°C exceeds baseline.",
        action="REVIEW",
        evidence={
            "temperature": 80.0,
            "anomaly_score": -0.22,
            "integrity_status": "VALID"
        },
        related_events=[]
    )

    dumped = event.model_dump()
    assert dumped["event_id"] == "EVT-DL-000001"
    assert dumped["source"] == "DOWNLINK"
    assert dumped["satellite_id"] == "SAT-EO-01"
    assert dumped["event_type"] == "TELEMETRY_ANOMALY"
    assert dumped["severity"] == "HIGH"
    assert dumped["action"] in ("REVIEW", "ALERT")
    assert isinstance(dumped["evidence"], dict)
    assert isinstance(dumped["related_events"], list)


def test_thermal_spoof_generates_security_event(db_session):
    """Thermal spoofing generates an event with source=DOWNLINK and action=REVIEW."""
    processor = TelemetryProcessor(db=db_session)
    packet = TelemetryInput(
        timestamp="2026-08-25T02:14:30Z",
        satellite_id="SAT-EO-01",
        sequence_number=1001,
        temperature=82.0,
        battery=88.0,
        signal_strength=-70.0
    )
    packet.packet_hash = compute_telemetry_hash(packet)

    response = processor.process_telemetry(packet)

    assert response.security_event is not None
    event = response.security_event
    assert event.source == "DOWNLINK"
    assert event.satellite_id == "SAT-EO-01"
    assert event.event_type in ("TELEMETRY_SPOOFING", "TELEMETRY_ANOMALY")
    assert event.severity in ("HIGH", "CRITICAL")
    assert event.action == "REVIEW"
    assert event.evidence["temperature"] == 82.0


def test_compound_tampering_generates_critical_alert(db_session):
    """Hash tampering combined with sequence jump triggers CRITICAL severity and ALERT action."""
    processor = TelemetryProcessor(db=db_session)

    # Establish baseline sequence 100
    p1 = TelemetryInput(
        timestamp="2026-08-25T02:00:00Z",
        satellite_id="SAT-EO-01",
        sequence_number=100,
        temperature=23.0,
        battery=88.0,
        signal_strength=-70.0
    )
    p1.packet_hash = compute_telemetry_hash(p1)
    processor.process_telemetry(p1)

    # Tampered packet: Sequence jump to 150 + forged bad hash
    p2 = TelemetryInput(
        timestamp="2026-08-25T02:00:06Z",
        satellite_id="SAT-EO-01",
        sequence_number=150,
        temperature=75.0,
        battery=88.0,
        signal_strength=-70.0,
        packet_hash="bad_tampered_hash_value"
    )

    response = processor.process_telemetry(p2)

    assert response.security_event is not None
    event = response.security_event
    assert event.event_type == "TELEMETRY_INTEGRITY_FAILURE"
    assert event.severity == "CRITICAL"
    assert event.action == "ALERT"
    assert event.evidence["integrity_status"] == "INVALID"
