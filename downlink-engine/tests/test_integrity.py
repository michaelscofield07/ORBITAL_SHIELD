"""Unit tests for Deterministic Telemetry Integrity Verification."""

import pytest
from datetime import datetime, timezone, timedelta

from app.schemas.telemetry import TelemetryInput
from app.models.telemetry import TelemetryRecord
from app.services.integrity_checker import IntegrityChecker
from app.utils.hashing import compute_telemetry_hash


@pytest.fixture
def checker():
    return IntegrityChecker(timestamp_tolerance_seconds=30.0, max_age_seconds=86400.0)


def create_packet(
    seq: int = 100,
    timestamp: str = None,
    temp: float = 24.0,
    battery: float = 88.0,
    signal: float = -70.0,
    packet_hash: str = None
) -> TelemetryInput:
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return TelemetryInput(
        timestamp=ts,
        satellite_id="SAT-EO-01",
        sequence_number=seq,
        temperature=temp,
        battery=battery,
        signal_strength=signal,
        packet_hash=packet_hash
    )


def test_first_packet_integrity(checker):
    """First packet received should pass integrity without historical record."""
    packet = create_packet(seq=100)
    result = checker.verify(packet, previous_record=None)

    assert result.sequence_valid is True
    assert result.timestamp_valid is True
    assert result.hash_valid is True
    assert result.integrity_status == "VALID"
    assert len(result.integrity_issues) == 0


def test_valid_sequential_packet(checker):
    """Packet with sequence = previous + 1 should be valid."""
    now = datetime.now(timezone.utc)
    prev = TelemetryRecord(
        sequence_number=100,
        timestamp=(now - timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        satellite_id="SAT-EO-01",
        temperature=24.0,
        battery=88.0,
        signal_strength=-70.0
    )
    packet = create_packet(seq=101, timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    result = checker.verify(packet, previous_record=prev)

    assert result.sequence_valid is True
    assert result.integrity_status == "VALID"


def test_duplicate_sequence_replay_detection(checker):
    """Duplicate sequence number indicates possible telemetry replay attack."""
    now = datetime.now(timezone.utc)
    prev = TelemetryRecord(
        sequence_number=100,
        timestamp=(now - timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        satellite_id="SAT-EO-01",
        temperature=24.0,
        battery=88.0,
        signal_strength=-70.0
    )
    packet = create_packet(seq=100, timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    result = checker.verify(packet, previous_record=prev)

    assert result.sequence_valid is False
    assert result.integrity_status == "INVALID"
    assert any("Duplicate sequence" in issue for issue in result.integrity_issues)


def test_sequence_jump_detection(checker):
    """Unexpected sequence jump (e.g. 100 -> 150) should be flagged."""
    now = datetime.now(timezone.utc)
    prev = TelemetryRecord(
        sequence_number=100,
        timestamp=(now - timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        satellite_id="SAT-EO-01",
        temperature=24.0,
        battery=88.0,
        signal_strength=-70.0
    )
    packet = create_packet(seq=150, timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    result = checker.verify(packet, previous_record=prev)

    assert result.sequence_valid is False
    assert result.integrity_status == "INVALID"
    assert any("Unexpected sequence jump" in issue for issue in result.integrity_issues)


def test_out_of_order_sequence_detection(checker):
    """Arriving with a lower sequence number than previous should be flagged."""
    now = datetime.now(timezone.utc)
    prev = TelemetryRecord(
        sequence_number=100,
        timestamp=(now - timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        satellite_id="SAT-EO-01",
        temperature=24.0,
        battery=88.0,
        signal_strength=-70.0
    )
    packet = create_packet(seq=95, timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    result = checker.verify(packet, previous_record=prev)

    assert result.sequence_valid is False
    assert result.integrity_status == "INVALID"
    assert any("Out-of-order" in issue for issue in result.integrity_issues)


def test_valid_sha256_hash(checker):
    """Matching SHA-256 hash passes verification."""
    packet = create_packet(seq=100)
    packet.packet_hash = compute_telemetry_hash(packet)

    result = checker.verify(packet, previous_record=None)
    assert result.hash_valid is True
    assert result.integrity_status == "VALID"


def test_invalid_sha256_hash_tampering(checker):
    """Mismatched SHA-256 hash triggers integrity failure."""
    packet = create_packet(seq=100, temp=24.0)
    packet.packet_hash = compute_telemetry_hash(packet)

    # Attacker alters temperature without recalculating hash
    packet.temperature = 78.0

    result = checker.verify(packet, previous_record=None)
    assert result.hash_valid is False
    assert result.integrity_status == "INVALID"
    assert any("Packet hash mismatch" in issue for issue in result.integrity_issues)


def test_future_timestamp_detection(checker):
    """Timestamps in the far future beyond tolerance should be flagged."""
    future_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    packet = create_packet(seq=100, timestamp=future_time.strftime("%Y-%m-%dT%H:%M:%SZ"))

    result = checker.verify(packet, previous_record=None)
    assert result.timestamp_valid is False
    assert any("Future timestamp" in issue for issue in result.integrity_issues)


def test_retrograde_timestamp_detection(checker):
    """Timestamp earlier than previous packet indicates clock anomaly."""
    now = datetime.now(timezone.utc)
    prev = TelemetryRecord(
        sequence_number=100,
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        satellite_id="SAT-EO-01",
        temperature=24.0,
        battery=88.0,
        signal_strength=-70.0
    )
    # 30 seconds earlier than prev
    past_ts = (now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    packet = create_packet(seq=101, timestamp=past_ts)

    result = checker.verify(packet, previous_record=prev)
    assert any("Retrograde timestamp" in issue for issue in result.integrity_issues)
