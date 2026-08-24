"""
Unit tests for ORBITAL_SHIELD Firmware Simulation Module.
"""

from datetime import datetime
import hashlib
import json
import pytest
from pydantic import ValidationError

from simulator.firmware.models import (
    FirmwareData,
    FirmwareEvent,
    FirmwareStatus,
)
from simulator.firmware.simulator import FirmwareSimulator


@pytest.fixture
def sim():
    """Returns a fresh FirmwareSimulator with default artifacts."""
    return FirmwareSimulator(default_satellite_id="SAT-ORBITAL-01")


def test_default_artifacts_registered(sim):
    """Test that default firmware artifacts (firmware_v1, firmware_v2) are pre-registered."""
    v1 = sim.get_artifact("firmware_v1")
    v2 = sim.get_artifact("firmware_v2")

    assert v1 is not None
    assert v1.version == "firmware_v1"
    assert v1.firmware_id == "FW-ORBITAL-V1"
    assert v1.size_bytes == 524288
    assert len(v1.hash) == 64  # SHA-256 hex string

    assert v2 is not None
    assert v2.version == "firmware_v2"
    assert v2.firmware_id == "FW-ORBITAL-V2"
    assert v2.size_bytes == 786432


def test_custom_artifact_registration_with_hash(sim):
    """Test registering a custom firmware artifact with automatic SHA-256 computation."""
    raw_payload = b"\x7fELF\x02\x01\x01\x00_CUSTOM_FIRMWARE_PAYLOAD_TEST"
    expected_hash = hashlib.sha256(raw_payload).hexdigest()

    custom_fw = sim.register_artifact(
        version="v3.0.0-rc1",
        artifact="orbital_payload_v3.bin",
        size_bytes=len(raw_payload),
        raw_payload=raw_payload,
    )

    assert custom_fw.version == "v3.0.0-rc1"
    assert custom_fw.hash == expected_hash
    assert custom_fw.size_bytes == len(raw_payload)
    assert custom_fw.firmware_id.startswith("FW-")


def test_firmware_event_structure(sim):
    """Test standardized outer envelope and inner data payload for firmware events."""
    event = sim.create_firmware_event(
        firmware_id_or_version="firmware_v1",
        status=FirmwareStatus.UPDATE_REQUESTED,
    )

    # Validate outer structure
    assert isinstance(event, FirmwareEvent)
    assert event.source == "GROUND_STATION_SIMULATOR"
    assert event.satellite_id == "SAT-ORBITAL-01"
    assert event.event_type == "FIRMWARE"
    assert isinstance(event.event_id, str) and len(event.event_id) > 0
    assert isinstance(event.timestamp, str)
    datetime.fromisoformat(event.timestamp)

    # Validate data payload
    data = event.data
    assert isinstance(data, FirmwareData)
    assert data.firmware_id == "FW-ORBITAL-V1"
    assert data.version == "firmware_v1"
    assert data.artifact == "orbital_obc_firmware_v1.0.bin"
    assert data.status == FirmwareStatus.UPDATE_REQUESTED
    assert len(data.hash) == 64


def test_unique_event_ids(sim):
    """Test that sequentially generated firmware events have unique event IDs."""
    e1 = sim.create_firmware_event("firmware_v1")
    e2 = sim.create_firmware_event("firmware_v1")

    assert e1.event_id != e2.event_id


def test_custom_satellite_id_handling(sim):
    """Test custom satellite_id override in firmware events."""
    evt = sim.create_firmware_event("firmware_v1", satellite_id="SAT-EPSILON-09")
    assert evt.satellite_id == "SAT-EPSILON-09"


def test_firmware_update_lifecycle_and_history(sim):
    """Test full update lifecycle tracking in history: REQUESTED -> IN_PROGRESS -> COMPLETED."""
    assert len(sim.get_history()) == 0

    # 1. Request
    req_evt = sim.request_firmware_update("firmware_v2")
    assert req_evt.data.status == FirmwareStatus.UPDATE_REQUESTED
    assert req_evt.source == "GROUND_STATION_SIMULATOR"

    # 2. In Progress
    prog_evt = sim.start_firmware_update("firmware_v2")
    assert prog_evt.data.status == FirmwareStatus.UPDATE_IN_PROGRESS
    assert prog_evt.source == "SATELLITE_SIMULATOR"

    # 3. Completed
    comp_evt = sim.complete_firmware_update("firmware_v2")
    assert comp_evt.data.status == FirmwareStatus.UPDATE_COMPLETED
    assert comp_evt.source == "SATELLITE_SIMULATOR"

    history = sim.get_history()
    assert len(history) == 3
    assert history[0].data.status == FirmwareStatus.UPDATE_REQUESTED
    assert history[1].data.status == FirmwareStatus.UPDATE_IN_PROGRESS
    assert history[2].data.status == FirmwareStatus.UPDATE_COMPLETED


def test_firmware_update_failure_event(sim):
    """Test generating a firmware update failure event."""
    fail_evt = sim.fail_firmware_update("firmware_v1")
    assert fail_evt.data.status == FirmwareStatus.UPDATE_FAILED

    history = sim.get_history(status=FirmwareStatus.UPDATE_FAILED)
    assert len(history) == 1
    assert history[0].data.status == FirmwareStatus.UPDATE_FAILED


def test_history_filtering_and_clearing(sim):
    """Test history limit, status filter, and clear."""
    sim.request_firmware_update("firmware_v1")
    sim.request_firmware_update("firmware_v2")
    sim.fail_firmware_update("firmware_v1")

    assert len(sim.get_history(limit=2)) == 2
    assert len(sim.get_history(version="firmware_v1")) == 2

    sim.clear_history()
    assert len(sim.get_history()) == 0


def test_unregistered_artifact_raises_keyerror(sim):
    """Test that requesting an unregistered firmware version raises KeyError."""
    with pytest.raises(KeyError, match="not registered"):
        sim.create_firmware_event("firmware_unknown_v99")


def test_invalid_pydantic_structure_rejection():
    """Test that invalid values and extra fields are rejected."""
    with pytest.raises(ValidationError):
        FirmwareData(
            firmware_id="FW-1",
            version="v1",
            artifact="art.bin",
            size_bytes=-100,  # Negative size forbidden
            hash="abc",
            status=FirmwareStatus.REGISTERED,
        )

    with pytest.raises(ValidationError):
        FirmwareEvent(
            event_id="evt-1",
            timestamp="2026-08-24T12:00:00Z",
            source="GROUND_STATION_SIMULATOR",
            satellite_id="SAT-ORBITAL-01",
            event_type="FIRMWARE",
            data=FirmwareData(
                firmware_id="FW-1",
                version="v1",
                artifact="art.bin",
                size_bytes=100,
                hash="a" * 64,
                status=FirmwareStatus.REGISTERED,
            ),
            unexpected_field="disallowed",  # type: ignore
        )


def test_json_serialization_and_deserialization(sim):
    """Test JSON export and import roundtrip."""
    event = sim.create_firmware_event("firmware_v2", status=FirmwareStatus.UPDATE_REQUESTED)
    json_str = event.model_dump_json()

    assert '"source":"GROUND_STATION_SIMULATOR"' in json_str
    assert '"event_type":"FIRMWARE"' in json_str
    assert '"version":"firmware_v2"' in json_str

    deserialized = FirmwareEvent.model_validate_json(json_str)
    assert deserialized == event
    assert deserialized.data.size_bytes == 786432
