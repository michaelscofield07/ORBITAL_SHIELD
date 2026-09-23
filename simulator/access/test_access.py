"""
Unit tests for ORBITAL_SHIELD Access Event Simulation Module.
"""

from datetime import datetime
import json
import pytest
from pydantic import ValidationError

from simulator.access.models import (
    AccessAction,
    AccessData,
    AccessEvent,
    AccessStatus,
)
from simulator.access.simulator import AccessSimulator


@pytest.fixture
def sim():
    """Returns a fresh AccessSimulator instance."""
    return AccessSimulator(default_satellite_id="SAT-ORBITAL-01")


def test_standardized_event_structure(sim):
    """Test outer envelope and inner data payload of access events."""
    event = sim.create_access_event(
        operator_id="OP-SARAH-01",
        device_id="DEV-CONSOLE-05",
        action=AccessAction.LOGIN,
        status=AccessStatus.SUCCESS,
        metadata={"ip_address": "192.168.1.100"},
    )

    # Validate outer structure
    assert isinstance(event, AccessEvent)
    assert event.source == "GROUND_STATION_SIMULATOR"
    assert event.satellite_id == "SAT-ORBITAL-01"
    assert event.event_type == "ACCESS"
    assert isinstance(event.event_id, str) and len(event.event_id) > 0
    assert isinstance(event.timestamp, str)
    datetime.fromisoformat(event.timestamp)

    # Validate inner data structure
    data = event.data
    assert isinstance(data, AccessData)
    assert data.access_id.startswith("ACC-")
    assert data.operator_id == "OP-SARAH-01"
    assert data.device_id == "DEV-CONSOLE-05"
    assert data.action == AccessAction.LOGIN
    assert data.status == AccessStatus.SUCCESS
    assert data.metadata["ip_address"] == "192.168.1.100"


def test_all_six_access_event_types(sim):
    """Test dedicated helpers for all 6 access actions."""
    # 1. LOGIN
    e_login = sim.login("OP-01", "DEV-01", ip_address="10.0.0.1", auth_method="MFA_U2F")
    assert e_login.data.action == AccessAction.LOGIN
    assert e_login.data.status == AccessStatus.SUCCESS
    assert e_login.data.metadata["auth_method"] == "MFA_U2F"

    # 2. FAILED_LOGIN
    e_fail = sim.failed_login("OP-02", "DEV-02", reason="BAD_PASSWORD", attempt_count=3)
    assert e_fail.data.action == AccessAction.FAILED_LOGIN
    assert e_fail.data.status == AccessStatus.FAILURE
    assert e_fail.data.metadata["attempt_count"] == 3

    # 3. LOGOUT
    e_logout = sim.logout("OP-01", "DEV-01", session_duration_sec=3600)
    assert e_logout.data.action == AccessAction.LOGOUT
    assert e_logout.data.status == AccessStatus.SUCCESS
    assert e_logout.data.metadata["session_duration_sec"] == 3600

    # 4. NEW_DEVICE
    e_newdev = sim.new_device("OP-03", "DEV-TABLET-01", device_type="TABLET", os_platform="ANDROID")
    assert e_newdev.data.action == AccessAction.NEW_DEVICE
    assert e_newdev.data.metadata["device_type"] == "TABLET"

    # 5. PRIVILEGE_CHANGE
    e_priv = sim.privilege_change("OP-01", "DEV-01", previous_role="OPERATOR", new_role="FLIGHT_DIRECTOR", authorized_by="ADMIN-01")
    assert e_priv.data.action == AccessAction.PRIVILEGE_CHANGE
    assert e_priv.data.metadata["new_role"] == "FLIGHT_DIRECTOR"

    # 6. COMMAND_ACCESS
    e_cmd = sim.command_access("OP-01", "DEV-01", command_type="ADJUST_CAMERA", command_id="CMD-999")
    assert e_cmd.data.action == AccessAction.COMMAND_ACCESS
    assert e_cmd.data.metadata["command_type"] == "ADJUST_CAMERA"


def test_unique_event_and_access_ids(sim):
    """Test that sequentially emitted events have unique event and access IDs."""
    e1 = sim.login("OP-01", "DEV-01")
    e2 = sim.login("OP-01", "DEV-01")

    assert e1.event_id != e2.event_id
    assert e1.data.access_id != e2.data.access_id


def test_custom_satellite_id_handling(sim):
    """Test overriding satellite_id in access events."""
    evt = sim.login("OP-01", "DEV-01", satellite_id="SAT-EPSILON-02")
    assert evt.satellite_id == "SAT-EPSILON-02"


def test_access_history_and_filters(sim):
    """Test access history logging and filtering."""
    assert len(sim.get_history()) == 0

    sim.login("OP-ALICE", "DEV-01")
    sim.failed_login("OP-BOB", "DEV-02")
    sim.login("OP-ALICE", "DEV-01")
    sim.logout("OP-ALICE", "DEV-01")

    history = sim.get_history()
    assert len(history) == 4

    # Filter by operator
    alice_events = sim.get_events_by_operator("OP-ALICE")
    assert len(alice_events) == 3

    # Filter by action
    fails = sim.get_history(action=AccessAction.FAILED_LOGIN)
    assert len(fails) == 1
    assert fails[0].data.operator_id == "OP-BOB"

    # Filter by status
    failed_status = sim.get_history(status=AccessStatus.FAILURE)
    assert len(failed_status) == 1

    # Filter by limit
    assert len(sim.get_history(limit=2)) == 2

    # Clear history
    sim.clear_history()
    assert len(sim.get_history()) == 0


def test_get_event_by_id(sim):
    """Test event lookup by event_id or access_id."""
    evt = sim.login("OP-01", "DEV-01")
    eid = evt.event_id
    aid = evt.data.access_id

    assert sim.get_event_by_id(eid) == evt
    assert sim.get_event_by_id(aid) == evt
    assert sim.get_event_by_id("NONEXISTENT_ID") is None


def test_invalid_action_rejection(sim):
    """Test that invalid action types raise ValueError."""
    with pytest.raises(ValueError, match="Invalid action"):
        sim.create_access_event("OP-01", "DEV-01", action="INVALID_ACTION")

    with pytest.raises(TypeError):
        sim.create_access_event("OP-01", "DEV-01", action=123)  # type: ignore


def test_invalid_pydantic_structure_rejection():
    """Test that malformed models or extra fields are strictly rejected."""
    with pytest.raises(ValidationError):
        AccessData(
            access_id="ACC-01",
            operator_id="OP-01",
            device_id="DEV-01",
            action="UNRECOGNIZED_ACTION",  # type: ignore
        )

    with pytest.raises(ValidationError):
        AccessEvent(
            event_id="evt-01",
            timestamp="2026-08-24T12:00:00Z",
            source="GROUND_STATION_SIMULATOR",
            satellite_id="SAT-ORBITAL-01",
            event_type="ACCESS",
            data=AccessData(
                access_id="ACC-01",
                operator_id="OP-01",
                device_id="DEV-01",
                action=AccessAction.LOGIN,
            ),
            unexpected_field="forbidden",  # type: ignore
        )


def test_json_serialization_and_deserialization(sim):
    """Test JSON export and import roundtrip."""
    event = sim.privilege_change("OP-ADMIN", "DEV-MAIN", previous_role="OPERATOR", new_role="ADMIN")
    json_str = event.model_dump_json()

    assert '"source":"GROUND_STATION_SIMULATOR"' in json_str
    assert '"event_type":"ACCESS"' in json_str
    assert '"action":"PRIVILEGE_CHANGE"' in json_str

    deserialized = AccessEvent.model_validate_json(json_str)
    assert deserialized == event
    assert deserialized.data.metadata["new_role"] == "ADMIN"
