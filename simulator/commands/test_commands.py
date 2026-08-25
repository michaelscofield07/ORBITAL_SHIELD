"""
Unit tests for ORBITAL_SHIELD Command Simulation Module.
"""

from datetime import datetime
import json
import pytest
from pydantic import ValidationError

from simulator.commands.generator import CommandGenerator
from simulator.commands.models import (
    CommandData,
    CommandEvent,
    CommandStatus,
    CommandType,
)


@pytest.fixture
def generator():
    """Returns a fresh CommandGenerator instance."""
    return CommandGenerator(default_satellite_id="SAT-ORBITAL-01")


def test_standardized_event_structure(generator):
    """Test the outer envelope and inner structure of generated command events."""
    event = generator.create_command(
        command_type=CommandType.ADJUST_CAMERA,
        parameters={"zoom": 2.0, "exposure_ms": 200},
    )

    # Validate outer structure
    assert isinstance(event, CommandEvent)
    assert event.source == "GROUND_STATION_SIMULATOR"
    assert event.satellite_id == "SAT-ORBITAL-01"
    assert event.event_type == "COMMAND"
    assert isinstance(event.event_id, str) and len(event.event_id) > 0
    assert isinstance(event.timestamp, str)
    # Check valid ISO format
    datetime.fromisoformat(event.timestamp)

    # Validate inner data structure
    data = event.data
    assert isinstance(data, CommandData)
    assert data.command_id.startswith("CMD-")
    assert data.command_type == CommandType.ADJUST_CAMERA
    assert data.parameters == {"zoom": 2.0, "exposure_ms": 200}
    assert data.status == CommandStatus.PENDING


def test_all_five_command_types(generator):
    """Test explicit creation of all 5 supported command types via generator helpers."""
    cmd_camera = generator.create_adjust_camera(zoom=3.5, pan=15.0, tilt=-5.0, exposure_ms=150)
    assert cmd_camera.data.command_type == CommandType.ADJUST_CAMERA
    assert cmd_camera.data.parameters["zoom"] == 3.5
    assert cmd_camera.data.parameters["pan"] == 15.0

    cmd_orbit = generator.create_change_orbit(delta_v_ms=12.5, target_altitude_km=550.0, inclination_deg=97.4)
    assert cmd_orbit.data.command_type == CommandType.CHANGE_ORBIT
    assert cmd_orbit.data.parameters["delta_v_ms"] == 12.5
    assert cmd_orbit.data.parameters["target_altitude_km"] == 550.0

    cmd_start_sensor = generator.create_start_sensor(sensor_id="RAD-01", sample_rate_hz=50.0)
    assert cmd_start_sensor.data.command_type == CommandType.START_SENSOR
    assert cmd_start_sensor.data.parameters["sensor_id"] == "RAD-01"
    assert cmd_start_sensor.data.parameters["sample_rate_hz"] == 50.0

    cmd_stop_sensor = generator.create_stop_sensor(sensor_id="RAD-01")
    assert cmd_stop_sensor.data.command_type == CommandType.STOP_SENSOR
    assert cmd_stop_sensor.data.parameters["sensor_id"] == "RAD-01"

    cmd_reboot = generator.create_reboot(mode="COLD", delay_sec=5)
    assert cmd_reboot.data.command_type == CommandType.REBOOT
    assert cmd_reboot.data.parameters["mode"] == "COLD"
    assert cmd_reboot.data.parameters["delay_sec"] == 5


def test_unique_command_and_event_ids(generator):
    """Test that sequentially generated commands have unique event and command IDs."""
    c1 = generator.create_adjust_camera()
    c2 = generator.create_adjust_camera()

    assert c1.event_id != c2.event_id
    assert c1.data.command_id != c2.data.command_id


def test_custom_satellite_id_handling(generator):
    """Test overriding satellite_id per command and generator default."""
    c1 = generator.create_command(CommandType.REBOOT, satellite_id="SAT-EPSILON-99")
    assert c1.satellite_id == "SAT-EPSILON-99"

    gen_custom = CommandGenerator(default_satellite_id="SAT-ALPHA-02")
    c2 = gen_custom.create_command(CommandType.REBOOT)
    assert c2.satellite_id == "SAT-ALPHA-02"


def test_command_submission_and_history(generator):
    """Test submitting commands, sequential history tracking, and retrieval."""
    assert len(generator.get_history()) == 0

    cmd1 = generator.submit_command(CommandType.START_SENSOR, {"sensor_id": "SENSOR-IR-1"})
    cmd2 = generator.submit_command(CommandType.STOP_SENSOR, {"sensor_id": "SENSOR-IR-1"})
    cmd3 = generator.submit_command(CommandType.REBOOT, {"mode": "WARM"})

    history = generator.get_history()
    assert len(history) == 3
    assert history[0].data.command_id == cmd1.data.command_id
    assert history[1].data.command_id == cmd2.data.command_id
    assert history[2].data.command_id == cmd3.data.command_id

    # Test limit filter
    assert len(generator.get_history(limit=2)) == 2

    # Test command_type filter
    sensor_cmds = generator.get_history(command_type=CommandType.START_SENSOR)
    assert len(sensor_cmds) == 1
    assert sensor_cmds[0].data.command_type == CommandType.START_SENSOR


def test_get_command_by_id_and_status_update(generator):
    """Test retrieving command by ID and updating status."""
    cmd = generator.submit_command(CommandType.CHANGE_ORBIT, {"delta_v_ms": 5.0, "target_altitude_km": 500})
    cid = cmd.data.command_id

    fetched = generator.get_command_by_id(cid)
    assert fetched is not None
    assert fetched.data.command_id == cid
    assert fetched.data.status == CommandStatus.PENDING

    # Update status to TRANSMITTED then EXECUTED
    updated = generator.update_command_status(cid, CommandStatus.TRANSMITTED)
    assert updated is not None
    assert updated.data.status == CommandStatus.TRANSMITTED

    updated2 = generator.update_command_status(cid, CommandStatus.EXECUTED)
    assert updated2 is not None
    assert updated2.data.status == CommandStatus.EXECUTED

    # Verify history reflects updated status
    assert generator.get_command_by_id(cid).data.status == CommandStatus.EXECUTED

    # Non-existent ID lookup
    assert generator.get_command_by_id("CMD-NONEXISTENT") is None
    assert generator.update_command_status("CMD-NONEXISTENT", CommandStatus.FAILED) is None


def test_clear_history(generator):
    """Test clearing command history."""
    generator.submit_command(CommandType.REBOOT)
    assert len(generator.get_history()) == 1

    generator.clear_history()
    assert len(generator.get_history()) == 0


def test_invalid_command_type_rejection(generator):
    """Test that invalid command types raise appropriate ValueError."""
    with pytest.raises(ValueError, match="Invalid command_type"):
        generator.create_command("UNKNOWN_COMMAND_TYPE")

    with pytest.raises(TypeError):
        generator.create_command(12345)  # type: ignore


def test_invalid_pydantic_structure_rejection():
    """Test that extra or malformed fields are rejected by strict Pydantic models."""
    with pytest.raises(ValidationError):
        CommandData(
            command_id="CMD-01",
            command_type="INVALID_TYPE",  # type: ignore
            parameters={},
        )

    with pytest.raises(ValidationError):
        CommandEvent(
            event_id="evt-1",
            timestamp="2026-08-24T12:00:00Z",
            source="GROUND_STATION_SIMULATOR",
            satellite_id="SAT-ORBITAL-01",
            event_type="COMMAND",
            data=CommandData(
                command_id="CMD-1",
                command_type=CommandType.REBOOT,
                parameters={},
            ),
            unauthorized_extra_field="rejected",  # type: ignore
        )


def test_json_serialization_and_deserialization(generator):
    """Test JSON export and import roundtrip."""
    event = generator.create_adjust_camera(zoom=2.5, exposure_ms=250)
    json_str = event.model_dump_json()

    assert '"source":"GROUND_STATION_SIMULATOR"' in json_str
    assert '"event_type":"COMMAND"' in json_str
    assert '"command_type":"ADJUST_CAMERA"' in json_str

    deserialized = CommandEvent.model_validate_json(json_str)
    assert deserialized == event
    assert deserialized.data.parameters["zoom"] == 2.5
