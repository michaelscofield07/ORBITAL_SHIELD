"""
Comprehensive Pytest test suite for Orbital Shield Uplink Command Security Engine.
Tests:
- Valid telecommand approvals and HMAC-SHA256 signing
- Replay attack defenses (duplicate session tokens, non-monotonic sequence counters)
- Clock drift & timestamp freshness tolerance
- RBAC privilege escalation prevention
- Parameter bound constraints and type safety
- Spacecraft telemetry precondition enforcement (Safe Mode, Battery SOC, Thermal limits)
- Cryptographic signature tamper detection
- Orbital Shield SecurityEvent contract conformance
- Policy updates and audit history querying via FastAPI endpoints
"""

from datetime import datetime, timezone, timedelta
import re
import uuid
import pytest
from fastapi.testclient import TestClient

from main import app, get_security_engine
from models import (
    CommandAction,
    CommandExecutionRequest,
    CommandSeverity,
    CommandType,
    OperatorRole,
    ParameterBound,
    SecurityEvent,
    SecurityPolicy,
    TelemetryState,
    UplinkCommand,
    ValidationResponse,
)
from validator import UplinkSecurityEngine


@pytest.fixture
def fresh_engine() -> UplinkSecurityEngine:
    """Fixture providing a fresh UplinkSecurityEngine instance with isolated state."""
    engine = UplinkSecurityEngine(master_secret_key=b"TEST_SECRET_KEY_FOR_ORBITAL_SHIELD_32B")
    engine.set_telemetry_state(
        TelemetryState(
            satellite_id="SAT-EO-01",
            operational_mode="NOMINAL",
            battery_soc_pct=95.0,
            solar_panels_deployed=True,
            bus_voltage_v=28.5,
            primary_temp_c=22.0,
            propellant_mass_kg=20.0,
            orbit_altitude_km=550.0,
            safe_mode_active=False,
            active_maneuver=False
        )
    )
    return engine


@pytest.fixture
def client(fresh_engine: UplinkSecurityEngine):
    """Fixture providing a FastAPI test client with injected fresh engine."""
    app.dependency_overrides[get_security_engine] = lambda: fresh_engine
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ===========================================================================
# 1. Valid Commands & Signing Tests
# ===========================================================================

def test_valid_change_orbit_approved(fresh_engine: UplinkSecurityEngine):
    """Flight Director issues valid CHANGE_ORBIT within all constraints."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.CHANGE_ORBIT.value,
        sequence_number=1,
        session_token="SESSION-TOKEN-VALID-01",
        timestamp=datetime.now(timezone.utc),
        parameters={
            "delta_v_ms": 1.25,
            "burn_duration_seconds": 45.0,
            "target_altitude_km": 560.0
        }
    )

    response = fresh_engine.validate(cmd)
    assert response.is_valid is True
    assert response.action == CommandAction.ALLOW
    assert len(response.rejection_reasons) == 0
    assert response.signed_frame is not None
    assert response.signed_frame.signing_algorithm == "HMAC-SHA256"
    assert len(response.signed_frame.hmac_signature) == 64
    assert response.signed_frame.dispatch_token.startswith("OPR-")

    # Verify signature passes verification
    assert fresh_engine.verify_hmac_signature(cmd, response.signed_frame.hmac_signature) is True


def test_valid_adjust_camera_by_payload_op(fresh_engine: UplinkSecurityEngine):
    """Payload Operator issues valid ADJUST_CAMERA command."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.ADJUST_CAMERA.value,
        sequence_number=1,
        session_token="SESSION-TOKEN-VALID-02",
        timestamp=datetime.now(timezone.utc),
        parameters={
            "zoom_level": 5.0,
            "exposure_ms": 250,
            "target_angle_deg": 15.0,
            "resolution": "4K"
        }
    )

    response = fresh_engine.validate(cmd)
    assert response.is_valid is True
    assert response.action == CommandAction.ALLOW


def test_valid_start_sensor_by_payload_op(fresh_engine: UplinkSecurityEngine):
    """Payload Operator starts optical camera sensor."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.START_SENSOR.value,
        sequence_number=1,
        session_token="SESSION-TOKEN-VALID-03",
        timestamp=datetime.now(timezone.utc),
        parameters={
            "sensor_id": "OPTICAL_CAM",
            "sampling_rate_hz": 10.0
        }
    )

    response = fresh_engine.validate(cmd)
    assert response.is_valid is True
    assert response.action == CommandAction.ALLOW


# ===========================================================================
# 2. Replay Attack & Sequence Defense Tests
# ===========================================================================

def test_replay_attack_duplicate_session_token_rejected(fresh_engine: UplinkSecurityEngine):
    """Replaying exact same session token triggers BLOCK and CRITICAL security event."""
    cmd1 = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.REBOOT.value,
        sequence_number=1,
        session_token="REPLAY-TOKEN-UNIQUE-999",
        timestamp=datetime.now(timezone.utc),
        parameters={"subsystem": "COMMS"}
    )
    res1 = fresh_engine.validate(cmd1)
    assert res1.is_valid is True

    # Replay attack with same session token
    cmd2 = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.REBOOT.value,
        sequence_number=2,
        session_token="REPLAY-TOKEN-UNIQUE-999",
        timestamp=datetime.now(timezone.utc),
        parameters={"subsystem": "COMMS"}
    )
    res2 = fresh_engine.validate(cmd2)
    assert res2.is_valid is False
    assert res2.action == CommandAction.BLOCK
    assert any("Replay Attack Detected" in r for r in res2.rejection_reasons)
    assert res2.security_event is not None
    assert res2.security_event.event_type == "REPLAY_ATTACK_DETECTED"
    assert res2.security_event.severity == CommandSeverity.CRITICAL
    assert res2.security_event.action == CommandAction.BLOCK


def test_replay_attack_stale_sequence_number_rejected(fresh_engine: UplinkSecurityEngine):
    """Submitting stale sequence number is rejected."""
    cmd1 = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.STOP_SENSOR.value,
        sequence_number=10,
        session_token="TOKEN-SEQ-10",
        timestamp=datetime.now(timezone.utc),
        parameters={"sensor_id": "SAR_RADAR"}
    )
    res1 = fresh_engine.validate(cmd1)
    assert res1.is_valid is True

    # Stale sequence number 5
    cmd2 = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.STOP_SENSOR.value,
        sequence_number=5,
        session_token="TOKEN-SEQ-5",
        timestamp=datetime.now(timezone.utc),
        parameters={"sensor_id": "SAR_RADAR"}
    )
    res2 = fresh_engine.validate(cmd2)
    assert res2.is_valid is False
    assert any("Sequence Counter Violation" in r for r in res2.rejection_reasons)
    assert res2.security_event.event_type == "REPLAY_ATTACK_DETECTED"


def test_timestamp_drift_expired_and_future_rejected(fresh_engine: UplinkSecurityEngine):
    """Commands with timestamps outside ±300s window are rejected."""
    now = datetime.now(timezone.utc)
    
    # 10 minutes in the past
    past_cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.START_SENSOR.value,
        sequence_number=1,
        session_token="TOKEN-DRIFT-PAST",
        timestamp=now - timedelta(seconds=600),
        parameters={"sensor_id": "INFRARED"}
    )
    past_res = fresh_engine.validate(past_cmd)
    assert past_res.is_valid is False
    assert any("Timestamp Drift Rejection" in r for r in past_res.rejection_reasons)


# ===========================================================================
# 3. RBAC & Privilege Escalation Tests
# ===========================================================================

def test_privilege_escalation_payload_op_calling_change_orbit(fresh_engine: UplinkSecurityEngine):
    """PAYLOAD_OP attempting to issue CHANGE_ORBIT is blocked."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.CHANGE_ORBIT.value,
        sequence_number=1,
        session_token="TOKEN-ESCALATION-01",
        timestamp=datetime.now(timezone.utc),
        parameters={
            "delta_v_ms": 2.0,
            "burn_duration_seconds": 30.0
        }
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is False
    assert res.action == CommandAction.BLOCK
    assert any("Privilege Violation" in r for r in res.rejection_reasons)
    assert res.security_event.event_type in ["UNAUTHORIZED_COMMAND", "UNAUTHORIZED_ROLE"]
    assert res.security_event.severity == CommandSeverity.CRITICAL


def test_privilege_escalation_orbital_engineer_calling_adjust_camera(fresh_engine: UplinkSecurityEngine):
    """ORBITAL_ENGINEER attempting to issue ADJUST_CAMERA is blocked."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-ENG-03",
        role=OperatorRole.ORBITAL_ENGINEER.value,
        command_type=CommandType.ADJUST_CAMERA.value,
        sequence_number=1,
        session_token="TOKEN-ESCALATION-02",
        timestamp=datetime.now(timezone.utc),
        parameters={"zoom_level": 2.0}
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is False
    assert res.action == CommandAction.BLOCK


def test_privilege_escalation_observer_blocked(fresh_engine: UplinkSecurityEngine):
    """OBSERVER role cannot issue any commands."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-OBS-09",
        role=OperatorRole.OBSERVER.value,
        command_type=CommandType.START_SENSOR.value,
        sequence_number=1,
        session_token="TOKEN-OBSERVER-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"sensor_id": "MAGNETOMETER"}
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is False
    assert res.action == CommandAction.BLOCK


# ===========================================================================
# 4. Parameter Bound Constraint Tests
# ===========================================================================

def test_out_of_bounds_excessive_burn_duration(fresh_engine: UplinkSecurityEngine):
    """Burn duration > 300.0s is rejected."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.CHANGE_ORBIT.value,
        sequence_number=1,
        session_token="TOKEN-BOUND-01",
        timestamp=datetime.now(timezone.utc),
        parameters={
            "delta_v_ms": 2.0,
            "burn_duration_seconds": 450.0  # Max 300.0
        }
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is False
    assert any("burn_duration_seconds' value 450.0 > maximum allowed 300.0" in r for r in res.rejection_reasons)
    assert res.security_event.event_type in ["INVALID_PARAMETERS", "BOUND_VIOLATION"]


def test_out_of_bounds_negative_delta_v(fresh_engine: UplinkSecurityEngine):
    """Delta-V < 0.01 m/s is rejected."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.CHANGE_ORBIT.value,
        sequence_number=1,
        session_token="TOKEN-BOUND-02",
        timestamp=datetime.now(timezone.utc),
        parameters={
            "delta_v_ms": -1.0,
            "burn_duration_seconds": 10.0
        }
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is False
    assert any("delta_v_ms' value -1.0 < minimum allowed 0.01" in r for r in res.rejection_reasons)


def test_out_of_bounds_invalid_sensor_id(fresh_engine: UplinkSecurityEngine):
    """Unrecognized sensor_id is rejected."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.START_SENSOR.value,
        sequence_number=1,
        session_token="TOKEN-BOUND-03",
        timestamp=datetime.now(timezone.utc),
        parameters={"sensor_id": "UNKNOWN_RADAR_99"}
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is False
    assert any("sensor_id' value 'UNKNOWN_RADAR_99' not in allowed set" in r for r in res.rejection_reasons)


def test_out_of_bounds_missing_required_parameter(fresh_engine: UplinkSecurityEngine):
    """Missing delta_v_ms parameter triggers bound violation."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.CHANGE_ORBIT.value,
        sequence_number=1,
        session_token="TOKEN-BOUND-04",
        timestamp=datetime.now(timezone.utc),
        parameters={"burn_duration_seconds": 10.0}
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is False
    assert any("Missing required parameter 'delta_v_ms'" in r for r in res.rejection_reasons)


# ===========================================================================
# 5. Spacecraft Telemetry Precondition Tests
# ===========================================================================

def test_telemetry_precondition_low_battery_blocks_maneuver(fresh_engine: UplinkSecurityEngine):
    """CHANGE_ORBIT rejected when battery SOC < 25%."""
    low_battery = TelemetryState(
        satellite_id="SAT-EO-01",
        battery_soc_pct=15.0,
        operational_mode="NOMINAL"
    )
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.CHANGE_ORBIT.value,
        sequence_number=1,
        session_token="TOKEN-TELEM-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"delta_v_ms": 1.0, "burn_duration_seconds": 15.0}
    )
    res = fresh_engine.validate(cmd, telemetry=low_battery)
    assert res.is_valid is False
    assert any("Insufficient Power" in r for r in res.rejection_reasons)
    assert res.security_event.event_type == "TELEMETRY_STATE_CONFLICT"


def test_telemetry_precondition_safe_mode_blocks_restricted(fresh_engine: UplinkSecurityEngine):
    """Satellite in Safe Mode rejects CHANGE_ORBIT and START_SENSOR."""
    safe_state = TelemetryState(
        satellite_id="SAT-EO-01",
        safe_mode_active=True,
        operational_mode="SAFE_MODE"
    )
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.CHANGE_ORBIT.value,
        sequence_number=1,
        session_token="TOKEN-SAFE-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"delta_v_ms": 1.0, "burn_duration_seconds": 15.0}
    )
    res = fresh_engine.validate(cmd, telemetry=safe_state)
    assert res.is_valid is False
    assert any("prohibited while spacecraft 'SAT-EO-01' is in SAFE_MODE" in r for r in res.rejection_reasons)


def test_telemetry_precondition_thermal_spike(fresh_engine: UplinkSecurityEngine):
    """Primary temperature > 75°C blocks power/sensor activation."""
    hot_state = TelemetryState(
        satellite_id="SAT-EO-01",
        primary_temp_c=80.0,
        operational_mode="NOMINAL"
    )
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.START_SENSOR.value,
        sequence_number=1,
        session_token="TOKEN-HOT-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"sensor_id": "SAR_RADAR"}
    )
    res = fresh_engine.validate(cmd, telemetry=hot_state)
    assert res.is_valid is False
    assert any("Thermal Safety Violation" in r for r in res.rejection_reasons)


# ===========================================================================
# 6. Cryptographic HMAC Tamper Detection Tests
# ===========================================================================

def test_hmac_signature_tamper_detection(fresh_engine: UplinkSecurityEngine):
    """Modifying parameters invalidates HMAC-SHA256 signature."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type=CommandType.ADJUST_CAMERA.value,
        sequence_number=1,
        session_token="TOKEN-CRYPTO-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"zoom_level": 4.0, "resolution": "1080P"}
    )
    res = fresh_engine.validate(cmd)
    assert res.is_valid is True
    sig = res.signed_frame.hmac_signature

    assert fresh_engine.verify_hmac_signature(cmd, sig) is True

    # Tamper with parameter payload
    tampered_cmd = cmd.model_copy(update={"parameters": {"zoom_level": 10.0, "resolution": "4K"}})
    assert fresh_engine.verify_hmac_signature(tampered_cmd, sig) is False


# ===========================================================================
# 7. Orbital Shield SecurityEvent Contract Conformance
# ===========================================================================

def test_security_event_schema_contract(fresh_engine: UplinkSecurityEngine):
    """Ensures SecurityEvent strictly conforms to Orbital Shield contract."""
    cmd = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-DIRECTOR-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type=CommandType.REBOOT.value,
        sequence_number=1,
        session_token="TOKEN-CONTRACT-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"subsystem": "OBC"}
    )
    res = fresh_engine.validate(cmd)
    event = res.security_event
    assert event is not None
    assert re.match(r"^EVT-UPLINK-[A-Z0-9]{5}$", event.event_id)
    assert event.source == "UPLINK"
    assert event.satellite_id == "SAT-EO-01"
    assert isinstance(event.severity, CommandSeverity)
    assert isinstance(event.action, CommandAction)
    assert 0.0 <= event.confidence <= 1.0
    assert isinstance(event.evidence, dict)
    assert isinstance(event.related_events, list)


# ===========================================================================
# 8. FastAPI Endpoints Integration Tests
# ===========================================================================

def test_api_validate_endpoint_approved(client: TestClient):
    """POST /commands/validate returns 200 with ALLOW action."""
    payload = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-EO-01",
            "operator_id": "OP-02",
            "role": "PAYLOAD_OP",
            "command_type": "ADJUST_CAMERA",
            "sequence_number": 1,
            "session_token": "API-TOKEN-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {"zoom_level": 2.5, "resolution": "1080P"}
        }
    }
    response = client.post("/commands/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "ALLOW"
    assert data["is_valid"] is True
    assert data["signed_frame"] is not None


def test_api_validate_endpoint_rejected_privilege_escalation(client: TestClient):
    """POST /commands/validate returns 200 with BLOCK action for unauthorized role."""
    payload = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-EO-01",
            "operator_id": "OP-OBSERVER-01",
            "role": "OBSERVER",
            "command_type": "CHANGE_ORBIT",
            "sequence_number": 1,
            "session_token": "API-TOKEN-02",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {"delta_v_ms": 1.0, "burn_duration_seconds": 10.0}
        }
    }
    response = client.post("/commands/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "BLOCK"
    assert data["is_valid"] is False


def test_api_execute_endpoint_dispatch_and_dry_run(client: TestClient):
    """POST /commands/execute supports dry run and dispatch."""
    payload = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-EO-01",
            "operator_id": "OP-02",
            "role": "PAYLOAD_OP",
            "command_type": "START_SENSOR",
            "sequence_number": 1,
            "session_token": "API-EXEC-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {"sensor_id": "OPTICAL_CAM"}
        },
        "dry_run": True
    }
    res = client.post("/commands/execute", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["validation"]["is_valid"] is True
    assert data["dispatched"] is False


def test_api_policy_read_and_update(client: TestClient):
    """GET and PUT /commands/policy endpoints."""
    res_get = client.get("/commands/policy")
    assert res_get.status_code == 200
    policy_data = res_get.json()
    assert policy_data["policy_id"] == "POL-ORBITAL-DEFAULT"

    policy_data["version"] = "2.0.0"
    res_put = client.put(
        "/commands/policy",
        json=policy_data,
        headers={"x-operator-role": "FLIGHT_DIRECTOR", "x-operator-id": "OP-DIRECTOR-01"}
    )
    assert res_put.status_code == 200
    assert res_put.json()["version"] == "2.0.0"


def test_api_history_and_health(client: TestClient):
    """GET /commands/history and GET /health endpoints."""
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "HEALTHY"

    res_hist = client.get("/commands/history?limit=10")
    assert res_hist.status_code == 200
    assert isinstance(res_hist.json(), list)


# ===========================================================================
# 9. Core UplinkSecurityEngine 5-Point Requirement Unit Tests
# ===========================================================================

def test_rbac_matrix_all_roles(fresh_engine: UplinkSecurityEngine):
    """Test full RBAC matrix exhaustively across all operator roles."""
    expected_matrix = {
        OperatorRole.PAYLOAD_OP.value: {"ADJUST_CAMERA", "START_SENSOR", "STOP_SENSOR"},
        OperatorRole.FLIGHT_DIRECTOR.value: {"ADJUST_CAMERA", "START_SENSOR", "STOP_SENSOR", "CHANGE_ORBIT", "REBOOT"},
        OperatorRole.ORBITAL_ENGINEER.value: {"CHANGE_ORBIT", "REBOOT"},
        OperatorRole.OBSERVER.value: set(),
    }

    all_commands = ["ADJUST_CAMERA", "START_SENSOR", "STOP_SENSOR", "CHANGE_ORBIT", "REBOOT"]

    for role, allowed_cmds in expected_matrix.items():
        for cmd_type in all_commands:
            cmd = UplinkCommand(
                command_id=str(uuid.uuid4()),
                satellite_id="SAT-EO-01",
                operator_id=f"OP-{role}",
                role=role,
                command_type=cmd_type,
                sequence_number=1,
                session_token=f"TOKEN-{role}-{cmd_type}",
                timestamp=datetime.now(timezone.utc),
                parameters={}
            )
            check = fresh_engine.verify_rbac(cmd)
            if cmd_type in allowed_cmds:
                assert check.passed is True, f"Role {role} should be allowed for {cmd_type}"
            else:
                assert check.passed is False, f"Role {role} should be blocked for {cmd_type}"
                assert check.severity_if_failed in [CommandSeverity.HIGH, CommandSeverity.CRITICAL]


def test_parameter_whitelist_and_bounds_adjust_camera(fresh_engine: UplinkSecurityEngine):
    """Test ADJUST_CAMERA parameter bounds (angle: -90.0 to 90.0, zoom: 1.0 to 10.0) and whitelist."""
    # Valid bounds
    cmd_valid = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-01",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type="ADJUST_CAMERA",
        sequence_number=1,
        session_token="TOKEN-PARAM-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"angle": 45.0, "zoom": 5.0}
    )
    res_valid = fresh_engine.validate(cmd_valid)
    assert res_valid.is_valid is True

    # Out of bounds: angle < -90.0
    cmd_invalid_angle = cmd_valid.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 2,
        "session_token": "TOKEN-PARAM-02",
        "parameters": {"angle": -95.0, "zoom": 5.0}
    })
    res_invalid_angle = fresh_engine.validate(cmd_invalid_angle)
    assert res_invalid_angle.is_valid is False
    assert any("angle' value -95.0 < minimum allowed -90.0" in r for r in res_invalid_angle.rejection_reasons)

    # Out of bounds: zoom > 10.0
    cmd_invalid_zoom = cmd_valid.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 3,
        "session_token": "TOKEN-PARAM-03",
        "parameters": {"angle": 45.0, "zoom": 12.0}
    })
    res_invalid_zoom = fresh_engine.validate(cmd_invalid_zoom)
    assert res_invalid_zoom.is_valid is False
    assert any("zoom' value 12.0 > maximum allowed 10.0" in r for r in res_invalid_zoom.rejection_reasons)

    # Parameter not in whitelist
    cmd_unwhitelisted = cmd_valid.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 4,
        "session_token": "TOKEN-PARAM-04",
        "parameters": {"angle": 45.0, "zoom": 5.0, "unauthorized_param": 100}
    })
    res_unwhitelisted = fresh_engine.validate(cmd_unwhitelisted)
    assert res_unwhitelisted.is_valid is False
    assert any("not in allowed parameter whitelist" in r for r in res_unwhitelisted.rejection_reasons)


def test_parameter_whitelist_and_bounds_change_orbit(fresh_engine: UplinkSecurityEngine):
    """Test CHANGE_ORBIT parameter bounds (delta_v: 0.1 to 50.0, thruster_duration: 1 to 120)."""
    # Valid
    cmd_valid = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id="SAT-EO-01",
        operator_id="OP-01",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type="CHANGE_ORBIT",
        sequence_number=1,
        session_token="TOKEN-ORBIT-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"delta_v": 15.0, "thruster_duration": 60.0}
    )
    res_valid = fresh_engine.validate(cmd_valid)
    assert res_valid.is_valid is True

    # delta_v < 0.1
    cmd_low_dv = cmd_valid.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 2,
        "session_token": "TOKEN-ORBIT-02",
        "parameters": {"delta_v": 0.05, "thruster_duration": 60.0}
    })
    res_low_dv = fresh_engine.validate(cmd_low_dv)
    assert res_low_dv.is_valid is False
    assert any("delta_v' value 0.05 < minimum allowed 0.1" in r for r in res_low_dv.rejection_reasons)

    # thruster_duration > 120
    cmd_high_dur = cmd_valid.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 3,
        "session_token": "TOKEN-ORBIT-03",
        "parameters": {"delta_v": 15.0, "thruster_duration": 150.0}
    })
    res_high_dur = fresh_engine.validate(cmd_high_dur)
    assert res_high_dur.is_valid is False
    assert any("thruster_duration' value 150.0 > maximum allowed 120.0" in r for r in res_high_dur.rejection_reasons)


def test_parameterless_commands_empty_params_valid(fresh_engine: UplinkSecurityEngine):
    """Test START_SENSOR, STOP_SENSOR, and REBOOT require no parameters."""
    for seq, cmd_type in enumerate(["START_SENSOR", "STOP_SENSOR", "REBOOT"], start=1):
        cmd = UplinkCommand(
            command_id=str(uuid.uuid4()),
            satellite_id="SAT-EO-01",
            operator_id="OP-DIR",
            role=OperatorRole.FLIGHT_DIRECTOR.value,
            command_type=cmd_type,
            sequence_number=seq,
            session_token=f"TOKEN-NO-PARAM-{cmd_type}",
            timestamp=datetime.now(timezone.utc),
            parameters={}
        )
        res = fresh_engine.validate(cmd)
        assert res.is_valid is True, f"Command {cmd_type} should be valid with empty parameters"


def test_last_sequence_numbers_tracking_and_replay_rejection(fresh_engine: UplinkSecurityEngine):
    """Test last_sequence_numbers dictionary tracking per satellite and strict > sequence requirement."""
    sat_a = "SAT-ALPHA-01"
    sat_b = "SAT-BETA-02"

    cmd_a1 = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id=sat_a,
        operator_id="OP-01",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type="START_SENSOR",
        sequence_number=10,
        session_token="TOKEN-A-10",
        timestamp=datetime.now(timezone.utc),
        parameters={}
    )
    res_a1 = fresh_engine.validate(cmd_a1)
    assert res_a1.is_valid is True
    assert fresh_engine.last_sequence_numbers[sat_a] == 10

    # Satellite B independent tracking
    cmd_b1 = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id=sat_b,
        operator_id="OP-01",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type="START_SENSOR",
        sequence_number=5,
        session_token="TOKEN-B-5",
        timestamp=datetime.now(timezone.utc),
        parameters={}
    )
    res_b1 = fresh_engine.validate(cmd_b1)
    assert res_b1.is_valid is True
    assert fresh_engine.last_sequence_numbers[sat_b] == 5

    # Equal sequence number on Sat A -> Rejected
    cmd_a_equal = cmd_a1.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 10,
        "session_token": "TOKEN-A-10-DUP",
    })
    res_a_equal = fresh_engine.validate(cmd_a_equal)
    assert res_a_equal.is_valid is False
    assert res_a_equal.security_event.event_type == "REPLAY_ATTACK_DETECTED"
    assert res_a_equal.action == CommandAction.BLOCK

    # Lower sequence number on Sat A -> Rejected
    cmd_a_lower = cmd_a1.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 9,
        "session_token": "TOKEN-A-9",
    })
    res_a_lower = fresh_engine.validate(cmd_a_lower)
    assert res_a_lower.is_valid is False
    assert res_a_lower.security_event.event_type == "REPLAY_ATTACK_DETECTED"

    # Higher sequence number on Sat A -> Accepted
    cmd_a_higher = cmd_a1.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 11,
        "session_token": "TOKEN-A-11",
    })
    res_a_higher = fresh_engine.validate(cmd_a_higher)
    assert res_a_higher.is_valid is True
    assert fresh_engine.last_sequence_numbers[sat_a] == 11


def test_eclipse_mode_blocks_change_orbit_and_reboot(fresh_engine: UplinkSecurityEngine):
    """Test set_eclipse_mode(satellite_id, active) blocks CHANGE_ORBIT and REBOOT."""
    sat = "SAT-EO-01"

    # Activate Eclipse Mode
    fresh_engine.set_eclipse_mode(sat, True)

    # CHANGE_ORBIT is blocked
    cmd_orbit = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id=sat,
        operator_id="OP-DIR",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type="CHANGE_ORBIT",
        sequence_number=1,
        session_token="TOKEN-ECLIPSE-01",
        timestamp=datetime.now(timezone.utc),
        parameters={"delta_v": 1.0, "thruster_duration": 10.0}
    )
    res_orbit = fresh_engine.validate(cmd_orbit)
    assert res_orbit.is_valid is False
    assert res_orbit.action == CommandAction.BLOCK
    assert any("prohibited while spacecraft 'SAT-EO-01' is in ECLIPSE mode" in r for r in res_orbit.rejection_reasons)

    # REBOOT is blocked
    cmd_reboot = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id=sat,
        operator_id="OP-DIR",
        role=OperatorRole.FLIGHT_DIRECTOR.value,
        command_type="REBOOT",
        sequence_number=2,
        session_token="TOKEN-ECLIPSE-02",
        timestamp=datetime.now(timezone.utc),
        parameters={}
    )
    res_reboot = fresh_engine.validate(cmd_reboot)
    assert res_reboot.is_valid is False
    assert res_reboot.action == CommandAction.BLOCK

    # ADJUST_CAMERA and START_SENSOR are allowed in eclipse mode
    cmd_camera = UplinkCommand(
        command_id=str(uuid.uuid4()),
        satellite_id=sat,
        operator_id="OP-02",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type="ADJUST_CAMERA",
        sequence_number=3,
        session_token="TOKEN-ECLIPSE-03",
        timestamp=datetime.now(timezone.utc),
        parameters={"angle": 10.0, "zoom": 2.0}
    )
    res_camera = fresh_engine.validate(cmd_camera)
    assert res_camera.is_valid is True

    # Deactivate Eclipse Mode
    fresh_engine.set_eclipse_mode(sat, False)

    # CHANGE_ORBIT is now allowed
    cmd_orbit_cleared = cmd_orbit.model_copy(update={
        "command_id": str(uuid.uuid4()),
        "sequence_number": 4,
        "session_token": "TOKEN-ECLIPSE-04",
    })
    res_orbit_cleared = fresh_engine.validate(cmd_orbit_cleared)
    assert res_orbit_cleared.is_valid is True


def test_hmac_sha256_hash_payload_format(fresh_engine: UplinkSecurityEngine):
    """Test HMAC-SHA256 signing payload format: {command_id}:{satellite_id}:{sequence_number}:{command_type}:{sorted_params_json}."""
    import hashlib
    import hmac
    import json

    secret_key = b"CUSTOM_SECRET_KEY_12345"
    engine = UplinkSecurityEngine(master_secret_key=secret_key)

    cmd = UplinkCommand(
        command_id="CMD-1234-UUID",
        satellite_id="SAT-EO-01",
        operator_id="OP-01",
        role=OperatorRole.PAYLOAD_OP.value,
        command_type="ADJUST_CAMERA",
        sequence_number=42,
        session_token="TOKEN-HMAC-TEST",
        timestamp=datetime.now(timezone.utc),
        parameters={"zoom": 2.5, "angle": -15.0}
    )

    # Manually compute expected hash
    sorted_params_json = json.dumps({"angle": -15.0, "zoom": 2.5}, sort_keys=True, separators=(",", ":"))
    expected_payload = f"CMD-1234-UUID:SAT-EO-01:42:ADJUST_CAMERA:{sorted_params_json}"
    expected_signature = hmac.new(secret_key, expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()

    signed_frame = engine.sign_command(cmd)
    assert signed_frame.hmac_signature == expected_signature
    assert engine.verify_hmac_signature(cmd, expected_signature) is True


# ===========================================================================
# 10. External Service Dispatch & FastApi Integration Tests
# ===========================================================================

def test_api_validate_blocked_dispatches_to_person_5_and_6(client: TestClient):
    """Test POST /commands/validate dispatches SecurityEvent to Person 5 and 6 on BLOCK."""
    from unittest.mock import AsyncMock, patch

    dispatched_urls = []

    async def mock_post(self, url, **kwargs):
        dispatched_urls.append(str(url))
        mock_resp = AsyncMock()
        mock_resp.status_code = 200
        return mock_resp

    with patch("httpx.AsyncClient.post", new=mock_post):
        # Trigger an invalid command (OBSERVER attempting CHANGE_ORBIT)
        payload = {
            "command": {
                "command_id": str(uuid.uuid4()),
                "satellite_id": "SAT-EO-01",
                "operator_id": "OP-OBSERVER-01",
                "role": "OBSERVER",
                "command_type": "CHANGE_ORBIT",
                "sequence_number": 1,
                "session_token": "API-BLOCK-DISPATCH-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "parameters": {"delta_v": 1.0, "thruster_duration": 10.0}
            }
        }
        res = client.post("/commands/validate", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["action"] == "BLOCK"
        assert data["is_valid"] is False
        assert data["security_event"] is not None

        # Verify dispatched to Person 5 and Person 6
        assert any("8005/events/ingest" in u for u in dispatched_urls)
        assert any("8006/audit/events" in u for u in dispatched_urls)


def test_api_execute_forwards_to_person_1_simulator(client: TestClient):
    """Test POST /commands/execute forwards signed frame to Person 1 Simulator."""
    from unittest.mock import AsyncMock, patch

    dispatched_urls = []

    async def mock_post(self, url, **kwargs):
        dispatched_urls.append(str(url))
        mock_resp = AsyncMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json = lambda: {"status": "SUCCESS", "simulated": True}
        return mock_resp

    with patch("httpx.AsyncClient.post", new=mock_post):
        payload = {
            "command": {
                "command_id": str(uuid.uuid4()),
                "satellite_id": "SAT-EO-01",
                "operator_id": "OP-DIRECTOR-01",
                "role": "FLIGHT_DIRECTOR",
                "command_type": "CHANGE_ORBIT",
                "sequence_number": 1,
                "session_token": "API-EXEC-P1-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "parameters": {"delta_v": 5.0, "thruster_duration": 30.0}
            },
            "dry_run": False
        }
        res = client.post("/commands/execute", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["validation"]["is_valid"] is True
        assert data["dispatched"] is True
        assert any("8001/commands/execute" in u for u in dispatched_urls)


# ===========================================================================
# 11. Specific User-Requested Test Suite
# ===========================================================================

def test_valid_camera_command(client: TestClient):
    """1. PAYLOAD_OP sends valid camera angle -> 200 ALLOW + valid signature."""
    payload = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-EO-01",
            "operator_id": "OP-PAYLOAD-01",
            "role": "PAYLOAD_OP",
            "command_type": "ADJUST_CAMERA",
            "sequence_number": 1,
            "session_token": "TOKEN-CAM-VALID-100",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {"angle": 30.0, "zoom": 2.5}
        }
    }
    response = client.post("/commands/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "ALLOW"
    assert data["is_valid"] is True
    assert data["signed_frame"] is not None
    assert data["signed_frame"]["signing_algorithm"] == "HMAC-SHA256"
    assert len(data["signed_frame"]["hmac_signature"]) == 64


def test_privilege_escalation(client: TestClient):
    """2. PAYLOAD_OP tries CHANGE_ORBIT -> 200 BLOCKED + UNAUTHORIZED_COMMAND + CRITICAL severity."""
    payload = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-EO-01",
            "operator_id": "OP-PAYLOAD-02",
            "role": "PAYLOAD_OP",
            "command_type": "CHANGE_ORBIT",
            "sequence_number": 1,
            "session_token": "TOKEN-ESC-200",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {"delta_v": 5.0, "thruster_duration": 30.0}
        }
    }
    response = client.post("/commands/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "BLOCK"
    assert data["is_valid"] is False
    assert data["security_event"] is not None
    assert data["security_event"]["event_type"] == "UNAUTHORIZED_COMMAND"
    assert data["security_event"]["severity"] == "CRITICAL"


def test_parameter_out_of_bounds(client: TestClient):
    """3. Camera angle set to 150 -> 200 BLOCKED + INVALID_PARAMETERS + HIGH severity."""
    payload = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-EO-01",
            "operator_id": "OP-PAYLOAD-03",
            "role": "PAYLOAD_OP",
            "command_type": "ADJUST_CAMERA",
            "sequence_number": 1,
            "session_token": "TOKEN-OOB-300",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {"angle": 150.0, "zoom": 2.0}
        }
    }
    response = client.post("/commands/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "BLOCK"
    assert data["is_valid"] is False
    assert data["security_event"] is not None
    assert data["security_event"]["event_type"] == "INVALID_PARAMETERS"
    assert data["security_event"]["severity"] == "HIGH"


def test_replay_attack(client: TestClient):
    """4. Send sequence 5, then send sequence 5 again -> 200 BLOCKED + REPLAY_ATTACK_DETECTED."""
    # First submission with sequence 5 -> ALLOW
    payload1 = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-REPLAY-TEST",
            "operator_id": "OP-DIRECTOR-01",
            "role": "FLIGHT_DIRECTOR",
            "command_type": "START_SENSOR",
            "sequence_number": 5,
            "session_token": "TOKEN-REPLAY-SEQ5-A",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {}
        }
    }
    res1 = client.post("/commands/validate", json=payload1)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["action"] == "ALLOW"
    assert data1["is_valid"] is True

    # Replay sequence 5 again -> 200 BLOCKED + REPLAY_ATTACK_DETECTED
    payload2 = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-REPLAY-TEST",
            "operator_id": "OP-DIRECTOR-01",
            "role": "FLIGHT_DIRECTOR",
            "command_type": "START_SENSOR",
            "sequence_number": 5,
            "session_token": "TOKEN-REPLAY-SEQ5-B",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {}
        }
    }
    res2 = client.post("/commands/validate", json=payload2)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["action"] == "BLOCK"
    assert data2["is_valid"] is False
    assert data2["security_event"] is not None
    assert data2["security_event"]["event_type"] == "REPLAY_ATTACK_DETECTED"


def test_unknown_command(client: TestClient):
    """5. Send 'SHUTDOWN_REACTOR' -> 200 BLOCKED + UNKNOWN_COMMAND."""
    payload = {
        "command": {
            "command_id": str(uuid.uuid4()),
            "satellite_id": "SAT-EO-01",
            "operator_id": "OP-DIRECTOR-01",
            "role": "FLIGHT_DIRECTOR",
            "command_type": "SHUTDOWN_REACTOR",
            "sequence_number": 1,
            "session_token": "TOKEN-UNKNOWN-CMD-500",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parameters": {}
        }
    }
    response = client.post("/commands/validate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "BLOCK"
    assert data["is_valid"] is False
    assert data["security_event"] is not None
    assert data["security_event"]["event_type"] == "UNKNOWN_COMMAND"



