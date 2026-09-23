"""
Integration tests for ORBITAL_SHIELD P1 Unified Simulator Workflow.
Verifies cohesive interaction between Telemetry, Scenarios, Commands, Firmware,
and Access Events through the common SimulatorGateway and FastAPI/WebSocket layer.
"""

from pathlib import Path
from fastapi.testclient import TestClient
import pandas as pd
import pytest

from simulator.access.models import AccessAction, AccessEvent, AccessStatus
from simulator.commands.models import CommandEvent, CommandStatus, CommandType
from simulator.firmware.models import FirmwareData, FirmwareEvent, FirmwareStatus
from simulator.gateway import SimulatorGateway
from simulator.main import create_app
from simulator.scenarios.models import ScenarioType, TelemetryAnomalyConfig
from simulator.telemetry.models import HealthResponse, TelemetryEvent


@pytest.fixture
def integrated_client():
    """Returns a TestClient backed by a fresh SimulatorGateway."""
    gw = SimulatorGateway()
    app = create_app(gateway=gw)
    client = TestClient(app)
    return client, gw


def test_gateway_initialization_and_health(integrated_client):
    """Test gateway startup, health check, and system status."""
    client, gw = integrated_client

    # 1. Test /health
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    health_data = HealthResponse(**health_resp.json())
    assert health_data.status == "healthy"
    assert health_data.total_records == 25000
    assert health_data.satellite_id == "SAT-ORBITAL-01"

    # 2. Test /system/status
    sys_resp = client.get("/system/status")
    assert sys_resp.status_code == 200
    sys_data = sys_resp.json()
    assert sys_data["satellite_id"] == "SAT-ORBITAL-01"
    assert "telemetry" in sys_data
    assert "scenarios" in sys_data
    assert sys_data["total_unified_events"] == 0


def test_telemetry_event_flow_through_gateway(integrated_client):
    """Test telemetry generation and transformation flow."""
    client, gw = integrated_client

    # GET /telemetry/current
    telem_resp = client.get("/telemetry/current")
    assert telem_resp.status_code == 200
    event = TelemetryEvent(**telem_resp.json())
    assert event.event_type == "TELEMETRY"
    assert event.source == "SATELLITE_SIMULATOR"
    assert event.data.MsgId == 6323

    # Activate scenario through gateway
    cfg = TelemetryAnomalyConfig(memory_multiplier=3.0, inject_page_faults=64, seed=42)
    gw.set_scenario(ScenarioType.TELEMETRY_ANOMALY, config=cfg)

    anom_event = gw.get_current_telemetry()
    assert anom_event is not None
    assert anom_event.data.MemoryPageFaults == 64

    gw.reset_scenario_to_normal()


def test_command_event_flow_through_gateway(integrated_client):
    """Test command generation, submission, and history via REST."""
    client, gw = integrated_client

    # POST /commands
    cmd_payload = {
        "command_type": "CHANGE_ORBIT",
        "parameters": {"delta_v_ms": 10.0, "target_altitude_km": 500.0},
    }
    post_resp = client.post("/commands", json=cmd_payload)
    assert post_resp.status_code == 201
    cmd_event = CommandEvent(**post_resp.json())
    assert cmd_event.event_type == "COMMAND"
    assert cmd_event.source == "GROUND_STATION_SIMULATOR"
    assert cmd_event.data.command_type == CommandType.CHANGE_ORBIT
    assert cmd_event.data.parameters["delta_v_ms"] == 10.0

    # GET /commands
    get_resp = client.get("/commands")
    assert get_resp.status_code == 200
    history = [CommandEvent(**item) for item in get_resp.json()]
    assert len(history) >= 1
    assert history[-1].data.command_id == cmd_event.data.command_id


def test_firmware_event_flow_through_gateway(integrated_client):
    """Test firmware artifact queries, update request, and history."""
    client, gw = integrated_client

    # GET /firmware/artifacts
    art_resp = client.get("/firmware/artifacts")
    assert art_resp.status_code == 200
    artifacts = [FirmwareData(**a) for a in art_resp.json()]
    assert any(a.version == "firmware_v1" for a in artifacts)
    assert any(a.version == "firmware_v2" for a in artifacts)

    # POST /firmware/update
    update_req = {"version": "firmware_v2"}
    post_resp = client.post("/firmware/update", json=update_req)
    assert post_resp.status_code == 201
    fw_event = FirmwareEvent(**post_resp.json())
    assert fw_event.event_type == "FIRMWARE"
    assert fw_event.data.version == "firmware_v2"
    assert fw_event.data.status == FirmwareStatus.UPDATE_REQUESTED

    # GET /firmware
    get_resp = client.get("/firmware")
    assert get_resp.status_code == 200
    fw_history = [FirmwareEvent(**item) for item in get_resp.json()]
    assert len(fw_history) >= 1
    assert fw_history[-1].data.version == "firmware_v2"


def test_access_event_flow_through_gateway(integrated_client):
    """Test operator and device access event recording and history."""
    client, gw = integrated_client

    # POST /access
    access_req = {
        "operator_id": "OP-ALICE-01",
        "device_id": "DEV-CONSOLE-01",
        "action": "LOGIN",
        "status": "SUCCESS",
        "metadata": {"auth_method": "MFA_HARDWARE_KEY"},
    }
    post_resp = client.post("/access", json=access_req)
    assert post_resp.status_code == 201
    acc_event = AccessEvent(**post_resp.json())
    assert acc_event.event_type == "ACCESS"
    assert acc_event.data.action == AccessAction.LOGIN
    assert acc_event.data.operator_id == "OP-ALICE-01"

    # GET /access
    get_resp = client.get("/access")
    assert get_resp.status_code == 200
    acc_history = [AccessEvent(**item) for item in get_resp.json()]
    assert len(acc_history) >= 1
    assert acc_history[-1].data.operator_id == "OP-ALICE-01"


def test_unified_events_latest_and_history(integrated_client):
    """Test retrieving latest events and chronological unified history."""
    client, gw = integrated_client

    # Trigger one event of each type
    gw.step_telemetry()
    client.post("/commands", json={"command_type": "ADJUST_CAMERA", "parameters": {"zoom": 1.5}})
    client.post("/firmware/update", json={"version": "firmware_v1"})
    client.post("/access", json={"operator_id": "OP-BOB", "device_id": "DEV-02", "action": "LOGIN"})

    # GET /events/latest
    latest_resp = client.get("/events/latest")
    assert latest_resp.status_code == 200
    latest_data = latest_resp.json()

    assert latest_data["TELEMETRY"]["event_type"] == "TELEMETRY"
    assert latest_data["COMMAND"]["event_type"] == "COMMAND"
    assert latest_data["FIRMWARE"]["event_type"] == "FIRMWARE"
    assert latest_data["ACCESS"]["event_type"] == "ACCESS"

    # GET /events/history
    hist_resp = client.get("/events/history")
    assert hist_resp.status_code == 200
    unified = hist_resp.json()
    assert len(unified) >= 4
    event_types_present = {e["event_type"] for e in unified}
    assert {"TELEMETRY", "COMMAND", "FIRMWARE", "ACCESS"}.issubset(event_types_present)


def test_websocket_stream_with_gateway(integrated_client):
    """Test WebSocket streaming continues to function seamlessly with SimulatorGateway."""
    client, gw = integrated_client

    with client.websocket_connect("/telemetry/stream?limit=3&interval=0.001") as ws:
        frames = []
        for _ in range(3):
            raw = ws.receive_text()
            evt = TelemetryEvent.model_validate_json(raw)
            frames.append(evt)

        assert len(frames) == 3
        assert all(f.event_type == "TELEMETRY" for f in frames)


def test_source_csv_remains_unchanged():
    """Verify source CSV remains 100% identical after full workflow operations."""
    dataset_path = Path(__file__).resolve().parent / "data" / "consolidated_dataset_raw.csv"
    df_before = pd.read_csv(dataset_path)

    gw = SimulatorGateway()
    # Exercise all operations
    gw.get_current_telemetry()
    gw.step_telemetry()
    gw.submit_command(CommandType.REBOOT)
    gw.request_firmware_update("firmware_v1")
    gw.record_access_event("OP-TEST", "DEV-TEST", AccessAction.LOGIN)

    df_after = pd.read_csv(dataset_path)
    pd.testing.assert_frame_equal(df_before, df_after)
