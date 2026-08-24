"""
Unit and Integration tests for ORBITAL_SHIELD FastAPI REST & WebSocket Endpoints.
"""

from fastapi.testclient import TestClient
import pandas as pd
import pytest

from simulator.main import create_app
from simulator.telemetry.engine import TelemetryReplayEngine
from simulator.telemetry.models import HealthResponse, TelemetryEvent


@pytest.fixture
def api_client():
    """Returns a TestClient with a fresh replay engine backed by the real dataset."""
    engine = TelemetryReplayEngine()
    app = create_app(engine=engine)
    client = TestClient(app)
    return client, engine


def test_get_health_endpoint(api_client):
    """Test GET /health returns 200 OK and valid HealthResponse schema."""
    client, engine = api_client
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()

    # Validate against Pydantic model
    health_model = HealthResponse(**data)
    assert health_model.status == "healthy"
    assert health_model.satellite_id == "SAT-ORBITAL-01"
    assert health_model.total_records == 25000
    assert health_model.current_index == 0
    assert health_model.emitted_count == 0
    assert health_model.simulator_state == "STOPPED"


def test_get_telemetry_current_endpoint(api_client):
    """Test GET /telemetry/current returns 200 OK and valid TelemetryEvent format."""
    client, engine = api_client
    response = client.get("/telemetry/current")

    assert response.status_code == 200
    data = response.json()

    # Validate against Pydantic model
    event_model = TelemetryEvent(**data)
    assert event_model.source == "SATELLITE_SIMULATOR"
    assert event_model.satellite_id == "SAT-ORBITAL-01"
    assert event_model.event_type == "TELEMETRY"

    # Verify data fields exist and match expected initial record
    payload = event_model.data
    assert payload.MsgId == 6323
    assert payload.CmdCode == 0
    assert payload.Label == 3
    assert payload.MemoryAnonMB > 0


def test_telemetry_current_updates_after_step(api_client):
    """Test GET /telemetry/current reflects the updated position after engine advances."""
    client, engine = api_client

    # Advance engine by 1 record
    stepped_event = engine.step()
    assert stepped_event is not None

    # Verify /health reflects new index
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["current_index"] == 1
    assert health_resp.json()["emitted_count"] == 1

    # Verify /telemetry/current reflects record index 1
    telem_resp = client.get("/telemetry/current")
    assert telem_resp.status_code == 200
    event_data = telem_resp.json()
    assert event_data["data"]["CmdCode"] == 1


def test_empty_dataset_returns_404():
    """Test that an empty dataset returns HTTP 404 on /telemetry/current."""
    empty_df = pd.DataFrame(columns=["MsgId"])
    engine = TelemetryReplayEngine(dataframe=empty_df)
    app = create_app(engine=engine)
    client = TestClient(app)

    response = client.get("/telemetry/current")
    assert response.status_code == 404
    assert "No telemetry records available" in response.json()["detail"]


def test_openapi_schema(api_client):
    """Test OpenAPI schema contains /health and /telemetry/current endpoints."""
    client, _ = api_client
    response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert "/health" in schema["paths"]
    assert "/telemetry/current" in schema["paths"]


def test_websocket_telemetry_stream(api_client):
    """Test WebSocket /telemetry/stream connects, streams valid TelemetryEvents, and finishes."""
    client, engine = api_client

    with client.websocket_connect("/telemetry/stream?limit=3&interval=0.001") as websocket:
        messages = []
        for _ in range(3):
            raw_msg = websocket.receive_text()
            event = TelemetryEvent.model_validate_json(raw_msg)
            messages.append(event)

        assert len(messages) == 3
        # Check standard envelope format
        for evt in messages:
            assert evt.source == "SATELLITE_SIMULATOR"
            assert evt.satellite_id == "SAT-ORBITAL-01"
            assert evt.event_type == "TELEMETRY"
            assert evt.data.MsgId > 0
            assert evt.data.Label in (0, 1, 2, 3, 4)

        # Check sequence progression
        assert messages[0].data.CmdCode == 0
        assert messages[1].data.CmdCode == 1


def test_websocket_client_disconnect_safe(api_client):
    """Test WebSocket server handles premature client disconnection gracefully."""
    client, engine = api_client

    # Connect, receive 1 message, and immediately exit context (disconnect)
    with client.websocket_connect("/telemetry/stream?limit=100&interval=0.01") as websocket:
        raw_msg = websocket.receive_text()
        event = TelemetryEvent.model_validate_json(raw_msg)
        assert event.source == "SATELLITE_SIMULATOR"
        # Context manager exit triggers client websocket close

    # Verify server / engine remains operational
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"
