"""
ORBITAL_SHIELD - Satellite & Ground Station Simulator API (P1 Unified Gateway)

FastAPI REST and WebSocket gateway exposing Telemetry, Commands, Firmware,
and Access Events across the P1 simulation pipeline.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
import uvicorn
import os
from pathlib import Path

from simulator.access.models import AccessAction, AccessEvent, AccessStatus
from simulator.commands.models import CommandEvent, CommandStatus, CommandType
from simulator.firmware.models import FirmwareData, FirmwareEvent, FirmwareStatus
from simulator.gateway import SimulatorGateway
from simulator.telemetry.engine import TelemetryReplayEngine
from simulator.telemetry.models import HealthResponse, TelemetryEvent

# Global default gateway instance
DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "data" / "consolidated_dataset_raw.csv"
default_gateway = SimulatorGateway(dataset_path=DEFAULT_DATASET_PATH)


# --- Request Schemas for Simulated Ingestion ---

class CommandSubmissionRequest(BaseModel):
    command_type: CommandType = Field(..., description="Target command type")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Command arguments")
    satellite_id: Optional[str] = Field(None, description="Optional target satellite override")


class FirmwareUpdateRequest(BaseModel):
    version: str = Field(..., description="Firmware version alias or artifact identifier")
    satellite_id: Optional[str] = Field(None, description="Optional target satellite override")


class AccessEventRequest(BaseModel):
    operator_id: str = Field(..., description="Operator identifier")
    device_id: str = Field(..., description="Device/terminal identifier")
    action: AccessAction = Field(..., description="Access action performed")
    status: AccessStatus = Field(default=AccessStatus.SUCCESS, description="Execution status")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Contextual metadata")
    satellite_id: Optional[str] = Field(None, description="Optional target satellite override")


def create_app(
    gateway: Optional[SimulatorGateway] = None,
    engine: Optional[TelemetryReplayEngine] = None,
) -> FastAPI:
    """
    Factory to create and configure the FastAPI application.
    Supports injecting a custom SimulatorGateway or TelemetryReplayEngine for tests.
    """
    if gateway is not None:
        app_gateway = gateway
    elif engine is not None:
        app_gateway = SimulatorGateway(telemetry_engine=engine)
    else:
        app_gateway = default_gateway

    app = FastAPI(
        title="ORBITAL_SHIELD Satellite & Ground Station Simulator",
        description="REST & WebSocket Gateway for Telemetry, Commands, Firmware, and Access Events.",
        version="1.0.0",
    )

    # Store handles in application state for backward compatibility and component access
    app.state.gateway = app_gateway
    app.state.engine = app_gateway.telemetry_engine

    # =========================================================================
    # 1. System & Health
    # =========================================================================

    @app.get(
        "/health",
        response_model=HealthResponse,
        summary="Check Simulator Health Status",
        description="Returns current operational state of the satellite simulator and replay metrics.",
        tags=["System"],
    )
    def get_health() -> HealthResponse:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_health()

    @app.get(
        "/system/status",
        summary="Get Comprehensive Simulator Status",
        description="Returns full operational metrics across all 5 simulator submodules.",
        tags=["System"],
    )
    def get_system_status() -> Dict[str, Any]:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_system_status()

    # =========================================================================
    # 2. Telemetry (REST & WebSocket)
    # =========================================================================

    @app.get(
        "/telemetry/current",
        response_model=TelemetryEvent,
        summary="Get Current Telemetry Frame",
        description="Returns the standardized TelemetryEvent for the current satellite state.",
        tags=["Telemetry"],
    )
    def get_current_telemetry() -> TelemetryEvent:
        gw: SimulatorGateway = app.state.gateway
        event = gw.get_current_telemetry()
        if event is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No telemetry records available in dataset.",
            )
        return event

    @app.websocket("/telemetry/stream")
    async def websocket_telemetry_stream(
        websocket: WebSocket,
        speed: Optional[float] = Query(
            None, ge=0.01, description="Optional playback speed multiplier (e.g. 2.0 = 2x)"
        ),
        interval: Optional[float] = Query(
            None, gt=0, description="Optional fixed delay interval between frames (seconds)"
        ),
        loop: Optional[bool] = Query(
            None, description="Optional toggle to enable/disable looping at end of dataset"
        ),
        limit: Optional[int] = Query(
            None, gt=0, description="Optional maximum number of frames to stream"
        ),
    ):
        """
        WebSocket endpoint streaming continuous standardized TelemetryEvent payloads.
        Delegates sequencing to TelemetryReplayEngine and ScenarioEngine through SimulatorGateway.
        Safely handles client disconnections.
        """
        await websocket.accept()
        gw: SimulatorGateway = app.state.gateway

        if loop is not None:
            gw.telemetry_engine.set_loop(loop)
        if speed is not None:
            gw.telemetry_engine.set_speed(speed)

        effective_interval = interval if interval is not None else gw.telemetry_engine.effective_interval_sec

        try:
            async for event in gw.stream_telemetry(
                limit=limit,
                interval_sec=effective_interval,
                auto_start=True,
            ):
                await websocket.send_text(event.model_dump_json())
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

    # =========================================================================
    # 3. Commands
    # =========================================================================

    @app.get(
        "/commands",
        response_model=List[CommandEvent],
        summary="Get Command History",
        description="Retrieves sequential ground station command history with optional filtering.",
        tags=["Commands"],
    )
    def get_commands(
        limit: Optional[int] = Query(None, gt=0, description="Max command records to return"),
        command_type: Optional[CommandType] = Query(None, description="Filter by command type"),
        cmd_status: Optional[CommandStatus] = Query(None, alias="status", description="Filter by status"),
    ) -> List[CommandEvent]:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_command_history(limit=limit, command_type=command_type, status=cmd_status)

    @app.post(
        "/commands",
        response_model=CommandEvent,
        status_code=status.HTTP_201_CREATED,
        summary="Submit Satellite Command",
        description="Generates and submits a command from ground station to satellite.",
        tags=["Commands"],
    )
    def submit_command(req: CommandSubmissionRequest) -> CommandEvent:
        gw: SimulatorGateway = app.state.gateway
        return gw.submit_command(
            command_type=req.command_type,
            parameters=req.parameters,
            satellite_id=req.satellite_id,
        )

    # =========================================================================
    # 4. Firmware
    # =========================================================================

    @app.get(
        "/firmware",
        response_model=List[FirmwareEvent],
        summary="Get Firmware Event History",
        description="Retrieves history of firmware updates and lifecycle events.",
        tags=["Firmware"],
    )
    def get_firmware_events(
        limit: Optional[int] = Query(None, gt=0, description="Max records to return"),
        fw_status: Optional[FirmwareStatus] = Query(None, alias="status", description="Filter by status"),
        version: Optional[str] = Query(None, description="Filter by firmware version"),
    ) -> List[FirmwareEvent]:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_firmware_history(limit=limit, status=fw_status, version=version)

    @app.get(
        "/firmware/artifacts",
        response_model=List[FirmwareData],
        summary="Get Registered Firmware Artifacts",
        description="Retrieves list of all registered firmware artifacts (firmware_v1, firmware_v2, etc.).",
        tags=["Firmware"],
    )
    def get_firmware_artifacts() -> List[FirmwareData]:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_registered_firmware_artifacts()

    @app.post(
        "/firmware/update",
        response_model=FirmwareEvent,
        status_code=status.HTTP_201_CREATED,
        summary="Request Firmware Update",
        description="Generates an UPDATE_REQUESTED event for a registered firmware artifact.",
        tags=["Firmware"],
    )
    def request_firmware_update(req: FirmwareUpdateRequest) -> FirmwareEvent:
        gw: SimulatorGateway = app.state.gateway
        try:
            return gw.request_firmware_update(
                firmware_id_or_version=req.version,
                satellite_id=req.satellite_id,
            )
        except KeyError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    # =========================================================================
    # 5. Access Events
    # =========================================================================

    @app.get(
        "/access",
        response_model=List[AccessEvent],
        summary="Get Access Event History",
        description="Retrieves operator and device access event logs.",
        tags=["Access"],
    )
    def get_access_events(
        limit: Optional[int] = Query(None, gt=0, description="Max records to return"),
        action: Optional[AccessAction] = Query(None, description="Filter by access action"),
        operator_id: Optional[str] = Query(None, description="Filter by operator ID"),
        acc_status: Optional[AccessStatus] = Query(None, alias="status", description="Filter by status"),
    ) -> List[AccessEvent]:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_access_history(
            limit=limit,
            action=action,
            operator_id=operator_id,
            status=acc_status,
        )

    @app.post(
        "/access",
        response_model=AccessEvent,
        status_code=status.HTTP_201_CREATED,
        summary="Record Access Event",
        description="Records an operator/device access event (e.g. LOGIN, LOGOUT, FAILED_LOGIN).",
        tags=["Access"],
    )
    def record_access_event(req: AccessEventRequest) -> AccessEvent:
        gw: SimulatorGateway = app.state.gateway
        return gw.record_access_event(
            operator_id=req.operator_id,
            device_id=req.device_id,
            action=req.action,
            status=req.status,
            metadata=req.metadata,
            satellite_id=req.satellite_id,
        )

    # =========================================================================
    # 6. Unified Event Bus Queries
    # =========================================================================

    @app.get(
        "/events/latest",
        summary="Get Latest Event Across All Types",
        description="Returns the most recent event for TELEMETRY, COMMAND, FIRMWARE, and ACCESS.",
        tags=["Unified Events"],
    )
    def get_all_latest_events() -> Dict[str, Optional[Any]]:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_all_latest_events()

    @app.get(
        "/events/history",
        summary="Get Unified Event History",
        description="Retrieves unified chronological event stream across all P1 simulator modules.",
        tags=["Unified Events"],
    )
    def get_unified_event_history(
        limit: Optional[int] = Query(None, gt=0, description="Max records to return"),
        event_type: Optional[str] = Query(None, description="Filter by event_type (TELEMETRY, COMMAND, FIRMWARE, ACCESS)"),
    ) -> List[Any]:
        gw: SimulatorGateway = app.state.gateway
        return gw.get_unified_history(limit=limit, event_type=event_type)

    return app

# Default ASGI application instance for uvicorn
_built_app = create_app()

# Add /health endpoint to the built app for two-machine smoke-testing
@_built_app.get("/health", tags=["Health"], summary="Simulator health check")
def simulator_health():
    _sim_port = int(os.getenv("SIMULATOR_PORT", "8000"))
    return {"module": "simulator", "status": "HEALTHY", "port": _sim_port}

app = _built_app

if __name__ == "__main__":
    # Load shared .env (integration-final repo root, one level above simulator/)
    _env = Path(__file__).resolve().parent.parent / ".env"
    if _env.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=_env, override=False)
        except ImportError:
            pass
    _port = int(os.getenv("SIMULATOR_PORT", "8000"))
    print(f"Starting ORBITAL_SHIELD Satellite Simulator Gateway on http://0.0.0.0:{_port} ...")
    uvicorn.run("simulator.main:app", host="0.0.0.0", port=_port, reload=True)  # B9: was 127.0.0.1