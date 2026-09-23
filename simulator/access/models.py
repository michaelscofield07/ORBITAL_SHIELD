"""
ORBITAL_SHIELD - Access Event Models & Schemas

Defines Pydantic models for operator and device access events at the Ground Station,
adhering to the standardized ORBITAL_SHIELD event envelope format.
"""

from enum import Enum
from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class AccessAction(str, Enum):
    """
    Standardized access event actions supported by the simulator.
    """
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    FAILED_LOGIN = "FAILED_LOGIN"
    NEW_DEVICE = "NEW_DEVICE"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    COMMAND_ACCESS = "COMMAND_ACCESS"


class AccessStatus(str, Enum):
    """
    Execution status of the access event.
    """
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    PENDING = "PENDING"


class AccessData(BaseModel):
    """
    Access event payload containing operator, device, action, status, and metadata.
    """
    model_config = ConfigDict(extra="forbid")

    access_id: str = Field(
        ...,
        description="Unique identifier for the access record (e.g. ACC-A1B2C3D4)"
    )
    operator_id: str = Field(
        ...,
        description="Identifier of the operator or service account (e.g. 'OP-ALICE-01')"
    )
    device_id: str = Field(
        ...,
        description="Identifier of the client device/terminal (e.g. 'DEV-CONSOLE-02')"
    )
    action: AccessAction = Field(
        ...,
        description="Type of access action performed"
    )
    status: AccessStatus = Field(
        default=AccessStatus.SUCCESS,
        description="Status outcome of the access action"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional contextual metadata (e.g. ip_address, role, command_type)"
    )


class AccessEvent(BaseModel):
    """
    Standardized Access Event envelope emitted by the Ground Station Simulator.
    
    Structure:
    {
        "event_id": "...",
        "timestamp": "...",
        "source": "GROUND_STATION_SIMULATOR",
        "satellite_id": "SAT-ORBITAL-01",
        "event_type": "ACCESS",
        "data": {
            "access_id": "...",
            "operator_id": "...",
            "device_id": "...",
            "action": "LOGIN",
            "status": "SUCCESS",
            "metadata": {...}
        }
    }
    """
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(
        ...,
        description="Unique identifier for this event instance (UUIDv4)"
    )
    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of access event creation/emission"
    )
    source: Literal["GROUND_STATION_SIMULATOR", "SATELLITE_SIMULATOR"] = Field(
        default="GROUND_STATION_SIMULATOR",
        description="Origin source identifier for the access event bus"
    )
    satellite_id: str = Field(
        default="SAT-ORBITAL-01",
        description="Target or associated satellite identifier"
    )
    event_type: Literal["ACCESS"] = Field(
        default="ACCESS",
        description="Standardized event category for the ORBITAL_SHIELD platform"
    )
    data: AccessData = Field(
        ...,
        description="Access event data payload"
    )
