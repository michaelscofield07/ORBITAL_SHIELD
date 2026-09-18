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

    def to_normalized_event(self) -> "NormalizedAccessEvent":
        """
        Converts this standardized AccessEvent into a P4-compatible NormalizedAccessEvent.
        """
        return normalize_access_event(self)

    def to_normalized_dict(self) -> Dict[str, Any]:
        """
        Converts this standardized AccessEvent into a P4-compatible dictionary representation.
        """
        return normalize_access_event(self).model_dump()


class NormalizedAccessEvent(BaseModel):
    """
    Normalized Access Event model conforming to the P4 Access Security schema contract.

    Exposes the 10 required fields:
    1. timestamp
    2. user_id
    3. source_ip
    4. device_id
    5. action
    6. result
    7. role
    8. previous_role
    9. satellite_id
    10. session_id
    """
    model_config = ConfigDict(extra="forbid")

    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of access event creation/emission"
    )
    user_id: str = Field(
        ...,
        description="Operator or user identifier"
    )
    source_ip: str = Field(
        ...,
        description="Simulated client source IP address"
    )
    device_id: str = Field(
        ...,
        description="Client device/terminal identifier"
    )
    action: str = Field(
        ...,
        description="Normalized access action (e.g. LOGIN, LOGOUT, NEW_DEVICE, PRIVILEGE_CHANGE, COMMAND)"
    )
    result: str = Field(
        ...,
        description="Execution outcome status (SUCCESS, FAILED)"
    )
    role: str = Field(
        ...,
        description="Current or target user role"
    )
    previous_role: str = Field(
        ...,
        description="Previous user role prior to modification"
    )
    satellite_id: str = Field(
        ...,
        description="Associated satellite identifier"
    )
    session_id: str = Field(
        ...,
        description="Simulated session identifier"
    )


def normalize_access_event(event: AccessEvent) -> NormalizedAccessEvent:
    """
    Converts a standardized P1 AccessEvent into a P4-compatible NormalizedAccessEvent.
    Adheres to P1-P4 field and action mapping specifications.
    """
    data = event.data
    meta = data.metadata if data.metadata is not None else {}

    raw_action = data.action.value if isinstance(data.action, AccessAction) else str(data.action)
    raw_status = data.status.value if isinstance(data.status, AccessStatus) else str(data.status)

    # 1. Action Mapping & Default Result
    if raw_action == "FAILED_LOGIN":
        normalized_action = "LOGIN"
        normalized_result = "FAILED"
    elif raw_action in ("COMMAND_ACCESS", "COMMAND"):
        normalized_action = "COMMAND"
        normalized_result = "FAILED" if raw_status.upper() in ("FAILURE", "DENIED", "FAILED") else "SUCCESS"
    elif raw_action == "LOGIN":
        normalized_action = "LOGIN"
        normalized_result = "FAILED" if raw_status.upper() in ("FAILURE", "DENIED", "FAILED") else "SUCCESS"
    elif raw_action == "LOGOUT":
        normalized_action = "LOGOUT"
        normalized_result = "FAILED" if raw_status.upper() in ("FAILURE", "DENIED", "FAILED") else "SUCCESS"
    elif raw_action == "PRIVILEGE_CHANGE":
        normalized_action = "PRIVILEGE_CHANGE"
        normalized_result = "FAILED" if raw_status.upper() in ("FAILURE", "DENIED", "FAILED") else "SUCCESS"
    elif raw_action == "NEW_DEVICE":
        normalized_action = "NEW_DEVICE"
        normalized_result = "FAILED" if raw_status.upper() in ("FAILURE", "DENIED", "FAILED") else "SUCCESS"
    else:
        normalized_action = raw_action
        normalized_result = "FAILED" if raw_status.upper() in ("FAILURE", "DENIED", "FAILED") else "SUCCESS"

    # Explicit result override in metadata if provided
    if "result" in meta:
        res_str = str(meta["result"]).upper()
        normalized_result = "FAILED" if res_str in ("FAILED", "FAILURE", "DENIED") else "SUCCESS"

    # 2. User ID (operator identifier)
    user_id = str(meta.get("user_id") or data.operator_id or "operator_01")

    # 3. Device ID
    device_id = str(meta.get("device_id") or data.device_id or "GS-DEVICE-01")

    # 4. Source IP (metadata source_ip, ip_address, ip, or default 10.0.0.15)
    source_ip = str(
        meta.get("source_ip")
        or meta.get("ip_address")
        or meta.get("ip")
        or "10.0.0.15"
    )

    # 5. Role & Previous Role
    # For privilege changes: meta contains previous_role and new_role (or role)
    role = str(meta.get("role") or meta.get("new_role") or "operator")
    previous_role = str(meta.get("previous_role") or meta.get("role") or "operator")

    # 6. Session ID
    session_id = str(meta.get("session_id") or "SESSION-001")

    # 7. Satellite ID
    satellite_id = str(meta.get("satellite_id") or event.satellite_id or "SAT-ORBITAL-01")

    # 8. Timestamp
    timestamp = str(event.timestamp)

    return NormalizedAccessEvent(
        timestamp=timestamp,
        user_id=user_id,
        source_ip=source_ip,
        device_id=device_id,
        action=normalized_action,
        result=normalized_result,
        role=role,
        previous_role=previous_role,
        satellite_id=satellite_id,
        session_id=session_id,
    )

