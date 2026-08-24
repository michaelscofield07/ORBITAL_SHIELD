"""
ORBITAL_SHIELD - Command Event Models & Schemas

Defines Pydantic models for Ground Station to Satellite commands, adhering to
the standardized ORBITAL_SHIELD event envelope format.
"""

from enum import Enum
from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class CommandType(str, Enum):
    """
    Standardized satellite command types supported by the simulator.
    """
    ADJUST_CAMERA = "ADJUST_CAMERA"
    CHANGE_ORBIT = "CHANGE_ORBIT"
    START_SENSOR = "START_SENSOR"
    STOP_SENSOR = "STOP_SENSOR"
    REBOOT = "REBOOT"


class CommandStatus(str, Enum):
    """
    Operational status of a simulated command.
    """
    PENDING = "PENDING"
    TRANSMITTED = "TRANSMITTED"
    RECEIVED = "RECEIVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class CommandData(BaseModel):
    """
    Command payload containing command ID, type, parameters, and execution status.
    """
    model_config = ConfigDict(extra="forbid")

    command_id: str = Field(
        ...,
        description="Unique identifier for the command (e.g. CMD-1a2b3c4d)"
    )
    command_type: CommandType = Field(
        ...,
        description="Type of command being issued to the satellite"
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value parameters/arguments for command execution"
    )
    status: CommandStatus = Field(
        default=CommandStatus.PENDING,
        description="Current lifecycle status of the command"
    )


class CommandEvent(BaseModel):
    """
    Standardized Command Event envelope emitted by the Ground Station Simulator.
    
    Structure:
    {
        "event_id": "...",
        "timestamp": "...",
        "source": "GROUND_STATION_SIMULATOR",
        "satellite_id": "SAT-ORBITAL-01",
        "event_type": "COMMAND",
        "data": {
            "command_id": "...",
            "command_type": "ADJUST_CAMERA",
            "parameters": {...},
            "status": "PENDING"
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
        description="ISO-8601 UTC timestamp of command creation/emission"
    )
    source: Literal["GROUND_STATION_SIMULATOR"] = Field(
        default="GROUND_STATION_SIMULATOR",
        description="Origin source identifier for command bus"
    )
    satellite_id: str = Field(
        default="SAT-ORBITAL-01",
        description="Target satellite identifier"
    )
    event_type: Literal["COMMAND"] = Field(
        default="COMMAND",
        description="Standardized event category for the ORBITAL_SHIELD platform"
    )
    data: CommandData = Field(
        ...,
        description="Command data payload"
    )
