"""
ORBITAL_SHIELD - Firmware Event Models & Schemas

Defines Pydantic models for simulated firmware artifacts and lifecycle events,
adhering to the standardized ORBITAL_SHIELD event envelope format.
"""

from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class FirmwareStatus(str, Enum):
    """
    Lifecycle status for simulated firmware updates.
    """
    REGISTERED = "REGISTERED"
    UPDATE_REQUESTED = "UPDATE_REQUESTED"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_COMPLETED = "UPDATE_COMPLETED"
    UPDATE_FAILED = "UPDATE_FAILED"


class FirmwareData(BaseModel):
    """
    Firmware metadata and update status payload.
    Note: Contains simulated metadata (e.g. hash) without making security decisions.
    """
    model_config = ConfigDict(extra="forbid")

    firmware_id: str = Field(
        ...,
        description="Unique identifier for the firmware artifact (e.g. FW-A1B2C3D4)"
    )
    version: str = Field(
        ...,
        description="Firmware release version string (e.g. 'v1.0.0', 'firmware_v1')"
    )
    artifact: str = Field(
        ...,
        description="Filename or binary artifact identifier (e.g. 'orbital_obc_v1.bin')"
    )
    size_bytes: int = Field(
        ...,
        ge=0,
        description="Size of the firmware image in bytes"
    )
    hash: str = Field(
        ...,
        description="SHA-256 cryptographic hash digest of the firmware artifact"
    )
    status: FirmwareStatus = Field(
        default=FirmwareStatus.UPDATE_REQUESTED,
        description="Current lifecycle status of the firmware update"
    )


class FirmwareEvent(BaseModel):
    """
    Standardized Firmware Event envelope emitted by the Ground Station / Satellite Simulator.
    
    Structure:
    {
        "event_id": "...",
        "timestamp": "...",
        "source": "GROUND_STATION_SIMULATOR",
        "satellite_id": "SAT-ORBITAL-01",
        "event_type": "FIRMWARE",
        "data": {
            "firmware_id": "...",
            "version": "...",
            "artifact": "...",
            "size_bytes": 0,
            "hash": "...",
            "status": "UPDATE_REQUESTED"
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
        description="ISO-8601 UTC timestamp of firmware event emission"
    )
    source: Literal["GROUND_STATION_SIMULATOR", "SATELLITE_SIMULATOR"] = Field(
        default="GROUND_STATION_SIMULATOR",
        description="Origin source identifier for the firmware event bus"
    )
    satellite_id: str = Field(
        default="SAT-ORBITAL-01",
        description="Target satellite identifier"
    )
    event_type: Literal["FIRMWARE"] = Field(
        default="FIRMWARE",
        description="Standardized event category for the ORBITAL_SHIELD platform"
    )
    data: FirmwareData = Field(
        ...,
        description="Firmware metadata and status payload"
    )
