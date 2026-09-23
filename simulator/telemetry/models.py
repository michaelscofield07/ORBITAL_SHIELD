"""
ORBITAL_SHIELD - Telemetry Event Models

This module defines the Pydantic models for standardized telemetry events.
All 31 original fields from the dataset are preserved with their exact data types
and values without arbitrary renaming or inventional modification.

Simulator-generated metadata fields (event_id, timestamp, source, satellite_id, event_type)
are explicitly marked and documented.
"""

from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class TelemetryData(BaseModel):
    """
    Preserved telemetry and communication payload from the CubeSat dataset.
    Contains all 31 features without alteration.
    """
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # --- Space Packet / Protocol Header Fields ---
    MsgId: int = Field(..., description="CCSDS Message ID")
    CmdCode: int = Field(..., description="Command Code / Opcode")
    TimeRadians: float = Field(..., description="Orbit time / position in radians from raw dataset")
    SequenceCount: int = Field(..., description="Packet sequence counter")
    MsgLength: int = Field(..., description="Packet message length in bytes")
    HasSecondaryHeader: int = Field(..., description="Flag indicating presence of secondary header (1/0)")
    MsgType: int = Field(..., description="Message type identifier")
    ApId: int = Field(..., description="Application Process Identifier (APID)")
    HeaderVersion: int = Field(..., description="CCSDS packet header version")
    SegmentationFlag: int = Field(..., description="Packet segmentation grouping flag")

    # --- Sliding Window Network & Flow Dynamics ---
    FlowLengthInWindow: float = Field(..., description="Flow duration length in the sliding window")
    SlidingWindowMeanIntervalSec: float = Field(..., description="Mean message arrival interval (sec)")
    SlidingWindowMaxIntervalSec: float = Field(..., description="Max message arrival interval (sec)")
    SlidingWindowMinIntervalSec: float = Field(..., description="Min message arrival interval (sec)")
    MessageCountInWindow: int = Field(..., description="Total count of messages in window")
    UniqueMessageIDsInWindow: int = Field(..., description="Count of unique message IDs in window")
    AverageMessageLengthInWindow: int = Field(..., description="Average message length in window")
    MessageRateInWindow: float = Field(..., description="Message transmission rate in window")
    StdDevMessageLengthInWindow: float = Field(..., description="Standard deviation of message length in window")

    # --- Error & Subsystem Diagnostic Counters ---
    CommandErrorCounter: int = Field(..., description="Counter of command execution errors")
    IngestErrors: int = Field(..., description="Counter of packet ingestion/parsing errors")

    # --- On-Board Computer (OBC) / Host Memory Metrics (MB) ---
    MemoryAnonMB: float = Field(..., description="Anonymous memory allocation (MB)")
    MemoryFileMB: float = Field(..., description="File-backed memory allocation (MB)")
    MemoryKernelstackMB: float = Field(..., description="Kernel stack memory (MB)")
    MemoryPageTableMB: float = Field(..., description="Page table memory (MB)")
    MemorySocketMB: float = Field(..., description="Socket buffer memory (MB)")
    MemoryPercpuMB: float = Field(..., description="Per-CPU memory allocation (MB)")
    MemoryShmemMB: float = Field(..., description="Shared memory allocation (MB)")
    MemorySlabUnreclaimableMB: float = Field(..., description="Unreclaimable SLAB memory (MB)")
    MemoryPageFaults: int = Field(..., description="Memory page fault counter")

    # --- Ground Truth Class Annotation ---
    Label: int = Field(..., description="Ground-truth dataset label (0-4)")


class TelemetryEvent(BaseModel):
    """
    Standardized Telemetry Event envelope emitted by the Simulator.
    
    Structure:
    {
        "event_id": "<SIMULATOR_GENERATED_UUID>",
        "timestamp": "<SIMULATOR_GENERATED_ISO8601_UTC>",
        "source": "SATELLITE_SIMULATOR",
        "satellite_id": "SAT-ORBITAL-01",
        "event_type": "TELEMETRY",
        "data": { ... 31 dataset fields ... }
    }
    """
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # Simulator-generated metadata fields
    event_id: str = Field(
        ...,
        description="Unique identifier for this telemetry event instance (Simulator-generated UUID)"
    )
    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of event creation/emission (Simulator-generated wall-clock)"
    )
    source: Literal["SATELLITE_SIMULATOR"] = Field(
        default="SATELLITE_SIMULATOR",
        description="Origin source identifier for the security telemetry bus"
    )
    satellite_id: str = Field(
        default="SAT-ORBITAL-01",
        description="Identifier of the simulated spacecraft (Simulator-configured)"
    )
    event_type: Literal["TELEMETRY"] = Field(
        default="TELEMETRY",
        description="Standardized event category for the ORBITAL_SHIELD platform"
    )

    # Telemetry data payload
    data: TelemetryData = Field(
        ...,
        description="Exact telemetry payload mapped from dataset record"
    )


class HealthResponse(BaseModel):
    """
    Response model for Simulator Health Check API endpoint.
    """
    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        default="healthy",
        description="Current health status of the satellite simulator service"
    )
    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of the health check"
    )
    simulator_state: str = Field(
        ...,
        description="Current operational state of the replay engine (STOPPED, RUNNING, PAUSED, COMPLETED)"
    )
    satellite_id: str = Field(
        ...,
        description="Active satellite identifier"
    )
    total_records: int = Field(
        ...,
        description="Total number of telemetry records in dataset"
    )
    current_index: int = Field(
        ...,
        description="Current record index position in replay sequence"
    )
    emitted_count: int = Field(
        ...,
        description="Total number of telemetry events emitted so far"
    )
