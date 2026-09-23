"""
ORBITAL_SHIELD - Scenario Engine Models & Configurations

Defines the supported simulation scenario types and their configuration parameters.
All scenarios are deterministic when provided with a random seed.
"""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class ScenarioType(str, Enum):
    """
    Supported controlled scenario types.
    NORMAL is the baseline operational state.
    """
    NORMAL = "NORMAL"
    TELEMETRY_ANOMALY = "TELEMETRY_ANOMALY"
    MESSAGE_BURST = "MESSAGE_BURST"
    MESSAGE_REPLAY = "MESSAGE_REPLAY"


class BaseScenarioConfig(BaseModel):
    """Base configuration for simulation scenarios."""
    model_config = ConfigDict(extra="forbid")
    
    scenario_type: ScenarioType
    seed: Optional[int] = Field(
        default=None,
        description="Random seed for deterministic reproducibility"
    )
    duration_frames: Optional[int] = Field(
        default=None,
        description="Optional limit on number of frames this scenario remains active (None = indefinite until reset)"
    )


class NormalScenarioConfig(BaseScenarioConfig):
    """Configuration for baseline normal operation (pass-through)."""
    scenario_type: Literal[ScenarioType.NORMAL] = ScenarioType.NORMAL


class TelemetryAnomalyConfig(BaseScenarioConfig):
    """
    Configuration for controlled telemetry value perturbations.
    Introduces synthetic value deviations (e.g. memory spikes, page faults, interval anomalies).
    """
    scenario_type: Literal[ScenarioType.TELEMETRY_ANOMALY] = ScenarioType.TELEMETRY_ANOMALY
    memory_multiplier: float = Field(
        default=4.0,
        gt=1.0,
        description="Multiplier applied to memory allocation fields (MemoryAnonMB, MemoryFileMB)"
    )
    inject_page_faults: int = Field(
        default=128,
        ge=1,
        description="Number of synthetic memory page faults to inject"
    )
    corrupt_command_errors: int = Field(
        default=1,
        ge=0,
        description="Value to set on CommandErrorCounter"
    )


class MessageBurstConfig(BaseScenarioConfig):
    """
    Configuration for high-frequency message burst simulation.
    Elevates message rates and sliding window counts.
    """
    scenario_type: Literal[ScenarioType.MESSAGE_BURST] = ScenarioType.MESSAGE_BURST
    burst_multiplier: float = Field(
        default=10.0,
        gt=1.0,
        description="Multiplier for MessageRateInWindow and MessageCountInWindow"
    )
    compressed_interval_sec: float = Field(
        default=0.005,
        gt=0.0,
        description="Compressed mean/min message interval in seconds"
    )
    burst_count: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Number of duplicate rapid burst frames emitted per input frame"
    )


class MessageReplayConfig(BaseScenarioConfig):
    """
    Configuration for message sequence replay simulation.
    Captures recent frames and re-emits historical frames in a loop.
    """
    scenario_type: Literal[ScenarioType.MESSAGE_REPLAY] = ScenarioType.MESSAGE_REPLAY
    buffer_size: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Number of recent frames to store in the replay buffer"
    )
    replay_cycles: int = Field(
        default=3,
        ge=1,
        description="Number of times to replay the buffer before resuming new capture"
    )


class ScenarioStatus(BaseModel):
    """Status snapshot of the Scenario Engine."""
    model_config = ConfigDict(extra="forbid")

    active_scenario: ScenarioType
    is_active: bool
    frames_processed: int
    frames_modified: int
    config: Dict[str, Any]
