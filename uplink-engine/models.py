"""
Domain models for the Orbital Shield Uplink Command Security Engine.
Defines Pydantic v2 schemas for commands, telemetry, validation, security events, and RBAC policies.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
import uuid

from pydantic import BaseModel, Field, ConfigDict, field_validator


class CommandAction(str, Enum):
    """Policy action outcome for command validation."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HOLD = "HOLD"


class CommandSeverity(str, Enum):
    """Severity classification for audit trail & alerting."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class OperatorRole(str, Enum):
    """Ground segment operator roles."""
    PAYLOAD_OP = "PAYLOAD_OP"
    FLIGHT_DIRECTOR = "FLIGHT_DIRECTOR"
    ORBITAL_ENGINEER = "ORBITAL_ENGINEER"
    OBSERVER = "OBSERVER"


class CommandType(str, Enum):
    """Spacecraft telecommand types."""
    ADJUST_CAMERA = "ADJUST_CAMERA"
    CHANGE_ORBIT = "CHANGE_ORBIT"
    START_SENSOR = "START_SENSOR"
    STOP_SENSOR = "STOP_SENSOR"
    REBOOT = "REBOOT"


# ---------------------------------------------------------------------------
# Spacecraft Telemetry Models
# ---------------------------------------------------------------------------

class TelemetryState(BaseModel):
    """Current downlink telemetry state of a target spacecraft."""
    model_config = ConfigDict(extra="ignore")

    satellite_id: str = Field(description="Target spacecraft identifier, e.g. SAT-EO-01")
    operational_mode: str = Field(default="NOMINAL", description="Operational mode: NOMINAL, SAFE_MODE, ECLIPSE")
    battery_soc_pct: float = Field(default=88.5, ge=0.0, le=100.0, description="Battery State of Charge in %")
    solar_panels_deployed: bool = Field(default=True, description="Deployment confirmation flag")
    bus_voltage_v: float = Field(default=28.2, ge=0.0, description="Primary bus voltage (Volts)")
    primary_temp_c: float = Field(default=21.4, description="Central thermal node temperature (°C)")
    propellant_mass_kg: float = Field(default=15.0, ge=0.0, description="Remaining propellant (kg)")
    orbit_altitude_km: float = Field(default=520.0, ge=100.0, description="Semi-major axis altitude (km)")
    safe_mode_active: bool = Field(default=False, description="Emergency safe hold indicator")
    active_maneuver: bool = Field(default=False, description="Indicates ongoing delta-V execution")
    last_telemetry_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of last accepted downlink frame"
    )


# ---------------------------------------------------------------------------
# Command Payload Models
# ---------------------------------------------------------------------------

class UplinkCommand(BaseModel):
    """Inbound telecommand payload adhering to Orbital Shield contract."""
    model_config = ConfigDict(extra="ignore")

    command_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique telecommand UUID"
    )
    satellite_id: str = Field(description="Target spacecraft identifier, e.g. SAT-EO-01")
    operator_id: str = Field(description="Operator ID, e.g. OP-02")
    role: str = Field(description="Operator role: PAYLOAD_OP, FLIGHT_DIRECTOR, ORBITAL_ENGINEER, OBSERVER")
    command_type: str = Field(description="Command type: ADJUST_CAMERA, CHANGE_ORBIT, START_SENSOR, STOP_SENSOR, REBOOT")
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Command-specific parameter key-value payload"
    )
    sequence_number: int = Field(ge=0, description="Strictly incrementing sequence number")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Ground station generation timestamp"
    )
    session_token: Optional[str] = Field(
        default=None,
        description="Optional ground session authorization token / nonce"
    )

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Ensure all incoming timestamps are timezone-aware UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Policy & Bound Definitions
# ---------------------------------------------------------------------------

class ParameterBound(BaseModel):
    """Dynamic limits and typing for command payload parameters."""
    model_config = ConfigDict(extra="ignore")

    param_name: str
    data_type: str = Field(default="float", description="Expected type: 'float', 'int', 'bool', 'str', 'list'")
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    allowed_values: Optional[List[Any]] = None
    required: bool = True


class SecurityPolicy(BaseModel):
    """Active ground-station security policy defining RBAC matrix and bounds."""
    model_config = ConfigDict(extra="ignore")

    policy_id: str = "POL-ORBITAL-DEFAULT"
    version: str = "1.0.0"
    role_permissions: Dict[str, List[str]] = Field(default_factory=dict)
    parameter_bounds: Dict[str, List[ParameterBound]] = Field(default_factory=dict)
    max_timestamp_skew_seconds: int = Field(default=300, ge=10, description="Max allowed clock drift window (s)")
    minimum_battery_soc_for_maneuver: float = Field(default=25.0, ge=0.0, le=100.0)
    critical_thermal_threshold_c: float = Field(default=75.0)
    safe_mode_restricted_commands: List[str] = Field(default_factory=list)
    rate_limit_per_minute: int = Field(default=60, ge=1)


# ---------------------------------------------------------------------------
# Security Event Model (Orbital Shield Contract)
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    """Structured security telemetry event matching the Orbital Shield shared contract."""
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(
        default_factory=lambda: f"EVT-UPLINK-{uuid.uuid4().hex[:5].upper()}",
        description="Formatted event ID (format 'EVT-UPLINK-XXXXX')"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: Literal["UPLINK"] = "UPLINK"
    satellite_id: str = Field(description="Target spacecraft ID")
    event_type: str = Field(description="Event classification, e.g. REPLAY_ATTACK, RBAC_VIOLATION, VALIDATION_PASS")
    severity: CommandSeverity = Field(description="CommandSeverity classification")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Threat detection confidence (0.0 - 1.0)")
    description: str = Field(description="Human-readable event summary")
    action: CommandAction = Field(description="Action taken: ALLOW, BLOCK, HOLD")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic and contextual evidence")
    related_events: List[str] = Field(default_factory=list, description="Associated event IDs")


class CheckResult(BaseModel):
    """Granular output of an individual rule check in the engine."""
    check_name: str
    passed: bool
    details: str
    severity_if_failed: CommandSeverity = CommandSeverity.HIGH


class SignedUplinkFrame(BaseModel):
    """Cryptographically signed payload ready for ground transmitter transmission."""
    model_config = ConfigDict(extra="ignore")

    command: UplinkCommand
    hmac_signature: str
    signing_algorithm: str = "HMAC-SHA256"
    signed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    dispatch_token: str


class ValidationResponse(BaseModel):
    """Full evaluation response from the Uplink Command Security Engine."""
    model_config = ConfigDict(extra="ignore")

    action: CommandAction
    is_valid: bool
    command_id: str
    satellite_id: str
    checks: List[CheckResult]
    rejection_reasons: List[str] = Field(default_factory=list)
    signed_frame: Optional[SignedUplinkFrame] = None
    security_event: Optional[SecurityEvent] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CommandValidationRequest(BaseModel):
    """API payload for /commands/validate."""
    command: UplinkCommand
    telemetry_override: Optional[TelemetryState] = None


class CommandExecutionRequest(BaseModel):
    """API payload for /commands/execute."""
    command: UplinkCommand
    dry_run: bool = Field(default=False, description="If True, validates and signs without dispatching to downlink")
    telemetry_override: Optional[TelemetryState] = None


class CommandExecutionResponse(BaseModel):
    """Response returned after command validation and downlink dispatch."""
    model_config = ConfigDict(extra="ignore")

    execution_id: str = Field(default_factory=lambda: f"EXEC-{uuid.uuid4().hex[:8].upper()}")
    validation: ValidationResponse
    dispatched: bool
    downlink_ack: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    dispatched_at: Optional[datetime] = None
