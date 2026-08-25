"""Pydantic schemas for Telemetry ingestion and Analysis results."""

from datetime import datetime, timezone
from typing import Optional, List, Any, Dict, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict
from app.schemas.security_event import SecurityEvent


class TelemetryInput(BaseModel):
    """Input telemetry packet contract received from simulator or ground station."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "timestamp": "2026-08-25T02:14:30Z",
                "satellite_id": "SAT-EO-01",
                "sequence_number": 1001,
                "temperature": 24.5,
                "battery": 87.2,
                "signal_strength": -71.3,
                "latitude": 11.0168,
                "longitude": 76.9558,
                "packet_hash": None,
                "signature": None,
                "user_id": "operator_01",
                "source_ip": "10.0.0.15",
                "device_id": "GS-DEVICE-01",
                "session_id": "SESSION-001",
                "action": "DOWNLINK_RECEIVE",
                "role": "operator"
            }
        }
    )

    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of telemetry acquisition (e.g., 2026-08-25T02:14:30Z)",
        examples=["2026-08-25T02:14:30Z"]
    )
    satellite_id: str = Field(
        default="SAT-EO-01",
        description="Unique satellite identifier",
        examples=["SAT-EO-01"]
    )
    sequence_number: int = Field(
        ...,
        ge=0,
        description="Monotonically increasing sequence number for downlink packet tracking",
        examples=[1001]
    )
    temperature: float = Field(
        ...,
        description="Bus/payload thermal sensor measurement in degrees Celsius",
        examples=[24.5]
    )
    battery: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="State of Charge (SoC) percentage [0.0 - 100.0%]",
        examples=[87.2]
    )
    signal_strength: float = Field(
        ...,
        description="Received downlink RF signal power in dBm (e.g., -71.3 dBm)",
        examples=[-71.3]
    )
    latitude: Optional[float] = Field(
        default=None,
        ge=-90.0,
        le=90.0,
        description="Sub-satellite latitude in decimal degrees [-90.0 to 90.0]",
        examples=[11.0168]
    )
    longitude: Optional[float] = Field(
        default=None,
        ge=-180.0,
        le=180.0,
        description="Sub-satellite longitude in decimal degrees [-180.0 to 180.0]",
        examples=[76.9558]
    )
    packet_hash: Optional[str] = Field(
        default=None,
        description="Optional SHA-256 cryptographic checksum of canonical packet payload",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    )
    signature: Optional[str] = Field(
        default=None,
        description="Optional cryptographic digital signature token",
        examples=["MEYCIQ..."]
    )

    # Optional Ground Station Access / Operator Context (for Module 4 integration)
    user_id: Optional[str] = Field(default=None, description="Operator user ID (e.g. operator_01)")
    source_ip: Optional[str] = Field(default=None, description="Ground station receiver IP address")
    device_id: Optional[str] = Field(default=None, description="Receiver device/terminal ID")
    session_id: Optional[str] = Field(default=None, description="Active ground station session ID")
    action: Optional[str] = Field(default=None, description="Action performed")
    role: Optional[str] = Field(default=None, description="Operator role")

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_format(cls, v: str) -> str:
        """Validate that timestamp follows ISO-8601 format."""
        try:
            clean_ts = v.replace("Z", "+00:00")
            datetime.fromisoformat(clean_ts)
        except Exception as e:
            raise ValueError(f"Invalid timestamp format '{v}'. Expected ISO-8601 (e.g., '2026-08-25T02:14:30Z')") from e
        return v


class IntegrityResult(BaseModel):
    """Result of deterministic telemetry integrity checks."""

    sequence_valid: bool = Field(..., description="Whether packet sequence aligns with historical progression")
    timestamp_valid: bool = Field(..., description="Whether packet timestamp is valid, reasonable, and non-retrograde")
    hash_valid: bool = Field(..., description="Whether payload hash matches calculated SHA-256 (or True if omitted)")
    signature_status: str = Field(
        default="NOT_PROVIDED",
        description="Signature status: 'VALID', 'INVALID', 'NOT_PROVIDED', or 'UNVERIFIED'"
    )
    integrity_status: str = Field(
        ...,
        description="Aggregated integrity assessment: 'VALID', 'INVALID', or 'SUSPICIOUS'"
    )
    integrity_issues: List[str] = Field(
        default_factory=list,
        description="List of specific integrity failure explanations"
    )


class AnomalyResult(BaseModel):
    """Result of Isolation Forest behavioral anomaly detection."""

    is_anomaly: bool = Field(..., description="True if behavior deviates from baseline normal distribution")
    anomaly_score: float = Field(..., description="Raw decision score (negative values indicates anomaly)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Normalized anomaly confidence metric [0.0 - 1.0]")
    severity: str = Field(..., description="Behavioral severity level: 'NORMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")
    reason: str = Field(..., description="Human/machine-readable diagnostic explanation of detected anomaly")


class TelemetryVerificationEvent(BaseModel):
    """
    Standardized Downlink Verification Event tailored for Module 4 (Access Security) and Person 5 (ML Correlation).
    """

    timestamp: str = Field(..., description="ISO-8601 UTC timestamp")
    user_id: str = Field(default="operator_01", description="Ground station operator ID")
    source_ip: str = Field(default="10.0.0.15", description="Ground station source IP")
    device_id: str = Field(default="GS-DEVICE-01", description="Ground station device ID")
    action: str = Field(default="DOWNLINK_RECEIVE", description="Action performed")
    result: str = Field(default="SUCCESS", description="Operation result: SUCCESS / FAILED / ALERT")
    role: str = Field(default="operator", description="Operator role")
    previous_role: str = Field(default="operator", description="Previous operator role")
    satellite_id: str = Field(default="SAT-EO-01", description="Satellite platform ID")
    session_id: str = Field(default="SESSION-001", description="Active session ID")
    sequence_number: int = Field(..., description="Packet sequence number")

    # Direct Verification Booleans & Status required by Module 4
    spoof_detected: bool = Field(..., description="True if ML or heuristic detected behavioral spoofing/anomaly")
    integrity_verified: bool = Field(..., description="True if sequence, timestamp, and SHA-256 hash are 100% valid")
    verification_status: str = Field(
        ...,
        description="Consolidated verification status: 'VERIFIED', 'SPOOFED', 'TAMPERED', or 'ANOMALOUS'"
    )
    security_event_id: Optional[str] = Field(default=None, description="Associated SecurityEvent ID if generated")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Forensic metrics")


class TelemetryAnalysisResponse(BaseModel):
    """Standardized response payload from POST /downlink/analyze."""

    status: str = Field(default="PROCESSED", description="Processing execution status")
    telemetry: TelemetryInput = Field(..., description="Echoed input telemetry packet")
    integrity: IntegrityResult = Field(..., description="Deterministic integrity verification breakdown")
    anomaly: AnomalyResult = Field(..., description="Machine learning behavioral anomaly evaluation")
    security_event: Optional[SecurityEvent] = Field(
        default=None,
        description="Emitted SecurityEvent adhering to the project-wide shared schema (null if normal)"
    )
    verification_event: Optional[TelemetryVerificationEvent] = Field(
        default=None,
        description="Structured verification event for Module 4 (Access Security) and Module 5 (ML Correlation)"
    )
