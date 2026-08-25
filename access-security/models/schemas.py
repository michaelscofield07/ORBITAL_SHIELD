"""
ORBITAL SHIELD — Access Security Module
Pydantic Schemas for Access Log Records, Security Detection Results, and Common Security Events.

Compliant with ML Correlation Brain (Person 5 / port 8005) and Audit Layer (Person 6).
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import uuid


class SeverityLevel(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(str, Enum):
    LOG          = "LOG"
    MONITOR      = "MONITOR"
    REVIEW       = "REVIEW"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    ALERT        = "ALERT"


class SourceModule(str, Enum):
    ACCESS = "ACCESS"


class AccessLogRecord(BaseModel):
    """
    Normalized data model for an incoming access or operator telemetry event.
    This schema serves as the internal contract for the Access Security Engine.
    """
    record_id: Optional[str] = Field(
        default_factory=lambda: f"REC-{uuid.uuid4().hex[:8].upper()}",
        description="Unique log record ID"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of access attempt"
    )
    user_id: str = Field(..., description="Operator or account user identifier")
    source_ip: str = Field(..., description="IP address of access request origin")
    device_id: str = Field(..., description="Hardware or workstation device identifier")
    action: str = Field("LOGIN", description="Action performed (e.g. LOGIN, EXECUTE_COMMAND, ROLE_CHANGE)")
    result: str = Field("SUCCESS", description="Outcome of action (SUCCESS, FAILURE)")
    role: str = Field("operator", description="Role associated with request")
    previous_role: Optional[str] = Field(None, description="Previous role before elevation if applicable")
    resource: Optional[str] = Field(None, description="Target resource or command path accessed")
    ground_station_id: Optional[str] = Field("GS-MAIN-01", description="Ground station identifier")
    satellite_id: Optional[str] = Field("SAT-EO-01", description="Associated satellite identifier")
    session_id: Optional[str] = Field(None, description="Active session ID if attributable")

    @field_validator("user_id", "source_ip", "device_id")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty or blank")
        return v.strip()


class DetectionResult(BaseModel):
    """
    Intermediate detection evaluation result produced by the Access Security Engine.
    """
    is_suspicious: bool = Field(..., description="True if anomaly or threat detected")
    event_type: str = Field(..., description="Anomaly classification e.g. BRUTE_FORCE, UNKNOWN_DEVICE")
    severity: SeverityLevel = Field(..., description="Assessed severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Rule confidence rating (0.0 to 1.0)")
    description: str = Field(..., description="Human-readable explanation of detection")
    action: ActionType = Field(..., description="Recommended mitigation action")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting telemetry evidence")
    user_id: str = Field(..., description="User involved")
    source_ip: str = Field(..., description="Originating IP")
    device_id: str = Field(..., description="Originating Device ID")
    satellite_id: str = Field("SAT-EO-01", description="Target satellite ID")
    session_id: Optional[str] = Field(None, description="Associated session ID")


class SecurityEvent(BaseModel):
    """
    Canonical Common Security Event format.
    Matches Person 5's ML Correlation Brain `IncomingEvent` contract and Person 6's Audit layer.
    """
    event_id: str = Field(
        default_factory=lambda: f"EVT-ACCESS-{uuid.uuid4().hex[:8].upper()}",
        description="Canonical security event identifier"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp"
    )
    source: str = Field("ACCESS", description="Source security module label")
    satellite_id: str = Field("SAT-EO-01", description="Target satellite identifier")
    event_type: str = Field(..., description="Machine-readable security event type")
    severity: str = Field(..., description="Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence rating between 0.0 and 1.0")
    description: str = Field(..., description="Summary explanation of the event")
    action: str = Field("REVIEW", description="Recommended action (LOG, MONITOR, REVIEW, HUMAN_REVIEW, ALERT)")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Detailed supporting evidence dictionary")
    related_events: List[str] = Field(default_factory=list, description="IDs of related events")
    operator_id: Optional[str] = Field(None, description="Attributable user/operator ID")
    session_id: Optional[str] = Field(None, description="Attributable session ID")


class AccessAnalysisRequest(BaseModel):
    """
    API payload for submitting access log records for security analysis.
    """
    records: List[AccessLogRecord] = Field(..., description="List of access log records to analyze")
    satellite_id: Optional[str] = Field("SAT-EO-01", description="Target satellite context override")


class AccessAnalysisResponse(BaseModel):
    """
    API response returning security evaluation results.
    """
    analyzed_count: int = Field(..., description="Total number of records processed")
    suspicious_count: int = Field(..., description="Number of suspicious events detected")
    events: List[SecurityEvent] = Field(..., description="Generated SecurityEvent objects")
    ml_brain_forwarded: bool = Field(False, description="Whether events were successfully pushed to ML Brain")
    ml_brain_response: Optional[Dict[str, Any]] = Field(None, description="Response or error telemetry from ML Brain")
