"""
ORBITAL SHIELD — Firmware Verification Module (Module 3)
Pydantic Schemas for Firmware Verification, Security Events, and Integration Bridges.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
import uuid


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED   = "FAILED"
    ERROR    = "ERROR"


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


class FirmwareVerificationRequest(BaseModel):
    """
    Request model for verifying a firmware artifact.
    """
    firmware_path: str = Field(..., description="Path to the firmware binary (.bin)")
    signature_path: Optional[str] = Field(None, description="Path to the signature file (.sig). If omitted, defaults to <firmware_path>.sig")
    public_key_path: Optional[str] = Field(None, description="Path to the trusted public key (.pub). If omitted, defaults to configured trusted key")
    
    firmware_name: Optional[str] = Field(None, description="Display name of firmware (e.g. firmware_v1.bin)")
    firmware_version: Optional[str] = Field("1.0", description="Firmware version identifier")
    satellite_id: Optional[str] = Field("SAT-COM-01", description="Target satellite identifier")
    subsystem: Optional[str] = Field("OBC", description="Target subsystem (e.g. OBC, ADCS, COMMS)")
    operator_id: Optional[str] = Field(None, description="Operator identifier if initiated by an operator session")
    session_id: Optional[str] = Field(None, description="Session identifier")


class FirmwareSecurityEvent(BaseModel):
    """
    Standard Module 3 security event format.
    Matches the user's required SUCCESS and FAILURE specifications.
    """
    module: str = Field("firmware_verification", description="Module identifier")
    firmware_name: str = Field(..., description="Name of the firmware artifact verified")
    firmware_version: str = Field("1.0", description="Version of the firmware")
    verification_status: VerificationStatus = Field(..., description="VERIFIED or FAILED")
    verification_method: str = Field("cosign", description="Cryptographic verification method")
    severity: SeverityLevel = Field(..., description="Assessed severity (INFO for valid, HIGH/CRITICAL for failed)")
    reason: Optional[str] = Field(None, description="Failure reason description if verification failed")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp"
    )
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional verification telemetry and hashes")


class MLBrainIncomingEvent(BaseModel):
    """
    Schema strictly compatible with the ML Correlation Brain (Person 5 / port 8005)
    POST /events/ingest contract.
    """
    event_id: str = Field(default_factory=lambda: f"EVT-FW-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = Field("FIRMWARE", description="Fixed source identifier for ML Brain")
    satellite_id: str = Field("SAT-COM-01", description="Satellite ID")
    event_type: str = Field("FIRMWARE_TAMPERING", description="Machine-readable event classification")
    severity: str = Field("CRITICAL", description="Severity level for ML Brain")
    confidence: float = Field(0.99, ge=0.0, le=1.0, description="Cryptographic confidence level")
    description: str = Field(..., description="Human-readable event summary")
    action: str = Field("REVIEW", description="Action recommendation (REVIEW / ALERT / LOG)")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting cryptographic evidence")
    related_events: List[str] = Field(default_factory=list, description="Linked event IDs")
    operator_id: Optional[str] = Field(None, description="Associated operator ID")
    session_id: Optional[str] = Field(None, description="Associated session ID")


class VerificationSummary(BaseModel):
    """
    Response returned by verification endpoints.
    """
    security_event: FirmwareSecurityEvent
    ml_brain_event: Optional[MLBrainIncomingEvent] = None
    ml_brain_forwarded: bool = False
    ml_brain_response: Optional[Dict[str, Any]] = None
