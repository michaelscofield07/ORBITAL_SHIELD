"""
ORBITAL SHIELD — Firmware Event Generator
Transforms verification outcomes into structured JSON security events matching:
1. Module 3 Specification (exact format requested).
2. ML Correlation Brain `IncomingEvent` contract (for upstream ingestion on port 8005).
"""

from __future__ import annotations
from datetime import datetime, timezone
import uuid
from typing import Optional, Dict, Any

from .cosign_verifier import VerificationOutcome
try:
    from models.schemas import (
        FirmwareSecurityEvent,
        MLBrainIncomingEvent,
        VerificationStatus,
        SeverityLevel,
    )
except ImportError:
    from ..models.schemas import (
        FirmwareSecurityEvent,
        MLBrainIncomingEvent,
        VerificationStatus,
        SeverityLevel,
    )



class EventGenerator:
    """
    Constructs normalized, structured security events from verification outcomes.
    """

    @staticmethod
    def generate_security_event(outcome: VerificationOutcome) -> FirmwareSecurityEvent:
        """
        Creates the canonical Module 3 security event.
        Strictly conforms to required SUCCESS and FAILURE schemas.
        """
        is_verified = outcome.status == VerificationStatus.VERIFIED
        
        event = FirmwareSecurityEvent(
            module="firmware_verification",
            firmware_name=outcome.firmware_name,
            firmware_version=outcome.firmware_version,
            verification_status=outcome.status,
            verification_method=outcome.verification_method,
            severity=SeverityLevel.INFO if is_verified else SeverityLevel.HIGH,
            reason=outcome.reason if not is_verified else None,
            timestamp=datetime.now(timezone.utc).isoformat(),
            details={
                "sha256": outcome.sha256_hash,
                "firmware_path": outcome.firmware_path,
                **outcome.details
            }
        )
        return event

    @staticmethod
    def generate_ml_brain_event(
        outcome: VerificationOutcome,
        satellite_id: str = "SAT-COM-01",
        subsystem: str = "OBC",
        operator_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> MLBrainIncomingEvent:
        """
        Creates an `IncomingEvent` compliant with ML Brain (Port 8005) schema.
        When verification fails, it raises a CRITICAL `FIRMWARE_TAMPERING` event.
        """
        is_verified = outcome.status == VerificationStatus.VERIFIED

        if is_verified:
            event_type = "FIRMWARE_VERIFIED"
            severity = "LOW"
            action = "LOG"
            description = (
                f"Firmware '{outcome.firmware_name}' (v{outcome.firmware_version}) "
                f"successfully verified via Cosign on {satellite_id} ({subsystem})."
            )
        else:
            event_type = "FIRMWARE_TAMPERING"
            severity = "CRITICAL"
            action = "REVIEW"
            description = (
                f"Firmware signature verification FAILED for '{outcome.firmware_name}' "
                f"on {satellite_id} ({subsystem}). Reason: {outcome.reason or 'Signature mismatch'}."
            )

        evidence: Dict[str, Any] = {
            "firmware_name": outcome.firmware_name,
            "firmware_version": outcome.firmware_version,
            "subsystem": subsystem,
            "verification_method": outcome.verification_method,
            "verification_status": outcome.status.value,
            "sha256": outcome.sha256_hash or "UNKNOWN",
            "reason": outcome.reason,
            "details": outcome.details
        }

        return MLBrainIncomingEvent(
            event_id=f"EVT-FW-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            source="FIRMWARE",
            satellite_id=satellite_id,
            event_type=event_type,
            severity=severity,
            confidence=0.99,
            description=description,
            action=action,
            evidence=evidence,
            related_events=[],
            operator_id=operator_id,
            session_id=session_id
        )
