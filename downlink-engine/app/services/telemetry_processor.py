"""Telemetry Processing Service orchestrating integrity, ML analysis, and event generation."""

from typing import Optional, Tuple, Dict, Any, List
from sqlalchemy.orm import Session

from app.schemas.telemetry import (
    TelemetryInput,
    IntegrityResult,
    AnomalyResult,
    TelemetryAnalysisResponse,
    TelemetryVerificationEvent,
)
from app.schemas.security_event import SecurityEvent
from app.models.telemetry import TelemetryRecord
from app.db.repository import TelemetryRepository
from app.services.integrity_checker import IntegrityChecker
from app.services.feature_extractor import FeatureExtractor
from app.services.anomaly_detector import AnomalyDetector
from app.core.logging_config import get_logger

logger = get_logger("services.telemetry_processor")


class TelemetryProcessor:
    """
    Main orchestration engine that ingests raw telemetry, applies dual security verification
    (deterministic integrity + Isolation Forest ML), generates standardized SecurityEvents,
    synthesizes Access Verification Events for Module 4, and coordinates database persistence.
    """

    def __init__(
        self,
        db: Session,
        integrity_checker: Optional[IntegrityChecker] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
        anomaly_detector: Optional[AnomalyDetector] = None
    ):
        self.db = db
        self.repository = TelemetryRepository(db)
        self.integrity_checker = integrity_checker or IntegrityChecker()
        self.feature_extractor = feature_extractor or FeatureExtractor()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()

    def process_telemetry(self, telemetry: TelemetryInput) -> TelemetryAnalysisResponse:
        """
        Execute full end-to-end telemetry ingestion and security evaluation pipeline.
        """
        logger.info(f"Processing telemetry sat={telemetry.satellite_id} seq={telemetry.sequence_number}")

        # 1. Retrieve satellite history state for sequence & window analysis
        previous_record = self.repository.get_latest_telemetry(telemetry.satellite_id)
        history_window = self.repository.get_recent_telemetry_window(telemetry.satellite_id, limit=20)

        # 2. Deterministic Integrity Verification
        integrity_result = self.integrity_checker.verify(telemetry, previous_record)

        # 3. Behavioral Feature Extraction
        features = self.feature_extractor.extract_features(
            telemetry=telemetry,
            previous_record=previous_record,
            history_window=history_window
        )

        # 4. Machine Learning Behavioral Anomaly Detection
        anomaly_result = self.anomaly_detector.predict(features)

        # 5. Evaluate and Synthesize SecurityEvent if abnormal
        security_event = self._evaluate_and_generate_event(
            telemetry=telemetry,
            previous_record=previous_record,
            integrity=integrity_result,
            anomaly=anomaly_result,
            features=features
        )

        # 6. Synthesize TelemetryVerificationEvent for Module 4 (Access Security)
        verification_event = self._create_verification_event(
            telemetry=telemetry,
            integrity=integrity_result,
            anomaly=anomaly_result,
            security_event=security_event
        )

        # 7. Database Persistence
        self.repository.save_telemetry(telemetry, integrity_result, anomaly_result)
        if security_event:
            self.repository.save_security_event(security_event)

        return TelemetryAnalysisResponse(
            status="PROCESSED",
            telemetry=telemetry,
            integrity=integrity_result,
            anomaly=anomaly_result,
            security_event=security_event,
            verification_event=verification_event
        )

    def _create_verification_event(
        self,
        telemetry: TelemetryInput,
        integrity: IntegrityResult,
        anomaly: AnomalyResult,
        security_event: Optional[SecurityEvent]
    ) -> TelemetryVerificationEvent:
        """Construct a structured verification event matching Module 4's expected access format."""
        integrity_ok = (integrity.integrity_status == "VALID")
        spoof_detected = anomaly.is_anomaly

        if not integrity_ok:
            verification_status = "TAMPERED"
            result = "ALERT"
        elif spoof_detected:
            verification_status = "SPOOFED"
            result = "ALERT"
        else:
            verification_status = "VERIFIED"
            result = "SUCCESS"

        evidence = {
            "anomaly_score": anomaly.anomaly_score,
            "confidence": anomaly.confidence,
            "temperature": telemetry.temperature,
            "battery": telemetry.battery,
            "signal_strength": telemetry.signal_strength,
            "integrity_issues": integrity.integrity_issues,
            "reason": anomaly.reason
        }

        return TelemetryVerificationEvent(
            timestamp=telemetry.timestamp,
            user_id=telemetry.user_id or "operator_01",
            source_ip=telemetry.source_ip or "10.0.0.15",
            device_id=telemetry.device_id or "GS-DEVICE-01",
            action=telemetry.action or "DOWNLINK_RECEIVE",
            result=result,
            role=telemetry.role or "operator",
            previous_role=telemetry.role or "operator",
            satellite_id=telemetry.satellite_id,
            session_id=telemetry.session_id or "SESSION-001",
            sequence_number=telemetry.sequence_number,
            spoof_detected=spoof_detected,
            integrity_verified=integrity_ok,
            verification_status=verification_status,
            security_event_id=security_event.event_id if security_event else None,
            evidence=evidence
        )

    def _evaluate_and_generate_event(
        self,
        telemetry: TelemetryInput,
        previous_record: Optional[TelemetryRecord],
        integrity: IntegrityResult,
        anomaly: AnomalyResult,
        features: Dict[str, float]
    ) -> Optional[SecurityEvent]:
        """
        Evaluate dual-engine results to decide whether a SecurityEvent must be emitted.
        """
        has_integrity_failure = integrity.integrity_status == "INVALID"
        has_behavioral_anomaly = anomaly.is_anomaly

        if not has_integrity_failure and not has_behavioral_anomaly:
            # Everything nominal -> no security event emitted
            return None

        event_id = self.repository.get_next_event_id()
        expected_seq = (previous_record.sequence_number + 1) if previous_record else telemetry.sequence_number

        # Structured forensic evidence dictionary
        evidence: Dict[str, Any] = {
            "satellite_id": telemetry.satellite_id,
            "sequence_number": telemetry.sequence_number,
            "expected_sequence_number": expected_seq,
            "temperature": telemetry.temperature,
            "expected_temperature_range": list(self.anomaly_detector.BASELINE_LIMITS["temperature"]),
            "battery": telemetry.battery,
            "signal_strength": telemetry.signal_strength,
            "packet_frequency": features.get("packet_frequency", 10.0),
            "anomaly_score": anomaly.anomaly_score,
            "integrity_status": integrity.integrity_status,
            "integrity_issues": integrity.integrity_issues,
            "signature_status": integrity.signature_status
        }

        # Case 1: Integrity Failures (Deterministic Security Violations)
        if has_integrity_failure:
            has_hash_fail = not integrity.hash_valid
            has_seq_fail = not integrity.sequence_valid
            has_time_fail = not integrity.timestamp_valid

            if has_hash_fail and has_seq_fail:
                event_type = "TELEMETRY_INTEGRITY_FAILURE"
                severity = "CRITICAL"
                action = "ALERT"
                description = (
                    f"Critical telemetry integrity failure: Packet hash mismatch and sequence violation "
                    f"(seq {telemetry.sequence_number}, expected {expected_seq})."
                )
                confidence = 0.98
            elif has_hash_fail:
                event_type = "PACKET_HASH_MISMATCH"
                severity = "HIGH"
                action = "ALERT"
                description = f"Cryptographic integrity failure: SHA-256 payload checksum mismatch for sequence {telemetry.sequence_number}."
                confidence = 0.99
            elif has_seq_fail:
                if previous_record and telemetry.sequence_number == previous_record.sequence_number:
                    event_type = "TELEMETRY_REPLAY"
                    severity = "HIGH"
                    action = "REVIEW"
                    description = f"Telemetry replay detected: Duplicate sequence number {telemetry.sequence_number}."
                    confidence = 0.95
                else:
                    event_type = "SEQUENCE_ANOMALY"
                    severity = "HIGH"
                    action = "REVIEW"
                    description = f"Telemetry sequence anomaly: Received {telemetry.sequence_number} (expected {expected_seq})."
                    confidence = 0.95
            elif has_time_fail:
                event_type = "TIMESTAMP_ANOMALY"
                severity = "MEDIUM"
                action = "REVIEW"
                description = f"Telemetry timestamp violation: {'; '.join(integrity.integrity_issues)}"
                confidence = 0.90
            else:
                event_type = "TELEMETRY_INTEGRITY_FAILURE"
                severity = "HIGH"
                action = "REVIEW"
                description = f"Telemetry integrity issues: {'; '.join(integrity.integrity_issues)}"
                confidence = 0.85

            if has_behavioral_anomaly and severity != "CRITICAL":
                severity = "CRITICAL"
                action = "ALERT"
                description += f" Compound behavioral deviation: {anomaly.reason}"

        # Case 2: Pure Behavioral Anomaly (ML Detection with intact integrity)
        else:
            if telemetry.temperature > 65.0 or telemetry.signal_strength < -110.0:
                event_type = "TELEMETRY_SPOOFING"
                severity = "HIGH"
                action = "REVIEW"
                description = f"Telemetry spoofing suspected: {anomaly.reason}"
                confidence = anomaly.confidence
            else:
                event_type = "TELEMETRY_ANOMALY"
                severity = anomaly.severity if anomaly.severity != "NORMAL" else "LOW"
                action = "REVIEW"
                description = f"Behavioral telemetry anomaly detected: {anomaly.reason}"
                confidence = anomaly.confidence

        return SecurityEvent(
            event_id=event_id,
            timestamp=telemetry.timestamp,
            source="DOWNLINK",
            satellite_id=telemetry.satellite_id,
            event_type=event_type,
            severity=severity,
            confidence=confidence,
            description=description,
            action=action,
            evidence=evidence,
            related_events=[]
        )
