"""Deterministic Telemetry Integrity Verification Service."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from app.schemas.telemetry import TelemetryInput, IntegrityResult
from app.models.telemetry import TelemetryRecord
from app.utils.hashing import verify_telemetry_hash, compute_telemetry_hash
from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger("services.integrity_checker")


class IntegrityChecker:
    """
    Performs deterministic cryptographic, sequence, and temporal integrity verification
    on incoming satellite telemetry packets.
    """

    def __init__(
        self,
        timestamp_tolerance_seconds: float = settings.TIMESTAMP_TOLERANCE_SECONDS,
        max_age_seconds: float = settings.TIMESTAMP_MAX_AGE_SECONDS
    ):
        self.timestamp_tolerance = timestamp_tolerance_seconds
        self.max_age_seconds = max_age_seconds

    def verify(
        self,
        telemetry: TelemetryInput,
        previous_record: Optional[TelemetryRecord] = None
    ) -> IntegrityResult:
        """
        Execute full integrity validation suite against telemetry packet.
        """
        issues: List[str] = []

        # 1. Sequence Validation
        seq_valid, seq_issues = self._validate_sequence(telemetry, previous_record)
        issues.extend(seq_issues)

        # 2. Timestamp Validation
        time_valid, time_issues = self._validate_timestamp(telemetry, previous_record)
        issues.extend(time_issues)

        # 3. Hash Validation
        hash_valid, hash_issues = self._validate_hash(telemetry)
        issues.extend(hash_issues)

        # 4. Signature Handling
        signature_status = self._check_signature(telemetry)

        # Aggregated Integrity Status
        if not seq_valid or not time_valid or not hash_valid:
            integrity_status = "INVALID"
        elif len(issues) > 0:
            integrity_status = "SUSPICIOUS"
        else:
            integrity_status = "VALID"

        logger.debug(
            f"Integrity check for sat={telemetry.satellite_id} seq={telemetry.sequence_number}: "
            f"status={integrity_status}, issues={issues}"
        )

        return IntegrityResult(
            sequence_valid=seq_valid,
            timestamp_valid=time_valid,
            hash_valid=hash_valid,
            signature_status=signature_status,
            integrity_status=integrity_status,
            integrity_issues=issues
        )

    def _validate_sequence(
        self,
        telemetry: TelemetryInput,
        previous_record: Optional[TelemetryRecord]
    ) -> Tuple[bool, List[str]]:
        """Validate sequence number progression against prior satellite state."""
        if previous_record is None:
            # First packet received for this satellite session
            return True, []

        prev_seq = previous_record.sequence_number
        curr_seq = telemetry.sequence_number

        if curr_seq == prev_seq:
            return False, [f"Duplicate sequence number detected: {curr_seq} (possible telemetry replay)"]
        
        if curr_seq < prev_seq:
            return False, [f"Out-of-order sequence received: {curr_seq} arrived after {prev_seq}"]

        if curr_seq > prev_seq + 1:
            diff = curr_seq - prev_seq
            return False, [f"Unexpected sequence jump detected: expected {prev_seq + 1}, received {curr_seq} (gap of {diff - 1} packets)"]

        return True, []

    def _validate_timestamp(
        self,
        telemetry: TelemetryInput,
        previous_record: Optional[TelemetryRecord]
    ) -> Tuple[bool, List[str]]:
        """Validate timestamp format, future tolerance, expiration, and monotonicity."""
        issues: List[str] = []
        try:
            # Parse timestamp into UTC
            ts_str = telemetry.timestamp.replace("Z", "+00:00")
            packet_dt = datetime.fromisoformat(ts_str)
            if packet_dt.tzinfo is None:
                packet_dt = packet_dt.replace(tzinfo=timezone.utc)
        except Exception as e:
            return False, [f"Unparseable timestamp format: {e}"]

        now_utc = datetime.now(timezone.utc)
        time_diff = (packet_dt - now_utc).total_seconds()

        # Check for future timestamps beyond allowable drift
        if time_diff > self.timestamp_tolerance:
            issues.append(f"Future timestamp detected: packet is {time_diff:.1f}s ahead of ground station clock (tolerance: {self.timestamp_tolerance}s)")

        # Check for excessively old packets (unless baseline playback)
        age = (now_utc - packet_dt).total_seconds()
        if age > self.max_age_seconds:
            # Informative notice for old historical replays
            issues.append(f"Excessively stale packet: timestamp is {age / 3600:.1f} hours old")

        # Check for non-decreasing time progression relative to previous packet
        if previous_record is not None:
            try:
                prev_ts_str = previous_record.timestamp.replace("Z", "+00:00")
                prev_dt = datetime.fromisoformat(prev_ts_str)
                if prev_dt.tzinfo is None:
                    prev_dt = prev_dt.replace(tzinfo=timezone.utc)

                if packet_dt < prev_dt:
                    issues.append(f"Retrograde timestamp anomaly: {telemetry.timestamp} is earlier than previous packet {previous_record.timestamp}")
            except Exception:
                pass

        is_valid = len(issues) == 0
        return is_valid, issues

    def _validate_hash(self, telemetry: TelemetryInput) -> Tuple[bool, List[str]]:
        """Validate cryptographic SHA-256 payload checksum if provided."""
        if not telemetry.packet_hash:
            # Hash not provided - treated as valid structurally, but noted in status
            return True, []

        computed_hash = compute_telemetry_hash(telemetry)
        if telemetry.packet_hash.strip().lower() != computed_hash.lower():
            return False, [
                f"Packet hash mismatch: received '{telemetry.packet_hash}', computed '{computed_hash}'"
            ]

        return True, []

    def _check_signature(self, telemetry: TelemetryInput) -> str:
        """Evaluate digital signature presence without fake verification."""
        if not telemetry.signature:
            return "NOT_PROVIDED"
        # Pluggable placeholder for ECDSA/RSA asymmetric signature verification
        return "UNVERIFIED"
