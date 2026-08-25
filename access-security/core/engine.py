"""
ORBITAL SHIELD — Access Security Module (Module 4)
Access Security Engine (Rule-based Detection Engine).

Processes normalized AccessLogRecords and evaluates them against 6 prototype security rules:
1. Normal successful login
2. Repeated failed logins (Brute force)
3. Suspicious login time (Off-hours access)
4. Unknown / new device login
5. Privilege escalation
6. Suspicious access to sensitive commands/resources
"""

from __future__ import annotations
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
import logging

try:
    from models.schemas import (
        AccessLogRecord,
        DetectionResult,
        SeverityLevel,
        ActionType,
    )
except ImportError:
    from ..models.schemas import (
        AccessLogRecord,
        DetectionResult,
        SeverityLevel,
        ActionType,
    )

logger = logging.getLogger("AccessSecurity.Engine")


class AccessSecurityEngine:
    """
    Rule-based Detection Engine for Ground Station / Operator Access Security.
    Designed for clarity, explainability, and fast execution without deep learning overhead.
    """

    DEFAULT_TRUSTED_DEVICES: Set[str] = {
        "GS-DEVICE-01",
        "GS-DEVICE-02",
        "GS-MOBILE-SECURE-01",
        "GS-CONTROL-WORKSTATION-01",
        "OPERATOR-CONSOLE-ALPHA",
    }

    DEFAULT_SENSITIVE_ACTIONS: Set[str] = {
        "PAYLOAD_SHUTDOWN",
        "PURGE_LOGS",
        "ORBIT_DEVIATION",
        "KEY_EXPORT",
        "OVERRIDE_AUTH",
        "EMERGENCY_REBOOT",
    }

    DEFAULT_SENSITIVE_RESOURCES: Set[str] = {
        "PAYLOAD_CONTROL",
        "CRYPTO_KEY_VAULT",
        "TELEMETRY_PURGE_SERVICE",
        "ORBITAL_PROPULSION_BUS",
    }

    def __init__(
        self,
        trusted_devices: Optional[Set[str]] = None,
        sensitive_actions: Optional[Set[str]] = None,
        sensitive_resources: Optional[Set[str]] = None,
        failed_attempts_threshold: int = 3,
        normal_operating_hours: Tuple[int, int] = (6, 21),  # 06:00 UTC to 21:00 UTC
    ):
        self.trusted_devices = trusted_devices or set(self.DEFAULT_TRUSTED_DEVICES)
        self.sensitive_actions = sensitive_actions or set(self.DEFAULT_SENSITIVE_ACTIONS)
        self.sensitive_resources = sensitive_resources or set(self.DEFAULT_SENSITIVE_RESOURCES)
        self.failed_attempts_threshold = failed_attempts_threshold
        self.operating_hours_start, self.operating_hours_end = normal_operating_hours

        # Internal stateful tracking for failed attempts
        self._user_failures: Dict[str, int] = {}
        self._ip_failures: Dict[str, int] = {}

    def reset_state(self) -> None:
        """Reset internal failure counters."""
        self._user_failures.clear()
        self._ip_failures.clear()

    def evaluate_batch(self, records: List[AccessLogRecord]) -> List[DetectionResult]:
        """
        Processes a sequential list of AccessLogRecord items and returns detection results for all records.
        """
        results: List[DetectionResult] = []
        for record in records:
            res = self.evaluate_record(record)
            results.append(res)
        return results

    def evaluate_record(self, record: AccessLogRecord) -> DetectionResult:
        """
        Evaluates a single access log record against all rule detectors in priority order.
        Priority:
        1. Privilege Escalation (CRITICAL)
        2. Suspicious Command / Sensitive Resource Access (CRITICAL / HIGH)
        3. Repeated Failed Logins / Brute Force (HIGH)
        4. Unknown / Untrusted Device (MEDIUM)
        5. Suspicious Login Time (MEDIUM)
        6. Normal Successful Login (INFO)
        """
        # Parse timestamp UTC hour
        dt_hour = self._extract_utc_hour(record.timestamp)
        is_failure = record.result.upper() in ("FAILURE", "FAILED", "DENIED")

        # Track failure counts if record is a login failure
        if is_failure and record.action.upper() in ("LOGIN", "AUTHENTICATE"):
            self._user_failures[record.user_id] = self._user_failures.get(record.user_id, 0) + 1
            self._ip_failures[record.source_ip] = self._ip_failures.get(record.source_ip, 0) + 1
        elif not is_failure and record.action.upper() in ("LOGIN", "AUTHENTICATE"):
            # On successful login, reset failure counters for that user
            self._user_failures[record.user_id] = 0

        # RULE 1: Privilege Escalation
        if self._is_privilege_escalation(record):
            return DetectionResult(
                is_suspicious=True,
                event_type="PRIVILEGE_ESCALATION",
                severity=SeverityLevel.CRITICAL,
                confidence=0.95,
                description=(
                    f"Privilege escalation detected for user '{record.user_id}': "
                    f"role changed from '{record.previous_role}' to '{record.role}'."
                ),
                action=ActionType.HUMAN_REVIEW,
                evidence={
                    "user_id": record.user_id,
                    "previous_role": record.previous_role,
                    "new_role": record.role,
                    "source_ip": record.source_ip,
                    "device_id": record.device_id,
                },
                user_id=record.user_id,
                source_ip=record.source_ip,
                device_id=record.device_id,
                satellite_id=record.satellite_id or "SAT-EO-01",
                session_id=record.session_id,
            )

        # RULE 2: Suspicious Access to Sensitive Commands / Resources
        if self._is_sensitive_access(record):
            return DetectionResult(
                is_suspicious=True,
                event_type="UNAUTHORIZED_COMMAND",
                severity=SeverityLevel.CRITICAL if record.role.lower() != "admin" else SeverityLevel.HIGH,
                confidence=0.92,
                description=(
                    f"Suspicious access attempt to sensitive command/resource "
                    f"'{record.resource or record.action}' by user '{record.user_id}' ({record.role})."
                ),
                action=ActionType.ALERT,
                evidence={
                    "user_id": record.user_id,
                    "action": record.action,
                    "resource": record.resource,
                    "role": record.role,
                    "source_ip": record.source_ip,
                    "device_id": record.device_id,
                },
                user_id=record.user_id,
                source_ip=record.source_ip,
                device_id=record.device_id,
                satellite_id=record.satellite_id or "SAT-EO-01",
                session_id=record.session_id,
            )

        # RULE 3: Repeated Failed Logins (Brute Force)
        user_fails = self._user_failures.get(record.user_id, 0)
        ip_fails = self._ip_failures.get(record.source_ip, 0)
        if is_failure and (user_fails >= self.failed_attempts_threshold or ip_fails >= self.failed_attempts_threshold):
            highest_fail_count = max(user_fails, ip_fails)
            severity = SeverityLevel.CRITICAL if highest_fail_count >= 5 else SeverityLevel.HIGH
            return DetectionResult(
                is_suspicious=True,
                event_type="BRUTE_FORCE",
                severity=severity,
                confidence=min(0.99, 0.85 + (highest_fail_count * 0.03)),
                description=(
                    f"Repeated failed login attempts ({highest_fail_count}) detected "
                    f"for user '{record.user_id}' from IP '{record.source_ip}'."
                ),
                action=ActionType.REVIEW,
                evidence={
                    "user_id": record.user_id,
                    "source_ip": record.source_ip,
                    "failed_attempts": highest_fail_count,
                    "user_failed_count": user_fails,
                    "ip_failed_count": ip_fails,
                    "device_id": record.device_id,
                },
                user_id=record.user_id,
                source_ip=record.source_ip,
                device_id=record.device_id,
                satellite_id=record.satellite_id or "SAT-EO-01",
                session_id=record.session_id,
            )

        # RULE 4: Unknown / New Device
        if record.device_id not in self.trusted_devices:
            return DetectionResult(
                is_suspicious=True,
                event_type="UNKNOWN_DEVICE",
                severity=SeverityLevel.MEDIUM if not is_failure else SeverityLevel.HIGH,
                confidence=0.85,
                description=(
                    f"Access attempt originating from untrusted/unknown device '{record.device_id}' "
                    f"by user '{record.user_id}'."
                ),
                action=ActionType.REVIEW,
                evidence={
                    "user_id": record.user_id,
                    "device_id": record.device_id,
                    "source_ip": record.source_ip,
                    "known_devices": list(self.trusted_devices)[:3] + ["..."],
                },
                user_id=record.user_id,
                source_ip=record.source_ip,
                device_id=record.device_id,
                satellite_id=record.satellite_id or "SAT-EO-01",
                session_id=record.session_id,
            )

        # RULE 5: Suspicious Login Time (Off-hours access)
        if dt_hour is not None and (dt_hour < self.operating_hours_start or dt_hour >= self.operating_hours_end):
            return DetectionResult(
                is_suspicious=True,
                event_type="SUSPICIOUS_LOGIN_TIME",
                severity=SeverityLevel.MEDIUM,
                confidence=0.75,
                description=(
                    f"Access attempt by user '{record.user_id}' during off-operating hours "
                    f"({dt_hour:02d}:00 UTC, normal window {self.operating_hours_start:02d}:00-{self.operating_hours_end:02d}:00 UTC)."
                ),
                action=ActionType.MONITOR,
                evidence={
                    "user_id": record.user_id,
                    "access_hour_utc": dt_hour,
                    "normal_window": f"{self.operating_hours_start:02d}:00-{self.operating_hours_end:02d}:00 UTC",
                    "source_ip": record.source_ip,
                },
                user_id=record.user_id,
                source_ip=record.source_ip,
                device_id=record.device_id,
                satellite_id=record.satellite_id or "SAT-EO-01",
                session_id=record.session_id,
            )

        # RULE 6: Normal Successful Login / Operation
        if not is_failure:
            return DetectionResult(
                is_suspicious=False,
                event_type="AUTHENTICATION_SUCCESS",
                severity=SeverityLevel.INFO,
                confidence=0.95,
                description=f"Normal successful access by user '{record.user_id}' from trusted device '{record.device_id}'.",
                action=ActionType.LOG,
                evidence={
                    "user_id": record.user_id,
                    "device_id": record.device_id,
                    "source_ip": record.source_ip,
                    "status": "ALLOWED",
                },
                user_id=record.user_id,
                source_ip=record.source_ip,
                device_id=record.device_id,
                satellite_id=record.satellite_id or "SAT-EO-01",
                session_id=record.session_id,
            )
        else:
            # Single isolated failed login (below threshold)
            return DetectionResult(
                is_suspicious=False,
                event_type="AUTHENTICATION_FAILURE",
                severity=SeverityLevel.LOW,
                confidence=0.90,
                description=f"Single login failure recorded for user '{record.user_id}' (attempt {user_fails}/{self.failed_attempts_threshold}).",
                action=ActionType.LOG,
                evidence={
                    "user_id": record.user_id,
                    "failed_attempts": user_fails,
                    "threshold": self.failed_attempts_threshold,
                    "source_ip": record.source_ip,
                },
                user_id=record.user_id,
                source_ip=record.source_ip,
                device_id=record.device_id,
                satellite_id=record.satellite_id or "SAT-EO-01",
                session_id=record.session_id,
            )

    # ─────────────────────────────────────────────────────────────
    # INTERNAL HELPER METHODS
    # ─────────────────────────────────────────────────────────────

    def _is_privilege_escalation(self, record: AccessLogRecord) -> bool:
        """Check if role transition or action signifies privilege escalation."""
        if record.previous_role and record.previous_role.lower() != record.role.lower():
            # Check if new role has higher privileges
            privileged_roles = {"admin", "sysadmin", "superadmin", "root"}
            if record.role.lower() in privileged_roles:
                return True
        if record.action.upper() in ("ROLE_ELEVATION", "PRIVILEGE_ESCALATION", "GRANT_ADMIN"):
            return True
        return False

    def _is_sensitive_access(self, record: AccessLogRecord) -> bool:
        """Check if action or resource accessed is flagged as sensitive or restricted."""
        act_upper = record.action.upper()
        res_upper = (record.resource or "").upper()
        
        if act_upper in self.sensitive_actions or res_upper in self.sensitive_resources:
            return True
        
        # If user is not admin but accessing restricted command
        if record.role.lower() not in ("admin", "sysadmin") and ("PAYLOAD" in res_upper or "SHUTDOWN" in act_upper):
            return True

        return False

    @staticmethod
    def _extract_utc_hour(timestamp_str: str) -> Optional[int]:
        """Safely extract integer UTC hour from an ISO 8601 timestamp string."""
        try:
            # Replace 'Z' with '+00:00' for datetime.fromisoformat compatibility
            ts = timestamp_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            return dt.hour
        except Exception:
            return None
