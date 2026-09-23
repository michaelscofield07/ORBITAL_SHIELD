"""
Core security rule engine for the Uplink Command Security Engine.
Enforces Role-Based Access Control (RBAC), parameter boundary checks,
sequence/replay defense, telemetry state preconditions, and HMAC-SHA256 command signing.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import logging
from typing import Any, Dict, List, Optional, Union
import uuid

from models import (
    CheckResult,
    CommandAction,
    CommandSeverity,
    CommandType,
    OperatorRole,
    ParameterBound,
    SecurityEvent,
    SecurityPolicy,
    SignedUplinkFrame,
    TelemetryState,
    UplinkCommand,
    ValidationResponse,
)

logger = logging.getLogger("uplink_security_engine")


class UplinkSecurityEngine:
    """Production-grade spacecraft telecommand verification and signing engine."""

    def __init__(
        self,
        master_secret_key: Optional[Union[bytes, str]] = None,
        policy: Optional[SecurityPolicy] = None
    ) -> None:
        if isinstance(master_secret_key, str):
            self._secret_key: bytes = master_secret_key.encode("utf-8")
        elif isinstance(master_secret_key, bytes):
            self._secret_key = master_secret_key
        else:
            self._secret_key = b"ORBITAL_SHIELD_TOP_SECRET_UPLINK_KEY_2026"

        # State tracking stores per satellite
        self.last_sequence_numbers: Dict[str, int] = {}
        self._highest_sequence: Dict[str, int] = self.last_sequence_numbers
        self._seen_tokens: Dict[str, datetime] = {}
        self._security_events: List[SecurityEvent] = []
        self._telemetry_cache: Dict[str, TelemetryState] = {}
        self._eclipse_mode: Dict[str, bool] = {}

        # Initialize default security policy
        self.policy: SecurityPolicy = policy or self._build_default_policy()

    @classmethod
    def _build_default_policy(cls) -> SecurityPolicy:
        """Constructs default defense policy with standard bounds and RBAC mapping."""
        role_permissions: Dict[str, List[str]] = {
            OperatorRole.PAYLOAD_OP.value: [
                CommandType.ADJUST_CAMERA.value,
                CommandType.START_SENSOR.value,
                CommandType.STOP_SENSOR.value,
            ],
            OperatorRole.FLIGHT_DIRECTOR.value: [
                CommandType.ADJUST_CAMERA.value,
                CommandType.START_SENSOR.value,
                CommandType.STOP_SENSOR.value,
                CommandType.CHANGE_ORBIT.value,
                CommandType.REBOOT.value,
            ],
            OperatorRole.ORBITAL_ENGINEER.value: [
                CommandType.CHANGE_ORBIT.value,
                CommandType.REBOOT.value,
            ],
            OperatorRole.OBSERVER.value: [],
        }

        parameter_bounds: Dict[str, List[ParameterBound]] = {
            CommandType.CHANGE_ORBIT.value: [
                ParameterBound(param_name="delta_v", data_type="float", min_value=0.1, max_value=50.0, required=False),
                ParameterBound(param_name="delta_v_ms", data_type="float", min_value=0.01, max_value=50.0, required=False),
                ParameterBound(param_name="thruster_duration", data_type="float", min_value=1.0, max_value=120.0, required=False),
                ParameterBound(param_name="burn_duration_seconds", data_type="float", min_value=0.1, max_value=300.0, required=False),
                ParameterBound(param_name="target_altitude_km", data_type="float", min_value=200.0, max_value=2000.0, required=False),
            ],
            CommandType.ADJUST_CAMERA.value: [
                ParameterBound(param_name="angle", data_type="float", min_value=-90.0, max_value=90.0, required=False),
                ParameterBound(param_name="target_angle_deg", data_type="float", min_value=-90.0, max_value=90.0, required=False),
                ParameterBound(param_name="zoom", data_type="float", min_value=1.0, max_value=10.0, required=False),
                ParameterBound(param_name="zoom_level", data_type="float", min_value=1.0, max_value=50.0, required=False),
                ParameterBound(param_name="exposure_ms", data_type="int", min_value=1, max_value=5000, required=False),
                ParameterBound(param_name="resolution", data_type="str", allowed_values=["4K", "1080P", "720P", "RAW"], required=False),
            ],
            CommandType.START_SENSOR.value: [
                ParameterBound(param_name="sensor_id", data_type="str", allowed_values=["OPTICAL_CAM", "SAR_RADAR", "INFRARED", "MAGNETOMETER", "SPECTROMETER"], required=False),
                ParameterBound(param_name="sampling_rate_hz", data_type="float", min_value=0.1, max_value=100.0, required=False),
            ],
            CommandType.STOP_SENSOR.value: [
                ParameterBound(param_name="sensor_id", data_type="str", allowed_values=["OPTICAL_CAM", "SAR_RADAR", "INFRARED", "MAGNETOMETER", "SPECTROMETER"], required=False),
            ],
            CommandType.REBOOT.value: [
                ParameterBound(param_name="subsystem", data_type="str", allowed_values=["OBC", "PAYLOAD_BUS", "COMMS", "ALL"], required=False),
                ParameterBound(param_name="force", data_type="bool", required=False),
            ],
        }

        safe_mode_restricted = [
            CommandType.CHANGE_ORBIT.value,
            CommandType.START_SENSOR.value,
            CommandType.REBOOT.value,
        ]

        return SecurityPolicy(
            policy_id="POL-ORBITAL-DEFAULT",
            version="1.0.0",
            role_permissions=role_permissions,
            parameter_bounds=parameter_bounds,
            max_timestamp_skew_seconds=300,
            minimum_battery_soc_for_maneuver=25.0,
            critical_thermal_threshold_c=75.0,
            safe_mode_restricted_commands=safe_mode_restricted,
            rate_limit_per_minute=60,
        )

    # -----------------------------------------------------------------------
    # Verification Pipeline Steps
    # -----------------------------------------------------------------------

    def verify_command_type(self, command: UplinkCommand) -> CheckResult:
        """Verifies if the incoming command type is recognized by the spacecraft command catalog."""
        known_commands = set(self.policy.parameter_bounds.keys()) | {c.value for c in CommandType}
        for cmds in self.policy.role_permissions.values():
            known_commands.update(cmds)

        if command.command_type in known_commands:
            return CheckResult(
                check_name="COMMAND_TYPE_VALIDATION",
                passed=True,
                details=f"Command '{command.command_type}' is recognized in spacecraft catalog."
            )
        return CheckResult(
            check_name="UNKNOWN_COMMAND",
            passed=False,
            details=f"Unknown command '{command.command_type}' is not recognized in spacecraft catalog.",
            severity_if_failed=CommandSeverity.HIGH
        )

    def verify_rbac(self, command: UplinkCommand) -> CheckResult:
        """Verifies if the declared operator role has authority to issue the target telecommand."""
        allowed_commands = self.policy.role_permissions.get(command.role, [])
        if command.command_type in allowed_commands:
            return CheckResult(
                check_name="RBAC_AUTHORIZATION",
                passed=True,
                details=f"Role '{command.role}' is authorized for '{command.command_type}'."
            )
        return CheckResult(
            check_name="RBAC_AUTHORIZATION",
            passed=False,
            details=f"Privilege Violation: Role '{command.role}' lacks clearance for command '{command.command_type}'.",
            severity_if_failed=CommandSeverity.CRITICAL if command.command_type in [
                CommandType.CHANGE_ORBIT.value, CommandType.REBOOT.value, "CHANGE_ORBIT", "REBOOT"
            ] else CommandSeverity.HIGH
        )

    def verify_sequence_and_freshness(self, command: UplinkCommand) -> List[CheckResult]:
        """
        Guards against replay attacks, old frames, and clock skew anomalies.
        Ensures monotonic sequence numbering (> last sequence number) and single-use session tokens / nonces.
        """
        results: List[CheckResult] = []
        now = datetime.now(timezone.utc)

        # 1. Timestamp freshness & drift check
        time_skew = abs((now - command.timestamp).total_seconds())
        if time_skew <= self.policy.max_timestamp_skew_seconds:
            results.append(CheckResult(
                check_name="TIMESTAMP_FRESHNESS",
                passed=True,
                details=f"Timestamp skew ({time_skew:.2f}s) is within allowable limit ({self.policy.max_timestamp_skew_seconds}s)."
            ))
        else:
            results.append(CheckResult(
                check_name="TIMESTAMP_FRESHNESS",
                passed=False,
                details=f"Timestamp Drift Rejection: Skew of {time_skew:.2f}s exceeds allowable threshold of {self.policy.max_timestamp_skew_seconds}s.",
                severity_if_failed=CommandSeverity.HIGH
            ))

        # 2. Session token / nonce replay defense check
        self._prune_expired_tokens(now)
        token_to_check = command.session_token or f"SEQ-{command.sequence_number}-{command.timestamp.isoformat()}"
        if token_to_check in self._seen_tokens:
            results.append(CheckResult(
                check_name="TOKEN_UNIQUENESS",
                passed=False,
                details=f"Replay Attack Detected: Token '{token_to_check}' has already been processed.",
                severity_if_failed=CommandSeverity.CRITICAL
            ))
        else:
            results.append(CheckResult(
                check_name="TOKEN_UNIQUENESS",
                passed=True,
                details=f"Token '{token_to_check[:16]}...' is unique."
            ))

        # 3. Monotonic sequence counter check: strictly > last_sequence_number
        last_seq = self.last_sequence_numbers.get(command.satellite_id, 0)
        if command.sequence_number > last_seq:
            results.append(CheckResult(
                check_name="SEQUENCE_MONOTONICITY",
                passed=True,
                details=f"Sequence number {command.sequence_number} is valid (prior: {last_seq})."
            ))
        else:
            results.append(CheckResult(
                check_name="SEQUENCE_MONOTONICITY",
                passed=False,
                details=f"Sequence Counter Violation: Command sequence {command.sequence_number} <= previous highest sequence {last_seq}.",
                severity_if_failed=CommandSeverity.CRITICAL
            ))

        return results

    def verify_parameter_bounds(self, command: UplinkCommand) -> List[CheckResult]:
        """
        Validates parameter whitelist, data types, min/max numerical bounds,
        and allowed enum values.
        """
        results: List[CheckResult] = []
        bounds = self.policy.parameter_bounds.get(command.command_type, [])
        params = command.parameters or {}

        # 1. Allowed parameter names whitelist for this command type
        allowed_param_names = {b.param_name for b in bounds}

        all_params_valid = True
        violation_messages: List[str] = []

        # Check for unwhitelisted parameter keys if bounds are registered
        if bounds:
            for param_key in params.keys():
                if param_key not in allowed_param_names:
                    all_params_valid = False
                    violation_messages.append(
                        f"Parameter '{param_key}' is not in allowed parameter whitelist for {command.command_type}."
                    )

        # 2. Check required parameters
        if command.command_type in [CommandType.CHANGE_ORBIT.value, "CHANGE_ORBIT"]:
            has_delta_v = "delta_v" in params or "delta_v_ms" in params
            if not has_delta_v:
                all_params_valid = False
                violation_messages.append("Missing required parameter 'delta_v_ms'.")

        for bound in bounds:
            if bound.required and bound.param_name not in params:
                if bound.param_name in ["delta_v", "delta_v_ms"] and ("delta_v" in params or "delta_v_ms" in params):
                    pass
                elif bound.param_name in ["thruster_duration", "burn_duration_seconds"] and ("thruster_duration" in params or "burn_duration_seconds" in params):
                    pass
                else:
                    all_params_valid = False
                    violation_messages.append(f"Missing required parameter '{bound.param_name}'.")
                    continue

            if bound.param_name not in params:
                continue

            val = params[bound.param_name]

            # Type verification
            if not self._check_type(val, bound.data_type):
                all_params_valid = False
                violation_messages.append(
                    f"Parameter '{bound.param_name}' type mismatch: expected {bound.data_type}, got {type(val).__name__}."
                )
                continue

            # Numerical range checks
            if bound.data_type in ["float", "int"] and isinstance(val, (int, float)):
                if bound.min_value is not None and val < bound.min_value:
                    all_params_valid = False
                    violation_messages.append(
                        f"Parameter '{bound.param_name}' value {val} < minimum allowed {bound.min_value}."
                    )
                if bound.max_value is not None and val > bound.max_value:
                    all_params_valid = False
                    violation_messages.append(
                        f"Parameter '{bound.param_name}' value {val} > maximum allowed {bound.max_value}."
                    )

            # Allowed value set checks
            if bound.allowed_values is not None and val not in bound.allowed_values:
                all_params_valid = False
                violation_messages.append(
                    f"Parameter '{bound.param_name}' value '{val}' not in allowed set {bound.allowed_values}."
                )

        if all_params_valid:
            results.append(CheckResult(
                check_name="PARAMETER_BOUNDS",
                passed=True,
                details=f"All {len(params)} parameters passed bound and type validation."
            ))
        else:
            results.append(CheckResult(
                check_name="PARAMETER_BOUNDS",
                passed=False,
                details="; ".join(violation_messages),
                severity_if_failed=CommandSeverity.HIGH
            ))

        return results

    def verify_telemetry_preconditions(
        self,
        command: UplinkCommand,
        telemetry: Optional[TelemetryState] = None
    ) -> List[CheckResult]:
        """Evaluates spacecraft health metrics and mission state before permitting safety-critical commands."""
        results: List[CheckResult] = []
        
        state = telemetry or self._telemetry_cache.get(
            command.satellite_id,
            TelemetryState(satellite_id=command.satellite_id)
        )

        # 1. Eclipse Mode restrictions: blocks CHANGE_ORBIT and REBOOT
        is_eclipse = self._eclipse_mode.get(command.satellite_id, False) or state.operational_mode == "ECLIPSE"
        if is_eclipse:
            if command.command_type in [CommandType.CHANGE_ORBIT.value, CommandType.REBOOT.value, "CHANGE_ORBIT", "REBOOT"]:
                results.append(CheckResult(
                    check_name="ECLIPSE_MODE_PRECONDITION",
                    passed=False,
                    details=f"Command '{command.command_type}' is prohibited while spacecraft '{command.satellite_id}' is in ECLIPSE mode.",
                    severity_if_failed=CommandSeverity.CRITICAL
                ))
            else:
                results.append(CheckResult(
                    check_name="ECLIPSE_MODE_PRECONDITION",
                    passed=True,
                    details="Command permitted under ECLIPSE mode."
                ))
        else:
            results.append(CheckResult(
                check_name="ECLIPSE_MODE_PRECONDITION",
                passed=True,
                details="Spacecraft is not in ECLIPSE mode."
            ))

        # 2. Safe Mode restrictions
        if state.safe_mode_active or state.operational_mode == "SAFE_MODE":
            if command.command_type in self.policy.safe_mode_restricted_commands:
                results.append(CheckResult(
                    check_name="SAFE_MODE_STATE_PRECONDITION",
                    passed=False,
                    details=f"Command '{command.command_type}' is prohibited while spacecraft '{command.satellite_id}' is in SAFE_MODE.",
                    severity_if_failed=CommandSeverity.CRITICAL
                ))
            else:
                results.append(CheckResult(
                    check_name="SAFE_MODE_STATE_PRECONDITION",
                    passed=True,
                    details="Command permitted under SAFE_MODE policy."
                ))
        else:
            results.append(CheckResult(
                check_name="SAFE_MODE_STATE_PRECONDITION",
                passed=True,
                details="Spacecraft is in nominal operational mode."
            ))

        # 3. Orbital Maneuver Battery Check
        if command.command_type in [CommandType.CHANGE_ORBIT.value, "CHANGE_ORBIT"]:
            if state.battery_soc_pct < self.policy.minimum_battery_soc_for_maneuver:
                results.append(CheckResult(
                    check_name="MANEUVER_POWER_PRECONDITION",
                    passed=False,
                    details=f"Insufficient Power: Battery SOC is {state.battery_soc_pct:.1f}%, required >= {self.policy.minimum_battery_soc_for_maneuver}%.",
                    severity_if_failed=CommandSeverity.HIGH
                ))
            else:
                results.append(CheckResult(
                    check_name="MANEUVER_POWER_PRECONDITION",
                    passed=True,
                    details=f"Power check passed (Battery SOC {state.battery_soc_pct:.1f}% >= {self.policy.minimum_battery_soc_for_maneuver}%)."
                ))

            if state.active_maneuver:
                results.append(CheckResult(
                    check_name="CONCURRENT_MANEUVER_PRECONDITION",
                    passed=False,
                    details="Spacecraft already has an active maneuver in progress.",
                    severity_if_failed=CommandSeverity.HIGH
                ))

        # 4. Thermal threshold check
        if state.primary_temp_c >= self.policy.critical_thermal_threshold_c:
            high_thermal_commands = [
                CommandType.START_SENSOR.value,
                CommandType.CHANGE_ORBIT.value,
                "START_SENSOR",
                "CHANGE_ORBIT",
            ]
            if command.command_type in high_thermal_commands:
                results.append(CheckResult(
                    check_name="THERMAL_SAFETY_PRECONDITION",
                    passed=False,
                    details=f"Thermal Safety Violation: Primary temperature ({state.primary_temp_c}°C) exceeds safety limit ({self.policy.critical_thermal_threshold_c}°C).",
                    severity_if_failed=CommandSeverity.CRITICAL
                ))
            else:
                results.append(CheckResult(
                    check_name="THERMAL_SAFETY_PRECONDITION",
                    passed=True,
                    details="Thermal threshold warning ignored for low-thermal command."
                ))

        return results

    # -----------------------------------------------------------------------
    # Cryptographic Signing (HMAC-SHA256)
    # -----------------------------------------------------------------------

    def sign_command(self, command: UplinkCommand) -> SignedUplinkFrame:
        """
        Signs the canonical payload using HMAC-SHA256 with the secret key.
        Returns a tamper-evident SignedUplinkFrame with expiration token.
        """
        canonical_bytes = self._canonicalize_command(command)
        hmac_sig = hmac.new(self._secret_key, canonical_bytes, hashlib.sha256).hexdigest()
        
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.policy.max_timestamp_skew_seconds)
        dispatch_token = f"OPR-{command.command_id[:8]}-{hmac_sig[:16]}-{int(expires_at.timestamp())}"

        return SignedUplinkFrame(
            command=command,
            hmac_signature=hmac_sig,
            signing_algorithm="HMAC-SHA256",
            signed_at=now,
            expires_at=expires_at,
            dispatch_token=dispatch_token,
        )

    def verify_hmac_signature(self, command: UplinkCommand, signature: str) -> bool:
        """Verifies if an existing HMAC-SHA256 signature matches the command payload."""
        canonical_bytes = self._canonicalize_command(command)
        expected_sig = hmac.new(self._secret_key, canonical_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, signature)

    def _canonicalize_command(self, command: UplinkCommand) -> bytes:
        """
        Generates deterministic byte payload matching the format:
        {command_id}:{satellite_id}:{sequence_number}:{command_type}:{sorted_params_json}
        """
        sorted_params_json = json.dumps(command.parameters or {}, sort_keys=True, separators=(",", ":"))
        payload_str = f"{command.command_id}:{command.satellite_id}:{command.sequence_number}:{command.command_type}:{sorted_params_json}"
        return payload_str.encode("utf-8")

    # -----------------------------------------------------------------------
    # Orchestration & Pipeline Execution
    # -----------------------------------------------------------------------

    def validate(
        self,
        command: UplinkCommand,
        telemetry: Optional[TelemetryState] = None
    ) -> ValidationResponse:
        """
        Executes complete verification pipeline:
        0. Unknown Command Check
        1. RBAC Check
        2. Sequence & Freshness Check
        3. Parameter Bounds Check
        4. Telemetry Precondition Check
        """
        checks: List[CheckResult] = []

        # 0. Command Type Validation
        cmd_type_res = self.verify_command_type(command)
        checks.append(cmd_type_res)

        # 1. RBAC Verification
        rbac_res = self.verify_rbac(command)
        checks.append(rbac_res)

        # 2. Sequence, Replay & Freshness Verification
        seq_res = self.verify_sequence_and_freshness(command)
        checks.extend(seq_res)

        # 3. Parameter Bounds Verification
        param_res = self.verify_parameter_bounds(command)
        checks.extend(param_res)

        # 4. Telemetry Precondition Verification
        telemetry_res = self.verify_telemetry_preconditions(command, telemetry)
        checks.extend(telemetry_res)

        # Evaluate overall outcome
        failed_checks = [c for c in checks if not c.passed]
        is_valid = len(failed_checks) == 0
        rejection_reasons = [f"[{c.check_name}] {c.details}" for c in failed_checks]

        action = CommandAction.ALLOW if is_valid else CommandAction.BLOCK
        signed_frame: Optional[SignedUplinkFrame] = None
        security_event: Optional[SecurityEvent] = None

        token_used = command.session_token or f"SEQ-{command.sequence_number}-{command.timestamp.isoformat()}"

        if is_valid:
            # Update state counters
            self.last_sequence_numbers[command.satellite_id] = command.sequence_number
            self._seen_tokens[token_used] = datetime.now(timezone.utc)
            
            # Sign command
            signed_frame = self.sign_command(command)
            
            # Create SecurityEvent adhering to Orbital Shield contract
            security_event = SecurityEvent(
                event_id=f"EVT-UPLINK-{uuid.uuid4().hex[:5].upper()}",
                timestamp=datetime.now(timezone.utc),
                source="UPLINK",
                satellite_id=command.satellite_id,
                event_type="COMMAND_VALIDATED",
                severity=CommandSeverity.LOW,
                confidence=1.0,
                description=f"Command '{command.command_type}' authorized and validated successfully for {command.satellite_id}.",
                action=CommandAction.ALLOW,
                evidence={
                    "command_id": command.command_id,
                    "operator_id": command.operator_id,
                    "role": command.role,
                    "sequence_number": command.sequence_number,
                    "dispatch_token": signed_frame.dispatch_token,
                },
                related_events=[]
            )
        else:
            highest_sev = max(
                (c.severity_if_failed for c in failed_checks),
                key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[s.value]
            )
            event_type = self._classify_event_type(failed_checks)
            confidence = 1.0 if event_type in ["REPLAY_ATTACK_DETECTED", "UNAUTHORIZED_COMMAND", "UNAUTHORIZED_ROLE", "UNKNOWN_COMMAND"] else 0.9

            security_event = SecurityEvent(
                event_id=f"EVT-UPLINK-{uuid.uuid4().hex[:5].upper()}",
                timestamp=datetime.now(timezone.utc),
                source="UPLINK",
                satellite_id=command.satellite_id,
                event_type=event_type,
                severity=highest_sev,
                confidence=confidence,
                description=f"Command '{command.command_type}' blocked: {'; '.join(rejection_reasons)}",
                action=CommandAction.BLOCK,
                evidence={
                    "command_id": command.command_id,
                    "operator_id": command.operator_id,
                    "role": command.role,
                    "sequence_number": command.sequence_number,
                    "failed_checks": [c.check_name for c in failed_checks],
                    "rejection_reasons": rejection_reasons,
                },
                related_events=[]
            )

        # Append to audit history
        self._security_events.append(security_event)

        return ValidationResponse(
            action=action,
            is_valid=is_valid,
            command_id=command.command_id,
            satellite_id=command.satellite_id,
            checks=checks,
            rejection_reasons=rejection_reasons,
            signed_frame=signed_frame,
            security_event=security_event,
        )

    # -----------------------------------------------------------------------
    # State Management & Helpers
    # -----------------------------------------------------------------------

    def set_eclipse_mode(self, satellite_id: str, active: bool) -> None:
        """Sets or clears eclipse mode for a satellite, blocking CHANGE_ORBIT and REBOOT."""
        self._eclipse_mode[satellite_id] = active
        if satellite_id in self._telemetry_cache:
            self._telemetry_cache[satellite_id].operational_mode = "ECLIPSE" if active else "NOMINAL"

    def set_telemetry_state(self, state: TelemetryState) -> None:
        """Stores or updates the cached telemetry state for a satellite."""
        self._telemetry_cache[state.satellite_id] = state

    def get_telemetry_state(self, satellite_id: str) -> TelemetryState:
        """Retrieves cached telemetry state or returns a nominal state."""
        return self._telemetry_cache.get(satellite_id, TelemetryState(satellite_id=satellite_id))

    def update_policy(self, new_policy: SecurityPolicy, operator_id: str = "SYSTEM_ADMIN") -> None:
        """Replaces active security policy and logs security event."""
        self.policy = new_policy
        event = SecurityEvent(
            event_id=f"EVT-UPLINK-{uuid.uuid4().hex[:5].upper()}",
            timestamp=datetime.now(timezone.utc),
            source="UPLINK",
            satellite_id="ALL",
            event_type="POLICY_UPDATED",
            severity=CommandSeverity.LOW,
            confidence=1.0,
            description=f"Security policy updated to version {new_policy.version} ({new_policy.policy_id}) by {operator_id}.",
            action=CommandAction.ALLOW,
            evidence={"policy_id": new_policy.policy_id, "version": new_policy.version, "operator_id": operator_id},
            related_events=[]
        )
        self._security_events.append(event)

    def get_security_events(
        self,
        satellite_id: Optional[str] = None,
        severity: Optional[CommandSeverity] = None,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[SecurityEvent]:
        """Queries security audit trail with optional filtering."""
        filtered = self._security_events
        if satellite_id:
            filtered = [e for e in filtered if e.satellite_id == satellite_id or e.satellite_id == "ALL"]
        if severity:
            filtered = [e for e in filtered if e.severity == severity]
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        
        return list(reversed(filtered))[:limit]

    def _prune_expired_tokens(self, now: datetime) -> None:
        """Prunes cached tokens older than 2x the allowable time skew."""
        cutoff = now - timedelta(seconds=self.policy.max_timestamp_skew_seconds * 2)
        self._seen_tokens = {n: t for n, t in self._seen_tokens.items() if t > cutoff}

    @staticmethod
    def _check_type(val: Any, expected: str) -> bool:
        """Validates primitive and complex data types."""
        if expected == "float":
            return isinstance(val, (int, float)) and not isinstance(val, bool)
        elif expected == "int":
            return isinstance(val, int) and not isinstance(val, bool)
        elif expected == "bool":
            return isinstance(val, bool)
        elif expected == "str":
            return isinstance(val, str)
        elif expected == "list":
            return isinstance(val, list)
        return True

    @staticmethod
    def _classify_event_type(failed_checks: List[CheckResult]) -> str:
        """Identifies primary security event classification based on failures."""
        check_names = {c.check_name for c in failed_checks}
        if "UNKNOWN_COMMAND" in check_names:
            return "UNKNOWN_COMMAND"
        if "TOKEN_UNIQUENESS" in check_names or "SEQUENCE_MONOTONICITY" in check_names:
            return "REPLAY_ATTACK_DETECTED"
        if "RBAC_AUTHORIZATION" in check_names:
            return "UNAUTHORIZED_COMMAND"
        if "TIMESTAMP_FRESHNESS" in check_names:
            return "TIMESTAMP_DRIFT"
        if "PARAMETER_BOUNDS" in check_names:
            return "INVALID_PARAMETERS"
        if any("PRECONDITION" in name for name in check_names):
            return "TELEMETRY_STATE_CONFLICT"
        return "MALFORMED_COMMAND"
