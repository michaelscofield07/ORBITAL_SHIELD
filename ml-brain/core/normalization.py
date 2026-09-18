"""
ORBITAL SHIELD — ML Correlation Brain
Core Data Cleaning & Event Normalization Engine

Normalizes security events from:
  1. Module 1: DOWNLINK (telemetry anomalies, signal spoofing)
  2. Module 2: UPLINK (unauthorized commands, command injection, replay)
  3. Module 3: FIRMWARE (firmware update integrity, unauthorized modification)
  4. Module 4: ACCESS (logins, privilege changes, resource/data access)
  5. CISO Notes (human observations, corrections, manual classifications)
  6. CERT-In Log Summaries (advisories, audit summaries, threat context)

Ensures every event conforms to the Common Event Model while preserving
the pristine original payload in `raw_log` for complete forensic traceability.
"""

import copy
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Union

from models.schemas import IncomingEvent, SourceModule, SeverityLevel, ActionType, AuthorizationStatus

logger = logging.getLogger("orbital.normalization")

# Module alias mapping table
_SOURCE_ALIASES = {
    "DOWNLINK": SourceModule.DOWNLINK,
    "DOWNLINK_MOD": SourceModule.DOWNLINK,
    "DOWNLINK_MODULE": SourceModule.DOWNLINK,
    "TELEMETRY": SourceModule.DOWNLINK,
    "SATELLITE_SIMULATOR": SourceModule.DOWNLINK,

    "UPLINK": SourceModule.UPLINK,
    "UPLINK_MOD": SourceModule.UPLINK,
    "UPLINK_MODULE": SourceModule.UPLINK,
    "COMMAND": SourceModule.UPLINK,
    "COMMANDS": SourceModule.UPLINK,
    "GROUND_STATION_COMMAND": SourceModule.UPLINK,

    "FIRMWARE": SourceModule.FIRMWARE,
    "FIRMWARE_MOD": SourceModule.FIRMWARE,
    "FIRMWARE_MODULE": SourceModule.FIRMWARE,

    "ACCESS": SourceModule.ACCESS,
    "ACCESS_MOD": SourceModule.ACCESS,
    "AUTH": SourceModule.ACCESS,
    "AUTHENTICATION": SourceModule.ACCESS,
    "GROUND_STATION_SIMULATOR": SourceModule.ACCESS,

    "CISO_NOTES": SourceModule.CISO_NOTES,
    "CISO_NOTE": SourceModule.CISO_NOTES,
    "CISO": SourceModule.CISO_NOTES,

    "CERT_IN": SourceModule.CERT_IN,
    "CERTIN": SourceModule.CERT_IN,
    "CERT_IN_SUMMARY": SourceModule.CERT_IN,

    "ML_BRAIN": SourceModule.ML_BRAIN,
}

# Known unauthorized or suspicious event types
_UNAUTHORIZED_EVENT_TYPES = {
    "UNAUTHORIZED_COMMAND",
    "ACCESS_VIOLATION",
    "FIRMWARE_TAMPERING",
    "COMMAND_INJECTION",
    "PRIVILEGE_ESCALATION",
    "UNAUTHORIZED_DATA_ACCESS",
    "DATA_EXFILTRATION",
    "INTEGRITY_FAILURE",
}

_SUSPICIOUS_EVENT_TYPES = {
    "SUSPICIOUS_LOGIN",
    "FAILED_LOGIN",
    "NEW_DEVICE",
    "REPLAY_ATTACK",
    "TELEMETRY_ANOMALY",
    "SIGNAL_INTERFERENCE",
}


def normalize_timestamp(ts: Union[str, datetime, int, float, None]) -> str:
    """Normalizes any incoming timestamp format into standard ISO-8601 UTC string."""
    if ts is None:
        return datetime.now(timezone.utc).isoformat()

    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    ts_str = str(ts).strip()
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()

    try:
        # Handle 'Z' suffix and variable sub-second precision
        clean_ts = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        logger.warning("Could not parse timestamp '%s', defaulting to current UTC time", ts)
        return datetime.now(timezone.utc).isoformat()


def normalize_source_module(source_raw: Any) -> SourceModule:
    """Resolves arbitrary source names or casing into the canonical SourceModule enum."""
    if isinstance(source_raw, SourceModule):
        return source_raw

    key = str(source_raw).strip().upper()
    if key in _SOURCE_ALIASES:
        return _SOURCE_ALIASES[key]

    # Fallback to general lookup
    for valid_source in SourceModule:
        if valid_source.value == key:
            return valid_source

    logger.warning("Unknown source '%s', defaulting to ML_BRAIN", source_raw)
    return SourceModule.ML_BRAIN


def determine_authorization_context(event_dict: dict) -> Tuple[str, str]:
    """
    Evaluates whether the event indicates Authorized, Unauthorized, Suspicious,
    or Verified/Rectified activity, and provides an explicit explanation.

    Returns:
        (authorization_status, rationale)
    """
    # 1. Explicit status already provided
    explicit_status = event_dict.get("authorization_status")
    if explicit_status:
        st = str(explicit_status).upper()
        if "UNAUTH" in st:
            return AuthorizationStatus.UNAUTHORIZED.value, "Explicitly marked unauthorized by source module."
        if "VERIF" in st or "RECTIF" in st:
            return AuthorizationStatus.VERIFIED_RECTIFIED.value, "Matched verified or rectified historical baseline."
        if "SUSP" in st:
            return AuthorizationStatus.SUSPICIOUS.value, "Marked suspicious — requires operator verification."
        if "AUTH" in st:
            return AuthorizationStatus.AUTHORIZED.value, "Explicitly validated as authorized."

    event_type = event_dict.get("event_type", "").upper()
    evidence = event_dict.get("evidence", {}) or {}
    action = str(event_dict.get("action", "")).upper()

    # 2. Check for unauthorized command or access violation
    if event_type in _UNAUTHORIZED_EVENT_TYPES:
        if event_type == "UNAUTHORIZED_COMMAND":
            cmd = evidence.get("command", "command")
            auth_req = evidence.get("auth_required", 2)
            auth_prov = evidence.get("auth_provided", 1)
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                f"Command '{cmd}' transmitted without requisite dual authorization (required: {auth_req}, provided: {auth_prov})."
            )
        elif event_type == "ACCESS_VIOLATION":
            res = evidence.get("resource", "resource")
            req_clr = evidence.get("clearance_required", "high clearance")
            held_clr = evidence.get("clearance_held", "insufficient clearance")
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                f"Attempted access to restricted resource '{res}' outside operator authorization scope (required: {req_clr}, held: {held_clr})."
            )
        elif event_type == "FIRMWARE_TAMPERING":
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                "Cryptographic signature check or digest verification failed on uploaded firmware image."
            )
        elif event_type == "COMMAND_INJECTION":
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                "Malicious or malformed payload injection detected in uplink stream."
            )
        elif event_type == "PRIVILEGE_ESCALATION":
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                "User privilege level modified without prerequisite supervisor approval or ticket."
            )
        elif event_type == "UNAUTHORIZED_DATA_ACCESS":
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                "Target database or data archive accessed without authorization grant."
            )
        else:
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                f"Activity classified as unauthorized based on event type: {event_type}."
            )

    # 3. Check for suspicious events
    if event_type in _SUSPICIOUS_EVENT_TYPES:
        if event_type == "SUSPICIOUS_LOGIN":
            loc = evidence.get("location", "anomalous location")
            ip = evidence.get("ip", "unknown IP")
            return (
                AuthorizationStatus.SUSPICIOUS.value,
                f"Login from unverified origin ({ip}, location: {loc}) outside authorized baseline."
            )
        elif event_type == "FAILED_LOGIN":
            return (
                AuthorizationStatus.SUSPICIOUS.value,
                "Failed authentication attempt detected; requires credential verification."
            )
        elif event_type == "REPLAY_ATTACK":
            return (
                AuthorizationStatus.SUSPICIOUS.value,
                "Duplicated command frame counter / packet hash detected in uplink."
            )
        else:
            return (
                AuthorizationStatus.SUSPICIOUS.value,
                f"Behavioral or telemetry anomaly detected ({event_type}); pending verification."
            )

    # 4. Check data access dictionary if present
    data_access = event_dict.get("data_access") or {}
    if data_access:
        access_auth = data_access.get("authorized")
        if access_auth is False:
            db_name = data_access.get("database", "database")
            return (
                AuthorizationStatus.UNAUTHORIZED.value,
                f"Unauthorized query or record retrieval against protected database '{db_name}'."
            )

    # 5. Default benign context
    if action in {"LOG", "MONITOR"}:
        return AuthorizationStatus.AUTHORIZED.value, "Routine operational event conforming to mission profile."

    return AuthorizationStatus.SUSPICIOUS.value, "Authorization cannot be definitively established from telemetry; requires verification."


def normalize_security_event(raw_input: Union[dict, IncomingEvent]) -> dict:
    """
    Cleans, validates, and normalizes an incoming security event from any
    module, CISO note, or CERT-In summary into the Common Event Model.

    Preserves the verbatim raw event inside `raw_log`.
    """
    # 1. Convert to raw dict copy to avoid mutating caller data
    if isinstance(raw_input, IncomingEvent):
        raw_dict = raw_input.model_dump(mode="json")
    elif isinstance(raw_input, dict):
        raw_dict = copy.deepcopy(raw_input)
    else:
        raise ValueError(f"Unsupported event payload type: {type(raw_input)}")

    # 2. Preserve original untouched raw event
    raw_log = copy.deepcopy(raw_dict)

    # 3. Normalize source
    source = normalize_source_module(raw_dict.get("source", "DOWNLINK")).value

    # 4. Normalize timestamp
    ts_normalized = normalize_timestamp(raw_dict.get("timestamp"))

    # 5. Extract and normalize identifiers
    event_id = str(raw_dict.get("event_id", "")).strip()
    if not event_id:
        import uuid
        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"

    satellite_id = str(raw_dict.get("satellite_id", "SAT-ORBITAL-01")).strip().upper()
    event_type = str(raw_dict.get("event_type", "SECURITY_EVENT")).strip().upper()

    # 6. Normalize Severity
    sev_raw = str(raw_dict.get("severity", "MEDIUM")).strip().upper()
    severity = sev_raw if sev_raw in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"

    # 7. Normalize Confidence
    try:
        confidence = float(raw_dict.get("confidence", 0.8))
        confidence = max(0.0, min(1.0, confidence))
    except (ValueError, TypeError):
        confidence = 0.8

    # 8. Normalize Action
    act_raw = str(raw_dict.get("action", "REVIEW")).strip().upper()
    action = act_raw if act_raw in {"REVIEW", "MONITOR", "HUMAN_REVIEW", "ALERT", "LOG"} else "REVIEW"

    # 9. Extract Actor, Device, Network endpoints
    operator_id = raw_dict.get("operator_id") or raw_dict.get("user_id") or raw_dict.get("actor")
    actor = raw_dict.get("actor") or operator_id or "UNKNOWN_ACTOR"
    session_id = raw_dict.get("session_id")
    device_id = raw_dict.get("device_id") or raw_dict.get("evidence", {}).get("device_id")
    source_ip = raw_dict.get("source_ip") or raw_dict.get("ip") or raw_dict.get("client_ip") or raw_dict.get("evidence", {}).get("ip") or raw_dict.get("evidence", {}).get("source_ip")
    destination_ip = raw_dict.get("destination_ip") or raw_dict.get("dest_ip") or raw_dict.get("evidence", {}).get("destination_ip") or raw_dict.get("evidence", {}).get("dest_ip")
    resource = raw_dict.get("resource") or raw_dict.get("evidence", {}).get("resource") or raw_dict.get("evidence", {}).get("target")

    # 10. Extract evidence, data_access, firmware_info
    evidence = raw_dict.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {"raw_evidence": evidence}

    data_access = copy.deepcopy(raw_dict.get("data_access") or evidence.get("data_access") or {})
    if not isinstance(data_access, dict):
        data_access = {"raw_data_access": data_access}
    for k in ("database", "tables", "files", "records_accessed", "records_count", "classification", "sensitivity"):
        if k in raw_dict and k not in data_access:
            data_access[k] = raw_dict[k]
        elif k in evidence and k not in data_access:
            data_access[k] = evidence[k]

    firmware_info = copy.deepcopy(raw_dict.get("firmware_info") or evidence.get("firmware_info") or {})
    if not isinstance(firmware_info, dict):
        firmware_info = {"raw_firmware": firmware_info}
    for k in ("component", "sha256", "previous_version", "new_version", "hash", "digest"):
        if k in raw_dict and k not in firmware_info:
            firmware_info[k] = raw_dict[k]
        elif k in evidence and k not in firmware_info:
            firmware_info[k] = evidence[k]

    packet_info = copy.deepcopy(raw_dict.get("packet_info") or evidence.get("packet_info") or {})
    if not isinstance(packet_info, dict):
        packet_info = {"raw_packet": packet_info}
    for k in ("frequency_mhz", "signal_dbm", "station_id", "packet_count", "telemetry_channel"):
        if k in raw_dict and k not in packet_info:
            packet_info[k] = raw_dict[k]
        elif k in evidence and k not in packet_info:
            packet_info[k] = evidence[k]

    related_events = raw_dict.get("related_events") or []
    if not isinstance(related_events, list):
        related_events = [str(related_events)]

    description = str(raw_dict.get("description", f"{event_type} on {satellite_id}")).strip()

    # 11. Normalize / Infer Authorization Status & Rationale
    temp_event = {
        "event_type": event_type,
        "evidence": evidence,
        "action": action,
        "authorization_status": raw_dict.get("authorization_status"),
        "data_access": data_access,
    }
    auth_status, auth_reason = determine_authorization_context(temp_event)

    # 12. Build Common Event Model dictionary
    normalized = {
        "event_id": event_id,
        "timestamp": ts_normalized,
        "source": source,
        "satellite_id": satellite_id,
        "event_type": event_type,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "action": action,
        "evidence": evidence,
        "related_events": related_events,
        "operator_id": operator_id,
        "session_id": session_id,
        "actor": actor,
        "device_id": device_id,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "resource": resource,
        "authorization_status": auth_status,
        "authorization_reason": auth_reason,
        "data_access": data_access,
        "firmware_info": firmware_info,
        "packet_info": packet_info,
        "raw_log": raw_log,
        "ciso_notes": raw_dict.get("ciso_notes"),
    }

    return normalized
