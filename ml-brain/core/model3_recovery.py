"""
ORBITAL SHIELD — ML Correlation Brain
MODEL 3: Retrain + Secure & Recover Guidance Engine

Implements the complete Model 3 specification:
  1. Executes / coordinates the human-in-the-loop retraining cycle
     (reusing fb_module.run_retrain_job for threshold widening + ML refiner retrain).
  2. Synthesizes an actionable, structured Secure & Recover Guidance plan
     for the CISO after multi-source security events are correlated.
  3. Uses local Ollama LLMs with automatic fallback (DeepSeek-R1 -> Qwen2.5).
  4. Automatically falls back to a deterministic rule-based recovery plan
     if Ollama is offline or returns invalid output.
  5. 100% Advisory-only: All guidance is persisted with review_status=PENDING_REVIEW
     and must be reviewed/accepted by a human CISO.
"""

import json
import logging
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from core import llm_client, feedback as fb_module, correlation_engine
from db import database as db

logger = logging.getLogger("orbital.model3_recovery")

_SYSTEM_PROMPT = """You are the Lead Spacecraft Cybersecurity Incident Response Advisor for the ORBITAL SHIELD mission defense system.
You provide expert containment, recovery, and verification guidance for the Chief Information Security Officer (CISO) and Flight Operations Director.

Analyze the provided satellite security incident and return ONLY a valid, parseable JSON object matching this EXACT schema:
{
  "affected_domain": "DOWNLINK" | "UPLINK" | "FIRMWARE" | "ACCESS" | "MULTI_DOMAIN",
  "isolation_summary": "Concise 1-2 sentence executive summary of mandatory operational isolation boundaries.",
  "secure_actions": [
    "Immediate operational containment action 1",
    "Immediate operational containment action 2"
  ],
  "recovery_actions": [
    "Step-by-step restoration action 1",
    "Step-by-step restoration action 2"
  ],
  "verification_steps": [
    "Telemetry or ground verification step 1 confirming safe state",
    "Verification step 2"
  ],
  "residual_risk": "LOW" | "MEDIUM" | "HIGH",
  "confidence": "LOW" | "MEDIUM" | "HIGH",
  "rationale": "Clear technical justification synthesizing root cause, attack progression, and defense recommendations."
}

Do not include conversational greetings, markdown formatting outside the JSON, or extraneous commentary. Return only the JSON object.
"""


def _build_incident_summary(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
    retrain_result: Optional[Dict[str, Any]] = None
) -> str:
    """Builds a structured prompt summarizing the correlated incident context."""
    inc_id = incident.get("event_id", "INC-UNKNOWN")
    rule_name = incident.get("rule_name", incident.get("rule_id", "UNKNOWN"))
    etype = incident.get("event_type", "SECURITY_INCIDENT")
    severity = incident.get("severity", "HIGH")
    score = incident.get("risk_score", 0)
    sat_id = incident.get("satellite_id", "UNKNOWN")
    actor = incident.get("operator_id") or incident.get("actor") or "Unknown"
    session = incident.get("session_id", "N/A")

    sources = sorted(list(set(e.get("source", "UNKNOWN") for e in events)))
    domains_str = ", ".join(sources) if sources else "UNKNOWN"

    lines = [
        f"INCIDENT DOSSIER: {inc_id}",
        f"- Target Spacecraft: {sat_id}",
        f"- Correlated Rule: {rule_name} ({incident.get('rule_id', '')})",
        f"- Classification: {etype} | Severity: {severity} | Composite Risk Score: {score}/100",
        f"- Attributed Ground Operator: {actor} | Session Token: {session}",
        f"- Contributing Ground/Space Domains: {domains_str}",
        f"- Contributing Events Count: {len(events)}",
        "",
        "CHRONOLOGICAL EVENT CHAIN (Up to 15 events):"
    ]

    for i, ev in enumerate(events[:15], 1):
        ts = ev.get("timestamp", "N/A")
        src = ev.get("source", "SYS")
        evt_type = ev.get("event_type", "ALERT")
        sev = ev.get("severity", "MED")
        desc = ev.get("description", "No description provided")
        evidence = ev.get("evidence") or {}
        lines.append(f"  {i}. [{ts}] [{src}] [{sev}] {evt_type}: {desc} | Evidence: {evidence}")

    # Include CERT-In intelligence if linked
    cert_in = incident.get("cert_in_context") or {}
    if cert_in.get("has_advisory"):
        refs = ", ".join(cert_in.get("references", []))
        tvs = ", ".join(cert_in.get("threat_vectors", []))
        lines.append("")
        lines.append(f"EXTERNAL THREAT INTELLIGENCE (CERT-In):")
        lines.append(f"  - Advisory Reference: {refs}")
        lines.append(f"  - Known Threat Vectors: {tvs}")

    if retrain_result:
        lines.append("")
        lines.append(f"ADAPTIVE RETRAIN CONTEXT:")
        lines.append(f"  - Retrain Status: {retrain_result.get('status')}")
        lines.append(f"  - Thresholds Adjusted: {len(retrain_result.get('thresholds_changed', []))}")

    return "\n".join(lines)


def _validate_guidance_shape(guidance: Dict[str, Any]) -> Dict[str, Any]:
    """Validates that the guidance dictionary adheres to the required contract."""
    required_keys = [
        "affected_domain", "isolation_summary", "secure_actions",
        "recovery_actions", "verification_steps", "residual_risk",
        "confidence", "rationale"
    ]
    for k in required_keys:
        if k not in guidance:
            raise ValueError(f"Guidance missing required field: '{k}'")

    # Validate list types
    for list_key in ("secure_actions", "recovery_actions", "verification_steps"):
        val = guidance[list_key]
        if not isinstance(val, list) or len(val) == 0:
            raise ValueError(f"Guidance field '{list_key}' must be a non-empty list.")
        # Ensure items are strings
        guidance[list_key] = [str(item) for item in val]

    # Validate enum-like strings
    if guidance["residual_risk"] not in ("LOW", "MEDIUM", "HIGH"):
        guidance["residual_risk"] = "MEDIUM"
    if guidance["confidence"] not in ("LOW", "MEDIUM", "HIGH"):
        guidance["confidence"] = "HIGH"

    return guidance


def _deterministic_recovery_guidance(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Expert rule-based fallback that generates rigorous, actionable containment,
    recovery, and verification steps based on contributing security domains.
    Guarantees the system never hard-fails if LLMs are unavailable.
    """
    sources = set(e.get("source", "").upper() for e in events)
    event_types = set(e.get("event_type", "").upper() for e in events)
    actor = incident.get("operator_id") or incident.get("actor") or "Target Operator"
    session = incident.get("session_id") or "Target Session"
    sat_id = incident.get("satellite_id", "SAT-01")

    secure_actions: List[str] = []
    recovery_actions: List[str] = []
    verification_steps: List[str] = []

    # UPLINK Domain Logic
    if "UPLINK" in sources or any("COMMAND" in et for et in event_types):
        secure_actions.append(
            "Execute emergency uplink carrier hold on Ground Station TT&C terminal to halt command ingestion."
        )
        secure_actions.append(
            "Invalidate all pending telecommand dispatch tokens and flush the OBC command staging buffer."
        )
        recovery_actions.append(
            "Re-authenticate Flight Dynamics flight controllers via out-of-band cryptographic challenge."
        )
        recovery_actions.append(
            f"Transmit authenticated telecommand sequence reset frame to spacecraft {sat_id} with incremented epoch counter."
        )
        verification_steps.append(
            "Query spacecraft onboard computer (OBC) telemetry to confirm last executed command ID matches authorized flight log."
        )
        verification_steps.append(
            "Verify uplink command rejection counters at Ground Gateway are stable and non-incrementing."
        )

    # FIRMWARE Domain Logic
    if "FIRMWARE" in sources or any("FIRMWARE" in et for et in event_types):
        secure_actions.append(
            f"Abort any active flash memory update routine on spacecraft {sat_id}; invalidate staged firmware images."
        )
        secure_actions.append(
            "Force spacecraft OBC bootloader to switch to the write-protected golden recovery image."
        )
        recovery_actions.append(
            "Re-verify the software supply chain signing keys and re-sign binary payload using Cosign cryptographic key pair."
        )
        recovery_actions.append(
            "Re-upload approved firmware release over isolated secure maintenance uplink channel."
        )
        verification_steps.append(
            "Perform cryptographic SHA-256 hash comparison between active OBC execution memory and master manifest."
        )
        verification_steps.append(
            "Execute onboard subsystem health self-tests (payload, power distribution, attitude determination)."
        )

    # ACCESS Domain Logic
    if "ACCESS" in sources or any("LOGIN" in et or "ACCESS" in et for et in event_types):
        secure_actions.append(
            f"Immediately terminate active session token '{session}' and suspend credentials for operator '{actor}'."
        )
        secure_actions.append(
            "Enforce mandatory hardware security key (FIDO2/WebAuthn) re-authentication across all ground stations."
        )
        recovery_actions.append(
            f"Audit privileged access logs and database query trails attributed to operator '{actor}' across past 24 hours."
        )
        recovery_actions.append(
            "Rotate Ground Station API gateway access keys and mutual TLS certificates."
        )
        verification_steps.append(
            "Verify zero active unauthenticated connections or concurrent sessions exist in Ground Station access logs."
        )
        verification_steps.append(
            "Confirm directory service integrity check passes with all rogue accounts locked out."
        )

    # DOWNLINK Domain Logic
    if "DOWNLINK" in sources or any("TELEMETRY" in et or "INTERFERENCE" in et for et in event_types):
        secure_actions.append(
            "Flag current downlink telemetry stream as untrusted; switch flight control consoles to secondary telemetry stream."
        )
        secure_actions.append(
            "Isolate RF front-end receiver processing pipeline to evaluate potential RF spoofing or packet injection."
        )
        recovery_actions.append(
            "Trigger automated ground station tracking antenna recalibration and LNA diagnostic test."
        )
        recovery_actions.append(
            f"Command spacecraft {sat_id} to transmit full memory housekeeping dump over backup S-band downlink."
        )
        verification_steps.append(
            "Verify telemetry sensor readings (temperature, battery voltage, solar array current) match physical orbital model."
        )
        verification_steps.append(
            "Confirm packet sequence monotonicity and SHA-256 integrity checksums over 10 consecutive nominal minor frames."
        )

    # General baseline if no specific domain matched
    if not secure_actions:
        secure_actions.append(
            f"Place spacecraft {sat_id} in safe-hold operational mode pending comprehensive security review."
        )
        secure_actions.append(
            "Lock mission control console access and freeze telemetry and command audit logs for forensic preservation."
        )
        recovery_actions.append(
            "Conduct structured multi-point operational review between CISO and Flight Operations Director."
        )
        recovery_actions.append(
            "Re-establish verified command link following standard emergency operating procedures."
        )
        verification_steps.append(
            "Confirm all spacecraft subsystems report nominal status in telemetry beacon."
        )

    # Determine domain classification
    if len(sources) > 1:
        affected_domain = "MULTI_DOMAIN"
        isolation_summary = (
            f"Multi-vector intrusion detected across {', '.join(sorted(sources))}. "
            f"Immediate isolation of ground operator sessions, command uplink channels, and firmware staging required."
        )
    elif len(sources) == 1:
        affected_domain = list(sources)[0]
        isolation_summary = f"Isolated security anomaly detected in {affected_domain} domain. Containment boundaries established."
    else:
        affected_domain = "MULTI_DOMAIN"
        isolation_summary = "Spacecraft security anomaly requires immediate operational containment and link verification."

    return {
        "affected_domain": affected_domain,
        "isolation_summary": isolation_summary,
        "secure_actions": secure_actions,
        "recovery_actions": recovery_actions,
        "verification_steps": verification_steps,
        "residual_risk": "MEDIUM" if incident.get("severity") in ("CRITICAL", "HIGH") else "LOW",
        "confidence": "HIGH",
        "rationale": (
            f"Deterministic recovery plan synthesized from {len(events)} correlated events "
            f"spanning {len(sources)} domains. Mirrors standard space operations emergency protocols."
        )
    }


def generate_recovery_guidance(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
    retrain_result: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], str, bool]:
    """
    Attempts to generate guidance using local Ollama LLMs with fallback.
    If LLMs are unreachable or return malformed output, falls back to deterministic logic.

    Returns:
        Tuple of (guidance_dict, model_name_used, llm_used_boolean)
    """
    user_prompt = _build_incident_summary(incident, events, retrain_result)

    # 1. Attempt LLM generation
    try:
        raw_guidance, model_name = llm_client.generate_with_fallback(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt
        )
        validated_guidance = _validate_guidance_shape(raw_guidance)
        logger.info("Successfully generated and validated Model 3 LLM recovery guidance using %s", model_name)
        return validated_guidance, model_name, True
    except Exception as exc:
        logger.warning(
            "LLM guidance generation failed or unavailable (%s). Falling back to deterministic recovery engine.",
            exc
        )

    # 2. Fall back to deterministic rule-based plan
    deterministic_guidance = _deterministic_recovery_guidance(incident, events)
    return deterministic_guidance, "deterministic_fallback", False


def run_model3_pipeline(
    incident_ids: Optional[List[str]] = None,
    run_retrain: bool = True
) -> Dict[str, Any]:
    """
    Executes the complete Model 3 Pipeline:
      1. Runs the existing retrain job (threshold widening + ML score refiner retrain).
      2. Generates advisory Secure & Recover Guidance for specified or all open incidents.
      3. Persists each plan in the database with review_status=PENDING_REVIEW.

    Returns:
        Structured Model3RunResponse dictionary.
    """
    cfg = llm_client.load_model3_config()
    max_to_process = int(cfg.get("max_open_incidents_to_process", 10))

    # Step 1: Execute existing retrain job if requested
    retrain_result = None
    if run_retrain:
        try:
            logger.info("Model 3: executing retrain job via feedback module...")
            retrain_result = fb_module.run_retrain_job()
            logger.info("Model 3: retrain job finished with status=%s", retrain_result.get("status"))
        except Exception as exc:
            logger.error("Model 3: retrain job encountered an error: %s", exc)
            retrain_result = {"status": "ERROR", "message": str(exc)}

    # Step 2: Determine target incidents
    target_incidents: List[Dict[str, Any]] = []
    if incident_ids:
        for iid in incident_ids:
            inc = db.fetch_incident_by_id(iid)
            if inc:
                target_incidents.append(inc)
            else:
                logger.warning("Model 3: requested incident '%s' not found in database", iid)
    else:
        open_incidents = db.fetch_open_incidents()
        target_incidents = open_incidents[:max_to_process]

    guidance_records: List[Dict[str, Any]] = []

    # Step 3: Generate and persist guidance for each incident
    for inc in target_incidents:
        inc_id = inc["event_id"]
        # Retrieve contributing raw events
        raw_events: List[Dict[str, Any]] = []
        with db.get_connection() as conn:
            for eid in inc.get("related_events", []):
                row = conn.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone()
                if row:
                    raw_events.append(db._row_to_dict(row))

        # Generate guidance
        guidance_dict, model_used, llm_used = generate_recovery_guidance(
            incident=inc,
            events=raw_events,
            retrain_result=retrain_result
        )

        guidance_id = f"GUIDE-{uuid.uuid4().hex[:8].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        record = {
            "guidance_id": guidance_id,
            "incident_id": inc_id,
            "generated_at": now_iso,
            "model_used": model_used,
            "llm_used": llm_used,
            "guidance_json": guidance_dict,
            "review_status": "PENDING_REVIEW",
            "reviewed_by": None,
            "review_notes": None,
            "reviewed_at": None,
        }

        # Persist to database
        db.insert_recovery_guidance(record)

        # Build response item
        guidance_records.append({
            "guidance_id": guidance_id,
            "incident_id": inc_id,
            "generated_at": now_iso,
            "model_used": model_used,
            "llm_used": llm_used,
            "guidance": guidance_dict,
            "review_status": "PENDING_REVIEW",
            "reviewed_by": None,
            "review_notes": None,
            "reviewed_at": None,
        })

    logger.info(
        "Model 3 Pipeline completed: retrain_status=%s | guidance_generated=%d",
        retrain_result.get("status") if retrain_result else "SKIPPED",
        len(guidance_records)
    )

    return {
        "status": "COMPLETED",
        "retrain_result": retrain_result,
        "guidance_count": len(guidance_records),
        "guidance_records": guidance_records,
        "message": f"Model 3 run complete. Retrain: {retrain_result.get('status') if retrain_result else 'SKIPPED'}. Generated guidance for {len(guidance_records)} incident(s)."
    }


def check_llm_reachability(timeout: float = 1.5) -> bool:
    """Probes local Ollama /api/tags endpoint to check if LLM daemon is reachable."""
    try:
        cfg = llm_client.load_model3_config()
        host = cfg.get("ollama_host", "http://localhost:11434")
        resp = httpx.get(f"{host}/api/tags", timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False


class RemediationNotAppliedError(ValueError):
    """Raised when verification is requested before CISO marks remediation as applied."""
    pass


class VerificationWindowTooEarlyError(Exception):
    """Raised when verification is requested before the minimum observation window has elapsed."""
    def __init__(self, retry_after_seconds: int, message: str):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.message = message


def verify_rectification(
    incident_id: str,
    reviewer: str = "ciso_verification",
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates telemetry received post-remediation to verify whether the
    correlated breach condition has ceased.

    Advisory-only: Does NOT mutate satellite or ground control state.
    Tests if the incident's triggering correlation rule re-fires on
    events received after human CISO confirmed remediation via /mark-applied.

    Guards:
    1. Rejects if remediation_applied_at is NULL (CISO must call /mark-applied first).
    2. Rejects with countdown if (now - remediation_applied_at) < verification_min_window_seconds.

    - If rule re-fires: verification_result = FAILED, status = VERIFICATION_FAILED.
    - If rule does not re-fire: verification_result = PASSED, status = RECTIFIED.
    """
    inc = db.fetch_incident_by_id(incident_id)
    if not inc:
        raise ValueError(f"Incident {incident_id} not found")

    guidance = db.fetch_recovery_guidance_by_incident(incident_id)
    if not guidance:
        raise ValueError(f"No recovery guidance found for incident {incident_id}")

    # Guard 0: Idempotency check — already verified RECTIFIED
    if inc.get("status") == "RECTIFIED" and guidance.get("verification_result") == "PASSED":
        logger.info("Incident %s is already RECTIFIED; returning idempotent verification result", incident_id)
        return {
            "incident_id": incident_id,
            "verification_result": "PASSED",
            "verified_at": guidance.get("verified_at") or datetime.now(timezone.utc).isoformat(),
            "status_updated_to": "RECTIFIED",
            "evidence_summary": guidance.get("verification_evidence") or {},
            "message": f"Breach rectification already verified PASSED for incident {incident_id} (idempotent)."
        }

    # Guard 1: Must have remediation confirmed by human operator

    remediation_applied_at = guidance.get("remediation_applied_at")
    if not remediation_applied_at:
        raise RemediationNotAppliedError(
            "Cannot verify before CISO confirms remediation was applied via /mark-applied."
        )

    # Guard 2: Observation window must have elapsed
    now_dt = datetime.now(timezone.utc)
    try:
        applied_dt = datetime.fromisoformat(remediation_applied_at.replace("Z", "+00:00"))
        elapsed_seconds = (now_dt - applied_dt).total_seconds()
    except Exception as exc:
        logger.warning("Could not parse remediation_applied_at '%s': %s", remediation_applied_at, exc)
        elapsed_seconds = 999999.0

    cfg = llm_client.load_model3_config()
    min_window = float(cfg.get("verification_min_window_seconds", 15))
    if elapsed_seconds < min_window:
        retry_after = max(1, math.ceil(min_window - elapsed_seconds))
        raise VerificationWindowTooEarlyError(
            retry_after_seconds=retry_after,
            message=f"Observation window active: {retry_after}s remaining before verification can be confirmed."
        )

    # Reference timestamp: evaluate telemetry received strictly after remediation was applied
    now_iso = now_dt.isoformat()
    sat_id = inc.get("satellite_id")
    try:
        applied_dt = datetime.fromisoformat(remediation_applied_at.replace("Z", "+00:00"))
        since_ts = applied_dt.isoformat()
    except Exception:
        applied_dt = now_dt
        since_ts = remediation_applied_at

    # Fetch post-remediation events for this spacecraft using server-assigned ingested_at
    post_remediation_events: List[Dict[str, Any]] = []
    with db.get_connection() as conn:
        if sat_id:
            rows = conn.execute(
                "SELECT * FROM events WHERE satellite_id = ? AND ingested_at >= ? ORDER BY ingested_at ASC",
                (sat_id, since_ts)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events WHERE ingested_at >= ? ORDER BY ingested_at ASC",
                (since_ts,)
            ).fetchall()
        raw_events = [db._row_to_dict(r) for r in rows]

    # Exclude stale telemetry: events with timestamp far in the past relative to ingested_at or before remediation
    for ev in raw_events:
        is_stale = False
        try:
            ev_ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
            ing_ts = datetime.fromisoformat(ev["ingested_at"].replace("Z", "+00:00"))
            if (ing_ts - ev_ts).total_seconds() > 300 or ev_ts < applied_dt:
                is_stale = True
                logger.info(
                    "Excluding stale telemetry event %s (timestamp=%s, ingested_at=%s, applied_at=%s)",
                    ev.get("event_id"), ev.get("timestamp"), ev.get("ingested_at"), since_ts
                )
        except Exception as exc:
            logger.warning("Could not check staleness for event %s: %s", ev.get("event_id"), exc)

        if not is_stale:
            post_remediation_events.append(ev)

    rule_id = inc.get("rule_id")

    # If 0 post-remediation events exist, do NOT default to RECTIFIED; return AWAITING_TELEMETRY
    if not post_remediation_events:
        verification_result = "AWAITING_TELEMETRY"
        status_updated_to = inc.get("status", "OPEN")
        evidence = {
            "since_timestamp": since_ts,
            "post_events_count": 0,
            "re_fired": False,
            "rule_evaluated": rule_id,
            "notes": notes or "No valid telemetry events ingested since remediation was applied; awaiting post-remediation telemetry.",
        }
        db.update_recovery_guidance_verification(guidance["guidance_id"], "AWAITING_TELEMETRY", evidence)
        return {
            "incident_id": incident_id,
            "verification_result": verification_result,
            "verified_at": now_iso,
            "status_updated_to": status_updated_to,
            "evidence_summary": evidence,
            "message": f"Breach rectification verification PENDING: 0 valid post-remediation telemetry events ingested since {since_ts}. Awaiting fresh telemetry.",
        }

    # Evaluate triggering rule against post-remediation events
    all_rules = correlation_engine.get_rules()
    target_rule = next(
        (
            r for r in all_rules
            if r.get("id") == rule_id
            or r.get("id") == (rule_id or "").replace("-", "_")
            or r.get("id") == (rule_id or "").replace("_", "-")
        ),
        None
    )

    re_fired = False
    fired_match = None
    if post_remediation_events and target_rule:
        for ev in post_remediation_events:
            match = correlation_engine._evaluate_single_rule(target_rule, ev, post_remediation_events)
            if match:
                re_fired = True
                fired_match = match
                break

    if re_fired:
        verification_result = "FAILED"
        status_updated_to = "VERIFICATION_FAILED"
        db.update_incident_status(
            incident_id=incident_id,
            status=status_updated_to,
            reviewer=reviewer,
            notes=notes or f"Breach verification failed: rule {rule_id} re-fired on post-remediation telemetry.",
            reviewed_at=now_iso,
        )

        # Log audit entry in config_audit
        audit_event_id = f"AUDIT-VERIF-{uuid.uuid4().hex[:8].upper()}"
        db.insert_config_audit({
            "audit_event_id": audit_event_id,
            "timestamp": now_iso,
            "change_type": "RECTIFICATION_VERIFICATION_FAILED",
            "rule_id": rule_id,
            "field_name": "incident_status",
            "before_value": inc.get("status", "OPEN"),
            "after_value": status_updated_to,
            "triggered_by": reviewer,
            "notes": notes or f"Verification failed: rule {rule_id} re-fired on {len(post_remediation_events)} post-remediation events.",
        })

        evidence = {
            "since_timestamp": since_ts,
            "post_events_count": len(post_remediation_events),
            "re_fired": True,
            "re_fired_rule_id": rule_id,
            "matched_events": fired_match.get("matched_events", []) if fired_match else [],
            "notes": notes,
        }
        db.update_recovery_guidance_verification(guidance["guidance_id"], "FAILED", evidence)

        msg = f"Breach rectification verification FAILED: rule {rule_id} re-fired on post-remediation telemetry ({len(post_remediation_events)} events analyzed)."

    else:
        verification_result = "PASSED"
        status_updated_to = "RECTIFIED"
        # Register via feedback module to update incident status and record suppressed pattern
        fb_module.submit_feedback(
            incident_id=incident_id,
            verdict="RECTIFIED",
            reviewer=reviewer,
            notes=notes or f"Breach verified rectified: rule {rule_id} did not re-fire on post-remediation telemetry."
        )

        evidence = {
            "since_timestamp": since_ts,
            "post_events_count": len(post_remediation_events),
            "re_fired": False,
            "rule_evaluated": rule_id,
            "notes": notes,
        }
        db.update_recovery_guidance_verification(guidance["guidance_id"], "PASSED", evidence)

        msg = f"Breach rectification verification PASSED: rule {rule_id} did not re-fire across {len(post_remediation_events)} post-remediation telemetry event(s)."

    return {
        "incident_id": incident_id,
        "verification_result": verification_result,
        "verified_at": now_iso,
        "status_updated_to": status_updated_to,
        "evidence_summary": evidence,
        "message": msg,
    }
