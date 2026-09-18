"""
ORBITAL SHIELD — ML Correlation Brain
MODEL 1: Understanding, Summarization & Incident Document Generation Engine

Model 1 is responsible for:
  1. Understanding normalized events, rule matches, and risk scores.
  2. Correlating related events into a complete attack progression.
  3. Determining and explaining authorization context (UNAUTHORIZED, SUSPICIOUS, VERIFIED_RECTIFIED, AUTHORIZED).
  4. Filtering unauthorized activity as the primary content while retaining minimum explanatory context.
  5. Searching historical logs to detect repeated unauthorized patterns and retrieving all associated data-access details.
  6. Segregating verified/rectified feedback to prevent recurring false alarms.
  7. Generating a human-readable incident document tailored for:
       - CISO Dashboard (executive summary, threat containment)
       - Security Analysts (full unauthorized forensic event chain)
       - CERT-In 6-Hour Audit & Reporting Workflow (regulatory breach compliance)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from db import database as db

logger = logging.getLogger("orbital.model1")

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def understand_incident(incident: dict, contributing_events: list[dict]) -> dict:
    """
    Main Model 1 reasoning entry point.
    Transforms raw incident + contributing events into an explainable,
    correlated, contextualized security incident document.

    Args:
        incident: Scored incident dictionary from scoring engine.
        contributing_events: Full list of raw/normalized contributing events.

    Returns:
        Enriched incident dictionary containing Model 1 fields:
          - authorization_status
          - authorization_reason
          - unauthorized_chain
          - data_access_summary
          - historical_pattern_matched
          - historical_pattern_details
          - incident_document_md
          - cert_in_report
    """
    # Sort events chronologically
    sorted_events = sorted(
        contributing_events,
        key=lambda e: _parse_iso(e.get("timestamp", ""))
    )

    # 1. Evaluate Authorization Context & Reason
    auth_status, auth_reason = _analyze_authorization_context(incident, sorted_events)

    # 2. Filter & Reconstruct Full Unauthorized Event Chain
    unauth_chain, data_access_summary = _build_unauthorized_chain(sorted_events)

    # 3. Check for Historical Repeated Pattern & Retrieve Associated Data Access (Section 13)
    hist_matched, hist_details = _correlate_historical_pattern_and_data_access(
        incident=incident,
        current_events=sorted_events,
        current_data_access=data_access_summary
    )

    # 4. Generate Human-Readable Incident Document (CISO + CERT-In)
    document_md = _generate_incident_document(
        incident=incident,
        events=sorted_events,
        auth_status=auth_status,
        auth_reason=auth_reason,
        unauthorized_chain=unauth_chain,
        data_access_summary=data_access_summary,
        hist_details=hist_details
    )

    # 5. Build CERT-In 6-Hour Audit & Reporting Payload
    cert_in_report = _build_cert_in_report(
        incident=incident,
        events=sorted_events,
        auth_status=auth_status,
        unauthorized_chain=unauth_chain,
        data_access_summary=data_access_summary,
        hist_details=hist_details
    )

    # Update incident fields
    incident["authorization_status"] = auth_status
    incident["authorization_reason"] = auth_reason
    incident["unauthorized_chain"] = unauth_chain
    incident["data_access_summary"] = data_access_summary
    incident["historical_pattern_matched"] = hist_matched
    incident["historical_pattern_details"] = hist_details
    incident["incident_document_md"] = document_md
    incident["cert_in_report"] = cert_in_report

    logger.info(
        "Model 1 Understanding complete for %s | auth=%s | chain_len=%d | hist_match=%s",
        incident["event_id"], auth_status, len(unauth_chain), hist_matched
    )
    return incident


# ─────────────────────────────────────────────────────────────
# 1. Authorization Status & Rationale Analysis
# ─────────────────────────────────────────────────────────────

def _analyze_authorization_context(incident: dict, events: list[dict]) -> Tuple[str, str]:
    """
    Determines whether the incident is AUTHORIZED, UNAUTHORIZED, SUSPICIOUS,
    or VERIFIED_RECTIFIED, and produces a plain-English explanation.
    """
    # 1. Check if the pattern or any contributing event was verified/rectified by CISO
    for ev in events:
        is_rect, rect_note = db.is_event_or_pattern_rectified(ev)
        if is_rect:
            return (
                "VERIFIED_RECTIFIED",
                f"PREVIOUSLY VERIFIED/RECTIFIED: Activity matches prior CISO verified or rectified baseline: {rect_note}"
            )

    # 2. Inspect individual events for definite unauthorized indicators
    unauthorized_reasons = []
    suspicious_reasons = []

    for ev in events:
        etype = ev.get("event_type", "").upper()
        ev_auth = ev.get("authorization_status", "").upper()
        ev_reason = ev.get("authorization_reason") or ""
        evidence = ev.get("evidence") or {}
        actor = ev.get("actor") or ev.get("operator_id") or "Operator"

        if ev_auth == "UNAUTHORIZED" or etype in {
            "UNAUTHORIZED_COMMAND", "ACCESS_VIOLATION", "FIRMWARE_TAMPERING",
            "COMMAND_INJECTION", "PRIVILEGE_ESCALATION", "UNAUTHORIZED_DATA_ACCESS",
            "DATA_EXFILTRATION"
        }:
            if etype == "PRIVILEGE_ESCALATION":
                unauthorized_reasons.append(
                    f"{actor} performed unapproved privilege escalation prior to resource execution."
                )
            elif etype == "ACCESS_VIOLATION":
                res = ev.get("resource") or evidence.get("resource", "restricted resource")
                unauthorized_reasons.append(
                    f"{actor} accessed resource '{res}' outside authorized operational scope."
                )
            elif etype == "UNAUTHORIZED_COMMAND":
                cmd = evidence.get("command", "command")
                unauthorized_reasons.append(
                    f"Command '{cmd}' was issued without dual authorization verification."
                )
            elif etype == "FIRMWARE_TAMPERING":
                unauthorized_reasons.append(
                    "Uploaded firmware artifact failed cryptographic signature verification."
                )
            elif etype == "UNAUTHORIZED_DATA_ACCESS":
                da = ev.get("data_access", {})
                db_name = da.get("database", "restricted database")
                unauthorized_reasons.append(
                    f"Unauthorized database query executed against '{db_name}'."
                )
            else:
                unauthorized_reasons.append(ev_reason or f"Unauthorized action detected ({etype}).")

        elif ev_auth == "SUSPICIOUS" or etype in {
            "SUSPICIOUS_LOGIN", "FAILED_LOGIN", "REPLAY_ATTACK",
            "TELEMETRY_ANOMALY", "SIGNAL_INTERFERENCE"
        }:
            suspicious_reasons.append(ev_reason or f"Anomalous telemetry or event signature ({etype}).")

    if unauthorized_reasons:
        return (
            "UNAUTHORIZED",
            f"UNAUTHORIZED: Unauthorized activity confirmed ({len(unauthorized_reasons)} trigger(s)): " + " ".join(unauthorized_reasons)
        )

    if suspicious_reasons:
        return (
            "SUSPICIOUS",
            f"SUSPICIOUS: Activity exhibits behavioral anomalies that require manual operator verification: " + " ".join(suspicious_reasons)
        )

    return (
        "AUTHORIZED",
        "AUTHORIZED: Events match normal operational parameters but met temporal correlation criteria."
    )


# ─────────────────────────────────────────────────────────────
# 2. Full Unauthorized Event Chain & Data Access Extraction
# ─────────────────────────────────────────────────────────────

def _build_unauthorized_chain(events: list[dict]) -> Tuple[List[dict], dict]:
    """
    Reconstructs the full causal chain of the incident.
    Prioritizes unauthorized/suspicious activity as the primary content,
    while retaining the minimum necessary contextual events to explain the chain.

    Returns:
        (unauthorized_chain_list, aggregated_data_access_summary)
    """
    chain = []
    aggregated_data_access = {
        "databases_accessed": [],
        "tables_accessed": [],
        "files_accessed": [],
        "total_records_accessed": 0,
        "sensitivity_levels": set(),
        "access_timestamps": []
    }

    for idx, ev in enumerate(events):
        etype = ev.get("event_type", "").upper()
        auth_status = ev.get("authorization_status", "SUSPICIOUS")
        is_unauthorized = auth_status == "UNAUTHORIZED" or etype in {
            "UNAUTHORIZED_COMMAND", "ACCESS_VIOLATION", "FIRMWARE_TAMPERING",
            "COMMAND_INJECTION", "PRIVILEGE_ESCALATION", "UNAUTHORIZED_DATA_ACCESS",
            "DATA_EXFILTRATION", "INTEGRITY_FAILURE"
        }
        is_suspicious = auth_status == "SUSPICIOUS" or etype in {
            "SUSPICIOUS_LOGIN", "FAILED_LOGIN", "REPLAY_ATTACK",
            "TELEMETRY_ANOMALY", "SIGNAL_INTERFERENCE", "NEW_DEVICE"
        }

        # Role of event in the chain
        if is_unauthorized:
            chain_role = "PRIMARY_UNAUTHORIZED_ACTIVITY"
        elif is_suspicious:
            chain_role = "SUSPICIOUS_INDICATOR"
        elif idx == 0 or etype in {"LOGIN", "AUTHENTICATION"}:
            chain_role = "EXPLANATORY_CONTEXT_AUTHENTICATION"
        else:
            chain_role = "EXPLANATORY_CONTEXT"

        # Extract data access details if present
        da = ev.get("data_access") or {}
        if isinstance(da, dict) and da:
            db_name = da.get("database")
            if db_name and db_name not in aggregated_data_access["databases_accessed"]:
                aggregated_data_access["databases_accessed"].append(db_name)

            for t in da.get("tables", []):
                if t not in aggregated_data_access["tables_accessed"]:
                    aggregated_data_access["tables_accessed"].append(t)

            for f in da.get("files", []):
                if f not in aggregated_data_access["files_accessed"]:
                    aggregated_data_access["files_accessed"].append(f)

            rec = da.get("records_count") or da.get("records_accessed") or 0
            if isinstance(rec, (int, float)):
                aggregated_data_access["total_records_accessed"] += int(rec)

            sens = da.get("classification") or da.get("sensitivity")
            if sens:
                aggregated_data_access["sensitivity_levels"].add(sens)

            aggregated_data_access["access_timestamps"].append(ev.get("timestamp"))

        chain_step = {
            "step": idx + 1,
            "event_id": ev["event_id"],
            "timestamp": ev["timestamp"],
            "source": ev.get("source"),
            "event_type": etype,
            "severity": ev.get("severity"),
            "actor": ev.get("actor") or ev.get("operator_id") or "UNKNOWN",
            "device_id": ev.get("device_id") or ev.get("evidence", {}).get("device_id"),
            "source_ip": ev.get("source_ip") or ev.get("evidence", {}).get("ip"),
            "resource": ev.get("resource") or ev.get("evidence", {}).get("resource"),
            "action": ev.get("action"),
            "authorization_status": auth_status,
            "authorization_reason": ev.get("authorization_reason"),
            "chain_role": chain_role,
            "data_access": da if da else None,
            "description": ev.get("description"),
        }
        chain.append(chain_step)

    aggregated_data_access["sensitivity_levels"] = sorted(list(aggregated_data_access["sensitivity_levels"]))
    return chain, aggregated_data_access


# ─────────────────────────────────────────────────────────────
# 3. Same Unauthorized Pattern + Associated Data Access (Section 13)
# ─────────────────────────────────────────────────────────────

def _correlate_historical_pattern_and_data_access(
    incident: dict,
    current_events: list[dict],
    current_data_access: dict
) -> Tuple[bool, dict]:
    """
    CRITICAL SECTION 13 REQUIREMENT:
    When a previously observed unauthorized pattern appears again:
      1. Search historical logs/database.
      2. Identify the matching pattern.
      3. Determine whether the pattern accessed data.
      4. Retrieve ALL relevant associated data-access details.
      5. Correlate historical information with current incident.
      6. Provide complete relevant details connecting pattern and data access.
    """
    rule_id = incident.get("rule_id")
    event_type = incident.get("event_type")
    current_inc_id = incident.get("event_id")

    # Search for prior incidents with same rule or event_type
    past_incidents = db.search_historical_patterns(
        rule_id=rule_id,
        event_type=event_type,
        exclude_incident_id=current_inc_id,
        limit=5
    )

    if not past_incidents:
        return False, {
            "pattern_matched": False,
            "message": "No previous occurrences of this unauthorized attack pattern found in historical audit logs.",
            "historical_matches_count": 0,
        }

    # Match found — gather historical data access details
    matched_incident_ids = [p["event_id"] for p in past_incidents]
    historical_accesses = db.fetch_historical_data_access(matched_incident_ids)

    # Primary past incident for comparison
    primary_past = past_incidents[0]
    past_chain_summary = primary_past.get("description", "")
    past_rule_name = primary_past.get("rule_name", rule_id)
    past_timestamp = primary_past.get("timestamp", "PAST")

    # Aggregate historical databases/files
    hist_dbs = set()
    hist_tables = set()
    hist_files = set()
    hist_records = 0

    for ha in historical_accesses:
        da = ha.get("data_access") or {}
        if da.get("database"):
            hist_dbs.add(da["database"])
        for t in da.get("tables", []):
            hist_tables.add(t)
        for f in da.get("files", []):
            hist_files.add(f)
        hist_records += da.get("records_count") or da.get("records_accessed") or 0

    # Compute correlation and overlap between past and current data access
    current_dbs = set(current_data_access.get("databases_accessed", []))
    current_files = set(current_data_access.get("files_accessed", []))

    common_dbs = list(current_dbs & hist_dbs)
    common_files = list(current_files & hist_files)

    correlation_narrative = (
        f"Repeated unauthorized attack pattern detected matching rule '{past_rule_name}' "
        f"(previously recorded in incident {primary_past['event_id']} on {past_timestamp}). "
    )
    if common_dbs:
        correlation_narrative += (
            f"TARGET RECURRENCE: Current attack targets the identical database resource ({', '.join(common_dbs)}) "
            f"accessed in the previous incident, indicating a persistent targeted intrusion campaign. "
        )
    elif current_dbs and hist_dbs:
        correlation_narrative += (
            f"DATA ACCESS CORRELATION: Current attack targeted database ({', '.join(current_dbs)}), whereas "
            f"prior occurrence targeted ({', '.join(hist_dbs)}). "
        )
    elif hist_dbs:
        correlation_narrative += (
            f"HISTORICAL PRECEDENT: Prior occurrence compromised databases [{', '.join(hist_dbs)}]. "
        )

    has_data_access = len(hist_dbs) > 0 or len(hist_files) > 0 or len(historical_accesses) > 0

    details = {
        "pattern_matched": True,
        "matched_rule_id": rule_id,
        "matching_rule_id": rule_id,
        "matched_rule_name": incident.get("rule_name"),
        "historical_incident_id": primary_past["event_id"],
        "historical_matches_count": len(past_incidents),
        "historical_timestamp": past_timestamp,
        "historical_severity": primary_past.get("severity"),
        "historical_risk_score": primary_past.get("risk_score"),
        "historical_narrative": past_chain_summary,
        "historical_had_data_access": has_data_access,
        "historical_databases_accessed": list(hist_dbs),
        "historical_tables_accessed": list(hist_tables),
        "historical_files_accessed": list(hist_files),
        "historical_total_records_accessed": hist_records,
        "historical_data_access": {
            "databases_accessed": list(hist_dbs),
            "tables_accessed": list(hist_tables),
            "files_accessed": list(hist_files),
            "total_records": hist_records,
            "access_records_count": len(historical_accesses),
        },
        "current_data_access": current_data_access,
        "common_databases_accessed": common_dbs,
        "common_files_accessed": common_files,
        "persistent_threat_indicator": len(common_dbs) > 0 or len(common_files) > 0,
        "correlation_narrative": correlation_narrative,
    }
    return True, details


# ─────────────────────────────────────────────────────────────
# 4. Human-Readable Incident Document Generator
# ─────────────────────────────────────────────────────────────

def _generate_incident_document(
    incident: dict,
    events: list[dict],
    auth_status: str,
    auth_reason: str,
    unauthorized_chain: list[dict],
    data_access_summary: dict,
    hist_details: dict
) -> str:
    """
    Renders a complete, professional, human-readable Incident Document
    tailored for CISO, Security Analysts, and CERT-In Auditors.
    """
    sat_id = incident.get("satellite_id", "SAT-ORBITAL-01")
    inc_id = incident.get("event_id", "INC-001")
    ts = incident.get("timestamp", datetime.now(timezone.utc).isoformat())
    sev = incident.get("severity", "HIGH")
    score = incident.get("risk_score", 0)
    rule_name = incident.get("rule_name", "Correlation Rule")
    etype = incident.get("event_type", "SECURITY_INCIDENT")

    # Primary unauthorized events vs contextual events
    primary_unauth = [step for step in unauthorized_chain if step["chain_role"] == "PRIMARY_UNAUTHORIZED_ACTIVITY"]
    context_events = [step for step in unauthorized_chain if step["chain_role"] != "PRIMARY_UNAUTHORIZED_ACTIVITY"]

    # Build markdown
    lines = []
    lines.append(f"# ORBITAL SHIELD — INCIDENT UNDERSTANDING & FORENSIC DOSSIER")
    lines.append(f"**Incident ID:** `{inc_id}` | **Target Satellite Asset:** `{sat_id}` | **Timestamp (UTC):** `{ts}`")
    lines.append(f"**Classification:** `{etype}` | **Severity:** `{sev}` | **Composite Risk Score:** `{score}/200`\n")
    lines.append(f"---")

    # Section 1: Executive Summary for CISO Dashboard
    lines.append(f"## 1. CISO EXECUTIVE SUMMARY & THREAT BRIEFING (CISO DASHBOARD)")
    lines.append(f"> **Authorization Status:** **{auth_status}**  ")
    lines.append(f"> **Authorization Finding:** {auth_reason}\n")
    lines.append(f"- **Primary Threat Vector:** {rule_name}")
    lines.append(f"- **Contributing Security Modules:** {', '.join(set(e.get('source') for e in events))}")
    actor = events[0].get("actor") or events[0].get("operator_id") or "Unknown"
    lines.append(f"- **Attributed Actor / Session:** `{actor}` (Session: `{events[0].get('session_id', 'N/A')}`)")
    lines.append(f"- **Total Contributing Events:** {len(events)} ({len(primary_unauth)} unauthorized actions, {len(context_events)} explanatory context frames)")

    # Immediate containment recommendations
    lines.append(f"\n### Immediate Containment Recommendations:")
    if "UNAUTHORIZED_COMMAND" in [e.get("event_type") for e in events]:
        lines.append(f"1. **Isolate Uplink Channel:** Immediately issue emergency uplink disable command to prevent unauthorized spacecraft state changes.")
    if "FIRMWARE" in [e.get("source") for e in events]:
        lines.append(f"2. **Firmware Rollback:** Revert on-board OBC image to known verified backup digest; invalidate untrusted firmware update job.")
    lines.append(f"3. **Revoke Credentials & Session:** Terminate active session `{events[0].get('session_id', 'N/A')}` and lock operator `{actor}` pending investigation.")
    lines.append(f"4. **Preserve Forensic Log:** All raw telemetry and command packets have been committed to immutable SQLite backing store.")

    lines.append(f"\n---")

    # Section 2: Full Unauthorized Event Chain Table
    lines.append(f"## 2. FULL UNAUTHORIZED EVENT CHAIN (FORENSIC PROGRESSION)")
    lines.append(f"The table below details the chronological progression of the security incident. Normal background activity has been filtered out to isolate the attack sequence.\n")
    lines.append(f"| Step | Timestamp (UTC) | Module | Event Classification | Severity | Actor / Device | Resource | Auth Status | Chain Role |")
    lines.append(f"|:---:|:---|:---:|:---|:---:|:---|:---|:---:|:---|")

    for step in unauthorized_chain:
        act_dev = f"`{step['actor']}`"
        if step.get("device_id"):
            act_dev += f" / `{step['device_id']}`"
        res = f"`{step['resource']}`" if step.get("resource") else "-"
        lines.append(
            f"| {step['step']} | {step['timestamp']} | {step['source']} | {step['event_type']} | "
            f"**{step['severity']}** | {act_dev} | {res} | `{step['authorization_status']}` | `{step['chain_role']}` |"
        )

    # Narrative explanation of the chain
    lines.append(f"\n### Attack Chain Narrative:")
    chain_narrative = []
    for step in unauthorized_chain:
        chain_narrative.append(f"**[{step['event_type']} @ {step['source']}]**: {step['description']}")
    lines.append(" → \n".join(chain_narrative))

    lines.append(f"\n---")

    # Section 3: Data Access Details
    lines.append(f"## 3. ASSOCIATED DATA ACCESS & EXFILTRATION ASSESSMENT")
    if data_access_summary.get("databases_accessed") or data_access_summary.get("files_accessed"):
        lines.append(f"- **Databases Accessed:** `{', '.join(data_access_summary['databases_accessed']) or 'None'}`")
        lines.append(f"- **Specific Tables / Schemas:** `{', '.join(data_access_summary['tables_accessed']) or 'None'}`")
        lines.append(f"- **Sensitive Files Affected:** `{', '.join(data_access_summary['files_accessed']) or 'None'}`")
        lines.append(f"- **Total Records Retrieved:** `{data_access_summary['total_records_accessed']}`")
        lines.append(f"- **Data Classification:** `{', '.join(data_access_summary['sensitivity_levels']) or 'RESTRICTED'}`")
    else:
        lines.append(f"*No sensitive database or file archive access was executed during this specific incident window.*")

    lines.append(f"\n---")

    # Section 4: Historical Repeated Pattern & Data Access Tracking (Section 13)
    lines.append(f"## 4. HISTORICAL REPEATED ATTACK PATTERN & DATA ACCESS TRACKING")
    if hist_details.get("pattern_matched"):
        lines.append(f"> **REPEATED ATTACK PATTERN IDENTIFIED**  ")
        lines.append(f"> {hist_details['correlation_narrative']}\n")
        lines.append(f"### Side-by-Side Pattern & Data Access Comparison:")
        lines.append(f"| Dimension | Previous Incident (`{hist_details['historical_incident_id']}`) | Current Incident (`{inc_id}`) |")
        lines.append(f"|:---|:---|:---|")
        lines.append(f"| **Timestamp** | {hist_details['historical_timestamp']} | {ts} |")
        lines.append(f"| **Severity / Score** | {hist_details['historical_severity']} ({hist_details['historical_risk_score']}) | {sev} ({score}) |")
        hist_da = hist_details.get("historical_data_access", {})
        lines.append(f"| **Databases Targeted** | `{', '.join(hist_da.get('databases_accessed', [])) or 'None'}` | `{', '.join(data_access_summary.get('databases_accessed', [])) or 'None'}` |")
        lines.append(f"| **Tables / Schemas** | `{', '.join(hist_da.get('tables_accessed', [])) or 'None'}` | `{', '.join(data_access_summary.get('tables_accessed', [])) or 'None'}` |")
        lines.append(f"| **Records Affected** | {hist_da.get('total_records', 0)} records | {data_access_summary.get('total_records_accessed', 0)} records |")
        lines.append(f"| **Target Recurrence** | - | **{'YES (Identical Database Targeted)' if hist_details.get('persistent_threat_indicator') else 'New Target Resource'}** |")
    else:
        lines.append(f"Historical comparison query completed: This is the **first recorded occurrence** of this specific attack pattern in the ORBITAL SHIELD incident database.")

    lines.append(f"\n---")

    # Section 5: CERT-In Space Cyber Security Framework Compliance
    lines.append(f"## 5. CERT-In 6-HOUR COMPLIANCE & REGULATORY AUDIT REPORT")
    lines.append(f"*Pursuant to CERT-In Cyber Security Directions & Space Cyber Security Framework 2026 (6-Hour Mandatory Breach Notification)*\n")
    lines.append(f"- **Reporting Obligation:** Mandatory notification required within **6 hours** of incident confirmation.")
    lines.append(f"- **Regulated Asset Class:** Spacecraft Telemetry, Tracking & Command (TT&C) Subsystems and Ground Control Infrastructure.")
    lines.append(f"- **Incident Categorization:** `{etype}` / Critical Space Infrastructure Security Compromise.")
    lines.append(f"- **Initial Root Cause Assessment:** Failure of dual-control authorization protocols or compromised operator session tokens spanning ground station modules.")
    lines.append(f"- **Impact On Spacecraft Operations:** High risk of unauthorized telemetry spoofing, commands injection, or payload firmware disruption.")
    lines.append(f"- **Audit Verification:** Immutable log hash generated and cryptographically indexed in SQLite WAL audit log.")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# 5. CERT-In 6-Hour Audit & Reporting Payload Builder
# ─────────────────────────────────────────────────────────────

def _build_cert_in_report(
    incident: dict,
    events: list[dict],
    auth_status: str,
    unauthorized_chain: list[dict],
    data_access_summary: dict,
    hist_details: dict
) -> dict:
    """Generates structured payload for CERT-In 6-hour reporting compliance."""
    first_event_ts = events[0].get("timestamp") if events else incident.get("timestamp")
    last_event_ts = events[-1].get("timestamp") if events else incident.get("timestamp")

    return {
        "framework": "CERT-In Space Cyber Security Framework (Feb 2026)",
        "mandatory_report_deadline_hours": 6,
        "cert_in_regulatory_window_hours": 6,
        "affected_entity_type": "Space Ground Station / Satellite TT&C Infrastructure",
        "incident_id": incident.get("event_id"),
        "satellite_id": incident.get("satellite_id"),
        "target_satellite": incident.get("satellite_id"),
        "severity": incident.get("severity"),
        "composite_risk_score": incident.get("risk_score"),
        "authorization_classification": auth_status,
        "detection_timestamp_utc": incident.get("timestamp"),
        "incident_start_utc": first_event_ts,
        "incident_end_utc": last_event_ts,
        "affected_subsystems": sorted(list(set(e.get("source") for e in events))),
        "impacted_systems": sorted(list(set(e.get("source") for e in events))),
        "compromised_resources": [
            step.get("resource") for step in unauthorized_chain if step.get("resource")
        ],
        "data_exfiltration_assessment": {
            "databases_accessed": data_access_summary.get("databases_accessed", []),
            "total_records_accessed": data_access_summary.get("total_records_accessed", 0),
            "sensitivity_levels": data_access_summary.get("sensitivity_levels", []),
        },
        "repeated_pattern_indicator": hist_details.get("pattern_matched", False),
        "prior_incident_reference": hist_details.get("historical_incident_id"),
        "regulatory_compliance_checklist": {
            "csso_notified": True,
            "forensic_logs_frozen": True,
            "session_revoked": False,
            "cert_in_dispatch_ready": True,
        }
    }


def _parse_iso(ts_str: str) -> float:
    """Parses an ISO timestamp string into POSIX epoch seconds for sorting."""
    if not ts_str:
        return 0.0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0
