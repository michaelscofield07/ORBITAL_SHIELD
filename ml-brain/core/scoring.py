"""
ORBITAL SHIELD — ML Correlation Brain
Step 4: Additive risk scoring engine

Design principle: every point in the risk score is traceable back to a
specific event_type or structural factor. No black-box scoring.
Both rule_score and ml_adjustment are logged separately.
"""

import logging
import uuid
from datetime import datetime, timezone

from core.correlation_engine import load_config

logger = logging.getLogger("orbital.scoring")

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def compute_risk_score(match: dict) -> dict:
    """
    Step 4: Compute an additive risk score from a fired-rule match dict.
    Returns a CorrelationIncident-compatible dict (without ML adjustment).

    Scoring formula (from rules.yaml, fully editable):
      base_score = 0
      + weight per event_type present in matched events
      + multi_source_bonus × (distinct_sources - 1)

    Severity classification:
      score > CRITICAL threshold → CRITICAL
      score > HIGH threshold     → HIGH
      score > MEDIUM threshold   → MEDIUM
      else                       → LOW
    """
    config   = load_config()
    scoring  = config.get("scoring", {})
    weights  = scoring.get("weights", {})
    bonus    = scoring.get("multi_source_bonus", 10)
    tholds   = scoring.get("severity_thresholds", {"CRITICAL": 70, "HIGH": 40, "MEDIUM": 20})

    matched_events = match["matched_events"]
    sources_present = set(e["source"] for e in matched_events)
    event_types_present = set(e["event_type"] for e in matched_events)

    # ── Additive scoring with full breakdown ──────────────────
    score_breakdown: dict[str, int] = {}
    base_score = 0

    for etype in event_types_present:
        w = weights.get(etype, 0)
        if w > 0:
            base_score += w
            score_breakdown[etype] = w

    multi_source_bonus = bonus * max(0, len(sources_present) - 1)
    if multi_source_bonus > 0:
        score_breakdown["multi_source_bonus"] = multi_source_bonus
    base_score += multi_source_bonus

    # ── Severity classification ───────────────────────────────
    crit_t = tholds.get("CRITICAL", 70)
    high_t = tholds.get("HIGH", 40)
    med_t  = tholds.get("MEDIUM", 20)

    if base_score > crit_t:
        severity = "CRITICAL"
    elif base_score > high_t:
        severity = "HIGH"
    elif base_score > med_t:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # ── Average confidence across matched events ──────────────
    confidences = [e["confidence"] for e in matched_events]
    avg_confidence = round(sum(confidences) / len(confidences), 3) if confidences else 0.5

    # ── Build incident dict ───────────────────────────────────
    incident_id  = f"INC-{uuid.uuid4().hex[:8].upper()}"
    now_iso      = datetime.now(timezone.utc).isoformat()
    event_ids    = [e["event_id"] for e in matched_events]

    incident = {
        "event_id":       incident_id,
        "timestamp":      now_iso,
        "source":         "ML_BRAIN",
        "event_type":     match["incident_type"],
        "severity":       severity,
        "confidence":     avg_confidence,
        "description":    match["description"],
        "related_events": event_ids,
        "action":         "HUMAN_REVIEW",
        "risk_score":     base_score,
        "rule_id":        match["rule_id"],
        "rule_name":      match["rule_name"],
        "rule_score":     base_score,       # pre-ML score, logged separately
        "ml_adjustment":  0,                # filled in by ml_refiner if active
        "satellite_id":   match.get("satellite_id", "UNKNOWN"),
        "operator_id":    match.get("operator_id"),
        "session_id":     match.get("session_id"),
        "status":         "OPEN",
        "score_breakdown": score_breakdown,
    }

    logger.info(
        "Scored incident %s | rule=%s | score=%d | severity=%s | breakdown=%s",
        incident_id, match["rule_id"], base_score, severity, score_breakdown
    )
    return incident


def apply_severity_override(incident: dict, new_severity: str) -> dict:
    """
    Allows the ML refiner to escalate (never silently downgrade) severity
    after adjusting the risk score. Downgrade is capped — severity can only
    move down by one level at most to prevent ML over-suppression.
    """
    current_ord = _SEVERITY_ORDER.get(incident["severity"], 0)
    new_ord     = _SEVERITY_ORDER.get(new_severity, 0)

    if new_ord >= current_ord:
        incident["severity"] = new_severity
    elif current_ord - new_ord == 1:
        incident["severity"] = new_severity   # one-level downgrade allowed
    # else: ignore — ML can't silently suppress a HIGH → LOW jump
    return incident


def recompute_severity_from_score(incident: dict) -> dict:
    """
    After ML adjusts risk_score, recompute severity from the updated score
    using the same threshold logic as compute_risk_score().
    """
    config = load_config()
    tholds = config.get("scoring", {}).get("severity_thresholds",
                                           {"CRITICAL": 70, "HIGH": 40, "MEDIUM": 20})
    score = incident["risk_score"]
    if score > tholds.get("CRITICAL", 70):
        incident["severity"] = "CRITICAL"
    elif score > tholds.get("HIGH", 40):
        incident["severity"] = "HIGH"
    elif score > tholds.get("MEDIUM", 20):
        incident["severity"] = "MEDIUM"
    else:
        incident["severity"] = "LOW"
    return incident
