"""
ORBITAL SHIELD — ML Correlation Brain
Feedback loop + self-training logic

This implements the CISO-in-the-loop learning pattern:
  1. CISO submits a verdict (CONFIRMED_REAL / FALSE_POSITIVE)
  2. Verdict is stored in feedback_log — the labeled training dataset
  3. POST /brain/retrain (manually triggered / nightly in production) reads
     accumulated feedback and adjusts thresholds + optionally retrains ML
  4. EVERY threshold or model change is logged as BRAIN_CONFIG_UPDATED
     with before/after values — never silently applied

This module never auto-applies feedback. It only prepares the update
and commits it when explicitly triggered.
"""

import logging
import uuid
import yaml
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db import database as db

logger = logging.getLogger("orbital.feedback")

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"


# ─────────────────────────────────────────────────────────────
# Feedback submission (Step 2 of the loop)
# ─────────────────────────────────────────────────────────────

def submit_feedback(incident_id: str, verdict: str, reviewer: str, notes: str | None) -> dict:
    """
    Store a CISO verdict in feedback_log. Also updates the incident's status.
    This does NOT retrain anything — learning happens only at retrain time.
    """
    incident = db.fetch_incident_by_id(incident_id)
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    # Map verdict to incident status
    status_map = {
        "CONFIRMED_REAL": "CONFIRMED",
        "FALSE_POSITIVE": "FALSE_POSITIVE",
    }
    new_status = status_map.get(verdict, "CONFIRMED")

    # Update incident record
    db.update_incident_status(
        incident_id=incident_id,
        status=new_status,
        reviewer=reviewer,
        notes=notes,
        reviewed_at=datetime.now(timezone.utc).isoformat()
    )

    # Retrieve the feature vector that was snapshotted at correlation time.
    # Propagate it into feedback_log so train_model() can use real features
    # instead of placeholder constants — this is the core parity fix.
    features_json: str | None = incident.get("features_json")
    # features_json may already be a str (from DB) or None (legacy rows)

    # Store in feedback_log (the labeled training dataset — never delete)
    db.insert_feedback(
        incident_id=incident_id,
        verdict=verdict,
        reviewer=reviewer,
        notes=notes,
        rule_id=incident.get("rule_id"),
        risk_score=incident.get("risk_score"),
        features_json=features_json,
    )

    logger.info("Feedback stored: incident=%s verdict=%s reviewer=%s features_available=%s",
                incident_id, verdict, reviewer, features_json is not None)
    return {
        "incident_id": incident_id,
        "verdict": verdict,
        "reviewer": reviewer,
        "status_updated_to": new_status,
    }


# ─────────────────────────────────────────────────────────────
# Retrain job (Step 4 of the loop)
# ─────────────────────────────────────────────────────────────

def run_retrain_job() -> dict:
    """
    The retrain job. Described as "runs nightly via scheduler in production".
    For demo purposes, triggered by POST /brain/retrain.

    Steps:
      1. Load all unused feedback from feedback_log
      2. Adjust rule thresholds based on false-positive patterns
      3. Optionally retrain the ML classifier
      4. Validate before applying (model) or log before applying (thresholds)
      5. Log every change as BRAIN_CONFIG_UPDATED — auditable, never silent
    """
    feedback_config = _load_feedback_config()
    fp_threshold    = feedback_config.get("false_positive_threshold", 3)
    step_seconds    = feedback_config.get("threshold_widening_step", 30)
    max_window      = feedback_config.get("max_threshold_seconds", 3600)
    min_for_ml      = feedback_config.get("min_feedback_for_retrain", 5)

    unused_feedback = db.fetch_unused_feedback()
    all_feedback    = db.fetch_all_feedback()

    if not unused_feedback:
        return {
            "status": "SKIPPED",
            "reason": "No new feedback since last retrain",
            "feedback_samples": 0,
            "thresholds_changed": [],
            "ml_retrained": False,
            "ml_accuracy": None,
            "config_updated": False,
            "audit_event_id": None,
            "message": "No unused feedback found. Run POST /brain/feedback to add CISO verdicts first."
        }

    # ── Load current config ───────────────────────────────────
    with open(_CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)
    new_config = deepcopy(config)

    threshold_changes: list[dict] = []

    # ── Step 1: Threshold adjustment from false-positive patterns ─
    # Count FPs per rule from unused feedback
    fp_by_rule: dict[str, int] = {}
    for fb in unused_feedback:
        if fb["verdict"] == "FALSE_POSITIVE" and fb.get("rule_id"):
            fp_by_rule[fb["rule_id"]] = fp_by_rule.get(fb["rule_id"], 0) + 1

    for rule in new_config.get("rules", []):
        rule_id = rule["id"]
        fp_count = fp_by_rule.get(rule_id, 0)
        if fp_count >= fp_threshold:
            old_window = rule["conditions"].get("time_window_seconds", 300)
            new_window = min(old_window + step_seconds, max_window)
            if new_window != old_window:
                rule["conditions"]["time_window_seconds"] = new_window
                change = {
                    "rule_id":     rule_id,
                    "field":       "time_window_seconds",
                    "before":      old_window,
                    "after":       new_window,
                    "fp_count":    fp_count,
                    "reason":      f"Rule {rule_id} produced {fp_count} false positives in this batch (threshold={fp_threshold}). Window widened by {step_seconds}s.",
                }
                threshold_changes.append(change)
                logger.info("Threshold widened: rule=%s %ds → %ds (FP count=%d)", rule_id, old_window, new_window, fp_count)

    # ── Step 2: Write updated config if thresholds changed ────
    audit_event_id = None
    config_written = False
    if threshold_changes:
        with open(_CONFIG_PATH, "w") as f:
            yaml.dump(new_config, f, default_flow_style=False, sort_keys=False)
        config_written = True
        logger.info("Config updated with %d threshold changes", len(threshold_changes))

        # Log every change as a BRAIN_CONFIG_UPDATED audit event
        for change in threshold_changes:
            eid = f"CFG-{uuid.uuid4().hex[:8].upper()}"
            audit_event_id = eid
            db.insert_config_audit({
                "audit_event_id": eid,
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "change_type":    "THRESHOLD_CHANGE",
                "rule_id":        change["rule_id"],
                "field_name":     change["field"],
                "before_value":   change["before"],
                "after_value":    change["after"],
                "triggered_by":   "retrain_job",
                "notes":          change["reason"],
            })

    # ── Step 3: ML retraining (optional, if scikit-learn available) ─
    ml_result = {"success": False, "reason": "Not attempted", "samples": len(all_feedback)}
    if len(all_feedback) >= min_for_ml:
        from core.ml_refiner import train_model
        ml_result = train_model(all_feedback)
        if ml_result.get("success"):
            eid = f"CFG-{uuid.uuid4().hex[:8].upper()}"
            audit_event_id = audit_event_id or eid
            db.insert_config_audit({
                "audit_event_id": eid,
                "timestamp":      datetime.now(timezone.utc).isoformat(),
                "change_type":    "MODEL_RETRAIN",
                "rule_id":        None,
                "field_name":     "classifier",
                "before_value":   f"accuracy={ml_result.get('old_accuracy', 0):.3f}",
                "after_value":    f"accuracy={ml_result.get('new_accuracy', 0):.3f}",
                "triggered_by":   "retrain_job",
                "notes":          f"Retrained on {ml_result['samples']} samples. Val accuracy: {ml_result.get('new_accuracy', 0):.3f}",
            })
            config_written = True

    # ── Step 4: Mark feedback as used ─────────────────────────
    db.mark_feedback_used([fb["id"] for fb in unused_feedback])

    return {
        "status":             "COMPLETED",
        "feedback_samples":   len(unused_feedback),
        "thresholds_changed": threshold_changes,
        "ml_retrained":       ml_result.get("success", False),
        "ml_accuracy":        ml_result.get("new_accuracy"),
        "config_updated":     config_written,
        "audit_event_id":     audit_event_id,
        "message": (
            f"Retrain completed. {len(threshold_changes)} threshold(s) adjusted. "
            f"ML retrained: {ml_result.get('success', False)}. "
            f"Every change is logged in the config_audit table as BRAIN_CONFIG_UPDATED."
        ),
    }


# ─────────────────────────────────────────────────────────────
# Config audit log (for /brain/status transparency)
# ─────────────────────────────────────────────────────────────

def get_config_audit_log() -> list[dict]:
    return db.fetch_config_audit_log()


# ─────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────

def _load_feedback_config() -> dict:
    with open(_CONFIG_PATH, "r") as f:
        return yaml.safe_load(f).get("feedback", {})
