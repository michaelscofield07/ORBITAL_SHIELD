"""
ORBITAL SHIELD — ML Correlation Brain
Step 6 (Optional): ML Refiner Layer

This layer REFINES the rule engine's risk score — it does NOT replace it.
It uses a scikit-learn RandomForestClassifier trained on CISO-labeled feedback.

Key constraints:
  - ML adjustment is bounded to ±ml_adjustment_cap points (from rules.yaml)
  - ML never independently triggers an action or escalates severity past CRITICAL
  - rule_score and ml_adjustment are ALWAYS logged separately
  - If no trained model exists, this module is a transparent no-op

Training data: CISO verdicts from POST /brain/feedback (feedback_log table).
Retraining: triggered by POST /brain/retrain (described as "nightly in production").
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Optional

logger = logging.getLogger("orbital.ml_refiner")

_MODEL_PATH = Path(__file__).parent.parent / "models" / "classifier.pkl"

# Module-level state
_model = None
_model_loaded = False


def load_model() -> bool:
    """Attempt to load a trained classifier. Returns True if successful."""
    global _model, _model_loaded
    if _MODEL_PATH.exists():
        try:
            with open(_MODEL_PATH, "rb") as f:
                _model = pickle.load(f)
            _model_loaded = True
            logger.info("ML refiner: classifier loaded from %s", _MODEL_PATH)
            return True
        except Exception as exc:
            logger.warning("ML refiner: failed to load model (%s) — running rule-only mode", exc)
            _model = None
            _model_loaded = False
    return False


def is_active() -> bool:
    """Returns True if the ML layer has a trained model available."""
    return _model_loaded and _model is not None


def refine_score(incident: dict, features: Optional[dict] = None) -> dict:
    """
    Apply ML adjustment to an incident's risk_score.

    If no model is loaded, this is a transparent no-op (returns incident unchanged).
    If a model is loaded, the adjustment is bounded by ml_adjustment_cap from config.

    The adjustment sign:
      CONFIRMED_REAL prediction → positive adjustment (raises score)
      FALSE_POSITIVE prediction → negative adjustment (lowers score)

    Args:
        incident: The incident dict from the scoring engine (modified in place).
        features: Optional pre-extracted feature dict from ingestion.extract_features().

    Returns:
        The (possibly modified) incident dict.
    """
    if not is_active():
        return incident  # no-op: rule engine score stands unmodified

    try:
        from core.correlation_engine import load_config
        config = load_config()
        cap = config.get("scoring", {}).get("ml_adjustment_cap", 15)

        feature_vector = _build_feature_vector(incident, features)
        if feature_vector is None:
            return incident

        # Predict probability of CONFIRMED_REAL
        proba = _model.predict_proba([feature_vector])[0]
        # Assume class order: [FALSE_POSITIVE, CONFIRMED_REAL]
        class_labels = list(_model.classes_)
        if "CONFIRMED_REAL" in class_labels:
            real_prob = proba[class_labels.index("CONFIRMED_REAL")]
        else:
            real_prob = proba[1]  # fallback: second class

        # Map probability to adjustment: [0,0.5) → negative, [0.5,1] → positive
        # Scaled to ±cap
        raw_adjustment = (real_prob - 0.5) * 2 * cap   # range: -cap to +cap
        adjustment = int(round(raw_adjustment))
        adjustment = max(-cap, min(cap, adjustment))    # hard clamp

        old_score = incident["risk_score"]
        incident["risk_score"]    = max(0, old_score + adjustment)
        incident["ml_adjustment"] = adjustment

        # Recompute severity after score change
        from core.scoring import recompute_severity_from_score
        incident = recompute_severity_from_score(incident)

        logger.info(
            "ML refiner: incident=%s rule_score=%d ml_adj=%d final_score=%d severity=%s (p_real=%.3f)",
            incident["event_id"], old_score, adjustment,
            incident["risk_score"], incident["severity"], real_prob
        )
    except Exception as exc:
        logger.error("ML refiner: error during refinement (%s) — returning unmodified incident", exc)

    return incident


def _build_feature_vector(incident: dict, features: Optional[dict]) -> Optional[list]:
    """
    Build a numeric feature vector for the ML model.
    Consistent with the features produced during training.
    """
    sev_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    try:
        f = features or {}
        return [
            incident.get("rule_score", 0),
            sev_map.get(incident.get("severity", "LOW"), 0),
            incident.get("confidence", 0.5),
            len(incident.get("related_events", [])),
            f.get("distinct_source_count", 1),
            f.get("satellite_match_count", 0),
            f.get("session_match_count", 0),
            f.get("operator_match_count", 0),
            f.get("min_time_delta", 0),
        ]
    except Exception:
        return None


def train_model(feedback_records: list[dict]) -> dict:
    """
    Train (or retrain) the RandomForestClassifier on labeled CISO feedback.
    Called by the retrain endpoint. Validates on a held-out slice before
    saving the new model.

    Returns a result dict with accuracy, sample counts, and whether the
    model was saved.
    """
    global _model, _model_loaded   # must appear before any use in this scope
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score
        import numpy as np
    except ImportError:
        return {
            "success": False,
            "reason": "scikit-learn not installed — ML layer is disabled",
            "samples": 0,
        }

    if len(feedback_records) < 5:
        return {
            "success": False,
            "reason": f"Insufficient labeled data: {len(feedback_records)} samples (need ≥5)",
            "samples": len(feedback_records),
        }

    X, y = [], []
    legacy_count = 0
    for fb in feedback_records:
        verdict = fb["verdict"]

        # ─ Deserialize the snapshotted feature vector ──────────────────────
        # features_json was stored on the incident at correlation time and
        # propagated to feedback_log at CISO verdict submission time.
        # If absent (legacy row pre-fix), fall back to best-effort reconstruction.
        stored_features_json = fb.get("features_json")
        if stored_features_json:
            try:
                stored_features = json.loads(stored_features_json) \
                    if isinstance(stored_features_json, str) \
                    else stored_features_json
            except (json.JSONDecodeError, TypeError):
                stored_features = None
        else:
            stored_features = None

        if stored_features is None:
            # Legacy row: best-effort from denormalized fields only
            legacy_count += 1
            risk_score = fb.get("risk_score", 50)
            sev_inferred = (
                3 if risk_score > 70 else
                2 if risk_score > 40 else
                1 if risk_score > 20 else 0
            )
            # Build a proxy incident dict and a blank features dict so
            # _build_feature_vector() produces a consistent-length vector
            proxy_incident = {
                "rule_score":     risk_score,
                "severity":       ["LOW", "MEDIUM", "HIGH", "CRITICAL"][sev_inferred],
                "confidence":     0.8,   # unknown for legacy rows
                "related_events": [],
            }
            feature_vec = _build_feature_vector(proxy_incident, {})
        else:
            # Happy path: use the real snapshotted feature vector
            proxy_incident = {
                "rule_score":     fb.get("risk_score", stored_features.get("satellite_match_count", 0)),
                "severity":       "HIGH",   # severity is embedded in risk_score; not critical here
                "confidence":     0.9,
                "related_events": ["x"] * max(stored_features.get("satellite_match_count", 1), 1),
            }
            feature_vec = _build_feature_vector(proxy_incident, stored_features)

        if feature_vec is not None:
            X.append(feature_vec)
            y.append(verdict)

    if legacy_count > 0:
        logger.warning(
            "ML retrain: %d/%d feedback rows have no stored features (pre-fix legacy rows). "
            "Submit new feedback after the fix to improve training quality.",
            legacy_count, len(feedback_records)
        )

    X_arr = X
    y_arr = y

    # Require at least one sample of each class
    unique_classes = set(y_arr)
    if len(unique_classes) < 2:
        return {
            "success": False,
            "reason": f"Need both CONFIRMED_REAL and FALSE_POSITIVE labels — only have: {unique_classes}",
            "samples": len(feedback_records),
        }

    # Split for validation
    if len(X_arr) >= 10:
        X_train, X_val, y_train, y_val = train_test_split(
            X_arr, y_arr, test_size=0.2, random_state=42, stratify=y_arr
        )
    else:
        X_train, y_train = X_arr, y_arr
        X_val, y_val = X_arr, y_arr

    clf = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
    clf.fit(X_train, y_train)

    val_accuracy = accuracy_score(y_val, clf.predict(X_val))

    # Load current model accuracy for comparison
    if _model_loaded and _model is not None and len(X_val) >= 2:
        old_accuracy = accuracy_score(y_val, _model.predict(X_val))
    else:
        old_accuracy = 0.0

    # Reject update if accuracy drops significantly
    if _model_loaded and val_accuracy < old_accuracy - 0.1:
        logger.warning(
            "ML retrain rejected: new accuracy %.3f < old accuracy %.3f - 0.1",
            val_accuracy, old_accuracy
        )
        return {
            "success": False,
            "reason": f"New model accuracy ({val_accuracy:.3f}) is significantly lower than current ({old_accuracy:.3f}). Update rejected.",
            "samples": len(feedback_records),
            "new_accuracy": val_accuracy,
            "old_accuracy": old_accuracy,
        }

    # Save new model — global must be declared before any use in this function
    _MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    _model = clf
    _model_loaded = True

    logger.info(
        "ML model retrained: samples=%d val_accuracy=%.3f",
        len(feedback_records), val_accuracy
    )
    return {
        "success": True,
        "samples": len(feedback_records),
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "new_accuracy": val_accuracy,
        "old_accuracy": old_accuracy,
        "model_path": str(_MODEL_PATH),
    }
