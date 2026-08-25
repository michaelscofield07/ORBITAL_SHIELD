"""Machine Learning Behavioral Anomaly Detection Service using Isolation Forest."""

from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.schemas.telemetry import AnomalyResult
from app.services.feature_extractor import FeatureExtractor
from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger("services.anomaly_detector")


class ModelNotLoadedException(Exception):
    """Raised when the Isolation Forest model artifact cannot be found or loaded."""
    pass


class AnomalyDetector:
    """
    Executes behavioral anomaly scoring and diagnostics on extracted satellite telemetry features
    using a pre-trained scikit-learn IsolationForest model combined with operational baseline bounds.
    """

    # Earth Observation Baseline Operating Limits (SAT-EO-01)
    BASELINE_LIMITS = {
        "temperature": (15.0, 32.0),
        "temperature_change": (-3.0, 3.0),
        "battery": (70.0, 100.0),
        "battery_change": (-2.0, 2.0),
        "signal_strength": (-85.0, -60.0),
        "signal_change": (-5.0, 5.0),
        "packet_frequency": (5.0, 30.0),
        "time_difference": (1.0, 15.0),
        "sequence_difference": (0.5, 1.5),
    }

    def __init__(self, model_path: Optional[Path] = None, auto_load: bool = True):
        self.model_path = model_path or settings.MODEL_PATH
        self.model: Optional[IsolationForest] = None
        self.feature_extractor = FeatureExtractor()
        if auto_load:
            self.load_model()

    def load_model(self) -> None:
        """Load trained Isolation Forest model from disk."""
        if not self.model_path.exists():
            logger.warning(
                f"Model file not found at '{self.model_path}'. "
                "Anomaly detection will fail until scripts/train_model.py is executed."
            )
            return

        try:
            self.model = joblib.load(self.model_path)
            logger.info(f"Loaded Isolation Forest model successfully from '{self.model_path}'")
        except Exception as e:
            logger.error(f"Failed to load Isolation Forest model from '{self.model_path}': {e}")
            raise ModelNotLoadedException(f"Failed to load model file: {e}") from e

    def is_ready(self) -> bool:
        """Check if model is currently loaded and ready for inference."""
        return self.model is not None

    def predict(self, features: Dict[str, float]) -> AnomalyResult:
        """
        Evaluate behavioral features and return an AnomalyResult combining Isolation Forest
        decision score and operational envelope bounds.
        """
        if self.model is None:
            if self.model_path.exists():
                self.load_model()
            else:
                raise ModelNotLoadedException(
                    f"Anomaly detection model is not loaded. Please train the model by running 'python scripts/train_model.py'."
                )

        feature_vector = self.feature_extractor.extract_vector(features)

        # Scikit-learn raw decision function (higher is more normal, lower is outlier)
        ml_score = float(self.model.decision_function(feature_vector)[0])
        ml_pred = int(self.model.predict(feature_vector)[0])

        # Calculate max domain limit violation ratio across telemetry dimensions
        max_violation = 0.0
        for k, (low, high) in self.BASELINE_LIMITS.items():
            val = features.get(k)
            if val is not None:
                span = high - low
                if val < low:
                    violation = (low - val) / span
                    max_violation = max(max_violation, violation)
                elif val > high:
                    violation = (val - high) / span
                    max_violation = max(max_violation, violation)

        # Calibrated anomaly score: baseline score penalized by feature violation magnitude
        if max_violation > 0.0:
            calibrated_score = ml_score - (max_violation * 0.4)
            is_anomaly = True
        else:
            calibrated_score = ml_score
            is_anomaly = (ml_score < settings.ANOMALY_THRESHOLD) or (ml_pred == -1)

        confidence = self._compute_confidence(calibrated_score, is_anomaly)
        severity = self._compute_severity(calibrated_score, is_anomaly)
        reason = self._generate_diagnostic_reason(features, is_anomaly, calibrated_score)

        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=round(calibrated_score, 4),
            confidence=round(confidence, 3),
            severity=severity,
            reason=reason
        )

    def _compute_confidence(self, score: float, is_anomaly: bool) -> float:
        """Calculate normalized confidence metric [0.0 - 1.0]."""
        if is_anomaly:
            conf = 0.70 + min(0.29, abs(score) * 1.5)
            return min(conf, 0.99)
        else:
            conf = 0.75 + min(0.24, max(0.0, score) * 1.2)
            return min(conf, 0.99)

    def _compute_severity(self, score: float, is_anomaly: bool) -> str:
        """Classify severity level based on calibrated anomaly score."""
        if not is_anomaly:
            return "NORMAL"

        if score <= settings.CRITICAL_SEVERITY_THRESHOLD:
            return "CRITICAL"
        elif score <= settings.HIGH_SEVERITY_THRESHOLD:
            return "HIGH"
        elif score <= -0.05:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_diagnostic_reason(
        self,
        features: Dict[str, float],
        is_anomaly: bool,
        score: float
    ) -> str:
        """Synthesize explainable diagnostic reason describing feature deviations."""
        if not is_anomaly:
            return "Telemetry parameters conform to baseline nominal operational profile."

        reasons = []
        temp = features.get("temperature", 0.0)
        temp_min, temp_max = self.BASELINE_LIMITS["temperature"]
        if temp > temp_max:
            reasons.append(f"Thermal spike detected: temperature {temp:.1f}°C exceeds nominal ceiling {temp_max:.1f}°C")
        elif temp < temp_min:
            reasons.append(f"Thermal drop detected: temperature {temp:.1f}°C below nominal floor {temp_min:.1f}°C")

        sig = features.get("signal_strength", 0.0)
        sig_min, sig_max = self.BASELINE_LIMITS["signal_strength"]
        if sig < sig_min:
            reasons.append(f"Severe RF attenuation: signal {sig:.1f} dBm below nominal floor {sig_min:.1f} dBm")
        elif sig > sig_max:
            reasons.append(f"Unusually high RF signal: {sig:.1f} dBm exceeds nominal ceiling {sig_max:.1f} dBm")

        freq = features.get("packet_frequency", 0.0)
        freq_min, freq_max = self.BASELINE_LIMITS["packet_frequency"]
        if freq > freq_max:
            reasons.append(f"Telemetry burst/flooding: {freq:.1f} pkts/min exceeds nominal limit {freq_max:.1f} pkts/min")

        bat = features.get("battery", 0.0)
        bat_min, _ = self.BASELINE_LIMITS["battery"]
        if bat < bat_min:
            reasons.append(f"Critical battery depletion: {bat:.1f}% below operational reserve {bat_min:.1f}%")

        if not reasons:
            reasons.append(f"Multi-variate statistical anomaly detected (isolation forest score: {score:.3f})")

        return "; ".join(reasons)
