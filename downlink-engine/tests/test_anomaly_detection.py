"""Unit tests for Isolation Forest Behavioral Anomaly Detection."""

import pytest
from app.services.anomaly_detector import AnomalyDetector
from app.services.feature_extractor import FeatureExtractor
from app.schemas.telemetry import TelemetryInput


@pytest.fixture
def detector():
    d = AnomalyDetector(auto_load=True)
    return d


@pytest.fixture
def extractor():
    return FeatureExtractor()


def test_model_is_loaded_and_ready(detector):
    """AnomalyDetector successfully loads Isolation Forest artifact."""
    assert detector.is_ready() is True


def test_nominal_telemetry_classified_as_normal(detector, extractor):
    """Standard operational telemetry parameters are classified as normal."""
    packet = TelemetryInput(
        timestamp="2026-08-25T02:00:00Z",
        satellite_id="SAT-EO-01",
        sequence_number=1001,
        temperature=23.5,
        battery=88.5,
        signal_strength=-70.2
    )
    features = extractor.extract_features(packet)
    result = detector.predict(features)

    assert result.is_anomaly is False
    assert result.severity == "NORMAL"
    assert result.anomaly_score >= 0.0
    assert result.confidence >= 0.70
    assert "nominal" in result.reason.lower()


def test_thermal_spike_detected(detector, extractor):
    """High temperature (e.g. 82°C) is flagged as behavioral anomaly."""
    packet = TelemetryInput(
        timestamp="2026-08-25T02:00:00Z",
        satellite_id="SAT-EO-01",
        sequence_number=1002,
        temperature=82.5,
        battery=88.0,
        signal_strength=-70.0
    )
    features = extractor.extract_features(packet)
    result = detector.predict(features)

    assert result.is_anomaly is True
    assert result.severity in ("HIGH", "CRITICAL")
    assert result.anomaly_score < 0.0
    assert "thermal" in result.reason.lower()


def test_signal_drop_detected(detector, extractor):
    """Severe RF attenuation (-125 dBm) is detected as an anomaly."""
    packet = TelemetryInput(
        timestamp="2026-08-25T02:00:00Z",
        satellite_id="SAT-EO-01",
        sequence_number=1003,
        temperature=24.0,
        battery=88.0,
        signal_strength=-125.0
    )
    features = extractor.extract_features(packet)
    result = detector.predict(features)

    assert result.is_anomaly is True
    assert result.severity in ("HIGH", "CRITICAL")
    assert "signal" in result.reason.lower() or "rf" in result.reason.lower()


def test_telemetry_burst_flood_detected(detector, extractor):
    """High packet frequency (300 pkts/min) is detected as behavioral anomaly."""
    features = {
        "temperature": 24.0,
        "temperature_change": 0.0,
        "battery": 88.0,
        "battery_change": 0.0,
        "signal_strength": -70.0,
        "signal_change": 0.0,
        "packet_frequency": 300.0,  # Telemetry flood!
        "time_difference": 0.2,
        "sequence_difference": 1.0
    }
    result = detector.predict(features)

    assert result.is_anomaly is True
    assert "burst" in result.reason.lower() or "flooding" in result.reason.lower() or "multi-variate" in result.reason.lower()
