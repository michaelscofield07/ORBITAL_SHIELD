"""Unit tests for Feature Extraction Pipeline."""

import pytest
from datetime import datetime, timezone, timedelta
import numpy as np

from app.schemas.telemetry import TelemetryInput
from app.models.telemetry import TelemetryRecord
from app.services.feature_extractor import FeatureExtractor


@pytest.fixture
def extractor():
    return FeatureExtractor()


def test_first_packet_feature_defaults(extractor):
    """Initial packet without history should yield zero differentials and nominal baseline defaults."""
    packet = TelemetryInput(
        timestamp="2026-08-25T02:00:00Z",
        satellite_id="SAT-EO-01",
        sequence_number=1,
        temperature=23.5,
        battery=88.0,
        signal_strength=-70.0
    )

    features = extractor.extract_features(packet, previous_record=None)

    assert features["temperature"] == 23.5
    assert features["temperature_change"] == 0.0
    assert features["battery"] == 88.0
    assert features["battery_change"] == 0.0
    assert features["signal_strength"] == -70.0
    assert features["signal_change"] == 0.0
    assert features["sequence_difference"] == 1.0
    assert features["time_difference"] == 6.0


def test_differential_feature_extraction(extractor):
    """Subsequent packet should calculate precise delta metrics."""
    prev = TelemetryRecord(
        sequence_number=10,
        timestamp="2026-08-25T02:00:00Z",
        satellite_id="SAT-EO-01",
        temperature=22.0,
        battery=88.0,
        signal_strength=-70.0
    )
    curr = TelemetryInput(
        timestamp="2026-08-25T02:00:06Z",
        satellite_id="SAT-EO-01",
        sequence_number=11,
        temperature=24.5,
        battery=87.5,
        signal_strength=-72.0
    )

    features = extractor.extract_features(curr, previous_record=prev)

    assert pytest.approx(features["temperature_change"], 0.01) == 2.5
    assert pytest.approx(features["battery_change"], 0.01) == -0.5
    assert pytest.approx(features["signal_change"], 0.01) == -2.0
    assert features["sequence_difference"] == 1.0
    assert pytest.approx(features["time_difference"], 0.01) == 6.0
    assert pytest.approx(features["packet_frequency"], 0.1) == 10.0


def test_feature_vector_conversion(extractor):
    """Feature dictionary converts to ordered numpy array for ML model."""
    packet = TelemetryInput(
        timestamp="2026-08-25T02:00:00Z",
        satellite_id="SAT-EO-01",
        sequence_number=1,
        temperature=24.0,
        battery=90.0,
        signal_strength=-68.0
    )
    features = extractor.extract_features(packet)
    vector = extractor.extract_vector(features)

    assert isinstance(vector, np.ndarray)
    assert vector.shape == (1, 9)
    assert vector[0][0] == 24.0


def test_batch_dataframe_extraction(extractor):
    """Batch extraction from list of records generates feature matrix with correct shape."""
    records = [
        {"timestamp": f"2026-08-25T02:00:{i*6:02d}Z", "satellite_id": "SAT-EO-01", "sequence_number": i+1, "temperature": 23.0 + i*0.1, "battery": 88.0 - i*0.1, "signal_strength": -70.0}
        for i in range(10)
    ]
    df = extractor.extract_batch_dataframe(records)

    assert len(df) == 10
    assert list(df.columns) == extractor.FEATURE_NAMES
    assert df["temperature_change"].iloc[1] > 0
