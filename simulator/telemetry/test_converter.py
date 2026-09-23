"""
Unit tests for ORBITAL_SHIELD Telemetry Event Models and Converter.
"""

from datetime import datetime
from pathlib import Path
import uuid
import pandas as pd
import pytest
from pydantic import ValidationError

from simulator.telemetry.models import TelemetryData, TelemetryEvent
from simulator.telemetry.converter import TelemetryConverter, row_to_telemetry_event


@pytest.fixture
def sample_raw_row_dict():
    """A sample dictionary representing a single valid dataset row."""
    return {
        "MsgId": 6323,
        "CmdCode": 0,
        "TimeRadians": 1.682673,
        "SequenceCount": 0,
        "MsgLength": 8,
        "HasSecondaryHeader": 1,
        "MsgType": 1,
        "ApId": 179,
        "HeaderVersion": 0,
        "SegmentationFlag": 4,
        "FlowLengthInWindow": 1.715681,
        "SlidingWindowMeanIntervalSec": 1.715681,
        "SlidingWindowMaxIntervalSec": 1.715681,
        "SlidingWindowMinIntervalSec": 1.715681,
        "MessageCountInWindow": 2,
        "UniqueMessageIDsInWindow": 2,
        "AverageMessageLengthInWindow": 8,
        "MessageRateInWindow": 0.10,
        "StdDevMessageLengthInWindow": 0.0,
        "CommandErrorCounter": 0,
        "IngestErrors": 0,
        "MemoryAnonMB": 5.550781,
        "MemoryFileMB": 4.539062,
        "MemoryKernelstackMB": 0.781250,
        "MemoryPageTableMB": 0.296875,
        "MemorySocketMB": 0.023438,
        "MemoryPercpuMB": 0.000515,
        "MemoryShmemMB": 1.253906,
        "MemorySlabUnreclaimableMB": 0.727631,
        "MemoryPageFaults": 0,
        "Label": 3,
    }


def test_row_to_telemetry_event_from_dict(sample_raw_row_dict):
    """Test converting a dictionary row into a TelemetryEvent."""
    event = row_to_telemetry_event(sample_raw_row_dict)

    # Verify outer structure
    assert isinstance(event, TelemetryEvent)
    assert event.source == "SATELLITE_SIMULATOR"
    assert event.satellite_id == "SAT-ORBITAL-01"
    assert event.event_type == "TELEMETRY"
    assert isinstance(event.event_id, str)
    assert len(event.event_id) > 0
    assert isinstance(event.timestamp, str)
    # Validate timestamp format
    datetime.fromisoformat(event.timestamp)

    # Verify data payload preservation
    data = event.data
    assert isinstance(data, TelemetryData)
    assert data.MsgId == 6323
    assert data.CmdCode == 0
    assert pytest.approx(data.TimeRadians, 1e-6) == 1.682673
    assert data.MsgLength == 8
    assert data.ApId == 179
    assert pytest.approx(data.MemoryAnonMB, 1e-6) == 5.550781
    assert data.Label == 3


def test_row_to_telemetry_event_from_real_dataset():
    """Test converting actual rows from the CSV dataset."""
    dataset_path = Path(__file__).resolve().parent.parent / "data" / "consolidated_dataset_raw.csv"
    assert dataset_path.exists(), f"Dataset not found at {dataset_path}"

    df = pd.read_csv(dataset_path, nrows=10)
    for idx, row in df.iterrows():
        event = row_to_telemetry_event(row)
        assert event.source == "SATELLITE_SIMULATOR"
        assert event.event_type == "TELEMETRY"
        assert event.data.MsgId == int(row["MsgId"])
        assert event.data.CmdCode == int(row["CmdCode"])
        assert pytest.approx(event.data.TimeRadians, 1e-6) == float(row["TimeRadians"])
        assert event.data.Label == int(row["Label"])


def test_custom_metadata_parameters(sample_raw_row_dict):
    """Test overriding satellite_id, event_id, and timestamp."""
    custom_id = "custom-evt-999"
    custom_sat = "CUBESAT-ALPHA"
    custom_ts = "2026-08-24T12:00:00+00:00"

    event = row_to_telemetry_event(
        sample_raw_row_dict,
        satellite_id=custom_sat,
        event_id=custom_id,
        timestamp=custom_ts,
    )

    assert event.event_id == custom_id
    assert event.satellite_id == custom_sat
    assert event.timestamp == custom_ts
    assert event.source == "SATELLITE_SIMULATOR"
    assert event.event_type == "TELEMETRY"


def test_telemetry_converter_class(sample_raw_row_dict):
    """Test TelemetryConverter stateful wrapper."""
    converter = TelemetryConverter(satellite_id="SAT-OPS-02")
    event = converter.convert_row(sample_raw_row_dict)

    assert event.satellite_id == "SAT-OPS-02"
    assert event.data.MsgId == sample_raw_row_dict["MsgId"]


def test_batch_dataframe_conversion(sample_raw_row_dict):
    """Test batch conversion of a DataFrame."""
    df = pd.DataFrame([sample_raw_row_dict, sample_raw_row_dict])
    converter = TelemetryConverter(satellite_id="SAT-FLEET-01")
    events = converter.convert_dataframe(df)

    assert len(events) == 2
    assert all(isinstance(e, TelemetryEvent) for e in events)
    assert events[0].event_id != events[1].event_id  # Unique UUIDs


def test_missing_field_raises_error(sample_raw_row_dict):
    """Test that missing required fields raise appropriate KeyError."""
    incomplete_dict = dict(sample_raw_row_dict)
    del incomplete_dict["MsgId"]

    with pytest.raises(KeyError, match="MsgId"):
        row_to_telemetry_event(incomplete_dict)


def test_nan_field_raises_error(sample_raw_row_dict):
    """Test that NaN values raise ValueError."""
    invalid_dict = dict(sample_raw_row_dict)
    invalid_dict["MemoryAnonMB"] = float("nan")

    with pytest.raises(ValueError, match="MemoryAnonMB"):
        row_to_telemetry_event(invalid_dict)


def test_json_serialization(sample_raw_row_dict):
    """Test JSON serialization and deserialization roundtrip."""
    event = row_to_telemetry_event(sample_raw_row_dict)
    json_str = event.model_dump_json()

    assert '"source":"SATELLITE_SIMULATOR"' in json_str
    assert '"event_type":"TELEMETRY"' in json_str

    deserialized = TelemetryEvent.model_validate_json(json_str)
    assert deserialized == event
    assert deserialized.data.MsgId == 6323
