"""
ORBITAL_SHIELD - Telemetry Converter

Converts raw dataset records (pandas Series or dict) into standardized TelemetryEvent objects.
Preserves all 31 original dataset values while attaching standardized simulator metadata.
"""

from datetime import datetime, timezone
import math
from typing import Any, Dict, Mapping, Optional, Union
import uuid
import pandas as pd

from .models import TelemetryData, TelemetryEvent


# Type casting helper to ensure numpy/pandas types convert cleanly to Python standard types
INT_FIELDS = {
    "MsgId", "CmdCode", "SequenceCount", "MsgLength", "HasSecondaryHeader",
    "MsgType", "ApId", "HeaderVersion", "SegmentationFlag", "MessageCountInWindow",
    "UniqueMessageIDsInWindow", "AverageMessageLengthInWindow", "CommandErrorCounter",
    "IngestErrors", "MemoryPageFaults", "Label"
}

FLOAT_FIELDS = {
    "TimeRadians", "FlowLengthInWindow", "SlidingWindowMeanIntervalSec",
    "SlidingWindowMaxIntervalSec", "SlidingWindowMinIntervalSec", "MessageRateInWindow",
    "StdDevMessageLengthInWindow", "MemoryAnonMB", "MemoryFileMB",
    "MemoryKernelstackMB", "MemoryPageTableMB", "MemorySocketMB",
    "MemoryPercpuMB", "MemoryShmemMB", "MemorySlabUnreclaimableMB"
}


def _clean_row_data(row: Union[pd.Series, Mapping[str, Any], Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extracts and normalizes dataset fields from a pandas Series or dictionary into native types.
    """
    if isinstance(row, pd.Series):
        raw_dict = row.to_dict()
    elif isinstance(row, Mapping) or isinstance(row, dict):
        raw_dict = dict(row)
    else:
        raise TypeError(f"Expected pandas.Series or dict-like object, got {type(row)}")

    cleaned: Dict[str, Any] = {}

    for k in INT_FIELDS:
        if k not in raw_dict:
            raise KeyError(f"Missing required integer telemetry field: '{k}'")
        val = raw_dict[k]
        if pd.isna(val):
            raise ValueError(f"Value for field '{k}' cannot be NaN")
        cleaned[k] = int(val)

    for k in FLOAT_FIELDS:
        if k not in raw_dict:
            raise KeyError(f"Missing required float telemetry field: '{k}'")
        val = raw_dict[k]
        if pd.isna(val) or math.isnan(float(val)):
            raise ValueError(f"Value for field '{k}' cannot be NaN")
        cleaned[k] = float(val)

    return cleaned


def row_to_telemetry_event(
    row: Union[pd.Series, Mapping[str, Any], Dict[str, Any]],
    satellite_id: str = "SAT-ORBITAL-01",
    event_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> TelemetryEvent:
    """
    Converts a single dataset record into a standardized TelemetryEvent.

    Parameters:
    - row: pandas Series or dictionary containing the 31 dataset fields.
    - satellite_id: Identifier for the simulated satellite (default: "SAT-ORBITAL-01").
                    Documented as a Simulator-generated metadata field.
    - event_id: Optional unique event ID string. If not provided, a UUIDv4 is generated.
                Documented as a Simulator-generated metadata field.
    - timestamp: Optional ISO-8601 UTC timestamp string. If not provided, current UTC time is used.
                 Documented as a Simulator-generated metadata field.

    Returns:
    - Standardized TelemetryEvent instance with validated TelemetryData payload.
    """
    cleaned_data = _clean_row_data(row)
    telemetry_data = TelemetryData(**cleaned_data)

    generated_event_id = event_id if event_id is not None else str(uuid.uuid4())
    generated_timestamp = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()

    return TelemetryEvent(
        event_id=generated_event_id,
        timestamp=generated_timestamp,
        source="SATELLITE_SIMULATOR",
        satellite_id=satellite_id,
        event_type="TELEMETRY",
        data=telemetry_data,
    )


class TelemetryConverter:
    """
    Stateful / configurable converter utility for batch or stream conversion.
    """

    def __init__(self, satellite_id: str = "SAT-ORBITAL-01"):
        self.satellite_id = satellite_id

    def convert_row(
        self,
        row: Union[pd.Series, Mapping[str, Any], Dict[str, Any]],
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> TelemetryEvent:
        """Converts a row using the configured satellite_id."""
        return row_to_telemetry_event(
            row=row,
            satellite_id=self.satellite_id,
            event_id=event_id,
            timestamp=timestamp,
        )

    def convert_dataframe(self, df: pd.DataFrame) -> list[TelemetryEvent]:
        """Converts an entire pandas DataFrame into a list of TelemetryEvents."""
        events = []
        for _, row in df.iterrows():
            events.append(self.convert_row(row))
        return events
