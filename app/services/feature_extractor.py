"""Feature extraction pipeline for satellite telemetry behavioral modeling."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union
import numpy as np
import pandas as pd

from app.schemas.telemetry import TelemetryInput
from app.models.telemetry import TelemetryRecord
from app.core.logging_config import get_logger

logger = get_logger("services.feature_extractor")


class FeatureExtractor:
    """
    Extracts multi-variate statistical and differential features from individual
    telemetry packets and sliding temporal windows.
    """

    FEATURE_NAMES = [
        "temperature",
        "temperature_change",
        "battery",
        "battery_change",
        "signal_strength",
        "signal_change",
        "packet_frequency",
        "time_difference",
        "sequence_difference",
    ]

    # Nominal default values for missing / initial state
    DEFAULT_TEMP = 24.0
    DEFAULT_BATTERY = 88.0
    DEFAULT_SIGNAL = -70.0
    NOMINAL_PACKET_INTERVAL_SEC = 6.0  # 10 packets per minute
    NOMINAL_PACKET_FREQ_PPM = 10.0

    def extract_features(
        self,
        telemetry: TelemetryInput,
        previous_record: Optional[Union[TelemetryRecord, TelemetryInput]] = None,
        history_window: Optional[List[Union[TelemetryRecord, TelemetryInput]]] = None
    ) -> Dict[str, float]:
        """
        Extract feature dictionary from a single telemetry packet and historical context.
        """
        temp = telemetry.temperature if telemetry.temperature is not None else self.DEFAULT_TEMP
        battery = telemetry.battery if telemetry.battery is not None else self.DEFAULT_BATTERY
        signal = telemetry.signal_strength if telemetry.signal_strength is not None else self.DEFAULT_SIGNAL

        # Parse current timestamp
        curr_dt = self._parse_iso_datetime(telemetry.timestamp)

        if previous_record is not None:
            prev_temp = previous_record.temperature if previous_record.temperature is not None else temp
            prev_battery = previous_record.battery if previous_record.battery is not None else battery
            prev_signal = previous_record.signal_strength if previous_record.signal_strength is not None else signal
            prev_seq = previous_record.sequence_number

            prev_dt = self._parse_iso_datetime(previous_record.timestamp)

            temp_change = temp - prev_temp
            battery_change = battery - prev_battery
            signal_change = signal - prev_signal
            seq_diff = float(telemetry.sequence_number - prev_seq)

            raw_time_diff = (curr_dt - prev_dt).total_seconds() if (curr_dt and prev_dt) else self.NOMINAL_PACKET_INTERVAL_SEC
            time_diff = max(0.001, raw_time_diff)
        else:
            # First packet baseline
            temp_change = 0.0
            battery_change = 0.0
            signal_change = 0.0
            seq_diff = 1.0
            time_diff = self.NOMINAL_PACKET_INTERVAL_SEC

        # Calculate packet frequency (packets per minute)
        packet_freq = self._calculate_frequency(time_diff)

        features = {
            "temperature": float(temp),
            "temperature_change": float(temp_change),
            "battery": float(battery),
            "battery_change": float(battery_change),
            "signal_strength": float(signal),
            "signal_change": float(signal_change),
            "packet_frequency": float(packet_freq),
            "time_difference": float(time_diff),
            "sequence_difference": float(seq_diff),
        }
        return features

    def extract_vector(self, features_dict: Dict[str, float]) -> np.ndarray:
        """Convert a feature dictionary into a 2D numpy array for scikit-learn."""
        vector = [features_dict[name] for name in self.FEATURE_NAMES]
        return np.array([vector], dtype=np.float64)

    def extract_batch_dataframe(self, df_or_records: Union[pd.DataFrame, List[Dict[str, Any]]]) -> pd.DataFrame:
        """
        Extract behavioral feature matrix from a chronological dataframe or list of telemetry dicts.
        Used primarily during offline baseline training.
        """
        if isinstance(df_or_records, list):
            df = pd.DataFrame(df_or_records)
        else:
            df = df_or_records.copy()

        # Ensure sorted chronologically
        if "sequence_number" in df.columns:
            df = df.sort_values(by="sequence_number").reset_index(drop=True)

        # Impute missing basics
        df["temperature"] = df["temperature"].fillna(self.DEFAULT_TEMP)
        df["battery"] = df["battery"].fillna(self.DEFAULT_BATTERY)
        df["signal_strength"] = df["signal_strength"].fillna(self.DEFAULT_SIGNAL)

        # Convert timestamps
        df["dt"] = pd.to_datetime(df["timestamp"].str.replace("Z", "+00:00"), utc=True)

        # Differential features
        df["temperature_change"] = df["temperature"].diff().fillna(0.0)
        df["battery_change"] = df["battery"].diff().fillna(0.0)
        df["signal_change"] = df["signal_strength"].diff().fillna(0.0)
        df["sequence_difference"] = df["sequence_number"].diff().fillna(1.0)

        # Time difference in seconds
        time_deltas = df["dt"].diff().dt.total_seconds().fillna(self.NOMINAL_PACKET_INTERVAL_SEC)
        df["time_difference"] = time_deltas.apply(lambda x: max(0.001, x) if pd.notnull(x) else self.NOMINAL_PACKET_INTERVAL_SEC)

        # Packet frequency (packets per minute rolling calculation)
        df["packet_frequency"] = (60.0 / df["time_difference"]).clip(lower=0.1, upper=500.0)

        return df[self.FEATURE_NAMES]

    def _parse_iso_datetime(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Safely parse ISO datetime string."""
        if not ts_str:
            return None
        try:
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _calculate_frequency(self, time_diff: float) -> float:
        """Calculate packet frequency in packets per minute from instantaneous inter-packet time."""
        if 0.001 <= time_diff <= 60.0:
            return min(60.0 / time_diff, 1000.0)
        elif time_diff > 60.0:
            # Long pause between sessions -> default to nominal rate
            return self.NOMINAL_PACKET_FREQ_PPM
        return self.NOMINAL_PACKET_FREQ_PPM
