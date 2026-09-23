"""Baseline telemetry generator and Isolation Forest model training script."""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.services.feature_extractor import FeatureExtractor
from app.core.config import settings
from app.core.logging_config import setup_logging, get_logger

setup_logging()
logger = get_logger("scripts.train_model")


def generate_normal_baseline_dataset(
    num_samples: int = 10000,
    satellite_id: str = "SAT-EO-01",
    output_path: Path = settings.BASELINE_DATA_PATH
) -> pd.DataFrame:
    """
    Synthesize realistic normal Earth Observation satellite telemetry baseline dataset.
    Simulates Low Earth Orbit (LEO) temperature cycles, solar panel charging, and nominal RF links.
    """
    logger.info(f"Generating {num_samples} normal telemetry samples for baseline...")
    np.random.seed(42)

    start_time = datetime(2026, 8, 20, 0, 0, 0, tzinfo=timezone.utc)
    records = []

    # Orbit period: ~95 minutes (LEO orbit)
    orbit_period_seconds = 95.0 * 60.0

    current_time = start_time
    for seq in range(1, num_samples + 1):
        elapsed_sec = (current_time - start_time).total_seconds()
        orbit_phase = (elapsed_sec % orbit_period_seconds) / orbit_period_seconds

        # Temperature: sinusoidal orbital day/night cycle [18.0°C to 27.0°C] + noise
        temp_nominal = 22.5 + 4.5 * np.sin(2 * np.pi * orbit_phase)
        temperature = float(np.clip(temp_nominal + np.random.normal(0, 0.35), 16.0, 30.0))

        # Battery: charging in sunlight, discharging in eclipse [82% - 96%]
        bat_nominal = 89.0 + 7.0 * np.sin(2 * np.pi * orbit_phase)
        battery = float(np.clip(bat_nominal + np.random.normal(0, 0.25), 80.0, 98.0))

        # Signal strength: stable RF downlink [-73.0 to -67.0 dBm]
        signal_nominal = -70.0 + 3.0 * np.cos(4 * np.pi * orbit_phase)
        signal_strength = float(np.clip(signal_nominal + np.random.normal(0, 0.8), -76.0, -64.0))

        # LEO Orbital Ground Track Coordinates
        lat = float(60.0 * np.sin(2 * np.pi * orbit_phase))
        lon = float(((elapsed_sec / 240.0) % 360.0) - 180.0)

        ts_str = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        records.append({
            "timestamp": ts_str,
            "satellite_id": satellite_id,
            "sequence_number": seq,
            "temperature": round(temperature, 2),
            "battery": round(battery, 2),
            "signal_strength": round(signal_strength, 2),
            "latitude": round(lat, 4),
            "longitude": round(lon, 4),
            "packet_hash": None,
            "signature": None
        })

        # Advance timestamp by 6.0 seconds nominal (10 packets/minute) with small jitter
        jitter = np.random.uniform(-0.15, 0.15)
        current_time += timedelta(seconds=6.0 + jitter)

    df = pd.DataFrame(records)

    # Save to CSV
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info(f"Baseline normal telemetry dataset saved to '{output_path}' ({len(df)} records)")
    return df


def train_isolation_forest(
    baseline_csv_path: Path = settings.BASELINE_DATA_PATH,
    model_output_path: Path = settings.MODEL_PATH
) -> IsolationForest:
    """
    Train an Isolation Forest behavioral anomaly detector on baseline normal telemetry.
    """
    if not baseline_csv_path.exists():
        logger.info(f"Baseline CSV '{baseline_csv_path}' not found. Generating new baseline...")
        df = generate_normal_baseline_dataset(output_path=baseline_csv_path)
    else:
        logger.info(f"Loading baseline dataset from '{baseline_csv_path}'...")
        df = pd.read_csv(baseline_csv_path)

    # Extract behavioral multi-feature matrix
    logger.info("Extracting behavioral feature vectors...")
    extractor = FeatureExtractor()
    feature_df = extractor.extract_batch_dataframe(df)

    logger.info(f"Feature matrix extracted with shape: {feature_df.shape}")
    logger.info(f"Features: {list(feature_df.columns)}")

    # Initialize Isolation Forest
    # Contamination set to 0.01 since baseline represents almost exclusively nominal flight operations
    logger.info("Fitting IsolationForest model (n_estimators=100, contamination=0.01)...")
    clf = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination=0.01,
        random_state=42,
        n_jobs=-1
    )

    clf.fit(feature_df.values)

    # Evaluate baseline inliers
    scores = clf.decision_function(feature_df.values)
    preds = clf.predict(feature_df.values)
    normal_pct = (preds == 1).mean() * 100.0

    logger.info(f"Model training complete:")
    logger.info(f"  - Nominal classification rate on baseline: {normal_pct:.2f}%")
    logger.info(f"  - Decision function mean: {scores.mean():.4f}, std: {scores.std():.4f}")
    logger.info(f"  - Decision function min: {scores.min():.4f}, max: {scores.max():.4f}")

    # Save model artifact
    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_output_path)
    logger.info(f"Trained Isolation Forest saved to '{model_output_path}'")

    return clf


if __name__ == "__main__":
    logger.info("Starting Downlink Security Engine model training pipeline...")
    train_isolation_forest()
    logger.info("Pipeline completed successfully.")
