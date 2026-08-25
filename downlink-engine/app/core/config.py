"""Application Configuration module for Downlink Security Engine."""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Base project directory (downlink-engine root)
# downlink-engine root is two levels up from this file (app/core/config.py)
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Also try the repo root (.env lives there in integration-final)
_REPO_ENV = BASE_DIR.parent / ".env"

# Load .env — prefer repo-root .env (integration-final layout), fall back to module-local
for _env_candidate in [_REPO_ENV, BASE_DIR / ".env"]:
    if _env_candidate.exists():
        load_dotenv(dotenv_path=_env_candidate, override=False)
        break
else:
    load_dotenv()


class Settings:
    """System configuration parameters."""

    PROJECT_NAME: str = "ORBITAL SHIELD - Downlink Security Engine"
    MODULE_NAME: str = "downlink-engine"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/downlink"

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'downlink.db'}")

    # Model and Baseline Paths
    MODEL_PATH: Path = Path(os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "isolation_forest.joblib")))
    BASELINE_DATA_PATH: Path = Path(os.getenv("BASELINE_DATA_PATH", str(BASE_DIR / "data" / "baseline" / "sample_normal_telemetry.csv")))

    # Satellite identifier
    SATELLITE_ID: str = os.getenv("SATELLITE_ID", "SAT-EO-01")

    # Integrity verification tolerances
    TIMESTAMP_TOLERANCE_SECONDS: float = float(os.getenv("TIMESTAMP_TOLERANCE_SECONDS", "30.0"))
    TIMESTAMP_MAX_AGE_SECONDS: float = float(os.getenv("TIMESTAMP_MAX_AGE_SECONDS", "86400.0"))

    # Anomaly detector thresholds
    # IsolationForest: decision_function < 0 is considered anomalous by default
    ANOMALY_THRESHOLD: float = float(os.getenv("ANOMALY_THRESHOLD", "0.0"))
    HIGH_SEVERITY_THRESHOLD: float = float(os.getenv("HIGH_SEVERITY_THRESHOLD", "-0.15"))
    CRITICAL_SEVERITY_THRESHOLD: float = float(os.getenv("CRITICAL_SEVERITY_THRESHOLD", "-0.30"))

    # Feature extraction sliding window size
    SEQUENCE_WINDOW_SIZE: int = int(os.getenv("SEQUENCE_WINDOW_SIZE", "100"))

    # Downstream service URLs (consumed by downlink routes that forward events)
    MLBRAIN_URL: str = os.getenv("MLBRAIN_URL", "http://localhost:8005/events/ingest")
    AUDIT_URL: str = os.getenv("AUDIT_URL", "http://localhost:8006/audit/events")

    # Server settings
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("DOWNLINK_PORT", os.getenv("PORT", "8001")))  # B1: was 8000
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()
