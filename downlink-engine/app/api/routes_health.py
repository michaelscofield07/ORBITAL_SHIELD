"""Health check endpoint for system monitoring and integration readiness."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any

from app.db.database import get_db
from app.services.anomaly_detector import AnomalyDetector
from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger("api.health")

router = APIRouter(tags=["Health"])

# Global detector instance for fast health inspection
_anomaly_detector = AnomalyDetector(auto_load=False)


@router.get(
    "/health",
    summary="System Health & Readiness Check",
    description="Returns operational status of the Downlink Security Engine, ML model loading status, and database connectivity.",
    response_model=Dict[str, Any]
)
def get_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Inspect system health status."""
    # Check DB connectivity
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = f"unhealthy: {str(e)}"

    # Check model loading status
    model_loaded = settings.MODEL_PATH.exists()

    overall_status = "healthy" if db_status == "connected" and model_loaded else "degraded"

    return {
        "status": overall_status,
        "module": settings.MODULE_NAME,
        "version": settings.VERSION,
        "model_loaded": model_loaded,
        "database": db_status
    }
