"""Downlink Security Engine primary API routes and WebSocket streaming."""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session
import json

from app.db.database import get_db
from app.schemas.telemetry import (
    TelemetryInput,
    TelemetryAnalysisResponse,
    TelemetryVerificationEvent,
)
from app.schemas.security_event import SecurityEvent, DailyReportResponse
from app.services.telemetry_processor import TelemetryProcessor
from app.services.report_generator import ReportGenerator
from app.services.anomaly_detector import AnomalyDetector, ModelNotLoadedException
from app.db.repository import TelemetryRepository
from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger("api.downlink")

router = APIRouter(prefix=settings.API_V1_PREFIX, tags=["Downlink Security"])


@router.post(
    "/analyze",
    response_model=TelemetryAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Ingested Downlink Telemetry Packet",
    description="Ingests a single satellite telemetry packet, performs deterministic integrity checks and Isolation Forest anomaly analysis, stores records, and returns full security findings with any generated SecurityEvent and verification event."
)
def analyze_telemetry(
    telemetry: TelemetryInput,
    db: Session = Depends(get_db)
) -> TelemetryAnalysisResponse:
    """Analyze a single downlink telemetry packet."""
    try:
        processor = TelemetryProcessor(db=db)
        response = processor.process_telemetry(telemetry)
        return response
    except ModelNotLoadedException as e:
        logger.error(f"ML Model error during telemetry processing: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error analyzing telemetry packet: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while processing downlink telemetry."
        )


@router.get(
    "/verification-events",
    response_model=List[TelemetryVerificationEvent],
    summary="Fetch Verified Telemetry Events for Module 4 (Access Security)",
    description="Returns verified telemetry/access records with boolean spoof_detected, integrity_verified, and verification_status (VERIFIED / SPOOFED / TAMPERED)."
)
def get_verification_events(
    satellite_id: Optional[str] = Query(None, description="Filter by satellite ID"),
    verification_status: Optional[str] = Query(None, description="Filter: VERIFIED, SPOOFED, TAMPERED, ANOMALOUS"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    db: Session = Depends(get_db)
) -> List[TelemetryVerificationEvent]:
    """Provide verified telemetry event feed for Module 4 Access Security correlation."""
    repo = TelemetryRepository(db)
    sat_id = satellite_id or settings.SATELLITE_ID
    records = repo.get_recent_telemetry_window(satellite_id=sat_id, limit=limit)
    events_map = {e.timestamp: e for e in repo.get_security_events(satellite_id=sat_id, limit=limit)}

    feed: List[TelemetryVerificationEvent] = []
    for r in records:
        integrity_ok = (r.integrity_status == "VALID")
        spoof = r.is_anomaly

        if not integrity_ok:
            v_status = "TAMPERED"
            res = "ALERT"
        elif spoof:
            v_status = "SPOOFED"
            res = "ALERT"
        else:
            v_status = "VERIFIED"
            res = "SUCCESS"

        if verification_status and v_status != verification_status.upper():
            continue

        sec_evt = events_map.get(r.timestamp)

        feed.append(
            TelemetryVerificationEvent(
                timestamp=r.timestamp,
                user_id="operator_01",
                source_ip="10.0.0.15",
                device_id="GS-DEVICE-01",
                action="DOWNLINK_RECEIVE",
                result=res,
                role="operator",
                previous_role="operator",
                satellite_id=r.satellite_id,
                session_id="SESSION-001",
                sequence_number=r.sequence_number,
                spoof_detected=spoof,
                integrity_verified=integrity_ok,
                verification_status=v_status,
                security_event_id=sec_evt.event_id if sec_evt else None,
                evidence={
                    "anomaly_score": r.anomaly_score,
                    "temperature": r.temperature,
                    "battery": r.battery,
                    "signal_strength": r.signal_strength,
                    "integrity_status": r.integrity_status
                }
            )
        )
    return feed


@router.get(
    "/events",
    response_model=List[SecurityEvent],
    summary="Query Standardized Security Events",
    description="Retrieves security events recorded by the Downlink Security Engine with filtering by severity, event type, satellite ID, and timestamp range. Consumed by Person 5 (ML Correlation Engine) and Person 6 (Dashboard)."
)
def get_security_events(
    satellite_id: Optional[str] = Query(None, description="Filter events by satellite ID (e.g. SAT-EO-01)"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    event_type: Optional[str] = Query(None, description="Filter by event type (e.g. TELEMETRY_ANOMALY, TELEMETRY_INTEGRITY_FAILURE)"),
    start_time: Optional[str] = Query(None, description="ISO-8601 start timestamp filter"),
    end_time: Optional[str] = Query(None, description="ISO-8601 end timestamp filter"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    db: Session = Depends(get_db)
) -> List[SecurityEvent]:
    """Fetch stored SecurityEvents."""
    repo = TelemetryRepository(db)
    return repo.get_security_events(
        satellite_id=satellite_id,
        severity=severity,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
        limit=limit
    )


@router.get(
    "/report",
    response_model=DailyReportResponse,
    summary="Generate Daily Telemetry Security Report",
    description="Generates an aggregated daily summary report of telemetry volume, anomaly counts, integrity violations, severity distributions, and actionable security recommendations for Person 6 (Audit & Dashboard)."
)
def get_daily_report(
    satellite_id: Optional[str] = Query(None, description="Satellite identifier (defaults to configured baseline SAT-EO-01)"),
    date: Optional[str] = Query(None, description="Report date in YYYY-MM-DD format (defaults to current UTC date)"),
    db: Session = Depends(get_db)
) -> DailyReportResponse:
    """Generate daily telemetry security summary."""
    report_gen = ReportGenerator(db)
    return report_gen.generate_daily_report(satellite_id=satellite_id, report_date=date)


@router.get(
    "/status",
    summary="Downlink Engine Operational State",
    description="Returns current operational telemetry status, total packet volume processed, and latest sequence state."
)
def get_engine_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Get operational state of the downlink engine."""
    repo = TelemetryRepository(db)
    sat_id = settings.SATELLITE_ID
    latest = repo.get_latest_telemetry(sat_id)
    total_packets = repo.get_total_telemetry_count(sat_id)
    detector = AnomalyDetector(auto_load=True)

    return {
        "satellite_id": sat_id,
        "total_packets_processed": total_packets,
        "latest_sequence_number": latest.sequence_number if latest else None,
        "latest_timestamp": latest.timestamp if latest else None,
        "latest_temperature": latest.temperature if latest else None,
        "latest_integrity_status": latest.integrity_status if latest else None,
        "model_loaded": detector.is_ready()
    }


@router.post(
    "/reset",
    summary="Reset Engine Database State",
    description="Clears all stored telemetry records and security events for a clean demonstration run."
)
def reset_engine_state(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Reset all stored telemetry records and events."""
    repo = TelemetryRepository(db)
    repo.clear_all()
    return {"status": "SUCCESS", "message": "Telemetry database and security events reset successfully."}


@router.websocket("/stream")
async def websocket_telemetry_stream(
    websocket: WebSocket,
    db: Session = Depends(get_db)
):
    """
    Bidirectional WebSocket endpoint for high-throughput continuous telemetry streaming.
    Accepts JSON telemetry packets and immediately streams back structured analysis responses.
    """
    await websocket.accept()
    logger.info("WebSocket telemetry streaming client connected.")
    processor = TelemetryProcessor(db=db)

    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                data = json.loads(raw_text)
                telemetry = TelemetryInput(**data)
                response = processor.process_telemetry(telemetry)
                # Send back the serialized analysis response
                await websocket.send_text(response.model_dump_json())
            except ValueError as ve:
                logger.warning(f"Invalid telemetry payload received over WebSocket: {ve}")
                error_resp = {
                    "status": "VALIDATION_ERROR",
                    "error": str(ve)
                }
                await websocket.send_text(json.dumps(error_resp))
            except Exception as e:
                logger.error(f"Error processing streaming telemetry packet: {e}")
                error_resp = {
                    "status": "PROCESSING_ERROR",
                    "error": str(e)
                }
                await websocket.send_text(json.dumps(error_resp))
    except WebSocketDisconnect:
        logger.info("WebSocket telemetry streaming client disconnected.")
