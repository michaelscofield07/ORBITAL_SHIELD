"""
ORBITAL SHIELD — Access Security Service (Module 4)
FastAPI service exposing ground station / operator access security detection API endpoints.

Default Port: 8002
Swagger UI: http://localhost:8002/docs
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import asyncio
import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from core.adapter import MockJSONInputAdapter
from core.engine import AccessSecurityEngine
from core.event_generator import EventGenerator
from models.schemas import (
    AccessLogRecord,
    AccessAnalysisRequest,
    AccessAnalysisResponse,
    SecurityEvent,
)

from dotenv import load_dotenv

# Load shared .env from repo root (integration-final layout)
_REPO_ENV = Path(__file__).resolve().parent.parent / ".env"
if _REPO_ENV.exists():
    load_dotenv(dotenv_path=_REPO_ENV, override=False)
else:
    load_dotenv()

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MOCK_DATA_PATH = DATA_DIR / "mock_access_logs.json"
ML_BRAIN_URL = os.environ.get("MLBRAIN_URL", os.environ.get("ML_BRAIN_URL", "http://localhost:8005/events/ingest"))
AUDIT_URL = os.environ.get("AUDIT_URL", "http://localhost:8006/audit/events")
_ACCESS_PORT = int(os.environ.get("ACCESS_PORT", "8002"))  # B2: was hardcoded 8001

app = FastAPI(
    title="ORBITAL SHIELD — Access Security (Module 4)",
    version="1.0.0",
    description="Ground Station / Operator Access Security Anomaly & Threat Detection Module."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engine and event store instances
engine = AccessSecurityEngine()
event_history: List[SecurityEvent] = []


@app.get("/health", summary="Health and Module Status")
def get_health() -> Dict[str, Any]:
    """
    Returns module status, engine configuration parameters, and ML Brain endpoint URL.
    """
    return {
        "module": "access_security",
        "status": "HEALTHY",
        "port": _ACCESS_PORT,
        "mock_dataset_available": MOCK_DATA_PATH.exists(),
        "trusted_devices_count": len(engine.trusted_devices),
        "failed_attempts_threshold": engine.failed_attempts_threshold,
        "ml_brain_endpoint": ML_BRAIN_URL,
        "audit_endpoint": AUDIT_URL,
        "cached_events_count": len(event_history),
    }


@app.post("/access/analyze", response_model=AccessAnalysisResponse, summary="Analyze Access Log Records")
async def analyze_access_endpoint(request: AccessAnalysisRequest) -> AccessAnalysisResponse:
    """
    Processes incoming access telemetry records, evaluates them against Access Security rules,
    generates canonical SecurityEvent payloads, and forwards suspicious events to ML Brain.
    """
    if not request.records:
        raise HTTPException(status_code=400, detail="Record list cannot be empty.")

    # Run detection engine
    detections = engine.evaluate_batch(request.records)
    
    generated_events: List[SecurityEvent] = []
    suspicious_count = 0
    ml_forwarded = False
    last_ml_resp: Optional[Dict[str, Any]] = None

    sat_id = request.satellite_id or "SAT-EO-01"

    for det in detections:
        event = EventGenerator.generate_security_event(det, satellite_id=sat_id)
        generated_events.append(event)
        event_history.append(event)

        if det.is_suspicious:
            suspicious_count += 1
            # Forward suspicious event to ML Brain
            forward_res = await EventGenerator.forward_to_ml_brain_async(event, ml_brain_url=ML_BRAIN_URL)
            if forward_res.get("forwarded"):
                ml_forwarded = True
            last_ml_resp = forward_res

            # B10 fix: also forward to audit service (fire-and-forget, non-blocking)
            import asyncio
            asyncio.ensure_future(_forward_to_audit(event))

    return AccessAnalysisResponse(
        analyzed_count=len(request.records),
        suspicious_count=suspicious_count,
        events=generated_events,
        ml_brain_forwarded=ml_forwarded,
        ml_brain_response=last_ml_resp,
    )


async def _forward_to_audit(event: SecurityEvent) -> None:
    """Fire-and-forget forwarding to audit service. Mirrors uplink_P4's pattern."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(AUDIT_URL, json=event.model_dump())
    except Exception as exc:
        import logging as _log
        _log.getLogger("AccessSecurity").warning(f"Audit forward failed: {exc}")



@app.get("/access/events", response_model=List[SecurityEvent], summary="Get Generated Security Events")
def get_security_events() -> List[SecurityEvent]:
    """
    Returns history of SecurityEvents generated during this runtime session.
    Provides Person 6 Audit Layer and Dashboard query access.
    """
    return event_history


@app.post("/access/mock/run", response_model=AccessAnalysisResponse, summary="Run Analysis on Mock Dataset")
async def run_mock_dataset_endpoint() -> AccessAnalysisResponse:
    """
    Loads records from mock_access_logs.json, runs detection engine, generates SecurityEvents,
    and returns complete summary.
    """
    adapter = MockJSONInputAdapter(MOCK_DATA_PATH)
    try:
        records = adapter.fetch_records()
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to read mock data: {err}")

    # Reset engine internal state before mock run
    engine.reset_state()

    req = AccessAnalysisRequest(records=records, satellite_id="SAT-EO-01")
    return await analyze_access_endpoint(req)


def run():
    """Start uvicorn server on env-configured port (default 8002)."""
    uvicorn.run("main:app", host="0.0.0.0", port=_ACCESS_PORT, reload=True)


if __name__ == "__main__":
    run()
