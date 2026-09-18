"""
ORBITAL SHIELD — ML Correlation Brain
FastAPI application entrypoint

Endpoints:
  POST /events/ingest            — receive events from upstream modules
  GET  /correlations/active      — list open, unresolved incidents
  GET  /correlations/{id}        — full incident detail with raw event chain
  GET  /brain/status             — health + config transparency
  POST /brain/feedback           — CISO confirms/rejects a flagged incident
  POST /brain/retrain            — trigger threshold/model update (demo-friendly)
  GET  /brain/audit-log          — config change history (all BRAIN_CONFIG_UPDATED events)

Design: advisory-only, no enforcement logic anywhere in this service.
"""

import asyncio
import logging
import sys
import time
import httpx
import yaml
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Local modules ─────────────────────────────────────────────
from models.schemas import (
    IncomingEvent, IngestResponse,
    CorrelationIncident, IncidentSummary,
    FeedbackPayload, FeedbackResponse,
    BrainStatus, RuleStatus, RetrainResponse,
    AuditEvent, IncidentDocumentResponse,
    CisoNoteRequest, CertInSummaryRequest,
    SourceModule, SeverityLevel, ActionType
)
from db import database as db
from core import (
    ingestion, correlation_engine, scoring, ml_refiner,
    feedback as fb_module, model1_understanding, normalization
)

# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("orbital.main")

# ─────────────────────────────────────────────────────────────
# Startup / Shutdown
# ─────────────────────────────────────────────────────────────

_start_time = time.time()
_CONFIG_PATH = Path(__file__).parent / "config" / "rules.yaml"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB, sliding window, and ML model on startup."""
    logger.info("=" * 60)
    logger.info("ORBITAL SHIELD — ML Correlation Brain starting...")
    logger.info("=" * 60)

    # 1. Database
    db.init_db()

    # 2. Sliding window (config-driven)
    with open(_CONFIG_PATH) as f:
        config = yaml.safe_load(f)
    win_cfg = config.get("window", {})
    ingestion.init_window(
        window_seconds=win_cfg.get("in_memory_seconds", 1800),
        max_events=win_cfg.get("max_events_in_memory", 5000)
    )

    # 3. Attempt ML model load (transparent no-op if no model exists)
    ml_loaded = ml_refiner.load_model()
    logger.info("ML refiner active: %s", ml_loaded)

    logger.info("ML Correlation Brain is READY. Swagger docs at /docs")
    logger.info("ADVISORY ONLY — this module has zero enforcement authority.")

    yield  # ← application runs here

    logger.info("ML Correlation Brain shutting down.")


# ─────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="ORBITAL SHIELD — ML Correlation Brain",
    description="""
## ML Correlation Brain (Person 5 Module)

This service is the **correlation and reasoning layer** for the ORBITAL SHIELD
satellite ground-station cybersecurity platform.

### What this module does
- Receives structured security events from four upstream modules (DOWNLINK, UPLINK, FIRMWARE, ACCESS)
- Applies a **deterministic, explainable rule engine** to detect cross-module attack patterns
- Produces **scored, ranked incident reports** for human (CISO) review
- Learns from CISO feedback in a **human-in-the-loop, scheduled retraining pattern**

### What this module deliberately does NOT do
- ❌ No auto-blocking, auto-disabling, or auto-config-changing
- ❌ No deep learning (unexplainable, unjustifiable at this scope)
- ❌ No silent threshold or model updates (every change is logged)
- ❌ No direct access to other modules' databases

### Advisory-only design
This module's only output is a **flagged, explained, ranked incident report** that goes
to a human (CISO) for review. Enforcement authority rests entirely with the human operator.

### Integration
- **Upstream**: POST /events/ingest (all four modules send here)
- **Downstream**: GET /correlations/active and GET /correlations/{id} (dashboard reads here)
- **Audit**: incidents are also POSTed to Person 6's audit service
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────
# ROUTE 1: Event ingestion
# ─────────────────────────────────────────────────────────────

@app.post(
    "/events/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Event Ingestion"],
    summary="Receive a security event from an upstream module",
    description="""
Accepts a single security event from any of the four upstream modules
(DOWNLINK, UPLINK, FIRMWARE, ACCESS). Validates the schema, stores it,
adds it to the sliding window, and immediately evaluates all correlation rules.
Returns a list of any incident IDs generated as a result of this event.
    """
)
async def ingest_event(event: IncomingEvent, background_tasks: BackgroundTasks):
    # Validate + store + add to window
    event_dict = ingestion.ingest_event(event)

    # Get current window for correlation
    window = ingestion.get_window()
    window_events = window.get_all()

    # Extract features (used by correlation engine and ML refiner)
    features = ingestion.extract_features(event_dict, window_events)

    # Evaluate all correlation rules
    fired_rules = correlation_engine.evaluate_rules(event_dict, window_events)

    # Fetch existing open incidents for deduplication
    existing_incidents = db.fetch_open_incidents()

    incidents_created = []
    for match in fired_rules:
        matched_ids = [e["event_id"] for e in match["matched_events"]]

        # Deduplication guard
        if correlation_engine.is_duplicate_incident(match["rule_id"], matched_ids, existing_incidents):
            logger.info("Skipping duplicate incident for rule %s", match["rule_id"])
            continue

        # Score the incident (rule-only at this point)
        incident = scoring.compute_risk_score(match)

        # Optional ML refinement (bounded ±cap, transparent no-op if inactive)
        incident = ml_refiner.refine_score(incident, features)

        # MODEL 1 — Incident Understanding, Summarization, Chaining & Document Generation
        incident = model1_understanding.understand_incident(incident, match["matched_events"])

        # Persist to DB
        db.insert_incident(incident)

        # Mark contributing events as correlated
        db.mark_events_correlated(matched_ids)

        incidents_created.append(incident)
        logger.info("Incident created: %s | type=%s | severity=%s | score=%d | auth=%s",
                    incident["event_id"], incident["event_type"],
                    incident["severity"], incident["risk_score"],
                    incident.get("authorization_status"))

        # Forward to audit module in background (non-blocking)
        background_tasks.add_task(_forward_to_audit, incident)

    return IngestResponse(
        status="ACCEPTED",
        event_id=event.event_id,
        correlations_triggered=[inc["event_id"] for inc in incidents_created],
        message=(
            f"Event {event.event_id} ingested. "
            f"{len(incidents_created)} correlation incident(s) generated."
        )
    )


# ─────────────────────────────────────────────────────────────
# ROUTE 2: Active correlations (dashboard)
# ─────────────────────────────────────────────────────────────

@app.get(
    "/correlations/active",
    response_model=list[IncidentSummary],
    tags=["Correlations"],
    summary="List all open, unresolved correlated incidents",
    description="Returns a summary list of all incidents currently in OPEN status."
)
async def get_active_correlations():
    incidents = db.fetch_open_incidents()
    return [
        IncidentSummary(
            event_id=inc["event_id"],
            timestamp=inc["timestamp"],
            event_type=inc["event_type"],
            severity=inc["severity"],
            risk_score=inc["risk_score"],
            status=inc["status"],
            satellite_id=inc["satellite_id"],
            rule_name=inc["rule_name"],
            related_events_count=len(inc["related_events"])
        )
        for inc in incidents
    ]


# ─────────────────────────────────────────────────────────────
# ROUTE 3: Full incident detail (dashboard)
# ─────────────────────────────────────────────────────────────

@app.get(
    "/correlations/{incident_id}",
    tags=["Correlations"],
    summary="Get full incident detail with contributing raw events",
    description="""
Returns complete incident data including the chain of raw events that
triggered the correlation. Each contributing event is fetched from the
event store and returned in full.
    """
)
async def get_correlation_detail(incident_id: str):
    incident = db.fetch_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    # Attach the full raw event payloads
    raw_events = []
    with db.get_connection() as conn:
        for eid in incident["related_events"]:
            row = conn.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone()
            if row:
                raw_events.append(db._row_to_dict(row))

    # If Model 1 understanding was not previously run, generate it on demand
    if not incident.get("incident_document_md"):
        incident = model1_understanding.understand_incident(incident, raw_events)
        db.insert_incident(incident)

    return {
        **incident,
        "contributing_events": raw_events,
        "contributing_events_count": len(raw_events),
    }


# ─────────────────────────────────────────────────────────────
# ROUTE 3B: Model 1 Human-Readable Incident Document (CISO & CERT-In)
# ─────────────────────────────────────────────────────────────

@app.get(
    "/correlations/{incident_id}/document",
    response_model=IncidentDocumentResponse,
    tags=["Model 1 Incident Documents"],
    summary="Get complete human-readable Incident Document for CISO & CERT-In",
    description="""
Returns the human-readable Markdown incident document generated by Model 1,
along with structured forensic progression chains, data access summaries,
historical pattern comparisons, and CERT-In regulatory compliance checklists.
    """
)
async def get_incident_document(incident_id: str):
    incident = db.fetch_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    # Ensure document is generated
    if not incident.get("incident_document_md"):
        raw_events = []
        with db.get_connection() as conn:
            for eid in incident["related_events"]:
                row = conn.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone()
                if row:
                    raw_events.append(db._row_to_dict(row))
        incident = model1_understanding.understand_incident(incident, raw_events)
        db.insert_incident(incident)

    return IncidentDocumentResponse(
        incident_id=incident["event_id"],
        timestamp=incident["timestamp"],
        satellite_id=incident.get("satellite_id", "SAT-ORBITAL-01"),
        event_type=incident["event_type"],
        severity=incident["severity"],
        risk_score=incident["risk_score"],
        authorization_status=incident.get("authorization_status", "UNAUTHORIZED"),
        authorization_reason=incident.get("authorization_reason", "Forensic analysis executed."),
        document_markdown=incident.get("incident_document_md", ""),
        incident_document_md=incident.get("incident_document_md", ""),
        unauthorized_event_chain=incident.get("unauthorized_chain", []),
        data_access_summary=incident.get("data_access_summary", {}),
        historical_comparison=incident.get("historical_pattern_details", {}),
        cert_in_compliance=incident.get("cert_in_report", {}),
    )


# ─────────────────────────────────────────────────────────────
# ROUTE 3C: CERT-In 6-Hour Audit & Reporting Document
# ─────────────────────────────────────────────────────────────

@app.get(
    "/correlations/{incident_id}/cert-in",
    tags=["CERT-In Reporting"],
    summary="Get CERT-In 6-Hour Mandatory Audit & Breach Notification Document",
    description="Returns the structured compliance payload formatted for CERT-In regulatory reporting."
)
async def get_cert_in_report(incident_id: str):
    incident = db.fetch_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    if not incident.get("cert_in_report"):
        raw_events = []
        with db.get_connection() as conn:
            for eid in incident["related_events"]:
                row = conn.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone()
                if row:
                    raw_events.append(db._row_to_dict(row))
        incident = model1_understanding.understand_incident(incident, raw_events)
        db.insert_incident(incident)

    return incident.get("cert_in_report", {})


# ─────────────────────────────────────────────────────────────
# ROUTE 3D: CISO Notes & Observations Ingestion
# ─────────────────────────────────────────────────────────────

@app.post(
    "/ciso/notes",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Context Ingestion"],
    summary="Ingest human-entered CISO notes and observations",
    description="Normalizes human-entered CISO observations into the Common Event Model and ingests them into the event store and sliding window."
)
async def ingest_ciso_notes(payload: CisoNoteRequest, background_tasks: BackgroundTasks):
    import uuid
    note_event = IncomingEvent(
        event_id=f"NOTE-{uuid.uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc),
        source=SourceModule.CISO_NOTES,
        satellite_id=payload.satellite_id or "SAT-ORBITAL-01",
        event_type="CISO_OBSERVATION",
        severity=SeverityLevel.MEDIUM,
        confidence=1.0,
        description=payload.notes,
        action=ActionType.REVIEW,
        operator_id=payload.operator_id or payload.author,
        evidence={"author": payload.author, "classification": payload.classification, "incident_id": payload.incident_id},
        related_events=[payload.incident_id] if payload.incident_id else [],
        ciso_notes=payload.notes,
    )
    return await ingest_event(note_event, background_tasks)


# ─────────────────────────────────────────────────────────────
# ROUTE 3E: CERT-In External Advisory & Summary Ingestion
# ─────────────────────────────────────────────────────────────

@app.post(
    "/cert-in/summary",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Context Ingestion"],
    summary="Ingest external CERT-In advisory and log summaries",
    description="Normalizes external CERT-In advisories or log summaries into the Common Event Model."
)
async def ingest_cert_in_summary(payload: CertInSummaryRequest, background_tasks: BackgroundTasks):
    import uuid
    summary_id = payload.summary_id or payload.cert_in_reference or f"CERTIN-{uuid.uuid4().hex[:8].upper()}"
    title = payload.title or payload.cert_in_reference or "CERT-In Cyber Advisory"
    details = payload.details or payload.summary or title
    actions = payload.recommended_actions or payload.mandate_actions
    cert_event = IncomingEvent(
        event_id=summary_id,
        timestamp=datetime.now(timezone.utc),
        source=SourceModule.CERT_IN,
        satellite_id=payload.satellite_id or "SAT-ORBITAL-01",
        event_type="CERT_IN_ADVISORY",
        severity=SeverityLevel(payload.severity) if payload.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") else SeverityLevel.HIGH,
        confidence=0.95,
        description=f"{title}: {details}",
        action=ActionType.REVIEW,
        evidence={
            "threat_vectors": payload.threat_vectors,
            "recommended_actions": actions,
            "incident_id": payload.incident_id,
        },
    )
    return await ingest_event(cert_event, background_tasks)


# ─────────────────────────────────────────────────────────────
# ROUTE 3F: Historical Pattern & Data Access Queries
# ─────────────────────────────────────────────────────────────

@app.get(
    "/patterns/historical",
    tags=["Historical Analysis"],
    summary="Search historical repeated attack patterns and data access records",
    description="Searches historical incidents and retrieves all associated data access records across past incidents."
)
async def get_historical_patterns(rule_id: Optional[str] = None, event_type: Optional[str] = None, limit: int = 10):
    patterns = db.search_historical_patterns(rule_id=rule_id, event_type=event_type, limit=limit)
    incident_ids = [p["event_id"] for p in patterns]
    data_accesses = db.fetch_historical_data_access(incident_ids)
    return {
        "matched_incidents": patterns,
        "historical_data_access_records": data_accesses,
        "count": len(patterns),
    }


# ─────────────────────────────────────────────────────────────
# ROUTE 4: Brain status (health + config transparency)
# ─────────────────────────────────────────────────────────────

@app.get(
    "/brain/status",
    response_model=BrainStatus,
    tags=["Brain Management"],
    summary="Health check + current rule/threshold configuration",
    description="""
Returns the current health status of the ML Brain, along with the active
rule configuration and scoring weights. Designed for transparency — the
dashboard can show the CISO exactly what rules are active and at what thresholds.
    """
)
async def get_brain_status():
    with open(_CONFIG_PATH) as f:
        config = yaml.safe_load(f)

    rules_cfg   = config.get("rules", [])
    scoring_cfg = config.get("scoring", {})
    window_cfg  = config.get("window", {})

    active_rules = [
        RuleStatus(
            rule_id=r["id"],
            name=r["name"],
            enabled=r.get("enabled", True),
            incident_type=r["incident_type"],
            time_window_seconds=r["conditions"].get("time_window_seconds", 300),
            min_sources=r["conditions"].get("min_sources", 2),
            min_events=r["conditions"].get("min_events", 2),
        )
        for r in rules_cfg
    ]

    return BrainStatus(
        status="OK",
        version="1.0.0",
        uptime_seconds=round(time.time() - _start_time, 1),
        events_ingested=db.count_events(),
        incidents_generated=db.count_incidents(),
        open_incidents=db.count_open_incidents(),
        ml_layer_active=ml_refiner.is_active(),
        last_retrain=_get_last_retrain(),
        active_rules=active_rules,
        scoring_weights=scoring_cfg.get("weights", {}),
        config_version=_config_version(),
        window_seconds=window_cfg.get("in_memory_seconds", 1800),
    )


# ─────────────────────────────────────────────────────────────
# ROUTE 5: CISO feedback
# ─────────────────────────────────────────────────────────────

@app.post(
    "/brain/feedback",
    response_model=FeedbackResponse,
    tags=["Brain Management"],
    summary="Submit CISO verdict on a flagged incident",
    description="""
The ONLY mechanism by which the ML Brain receives labeled training data.
The verdict (CONFIRMED_REAL or FALSE_POSITIVE) is stored in the feedback_log
table — the growing labeled dataset. Learning happens only at scheduled
retrain time (POST /brain/retrain), never automatically per-feedback.
    """
)
async def submit_feedback(payload: FeedbackPayload):
    try:
        result = fb_module.submit_feedback(
            incident_id=payload.incident_id,
            verdict=payload.verdict.value,
            reviewer=payload.reviewer,
            notes=payload.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return FeedbackResponse(
        status="ACCEPTED",
        incident_id=payload.incident_id,
        verdict=payload.verdict.value,
        message=(
            f"Feedback stored. Incident {payload.incident_id} marked as {result['status_updated_to']}. "
            f"This verdict will be used in the next retrain cycle (POST /brain/retrain)."
        )
    )


# ─────────────────────────────────────────────────────────────
# ROUTE 6: Manual retrain trigger (demo-friendly)
# ─────────────────────────────────────────────────────────────

@app.post(
    "/brain/retrain",
    response_model=RetrainResponse,
    tags=["Brain Management"],
    summary="Trigger threshold adjustment + optional ML retraining",
    description="""
In production, this runs on a nightly schedule. For demo purposes, it can be
triggered manually. This endpoint:

1. Reads all accumulated CISO feedback since the last retrain
2. Adjusts rule time-window thresholds if a rule has produced too many false positives
3. Optionally retrains the ML classifier if ≥5 labeled samples are available
4. Validates the new model before deploying it (rejects if accuracy drops)
5. Logs EVERY change as a BRAIN_CONFIG_UPDATED event in the audit log

**This is the honest, professionally correct human-in-the-loop design.**
No unsupervised, autonomous learning ever happens.
    """
)
async def trigger_retrain():
    result = fb_module.run_retrain_job()
    return RetrainResponse(**result)


# ─────────────────────────────────────────────────────────────
# ROUTE 7: Config audit log
# ─────────────────────────────────────────────────────────────

@app.get(
    "/brain/audit-log",
    tags=["Brain Management"],
    summary="Get history of all brain config/threshold changes",
    description="""
Returns all BRAIN_CONFIG_UPDATED events — every threshold change and
model retrain is logged here with before/after values. Designed for
dashboard transparency and demo storytelling.
    """
)
async def get_audit_log():
    return {
        "config_changes": fb_module.get_config_audit_log(),
        "total": len(fb_module.get_config_audit_log()),
    }


# ─────────────────────────────────────────────────────────────
# ROUTE 8: Feedback log (for dashboard + demo)
# ─────────────────────────────────────────────────────────────

@app.get(
    "/brain/feedback-log",
    tags=["Brain Management"],
    summary="Get all CISO feedback records",
    description="Returns the complete labeled training dataset (feedback_log table)."
)
async def get_feedback_log():
    all_fb = db.fetch_all_feedback()
    return {"feedback": all_fb, "total": len(all_fb)}


# ─────────────────────────────────────────────────────────────
# ROUTE 9: Raw event store (for debugging / integration testing)
# ─────────────────────────────────────────────────────────────

@app.get(
    "/events/recent",
    tags=["Event Ingestion"],
    summary="List recently ingested raw events (debug / integration testing)",
)
async def get_recent_events(limit: int = 50):
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY ingested_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return {"events": [db._row_to_dict(r) for r in rows], "count": len(rows)}


# ─────────────────────────────────────────────────────────────
# Root health check
# ─────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"], summary="Root health check")
async def root():
    return {
        "service": "ORBITAL SHIELD — ML Correlation Brain",
        "status": "OK",
        "version": "1.0.0",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "docs": "/docs",
        "design_principle": "Advisory only — zero enforcement authority."
    }


# ─────────────────────────────────────────────────────────────
# Background helpers
# ─────────────────────────────────────────────────────────────

async def _forward_to_audit(incident: dict) -> None:
    """
    Forward a correlated incident to Person 6's audit service.
    Non-blocking, retries on failure. Config-driven endpoint.
    """
    try:
        with open(_CONFIG_PATH) as f:
            config = yaml.safe_load(f)
        audit_cfg = config.get("audit", {})
        endpoint  = audit_cfg.get("endpoint", "http://localhost:8006/audit/events")
        timeout   = audit_cfg.get("timeout_seconds", 5)
        retries   = audit_cfg.get("max_retries", 3) if audit_cfg.get("retry_on_failure") else 1

        payload = AuditEvent(
            event_id=incident["event_id"],
            timestamp=incident["timestamp"],
            source="ML_BRAIN",
            event_type=incident["event_type"],
            severity=incident["severity"],
            confidence=incident["confidence"],
            description=incident["description"],
            related_events=incident["related_events"],
            action=incident.get("action", "HUMAN_REVIEW"),
            risk_score=incident["risk_score"],
        ).model_dump(mode="json")

        async with httpx.AsyncClient(timeout=timeout) as client:
            for attempt in range(retries):
                try:
                    resp = await client.post(endpoint, json=payload)
                    if resp.status_code < 400:
                        logger.info("Forwarded %s to audit service (status=%d)", incident["event_id"], resp.status_code)
                        return
                    logger.warning("Audit forward attempt %d/%d failed: HTTP %d", attempt + 1, retries, resp.status_code)
                except httpx.RequestError as exc:
                    logger.warning("Audit forward attempt %d/%d error: %s", attempt + 1, retries, exc)
                if attempt < retries - 1:
                    await asyncio.sleep(1)

        logger.error("Could not forward %s to audit service after %d attempts", incident["event_id"], retries)

    except Exception as exc:
        logger.error("Audit forwarding failed for %s: %s", incident.get("event_id"), exc)


def _get_last_retrain() -> datetime | None:
    log = fb_module.get_config_audit_log()
    if log:
        try:
            return datetime.fromisoformat(log[0]["timestamp"].replace("Z", "+00:00"))
        except Exception:
            pass
    return None


def _config_version() -> str:
    """Simple version derived from config file mtime."""
    try:
        mtime = _CONFIG_PATH.stat().st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
    except Exception:
        return "unknown"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8005, reload=True)
