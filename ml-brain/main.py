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
import json
import logging
import sys
import time
import uuid
import httpx
import yaml
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, AsyncGenerator


from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

# ── Local modules ─────────────────────────────────────────────
from models.schemas import (
    IncomingEvent, IngestResponse,
    CorrelationIncident, IncidentSummary,
    FeedbackPayload, FeedbackResponse,
    BrainStatus, RuleStatus, RetrainResponse,
    AuditEvent, IncidentDocumentResponse,
    CisoNoteRequest, CertInSummaryRequest,
    RecoveryGuidanceRecord, Model3RunRequest,
    Model3RunResponse, GuidanceReviewPayload,
    GuidanceEditPayload, MarkAppliedPayload, VerifyPayload, VerificationResultResponse,
    Model3StatusCounts, Model3StatusResponse,
    IncidentModel3StatusResponse,
    SourceModule, SeverityLevel, ActionType
)
from db import database as db
from core import (
    ingestion, correlation_engine, scoring, ml_refiner,
    feedback as fb_module, model1_understanding, normalization,
    model3_recovery, llm_client
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

# SSE Subscribers set for live module health streaming
_sse_subscribers: set[asyncio.Queue] = set()


def _sse_subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_subscribers.add(q)
    return q


def _sse_unsubscribe(q: asyncio.Queue) -> None:
    _sse_subscribers.discard(q)


async def _broadcast_sse_event(source: str, event_type: str, timestamp: str) -> None:
    """Push a small status message to every connected SSE client."""
    data = json.dumps({"source": source, "event_type": event_type,
                       "timestamp": timestamp, "status": "RECEIVED"})
    for q in list(_sse_subscribers):
        try:
            q.put_nowait(data)
        except asyncio.QueueFull:
            pass  # slow client — drop rather than block


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

    # 4. Asynchronous background model warmup (loads weights into VRAM before demo queries)
    asyncio.create_task(llm_client.warmup_models_async())

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

        # Snapshot the feature vector onto the incident so it is stored in DB.
        # This closes the training/inference parity gap: the exact same feature
        # values used during inference will be retrieved at retrain time instead
        # of being rebuilt from placeholder constants.
        incident["features_json"] = features

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

        # Forward to audit module in background (detached non-blocking task)
        # Never blocks event ingestion response even if port 8006 is offline
        asyncio.create_task(_forward_to_audit(incident))

    # Broadcast to SSE subscribers (additive only, does not change response)
    background_tasks.add_task(
        _broadcast_sse_event,
        source=event.source.value if hasattr(event.source, "value") else str(event.source),
        event_type=event.event_type,
        timestamp=event.timestamp.isoformat() if hasattr(event.timestamp, "isoformat") else str(event.timestamp),
    )

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
            related_events_count=len(inc.get("related_events") or []),
            description=inc.get("description"),
            confidence=inc.get("confidence"),
            related_events=inc.get("related_events") or [],
            action=inc.get("action"),
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

    # Look up SPARTA / CERT-In metadata for the rule that fired this incident
    with open(_CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)
    rule_meta = next(
        (r for r in cfg.get("rules", []) if r["id"] == incident.get("rule_id")),
        {}
    )

    # If Model 1 understanding was not previously run, generate it on demand
    if not incident.get("incident_document_md"):
        incident = model1_understanding.understand_incident(incident, raw_events)
        db.insert_incident(incident)

    return {
        **incident,
        "contributing_events": raw_events,
        "contributing_events_count": len(raw_events),
        "sparta_technique_id": rule_meta.get("sparta_technique_id"),
        "cert_in_category":    rule_meta.get("cert_in_category"),
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
        cert_in_context=incident.get("cert_in_context", {}),
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
        cert_in_reference=payload.cert_in_reference or summary_id,
        title=title,
        threat_vectors=payload.threat_vectors or [],
        recommended_actions=actions or [],
        mandate_actions=payload.mandate_actions or [],
        cert_in_details=details,
        related_events=[payload.incident_id] if payload.incident_id else [],
        evidence={
            "cert_in_reference": payload.cert_in_reference or summary_id,
            "title": title,
            "threat_vectors": payload.threat_vectors or [],
            "recommended_actions": actions or [],
            "incident_id": payload.incident_id,
        },
    )
    ingest_res = await ingest_event(cert_event, background_tasks)

    # If linked to an existing incident, immediately refresh that incident's Model 1 understanding
    if payload.incident_id:
        inc = db.fetch_incident_by_id(payload.incident_id)
        if inc:
            raw_events = []
            with db.get_connection() as conn:
                for eid in inc.get("related_events", []):
                    row = conn.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone()
                    if row:
                        raw_events.append(db._row_to_dict(row))
            updated_inc = model1_understanding.understand_incident(inc, raw_events)
            db.insert_incident(updated_inc)

    return ingest_res


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
            sparta_technique_id=r.get("sparta_technique_id"),
            cert_in_category=r.get("cert_in_category"),
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
# ROUTE 6B: Model 3 — Retrain + Secure & Recover Guidance Pipeline
# ─────────────────────────────────────────────────────────────

@app.post(
    "/brain/model3/run",
    response_model=Model3RunResponse,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Execute Model 3: Retrain + Secure & Recover Guidance Pipeline",
    description="""
Executes the unified Model 3 workflow:
1. Runs the human-in-the-loop retraining cycle (threshold adjustment + ML refiner model update).
2. Generates actionable Secure & Recover Guidance for specified or active incidents via local Ollama LLMs (DeepSeek-R1 / Qwen2.5) with automatic deterministic fallback.
3. Persists each generated guidance plan with review_status='PENDING_REVIEW'.
    """
)
async def run_model3_pipeline_endpoint(payload: Optional[Model3RunRequest] = None):
    p = payload or Model3RunRequest()
    result = model3_recovery.run_model3_pipeline(
        incident_ids=p.incident_ids,
        run_retrain=p.run_retrain
    )
    return Model3RunResponse(**result)


def _format_guidance_record(row: dict) -> RecoveryGuidanceRecord:
    """Helper to convert a recovery_guidance database row to RecoveryGuidanceRecord."""
    guidance_dict = (
        json.loads(row["guidance_json"])
        if isinstance(row.get("guidance_json"), str)
        else row.get("guidance_json", {})
    )
    return RecoveryGuidanceRecord(
        guidance_id=row["guidance_id"],
        incident_id=row["incident_id"],
        generated_at=row["generated_at"],
        model_used=row["model_used"],
        llm_used=bool(row.get("llm_used")),
        guidance=guidance_dict,
        review_status=row.get("review_status", "PENDING_REVIEW"),
        reviewed_by=row.get("reviewed_by"),
        review_notes=row.get("review_notes"),
        reviewed_at=row.get("reviewed_at"),
        ciso_edited=row.get("ciso_edited"),
        edited_by=row.get("edited_by"),
        edited_at=row.get("edited_at"),
        remediation_applied_at=row.get("remediation_applied_at"),
        remediation_applied_by=row.get("remediation_applied_by"),
        remediation_notes=row.get("remediation_notes"),
        verification_result=row.get("verification_result"),
        verified_at=row.get("verified_at"),
        verification_evidence=row.get("verification_evidence"),
    )


@app.get(
    "/correlations/{id}/recovery-guidance",
    response_model=RecoveryGuidanceRecord,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Get or generate Secure & Recover Guidance for an incident",
    description="""
Returns existing recovery guidance for the incident. If no guidance has been
generated yet, dynamically runs the Model 3 guidance generator, persists
the resulting plan as PENDING_REVIEW, and returns it.
    """
)
async def get_incident_recovery_guidance(id: str):
    inc = db.fetch_incident_by_id(id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {id} not found")

    existing = db.fetch_recovery_guidance_by_incident(id)
    if existing:
        return _format_guidance_record(existing)

    # Dynamic generation if not yet created
    raw_events = []
    with db.get_connection() as conn:
        for eid in inc.get("related_events", []):
            row = conn.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone()
            if row:
                raw_events.append(db._row_to_dict(row))

    guidance_dict, model_used, llm_used = model3_recovery.generate_recovery_guidance(
        incident=inc,
        events=raw_events
    )

    guidance_id = f"GUIDE-{uuid.uuid4().hex[:8].upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    record = {
        "guidance_id": guidance_id,
        "incident_id": id,
        "generated_at": now_iso,
        "model_used": model_used,
        "llm_used": llm_used,
        "guidance_json": guidance_dict,
        "review_status": "PENDING_REVIEW",
        "reviewed_by": None,
        "review_notes": None,
        "reviewed_at": None,
        "ciso_edited_json": None,
        "edited_by": None,
        "edited_at": None,
        "verification_result": None,
        "verified_at": None,
        "verification_evidence_json": None,
    }
    db.insert_recovery_guidance(record)

    created = db.fetch_recovery_guidance_by_id(guidance_id)
    return _format_guidance_record(created or record)


@app.post(
    "/correlations/{id}/recovery-guidance/review",
    response_model=RecoveryGuidanceRecord,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Submit CISO review verdict on recovery guidance",
    description="""
Allows the CISO to ACCEPT or DISMISS advisory recovery guidance for an incident.
Ensures that no recovery action is ever taken automatically without explicit human sign-off.
    """
)
async def review_incident_recovery_guidance(id: str, payload: GuidanceReviewPayload):
    if payload.review_status not in ("ACCEPTED", "DISMISSED"):
        raise HTTPException(
            status_code=400,
            detail="review_status must be either 'ACCEPTED' or 'DISMISSED'"
        )

    existing = db.fetch_recovery_guidance_by_incident(id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"No recovery guidance found for incident {id}")

    if existing.get("review_status") in ("REMEDIATION_APPLIED", "RECTIFIED", "VERIFICATION_FAILED"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot review guidance in terminal state '{existing.get('review_status')}'."
        )


    db.update_recovery_guidance_review(
        guidance_id=existing["guidance_id"],
        review_status=payload.review_status,
        reviewed_by=payload.reviewer,
        review_notes=payload.notes,
    )

    updated = db.fetch_recovery_guidance_by_id(existing["guidance_id"])
    return _format_guidance_record(updated)


@app.put(
    "/correlations/{id}/recovery-guidance/edit",
    response_model=RecoveryGuidanceRecord,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Submit CISO edits to the recovery guidance plan",
    description="""
Enables the CISO to edit, refine, and approve the recovery plan before manual execution.
Preserves the original LLM guidance in `guidance` while saving human-curated actions in `ciso_edited`.
Sets `review_status` to 'EDITED'.
    """
)
async def edit_incident_recovery_guidance(id: str, payload: GuidanceEditPayload):
    inc = db.fetch_incident_by_id(id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {id} not found")

    existing = db.fetch_recovery_guidance_by_incident(id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"No recovery guidance found for incident {id}")

    if not payload.secure_actions and not payload.recovery_actions:
        raise HTTPException(
            status_code=400,
            detail="Cannot save empty guidance plan: at least one secure or recovery action must be provided."
        )

    curr_status = existing.get("review_status")
    if curr_status == "DISMISSED":
        raise HTTPException(status_code=400, detail="Cannot edit dismissed recovery guidance.")
    if curr_status in ("REMEDIATION_APPLIED", "RECTIFIED", "VERIFICATION_FAILED"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot edit guidance in state '{curr_status}': remediation workflow already initiated."
        )

    edited_content = {

        "secure_actions": payload.secure_actions,
        "recovery_actions": payload.recovery_actions,
        "verification_steps": payload.verification_steps,
        "edited_by": payload.reviewer,
        "notes": payload.notes,
    }

    db.update_recovery_guidance_edit(
        guidance_id=existing["guidance_id"],
        edited_guidance=edited_content,
        reviewer=payload.reviewer,
        notes=payload.notes,
    )

    updated = db.fetch_recovery_guidance_by_id(existing["guidance_id"])
    return _format_guidance_record(updated)


@app.post(
    "/correlations/{id}/recovery-guidance/mark-applied",
    response_model=RecoveryGuidanceRecord,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Confirm that CISO/operator applied remediation outside the system",
    description="""
Explicitly records that the human CISO has executed remediation actions in the real world.
Sets review_status to REMEDIATION_APPLIED and records remediation_applied_at timestamp.
Must be called before /verify is permitted. Requires prior ACCEPTED or EDITED status.
    """
)
async def mark_incident_remediation_applied(id: str, payload: MarkAppliedPayload):
    inc = db.fetch_incident_by_id(id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {id} not found")

    existing = db.fetch_recovery_guidance_by_incident(id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"No recovery guidance found for incident {id}")

    current_status = existing.get("review_status")
    if current_status not in ("ACCEPTED", "EDITED"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot mark remediation applied: guidance must be in ACCEPTED or EDITED status first (current status: {current_status})."
        )

    db.mark_remediation_applied(
        guidance_id=existing["guidance_id"],
        reviewer=payload.reviewer,
        notes=payload.notes,
    )

    updated = db.fetch_recovery_guidance_by_id(existing["guidance_id"])
    return _format_guidance_record(updated)


@app.post(
    "/correlations/{id}/recovery-guidance/verify",
    response_model=VerificationResultResponse,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Verify breach rectification using post-remediation telemetry",
    description="""
Tests whether the incident's triggering correlation rule re-fires on telemetry received
after remediation was applied. If rule re-fires, updates incident to VERIFICATION_FAILED.
If rule does not re-fire, updates incident to RECTIFIED and logs the resolved pattern.
Guards:
- Requires human CISO attribution in request body (VerifyPayload: reviewer required, notes optional).
- Rejects with HTTP 400 if /mark-applied has not yet been executed by the CISO.
- Rejects with HTTP 409 if called before verification_min_window_seconds has elapsed.
    """
)
async def verify_incident_rectification(
    id: str,
    payload: VerifyPayload,
):
    try:
        result = model3_recovery.verify_rectification(
            incident_id=id,
            reviewer=payload.reviewer,
            notes=payload.notes
        )
        return VerificationResultResponse(**result)
    except model3_recovery.RemediationNotAppliedError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except model3_recovery.VerificationWindowTooEarlyError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": exc.message,
                "retry_after_seconds": exc.retry_after_seconds
            }
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Verification failed for incident %s: %s", id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Verification error: {exc}")


@app.get(
    "/brain/model3/status",
    response_model=Model3StatusResponse,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Get Model 3 operational and reachability status",
    description="""
Returns live status of the Model 3 guidance engine:
- LLM reachability probe against local Ollama daemon
- Last model used (DeepSeek-R1, Qwen2.5, or deterministic fallback)
- Counts of guidance across lifecycle stages (pending, edited, accepted, awaiting verification, rectified, failed)
- Timestamp of last run and active incident count
    """
)
async def get_model3_status():
    reachable = model3_recovery.check_llm_reachability(timeout=1.5)
    counts_dict = db.count_recovery_guidance_by_status()
    last_model, last_run = db.fetch_latest_guidance_metadata()
    open_incidents = db.fetch_open_incidents()

    return Model3StatusResponse(
        llm_reachable=reachable,
        last_model_used=last_model or "none",
        counts=Model3StatusCounts(**counts_dict),
        last_run_at=last_run,
        active_incident_count=len(open_incidents),
    )


@app.get(
    "/correlations/{id}/model3-status",
    response_model=IncidentModel3StatusResponse,
    tags=["Model 3 Secure & Recover Guidance"],
    summary="Get incident Model 3 lifecycle stage and transition stepper",
    description="""
Returns the current lifecycle stage for Mission Control dashboard visualization:
Stages: DETECTED -> CORRELATED -> GUIDANCE_GENERATED -> CISO_REVIEWED -> VERIFYING -> RECTIFIED | VERIFICATION_FAILED
Includes timestamps for each stage transition.
    """
)
async def get_incident_model3_status(id: str):
    inc = db.fetch_incident_by_id(id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {id} not found")

    guidance = db.fetch_recovery_guidance_by_incident(id)
    inc_status = inc.get("status", "OPEN").upper()

    # Determine stage
    if inc_status == "RECTIFIED":
        stage = "RECTIFIED"
    elif inc_status == "VERIFICATION_FAILED":
        stage = "VERIFICATION_FAILED"
    elif guidance and (guidance.get("review_status") == "REMEDIATION_APPLIED" or guidance.get("remediation_applied_at")):
        stage = "REMEDIATION_APPLIED"
    elif guidance and guidance.get("review_status") in ("ACCEPTED", "EDITED"):
        stage = "CISO_REVIEWED"
    elif guidance:
        stage = "GUIDANCE_GENERATED"
    else:
        stage = "CORRELATED"

    timestamps = {
        "detected_at": inc.get("timestamp"),
        "correlated_at": inc.get("created_at"),
        "guidance_generated_at": guidance.get("generated_at") if guidance else None,
        "reviewed_at": (guidance.get("reviewed_at") or guidance.get("edited_at")) if guidance else None,
        "remediation_applied_at": guidance.get("remediation_applied_at") if guidance else None,
        "verified_at": guidance.get("verified_at") if guidance else None,
    }

    return IncidentModel3StatusResponse(
        incident_id=id,
        guidance_id=guidance.get("guidance_id") if guidance else None,
        current_stage=stage,
        model_used=guidance.get("model_used") if guidance else None,
        llm_used=guidance.get("llm_used") if guidance else None,
        review_status=guidance.get("review_status") if guidance else None,
        verification_result=guidance.get("verification_result") if guidance else None,
        timestamps=timestamps,
    )


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
# ROUTE 10: SSE live module health stream
# ─────────────────────────────────────────────────────────────

@app.get(
    "/brain/stream",
    tags=["Brain Management"],
    summary="SSE stream — live module event notifications",
    description="Server-Sent Events stream. Every time /events/ingest accepts an event, "
                "a JSON message is pushed: {source, event_type, timestamp, status}. "
                "Subscribe from the dashboard module health strip.",
)
async def brain_stream(request: Request):
    q = _sse_subscribe()

    async def event_generator() -> AsyncGenerator[dict, None]:
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield {"data": data}
                except asyncio.TimeoutError:
                    # Send a heartbeat comment so the connection stays alive
                    yield {"comment": "heartbeat"}
        finally:
            _sse_unsubscribe(q)

    return EventSourceResponse(event_generator())


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
    import os
    import uvicorn
    try:
        from dotenv import load_dotenv
        _env = Path(__file__).resolve().parent.parent / ".env"
        if _env.exists():
            load_dotenv(dotenv_path=_env, override=False)
    except ImportError:
        pass
    _port = int(os.getenv("MLBRAIN_PORT", "8005"))
    uvicorn.run("main:app", host="0.0.0.0", port=_port, reload=True)
