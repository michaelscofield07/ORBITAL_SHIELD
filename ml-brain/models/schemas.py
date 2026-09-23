"""
ORBITAL SHIELD — ML Correlation Brain
Pydantic schemas for all input/output event contracts.

These schemas define the API contract between this module and:
  - Upstream modules (DOWNLINK, UPLINK, FIRMWARE, ACCESS)
  - Downstream audit module (Person 6)
  - Dashboard frontend (Person 6)

Do NOT change field names without coordinating with the team.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator
import uuid


# ─────────────────────────────────────────────────────────────
# SHARED ENUMS
# ─────────────────────────────────────────────────────────────

class SourceModule(str, Enum):
    DOWNLINK    = "DOWNLINK"
    UPLINK      = "UPLINK"
    FIRMWARE    = "FIRMWARE"
    ACCESS      = "ACCESS"
    ML_BRAIN    = "ML_BRAIN"   # this module's own output source label
    CISO_NOTES  = "CISO_NOTES"
    CERT_IN     = "CERT_IN"


class AuthorizationStatus(str, Enum):
    AUTHORIZED         = "AUTHORIZED"
    UNAUTHORIZED       = "UNAUTHORIZED"
    SUSPICIOUS         = "SUSPICIOUS"          # requires verification
    VERIFIED_RECTIFIED = "VERIFIED_RECTIFIED"  # verified by CISO or historical baseline
    UNKNOWN            = "UNKNOWN"             # credentials or context absent from telemetry



class SeverityLevel(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    # Ordered comparison support
    _order = {"INFO": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def __lt__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] < self._order[other.value]

    def __le__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] <= self._order[other.value]

    def __gt__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] > self._order[other.value]

    def __ge__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] >= self._order[other.value]


class ActionType(str, Enum):
    REVIEW         = "REVIEW"
    MONITOR        = "MONITOR"
    HUMAN_REVIEW   = "HUMAN_REVIEW"
    ALERT          = "ALERT"
    LOG            = "LOG"
    FLAG           = "FLAG"
    QUARANTINE     = "QUARANTINE"
    BLOCK_ADVISORY = "BLOCK_ADVISORY"


class VerdictType(str, Enum):
    CONFIRMED_REAL      = "CONFIRMED_REAL"
    FALSE_POSITIVE      = "FALSE_POSITIVE"
    RECTIFIED           = "RECTIFIED"
    VERIFIED_LEGITIMATE = "VERIFIED_LEGITIMATE"


# ─────────────────────────────────────────────────────────────
# UPSTREAM INPUT — events from the 4 security modules
# ─────────────────────────────────────────────────────────────

class IncomingEvent(BaseModel):
    """
    Shared event schema. All four upstream modules MUST produce events
    conforming to this exact shape. Validated at ingestion time.
    """
    event_id:      str            = Field(..., description="Unique event identifier from source module")
    timestamp:     datetime       = Field(..., description="ISO-8601 UTC timestamp of the event")
    source:        SourceModule   = Field(..., description="Which security module produced this event")
    satellite_id:  str            = Field(..., description="Target satellite identifier")
    event_type:    str            = Field(..., description="Machine-readable event classification")
    severity:      SeverityLevel  = Field(..., description="Severity assessed by the source module")
    confidence:    float          = Field(..., ge=0.0, le=1.0, description="Source module's confidence 0.0–1.0")
    description:   str            = Field(..., description="Human-readable event summary")
    action:        ActionType     = Field(..., description="Recommended action from source module")
    evidence:      Dict[str, Any] = Field(default_factory=dict, description="Source-module-specific supporting evidence (passed through)")
    related_events: List[str]     = Field(default_factory=list, description="Event IDs already linked by the source module")

    # Optional join keys — provided when the source can attribute the event
    operator_id:   Optional[str]  = Field(None, description="Operator responsible (if attributable)")
    session_id:    Optional[str]  = Field(None, description="Operator session (if attributable)")

    # Common Event Model extensions
    actor:                Optional[str]  = Field(None, description="Acting user, operator, or automated process")
    source_ip:            Optional[str]  = Field(None, description="Simulated client/source IP address")
    destination_ip:       Optional[str]  = Field(None, description="Simulated destination IP address")
    resource:             Optional[str]  = Field(None, description="Target resource (database, file, subsystem)")
    authorization_status: Optional[str]  = Field(None, description="AUTHORIZED / UNAUTHORIZED / SUSPICIOUS / VERIFIED_RECTIFIED")
    data_access:          Optional[Dict[str, Any]] = Field(default_factory=dict, description="Details on database, tables, files accessed")
    firmware_info:        Optional[Dict[str, Any]] = Field(default_factory=dict, description="Firmware hash, artifact, version details")
    packet_info:          Optional[Dict[str, Any]] = Field(default_factory=dict, description="Command packet/request info")
    raw_log:              Optional[Dict[str, Any]] = Field(default_factory=dict, description="Original raw event payload untouched")
    ciso_notes:           Optional[str]  = Field(None, description="CISO feedback or observations")

    # First-class CERT-In advisory and threat intelligence extensions
    cert_in_reference:   Optional[str]  = Field(None, description="CERT-In advisory reference identifier (e.g. CERTIN-ADV-2026-0881)")
    title:               Optional[str]  = Field(None, description="Advisory or summary title")
    threat_vectors:      Optional[List[str]] = Field(default_factory=list, description="Threat vectors identified by CERT-In")
    recommended_actions: Optional[List[str]] = Field(default_factory=list, description="Recommended remediation actions from CERT-In")
    mandate_actions:     Optional[List[str]] = Field(default_factory=list, description="Mandated regulatory actions from CERT-In")
    cert_in_details:     Optional[Union[Dict[str, Any], str]] = Field(default=None, description="Structured CERT-In advisory payload or text details")

    @field_validator("event_id")
    @classmethod
    def event_id_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("event_id must not be blank")
        return v.strip()

    @field_validator("satellite_id")
    @classmethod
    def satellite_id_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("satellite_id must not be blank")
        return v.strip().upper()

    model_config = {
        "extra": "allow",
        "json_schema_extra": {
            "example": {
        "event_id": "EVT-100",
        "timestamp": "2026-08-24T12:00:00Z",
        "source": "DOWNLINK",
        "satellite_id": "SAT-EO-01",
        "event_type": "TELEMETRY_ANOMALY",
        "severity": "HIGH",
        "confidence": 0.93,
        "description": "Unexpected thermal increase detected in main bus",
        "action": "REVIEW",
        "evidence": {"sensor": "thermal_01", "delta_celsius": 12.5},
        "related_events": [],
        "operator_id": "OP-02",
        "session_id": "S123"
    }}}


class IngestResponse(BaseModel):
    status:         str
    event_id:       str
    correlations_triggered: List[str] = Field(default_factory=list, description="Incident IDs generated as a result of this event")
    message:        str


# ─────────────────────────────────────────────────────────────
# OUTPUT — correlation incidents produced by this module
# ─────────────────────────────────────────────────────────────

class CorrelationIncident(BaseModel):
    """
    Output event sent to the Audit module and queryable via the dashboard.
    All fields are populated by the correlation engine — never modified by ML alone.
    """
    event_id:        str           = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    timestamp:       datetime      = Field(default_factory=datetime.utcnow)
    source:          str           = Field(default="ML_BRAIN")
    event_type:      str           = Field(..., description="CROSS_MODULE_ATTACK / ESCALATING_INCIDENT / SUPPLY_CHAIN_RISK / etc.")
    severity:        SeverityLevel
    confidence:      float         = Field(..., ge=0.0, le=1.0)
    description:     str           = Field(..., description="Human-readable explanation of WHY this correlation fired")
    related_events:  List[str]     = Field(..., description="Raw event_ids that contributed to this incident")
    action:          str           = Field(default="HUMAN_REVIEW")
    risk_score:      int           = Field(..., ge=0, le=200, description="Additive risk score from scoring engine")

    # Audit trail fields
    rule_id:         str           = Field(..., description="Which rule triggered this incident")
    rule_name:       str
    rule_score:      int           = Field(..., description="Score from rule engine alone, before ML adjustment")
    ml_adjustment:   int           = Field(default=0, description="Score delta applied by ML refiner (0 if ML layer inactive)")
    satellite_id:    str
    operator_id:     Optional[str] = None
    session_id:      Optional[str] = None
    status:          str           = Field(default="OPEN", description="OPEN / CONFIRMED / FALSE_POSITIVE")
    reviewed_by:     Optional[str] = None
    review_notes:    Optional[str] = None
    reviewed_at:     Optional[datetime] = None

    # Model 1 Understanding & Summarization extensions
    authorization_status:        str           = Field(default="UNAUTHORIZED", description="AUTHORIZED / UNAUTHORIZED / SUSPICIOUS / VERIFIED_RECTIFIED")
    authorization_reason:        Optional[str] = Field(None, description="Forensic explanation of WHY this authorization status was assigned")
    unauthorized_chain:          List[Dict[str, Any]] = Field(default_factory=list, description="Reconstructed chain of unauthorized & contextual events")
    data_access_summary:         Optional[Dict[str, Any]] = Field(default_factory=dict, description="Summary of all databases, files, and records accessed")
    historical_pattern_matched:  bool          = Field(default=False, description="True if a previous identical attack pattern was found in database")
    historical_pattern_details:  Optional[Dict[str, Any]] = Field(default_factory=dict, description="Historical data access and comparison details")
    incident_document_md:        Optional[str] = Field(None, description="Complete human-readable incident document for CISO & CERT-In")
    cert_in_report:              Optional[Dict[str, Any]] = Field(default_factory=dict, description="CERT-In 6-hour audit & compliance reporting block")


class IncidentSummary(BaseModel):
    """Lightweight summary for list endpoints."""
    event_id:    str
    timestamp:   datetime
    event_type:  str
    severity:    SeverityLevel
    risk_score:  int
    status:      str
    satellite_id: str
    rule_name:   str
    related_events_count: int


# ─────────────────────────────────────────────────────────────
# FEEDBACK — CISO review decisions
# ─────────────────────────────────────────────────────────────

class FeedbackPayload(BaseModel):
    """
    CISO verdict on a flagged incident.
    This is the ONLY mechanism by which the ML layer receives labeled training data.
    """
    incident_id: str    = Field(..., description="The INC-xxx ID of the correlated incident")
    verdict:     VerdictType = Field(...)
    reviewer:    str    = Field(..., description="Reviewer identity for audit trail")
    notes:       Optional[str] = Field(None)

    model_config = {"json_schema_extra": {"example": {
        "incident_id": "INC-001",
        "verdict": "CONFIRMED_REAL",
        "reviewer": "ciso_01",
        "notes": "Verified — operator session was compromised"
    }}}


class FeedbackResponse(BaseModel):
    status:      str
    incident_id: str
    verdict:     str
    message:     str


# ─────────────────────────────────────────────────────────────
# BRAIN STATUS — health + config transparency endpoint
# ─────────────────────────────────────────────────────────────

class RuleStatus(BaseModel):
    rule_id:        str
    name:           str
    enabled:        bool
    incident_type:  str
    time_window_seconds: int
    min_sources:    int
    min_events:     int
    # SPARTA v2.0 (space-systems ATT&CK) and CERT-In classification — metadata only
    sparta_technique_id: Optional[str] = None
    cert_in_category:    Optional[str] = None


class BrainStatus(BaseModel):
    status:             str = "OK"
    version:            str = "1.0.0"
    uptime_seconds:     float
    events_ingested:    int
    incidents_generated: int
    open_incidents:     int
    ml_layer_active:    bool
    last_retrain:       Optional[datetime]
    active_rules:       List[RuleStatus]
    scoring_weights:    Dict[str, int]
    config_version:     str
    window_seconds:     int


# ─────────────────────────────────────────────────────────────
# RETRAIN — manual trigger response
# ─────────────────────────────────────────────────────────────

class RetrainResponse(BaseModel):
    status:             str
    feedback_samples:   int
    thresholds_changed: List[Dict[str, Any]]
    ml_retrained:       bool
    ml_accuracy:        Optional[float]
    config_updated:     bool
    audit_event_id:     Optional[str]
    message:            str


# ─────────────────────────────────────────────────────────────
# AUDIT EVENT — sent to Person 6's audit service
# ─────────────────────────────────────────────────────────────

class AuditEvent(BaseModel):
    """Minimal shape for forwarding to the audit module."""
    event_id:       str
    timestamp:      datetime
    source:         str = "ML_BRAIN"
    event_type:     str
    severity:       str
    confidence:     float
    description:    str
    related_events: List[str]
    action:         str
    risk_score:     int


# ─────────────────────────────────────────────────────────────
# MODEL 1 — INCIDENT DOCUMENT & EXTERNAL CONTEXT SCHEMAS
# ─────────────────────────────────────────────────────────────

class IncidentDocumentResponse(BaseModel):
    incident_id:                 str
    timestamp:                   str
    satellite_id:                str
    event_type:                  str
    severity:                    str
    risk_score:                  int
    authorization_status:        str
    authorization_reason:        str
    document_markdown:           str
    incident_document_md:        Optional[str] = None
    unauthorized_event_chain:    List[Dict[str, Any]]
    data_access_summary:         Dict[str, Any]
    historical_comparison:       Dict[str, Any]
    cert_in_compliance:          Dict[str, Any]
    cert_in_context:             Optional[Dict[str, Any]] = Field(default_factory=dict, description="Structured CERT-In advisory context and threat intelligence")


class CisoNoteRequest(BaseModel):
    satellite_id:                Optional[str] = None
    incident_id:                 Optional[str] = None
    operator_id:                 Optional[str] = None
    author:                      str = "CISO"
    notes:                       str
    classification:              Optional[str] = "OBSERVATION"
    action_recommended:          Optional[str] = None


class CertInSummaryRequest(BaseModel):
    summary_id:                  Optional[str] = None
    title:                       Optional[str] = None
    severity:                    str = "HIGH"
    details:                     Optional[str] = None
    cert_in_reference:           Optional[str] = None
    summary:                     Optional[str] = None
    incident_id:                 Optional[str] = None
    satellite_id:                Optional[str] = None
    threat_vectors:              List[str] = Field(default_factory=list)
    recommended_actions:         List[str] = Field(default_factory=list)
    mandate_actions:             List[str] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# MODEL 3 — RETRAIN + SECURE & RECOVERY GUIDANCE SCHEMAS
# ─────────────────────────────────────────────────────────────

class SecureAndRecoverGuidance(BaseModel):
    """
    Validated advisory output produced by Model 3 LLM or deterministic fallback.
    Never applied automatically; strictly advisory recommendations for the CISO.
    """
    affected_domain:             str = Field(..., description="Primary affected security domain (DOWNLINK, UPLINK, FIRMWARE, ACCESS, MULTI_DOMAIN)")
    isolation_summary:           str = Field(..., description="Brief summary of required isolation boundaries")
    secure_actions:              List[str] = Field(..., description="Actionable immediate containment and defense steps")
    recovery_actions:            List[str] = Field(..., description="Step-by-step restoration and operational recovery actions")
    verification_steps:          List[str] = Field(..., description="Verification procedures to validate system health post-recovery")
    residual_risk:               str = Field(..., description="Assessment of residual threat level after actions (LOW, MEDIUM, HIGH)")
    confidence:                  str = Field(..., description="Model confidence level (LOW, MEDIUM, HIGH)")
    rationale:                   str = Field(..., description="Technical justification and reasoning behind the guidance")


class RecoveryGuidanceRecord(BaseModel):
    """
    Persisted Model 3 guidance record from the recovery_guidance database table.
    """
    guidance_id:                 str
    incident_id:                 str
    generated_at:                str
    model_used:                  str
    llm_used:                    bool
    guidance:                    Dict[str, Any]
    review_status:               str = "PENDING_REVIEW"
    reviewed_by:                 Optional[str] = None
    review_notes:                Optional[str] = None
    reviewed_at:                 Optional[str] = None
    ciso_edited:                 Optional[Dict[str, Any]] = None
    edited_by:                   Optional[str] = None
    edited_at:                   Optional[str] = None
    remediation_applied_at:      Optional[str] = None
    remediation_applied_by:      Optional[str] = None
    remediation_notes:           Optional[str] = None
    verification_result:         Optional[str] = None
    verified_at:                 Optional[str] = None
    verification_evidence:       Optional[Dict[str, Any]] = None


class Model3RunRequest(BaseModel):
    """Payload to trigger the Model 3 pipeline."""
    incident_ids:                Optional[List[str]] = Field(None, description="Optional list of specific incident IDs to process. Defaults to all OPEN incidents.")
    run_retrain:                 bool = Field(True, description="Whether to execute the existing retrain job prior to generating guidance.")


class Model3RunResponse(BaseModel):
    """Response returned after running the Model 3 pipeline."""
    status:                      str
    retrain_result:              Optional[Dict[str, Any]] = None
    guidance_count:              int
    guidance_records:            List[RecoveryGuidanceRecord]
    message:                     str


class GuidanceReviewPayload(BaseModel):
    """Payload for CISO review (acceptance or dismissal) of generated recovery guidance."""
    review_status:               str = Field(..., description="Verdict: ACCEPTED or DISMISSED")
    reviewer:                    str = Field(..., description="CISO / Analyst reviewer identifier")
    notes:                       Optional[str] = Field(None, description="Operational notes or justification")


class GuidanceEditPayload(BaseModel):
    """Payload for CISO to submit an edited version of the recovery guidance."""
    reviewer:                    str = Field(..., description="CISO / Analyst reviewer identifier")
    secure_actions:              List[str] = Field(default_factory=list, description="CISO-curated containment and defense steps")
    recovery_actions:            List[str] = Field(default_factory=list, description="CISO-curated operational recovery actions")
    verification_steps:          List[str] = Field(default_factory=list, description="CISO-curated post-recovery verification procedures")
    notes:                       Optional[str] = Field(None, description="Operational notes or reasoning for edits")



class MarkAppliedPayload(BaseModel):
    """Payload for CISO to confirm that remediation actions have been executed outside this system."""
    reviewer:                    str = Field(..., description="CISO / Operator identity who applied the remediation")
    notes:                       Optional[str] = Field(None, description="Operational notes detailing actions taken or ground changes made")


class VerificationResultResponse(BaseModel):
    """Response returned after running breach-rectification verification."""
    incident_id:                 str
    verification_result:         str = Field(..., description="Outcome: PASSED or FAILED")
    verified_at:                 str
    status_updated_to:           str
    evidence_summary:            Dict[str, Any]
    message:                     str


class Model3StatusCounts(BaseModel):
    """Breakdown of guidance records and incidents by lifecycle status."""
    pending_review:              int
    edited:                      int
    accepted:                    int
    remediation_applied:         int = 0
    dismissed:                   int
    awaiting_verification:        int
    rectified:                   int
    verification_failed:         int


class Model3StatusResponse(BaseModel):
    """Live status of Model 3 engine, LLM availability, and workflow metrics."""
    llm_reachable:               bool
    last_model_used:             str
    counts:                      Model3StatusCounts
    last_run_at:                 Optional[str] = None
    active_incident_count:       int


class IncidentModel3StatusResponse(BaseModel):
    """Stepper progress for a specific incident through the Model 3 lifecycle."""
    incident_id:                 str
    guidance_id:                 Optional[str] = None
    current_stage:               str = Field(..., description="DETECTED | CORRELATED | GUIDANCE_GENERATED | CISO_REVIEWED | REMEDIATION_APPLIED | RECTIFIED | VERIFICATION_FAILED")
    model_used:                  Optional[str] = None
    llm_used:                    Optional[bool] = None
    review_status:               Optional[str] = None
    verification_result:         Optional[str] = None
    timestamps:                  Dict[str, Optional[str]]


