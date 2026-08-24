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
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
import uuid


# ─────────────────────────────────────────────────────────────
# SHARED ENUMS
# ─────────────────────────────────────────────────────────────

class SourceModule(str, Enum):
    DOWNLINK  = "DOWNLINK"
    UPLINK    = "UPLINK"
    FIRMWARE  = "FIRMWARE"
    ACCESS    = "ACCESS"
    ML_BRAIN  = "ML_BRAIN"   # this module's own output source label


class SeverityLevel(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    # Ordered comparison support
    _order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def __lt__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] < self._order[other.value]

    def __le__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] <= self._order[other.value]

    def __gt__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] > self._order[other.value]

    def __ge__(self, other: "SeverityLevel") -> bool:
        return self._order[self.value] >= self._order[other.value]


class ActionType(str, Enum):
    REVIEW       = "REVIEW"
    MONITOR      = "MONITOR"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    ALERT        = "ALERT"
    LOG          = "LOG"


class VerdictType(str, Enum):
    CONFIRMED_REAL = "CONFIRMED_REAL"
    FALSE_POSITIVE = "FALSE_POSITIVE"


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

    model_config = {"json_schema_extra": {"example": {
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
