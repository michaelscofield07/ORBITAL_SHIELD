"""
Audit Service — Data Contracts

Defines the shared SecurityEvent format (matches what P2/P3/P4/P5 send)
plus the audit-specific wrapper that adds hash-chain fields.
"""

from enum import Enum
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Action(str, Enum):
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    MONITOR = "MONITOR"


class SecurityEvent(BaseModel):
    """The shared event format — this is what P2/P3/P4/P5 send us."""
    event_id: str
    timestamp: datetime
    source: str                # "DOWNLINK" | "UPLINK" | "FIRMWARE" | "ACCESS" | "ML_BRAIN"
    satellite_id: Optional[str] = None
    event_type: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    action: Action
    evidence: dict = Field(default_factory=dict)
    related_events: List[str] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """What actually gets stored — the event plus tamper-evidence fields."""
    event: SecurityEvent
    record_hash: str            # hash of (event + previous_hash)
    previous_hash: str          # hash of the record before this one
    stored_at: datetime


class ReviewStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class ReviewAction(BaseModel):
    """Human review decision on an incident."""
    event_id: str
    status: ReviewStatus
    reviewed_by: str
    reviewed_at: datetime
    notes: Optional[str] = None