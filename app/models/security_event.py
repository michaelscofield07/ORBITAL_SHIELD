"""SQLAlchemy model for persisting standardized Security Events."""

from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, Float, String, Text, DateTime
from app.db.database import Base


class SecurityEventRecord(Base):
    """Database representation of emitted SecurityEvents."""

    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    source = Column(String(32), nullable=False, default="DOWNLINK")
    satellite_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    description = Column(String(512), nullable=False)
    action = Column(String(32), nullable=False, default="REVIEW")
    evidence = Column(Text, nullable=False, default="{}")
    related_events = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def get_evidence_dict(self) -> dict:
        """Parse evidence JSON string to dict."""
        try:
            return json.loads(self.evidence)
        except Exception:
            return {}

    def get_related_events_list(self) -> list:
        """Parse related_events JSON string to list."""
        try:
            return json.loads(self.related_events)
        except Exception:
            return []

    def __repr__(self):
        return f"<SecurityEventRecord(id={self.event_id}, type={self.event_type}, severity={self.severity})>"
