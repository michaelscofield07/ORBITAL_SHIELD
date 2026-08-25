"""SQLAlchemy model for persisting raw and analyzed telemetry packets."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, Float, String, Boolean, DateTime
from app.db.database import Base


class TelemetryRecord(Base):
    """Database representation of ingested satellite telemetry."""

    __tablename__ = "telemetry_records"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    satellite_id = Column(String(64), nullable=False, index=True)
    sequence_number = Column(Integer, nullable=False, index=True)
    temperature = Column(Float, nullable=False)
    battery = Column(Float, nullable=False)
    signal_strength = Column(Float, nullable=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    packet_hash = Column(String(128), nullable=True)
    integrity_status = Column(String(32), nullable=False, default="VALID")
    anomaly_score = Column(Float, nullable=False, default=0.0)
    is_anomaly = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<TelemetryRecord(id={self.id}, sat={self.satellite_id}, seq={self.sequence_number}, anomaly={self.is_anomaly})>"
