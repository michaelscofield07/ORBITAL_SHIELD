"""Database repository for Telemetry and Security Event persistence and querying."""

import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.models.telemetry import TelemetryRecord
from app.models.security_event import SecurityEventRecord
from app.schemas.telemetry import TelemetryInput, IntegrityResult, AnomalyResult
from app.schemas.security_event import SecurityEvent
from app.core.logging_config import get_logger

logger = get_logger("db.repository")


class TelemetryRepository:
    """Repository handling all database interactions for telemetry and security events."""

    def __init__(self, db: Session):
        self.db = db

    def save_telemetry(
        self,
        telemetry: TelemetryInput,
        integrity: IntegrityResult,
        anomaly: AnomalyResult
    ) -> TelemetryRecord:
        """Persist an ingested and analyzed telemetry record."""
        record = TelemetryRecord(
            timestamp=telemetry.timestamp,
            satellite_id=telemetry.satellite_id,
            sequence_number=telemetry.sequence_number,
            temperature=telemetry.temperature,
            battery=telemetry.battery,
            signal_strength=telemetry.signal_strength,
            latitude=telemetry.latitude,
            longitude=telemetry.longitude,
            packet_hash=telemetry.packet_hash,
            integrity_status=integrity.integrity_status,
            anomaly_score=anomaly.anomaly_score,
            is_anomaly=anomaly.is_anomaly
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        logger.debug(f"Saved telemetry record id={record.id}, seq={record.sequence_number}")
        return record

    def get_latest_telemetry(self, satellite_id: str) -> Optional[TelemetryRecord]:
        """Fetch the most recently ingested telemetry record for a satellite."""
        return (
            self.db.query(TelemetryRecord)
            .filter(TelemetryRecord.satellite_id == satellite_id)
            .order_by(desc(TelemetryRecord.id))
            .first()
        )

    def get_recent_telemetry_window(self, satellite_id: str, limit: int = 50) -> List[TelemetryRecord]:
        """Fetch recent telemetry history ordered by sequence number ascending."""
        records = (
            self.db.query(TelemetryRecord)
            .filter(TelemetryRecord.satellite_id == satellite_id)
            .order_by(desc(TelemetryRecord.id))
            .limit(limit)
            .all()
        )
        # Reverse to get chronological ascending order
        return list(reversed(records))

    def get_next_event_id(self) -> str:
        """Generate a sequential unique event identifier: EVT-DL-000001."""
        count = self.db.query(func.count(SecurityEventRecord.id)).scalar() or 0
        return f"EVT-DL-{count + 1:06d}"

    def save_security_event(self, event: SecurityEvent) -> SecurityEventRecord:
        """Persist a generated SecurityEvent."""
        record = SecurityEventRecord(
            event_id=event.event_id,
            timestamp=event.timestamp,
            source=event.source,
            satellite_id=event.satellite_id,
            event_type=event.event_type,
            severity=event.severity,
            confidence=event.confidence,
            description=event.description,
            action=event.action,
            evidence=json.dumps(event.evidence),
            related_events=json.dumps(event.related_events)
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        logger.info(f"Saved SecurityEvent id={record.event_id}, type={record.event_type}, severity={record.severity}")
        return record

    def get_security_events(
        self,
        satellite_id: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100
    ) -> List[SecurityEvent]:
        """Query security events with filtering support for downstream consumers."""
        query = self.db.query(SecurityEventRecord)

        if satellite_id:
            query = query.filter(SecurityEventRecord.satellite_id == satellite_id)
        if severity:
            query = query.filter(SecurityEventRecord.severity == severity.upper())
        if event_type:
            query = query.filter(SecurityEventRecord.event_type == event_type.upper())
        if start_time:
            query = query.filter(SecurityEventRecord.timestamp >= start_time)
        if end_time:
            query = query.filter(SecurityEventRecord.timestamp <= end_time)

        records = query.order_by(desc(SecurityEventRecord.id)).limit(limit).all()

        events: List[SecurityEvent] = []
        for r in records:
            events.append(
                SecurityEvent(
                    event_id=r.event_id,
                    timestamp=r.timestamp,
                    source=r.source,
                    satellite_id=r.satellite_id,
                    event_type=r.event_type,
                    severity=r.severity,
                    confidence=r.confidence,
                    description=r.description,
                    action=r.action,
                    evidence=r.get_evidence_dict(),
                    related_events=r.get_related_events_list()
                )
            )
        return events

    def get_total_telemetry_count(self, satellite_id: Optional[str] = None) -> int:
        """Get total count of processed telemetry packets."""
        query = self.db.query(func.count(TelemetryRecord.id))
        if satellite_id:
            query = query.filter(TelemetryRecord.satellite_id == satellite_id)
        return query.scalar() or 0

    def clear_all(self):
        """Reset and wipe all telemetry and security event records."""
        self.db.query(TelemetryRecord).delete()
        self.db.query(SecurityEventRecord).delete()
        self.db.commit()
        logger.info("Cleared all telemetry and security event database records.")

    def get_aggregated_stats(
        self,
        satellite_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """Aggregate telemetry and security metrics for daily report generation."""
        telemetry_query = self.db.query(TelemetryRecord).filter(TelemetryRecord.satellite_id == satellite_id)
        events_query = self.db.query(SecurityEventRecord).filter(SecurityEventRecord.satellite_id == satellite_id)

        if start_time:
            telemetry_query = telemetry_query.filter(TelemetryRecord.timestamp >= start_time)
            events_query = events_query.filter(SecurityEventRecord.timestamp >= start_time)
        if end_time:
            telemetry_query = telemetry_query.filter(TelemetryRecord.timestamp <= end_time)
            events_query = events_query.filter(SecurityEventRecord.timestamp <= end_time)

        total_telemetry = telemetry_query.count()
        anomalous_packets = telemetry_query.filter(TelemetryRecord.is_anomaly == True).count()
        normal_packets = total_telemetry - anomalous_packets
        integrity_failures = telemetry_query.filter(TelemetryRecord.integrity_status == "INVALID").count()

        # Event type counts
        events = events_query.all()
        sequence_violations = sum(1 for e in events if e.event_type in ("SEQUENCE_ANOMALY", "TELEMETRY_REPLAY"))
        timestamp_violations = sum(1 for e in events if e.event_type == "TIMESTAMP_ANOMALY")
        hash_failures = sum(1 for e in events if e.event_type == "PACKET_HASH_MISMATCH")

        # Severity breakdown
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for e in events:
            if e.severity in severity_counts:
                severity_counts[e.severity] += 1

        return {
            "total_telemetry": total_telemetry,
            "normal_packets": normal_packets,
            "anomalous_packets": anomalous_packets,
            "integrity_failures": integrity_failures,
            "sequence_violations": sequence_violations,
            "timestamp_violations": timestamp_violations,
            "hash_failures": hash_failures,
            "severity_distribution": severity_counts,
            "events": [
                SecurityEvent(
                    event_id=e.event_id,
                    timestamp=e.timestamp,
                    source=e.source,
                    satellite_id=e.satellite_id,
                    event_type=e.event_type,
                    severity=e.severity,
                    confidence=e.confidence,
                    description=e.description,
                    action=e.action,
                    evidence=e.get_evidence_dict(),
                    related_events=e.get_related_events_list()
                )
                for e in events
            ]
        }
