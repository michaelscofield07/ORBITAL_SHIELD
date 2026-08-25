"""Daily telemetry security report generation service."""

from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.schemas.security_event import DailyReportResponse, SecurityEvent
from app.db.repository import TelemetryRepository
from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger("services.report_generator")


class ReportGenerator:
    """Generates daily security summaries and recommendations for Person 6 (Audit & Dashboard)."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = TelemetryRepository(db)

    def generate_daily_report(
        self,
        satellite_id: Optional[str] = None,
        report_date: Optional[str] = None
    ) -> DailyReportResponse:
        """
        Synthesize aggregated metrics and recommendations for a given day.
        """
        sat_id = satellite_id or settings.SATELLITE_ID
        if not report_date:
            report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        start_time = f"{report_date}T00:00:00Z"
        end_time = f"{report_date}T23:59:59Z"

        stats = self.repository.get_aggregated_stats(
            satellite_id=sat_id,
            start_time=start_time,
            end_time=end_time
        )

        events: List[SecurityEvent] = stats["events"]

        # Extract top anomalies (sorted by highest severity: CRITICAL > HIGH > MEDIUM > LOW)
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_events = sorted(
            events,
            key=lambda e: (severity_order.get(e.severity, 0), e.confidence),
            reverse=True
        )

        top_anomalies = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "severity": e.severity,
                "description": e.description,
                "evidence": e.evidence
            }
            for e in sorted_events[:5]
        ]

        # Generate intelligent operational recommendations
        recommendations = self._generate_recommendations(stats)

        return DailyReportResponse(
            report_date=report_date,
            satellite_id=sat_id,
            total_telemetry_packets=stats["total_telemetry"],
            normal_packets=stats["normal_packets"],
            anomalous_packets=stats["anomalous_packets"],
            integrity_failures=stats["integrity_failures"],
            sequence_violations=stats["sequence_violations"],
            timestamp_violations=stats["timestamp_violations"],
            hash_failures=stats["hash_failures"],
            severity_distribution=stats["severity_distribution"],
            top_anomalies=top_anomalies,
            security_events=events,
            recommendations=recommendations
        )

    def _generate_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Synthesize actionable advice based on aggregate observations."""
        recs = []
        if stats["total_telemetry"] == 0:
            return ["No telemetry received during this reporting window. Verify ground station downlink connectivity."]

        if stats["hash_failures"] > 0:
            recs.append(
                f"CRITICAL: {stats['hash_failures']} cryptographic hash mismatch(es) detected. "
                "Investigate potential active man-in-the-middle tampering on RF downlink path."
            )

        if stats["sequence_violations"] > 0:
            recs.append(
                f"HIGH: {stats['sequence_violations']} sequence number violation(s) observed. "
                "Inspect ground receiver demodulator packet drop rates or replay injection attempts."
            )

        if stats["timestamp_violations"] > 0:
            recs.append(
                f"MEDIUM: {stats['timestamp_violations']} timestamp anomalies recorded. "
                "Perform clock drift synchronization check on onboard satellite RTC."
            )

        if stats["anomalous_packets"] > 0:
            pct = (stats["anomalous_packets"] / max(1, stats["total_telemetry"])) * 100.0
            recs.append(
                f"REVIEW: {stats['anomalous_packets']} packet(s) ({pct:.1f}%) exhibited behavioral ML anomalies. "
                "Cross-correlate thermal and RF subsystems with orbital solar eclipse transitions."
            )

        if not recs:
            recs.append("Downlink integrity and telemetry behavior operate within nominal bounds. No action required.")

        return recs
