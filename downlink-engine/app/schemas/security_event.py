"""Shared Security Event schema for ORBITAL SHIELD."""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class SecurityEvent(BaseModel):
    """Canonical, project-wide security event schema consumed by Person 5 (ML Correlation) and Person 6 (Audit/Dashboard)."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "event_id": "EVT-DL-000001",
                "timestamp": "2026-08-25T02:14:30Z",
                "source": "DOWNLINK",
                "satellite_id": "SAT-EO-01",
                "event_type": "TELEMETRY_ANOMALY",
                "severity": "HIGH",
                "confidence": 0.93,
                "description": "Unexpected thermal increase detected: 72.0°C exceeds normal range [18.0, 28.0]°C",
                "action": "REVIEW",
                "evidence": {
                    "anomaly_score": -0.192,
                    "temperature": 72.0,
                    "expected_temperature_range": [18.0, 28.0],
                    "battery": 87.2,
                    "signal_strength": -71.3
                },
                "related_events": []
            }
        }
    )

    event_id: str = Field(
        ...,
        description="Unique security event identifier (e.g., EVT-DL-000001)",
        examples=["EVT-DL-000001"]
    )
    timestamp: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of event generation",
        examples=["2026-08-25T02:14:30Z"]
    )
    source: str = Field(
        default="DOWNLINK",
        description="Module source emitting the event (always 'DOWNLINK' for Person 2)",
        examples=["DOWNLINK"]
    )
    satellite_id: str = Field(
        ...,
        description="Target satellite platform ID",
        examples=["SAT-EO-01"]
    )
    event_type: str = Field(
        ...,
        description="Classified event type (e.g., TELEMETRY_ANOMALY, TELEMETRY_INTEGRITY_FAILURE, PACKET_HASH_MISMATCH, TELEMETRY_SPOOFING)",
        examples=["TELEMETRY_ANOMALY"]
    )
    severity: str = Field(
        ...,
        description="Event severity tier: 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'",
        examples=["HIGH"]
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score for this finding between 0.0 and 1.0",
        examples=[0.93]
    )
    description: str = Field(
        ...,
        description="Human-readable summary of the security finding",
        examples=["Unexpected thermal increase detected"]
    )
    action: str = Field(
        default="REVIEW",
        description="Recommended operational action: 'REVIEW' or 'ALERT'",
        examples=["REVIEW"]
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured machine-readable forensic metrics and evidence for downstream correlation",
        examples=[{
            "anomaly_score": -0.72,
            "temperature": 72.0,
            "expected_temperature_range": [18.0, 28.0],
            "sequence_number": 1050,
            "expected_sequence_number": 1005,
            "integrity_status": "INVALID"
        }]
    )
    related_events: List[str] = Field(
        default_factory=list,
        description="List of associated event IDs",
        examples=[[]]
    )


class DailyReportResponse(BaseModel):
    """Structured daily security and telemetry report schema for GET /downlink/report."""

    report_date: str = Field(..., description="Report generation date (YYYY-MM-DD)")
    satellite_id: str = Field(..., description="Satellite platform ID")
    total_telemetry_packets: int = Field(..., description="Total count of ingested telemetry packets")
    normal_packets: int = Field(..., description="Count of normal, non-anomalous packets")
    anomalous_packets: int = Field(..., description="Count of behaviorally anomalous packets")
    integrity_failures: int = Field(..., description="Count of packets failing integrity checks")
    sequence_violations: int = Field(..., description="Count of sequence violations (jumps/duplicates)")
    timestamp_violations: int = Field(..., description="Count of timestamp anomalies")
    hash_failures: int = Field(..., description="Count of SHA-256 hash mismatch failures")
    severity_distribution: Dict[str, int] = Field(
        ...,
        description="Count of security events categorized by severity level (LOW, MEDIUM, HIGH, CRITICAL)"
    )
    top_anomalies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of highest-severity anomaly occurrences with forensic details"
    )
    security_events: List[SecurityEvent] = Field(
        default_factory=list,
        description="List of all SecurityEvents recorded during the reporting period"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable operational security recommendations based on daily telemetry patterns"
    )
