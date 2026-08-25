"""
ORBITAL SHIELD — Access Security Event Generator & Integrations.
Transforms Access Engine DetectionResults into canonical SecurityEvents,
and handles integration with ML Correlation Brain (Person 5 / port 8005) and Audit Layer (Person 6).
"""

from __future__ import annotations
from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional
import uuid
import logging
import httpx

try:
    from models.schemas import DetectionResult, SecurityEvent
except ImportError:
    from ..models.schemas import DetectionResult, SecurityEvent

logger = logging.getLogger("AccessSecurity.EventGenerator")

ML_BRAIN_URL = os.environ.get("ML_BRAIN_URL", "http://localhost:8005/events/ingest")


class EventGenerator:
    """
    Constructs normalized, structured security events from detection engine outcomes,
    and manages forwarding to downstream ML Correlation Brain and Audit systems.
    """

    @staticmethod
    def generate_security_event(
        detection: DetectionResult,
        satellite_id: Optional[str] = None
    ) -> SecurityEvent:
        """
        Creates the canonical SecurityEvent from a DetectionResult.
        Fully compliant with ML Brain `IncomingEvent` schema and Person 6 Audit format.
        """
        sat_id = satellite_id or detection.satellite_id or "SAT-EO-01"
        event_id = f"EVT-ACC-{uuid.uuid4().hex[:8].upper()}"
        
        # Build evidence dictionary with enriched telemetry
        evidence = {
            "user_id": detection.user_id,
            "source_ip": detection.source_ip,
            "device_id": detection.device_id,
            "is_suspicious": detection.is_suspicious,
            **detection.evidence
        }

        return SecurityEvent(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source="ACCESS",
            satellite_id=sat_id,
            event_type=detection.event_type,
            severity=detection.severity.value if hasattr(detection.severity, "value") else str(detection.severity),
            confidence=detection.confidence,
            description=detection.description,
            action=detection.action.value if hasattr(detection.action, "value") else str(detection.action),
            evidence=evidence,
            related_events=[],
            operator_id=detection.user_id,
            session_id=detection.session_id
        )

    @staticmethod
    async def forward_to_ml_brain_async(
        event: SecurityEvent,
        ml_brain_url: str = ML_BRAIN_URL,
        timeout: float = 3.0
    ) -> Dict[str, Any]:
        """
        Asynchronously forwards a SecurityEvent to Person 5's ML Correlation Brain.
        Gracefully handles offline state without crashing or raising unhandled exceptions.
        """
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    ml_brain_url,
                    json=event.model_dump()
                )
                if response.status_code in (200, 201, 202):
                    return {
                        "forwarded": True,
                        "status_code": response.status_code,
                        "ml_brain_response": response.json()
                    }
                else:
                    logger.warning(f"ML Brain responded with HTTP status {response.status_code}")
                    return {
                        "forwarded": False,
                        "status_code": response.status_code,
                        "error": response.text
                    }
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException) as err:
            logger.warning(f"[WARNING] ML Brain unavailable — event generated locally. ({err})")
            return {
                "forwarded": False,
                "status": "OFFLINE",
                "message": "[WARNING] ML Brain unavailable — event generated locally.",
                "details": str(err)
            }
        except Exception as err:
            logger.error(f"Unexpected error when communicating with ML Brain: {err}")
            return {
                "forwarded": False,
                "status": "ERROR",
                "message": f"Communication failed: {str(err)}"
            }

    @classmethod
    def forward_to_ml_brain_sync(
        cls,
        event: SecurityEvent,
        ml_brain_url: str = ML_BRAIN_URL,
        timeout: float = 3.0
    ) -> Dict[str, Any]:
        """
        Synchronous wrapper for forwarding events to ML Brain (ideal for CLI demo script).
        """
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(
                    ml_brain_url,
                    json=event.model_dump()
                )
                if response.status_code in (200, 201, 202):
                    return {
                        "forwarded": True,
                        "status_code": response.status_code,
                        "ml_brain_response": response.json()
                    }
                else:
                    print(f"[WARNING] ML Brain HTTP {response.status_code}: {response.text[:100]}")
                    return {
                        "forwarded": False,
                        "status_code": response.status_code,
                        "error": response.text
                    }
        except Exception as err:
            print(f"[WARNING] ML Brain unavailable — event generated locally.")
            return {
                "forwarded": False,
                "status": "OFFLINE",
                "message": "[WARNING] ML Brain unavailable — event generated locally.",
                "details": str(err)
            }
