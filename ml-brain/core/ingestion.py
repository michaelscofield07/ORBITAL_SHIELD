"""
ORBITAL SHIELD — ML Correlation Brain
Step 1: Event ingestion — validation, storage, and sliding window management

The in-memory window gives sub-millisecond correlation lookups.
The SQLite DB backs up every event so nothing is lost on restart.
"""

import logging
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Deque

from models.schemas import IncomingEvent
from db import database as db

logger = logging.getLogger("orbital.ingestion")

# ─────────────────────────────────────────────────────────────
# In-memory sliding window
# ─────────────────────────────────────────────────────────────

class SlidingWindow:
    """
    Thread-safe, time-bounded in-memory event buffer.
    Backed by a deque ordered by timestamp.
    Events older than `window_seconds` are lazily evicted on each `add()`.
    """

    def __init__(self, window_seconds: int = 1800, max_events: int = 5000):
        self._window_seconds = window_seconds
        self._max_events = max_events
        self._events: Deque[dict] = deque()
        self._lock = Lock()

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    @window_seconds.setter
    def window_seconds(self, value: int) -> None:
        with self._lock:
            self._window_seconds = value

    def add(self, event: dict) -> None:
        """Add an event and evict stale entries."""
        with self._lock:
            self._events.append(event)
            self._evict()

    def _evict(self) -> None:
        """Remove events outside the window or beyond the size cap."""
        now = datetime.now(timezone.utc)
        while self._events:
            oldest = self._events[0]
            event_ts = _parse_ts(oldest["timestamp"])
            age = (now - event_ts).total_seconds()
            if age > self._window_seconds or len(self._events) > self._max_events:
                self._events.popleft()
            else:
                break

    def get_all(self) -> list[dict]:
        with self._lock:
            self._evict()
            return list(self._events)

    def get_by_satellite(self, satellite_id: str, within_seconds: int) -> list[dict]:
        now = datetime.now(timezone.utc)
        with self._lock:
            return [
                e for e in self._events
                if e["satellite_id"] == satellite_id
                and (now - _parse_ts(e["timestamp"])).total_seconds() <= within_seconds
            ]

    def get_by_session(self, session_id: str, within_seconds: int) -> list[dict]:
        now = datetime.now(timezone.utc)
        with self._lock:
            return [
                e for e in self._events
                if e.get("session_id") == session_id
                and (now - _parse_ts(e["timestamp"])).total_seconds() <= within_seconds
            ]

    def get_by_operator(self, operator_id: str, within_seconds: int) -> list[dict]:
        now = datetime.now(timezone.utc)
        with self._lock:
            return [
                e for e in self._events
                if e.get("operator_id") == operator_id
                and (now - _parse_ts(e["timestamp"])).total_seconds() <= within_seconds
            ]

    def size(self) -> int:
        with self._lock:
            return len(self._events)


# Module-level singleton — shared across all route handlers
_window: SlidingWindow | None = None


def get_window() -> SlidingWindow:
    global _window
    if _window is None:
        raise RuntimeError("Sliding window not initialised — call init_window() first")
    return _window


def init_window(window_seconds: int = 1800, max_events: int = 5000) -> SlidingWindow:
    global _window
    _window = SlidingWindow(window_seconds=window_seconds, max_events=max_events)
    logger.info("Sliding window initialised (window=%ds, max=%d events)", window_seconds, max_events)
    return _window


# ─────────────────────────────────────────────────────────────
# Ingestion entry point
# ─────────────────────────────────────────────────────────────

def ingest_event(event: IncomingEvent) -> dict:
    """
    Validate (Pydantic already did this), store to DB, add to sliding window.
    Returns the serialised dict for downstream correlation.
    """
    event_dict = _event_to_dict(event)

    # 1. Persist to DB (idempotent — duplicate event_id is silently ignored)
    db.insert_event(event_dict)

    # 2. Add to in-memory window
    window = get_window()
    window.add(event_dict)

    logger.info(
        "Ingested %s | source=%s | satellite=%s | severity=%s | confidence=%.2f",
        event.event_id, event.source.value, event.satellite_id,
        event.severity.value, event.confidence
    )
    return event_dict


# ─────────────────────────────────────────────────────────────
# Feature extraction (Step 2)
# ─────────────────────────────────────────────────────────────

def extract_features(event_dict: dict, window_events: list[dict]) -> dict:
    """
    Compute correlation-relevant features for the incoming event against
    the current sliding window. These features are used by both the rule
    engine and (optionally) the ML layer.
    """
    now = _parse_ts(event_dict["timestamp"])
    satellite_id = event_dict["satellite_id"]
    operator_id  = event_dict.get("operator_id")
    session_id   = event_dict.get("session_id")

    same_satellite = [e for e in window_events if e["satellite_id"] == satellite_id
                      and e["event_id"] != event_dict["event_id"]]
    same_operator  = [e for e in window_events if e.get("operator_id") == operator_id
                      and operator_id and e["event_id"] != event_dict["event_id"]]
    same_session   = [e for e in window_events if e.get("session_id") == session_id
                      and session_id and e["event_id"] != event_dict["event_id"]]

    time_deltas = [
        abs((now - _parse_ts(e["timestamp"])).total_seconds())
        for e in same_satellite
    ]
    distinct_sources = len(set(e["source"] for e in same_satellite))
    severity_counts = {sev: sum(1 for e in same_satellite if e["severity"] == sev)
                       for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}

    return {
        "satellite_match_count":  len(same_satellite),
        "operator_match_count":   len(same_operator),
        "session_match_count":    len(same_session),
        "distinct_source_count":  distinct_sources,
        "time_deltas_seconds":    time_deltas,
        "min_time_delta":         min(time_deltas) if time_deltas else 0,
        "max_time_delta":         max(time_deltas) if time_deltas else 0,
        "severity_distribution":  severity_counts,
        "event_types_in_window":  list(set(e["event_type"] for e in same_satellite)),
        "window_size":            len(window_events),
    }


# ─────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────

def _event_to_dict(event: IncomingEvent) -> dict:
    return {
        "event_id":      event.event_id,
        "timestamp":     event.timestamp.isoformat(),
        "source":        event.source.value,
        "satellite_id":  event.satellite_id,
        "event_type":    event.event_type,
        "severity":      event.severity.value,
        "confidence":    event.confidence,
        "description":   event.description,
        "action":        event.action.value,
        "evidence":      event.evidence,
        "related_events": event.related_events,
        "operator_id":   event.operator_id,
        "session_id":    event.session_id,
    }


def _parse_ts(ts: str | datetime) -> datetime:
    if isinstance(ts, datetime):
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except ValueError:
        return datetime.now(timezone.utc)
