"""
Audit Service — Human Review Actions

Lets an admin mark an incident as Investigating or Resolved,
and records who did it and when.
"""

from fastapi import APIRouter, HTTPException
from datetime import datetime
from schemas import ReviewStatus
from storage import DB_PATH
import sqlite3
from typing import Optional

router = APIRouter()


@router.post("/audit/{event_id}/review")
def review_event(event_id: str, status: ReviewStatus, reviewed_by: str, notes: Optional[str] = None):
    conn = sqlite3.connect(DB_PATH)

    # Confirm the event actually exists before trying to update it
    existing = conn.execute(
        "SELECT id FROM audit_events WHERE event_id = ?", (event_id,)
    ).fetchone()

    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    conn.execute(
        "UPDATE audit_events SET review_status = ? WHERE event_id = ?",
        (status.value, event_id),
    )
    conn.commit()
    conn.close()

    return {
        "event_id": event_id,
        "review_status": status.value,
        "reviewed_by": reviewed_by,
        "reviewed_at": datetime.now().isoformat(),
        "notes": notes,
    }


@router.get("/audit/{event_id}/status")
def get_review_status(event_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT review_status FROM audit_events WHERE event_id = ?", (event_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    return {"event_id": event_id, "review_status": row[0]}