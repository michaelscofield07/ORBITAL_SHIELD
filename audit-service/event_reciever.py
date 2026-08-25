"""
Audit Service — Event Receiver

The API endpoint P2/P3/P4/P5 call to submit a SecurityEvent.
Computes the hash chain link and stores it.
"""

from fastapi import APIRouter, HTTPException
from schemas import SecurityEvent
from hash_chain import compute_record_hash
from storage import get_last_hash, save_record

router = APIRouter()


@router.post("/audit/events")
def receive_event(event: SecurityEvent):
    previous_hash = get_last_hash()
    record_hash = compute_record_hash(event, previous_hash)

    try:
        save_record(event, record_hash, previous_hash)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to store event: {e}")

    return {
        "status": "stored",
        "event_id": event.event_id,
        "record_hash": record_hash,
    }