"""
Audit Service — Chain Verification

Walks the entire stored chain and recomputes each hash,
comparing against what was actually stored. Detects any tampering.
"""

from fastapi import APIRouter
from schemas import SecurityEvent
from hash_chain import compute_record_hash, GENESIS_HASH
from storage import get_all_records

router = APIRouter()


@router.get("/audit/verify")
def verify_chain():
    records = get_all_records()

    if not records:
        return {"valid": True, "message": "No records to verify", "checked": 0}

    expected_previous_hash = GENESIS_HASH

    for i, row in enumerate(records):
        event = SecurityEvent.model_validate_json(row["event_json"])

        # Check 1: does this record's previous_hash match what we expect?
        if row["previous_hash"] != expected_previous_hash:
            return {
                "valid": False,
                "message": f"Chain broken at record {i} (event_id={row['event_id']}): previous_hash mismatch",
                "checked": i,
            }

        # Check 2: recompute this record's hash and compare
        recomputed = compute_record_hash(event, row["previous_hash"])
        if recomputed != row["record_hash"]:
            return {
                "valid": False,
                "message": f"Tampering detected at record {i} (event_id={row['event_id']}): hash mismatch",
                "checked": i,
            }

        expected_previous_hash = row["record_hash"]

    return {"valid": True, "message": "Chain intact", "checked": len(records)}