"""
Audit Service — Hash Chain Logic

Pure functions: no database access. Computing and verifying
hashes only. This is what makes the audit log tamper-evident —
each record's hash depends on the previous record's hash.
"""

import hashlib
import json
from schemas import SecurityEvent


GENESIS_HASH = "0" * 64  # the "previous hash" for the very first event ever stored


def compute_record_hash(event: SecurityEvent, previous_hash: str) -> str:
    """
    Computes the hash for one audit record.
    Combines the event's data with the previous record's hash,
    so altering ANY past event changes this hash too.
    """
    event_json = event.model_dump_json(exclude_none=True)
    combined = f"{previous_hash}{event_json}"
    return hashlib.sha256(combined.encode()).hexdigest()


def is_chain_link_valid(event: SecurityEvent, previous_hash: str, claimed_hash: str) -> bool:
    """
    Recomputes the hash for a given event + previous_hash,
    and checks it matches what was actually stored.
    """
    recomputed = compute_record_hash(event, previous_hash)
    return recomputed == claimed_hash