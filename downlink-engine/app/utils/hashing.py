"""Cryptographic hashing utilities for telemetry integrity checks."""

import hashlib
import json
from typing import Dict, Any, Union

# Exclude metadata and checksum fields from spacecraft telemetry hash
EXCLUDED_HASH_KEYS = {
    "packet_hash",
    "signature",
    "user_id",
    "source_ip",
    "device_id",
    "session_id",
    "action",
    "role",
    "previous_role"
}


def compute_telemetry_hash(data: Union[Dict[str, Any], Any]) -> str:
    """
    Compute a deterministic SHA-256 hash over canonical spacecraft telemetry fields.
    
    Excludes checksum and ground station metadata fields.
    Fields are sorted alphabetically and serialized consistently.
    """
    if hasattr(data, "model_dump"):
        raw_dict = data.model_dump()
    elif hasattr(data, "dict"):
        raw_dict = data.dict()
    elif isinstance(data, dict):
        raw_dict = data
    else:
        raise ValueError(f"Unsupported data format for hash computation: {type(data)}")

    filtered = {
        k: v for k, v in raw_dict.items()
        if k not in EXCLUDED_HASH_KEYS and v is not None
    }

    # Deterministic JSON representation (sorted keys, no extra whitespace)
    canonical_json = json.dumps(filtered, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def verify_telemetry_hash(data: Union[Dict[str, Any], Any], expected_hash: str) -> bool:
    """Verify if the computed SHA-256 hash matches the expected hash."""
    if not expected_hash:
        return False
    computed = compute_telemetry_hash(data)
    return computed.lower() == expected_hash.strip().lower()
