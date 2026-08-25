"""
Audit Service — Storage Layer

Handles all SQLite reads/writes for the audit_events table.
Does not know anything about hashing logic — just persistence.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from schemas import SecurityEvent, AuditRecord

DB_PATH = Path(__file__).resolve().parent / "audit.db"


def init_db():
    """Creates the audit_events table if it doesn't exist yet."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_json TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                stored_at TEXT NOT NULL,
                review_status TEXT DEFAULT 'OPEN'
            )
        """)
        conn.commit()
    finally:
        conn.close()


def get_last_hash() -> str:
    """Returns the record_hash of the most recently stored event, or GENESIS_HASH if empty."""
    from hash_chain import GENESIS_HASH

    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT record_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()

    return row[0] if row else GENESIS_HASH


def save_record(event: SecurityEvent, record_hash: str, previous_hash: str):
    """Inserts a new audit record into the database."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """INSERT INTO audit_events
               (event_id, event_json, record_hash, previous_hash, stored_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.model_dump_json(exclude_none=True),
                record_hash,
                previous_hash,
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_all_records() -> List[Dict]:
    """Returns all stored audit records, in insertion order."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]