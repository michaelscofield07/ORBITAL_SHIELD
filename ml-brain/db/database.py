"""
ORBITAL SHIELD — ML Correlation Brain
Database layer: SQLite via sqlite3

Tables:
  events        — all ingested raw events from upstream modules
  incidents     — all correlated incidents produced by this module
  feedback_log  — CISO-confirmed verdicts (the labeled training dataset)
  config_audit  — log of every brain config/threshold change
"""

import sqlite3
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("orbital.db")

# DB lives next to this file by default; override via env var DB_PATH
_DEFAULT_DB_PATH = Path(__file__).parent / "orbital_brain.db"


def get_db_path() -> Path:
    import os
    env_path = os.environ.get("DB_PATH")
    return Path(env_path) if env_path else _DEFAULT_DB_PATH


@contextmanager
def get_connection():
    """Thread-safe SQLite connection context manager."""
    conn = sqlite3.connect(str(get_db_path()), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # concurrent read/write safety
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create all tables if they don't already exist."""
    with get_connection() as conn:
        conn.executescript("""
        -- ─── Raw events from upstream modules ────────────────────────────────
        CREATE TABLE IF NOT EXISTS events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id      TEXT    NOT NULL UNIQUE,
            timestamp     TEXT    NOT NULL,
            source        TEXT    NOT NULL,
            satellite_id  TEXT    NOT NULL,
            event_type    TEXT    NOT NULL,
            severity      TEXT    NOT NULL,
            confidence    REAL    NOT NULL,
            description   TEXT    NOT NULL,
            action        TEXT    NOT NULL,
            evidence      TEXT    DEFAULT '{}',
            related_events TEXT   DEFAULT '[]',
            operator_id   TEXT,
            session_id    TEXT,
            ingested_at   TEXT    NOT NULL,
            correlated    INTEGER DEFAULT 0    -- 1 if this event contributed to at least one incident
        );
        CREATE INDEX IF NOT EXISTS idx_events_satellite  ON events(satellite_id);
        CREATE INDEX IF NOT EXISTS idx_events_operator   ON events(operator_id);
        CREATE INDEX IF NOT EXISTS idx_events_session    ON events(session_id);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_source     ON events(source);

        -- ─── Correlated incidents produced by this module ─────────────────────
        CREATE TABLE IF NOT EXISTS incidents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id        TEXT    NOT NULL UNIQUE,
            timestamp       TEXT    NOT NULL,
            source          TEXT    DEFAULT 'ML_BRAIN',
            event_type      TEXT    NOT NULL,
            severity        TEXT    NOT NULL,
            confidence      REAL    NOT NULL,
            description     TEXT    NOT NULL,
            related_events  TEXT    NOT NULL,   -- JSON array of raw event_ids
            action          TEXT    DEFAULT 'HUMAN_REVIEW',
            risk_score      INTEGER NOT NULL,
            rule_id         TEXT    NOT NULL,
            rule_name       TEXT    NOT NULL,
            rule_score      INTEGER NOT NULL,
            ml_adjustment   INTEGER DEFAULT 0,
            satellite_id    TEXT    NOT NULL,
            operator_id     TEXT,
            session_id      TEXT,
            status          TEXT    DEFAULT 'OPEN',
            reviewed_by     TEXT,
            review_notes    TEXT,
            reviewed_at     TEXT,
            created_at      TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incidents_satellite ON incidents(satellite_id);
        CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);

        -- ─── CISO feedback — the labeled training dataset ─────────────────────
        -- NEVER DELETE rows from this table — it is the audit trail
        CREATE TABLE IF NOT EXISTS feedback_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id  TEXT    NOT NULL,
            verdict      TEXT    NOT NULL,    -- CONFIRMED_REAL or FALSE_POSITIVE
            reviewer     TEXT    NOT NULL,
            notes        TEXT,
            rule_id      TEXT,               -- denormalized for training queries
            risk_score   INTEGER,            -- denormalized for training queries
            submitted_at TEXT    NOT NULL,
            used_in_retrain INTEGER DEFAULT 0  -- 1 once incorporated into a retrain batch
        );
        CREATE INDEX IF NOT EXISTS idx_feedback_verdict  ON feedback_log(verdict);
        CREATE INDEX IF NOT EXISTS idx_feedback_incident ON feedback_log(incident_id);

        -- ─── Config / threshold change audit log ─────────────────────────────
        -- Logged as BRAIN_CONFIG_UPDATED events; never delete
        CREATE TABLE IF NOT EXISTS config_audit (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_event_id TEXT  NOT NULL UNIQUE,
            timestamp    TEXT    NOT NULL,
            change_type  TEXT    NOT NULL,    -- THRESHOLD_CHANGE / MODEL_RETRAIN / WEIGHT_CHANGE
            rule_id      TEXT,
            field_name   TEXT,
            before_value TEXT,
            after_value  TEXT,
            triggered_by TEXT,               -- 'retrain_job' / 'manual' / 'ciso_feedback'
            notes        TEXT
        );
        """)

        # ─── Safe, Non-Destructive Migrations for Common Event Model & Model 1 ───
        _add_column_if_missing(conn, "events", "actor", "TEXT")
        _add_column_if_missing(conn, "events", "device_id", "TEXT")
        _add_column_if_missing(conn, "events", "source_ip", "TEXT")
        _add_column_if_missing(conn, "events", "destination_ip", "TEXT")
        _add_column_if_missing(conn, "events", "resource", "TEXT")
        _add_column_if_missing(conn, "events", "authorization_status", "TEXT")
        _add_column_if_missing(conn, "events", "authorization_reason", "TEXT")
        _add_column_if_missing(conn, "events", "data_access", "TEXT DEFAULT '{}'")
        _add_column_if_missing(conn, "events", "firmware_info", "TEXT DEFAULT '{}'")
        _add_column_if_missing(conn, "events", "packet_info", "TEXT DEFAULT '{}'")
        _add_column_if_missing(conn, "events", "raw_log", "TEXT DEFAULT '{}'")
        _add_column_if_missing(conn, "events", "ciso_notes", "TEXT")

        _add_column_if_missing(conn, "incidents", "authorization_status", "TEXT DEFAULT 'UNAUTHORIZED'")
        _add_column_if_missing(conn, "incidents", "authorization_reason", "TEXT")
        _add_column_if_missing(conn, "incidents", "unauthorized_chain", "TEXT DEFAULT '[]'")
        _add_column_if_missing(conn, "incidents", "data_access_summary", "TEXT DEFAULT '{}'")
        _add_column_if_missing(conn, "incidents", "historical_pattern_matched", "INTEGER DEFAULT 0")
        _add_column_if_missing(conn, "incidents", "historical_pattern_details", "TEXT DEFAULT '{}'")
        _add_column_if_missing(conn, "incidents", "incident_document_md", "TEXT")
        _add_column_if_missing(conn, "incidents", "cert_in_report", "TEXT DEFAULT '{}'")

        _add_column_if_missing(conn, "feedback_log", "is_rectified", "INTEGER DEFAULT 0")
        _add_column_if_missing(conn, "feedback_log", "verified_pattern_json", "TEXT")

    logger.info("Database initialised at %s", get_db_path())


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    """Safely adds a column to an existing SQLite table if it does not already exist."""
    cursor = conn.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cursor.fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


# ─────────────────────────────────────────────────────────────
# Event store helpers
# ─────────────────────────────────────────────────────────────

def insert_event(event: dict) -> None:
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO events
            (event_id, timestamp, source, satellite_id, event_type,
             severity, confidence, description, action, evidence,
             related_events, operator_id, session_id, ingested_at,
             actor, device_id, source_ip, destination_ip, resource,
             authorization_status, authorization_reason, data_access,
             firmware_info, packet_info, raw_log, ciso_notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            event["event_id"],
            event["timestamp"],
            event["source"],
            event["satellite_id"],
            event["event_type"],
            event["severity"],
            event["confidence"],
            event["description"],
            event["action"],
            json.dumps(event.get("evidence", {}), default=str),
            json.dumps(event.get("related_events", []), default=str),
            event.get("operator_id"),
            event.get("session_id"),
            datetime.now(timezone.utc).isoformat(),
            event.get("actor") or event.get("operator_id"),
            event.get("device_id"),
            event.get("source_ip"),
            event.get("destination_ip"),
            event.get("resource"),
            event.get("authorization_status"),
            event.get("authorization_reason"),
            json.dumps(event.get("data_access", {}), default=str),
            json.dumps(event.get("firmware_info", {}), default=str),
            json.dumps(event.get("packet_info", {}), default=str),
            json.dumps(event.get("raw_log", {}), default=str),
            event.get("ciso_notes"),
        ))


def fetch_recent_events(since_iso: str, satellite_id: str | None = None) -> list[dict]:
    """Fetch events from the DB for the persistent backing store."""
    with get_connection() as conn:
        if satellite_id:
            rows = conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? AND satellite_id = ? ORDER BY timestamp ASC",
                (since_iso, satellite_id)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
                (since_iso,)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


def mark_events_correlated(event_ids: list[str]) -> None:
    with get_connection() as conn:
        conn.executemany(
            "UPDATE events SET correlated = 1 WHERE event_id = ?",
            [(eid,) for eid in event_ids]
        )


# ─────────────────────────────────────────────────────────────
# Incident store helpers
# ─────────────────────────────────────────────────────────────

def insert_incident(incident: dict) -> None:
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO incidents
            (event_id, timestamp, source, event_type, severity, confidence,
             description, related_events, action, risk_score, rule_id, rule_name,
             rule_score, ml_adjustment, satellite_id, operator_id, session_id,
             status, created_at, authorization_status, authorization_reason,
             unauthorized_chain, data_access_summary, historical_pattern_matched,
             historical_pattern_details, incident_document_md, cert_in_report)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            incident["event_id"],
            incident["timestamp"],
            incident.get("source", "ML_BRAIN"),
            incident["event_type"],
            incident["severity"],
            incident["confidence"],
            incident["description"],
            json.dumps(incident["related_events"], default=str),
            incident.get("action", "HUMAN_REVIEW"),
            incident["risk_score"],
            incident["rule_id"],
            incident["rule_name"],
            incident["rule_score"],
            incident.get("ml_adjustment", 0),
            incident["satellite_id"],
            incident.get("operator_id"),
            incident.get("session_id"),
            incident.get("status", "OPEN"),
            datetime.now(timezone.utc).isoformat(),
            incident.get("authorization_status", "UNAUTHORIZED"),
            incident.get("authorization_reason"),
            json.dumps(incident.get("unauthorized_chain", []), default=str),
            json.dumps(incident.get("data_access_summary", {}), default=str),
            1 if incident.get("historical_pattern_matched") else 0,
            json.dumps(incident.get("historical_pattern_details", {}), default=str),
            incident.get("incident_document_md"),
            json.dumps(incident.get("cert_in_report", {}), default=str),
        ))


def fetch_open_incidents() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE status = 'OPEN' ORDER BY timestamp DESC"
        ).fetchall()
        return [_incident_row_to_dict(r) for r in rows]


def fetch_incident_by_id(incident_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE event_id = ?", (incident_id,)
        ).fetchone()
        return _incident_row_to_dict(row) if row else None


def update_incident_status(incident_id: str, status: str, reviewer: str,
                            notes: str | None, reviewed_at: str) -> None:
    with get_connection() as conn:
        conn.execute("""
            UPDATE incidents
            SET status = ?, reviewed_by = ?, review_notes = ?, reviewed_at = ?
            WHERE event_id = ?
        """, (status, reviewer, notes, reviewed_at, incident_id))


def count_incidents() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]


def count_open_incidents() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM incidents WHERE status='OPEN'").fetchone()[0]


# ─────────────────────────────────────────────────────────────
# Feedback store helpers
# ─────────────────────────────────────────────────────────────

def insert_feedback(incident_id: str, verdict: str, reviewer: str,
                    notes: str | None, rule_id: str | None, risk_score: int | None,
                    is_rectified: int = 0, verified_pattern_json: str | None = None) -> None:
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO feedback_log
            (incident_id, verdict, reviewer, notes, rule_id, risk_score, submitted_at, is_rectified, verified_pattern_json)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (incident_id, verdict, reviewer, notes, rule_id, risk_score,
              datetime.now(timezone.utc).isoformat(), is_rectified, verified_pattern_json))


def fetch_unused_feedback() -> list[dict]:
    """Return feedback not yet incorporated into a retrain batch."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM feedback_log WHERE used_in_retrain = 0 ORDER BY submitted_at ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def fetch_all_feedback() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM feedback_log ORDER BY submitted_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def mark_feedback_used(feedback_ids: list[int]) -> None:
    with get_connection() as conn:
        conn.executemany(
            "UPDATE feedback_log SET used_in_retrain = 1 WHERE id = ?",
            [(fid,) for fid in feedback_ids]
        )


def count_fp_for_rule(rule_id: str, since_retrain: str | None = None) -> int:
    with get_connection() as conn:
        if since_retrain:
            return conn.execute(
                "SELECT COUNT(*) FROM feedback_log WHERE rule_id=? AND verdict='FALSE_POSITIVE' AND submitted_at >= ?",
                (rule_id, since_retrain)
            ).fetchone()[0]
        return conn.execute(
            "SELECT COUNT(*) FROM feedback_log WHERE rule_id=? AND verdict='FALSE_POSITIVE'",
            (rule_id,)
        ).fetchone()[0]


# ─────────────────────────────────────────────────────────────
# Config audit log helpers
# ─────────────────────────────────────────────────────────────

def insert_config_audit(record: dict) -> None:
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO config_audit
            (audit_event_id, timestamp, change_type, rule_id, field_name,
             before_value, after_value, triggered_by, notes)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            record["audit_event_id"],
            record["timestamp"],
            record["change_type"],
            record.get("rule_id"),
            record.get("field_name"),
            str(record.get("before_value")),
            str(record.get("after_value")),
            record.get("triggered_by"),
            record.get("notes"),
        ))


def fetch_config_audit_log() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM config_audit ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()
        return [dict(r) for r in rows]


def count_events() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


# ─────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["evidence"] = json.loads(d.get("evidence") or "{}")
    d["related_events"] = json.loads(d.get("related_events") or "[]")
    if "data_access" in d:
        d["data_access"] = json.loads(d.get("data_access") or "{}")
    if "firmware_info" in d:
        d["firmware_info"] = json.loads(d.get("firmware_info") or "{}")
    if "packet_info" in d:
        d["packet_info"] = json.loads(d.get("packet_info") or "{}")
    if "raw_log" in d:
        d["raw_log"] = json.loads(d.get("raw_log") or "{}")
    return d


def _incident_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["related_events"] = json.loads(d.get("related_events") or "[]")
    if "unauthorized_chain" in d:
        d["unauthorized_chain"] = json.loads(d.get("unauthorized_chain") or "[]")
    if "data_access_summary" in d:
        d["data_access_summary"] = json.loads(d.get("data_access_summary") or "{}")
    if "historical_pattern_details" in d:
        d["historical_pattern_details"] = json.loads(d.get("historical_pattern_details") or "{}")
    if "cert_in_report" in d:
        d["cert_in_report"] = json.loads(d.get("cert_in_report") or "{}")
    return d


# ─────────────────────────────────────────────────────────────
# Historical Pattern & Verified / Rectified Data Helpers
# ─────────────────────────────────────────────────────────────

def search_historical_patterns(rule_id: str | None = None, event_type: str | None = None,
                                exclude_incident_id: str | None = None, limit: int = 5) -> list[dict]:
    """
    Search historical incidents in the database that match a given rule_id
    or event_type, excluding the currently evaluated incident.
    """
    with get_connection() as conn:
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if exclude_incident_id:
            query += " AND event_id != ?"
            params.append(exclude_incident_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, tuple(params)).fetchall()
        return [_incident_row_to_dict(r) for r in rows]


def fetch_historical_data_access(matched_incident_ids: list[str]) -> list[dict]:
    """
    Retrieves all data access records from contributing events of historical incidents.
    """
    if not matched_incident_ids:
        return []
    with get_connection() as conn:
        placeholders = ",".join("?" * len(matched_incident_ids))
        query = f"SELECT * FROM incidents WHERE event_id IN ({placeholders})"
        inc_rows = conn.execute(query, tuple(matched_incident_ids)).fetchall()
        incidents = [_incident_row_to_dict(r) for r in inc_rows]

        all_event_ids = []
        for inc in incidents:
            all_event_ids.extend(inc.get("related_events", []))

        if not all_event_ids:
            return []

        ev_placeholders = ",".join("?" * len(all_event_ids))
        ev_query = f"SELECT * FROM events WHERE event_id IN ({ev_placeholders})"
        ev_rows = conn.execute(ev_query, tuple(all_event_ids)).fetchall()
        events = [_row_to_dict(r) for r in ev_rows]

        data_accesses = []
        for ev in events:
            da = ev.get("data_access") or {}
            if da and any(v for v in da.values()):
                data_accesses.append({
                    "event_id": ev["event_id"],
                    "timestamp": ev["timestamp"],
                    "actor": ev.get("actor") or ev.get("operator_id"),
                    "data_access": da,
                    "resource": ev.get("resource"),
                })
        return data_accesses


def fetch_verified_rectified_signatures() -> list[dict]:
    """
    Fetches all verdicts where CISO verified the activity as legitimate,
    rectified, or false positive.
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM feedback_log WHERE verdict IN ('CONFIRMED_REAL', 'FALSE_POSITIVE', 'RECTIFIED', 'VERIFIED_LEGITIMATE') ORDER BY submitted_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def is_event_or_pattern_rectified(event_dict: dict) -> tuple[bool, str | None]:
    """
    Checks whether the incoming event matches a previously rectified or
    verified-legitimate operation, preventing redundant alerts.
    """
    actor = event_dict.get("actor") or event_dict.get("operator_id")
    rule_id = event_dict.get("rule_id")

    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM feedback_log WHERE verdict IN ('RECTIFIED', 'VERIFIED_LEGITIMATE', 'FALSE_POSITIVE') ORDER BY submitted_at DESC LIMIT 50"
        ).fetchall()
        for r in rows:
            vp = r["verified_pattern_json"]
            if vp:
                try:
                    pattern = json.loads(vp)
                    if actor and pattern.get("actor") == actor:
                        return True, f"Operator/Actor {actor} matches verified legitimate baseline ({r['verdict']}): {r['notes']}"
                    if rule_id and pattern.get("rule_id") == rule_id:
                        return True, f"Rule {rule_id} matches verified pattern: {r['notes']}"
                except Exception:
                    pass
            if rule_id and r["rule_id"] == rule_id and r["verdict"] in ('RECTIFIED', 'VERIFIED_LEGITIMATE'):
                return True, f"Activity under {rule_id} was previously rectified by {r['reviewer']}: {r['notes']}"

    return False, None

