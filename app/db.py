"""SQLite connection management and schema.

Kept deliberately simple (stdlib sqlite3, no ORM) so the data file can be opened and
inspected directly with the sqlite3 CLI or any SQLite browser -- this matters for this
project specifically, since part of the validation flow is hand-editing a row in the
actual data store to confirm tamper detection.
"""
import sqlite3
from pathlib import Path

# Tests patch this module-level constant directly (see tests/test_write_api.py) to
# point the app at an isolated throwaway file rather than the dev database.
DB_PATH = Path(__file__).resolve().parent.parent / "audit_log.db"

# Genesis value: the previousHash stored on the very first record in the chain.
# Chosen as 64 zero-characters to match the string length of a SHA-256 hex digest,
# so genesis is visually and structurally consistent with a "real" hash, but is a
# reserved value that can never be produced by SHA-256 output of real content in
# any way that matters here (it's a convention, not a security property).
GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    payload         TEXT NOT NULL,           -- JSON-encoded, may contain per-field
                                              -- redaction placeholders (see redactions
                                              -- table, added in Scenario B)
    timestamp       TEXT NOT NULL,           -- caller-supplied event time (ISO 8601)
    received_at     TEXT NOT NULL,           -- server-assigned ingestion time (ISO 8601)
    content_hash    TEXT NOT NULL,           -- SHA-256 over this record's own fields
    previous_hash   TEXT NOT NULL,           -- content_hash of the prior record, or
                                              -- GENESIS_HASH for the first record
    archived        INTEGER NOT NULL DEFAULT 0,   -- Scenario B: retention
    archived_at     TEXT                          -- Scenario B: retention
);

CREATE INDEX IF NOT EXISTS idx_events_actor ON events (actor_id);
CREATE INDEX IF NOT EXISTS idx_events_resource ON events (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);

-- Scenario B: field-level redaction. Stores the hash of a field's ORIGINAL value,
-- preserved independently of the (now-placeholder) value sitting in events.payload.
-- This is what lets content_hash still recompute correctly after redaction -- see
-- app/redaction.py and app/hash_chain.py for the full reasoning.
CREATE TABLE IF NOT EXISTS redactions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        INTEGER NOT NULL REFERENCES events(id),
    field_name      TEXT NOT NULL,
    field_hash      TEXT NOT NULL,    -- hash of the ORIGINAL (pre-redaction) value
    redacted_at     TEXT NOT NULL,
    UNIQUE (event_id, field_name)
);

CREATE INDEX IF NOT EXISTS idx_redactions_event ON redactions (event_id);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
