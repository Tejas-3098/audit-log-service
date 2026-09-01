"""SQLite connection management.

Kept deliberately simple (stdlib sqlite3, no ORM) so the data file can be opened and
inspected directly with the sqlite3 CLI or any SQLite browser -- this matters for this
project specifically, since part of the validation flow is hand-editing a row in the
actual data store to confirm tamper detection.
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "audit_log.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Schema creation. Table definitions added in the next commit (Task 2)."""
    conn = get_connection()
    conn.close()
