"""Event write logic: append-only inserts with hash-chain linking.

Deliberately, this module exposes no update or delete function at all -- not "blocked
by a check," genuinely absent. That's what makes the write API append-only: there is no
code path anywhere in this service capable of mutating or removing a stored event.
"""
import json
import sqlite3

from app.hash_chain import GENESIS_HASH, compute_content_hash, hash_payload_fields
from app.schemas import EventCreate, EventOut, now_iso


def _row_to_event_out(row: sqlite3.Row) -> EventOut:
    return EventOut(
        id=row["id"],
        event_type=row["event_type"],
        actor_id=row["actor_id"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        payload=json.loads(row["payload"]),
        timestamp=row["timestamp"],
        received_at=row["received_at"],
        content_hash=row["content_hash"],
        previous_hash=row["previous_hash"],
        archived=bool(row["archived"]),
        archived_at=row["archived_at"],
    )


def get_latest_content_hash(conn: sqlite3.Connection) -> str:
    """Return the content_hash of the most recently inserted record, or GENESIS_HASH
    if the chain is empty. Ordered by id (insertion order), which is the chain's
    canonical order -- not by timestamp, since timestamp is caller-supplied and not
    trustworthy for ordering purposes.
    """
    row = conn.execute(
        "SELECT content_hash FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["content_hash"] if row else GENESIS_HASH


def append_event(conn: sqlite3.Connection, event: EventCreate) -> EventOut:
    previous_hash = get_latest_content_hash(conn)
    payload_field_hashes = hash_payload_fields(event.payload)

    timestamp_iso = event.timestamp.isoformat()

    content_hash = compute_content_hash(
        event_type=event.event_type,
        actor_id=event.actor_id,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        timestamp=timestamp_iso,
        payload_field_hashes=payload_field_hashes,
    )

    received_at = now_iso()

    cursor = conn.execute(
        """
        INSERT INTO events (
            event_type, actor_id, resource_type, resource_id, payload,
            timestamp, received_at, content_hash, previous_hash, archived, archived_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
        """,
        (
            event.event_type,
            event.actor_id,
            event.resource_type,
            event.resource_id,
            json.dumps(event.payload),
            timestamp_iso,
            received_at,
            content_hash,
            previous_hash,
        ),
    )
    conn.commit()

    row = conn.execute(
        "SELECT * FROM events WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_event_out(row)
