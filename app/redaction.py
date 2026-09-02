"""Field-level redaction: replace a payload field's value with a placeholder while
preserving the record's content_hash.

How this works, concretely:
  1. Before overwriting anything, hash the field's CURRENT (original) value and store
     that hash in the `redactions` table, keyed by (event_id, field_name).
  2. Overwrite the field's value in events.payload with a placeholder string.
  3. events.content_hash is left completely untouched -- it was computed at write time
     from the original field hashes and stays valid, because /audit/verify (and any
     other consumer recomputing the hash) is expected to use
     effective_payload_field_hashes(), which substitutes the preserved hash for any
     redacted field rather than hashing the placeholder.

This is Design Option 1 from REQUIREMENTS.md/ARCHITECTURE.md (field-level hash
commitment), chosen over crypto-shredding (Option 3) because it directly solves the
stated problem -- "the original hash covers the original value, so simply removing
the value would invalidate the hash" -- without requiring key-management
infrastructure. See ARCHITECTURE.md for the full trade-off discussion, including why
Option 3 would be the stronger choice for genuine "right to erasure" compliance in a
real production system (this scheme does NOT destroy the original value -- the
original field_hash remains recoverable-in-principle if someone had also retained the
original value elsewhere; true erasure would require Option 3's key destruction).
"""
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from app.hash_chain import hash_payload_fields

REDACTION_PLACEHOLDER = "[REDACTED]"


@dataclass
class RedactionResult:
    event_id: int
    redacted_fields: list[str]
    already_redacted_fields: list[str]
    fields_not_found: list[str]


def redact_fields(conn: sqlite3.Connection, event_id: int, field_names: list[str]) -> RedactionResult:
    row = conn.execute("SELECT payload FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise ValueError(f"No event with id {event_id}")

    payload = json.loads(row["payload"])

    already_redacted_rows = conn.execute(
        "SELECT field_name FROM redactions WHERE event_id = ?", (event_id,)
    ).fetchall()
    already_redacted = {r["field_name"] for r in already_redacted_rows}

    redacted_now: list[str] = []
    already: list[str] = []
    not_found: list[str] = []

    redacted_at = datetime.now(timezone.utc).isoformat()

    for field_name in field_names:
        if field_name not in payload:
            not_found.append(field_name)
            continue
        if field_name in already_redacted:
            already.append(field_name)
            continue

        # Hash the ORIGINAL value before overwriting it -- this must happen before
        # the payload dict is mutated below.
        original_field_hash = hash_payload_fields({field_name: payload[field_name]})[
            field_name
        ]

        conn.execute(
            """
            INSERT INTO redactions (event_id, field_name, field_hash, redacted_at)
            VALUES (?, ?, ?, ?)
            """,
            (event_id, field_name, original_field_hash, redacted_at),
        )

        payload[field_name] = REDACTION_PLACEHOLDER
        redacted_now.append(field_name)

    if redacted_now:
        conn.execute(
            "UPDATE events SET payload = ? WHERE id = ?",
            (json.dumps(payload), event_id),
        )

    conn.commit()

    return RedactionResult(
        event_id=event_id,
        redacted_fields=redacted_now,
        already_redacted_fields=already,
        fields_not_found=not_found,
    )


def get_redaction_hashes(conn: sqlite3.Connection, event_id: int) -> dict:
    """Return {field_name: original_field_hash} for all fields redacted on this event.
    Used by verify.py to recompute content_hash correctly for redacted records.
    """
    rows = conn.execute(
        "SELECT field_name, field_hash FROM redactions WHERE event_id = ?", (event_id,)
    ).fetchall()
    return {r["field_name"]: r["field_hash"] for r in rows}
