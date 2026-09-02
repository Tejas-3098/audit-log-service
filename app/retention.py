"""Retention: archive (soft-delete) records older than a configurable window.

Archiving sets `archived=1` and `archived_at` on qualifying records. Archived records
are never physically deleted -- this is deliberate, not an oversight: physical deletion
would remove a record's content_hash from the database entirely, making it impossible
for /audit/verify to confirm chain continuity through that point (the next record's
previous_hash would have nothing to check against). Soft-delete preserves the hash
while allowing the *payload* to eventually be excluded from normal query results or
handled specially, per whatever downstream retention/privacy policy applies -- this
scope only implements the archiving mechanism itself, not payload purging on archive
(see REQUIREMENTS.md/ARCHITECTURE.md for the distinction between "archived" and
"redacted", which are two different operations aimed at two different problems).

This is implemented as an explicit, callable operation (triggered via an endpoint),
not a background scheduled job -- documented as a scope decision, not an oversight. A
production deployment would run this on a schedule (e.g. daily) rather than requiring
someone to call the endpoint.
"""
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class ArchiveResult:
    archived_count: int
    archived_record_ids: list[int]


def archive_older_than(conn: sqlite3.Connection, older_than_days: int) -> ArchiveResult:
    """Archive all non-archived records whose `timestamp` is older than the given
    window. Uses the caller-supplied `timestamp` (event time) rather than
    `received_at`, since retention policy is naturally about how old the *event*
    is, not when the server happened to ingest it.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    archived_at = datetime.now(timezone.utc).isoformat()

    rows = conn.execute(
        "SELECT id FROM events WHERE archived = 0 AND timestamp < ?", (cutoff,)
    ).fetchall()
    ids = [row["id"] for row in rows]

    if ids:
        placeholders = ",".join("?" for _ in ids)
        conn.execute(
            f"UPDATE events SET archived = 1, archived_at = ? WHERE id IN ({placeholders})",
            [archived_at] + ids,
        )
        conn.commit()

    return ArchiveResult(archived_count=len(ids), archived_record_ids=ids)
