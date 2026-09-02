"""Event query logic: read-only, filtered, paginated access to the audit log.

Filtering supports any combination of actorId, resourceType+resourceId, eventType,
and a timestamp range (from/to), per the assignment spec. Pagination uses simple
offset/limit rather than cursor-based pagination -- documented as a deliberate scope
choice in ARCHITECTURE.md (simpler to implement and reason about; a real production
system handling very large result sets would likely move to cursor-based pagination
to avoid the performance cliff of large OFFSET values in SQL).
"""
import json
import sqlite3
from dataclasses import dataclass

from app.events import row_to_event_out
from app.schemas import EventOut


@dataclass
class EventQuery:
    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    event_type: str | None = None
    timestamp_from: str | None = None
    timestamp_to: str | None = None
    limit: int = 50
    offset: int = 0


def query_events(conn: sqlite3.Connection, query: EventQuery) -> tuple[list[EventOut], int]:
    """Returns (page_of_events, total_matching_count) for pagination metadata.

    Note: resource_type and resource_id are only meaningful together, per the spec
    ("resourceType and resourceId" listed as one combined filter dimension) -- but
    we allow them independently too since it's a strict superset of functionality
    and doesn't complicate the query.
    """
    where_clauses = []
    params: list = []

    if query.actor_id is not None:
        where_clauses.append("actor_id = ?")
        params.append(query.actor_id)
    if query.resource_type is not None:
        where_clauses.append("resource_type = ?")
        params.append(query.resource_type)
    if query.resource_id is not None:
        where_clauses.append("resource_id = ?")
        params.append(query.resource_id)
    if query.event_type is not None:
        where_clauses.append("event_type = ?")
        params.append(query.event_type)
    if query.timestamp_from is not None:
        where_clauses.append("timestamp >= ?")
        params.append(query.timestamp_from)
    if query.timestamp_to is not None:
        where_clauses.append("timestamp <= ?")
        params.append(query.timestamp_to)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    count_row = conn.execute(
        f"SELECT COUNT(*) as total FROM events {where_sql}", params
    ).fetchone()
    total = count_row["total"]

    rows = conn.execute(
        f"""
        SELECT * FROM events {where_sql}
        ORDER BY id ASC
        LIMIT ? OFFSET ?
        """,
        params + [query.limit, query.offset],
    ).fetchall()

    return [row_to_event_out(row) for row in rows], total
