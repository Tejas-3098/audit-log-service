from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query, status

from app.db import get_connection, init_db
from app.events import append_event
from app.queries import EventQuery, query_events
from app.redaction import redact_fields
from app.retention import archive_older_than
from app.schemas import (
    ArchiveResultOut,
    EventCreate,
    EventOut,
    EventPage,
    RedactRequest,
    RedactResultOut,
    VerifyResult,
)
from app.verify import verify_chain


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Audit Log Service",
    description="Tamper-evident, append-only audit log service.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/audit/events", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def create_event(event: EventCreate) -> EventOut:
    """Append a new event to the audit log.

    There is deliberately no corresponding PUT/PATCH/DELETE route for events anywhere
    in this API -- append-only is enforced by the absence of any mutation path, not by
    a permission check on an update route that could exist.
    """
    conn = get_connection()
    try:
        return append_event(conn, event)
    finally:
        conn.close()


@app.get("/audit/events", response_model=EventPage)
def list_events(
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    event_type: str | None = None,
    timestamp_from: datetime | None = None,
    timestamp_to: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> EventPage:
    """Query audit events with optional filters and pagination.

    All filters are optional and combine with AND semantics. timestamp_from/to filter
    against the caller-supplied `timestamp` field (not `received_at`), since that's the
    field the assignment's spec refers to as the event's time.
    """
    conn = get_connection()
    try:
        query = EventQuery(
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type=event_type,
            timestamp_from=timestamp_from.isoformat() if timestamp_from else None,
            timestamp_to=timestamp_to.isoformat() if timestamp_to else None,
            limit=limit,
            offset=offset,
        )
        items, total = query_events(conn, query)
        return EventPage(items=items, total=total, limit=limit, offset=offset)
    finally:
        conn.close()


@app.get("/audit/verify", response_model=VerifyResult)
def verify() -> VerifyResult:
    """Walk the full audit chain and report whether it's intact.

    On failure, reports the first inconsistent record and distinguishes a
    CONTENT_MISMATCH (the record's own hash no longer matches its content) from a
    BROKEN_LINK (the record's previous_hash doesn't match the prior record's hash).
    See app/verify.py for the full reasoning behind this distinction.
    """
    conn = get_connection()
    try:
        result = verify_chain(conn)
        return VerifyResult(
            intact=result.intact,
            records_checked=result.records_checked,
            first_violation_record_id=result.first_violation_record_id,
            violation_type=result.violation_type.value if result.violation_type else None,
            detail=result.detail,
        )
    finally:
        conn.close()


@app.post("/audit/retention/archive", response_model=ArchiveResultOut)
def archive_records(older_than_days: int = Query(..., ge=0)) -> ArchiveResultOut:
    """Archive (soft-delete) all non-archived records whose event timestamp is older
    than `older_than_days`. Archived records are never physically removed -- see
    app/retention.py for why that matters for chain continuity.

    This is a manually-triggered operation for this scope, not a scheduled background
    job. See PLAN.md / ARCHITECTURE.md for the documented production gap.
    """
    conn = get_connection()
    try:
        result = archive_older_than(conn, older_than_days)
        return ArchiveResultOut(
            archived_count=result.archived_count,
            archived_record_ids=result.archived_record_ids,
        )
    finally:
        conn.close()


@app.post("/audit/events/{event_id}/redact", response_model=RedactResultOut)
def redact_event_fields(event_id: int, request: RedactRequest) -> RedactResultOut:
    """Redact one or more payload fields on a stored event.

    The record's content_hash is NOT changed by this operation -- see
    app/redaction.py for the full mechanism. /audit/verify will continue to report
    the chain as intact after redaction, because it recomputes hashes using
    effective_payload_field_hashes(), which substitutes the preserved original
    field-hash for any redacted field rather than hashing the placeholder value.

    Idempotent: re-redacting an already-redacted field is a no-op (reported in
    already_redacted_fields, not an error) rather than double-hashing a placeholder.
    """
    conn = get_connection()
    try:
        try:
            result = redact_fields(conn, event_id, request.fields)
        except ValueError:
            raise HTTPException(status_code=404, detail=f"No event with id {event_id}")
        return RedactResultOut(
            event_id=result.event_id,
            redacted_fields=result.redacted_fields,
            already_redacted_fields=result.already_redacted_fields,
            fields_not_found=result.fields_not_found,
        )
    finally:
        conn.close()
