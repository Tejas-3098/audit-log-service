from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query, status

from app.auth import require_compliance, require_read, require_write
from app.db import get_connection, init_db
from app.compliance import generate_account_access_report
from app.events import append_event
from app.export import export_bundle
from app.queries import EventQuery, query_events
from app.redaction import redact_fields
from app.retention import archive_older_than
from app.schemas import (
    ArchiveResultOut,
    ComplianceReportOut,
    EventCreate,
    EventOut,
    EventPage,
    ExportBundleOut,
    ExportedRecordOut,
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


@app.post(
    "/audit/events",
    response_model=EventOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_write)],
)
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


@app.get(
    "/audit/events",
    response_model=EventPage,
    dependencies=[Depends(require_read)],
)
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


@app.get(
    "/audit/verify",
    response_model=VerifyResult,
    dependencies=[Depends(require_read)],
)
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


@app.post(
    "/audit/retention/archive",
    response_model=ArchiveResultOut,
    dependencies=[Depends(require_write)],
)
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


@app.post(
    "/audit/events/{event_id}/redact",
    response_model=RedactResultOut,
    dependencies=[Depends(require_write)],
)
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


@app.get(
    "/audit/export",
    response_model=ExportBundleOut,
    dependencies=[Depends(require_read)],
)
def export(
    resource_id: str | None = None,
    actor_id: str | None = None,
) -> ExportBundleOut:
    """Export a self-contained, independently verifiable bundle of records for a
    given resourceId or actorId (at least one required).

    See app/export.py for what a recipient can actually verify from this bundle and
    why it's structured the way it is (previous_hash/next_hash captured from the FULL
    chain at export time, plus a manifest_hash over the whole bundle).
    """
    if resource_id is None and actor_id is None:
        raise HTTPException(
            status_code=400,
            detail="At least one of resource_id or actor_id must be provided.",
        )

    conn = get_connection()
    try:
        bundle = export_bundle(conn, resource_id=resource_id, actor_id=actor_id)
        return ExportBundleOut(
            exported_at=bundle.exported_at,
            filter_resource_id=bundle.filter_resource_id,
            filter_actor_id=bundle.filter_actor_id,
            record_count=bundle.record_count,
            manifest_hash=bundle.manifest_hash,
            records=[
                ExportedRecordOut(
                    id=r.id,
                    event_type=r.event_type,
                    actor_id=r.actor_id,
                    resource_type=r.resource_type,
                    resource_id=r.resource_id,
                    payload=r.payload,
                    timestamp=r.timestamp,
                    received_at=r.received_at,
                    content_hash=r.content_hash,
                    previous_hash=r.previous_hash,
                    next_hash=r.next_hash,
                    archived=r.archived,
                )
                for r in bundle.records
            ],
        )
    finally:
        conn.close()


@app.get(
    "/audit/compliance/account-access-report",
    response_model=ComplianceReportOut,
    dependencies=[Depends(require_compliance)],
)
def compliance_account_access_report(
    requested_by: str = Query(..., description="Identifier of the requesting regulator/compliance user"),
    actor_id: str | None = None,
    event_type: str | None = None,
    timestamp_from: datetime | None = None,
    timestamp_to: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ComplianceReportOut:
    """Scenario C: compliance/regulatory report of access to client account data.

    Always scoped to resourceType == ACCOUNT (the assumed mapping for "client account
    data" in this service -- see SCENARIO_C.md for the full clarification process).
    Every call to this endpoint writes its own COMPLIANCE_REPORT_GENERATED audit
    event, so that who generated an account-access report is itself always subject to
    later audit.

    `requested_by` is required and is recorded as the actor on that audit event --
    stands in for real regulator identity/authentication, which is scoped out of this
    implementation (see SCENARIO_C.md "What was scoped out").
    """
    conn = get_connection()
    try:
        report = generate_account_access_report(
            conn,
            requested_by=requested_by,
            actor_id=actor_id,
            event_type=event_type,
            timestamp_from=timestamp_from.isoformat() if timestamp_from else None,
            timestamp_to=timestamp_to.isoformat() if timestamp_to else None,
            limit=limit,
            offset=offset,
        )
        return ComplianceReportOut(
            items=report.items,
            total=report.total,
            limit=report.limit,
            offset=report.offset,
            report_event_id=report.report_event_id,
        )
    finally:
        conn.close()
