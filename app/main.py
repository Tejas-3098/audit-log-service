from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Query, status

from app.db import get_connection, init_db
from app.events import append_event
from app.queries import EventQuery, query_events
from app.schemas import EventCreate, EventOut, EventPage


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
