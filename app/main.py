from fastapi import FastAPI, status

from app.db import get_connection, init_db
from app.events import append_event
from app.schemas import EventCreate, EventOut

app = FastAPI(
    title="Audit Log Service",
    description="Tamper-evident, append-only audit log service.",
    version="0.1.0",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


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
