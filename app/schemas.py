"""Pydantic request/response models."""
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    """Request body for POST /audit/events.

    Note: `timestamp` is caller-supplied and treated as the event's source-of-truth
    time (e.g., when the underlying action actually occurred). The server additionally
    records its own `received_at` at write time -- see EventOut. This dual-timestamp
    approach was a deliberate design decision (see REQUIREMENTS.md / ARCHITECTURE.md):
    it preserves the caller's authoritative event time while still capturing an
    independent, server-controlled ingestion time that isn't subject to client clock
    drift or manipulation.
    """

    event_type: str = Field(..., min_length=1, examples=["USER_LOGIN"])
    actor_id: str = Field(..., min_length=1, examples=["user-123"])
    resource_type: str = Field(..., min_length=1, examples=["ACCOUNT"])
    resource_id: str = Field(..., min_length=1, examples=["acct-456"])
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(
        ..., description="Caller-supplied event time, ISO 8601. Must include timezone info."
    )


class EventOut(BaseModel):
    """Response body representing a stored event."""

    id: int
    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: dict[str, Any]
    timestamp: str
    received_at: str
    content_hash: str
    previous_hash: str
    archived: bool
    archived_at: str | None = None


class EventPage(BaseModel):
    """Paginated response for GET /audit/events."""

    items: list[EventOut]
    total: int
    limit: int
    offset: int


class VerifyResult(BaseModel):
    """Response body for GET /audit/verify."""

    intact: bool
    records_checked: int
    first_violation_record_id: int | None = None
    violation_type: str | None = None
    detail: str | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
