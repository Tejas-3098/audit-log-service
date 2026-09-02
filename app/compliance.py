"""Scenario C: compliance/regulatory reporting.

See SCENARIO_C.md for the full clarification process behind this design. In short:
this endpoint answers "regulators need to be able to audit access to client account
data" by always scoping to resourceType == ACCOUNT (the assumed mapping for "client
account data" in this service's data model), reusing the existing query/pagination
logic rather than building a separate reporting subsystem, and -- notably -- writing
its own audit event every time it's called, so that "who looked at account access
data" is itself always answerable by a later audit.
"""
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from app.events import append_event
from app.queries import EventQuery, query_events
from app.schemas import EventCreate, EventOut

ACCOUNT_ACCESS_RESOURCE_TYPE = "ACCOUNT"


@dataclass
class ComplianceReport:
    items: list[EventOut]
    total: int
    limit: int
    offset: int
    report_event_id: int


def generate_account_access_report(
    conn: sqlite3.Connection,
    requested_by: str,
    actor_id: str | None = None,
    event_type: str | None = None,
    timestamp_from: str | None = None,
    timestamp_to: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> ComplianceReport:
    query = EventQuery(
        actor_id=actor_id,
        resource_type=ACCOUNT_ACCESS_RESOURCE_TYPE,  # always forced -- see SCENARIO_C.md
        event_type=event_type,
        timestamp_from=timestamp_from,
        timestamp_to=timestamp_to,
        limit=limit,
        offset=offset,
    )
    items, total = query_events(conn, query)

    # Record the act of generating this report as its own audit event -- addresses
    # SCENARIO_C.md ambiguity #5 (does "access" include the compliance team's own
    # act of looking?) directly, rather than leaving it as a documented gap.
    report_event = append_event(
        conn,
        EventCreate(
            event_type="COMPLIANCE_REPORT_GENERATED",
            actor_id=requested_by,
            resource_type=ACCOUNT_ACCESS_RESOURCE_TYPE,
            resource_id="ALL",
            payload={
                "filters": {
                    "actor_id": actor_id,
                    "event_type": event_type,
                    "timestamp_from": timestamp_from,
                    "timestamp_to": timestamp_to,
                },
                "record_count_returned": len(items),
                "total_matching": total,
            },
            timestamp=datetime.now(timezone.utc),
        ),
    )

    return ComplianceReport(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        report_event_id=report_event.id,
    )
