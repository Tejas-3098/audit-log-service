"""Bulk export: produce a self-contained, independently verifiable bundle of records
for a given resourceId or actorId.

The interesting design problem here: an export is a SUBSET of the full chain, not the
whole thing. A recipient given only the subset can't walk it as a mini hash-chain the
way /audit/verify walks the full table, because consecutive records in the export
generally aren't consecutive in the real chain -- record N's previous_hash points to
some other record that isn't necessarily in this export at all.

So the bundle includes, for each record, three things captured at export time:
  1. The record's own fields + content_hash -- a recipient can independently recompute
     content_hash from the fields using the same (documented, public) hashing scheme,
     confirming THIS record's content hasn't been altered since export.
  2. previous_hash -- the content_hash of whatever record preceded it in the FULL
     chain (already stored on every record).
  3. next_hash -- the content_hash of whatever record followed it in the FULL chain
     at export time. This is NOT normally stored (verify.py doesn't need it, since it
     walks forward and only ever needs the previous link) -- it's computed specifically
     for export, by walking the full ordered table once and looking at each matched
     record's neighbor.

Together, (2) and (3) let a recipient who later gets independent access to the live
service (e.g., a follow-up /audit/verify call, or a second export) confirm this
record's *position* in the chain is still consistent -- i.e., that it hasn't been
quietly removed or reordered since export -- without needing every intervening record
handed to them upfront.

Finally, a manifest_hash over the whole bundle (a hash of the sorted list of exported
record ids + content_hashes) lets a recipient detect if the EXPORT ITSELF was altered
in transit or storage after being produced, independent of anything about the live
chain.
"""
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.hash_chain import sha256_hex


@dataclass
class ExportedRecord:
    id: int
    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: dict
    timestamp: str
    received_at: str
    content_hash: str
    previous_hash: str
    next_hash: str | None
    archived: bool


@dataclass
class ExportBundle:
    exported_at: str
    filter_resource_id: str | None
    filter_actor_id: str | None
    record_count: int
    manifest_hash: str
    records: list[ExportedRecord] = field(default_factory=list)


def export_bundle(
    conn: sqlite3.Connection,
    resource_id: str | None = None,
    actor_id: str | None = None,
) -> ExportBundle:
    if resource_id is None and actor_id is None:
        raise ValueError("At least one of resource_id or actor_id must be provided.")

    # Walk the FULL chain once, in order, so we can determine each record's true
    # chain-neighbor (next_hash) -- this can't be derived from the filtered subset
    # alone.
    all_rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()

    matched: list[ExportedRecord] = []
    for i, row in enumerate(all_rows):
        if resource_id is not None and row["resource_id"] != resource_id:
            continue
        if actor_id is not None and row["actor_id"] != actor_id:
            continue

        next_hash = all_rows[i + 1]["content_hash"] if i + 1 < len(all_rows) else None

        matched.append(
            ExportedRecord(
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
                next_hash=next_hash,
                archived=bool(row["archived"]),
            )
        )

    manifest_source = json.dumps(
        sorted([(r.id, r.content_hash) for r in matched]),
        sort_keys=True,
        separators=(",", ":"),
    )
    manifest_hash = sha256_hex(manifest_source)

    return ExportBundle(
        exported_at=datetime.now(timezone.utc).isoformat(),
        filter_resource_id=resource_id,
        filter_actor_id=actor_id,
        record_count=len(matched),
        manifest_hash=manifest_hash,
        records=matched,
    )
