"""Chain verification: walks the full audit log in insertion order and confirms
tamper-evidence holds.

Two independent things can go wrong with a record, and we distinguish them because
they imply different failure modes for a reviewer investigating a break:

1. CONTENT_MISMATCH: the record's stored content_hash does not match a hash freshly
   recomputed from its current field values. This means the record itself was edited
   after being written (e.g., someone changed `payload` or `actor_id` directly in the
   database).

2. BROKEN_LINK: the record's stored previous_hash does not match the content_hash of
   the record immediately before it in the chain. This means either the prior record
   was altered (and its hash changed as a result, even if this record itself is
   untouched), or a record was deleted/inserted out of band, breaking the linkage.

A single tampering event on a "middle" record typically produces both a
CONTENT_MISMATCH on that record AND a cascading BROKEN_LINK on the very next record
(since the next record's previous_hash was computed against the original, now-invalid
hash). We report the FIRST inconsistency encountered walking forward from the start of
the chain, per the assignment's requirement to identify "which record is the first
inconsistency."
"""
import sqlite3
from dataclasses import dataclass
from enum import Enum

from app.hash_chain import GENESIS_HASH, compute_content_hash, hash_payload_fields
import json


class ViolationType(str, Enum):
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    BROKEN_LINK = "BROKEN_LINK"


@dataclass
class VerificationResult:
    intact: bool
    records_checked: int
    first_violation_record_id: int | None = None
    violation_type: ViolationType | None = None
    detail: str | None = None


def verify_chain(conn: sqlite3.Connection) -> VerificationResult:
    rows = conn.execute(
        """
        SELECT id, event_type, actor_id, resource_type, resource_id, payload,
               timestamp, content_hash, previous_hash, archived
        FROM events
        ORDER BY id ASC
        """
    ).fetchall()

    expected_previous_hash = GENESIS_HASH
    records_checked = 0

    for row in rows:
        records_checked += 1

        # Archived records are skipped for content/link re-verification per the
        # retention design (Scenario B) -- their hash is preserved at archive time
        # and re-checking it here would require access to the pre-archive payload
        # state, which is out of scope for base chain walking. See app/retention.py
        # (added in Scenario B) for how archived records are actually protected.
        if row["archived"]:
            expected_previous_hash = row["content_hash"]
            continue

        payload = json.loads(row["payload"])
        recomputed_hash = compute_content_hash(
            event_type=row["event_type"],
            actor_id=row["actor_id"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            timestamp=row["timestamp"],
            payload_field_hashes=hash_payload_fields(payload),
        )

        if recomputed_hash != row["content_hash"]:
            return VerificationResult(
                intact=False,
                records_checked=records_checked,
                first_violation_record_id=row["id"],
                violation_type=ViolationType.CONTENT_MISMATCH,
                detail=(
                    f"Record {row['id']}'s stored content_hash does not match a hash "
                    "recomputed from its current field values. The record's content "
                    "was modified after it was written."
                ),
            )

        if row["previous_hash"] != expected_previous_hash:
            return VerificationResult(
                intact=False,
                records_checked=records_checked,
                first_violation_record_id=row["id"],
                violation_type=ViolationType.BROKEN_LINK,
                detail=(
                    f"Record {row['id']}'s previous_hash does not match the "
                    f"content_hash of the preceding record. The chain linkage is "
                    "broken at this point (a prior record may have been altered, "
                    "or records were deleted/reordered)."
                ),
            )

        expected_previous_hash = row["content_hash"]

    return VerificationResult(intact=True, records_checked=records_checked)
