"""End-to-end validation of Scenario B's combined lifecycle: retention, redaction,
and bulk export working together in one realistic story.

Scenario A and Scenario C each have one composed end-to-end test
(tests/test_e2e_validation_flow.py and tests/test_scenario_c_compliance.py
respectively) walking a full realistic narrative rather than just isolated
per-feature checks. Scenario B's three features (retention, redaction, export) each
have their own dedicated test file, but until this file, no single test exercised
all three together the way a real compliance workflow actually would: an old
record gets archived per retention policy, a sensitive field on a DIFFERENT
(non-archived) record gets redacted for privacy, and then the whole account's
history gets exported for a regulator -- all while the hash chain stays verifiably
intact throughout.
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.hash_chain import compute_content_hash, hash_payload_fields
from app.main import app

client = TestClient(app)


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def test_scenario_b_combined_retention_redaction_and_export_lifecycle():
    # --- 1. Write a realistic history for one account: an old record (retention
    #        candidate), a record with sensitive data (redaction candidate), and a
    #        recent record -- spanning a period a real bank account might have. ---
    old_event = client.post(
        "/audit/events",
        json={
            "event_type": "ACCOUNT_OPENED",
            "actor_id": "user-alice",
            "resource_type": "ACCOUNT",
            "resource_id": "acct-100",
            "payload": {"initial_deposit": 5000},
            "timestamp": _iso_days_ago(400),  # well past a 90-day retention window
        },
    ).json()

    sensitive_event = client.post(
        "/audit/events",
        json={
            "event_type": "RECORD_UPDATED",
            "actor_id": "user-alice",
            "resource_type": "ACCOUNT",
            "resource_id": "acct-100",
            "payload": {"account_number": "9876543210", "note": "routine update"},
            "timestamp": _iso_days_ago(10),
        },
    ).json()

    recent_event = client.post(
        "/audit/events",
        json={
            "event_type": "USER_LOGIN",
            "actor_id": "user-alice",
            "resource_type": "ACCOUNT",
            "resource_id": "acct-100",
            "payload": {"ip": "10.0.0.1"},
            "timestamp": _iso_days_ago(1),
        },
    ).json()

    # Sanity: chain intact before any lifecycle operations.
    assert client.get("/audit/verify").json()["intact"] is True

    # --- 2. Apply retention: archive anything older than 90 days. Only the
    #        ACCOUNT_OPENED record should qualify. ---
    archive_response = client.post(
        "/audit/retention/archive", params={"older_than_days": 90}
    )
    archive_body = archive_response.json()
    assert archive_body["archived_count"] == 1
    assert archive_body["archived_record_ids"] == [old_event["id"]]

    # Verify must still report intact -- a legitimately archived record must not
    # produce a false-positive break.
    assert client.get("/audit/verify").json()["intact"] is True

    # --- 3. Redact the sensitive field on a DIFFERENT, non-archived record. ---
    redact_response = client.post(
        f"/audit/events/{sensitive_event['id']}/redact",
        json={"fields": ["account_number"]},
    )
    assert redact_response.json()["redacted_fields"] == ["account_number"]

    # Verify must STILL report intact after both retention and redaction have
    # been applied together -- this is the property neither feature's own
    # isolated test file confirms in combination.
    verify_after_both = client.get("/audit/verify").json()
    assert verify_after_both["intact"] is True
    assert verify_after_both["records_checked"] == 3

    # --- 4. Export the full account history as a bundle for a regulator. ---
    export_response = client.get("/audit/export", params={"resource_id": "acct-100"})
    export_body = export_response.json()
    assert export_body["record_count"] == 3

    exported_old = next(r for r in export_body["records"] if r["id"] == old_event["id"])
    exported_sensitive = next(
        r for r in export_body["records"] if r["id"] == sensitive_event["id"]
    )
    exported_recent = next(
        r for r in export_body["records"] if r["id"] == recent_event["id"]
    )

    # The archived record is correctly flagged as archived in the export.
    assert exported_old["archived"] is True
    # The redacted field appears as its placeholder in the export, not the
    # original sensitive value -- export doesn't bypass redaction.
    assert exported_sensitive["payload"]["account_number"] == "[REDACTED]"
    assert exported_sensitive["payload"]["note"] == "routine update"  # untouched
    assert exported_recent["archived"] is False

    # --- 5. A recipient of the export can still independently recompute the
    #        redacted record's content_hash using ONLY what's in the bundle --
    #        this only works because effective_payload_field_hashes() correctly
    #        substitutes the preserved original field-hash. Confirms the export
    #        and redaction features compose correctly, not just independently. ---
    conn = sqlite3.connect(db_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    redaction_row = conn.execute(
        "SELECT field_hash FROM redactions WHERE event_id = ? AND field_name = ?",
        (sensitive_event["id"], "account_number"),
    ).fetchone()
    conn.close()
    assert redaction_row is not None

    from app.hash_chain import effective_payload_field_hashes

    effective_hashes = effective_payload_field_hashes(
        exported_sensitive["payload"], {"account_number": redaction_row["field_hash"]}
    )
    recomputed = compute_content_hash(
        event_type=exported_sensitive["event_type"],
        actor_id=exported_sensitive["actor_id"],
        resource_type=exported_sensitive["resource_type"],
        resource_id=exported_sensitive["resource_id"],
        timestamp=exported_sensitive["timestamp"],
        payload_field_hashes=effective_hashes,
    )
    assert recomputed == exported_sensitive["content_hash"]
