import json
import sqlite3

from fastapi.testclient import TestClient

import app.db as db_module
from app.main import app

client = TestClient(app)


def _create(**overrides):
    base = {
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-1",
        "payload": {"account_number": "1234567890", "note": "routine update"},
        "timestamp": "2026-09-02T12:00:00+00:00",
    }
    base.update(overrides)
    response = client.post("/audit/events", json=base)
    assert response.status_code == 201
    return response.json()


def test_redact_replaces_field_value_with_placeholder():
    event = _create()
    response = client.post(
        f"/audit/events/{event['id']}/redact", json={"fields": ["account_number"]}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["redacted_fields"] == ["account_number"]

    query_result = client.get(
        "/audit/events", params={"resource_id": "acct-1"}
    ).json()["items"][0]
    assert query_result["payload"]["account_number"] == "[REDACTED]"
    assert query_result["payload"]["note"] == "routine update"  # untouched


def test_redaction_does_not_break_chain_verification():
    """The central claim of the whole redaction design: redacting a field must NOT
    invalidate the record's content_hash, and /audit/verify must still report the
    chain as intact both before and after.
    """
    e1 = _create()
    e2 = _create(actor_id="user-2", resource_id="acct-2")

    assert client.get("/audit/verify").json()["intact"] is True

    redact_response = client.post(
        f"/audit/events/{e1['id']}/redact", json={"fields": ["account_number"]}
    )
    assert redact_response.status_code == 200

    verify_after = client.get("/audit/verify").json()
    assert verify_after["intact"] is True
    assert verify_after["records_checked"] == 2


def test_redaction_preserved_hash_is_specific_to_the_original_value():
    """Sanity check on the actual security property: verify still recomputes the
    SAME content_hash as before redaction, not merely "no error was raised." We
    confirm this indirectly -- by checking that if someone also tampers a
    NON-redacted field on the same record after redaction, verify still catches
    it. This proves verify is doing a real recomputation, not just skipping
    redacted records wholesale.
    """
    event = _create()
    client.post(f"/audit/events/{event['id']}/redact", json={"fields": ["account_number"]})
    assert client.get("/audit/verify").json()["intact"] is True

    # Now tamper the untouched `note` field directly in the DB.
    conn = sqlite3.connect(db_module.DB_PATH)
    row = conn.execute("SELECT payload FROM events WHERE id = ?", (event["id"],)).fetchone()
    payload = json.loads(row[0])
    payload["note"] = "attacker changed this"
    conn.execute(
        "UPDATE events SET payload = ? WHERE id = ?",
        (json.dumps(payload), event["id"]),
    )
    conn.commit()
    conn.close()

    verify_body = client.get("/audit/verify").json()
    assert verify_body["intact"] is False
    assert verify_body["first_violation_record_id"] == event["id"]
    assert verify_body["violation_type"] == "CONTENT_MISMATCH"


def test_redacting_already_redacted_field_is_idempotent_no_op():
    event = _create()
    first = client.post(
        f"/audit/events/{event['id']}/redact", json={"fields": ["account_number"]}
    ).json()
    second = client.post(
        f"/audit/events/{event['id']}/redact", json={"fields": ["account_number"]}
    ).json()

    assert first["redacted_fields"] == ["account_number"]
    assert second["redacted_fields"] == []
    assert second["already_redacted_fields"] == ["account_number"]

    # Confirm the chain is still intact after the redundant call.
    assert client.get("/audit/verify").json()["intact"] is True


def test_redact_reports_field_not_found():
    event = _create()
    response = client.post(
        f"/audit/events/{event['id']}/redact", json={"fields": ["nonexistent_field"]}
    )
    body = response.json()
    assert body["fields_not_found"] == ["nonexistent_field"]
    assert body["redacted_fields"] == []


def test_redact_nonexistent_event_returns_404():
    response = client.post("/audit/events/99999/redact", json={"fields": ["x"]})
    assert response.status_code == 404


def test_redact_multiple_fields_in_one_call():
    event = _create(payload={"account_number": "111", "ssn": "222", "note": "keep me"})
    response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["account_number", "ssn"]},
    )
    body = response.json()
    assert set(body["redacted_fields"]) == {"account_number", "ssn"}

    query_result = client.get("/audit/events").json()["items"][0]
    assert query_result["payload"]["account_number"] == "[REDACTED]"
    assert query_result["payload"]["ssn"] == "[REDACTED]"
    assert query_result["payload"]["note"] == "keep me"
    assert client.get("/audit/verify").json()["intact"] is True
