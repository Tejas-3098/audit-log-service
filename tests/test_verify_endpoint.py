import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    test_db_path = tmp_path / "test_audit_log.db"
    monkeypatch.setattr(db_module, "DB_PATH", test_db_path)
    db_module.init_db()
    yield


def _create(**overrides):
    base = {
        "event_type": "USER_LOGIN",
        "actor_id": "user-1",
        "resource_type": "SESSION",
        "resource_id": "sess-1",
        "payload": {"ip": "10.0.0.1"},
        "timestamp": "2026-09-01T12:00:00+00:00",
    }
    base.update(overrides)
    response = client.post("/audit/events", json=base)
    assert response.status_code == 201
    return response.json()


def test_verify_on_empty_chain_is_intact():
    response = client.get("/audit/verify")
    body = response.json()
    assert body["intact"] is True
    assert body["records_checked"] == 0


def test_verify_on_untouched_chain_is_intact():
    _create()
    _create(actor_id="user-2")
    _create(actor_id="user-3")
    response = client.get("/audit/verify")
    body = response.json()
    assert body["intact"] is True
    assert body["records_checked"] == 3
    assert body["first_violation_record_id"] is None


def test_verify_detects_direct_tampering_of_a_field():
    """This is the assignment's core validation flow: write events, verify (passes),
    directly modify a record in the actual SQLite file (not through the API, which has
    no mutation route), verify again (must detect and localize the break).
    """
    e1 = _create(actor_id="user-1")
    e2 = _create(actor_id="user-2")
    e3 = _create(actor_id="user-3")

    # Sanity check: chain is intact before tampering.
    assert client.get("/audit/verify").json()["intact"] is True

    # Tamper directly in the SQLite file, bypassing the API entirely -- mirrors the
    # assignment's instruction to modify "a record directly in the data store."
    conn = sqlite3.connect(db_module.DB_PATH)
    conn.execute(
        "UPDATE events SET actor_id = ? WHERE id = ?", ("attacker", e2["id"])
    )
    conn.commit()
    conn.close()

    response = client.get("/audit/verify")
    body = response.json()
    assert body["intact"] is False
    assert body["first_violation_record_id"] == e2["id"]
    assert body["violation_type"] == "CONTENT_MISMATCH"


def test_verify_detects_tampering_on_last_record_with_no_cascade():
    """Tampering with the LAST record in the chain produces a pure CONTENT_MISMATCH
    with no downstream BROKEN_LINK to cascade into (there's no record after it),
    isolating this failure mode from the broken-link case tested separately below.
    """
    e1 = _create(actor_id="user-1")
    e2 = _create(actor_id="user-2")

    conn = sqlite3.connect(db_module.DB_PATH)
    conn.execute(
        "UPDATE events SET payload = ? WHERE id = ?",
        (json.dumps({"ip": "9.9.9.9"}), e2["id"]),
    )
    conn.commit()
    conn.close()

    response = client.get("/audit/verify")
    body = response.json()
    assert body["intact"] is False
    assert body["first_violation_record_id"] == e2["id"]
    assert body["violation_type"] == "CONTENT_MISMATCH"


def test_verify_reports_first_violation_when_multiple_records_tampered():
    e1 = _create(actor_id="user-1")
    e2 = _create(actor_id="user-2")
    e3 = _create(actor_id="user-3")

    conn = sqlite3.connect(db_module.DB_PATH)
    # Tamper both e2 and e3 -- verify should report e2 as the FIRST inconsistency,
    # not e3, since we walk forward from the start of the chain.
    conn.execute("UPDATE events SET actor_id = ? WHERE id = ?", ("attacker", e2["id"]))
    conn.execute("UPDATE events SET actor_id = ? WHERE id = ?", ("attacker2", e3["id"]))
    conn.commit()
    conn.close()

    response = client.get("/audit/verify")
    body = response.json()
    assert body["intact"] is False
    assert body["first_violation_record_id"] == e2["id"]


def test_verify_detects_directly_deleted_record_as_broken_link():
    """Deleting a middle record out-of-band (bypassing the API, which has no DELETE
    route) breaks the chain linkage for the record that follows it.
    """
    e1 = _create(actor_id="user-1")
    e2 = _create(actor_id="user-2")
    e3 = _create(actor_id="user-3")

    conn = sqlite3.connect(db_module.DB_PATH)
    conn.execute("DELETE FROM events WHERE id = ?", (e2["id"],))
    conn.commit()
    conn.close()

    response = client.get("/audit/verify")
    body = response.json()
    assert body["intact"] is False
    assert body["first_violation_record_id"] == e3["id"]
    assert body["violation_type"] == "BROKEN_LINK"
