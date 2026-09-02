import sqlite3
from datetime import datetime, timedelta, timezone

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


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _create(**overrides):
    base = {
        "event_type": "USER_LOGIN",
        "actor_id": "user-1",
        "resource_type": "SESSION",
        "resource_id": "sess-1",
        "payload": {},
        "timestamp": _iso_days_ago(0),
    }
    base.update(overrides)
    response = client.post("/audit/events", json=base)
    assert response.status_code == 201
    return response.json()


def test_archive_moves_old_records_only():
    old_event = _create(timestamp=_iso_days_ago(100))
    recent_event = _create(timestamp=_iso_days_ago(1))

    response = client.post("/audit/retention/archive", params={"older_than_days": 90})
    body = response.json()

    assert body["archived_count"] == 1
    assert body["archived_record_ids"] == [old_event["id"]]

    # Confirm via direct DB read that the recent event was untouched.
    conn = sqlite3.connect(db_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    old_row = conn.execute(
        "SELECT * FROM events WHERE id = ?", (old_event["id"],)
    ).fetchone()
    recent_row = conn.execute(
        "SELECT * FROM events WHERE id = ?", (recent_event["id"],)
    ).fetchone()
    conn.close()

    assert old_row["archived"] == 1
    assert old_row["archived_at"] is not None
    assert recent_row["archived"] == 0
    assert recent_row["archived_at"] is None


def test_archive_does_not_physically_delete_records():
    old_event = _create(timestamp=_iso_days_ago(100))
    client.post("/audit/retention/archive", params={"older_than_days": 90})

    conn = sqlite3.connect(db_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM events WHERE id = ?", (old_event["id"],)).fetchone()
    conn.close()

    assert row is not None
    assert row["content_hash"]  # hash preserved, needed for chain continuity


def test_verify_does_not_false_positive_on_legitimately_archived_records():
    """The core requirement from the spec: 'The chain verification endpoint must
    handle the presence of archived records correctly and not report a false
    positive break for records that were legitimately archived per policy.'
    """
    e1 = _create(timestamp=_iso_days_ago(100))
    e2 = _create(timestamp=_iso_days_ago(50))
    e3 = _create(timestamp=_iso_days_ago(1))

    # Archive only the oldest record.
    archive_response = client.post(
        "/audit/retention/archive", params={"older_than_days": 90}
    )
    assert archive_response.json()["archived_count"] == 1

    verify_response = client.get("/audit/verify")
    body = verify_response.json()
    assert body["intact"] is True
    assert body["records_checked"] == 3


def test_verify_still_detects_tampering_on_non_archived_record_in_mixed_chain():
    """Archiving one record shouldn't blind /audit/verify to real tampering
    elsewhere in the same chain.
    """
    e1 = _create(timestamp=_iso_days_ago(100))
    e2 = _create(timestamp=_iso_days_ago(1), actor_id="user-2")

    client.post("/audit/retention/archive", params={"older_than_days": 90})
    assert client.get("/audit/verify").json()["intact"] is True

    conn = sqlite3.connect(db_module.DB_PATH)
    conn.execute("UPDATE events SET actor_id = ? WHERE id = ?", ("attacker", e2["id"]))
    conn.commit()
    conn.close()

    body = client.get("/audit/verify").json()
    assert body["intact"] is False
    assert body["first_violation_record_id"] == e2["id"]
    assert body["violation_type"] == "CONTENT_MISMATCH"


def test_archive_with_no_qualifying_records_returns_zero():
    _create(timestamp=_iso_days_ago(1))
    response = client.post("/audit/retention/archive", params={"older_than_days": 90})
    body = response.json()
    assert body["archived_count"] == 0
    assert body["archived_record_ids"] == []


def test_archive_is_idempotent_on_already_archived_records():
    old_event = _create(timestamp=_iso_days_ago(100))
    first = client.post("/audit/retention/archive", params={"older_than_days": 90}).json()
    second = client.post("/audit/retention/archive", params={"older_than_days": 90}).json()
    assert first["archived_count"] == 1
    assert second["archived_count"] == 0  # already archived, not re-selected


def test_query_api_includes_archived_records_by_default():
    """Archived != deleted -- query results should still include archived records
    unless a future filter explicitly excludes them (not implemented in this scope,
    documented as a simple default rather than added complexity).
    """
    old_event = _create(timestamp=_iso_days_ago(100), actor_id="user-archived")
    client.post("/audit/retention/archive", params={"older_than_days": 90})

    response = client.get("/audit/events", params={"actor_id": "user-archived"})
    body = response.json()
    assert body["total"] == 1
