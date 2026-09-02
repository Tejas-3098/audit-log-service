import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Point the app at a throwaway SQLite file for the duration of each test.

    Patches app.db.DB_PATH directly (rather than relying on an env var read at import
    time) because module import order across test files is not guaranteed -- an env
    var set in this file could run after app.db has already been imported by another
    test module, silently leaving the real dev database in use.
    """
    test_db_path = tmp_path / "test_audit_log.db"
    monkeypatch.setattr(db_module, "DB_PATH", test_db_path)
    db_module.init_db()
    yield
    # tmp_path is cleaned up automatically by pytest; no manual teardown needed.


def _sample_event(**overrides):
    base = {
        "event_type": "USER_LOGIN",
        "actor_id": "user-123",
        "resource_type": "SESSION",
        "resource_id": "sess-1",
        "payload": {"ip": "10.0.0.1"},
        "timestamp": "2026-09-01T12:00:00+00:00",
    }
    base.update(overrides)
    return base


def test_create_event_returns_201_with_hash_fields():
    response = client.post("/audit/events", json=_sample_event())
    assert response.status_code == 201
    body = response.json()
    assert body["content_hash"]
    assert len(body["content_hash"]) == 64
    assert body["previous_hash"] == "0" * 64  # first record chains to genesis


def test_second_event_chains_to_first():
    r1 = client.post("/audit/events", json=_sample_event())
    r2 = client.post("/audit/events", json=_sample_event(actor_id="user-456"))
    assert r2.json()["previous_hash"] == r1.json()["content_hash"]


def test_missing_required_field_returns_422():
    bad_event = _sample_event()
    del bad_event["actor_id"]
    response = client.post("/audit/events", json=bad_event)
    assert response.status_code == 422


def test_no_update_or_delete_routes_exist():
    """Append-only guarantee: confirm there is no route capable of mutating a stored
    event. We check this against the app's registered routes directly, not just by
    probing a guessed URL, so the test fails loudly if a mutation route is ever added.
    """
    mutating_methods = {"PUT", "PATCH", "DELETE"}
    for route in app.routes:
        methods = getattr(route, "methods", set()) or set()
        path = getattr(route, "path", "")
        if "/audit/events" in path:
            assert not (methods & mutating_methods), (
                f"Found a mutating method on an events route: {path} {methods}"
            )
