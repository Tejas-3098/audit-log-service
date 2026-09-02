from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _create(**overrides):
    base = {
        "event_type": "USER_LOGIN",
        "actor_id": "user-1",
        "resource_type": "SESSION",
        "resource_id": "sess-1",
        "payload": {},
        "timestamp": "2026-09-01T12:00:00+00:00",
    }
    base.update(overrides)
    response = client.post("/audit/events", json=base)
    assert response.status_code == 201
    return response.json()


def test_query_with_no_filters_returns_all_events():
    _create()
    _create(actor_id="user-2")
    response = client.get("/audit/events")
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2


def test_filter_by_actor_id():
    _create(actor_id="user-1")
    _create(actor_id="user-2")
    response = client.get("/audit/events", params={"actor_id": "user-1"})
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["actor_id"] == "user-1"


def test_filter_by_resource_type_and_id():
    _create(resource_type="ACCOUNT", resource_id="acct-1")
    _create(resource_type="ACCOUNT", resource_id="acct-2")
    _create(resource_type="SESSION", resource_id="sess-1")
    response = client.get(
        "/audit/events", params={"resource_type": "ACCOUNT", "resource_id": "acct-1"}
    )
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["resource_id"] == "acct-1"


def test_filter_by_event_type():
    _create(event_type="USER_LOGIN")
    _create(event_type="RECORD_UPDATED")
    response = client.get("/audit/events", params={"event_type": "RECORD_UPDATED"})
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["event_type"] == "RECORD_UPDATED"


def test_filter_by_timestamp_range():
    _create(timestamp="2026-09-01T09:00:00+00:00")
    _create(timestamp="2026-09-01T12:00:00+00:00")
    _create(timestamp="2026-09-01T18:00:00+00:00")
    response = client.get(
        "/audit/events",
        params={
            "timestamp_from": "2026-09-01T10:00:00+00:00",
            "timestamp_to": "2026-09-01T13:00:00+00:00",
        },
    )
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["timestamp"].startswith("2026-09-01T12:00:00")


def test_combined_filters():
    _create(actor_id="user-1", event_type="USER_LOGIN")
    _create(actor_id="user-1", event_type="RECORD_UPDATED")
    _create(actor_id="user-2", event_type="USER_LOGIN")
    response = client.get(
        "/audit/events", params={"actor_id": "user-1", "event_type": "USER_LOGIN"}
    )
    body = response.json()
    assert body["total"] == 1


def test_pagination_does_not_skip_or_duplicate():
    for i in range(5):
        _create(actor_id=f"user-{i}")

    page1 = client.get("/audit/events", params={"limit": 2, "offset": 0}).json()
    page2 = client.get("/audit/events", params={"limit": 2, "offset": 2}).json()
    page3 = client.get("/audit/events", params={"limit": 2, "offset": 4}).json()

    all_ids = [item["id"] for item in page1["items"] + page2["items"] + page3["items"]]
    assert len(all_ids) == 5
    assert len(set(all_ids)) == 5  # no duplicates
    assert all_ids == sorted(all_ids)  # consistent order across pages


def test_pagination_metadata_reflects_total_not_page_size():
    for i in range(5):
        _create(actor_id=f"user-{i}")
    response = client.get("/audit/events", params={"limit": 2, "offset": 0})
    body = response.json()
    assert body["total"] == 5
    assert len(body["items"]) == 2


def test_empty_result_set():
    response = client.get("/audit/events", params={"actor_id": "nonexistent"})
    body = response.json()
    assert body["total"] == 0
    assert body["items"] == []
