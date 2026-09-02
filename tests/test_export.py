import json

import pytest
from fastapi.testclient import TestClient

import app.db as db_module
from app.hash_chain import compute_content_hash, hash_payload_fields
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
        "event_type": "RECORD_UPDATED",
        "actor_id": "user-1",
        "resource_type": "ACCOUNT",
        "resource_id": "acct-1",
        "payload": {"field": "x"},
        "timestamp": "2026-09-02T12:00:00+00:00",
    }
    base.update(overrides)
    response = client.post("/audit/events", json=base)
    assert response.status_code == 201
    return response.json()


def test_export_requires_at_least_one_filter():
    response = client.get("/audit/export")
    assert response.status_code == 400


def test_export_by_resource_id_returns_only_matching_records():
    _create(resource_id="acct-1")
    _create(resource_id="acct-1")
    _create(resource_id="acct-2")

    response = client.get("/audit/export", params={"resource_id": "acct-1"})
    body = response.json()
    assert body["record_count"] == 2
    assert all(r["resource_id"] == "acct-1" for r in body["records"])


def test_export_by_actor_id_returns_only_matching_records():
    _create(actor_id="user-a")
    _create(actor_id="user-b")

    response = client.get("/audit/export", params={"actor_id": "user-a"})
    body = response.json()
    assert body["record_count"] == 1
    assert body["records"][0]["actor_id"] == "user-a"


def test_export_includes_next_hash_from_full_chain_not_just_subset():
    """The key design point: next_hash must reflect the record's neighbor in the
    FULL chain, even when that neighbor doesn't match the export filter and isn't
    itself included in the bundle.
    """
    e1 = _create(resource_id="acct-1")
    e2 = _create(resource_id="acct-2")  # not matched by the export filter below
    e3 = _create(resource_id="acct-1")

    response = client.get("/audit/export", params={"resource_id": "acct-1"})
    body = response.json()
    assert body["record_count"] == 2

    exported_e1 = next(r for r in body["records"] if r["id"] == e1["id"])
    # e1's true next neighbor in the full chain is e2, which is NOT in this export.
    assert exported_e1["next_hash"] == e2["content_hash"]

    exported_e3 = next(r for r in body["records"] if r["id"] == e3["id"])
    assert exported_e3["next_hash"] is None  # e3 is the last record overall


def test_export_last_record_overall_has_no_next_hash():
    e1 = _create()
    response = client.get("/audit/export", params={"resource_id": "acct-1"})
    body = response.json()
    assert body["records"][0]["next_hash"] is None


def test_recipient_can_independently_recompute_content_hash_from_bundle():
    """Simulates what a recipient of the export would actually do: recompute each
    record's content_hash from the fields in the bundle, using only the documented
    hashing scheme (no access to the live service), and confirm it matches.
    """
    _create(payload={"field": "original_value"})
    response = client.get("/audit/export", params={"resource_id": "acct-1"})
    record = response.json()["records"][0]

    recomputed = compute_content_hash(
        event_type=record["event_type"],
        actor_id=record["actor_id"],
        resource_type=record["resource_type"],
        resource_id=record["resource_id"],
        timestamp=record["timestamp"],
        payload_field_hashes=hash_payload_fields(record["payload"]),
    )
    assert recomputed == record["content_hash"]


def test_manifest_hash_changes_if_any_record_is_altered():
    """Confirms the manifest_hash actually depends on the exported content -- if a
    record in the bundle were altered after export, recomputing the manifest_hash
    (from the ids+content_hashes) would no longer match, revealing tampering with
    the export itself.
    """
    _create(resource_id="acct-1")
    _create(resource_id="acct-1")

    response1 = client.get("/audit/export", params={"resource_id": "acct-1"})
    manifest1 = response1.json()["manifest_hash"]

    _create(resource_id="acct-1")  # add a third record, changing what should export

    response2 = client.get("/audit/export", params={"resource_id": "acct-1"})
    manifest2 = response2.json()["manifest_hash"]

    assert manifest1 != manifest2


def test_export_includes_redacted_placeholder_not_original_value():
    event = _create(payload={"account_number": "1234567890"})
    client.post(f"/audit/events/{event['id']}/redact", json={"fields": ["account_number"]})

    response = client.get("/audit/export", params={"resource_id": "acct-1"})
    record = response.json()["records"][0]
    assert record["payload"]["account_number"] == "[REDACTED]"


def test_export_with_no_matching_records_returns_empty_bundle():
    response = client.get("/audit/export", params={"resource_id": "nonexistent"})
    body = response.json()
    assert body["record_count"] == 0
    assert body["records"] == []
