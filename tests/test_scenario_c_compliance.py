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
        "timestamp": "2026-09-02T12:00:00+00:00",
    }
    base.update(overrides)
    response = client.post("/audit/events", json=base)
    assert response.status_code == 201
    return response.json()


def test_report_only_includes_account_resource_type():
    _create(resource_type="ACCOUNT", resource_id="acct-1")
    _create(resource_type="SESSION", resource_id="sess-1")  # should NOT appear
    _create(resource_type="ACCOUNT", resource_id="acct-2")

    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1"},
    )
    body = response.json()
    # 2 ACCOUNT events, but NOT counting the report-generation event this call itself
    # writes (which is also resource_type=ACCOUNT, resource_id="ALL") -- see next test.
    assert body["total"] == 2
    assert all(item["resource_type"] == "ACCOUNT" for item in body["items"])


def test_report_generation_writes_its_own_audit_event():
    """The core design point of Scenario C's implementation: the act of generating
    a compliance report must itself be auditable.
    """
    _create(resource_type="ACCOUNT", resource_id="acct-1")

    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-jane"},
    )
    body = response.json()
    report_event_id = body["report_event_id"]
    assert report_event_id is not None

    # Confirm that event is now genuinely in the log and attributable to the
    # requesting regulator.
    query_response = client.get(
        "/audit/events", params={"event_type": "COMPLIANCE_REPORT_GENERATED"}
    )
    query_body = query_response.json()
    assert query_body["total"] == 1
    report_event = query_body["items"][0]
    assert report_event["id"] == report_event_id
    assert report_event["actor_id"] == "regulator-jane"
    assert report_event["payload"]["record_count_returned"] == 1


def test_second_report_call_is_itself_visible_to_a_later_report():
    """Chain reaction check: generating a report writes a COMPLIANCE_REPORT_GENERATED
    event with resource_type=ACCOUNT -- so a SECOND report call should see the FIRST
    call's own audit trail, since it's itself an ACCOUNT-scoped event.
    """
    _create(resource_type="ACCOUNT", resource_id="acct-1")

    first = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1"},
    ).json()
    assert first["total"] == 1  # only the original event, not yet its own report event

    second = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-2"},
    ).json()
    # Second call should see: original event + the first report-generation event.
    assert second["total"] == 2


def test_report_respects_additional_filters():
    _create(resource_type="ACCOUNT", resource_id="acct-1", actor_id="user-a")
    _create(resource_type="ACCOUNT", resource_id="acct-2", actor_id="user-b")

    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1", "actor_id": "user-a"},
    )
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["actor_id"] == "user-a"


def test_report_requires_requested_by():
    response = client.get("/audit/compliance/account-access-report")
    assert response.status_code == 422  # missing required query param


def test_chain_remains_intact_after_report_generation():
    """The report-generation event goes through the normal append_event path, so
    it must chain correctly and not disturb /audit/verify.
    """
    _create(resource_type="ACCOUNT", resource_id="acct-1")
    client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1"},
    )
    verify_body = client.get("/audit/verify").json()
    assert verify_body["intact"] is True
    assert verify_body["records_checked"] == 2  # original event + report event
