"""Tests for API key auth enforcement itself.

Deliberately overrides conftest.py's autouse bypass_auth fixture (same name, so
pytest's fixture resolution shadows the conftest version for this module only) --
every other test file in this suite bypasses auth to focus on business logic, but
this file exists specifically to test that the auth mechanism itself actually works.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

DEFAULT_WRITE_KEY = "dev-write-key-CHANGE-ME"
DEFAULT_READ_KEY = "dev-read-key-CHANGE-ME"
DEFAULT_COMPLIANCE_KEY = "dev-compliance-key-CHANGE-ME"


@pytest.fixture(autouse=True)
def bypass_auth():
    """Overrides conftest.py's bypass_auth: intentionally does NOT touch
    app.dependency_overrides, so the real require_write/require_read/
    require_compliance dependencies stay active for every test in this file.
    """
    yield


def _sample_event():
    return {
        "event_type": "USER_LOGIN",
        "actor_id": "user-1",
        "resource_type": "SESSION",
        "resource_id": "sess-1",
        "payload": {},
        "timestamp": "2026-09-02T12:00:00+00:00",
    }


def test_write_endpoint_rejects_missing_api_key():
    response = client.post("/audit/events", json=_sample_event())
    assert response.status_code == 401


def test_write_endpoint_rejects_wrong_api_key():
    response = client.post(
        "/audit/events", json=_sample_event(), headers={"X-API-Key": "totally-wrong"}
    )
    assert response.status_code == 401


def test_write_endpoint_accepts_correct_write_key():
    response = client.post(
        "/audit/events",
        json=_sample_event(),
        headers={"X-API-Key": DEFAULT_WRITE_KEY},
    )
    assert response.status_code == 201


def test_write_endpoint_rejects_read_scoped_key():
    """Scopes are not interchangeable -- a read-scoped key must not grant write
    access, even though a human might assume 'I have a valid key' is enough.
    """
    response = client.post(
        "/audit/events",
        json=_sample_event(),
        headers={"X-API-Key": DEFAULT_READ_KEY},
    )
    assert response.status_code == 401


def test_read_endpoint_rejects_missing_api_key():
    response = client.get("/audit/events")
    assert response.status_code == 401


def test_read_endpoint_accepts_correct_read_key():
    response = client.get("/audit/events", headers={"X-API-Key": DEFAULT_READ_KEY})
    assert response.status_code == 200


def test_read_endpoint_rejects_write_scoped_key():
    response = client.get("/audit/events", headers={"X-API-Key": DEFAULT_WRITE_KEY})
    assert response.status_code == 401


def test_verify_endpoint_requires_read_scope():
    response = client.get("/audit/verify")
    assert response.status_code == 401
    response_ok = client.get("/audit/verify", headers={"X-API-Key": DEFAULT_READ_KEY})
    assert response_ok.status_code == 200


def test_archive_endpoint_requires_write_scope():
    response = client.post(
        "/audit/retention/archive", params={"older_than_days": 90}
    )
    assert response.status_code == 401
    response_ok = client.post(
        "/audit/retention/archive",
        params={"older_than_days": 90},
        headers={"X-API-Key": DEFAULT_WRITE_KEY},
    )
    assert response_ok.status_code == 200


def test_compliance_endpoint_rejects_general_read_key():
    """The compliance scope is deliberately distinct and narrower than general
    read access -- see app/auth.py and SCENARIO_C.md for why. A read key must
    NOT be sufficient here.
    """
    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1"},
        headers={"X-API-Key": DEFAULT_READ_KEY},
    )
    assert response.status_code == 401


def test_compliance_endpoint_accepts_compliance_key():
    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1"},
        headers={"X-API-Key": DEFAULT_COMPLIANCE_KEY},
    )
    assert response.status_code == 200


def test_health_check_requires_no_auth():
    """Liveness check stays open -- reasonable for a health endpoint, and
    consistent with common practice (load balancers/orchestrators probing
    /health typically can't be expected to carry application credentials).
    """
    response = client.get("/health")
    assert response.status_code == 200


def test_api_keys_are_read_at_request_time_not_import_time(monkeypatch):
    """Confirms keys come from os.environ at request time, not baked in at
    import time -- the same lesson learned earlier from the app.db.DB_PATH
    test-isolation bug (see conftest.py's docstring) applied consistently here.
    If this were import-time, overriding the env var mid-test-run would have
    no effect, since app.auth would already have been imported with the old
    default baked in.
    """
    monkeypatch.setenv("AUDIT_LOG_API_KEY_WRITE", "custom-write-key")

    response_old_key = client.post(
        "/audit/events",
        json=_sample_event(),
        headers={"X-API-Key": DEFAULT_WRITE_KEY},
    )
    assert response_old_key.status_code == 401  # default no longer valid

    response_new_key = client.post(
        "/audit/events",
        json=_sample_event(),
        headers={"X-API-Key": "custom-write-key"},
    )
    assert response_new_key.status_code == 201
