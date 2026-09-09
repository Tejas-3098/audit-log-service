"""Tests for JWT-based auth: token issuance, authentication, and authorization.

Deliberately overrides conftest.py's autouse bypass_auth fixture (same name, so
pytest's fixture resolution shadows the conftest version for this module only) --
every other test file bypasses auth to focus on business logic, but this file
exists specifically to test that the auth mechanism itself actually works.

Structured to test authentication and authorization as the two distinct concerns
they are: authentication tests check whether a request is accepted AT ALL (401 on
failure); authorization tests check whether an authenticated request is accepted
for THIS SPECIFIC endpoint (403 on failure). See app/auth.py's module docstring for
the full reasoning behind that status-code split.
"""
import time

import pytest
from fastapi.testclient import TestClient

from app.jwt_utils import encode
from app.main import app

client = TestClient(app)

DEFAULT_SIGNING_SECRET = "dev-jwt-signing-secret-CHANGE-ME"
DEFAULT_CLIENT_SECRETS = {
    "write": "dev-write-secret-CHANGE-ME",
    "read": "dev-read-secret-CHANGE-ME",
    "compliance": "dev-compliance-secret-CHANGE-ME",
}


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


def _get_token(scope: str) -> str:
    response = client.post(
        "/auth/token",
        json={"client_id": f"test-client-{scope}", "client_secret": DEFAULT_CLIENT_SECRETS[scope]},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- Token issuance (POST /auth/token) ---


def test_token_issuance_succeeds_with_correct_client_secret():
    response = client.post(
        "/auth/token",
        json={"client_id": "my-service", "client_secret": DEFAULT_CLIENT_SECRETS["write"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "write"
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    assert body["access_token"].count(".") == 2  # structurally a JWT


def test_token_issuance_fails_with_wrong_client_secret():
    response = client.post(
        "/auth/token", json={"client_id": "attacker", "client_secret": "not-a-real-secret"}
    )
    assert response.status_code == 401


def test_each_client_secret_yields_its_correct_scope():
    for scope, secret in DEFAULT_CLIENT_SECRETS.items():
        response = client.post(
            "/auth/token", json={"client_id": "test", "client_secret": secret}
        )
        assert response.json()["scope"] == scope


# --- Authentication (401 cases: no/invalid/expired credentials) ---


def test_write_endpoint_rejects_missing_authorization_header():
    response = client.post("/audit/events", json=_sample_event())
    assert response.status_code == 401


def test_write_endpoint_rejects_malformed_authorization_header():
    """Header present but not in 'Bearer <token>' form."""
    response = client.post(
        "/audit/events", json=_sample_event(), headers={"Authorization": "not-a-bearer-token"}
    )
    assert response.status_code == 401


def test_write_endpoint_rejects_garbage_token():
    response = client.post(
        "/audit/events", json=_sample_event(), headers=_bearer("this.is.garbage")
    )
    assert response.status_code == 401


def test_write_endpoint_rejects_tampered_token():
    """A structurally valid but tampered token must fail signature verification --
    the core security property a real JWT gives you over a plain string comparison.
    """
    valid_token = _get_token("write")
    header, payload, signature = valid_token.split(".")
    # Flip one character in the payload segment -- this changes what's encoded
    # without touching the signature, so it must fail verification.
    tampered_char = "A" if payload[-1] != "A" else "B"
    tampered_token = f"{header}.{payload[:-1]}{tampered_char}.{signature}"

    response = client.post(
        "/audit/events", json=_sample_event(), headers=_bearer(tampered_token)
    )
    assert response.status_code == 401


def test_write_endpoint_rejects_expired_token():
    """Construct an already-expired token directly (rather than sleeping in a
    test) using the same signing secret and encode() function real tokens use.
    """
    now = int(time.time())
    expired_payload = {"sub": "test-client", "scope": "write", "iat": now - 1000, "exp": now - 1}
    expired_token = encode(expired_payload, DEFAULT_SIGNING_SECRET)

    response = client.post(
        "/audit/events", json=_sample_event(), headers=_bearer(expired_token)
    )
    assert response.status_code == 401


def test_write_endpoint_accepts_valid_unexpired_token():
    token = _get_token("write")
    response = client.post(
        "/audit/events", json=_sample_event(), headers=_bearer(token)
    )
    assert response.status_code == 201


# --- Authorization (403 cases: valid, unexpired token, wrong scope) ---


def test_write_endpoint_rejects_valid_read_scoped_token():
    """This is a 403, not a 401: the token is completely valid and unexpired --
    the caller is genuinely authenticated. They're just not authorized for this
    specific endpoint. That distinction is the point of this whole redesign.
    """
    read_token = _get_token("read")
    response = client.post(
        "/audit/events", json=_sample_event(), headers=_bearer(read_token)
    )
    assert response.status_code == 403


def test_read_endpoint_rejects_valid_write_scoped_token():
    write_token = _get_token("write")
    response = client.get("/audit/events", headers=_bearer(write_token))
    assert response.status_code == 403


def test_read_endpoint_accepts_correct_read_scoped_token():
    token = _get_token("read")
    response = client.get("/audit/events", headers=_bearer(token))
    assert response.status_code == 200


def test_compliance_endpoint_rejects_general_read_scoped_token():
    """The compliance scope is deliberately distinct and narrower than general
    read access -- a read token must NOT be sufficient here. See SCENARIO_C.md.
    """
    read_token = _get_token("read")
    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1"},
        headers=_bearer(read_token),
    )
    assert response.status_code == 403


def test_compliance_endpoint_accepts_compliance_scoped_token():
    token = _get_token("compliance")
    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "regulator-1"},
        headers=_bearer(token),
    )
    assert response.status_code == 200


def test_verify_endpoint_requires_read_scope():
    response = client.get("/audit/verify")
    assert response.status_code == 401
    token = _get_token("read")
    response_ok = client.get("/audit/verify", headers=_bearer(token))
    assert response_ok.status_code == 200


def test_archive_endpoint_requires_write_scope():
    response = client.post("/audit/retention/archive", params={"older_than_days": 90})
    assert response.status_code == 401
    token = _get_token("write")
    response_ok = client.post(
        "/audit/retention/archive", params={"older_than_days": 90}, headers=_bearer(token)
    )
    assert response_ok.status_code == 200


def test_health_check_requires_no_auth():
    response = client.get("/health")
    assert response.status_code == 200


# --- Request-time secret resolution (same lesson as app.db.DB_PATH) ---


def test_signing_secret_is_read_at_request_time_not_import_time(monkeypatch):
    """Confirms the token-signing secret comes from os.environ at request time,
    not baked in at import time -- if this were import-time, overriding the env
    var mid-test-run would have no effect on already-issued or newly-decoded
    tokens.
    """
    monkeypatch.setenv("AUDIT_LOG_JWT_SIGNING_SECRET", "custom-signing-secret")

    # A token signed with the OLD (default) secret must now fail, since the
    # service verifies against the NEW secret.
    now = int(time.time())
    old_token = encode(
        {"sub": "x", "scope": "write", "iat": now, "exp": now + 900}, DEFAULT_SIGNING_SECRET
    )
    response_old = client.post(
        "/audit/events", json=_sample_event(), headers=_bearer(old_token)
    )
    assert response_old.status_code == 401

    # A token issued fresh via the API (which reads the NEW secret) must succeed.
    token_response = client.post(
        "/auth/token",
        json={"client_id": "x", "client_secret": DEFAULT_CLIENT_SECRETS["write"]},
    )
    new_token = token_response.json()["access_token"]
    response_new = client.post(
        "/audit/events", json=_sample_event(), headers=_bearer(new_token)
    )
    assert response_new.status_code == 201
