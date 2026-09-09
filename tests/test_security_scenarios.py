"""A combined adversarial narrative exercising the auth system the way an actual
attacker (or a careless integration) would encounter it -- one coherent story
across multiple endpoints, rather than the endpoint-by-endpoint checks in
tests/test_auth.py. Complements, doesn't replace, that file's exhaustive per-case
coverage.
"""
import time

import pytest
from fastapi.testclient import TestClient

from app.jwt_utils import encode
from app.main import app

client = TestClient(app)

SIGNING_SECRET = "dev-jwt-signing-secret-CHANGE-ME"
CLIENT_SECRETS = {
    "write": "dev-write-secret-CHANGE-ME",
    "read": "dev-read-secret-CHANGE-ME",
    "compliance": "dev-compliance-secret-CHANGE-ME",
}


@pytest.fixture(autouse=True)
def bypass_auth():
    """Overrides conftest.py's bypass_auth -- this file specifically tests real
    auth/authorization enforcement across a multi-step adversarial scenario.
    """
    yield


def _token(scope: str) -> str:
    response = client.post(
        "/auth/token",
        json={"client_id": "scenario-test", "client_secret": CLIENT_SECRETS[scope]},
    )
    return response.json()["access_token"]


def test_attacker_with_no_credentials_is_locked_out_of_every_sensitive_endpoint():
    """An attacker who hasn't authenticated at all should be rejected uniformly
    across the entire API surface, not just the one endpoint they happened to try.
    """
    sample_event = {
        "event_type": "USER_LOGIN",
        "actor_id": "x",
        "resource_type": "SESSION",
        "resource_id": "x",
        "payload": {},
        "timestamp": "2026-09-02T12:00:00+00:00",
    }
    attempts = [
        ("POST", "/audit/events", {"json": sample_event}),
        ("GET", "/audit/events", {}),
        ("GET", "/audit/verify", {}),
        ("POST", "/audit/retention/archive", {"params": {"older_than_days": 90}}),
        ("GET", "/audit/export", {"params": {"resource_id": "x"}}),
        (
            "GET",
            "/audit/compliance/account-access-report",
            {"params": {"requested_by": "x"}},
        ),
    ]
    for method, path, kwargs in attempts:
        response = client.request(method, path, **kwargs)
        assert response.status_code == 401, f"{method} {path} should require auth"


def test_stolen_read_token_cannot_be_escalated_to_write_access():
    """Simulates a leaked/stolen read-scoped token being reused against
    write-scoped endpoints -- must fail at every one, not just some.
    """
    stolen_read_token = _token("read")
    headers = {"Authorization": f"Bearer {stolen_read_token}"}

    write_attempts = [
        ("POST", "/audit/events", {"json": {
            "event_type": "USER_LOGIN", "actor_id": "x", "resource_type": "SESSION",
            "resource_id": "x", "payload": {}, "timestamp": "2026-09-02T12:00:00+00:00",
        }}),
        ("POST", "/audit/retention/archive", {"params": {"older_than_days": 90}}),
    ]
    for method, path, kwargs in write_attempts:
        response = client.request(method, path, headers=headers, **kwargs)
        assert response.status_code == 403, (
            f"{method} {path} should reject a valid but wrong-scope token with 403"
        )

    # But it SHOULD still work for what it's actually scoped for.
    response = client.get("/audit/events", headers=headers)
    assert response.status_code == 200


def test_forged_token_claiming_compliance_scope_is_rejected():
    """An attacker who understands the token FORMAT (structurally valid JWT) but
    doesn't know the signing secret tries to forge a high-privilege token by hand.
    Must fail on signature verification, regardless of how plausible the claimed
    payload looks.
    """
    now = int(time.time())
    forged_payload = {"sub": "attacker", "scope": "compliance", "iat": now, "exp": now + 900}
    # Signed with the WRONG secret -- the attacker doesn't know the real one.
    forged_token = encode(forged_payload, "attacker-guessed-secret")

    response = client.get(
        "/audit/compliance/account-access-report",
        params={"requested_by": "attacker"},
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert response.status_code == 401  # signature invalid -- not even authenticated


def test_expired_token_cannot_be_replayed_after_ttl():
    """Simulates a token that was valid when issued but has since expired --
    confirms it can't be replayed indefinitely, addressing the key weakness of the
    prior static-key model (which had no expiry at all).
    """
    now = int(time.time())
    stale_token = encode(
        {"sub": "old-client", "scope": "write", "iat": now - 10000, "exp": now - 9000},
        SIGNING_SECRET,
    )
    response = client.post(
        "/audit/events",
        json={
            "event_type": "USER_LOGIN", "actor_id": "x", "resource_type": "SESSION",
            "resource_id": "x", "payload": {}, "timestamp": "2026-09-02T12:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {stale_token}"},
    )
    assert response.status_code == 401


def test_full_legitimate_workflow_still_succeeds_end_to_end():
    """Sanity check that all this hardening didn't break the legitimate path --
    obtain a token, write an event, read it back, verify the chain, all with
    correctly-scoped tokens.
    """
    write_token = _token("write")
    read_token = _token("read")

    write_response = client.post(
        "/audit/events",
        json={
            "event_type": "USER_LOGIN", "actor_id": "legit-user", "resource_type": "SESSION",
            "resource_id": "sess-1", "payload": {}, "timestamp": "2026-09-02T12:00:00+00:00",
        },
        headers={"Authorization": f"Bearer {write_token}"},
    )
    assert write_response.status_code == 201

    read_response = client.get(
        "/audit/events",
        params={"actor_id": "legit-user"},
        headers={"Authorization": f"Bearer {read_token}"},
    )
    assert read_response.status_code == 200
    assert read_response.json()["total"] == 1

    verify_response = client.get("/audit/verify", headers={"Authorization": f"Bearer {read_token}"})
    assert verify_response.json()["intact"] is True
