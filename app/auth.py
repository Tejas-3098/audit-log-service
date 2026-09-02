"""Minimal API key authentication, three scopes.

This is a deliberately minimal auth mechanism for this assignment's scope -- see
ARCHITECTURE.md / REQUIREMENTS.md for the full reasoning on why full OAuth2/RBAC/mTLS
was scoped out. Three scopes exist:

  - "write":      required for anything that appends new events, archives, or
                   redacts (POST /audit/events, /audit/retention/archive,
                   /audit/events/{id}/redact)
  - "read":       required for querying/viewing existing data (GET /audit/events,
                   /audit/verify, /audit/export)
  - "compliance": required specifically for the Scenario C regulatory report
                   (GET /audit/compliance/account-access-report) -- a distinct,
                   narrower scope than general "read", matching the design promised
                   in SCENARIO_C.md ("regulators are modeled as a distinct access
                   scope"). Having a separate compliance key means a general
                   read-scoped integration can't incidentally pull regulatory
                   reports, and a compliance key holder doesn't get blanket read
                   access to every other endpoint.

Keys are read from environment variables at REQUEST time (not at import time) so
that tests can override them per-test via monkeypatching os.environ, the same
pattern already used for app.db.DB_PATH -- see the test-isolation lesson learned in
tests/test_write_api.py's fixture history for why import-time reads would be fragile
here.

Insecure defaults are provided ONLY so the service is runnable locally without any
setup -- documented explicitly in README.md as unsafe for anything beyond local
development, and MUST be overridden via environment variables for any real
deployment.
"""
import os

from fastapi import Header, HTTPException, status

_DEFAULT_KEYS = {
    "write": "dev-write-key-CHANGE-ME",
    "read": "dev-read-key-CHANGE-ME",
    "compliance": "dev-compliance-key-CHANGE-ME",
}


def _expected_key(scope: str) -> str:
    env_var = f"AUDIT_LOG_API_KEY_{scope.upper()}"
    return os.environ.get(env_var, _DEFAULT_KEYS[scope])


def require_scope(scope: str):
    """Returns a FastAPI dependency enforcing the given scope's API key via the
    X-API-Key header.
    """

    def dependency(x_api_key: str | None = Header(default=None)) -> None:
        expected = _expected_key(scope)
        if x_api_key is None or x_api_key != expected:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Missing or invalid API key for '{scope}' scope.",
            )

    return dependency


# Named instances so main.py's routes and tests/conftest.py's dependency_overrides
# refer to the exact same function objects -- FastAPI's dependency_overrides is
# keyed by object identity, so re-calling require_scope("write") elsewhere would
# produce a different, unoverridable object.
require_write = require_scope("write")
require_read = require_scope("read")
require_compliance = require_scope("compliance")
