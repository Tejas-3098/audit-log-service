"""JWT-based authentication and scope-based authorization.

Upgrade from the earlier static-API-key model (a shared secret compared directly on
every request) to short-lived, signed bearer tokens with a scope claim. This treats
authentication and authorization as the two genuinely distinct concerns they are:

  - Authentication ("is this request genuinely from someone who holds a valid
    credential, and is that credential still current?"): verified via HMAC-SHA256
    signature check (timing-safe, see app/jwt_utils.py) and an expiry (`exp`) claim.
    A tampered or forged token is cryptographically detectable, and a token issued
    15 minutes ago stops working on its own -- neither property held for the
    previous static-key model.
  - Authorization ("given a genuinely authenticated caller, are they allowed to do
    THIS specific thing?"): verified via the token's `scope` claim against the
    scope required by the endpoint being called. A valid, unexpired token for the
    wrong scope is rejected with 403 Forbidden -- distinct from 401 Unauthorized,
    which is reserved for missing/invalid/expired credentials. This status-code
    split is deliberate: 401 means "we don't know who you are," 403 means "we know
    who you are, and the answer is no."

Flow: a client exchanges one of three pre-shared client secrets for a signed token
via POST /auth/token (see main.py), then presents that token as
`Authorization: Bearer <token>` on every subsequent request. The three scopes
(write, read, compliance) are unchanged from the prior model -- see
SCENARIO_C.md for why "compliance" is kept distinct from general "read".

Still not full OAuth2 (no refresh tokens, no external identity provider, no
revocation list) -- documented explicitly in ARCHITECTURE.md as the next real step.
What this upgrade adds over the prior model: token expiry, cryptographic tamper
detection, and authentication/authorization as two distinct, separately-tested
checks rather than one flat string comparison.

As with the prior model, all secrets (client secrets AND the token-signing secret)
are read from environment variables at request/call time, not import time -- the
same import-order lesson applied consistently throughout this project (see
tests/conftest.py's docstring for where this was first learned, from app.db.DB_PATH).
"""
import hmac
import os
import time

from fastapi import Header, HTTPException, status

from app.jwt_utils import ExpiredTokenError, InvalidSignatureError, MalformedTokenError, decode, encode

TOKEN_TTL_SECONDS = 15 * 60  # 15 minutes

SCOPES = ("write", "read", "compliance")

# Pre-shared client secrets, one per scope -- exchanged for a token via
# POST /auth/token, never sent directly on subsequent requests. Insecure defaults
# for local dev only; MUST be overridden via environment variables for any real
# deployment -- see README.md.
_DEFAULT_CLIENT_SECRETS = {
    "write": "dev-write-secret-CHANGE-ME",
    "read": "dev-read-secret-CHANGE-ME",
    "compliance": "dev-compliance-secret-CHANGE-ME",
}


def _signing_secret() -> str:
    """Secret used to sign issued tokens -- distinct from the client secrets used
    to obtain them. Compromising a client secret only lets an attacker request new
    tokens of that scope; compromising the signing secret would let them forge
    tokens directly, which is why they're kept as separate values.
    """
    return os.environ.get("AUDIT_LOG_JWT_SIGNING_SECRET", "dev-jwt-signing-secret-CHANGE-ME")


def _client_secret(scope: str) -> str:
    env_var = f"AUDIT_LOG_CLIENT_SECRET_{scope.upper()}"
    return os.environ.get(env_var, _DEFAULT_CLIENT_SECRETS[scope])


def scope_for_client_secret(client_secret: str) -> str | None:
    """Returns the scope associated with a given client secret using a timing-safe
    comparison against each known scope's secret, or None if it matches none of
    them.
    """
    for scope in SCOPES:
        if hmac.compare_digest(client_secret.encode(), _client_secret(scope).encode()):
            return scope
    return None


def issue_token(client_id: str, scope: str) -> str:
    now = int(time.time())
    payload = {
        "sub": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    return encode(payload, _signing_secret())


def require_scope(scope: str):
    """Returns a FastAPI dependency enforcing the given scope via a validated,
    unexpired JWT bearer token in the Authorization header.
    """

    def dependency(authorization: str | None = Header(default=None)) -> None:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header. Expected 'Bearer <token>'.",
            )
        token = authorization[len("Bearer "):]

        try:
            payload = decode(token, _signing_secret())
        except ExpiredTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired."
            )
        except (InvalidSignatureError, MalformedTokenError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token."
            )

        token_scope = payload.get("scope")
        if token_scope != scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token scope '{token_scope}' does not grant access to the "
                f"'{scope}' scope required by this endpoint.",
            )

    return dependency


# Named instances so main.py's routes and tests/conftest.py's dependency_overrides
# refer to the exact same function objects -- FastAPI's dependency_overrides is
# keyed by object identity, so re-calling require_scope("write") elsewhere would
# produce a different, unoverridable object.
require_write = require_scope("write")
require_read = require_scope("read")
require_compliance = require_scope("compliance")
