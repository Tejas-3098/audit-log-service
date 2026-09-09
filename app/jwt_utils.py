"""Minimal, spec-compliant JWT (HS256) encode/decode using only the Python standard
library -- no third-party dependency needed for something this size, and it means
this logic can be (and was) fully manually verified in a sandboxed environment with
no network access, unlike most of the rest of this project's dependency-requiring
code.

Implements the standard JWT structure: base64url(header).base64url(payload).
base64url(HMAC-SHA256 signature), matching what any standard JWT library (PyJWT,
jose, jsonwebtoken) would produce for the same header/payload/secret -- this is a
real implementation of the spec, not a simplified stand-in.
"""
import base64
import hashlib
import hmac
import json
import time


class JWTError(Exception):
    """Base class for all JWT verification failures."""


class MalformedTokenError(JWTError):
    """Token isn't structurally a valid JWT (wrong segment count, bad encoding)."""


class InvalidSignatureError(JWTError):
    """Token is structurally valid but the signature doesn't verify."""


class ExpiredTokenError(JWTError):
    """Token's signature is valid but its `exp` claim is in the past."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def decode(token: str, secret: str) -> dict:
    """Verifies signature and expiry, returns the payload dict on success.

    Raises MalformedTokenError, InvalidSignatureError, or ExpiredTokenError.
    Signature comparison uses hmac.compare_digest (timing-safe) -- a token that
    fails signature verification never even reaches the point of being parsed as
    JSON, so a forged/tampered token can't be used to probe the payload structure.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedTokenError(f"Expected 3 segments, got {len(parts)}")

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()

    try:
        actual_signature = _b64url_decode(signature_b64)
    except Exception as e:
        raise MalformedTokenError(f"Invalid signature encoding: {e}") from e

    if not hmac.compare_digest(expected_signature, actual_signature):
        raise InvalidSignatureError("Signature verification failed")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise MalformedTokenError(f"Invalid payload encoding: {e}") from e

    if "exp" in payload and time.time() > payload["exp"]:
        raise ExpiredTokenError("Token has expired")

    return payload
