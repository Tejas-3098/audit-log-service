"""Hash chain computation.

Each event record commits to two things:
  1. content_hash  -- a hash of the record's own fields
  2. previous_hash -- the content_hash of the immediately preceding record (or
                       GENESIS_HASH for the first record in the chain)

content_hash is built from *per-field* hashes rather than one flat hash over the whole
payload blob. This is deliberate, not incidental: Scenario B requires redacting individual
payload fields without invalidating the record's hash. If content_hash were a single hash
over the concatenated raw payload, redacting any field would change that hash and break
the chain. By hashing each field independently and then hashing the *set* of field-hashes
together, a field's value can be replaced with a redaction placeholder while its stored
field-hash (kept in a separate redactions table, added in Scenario B) stays the same --
so content_hash still recomputes correctly.

Canonicalization: all values are serialized via json.dumps(..., sort_keys=True,
separators=(",", ":")) before hashing, so the same logical value always hashes the same
way regardless of dict key ordering or incidental whitespace.
"""
import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64

# Fields that make up an event's identity for hashing purposes. `payload` is handled
# separately (hashed field-by-field) -- see hash_payload_fields().
CORE_FIELDS = (
    "event_type",
    "actor_id",
    "resource_type",
    "resource_id",
    "timestamp",
)


def _canonical(value: Any) -> str:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_payload_fields(payload: dict) -> dict:
    """Hash each payload field independently.

    Returns a dict mapping field_name -> field_hash. This is what makes field-level
    redaction possible later: the field_hash for a given field never has to change just
    because the field's *value* is redacted, as long as we keep the original field_hash
    on record separately.
    """
    return {key: sha256_hex(_canonical(value)) for key, value in payload.items()}


def compute_content_hash(
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    timestamp: str,
    payload_field_hashes: dict,
) -> str:
    """Compute a record's content_hash from its core fields and its payload field-hashes.

    payload_field_hashes must be the *hashes* of the payload fields (from
    hash_payload_fields), not the raw payload -- this is what keeps the overall
    content_hash stable across redaction of individual payload values.
    """
    core = {
        "event_type": event_type,
        "actor_id": actor_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "timestamp": timestamp,
    }
    combined = {
        "core": core,
        "payload_field_hashes": payload_field_hashes,
    }
    return sha256_hex(_canonical(combined))


def compute_chain_link(content_hash: str, previous_hash: str) -> str:
    """Not currently used as a separate step -- content_hash already incorporates the
    record's own content. previous_hash is stored alongside content_hash on the record
    and verified by comparing it against the prior record's content_hash at read time
    (see app/verify.py). Kept as an explicit helper in case chain-linking logic needs to
    become more elaborate later (e.g., including previous_hash inside content_hash
    itself, which was deliberately NOT done here -- see ARCHITECTURE.md for why).
    """
    return sha256_hex(_canonical({"content_hash": content_hash, "previous_hash": previous_hash}))
