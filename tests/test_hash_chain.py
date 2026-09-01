from app.hash_chain import (
    GENESIS_HASH,
    compute_content_hash,
    hash_payload_fields,
    sha256_hex,
)


def _sample_args(payload=None):
    payload = payload if payload is not None else {"amount": 100, "currency": "USD"}
    return dict(
        event_type="RECORD_UPDATED",
        actor_id="user-123",
        resource_type="ACCOUNT",
        resource_id="acct-456",
        timestamp="2026-09-01T12:00:00Z",
        payload_field_hashes=hash_payload_fields(payload),
    )


def test_same_input_produces_same_hash():
    args = _sample_args()
    h1 = compute_content_hash(**args)
    h2 = compute_content_hash(**args)
    assert h1 == h2


def test_field_order_does_not_affect_hash():
    payload_a = {"amount": 100, "currency": "USD"}
    payload_b = {"currency": "USD", "amount": 100}
    h1 = compute_content_hash(**_sample_args(payload_a))
    h2 = compute_content_hash(**_sample_args(payload_b))
    assert h1 == h2


def test_changing_a_field_changes_the_hash():
    h1 = compute_content_hash(**_sample_args())
    args_changed = _sample_args()
    args_changed["actor_id"] = "user-999"
    h2 = compute_content_hash(**args_changed)
    assert h1 != h2


def test_changing_payload_value_changes_the_hash():
    h1 = compute_content_hash(**_sample_args({"amount": 100, "currency": "USD"}))
    h2 = compute_content_hash(**_sample_args({"amount": 999, "currency": "USD"}))
    assert h1 != h2


def test_hash_is_sha256_hex_digest():
    h = compute_content_hash(**_sample_args())
    assert len(h) == 64
    int(h, 16)  # raises if not valid hex


def test_genesis_hash_is_64_char_placeholder():
    assert GENESIS_HASH == "0" * 64
    assert len(GENESIS_HASH) == 64


def test_hash_payload_fields_produces_one_hash_per_field():
    payload = {"amount": 100, "currency": "USD", "note": "test"}
    hashes = hash_payload_fields(payload)
    assert set(hashes.keys()) == {"amount", "currency", "note"}
    for h in hashes.values():
        assert len(h) == 64


def test_redacting_a_field_value_does_not_change_its_stored_field_hash():
    """This is the property Scenario B's redaction design depends on: the field_hash
    computed from the ORIGINAL value must be reusable after the value is replaced with
    a redaction placeholder, so content_hash can still be recomputed correctly.
    """
    original_payload = {"account_number": "1234567890"}
    original_field_hashes = hash_payload_fields(original_payload)

    # Simulate redaction: the field-hash is preserved as-is (this is what the
    # redactions table will store), independent of what happens to the raw value.
    preserved_hash = original_field_hashes["account_number"]

    args = _sample_args(payload={})  # payload arg unused when we override the hash below
    args["payload_field_hashes"] = {"account_number": preserved_hash}
    h_with_original_hash_reused = compute_content_hash(**args)

    # Recomputing content_hash using the preserved field-hash (not the raw value, which
    # is now redacted) must match what it would have been before redaction.
    full_args = dict(
        event_type="RECORD_UPDATED",
        actor_id="user-123",
        resource_type="ACCOUNT",
        resource_id="acct-456",
        timestamp="2026-09-01T12:00:00Z",
        payload_field_hashes=original_field_hashes,
    )
    h_before_redaction = compute_content_hash(**full_args)

    assert h_with_original_hash_reused == h_before_redaction


def test_sha256_hex_matches_known_vector():
    # Standard published SHA-256 test vector: SHA256("abc")
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
