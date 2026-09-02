# Testing Approach, Coverage, and Limitations

## Approach

Two layers of verification were used throughout this project, consistently:

1. **Manual, dependency-free verification.** The authoring environment (a sandboxed
   container used during AI-assisted development) had no network access to install
   FastAPI/pytest, so every non-trivial piece of logic — hash chaining, chain
   verification (including the tricky delete-cascade case), redaction's interaction
   with hash recomputation, export's cross-chain `next_hash` correctness — was first
   manually verified against a real in-memory SQLite instance and `hashlib`/`sqlite3`
   directly, independent of FastAPI/Pydantic. This caught real issues before they ever
   reached a human test run (e.g., a test-isolation ordering bug involving env-var
   read timing, described in `AI_USAGE_LOG.md`).
2. **Real `pytest` execution**, done by the engineer on his own machine, for every
   feature branch before merging. This is the layer that actually matters for
   correctness — the manual verification above is a substitute for real execution
   during authoring, not a replacement for it. A real deprecation bug
   (`@app.on_event("startup")`) was only caught this way, not by manual verification,
   since it was a framework-API-surface issue rather than a logic issue.

## What's Covered

- **Hash chain correctness**: determinism, field-order independence, sensitivity to
  field changes, genesis handling, known-vector SHA-256 sanity check.
- **Write API**: successful writes, chain linkage across sequential writes, input
  validation (422 on missing fields), and an explicit test asserting no
  mutation route exists for `/audit/events`.
- **Query API**: every filter dimension individually and in combination, pagination
  correctness (no skips/duplicates across pages, correct total count), empty results.
- **Chain verification**: intact-chain reporting, direct-tampering detection (the
  exact validation flow the assignment describes), distinguishing `CONTENT_MISMATCH`
  from `BROKEN_LINK`, correctly reporting the *first* violation when multiple records
  are tampered, detecting a directly-deleted record.
- **End-to-end flow**: a single composed test replicating the assignment's own
  described validation flow (write → query → verify → tamper → verify) using
  realistic, varied event data rather than minimal fixtures.
- **Retention**: only qualifying (old) records archived, archived records not
  physically deleted, `/audit/verify` doesn't false-positive on legitimate archiving,
  tampering elsewhere is still detected despite archived records present, idempotency.
- **Redaction**: placeholder substitution, chain remains intact after redaction
  (the central design claim), and — critically — that verification is doing genuine
  recomputation on redacted records rather than blanket-skipping them (confirmed by
  tampering an *unredacted* field on an already-redacted record and checking it's
  still caught).
- **Bulk export**: filtering correctness, the cross-chain `next_hash` property (a
  record's neighbor hash reflects the *full* chain even when that neighbor isn't
  itself in the export), a simulated recipient workflow (recomputing `content_hash`
  from only the bundle's fields), `manifest_hash` sensitivity to changes in the
  exported set, redacted fields appearing as placeholders in exports.
- **Scenario C (compliance reporting)**: scoping to `resourceType == ACCOUNT`,
  correct attribution of the self-generated `COMPLIANCE_REPORT_GENERATED` event, the
  self-referential property (a second report call sees the first call's own report
  event), chain integrity after report generation.
- **Auth**: missing/wrong key rejection, correct-key acceptance, cross-scope
  rejection (a read key must not work on a write endpoint; a general read key must
  not work on the narrower compliance endpoint), the health check remaining
  unauthenticated, and that keys are read at request time (not baked in at import
  time) via a live env-var override mid-test.

## What's NOT Covered, and Why

- **Concurrency / race conditions.** This is a single-writer prototype assumption,
  documented in `ARCHITECTURE.md`. No tests exercise concurrent writers racing to
  extend the chain, or read-during-write consistency beyond what SQLite provides
  by default. A production system would need this tested explicitly, likely after
  moving off SQLite to a database with better concurrent-write support.
- **Load / performance testing.** No tests exercise the query API's behavior under a
  large number of records (e.g., pagination performance at scale, where offset-based
  pagination is known to degrade — documented as a limitation in `ARCHITECTURE.md`).
- **Malformed/adversarial input beyond Pydantic's validation layer.** Tests confirm
  Pydantic rejects missing required fields, but don't specifically probe things like
  extremely large payloads, deeply nested JSON, or unicode edge cases in field values.
- **HTTP-level concerns**: no tests for request size limits, timeout behavior, or
  behavior under malformed JSON bodies (relying on FastAPI/Starlette's default
  handling, not independently verified here).
- **The `already_redacted_fields` / `fields_not_found` mixed-batch case** isn't
  explicitly tested (e.g., one call redacting one already-redacted field and one
  never-before-seen field in the same request) — individually tested, not in
  combination.
- **Auth key rotation / multiple valid keys per scope.** The current design supports
  exactly one key per scope at a time (via a single env var) — no tests (or
  implementation) for supporting multiple simultaneously-valid keys, which a real
  deployment doing zero-downtime key rotation would need.

## Running the Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

No network access or external services required — SQLite runs in-process, and every
test uses an isolated, throwaway database file (see `tests/conftest.py`).
