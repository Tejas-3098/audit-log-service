# Architecture

## 1. Overview

A tamper-evident, append-only audit log service. Events are written once, never
mutated or deleted, and each record cryptographically commits to its own content and
to the record before it — forming a hash chain that makes any retroactive alteration
detectable. Built with Python, FastAPI, and SQLite.

## 2. Components

```
app/
├── main.py        FastAPI app, all route definitions
├── db.py           SQLite connection + schema
├── schemas.py      Pydantic request/response models
├── hash_chain.py   Core hashing logic (canonicalization, field hashing, chaining)
├── events.py       Write path (append-only insert + chain linking)
├── queries.py      Read path (filtered, paginated queries)
├── verify.py       Chain verification (walks the log, detects tampering)
├── retention.py    Archiving (Scenario B)
├── redaction.py    Field-level redaction (Scenario B)
└── export.py       Bulk export bundles (Scenario B)
```

Each module maps directly to one row in `PLAN.md`'s task breakdown — the file
structure mirrors the actual build sequence, not a pre-imagined "ideal" layout imposed
after the fact.

## 3. Data Model

Single table, `events`:

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | Auto-increment; also the chain's canonical ordering (see §5) |
| `event_type`, `actor_id`, `resource_type`, `resource_id` | TEXT | Indexed for query filtering |
| `payload` | TEXT (JSON) | Event-specific detail; individual fields may later be redacted (see §7) |
| `timestamp` | TEXT (ISO 8601) | Caller-supplied, source-of-truth event time |
| `received_at` | TEXT (ISO 8601) | Server-assigned ingestion time |
| `content_hash` | TEXT | SHA-256 over this record's own fields |
| `previous_hash` | TEXT | `content_hash` of the prior record, or genesis for the first |
| `archived`, `archived_at` | INTEGER, TEXT | Retention (see §6) |

Plus `redactions` (Scenario B, see §7) for preserving original field-hashes
independently of a redacted field's placeholder value.

No update or delete operation exists anywhere in the codebase for the `events` table.
Append-only is enforced by the absence of the capability, not a permission check on a
route that could otherwise exist.

## 4. API Surface

| Method | Path | Purpose |
|---|---|---|
| POST | `/audit/events` | Write a new event |
| GET | `/audit/events` | Query events (filters + pagination) |
| GET | `/audit/verify` | Walk the chain, report intact/broken |
| POST | `/audit/retention/archive` | Archive records older than a window |
| POST | `/audit/events/{id}/redact` | Redact payload fields on a record |
| GET | `/audit/export` | Self-contained, independently verifiable export bundle |
| GET | `/health` | Liveness check |

## 5. Hash Chain Design

**Why field-level hashing, not one flat hash over the payload:**

Rather than hashing the whole record as a single blob, each payload field is hashed
independently (`hash_payload_fields()` in `hash_chain.py`), and `content_hash` is
derived from the *set* of field-hashes plus the record's core fields. This was a
forward-looking decision made in Scenario A specifically to enable Scenario B's
redaction requirement without needing to redesign the hash chain later — see §7.

**Canonicalization:** All values are serialized via
`json.dumps(..., sort_keys=True, separators=(",", ":"))` before hashing, so the same
logical value always hashes identically regardless of dict key ordering or incidental
whitespace.

**Ordering:** The chain's canonical order is `id` (insertion order), not the
caller-supplied `timestamp`. Timestamp is not trustworthy for ordering — a caller
could supply any value — whereas `id` reflects the server's actual write sequence.

**Genesis value:** The first record's `previous_hash` is `"0" * 64` — a value
structurally consistent with a real SHA-256 digest's length but reserved as a
convention, not a security property.

**Hash algorithm:** SHA-256. No known practical collision attacks, native `hashlib`
support, and it's a widely auditable, industry-standard choice — no exotic dependency
required to verify the scheme independently.

## 6. Retention (Scenario B)

Records past a configurable age (`older_than_days`) can be archived via
`POST /audit/retention/archive`. Archiving is a **soft delete**: `archived=1` and
`archived_at` are set, but the row — and critically, its `content_hash` — is never
physically removed.

This is deliberate: a real `DELETE` would strip the record's hash from the database
entirely, making it impossible for `/audit/verify` to confirm chain continuity past
that point (the next record's `previous_hash` would have nothing to check against).
Soft-delete preserves the chain's integrity while still allowing a record's data to be
excluded from normal handling per whatever retention policy applies downstream.

`/audit/verify` skips re-checking an archived record's *content* (since the point of
archiving may eventually be to stop retaining full payload detail — not implemented
in this scope, but the seam is there) while still using its `content_hash` to
maintain chain-link continuity through it. This means archiving a record never
produces a false-positive chain break, and tampering elsewhere in the same chain is
still detected normally — both explicitly tested in `tests/test_retention.py`.

**Production gap, documented:** archiving here is a manually-triggered endpoint, not a
scheduled job. A real deployment would run this on a schedule (e.g., daily).

## 7. Redaction Design (Scenario B)

**The problem, as stated in the assignment:** "the original hash covers the original
value, so simply removing the value would invalidate the hash."

**Three options were considered** (see `REQUIREMENTS.md` for the original comparison):

1. **Field-level hash commitment** (chosen) — hash each payload field independently;
   redact a field's value while preserving its original field-hash separately, so the
   record's overall `content_hash` still recomputes correctly.
2. **Tombstone events** — never mutate stored data; redaction is a separate audited
   event, and the read layer masks fields on the way out. Simpler, but the sensitive
   value technically remains in storage (masked, not erased) — weaker privacy
   guarantee unless paired with encryption.
3. **Crypto-shredding** — encrypt sensitive fields per-record; redact by destroying
   the encryption key, making the ciphertext permanently unreadable while the hash
   (computed over ciphertext) stays valid.

**Why Option 1:** It directly and provably solves the stated problem without
requiring key-management infrastructure disproportionate to this assignment's scope.
It's also the easiest to defend live — the mechanism is fully inspectable in the
`redactions` table and doesn't depend on trusting that a key was actually destroyed.

**Why not Option 3:** Genuine "right to erasure" compliance (the value becomes
*actually* unrecoverable, not just hidden) is a real production requirement Option 1
does not fully satisfy — Option 1 preserves the original field-hash, and if the
original value were also retained elsewhere, redaction here doesn't erase it there.
Option 3 would be the stronger choice for a production system with genuine legal
erasure requirements. Documented here as the deliberate trade-off, not an oversight.

**How it works, concretely:**
1. Before overwriting anything, the field's current value is hashed and stored in the
   `redactions` table (`event_id`, `field_name`, `field_hash`).
2. The field's value in `events.payload` is overwritten with `"[REDACTED]"`.
3. `events.content_hash` is never touched. Any consumer recomputing it (chiefly
   `/audit/verify`) uses `effective_payload_field_hashes()`, which substitutes the
   preserved field-hash for any redacted field instead of hashing the placeholder —
   this is what keeps the hash valid across redaction.

**Verified property (not just claimed):** redacting a field does not merely avoid an
error — `tests/test_redaction.py` includes a test that, after redacting one field,
tampers a *different* field on the same record directly in the database and confirms
`/audit/verify` still catches it. This proves the verification logic is doing genuine
recomputation on redacted records, not silently skipping them.

## 8. Bulk Export Design (Scenario B)

An export is a *subset* of the full chain — record N's `previous_hash` generally
points to a record not included in the export. So a naive "walk the exported records
as a mini-chain" approach doesn't work.

Each exported record instead carries:
- Its own fields + `content_hash` (a recipient can independently recompute this from
  just the bundle, using the documented hashing scheme, confirming the record's
  content is unaltered since export).
- `previous_hash` (already stored).
- `next_hash` — computed specifically for export, by walking the *full* ordered table
  once and capturing each matched record's true neighbor's hash, even when that
  neighbor isn't itself in the bundle.

A `manifest_hash` (SHA-256 over the sorted list of exported record ids +
content_hashes) additionally lets a recipient detect if the export bundle itself was
altered after being produced.

`previous_hash`/`next_hash` alone don't let a recipient re-verify the *entire* chain's
integrity without further access to the live service — they establish that a record's
declared position is internally consistent with what was true at export time, which a
recipient can later cross-check against a fresh `/audit/verify` call or a subsequent
export.

## 9. Authentication

Not specified in the assignment. Minimal static API key implemented (documented in
`README.md`), with production RBAC/OAuth2/mTLS explicitly scoped out — see
`REQUIREMENTS.md` §3 for the full reasoning on this trade-off.

## 10. Deployment Considerations

This service is deliberately **not deployed anywhere** for this assignment — it's
built and documented to run locally, per the deliverables' emphasis on a runnable
prototype with local setup instructions, and the live defense's expectation of
running/modifying code in the engineer's own environment. Actually deploying it would
spend time on infrastructure rather than the engineering judgment being assessed.

That said, here's what moving this to production would actually require — listed to
show the gap is understood, not to pretend it's already closed:

- **Containerization.** A `Dockerfile` (not included) would wrap the app +
  dependencies; `docker-compose` or similar for local multi-service orchestration if
  a real database were introduced (see next point).
- **Database.** SQLite is a deliberate scope choice for this prototype, chosen
  specifically because it lets a reviewer open the file directly and hand-edit a row
  to demonstrate tamper detection. A production deployment handling concurrent
  writers would move to Postgres, with the schema translating directly (the hash chain logic is entirely database-agnostic — it
  operates on rows via a `sqlite3.Connection`-shaped interface in this codebase, and
  swapping to `psycopg`/SQLAlchemy would be a connection-layer change, not a redesign
  of `hash_chain.py`, `verify.py`, `redaction.py`, or `export.py`).
- **Process model.** `uvicorn app.main:app --reload` (the local dev command in
  `README.md`) is single-process and auto-reloading — not production-appropriate.
  Production would run multiple `uvicorn` workers (e.g., via `gunicorn` with
  `uvicorn.workers.UvicornWorker`) behind a reverse proxy/load balancer (nginx, or a
  managed equivalent).
- **Secrets management.** The API keys are currently plain environment variables with
  insecure defaults for local dev (`README.md` §Authentication). Production would pull
  these from a real secrets manager (AWS Secrets Manager, HashiCorp Vault, or
  equivalent), rotated periodically — which would also require the key-rotation
  support explicitly noted as unimplemented in `TESTING.md`.
- **Observability.** No structured logging, metrics, or tracing exist currently
  (noted as a gap in §11 below). Production would need request logging correlated
  with `actor_id`/`resource_id` where relevant, metrics on write throughput and
  `/audit/verify` chain-length-over-time, and alerting on any `/audit/verify` call
  reporting `intact: false` — arguably the single most important alert this system
  could ever fire.
- **CI.** No CI pipeline exists in this repo. A minimal one (GitHub Actions running
  `pytest tests/ -v` on every PR) would be a natural, low-cost addition — it would
  have caught nothing new here specifically (every PR in this project's history was
  manually verified and human-tested before merging), but it turns that discipline
  into an enforced gate rather than a personal habit, which matters once more than
  one engineer is contributing.
- **Backups / disaster recovery.** For an audit log specifically, backup integrity
  matters as much as the live chain's integrity — a restored backup should itself be
  independently verifiable via `/audit/verify` without modification, which the
  current design already supports (verification only depends on the data in the
  `events`/`redactions` tables), but this hasn't been tested against an actual
  backup/restore cycle.

## 11. Known Limitations / Production Gaps

- Single-writer prototype assumption; no concurrent-write race handling beyond what
  SQLite provides by default.
- Offset/limit pagination rather than cursor-based — simpler for this scope, would not
  scale gracefully to very large result sets in a real deployment.
- Archiving is manually triggered, not scheduled.
- Redaction (Option 1) does not provide true cryptographic erasure — see §7.
- No rate limiting, request size limits beyond what FastAPI/Pydantic validate by
  default, or structured logging/observability — all reasonable production additions,
  out of scope for this timebox.
