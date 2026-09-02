# Task Decomposition — Scenario A (Core Audit Log Service)

> **Schedule note (added Day 2):** The original plan targeted finishing all of
> Scenario A (Tasks 1–8) within Day 1. In practice, Day 1 covered Tasks 1–5 (scaffold
> through the query API) — the remaining Scenario A work (chain verification endpoint,
> end-to-end tamper-detection test, Day 1 log wrap-up) is carrying into Day 2 alongside
> the originally Day-2-scoped work (Scenarios B and C, hardening, docs, summary). This
> is a straightforward schedule shift, not a scope cut — everything originally planned
> is still going in, just resequenced across the two real working days. Noted here
> rather than silently redrawing the day boundaries, since the assignment explicitly
> asks for an honest account of process, including where the actual pace diverged from
> the plan.

Tasks below are sequenced by dependency, not just by priority. Each maps to a planned commit.

| # | Task | Depends on | Notes |
|---|---|---|---|
| 1 | Project scaffold (FastAPI app, SQLite connection, project structure, health check) | — | Nothing else can be built without a running app skeleton |
| 2 | Event data model / SQLite schema (`events` table incl. `contentHash`, `previousHash`) | 1 | Schema must exist before any chain logic can persist anything |
| 3 | Hash chain computation (canonical serialization + SHA-256 chaining, unit tested in isolation) | 2 | Core cryptographic logic — must be correct and tested before any API wraps it |
| 4 | Write API (`POST /audit/events`) | 2, 3 | Uses schema + hash logic; enforces append-only by simply not exposing PUT/DELETE |
| 5 | Query API (`GET /audit/events` with filters + pagination) | 2 | Independent of hash logic, only needs schema |
| 6 | Chain verification endpoint (`GET /audit/verify`) | 3, 4 | Needs real written data (from 4) to walk and needs the hash logic (3) to recompute against |
| 7 | End-to-end validation test (write → query → verify → tamper → verify) | 4, 5, 6 | Exercises the full stack exactly as the assignment's grading flow describes |
| 8 | Day 1 AI usage log update | all above | Documentation checkpoint, not a dependency for anything else |

## Acceptance Criteria (per task, high level)

- **Task 3 (hash chain):** Same event fields always produce the same hash regardless of
  JSON key ordering; changing any field changes the hash; genesis record uses a defined,
  documented constant as its `previousHash`.
- **Task 4 (write API):** Rejects malformed input (Pydantic validation); no route exists
  that can update or delete a record — not just "blocked," genuinely absent from the API.
- **Task 5 (query API):** All four filter dimensions work individually and in combination;
  pagination doesn't skip or duplicate records across pages.
- **Task 6 (verify endpoint):** Correctly reports "intact" on an untouched chain; correctly
  identifies the *first* broken record (not just "something's wrong") and distinguishes a
  content-hash mismatch from a broken previous-hash link.
- **Task 7 (E2E test):** Directly mutates a row in the SQLite file (not through the API,
  since the API has no mutation route) and confirms `/audit/verify` detects it.

## Technical Context

- FastAPI + Pydantic for request/response validation.
- `sqlite3` (stdlib) or SQLAlchemy Core — decision made at scaffold time (Task 1), documented
  in `ARCHITECTURE.md`.
- `hashlib.sha256` for hashing, `json.dumps(..., sort_keys=True, separators=(",", ":"))` for
  canonical serialization.
