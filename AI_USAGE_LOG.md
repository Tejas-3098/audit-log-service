# AI Usage Log

Running log of AI-assisted work on this project, updated per session. A synthesized
summary will be added at the end (see `SUMMARY.md` once written).

---

## Session: Day 1, 2026-09-01 — Planning

- **Prompted for:** Help scoping the assignment, resolving ambiguities left open by the
  spec (tech stack, data store, timestamp handling, hash algorithm, auth approach,
  redaction design), and producing a day-by-day task plan.
- **AI suggested:** SQLite over in-memory/Postgres for the data store; SHA-256 for
  hashing; dual timestamp (caller-supplied + server-received); minimal API-key auth
  with documented production RBAC/OAuth2 plan; field-level hash commitment (Merkle-lite)
  for redaction over crypto-shredding or tombstone-event approaches.
- **Accepted / Modified / Rejected:** Accepted all of the above after discussion of
  trade-offs. Chose field-level hash commitment specifically because it directly
  addresses the stated problem ("the original hash covers the original value") without
  requiring key-management infrastructure that would be disproportionate to the
  assignment's timebox.
- **Rationale:** These are architectural decisions with real trade-offs; I evaluated the
  options presented against the assignment's actual requirements and time constraints
  before accepting rather than taking the first suggestion.

---

## Session: Day 1, 2026-09-01 — Local test run (write API)

- **Ran:** `pytest tests/ -v` locally after pulling the schema, hash chain, and write
  API commits — first real execution of the FastAPI layer (previously only manually
  verified via direct calls to the underlying logic in a sandboxed environment without
  network access to install FastAPI/pytest).
- **Result:** 14 passed, 2 deprecation warnings (`@app.on_event("startup")` deprecated
  in current FastAPI in favor of lifespan handlers).
- **AI suggested:** Replace with an `@asynccontextmanager` lifespan function.
- **Accepted as-is.** Small, low-risk, well-documented FastAPI migration path.
- **Note:** This is a good example of the assignment's expected workflow — AI-generated
  code was written without the ability to execute it in the authoring environment,
  a real issue surfaced on first actual test run, and was fixed and logged rather than
  assumed correct.

---

## Session wrap-up: Scenario A complete (schema through end-to-end validation)

Scenario A's tasks (schema, hash chain, write API, query API, verify endpoint, and
the composed end-to-end validation test) ended up spanning across the actual Day 1
and into early Day 2 rather than finishing within Day 1 as originally planned — see
the schedule note added to PLAN.md for the honest account of that shift.

**Overall pattern of AI use across Scenario A:**
- AI (this tool) generated the majority of the implementation code — schema, hash
  chain logic, API endpoints, and test suites — based on task-by-task direction and
  the architectural decisions made collaboratively during planning (data store, hash
  algorithm, timestamp handling, redaction approach — see earlier log entries).
- AI accelerated most on: boilerplate (Pydantic models, FastAPI routing, SQL
  parameter binding), test scaffolding across many small filter/edge-case
  combinations, and reasoning through the CONTENT_MISMATCH vs. BROKEN_LINK
  distinction in the verify endpoint (the delete-cascade case in particular — was
  worth an explicit test to confirm the reasoning was actually correct, not just
  plausible).
- Where output was corrected rather than accepted as-is: a real deprecation bug
  (on_event startup handler) was caught only once actual pytest execution became
  possible on a real machine, since the authoring environment (a sandboxed container)
  had no network access to install FastAPI/pytest and verify execution directly.
  All logic was cross-checked with manual, dependency-free verification scripts run
  directly against sqlite3/hashlib as a substitute, but this is not a substitute for
  actually running the real test suite -- the deprecation warning is a concrete
  example of a class of issue (API surface changes in a fast-moving dependency) that
  only surfaces on real execution.
- A test-isolation bug was caught and fixed during authoring itself (before any human
  run): an env-var-based approach to isolating the test database was replaced with
  direct monkeypatching of the DB_PATH constant, after recognizing that pytest's
  alphabetical test-file collection order could import app.db (fixing DB_PATH) before
  an env-var override in a later-collected file ever ran.
- Engineer (Tejas) made the actual architectural decisions (SQLite over
  in-memory/Postgres, SHA-256, dual timestamp, minimal API key auth, field-level hash
  commitment for redaction) after being presented options and trade-offs -- AI did not
  make these calls unilaterally, and multiple AI-suggested trade-offs were evaluated
  explicitly rather than the first suggestion being taken by default.
- Git workflow (feature branches, PRs, merges) was done by the engineer on his own
  machine and account per the assignment's requirement; AI assisted by drafting PR
  descriptions and explaining git/GitHub flow (branch naming, PAT auth setup, merge
  vs. rebase) when the engineer had genuine process questions, not by performing the
  actual pushes/merges itself.

---
