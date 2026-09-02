# Final Engineering Summary

## 1. Plan and Rationale

The goal was to build a tamper-evident, append-only audit log service demonstrating
AI-assisted engineering execution across three scenarios: a greenfield core service
(A), an extension requiring genuine cryptographic design (B — retention and
redaction), and an intentionally ambiguous requirement demanding a clarification
process before implementation (C — compliance reporting).

The approach throughout was: **requirement analysis and task decomposition before any
code**, **one feature per git branch and PR**, and **manual verification of every
piece of non-trivial logic before it was wired into the API**, since the authoring
environment had no network access to actually run FastAPI/pytest directly. Real
`pytest` execution happened on the engineer's own machine before every merge — this
two-layer verification approach is documented in full in `TESTING.md`, including the
real bugs it caught at each layer.

One architectural decision made early paid off repeatedly: hashing payload fields
*individually* rather than as one flat blob (`app/hash_chain.py`, Task 3) was chosen
specifically because it would be needed for Scenario B's redaction requirement —
this meant Scenario B's redaction feature (`app/redaction.py`) was almost entirely a
matter of "cashing in" on a decision made days earlier, rather than a hash-chain
redesign under time pressure.

The schedule shifted honestly partway through: Scenario A's tasks (originally
planned to finish within "Day 1") actually extended into "Day 2," documented
transparently in `PLAN.md`'s schedule note rather than silently redrawn. Everything
originally planned still went in — this was a resequencing, not a scope cut.

## 2. Artifacts Produced

| Artifact | Location |
|---|---|
| Requirement analysis, ambiguities, assumptions | `REQUIREMENTS.md` |
| Task decomposition (Scenarios A & B) | `PLAN.md` |
| Scenario C clarification process | `SCENARIO_C.md` |
| Architecture, data model, API design, trade-offs | `ARCHITECTURE.md` |
| Working service | `app/` (9 modules, mapped 1:1 to the task breakdown) |
| Test suite | `tests/` (10 files, ~65 tests across unit, integration, and end-to-end) |
| Setup instructions, API usage | `README.md` |
| Testing approach and known gaps | `TESTING.md` |
| AI usage traceability | `AI_USAGE_LOG.md` |
| Attestation | `ATTESTATION.md` |
| This summary | `SUMMARY.md` |

**API surface**: `POST/GET /audit/events`, `GET /audit/verify`,
`POST /audit/retention/archive`, `POST /audit/events/{id}/redact`, `GET /audit/export`,
`GET /audit/compliance/account-access-report`, `GET /health`.

## 3. Risks and Trade-offs

| Decision | Trade-off accepted | Documented in |
|---|---|---|
| SQLite over Postgres | Simpler, zero-external-dependency, but not built for concurrent writers at scale | `ARCHITECTURE.md` §11 |
| Field-level hash commitment for redaction (not crypto-shredding) | Directly solves the stated problem without key-management overhead, but doesn't provide true cryptographic erasure — a real "right to be forgotten" need would require the stronger Option 3 | `ARCHITECTURE.md` §7 |
| Offset/limit pagination (not cursor-based) | Simpler to implement and reason about; degrades at very large scale | `ARCHITECTURE.md` §11 |
| Manually-triggered archiving (not scheduled) | Matches this scope's needs; a real deployment needs a scheduler | `ARCHITECTURE.md` §6 |
| Minimal static API keys (not OAuth2/RBAC) | Real, demonstrable auth mechanism proportionate to this timebox; genuinely insufficient for production | `ARCHITECTURE.md` §9, `README.md` |
| Scenario C's `compliance` scope stands in for real external-auditor provisioning | Concrete and testable now; a real regulator access-grant system is a substantial separate feature | `SCENARIO_C.md` §6 |
| Not deploying the service anywhere | Matches the assignment's ask for a locally-runnable prototype; deployment considerations (containerization, real DB, secrets management, observability, CI) documented instead of built | `ARCHITECTURE.md` §10 |

## 4. Assumptions

Consolidated from `REQUIREMENTS.md` and `SCENARIO_C.md`:

- Single-writer prototype; no concurrent-write handling beyond SQLite's defaults.
- Reviewers run this locally — no hosted deployment or containerization assumed.
- "Client account data" (Scenario C) maps to `resourceType == "ACCOUNT"` in this
  service's existing data model, with no separate account-classification system.
- "Production quality" means clean structure, real tests, and defensible documented
  trade-offs — not that every conceivable production concern is fully implemented
  given the explicit multi-day timebox.

## 5. Limitations (full list in `TESTING.md` and `ARCHITECTURE.md` §11)

- No concurrency/load testing.
- Redaction does not provide true cryptographic erasure (see trade-offs above).
- No key rotation support (one key per scope at a time).
- No external-auditor provisioning system for Scenario C — a static compliance
  scope stands in for it.
- No CSV/PDF export or scheduled report delivery for Scenario C.
- No structured logging/observability, rate limiting, or request-size limits beyond
  FastAPI/Pydantic's defaults.

## 6. Process Note

This project was built through an iterative, AI-assisted workflow: the engineer
(Tejas Sridhar) made every architectural decision after being presented options and
trade-offs (data store, hash algorithm, redaction design, auth approach), reviewed
every pull request's diff before merging, and ran the actual test suite on his own
machine before every merge — catching real issues (a FastAPI deprecation warning) that
manual, dependency-free verification in the authoring environment could not have
caught on its own. The full AI usage log, including where AI output was corrected
rather than accepted as-is, is in `AI_USAGE_LOG.md`.
