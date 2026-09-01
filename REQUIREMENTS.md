# Requirements Analysis

## 1. Problem Restated

Build a service that records events in an append-only log and can prove — cryptographically,
not just by policy — that no past record has been altered or removed. The service needs to
support writing events, querying them with realistic filters, and verifying the integrity of
the entire log on demand. Two extensions are required on top of that core: a way to legally
retire old or sensitive data (retention/redaction) without breaking the tamper-evidence
guarantee, and a way to translate a vague compliance ask into a concrete, scoped feature.

## 2. Explicit Requirements (pulled directly from the spec)

**Write API**
- Accept: `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, `timestamp`.
- No update or delete operation exposed anywhere in the API surface.

**Query API**
- Filter by any combination of: `actorId`; `resourceType` + `resourceId`; `eventType`; time
  range (`from`/`to`).
- Paginated.

**Tamper evidence**
- Each record stores a hash of its own content and a hash of the immediately preceding
  record (or a genesis value for record 0).
- A `GET /audit/verify` endpoint walks the chain and reports intact/broken, and — if broken —
  the first inconsistent record and the type of violation.

**Validation flow (this is how the whole thing gets graded)**
- Write events → query them → verify (should pass) → directly mutate a record in the data
  store → verify again (should fail, and point at the right record).

**Scenario B — retention & redaction**
- Records past a configurable age can be archived/soft-deleted without the verify endpoint
  producing false-positive breaks for legitimately archived records.
- Sensitive payload fields must be redactable without invalidating the hash chain.
- A bulk export endpoint for a given `resourceId`/`actorId` that produces a self-contained,
  independently verifiable bundle.

**Scenario C — ambiguous compliance requirement**
- Given only: *"Regulators need to be able to audit access to client account data,"*
  demonstrate the clarification process itself, not just an implementation.

## 3. Ambiguities Identified and How They're Resolved

| # | Ambiguity | Resolution | Where documented |
|---|---|---|---|
| 1 | Server-assigned vs. caller-supplied timestamp | Both: caller-supplied `timestamp` is stored as the event's source-of-truth time; server also records `receivedAt` for ingestion-time ordering and to guard against clock drift/backdating disputes. | ARCHITECTURE.md §Decisions |
| 2 | Hash algorithm | SHA-256 — no practical collision attacks, standard library support, widely auditable choice. | ARCHITECTURE.md §Decisions |
| 3 | Auth/authz — not mentioned in spec at all | Minimal static API key with two scopes (write, read). Full OAuth2/RBAC/mTLS documented as the production path, scoped out here as disproportionate to a prototype timebox. | ARCHITECTURE.md §Decisions, §Production Gaps |
| 4 | How to redact a field without invalidating its record's hash | Field-level hash commitment: each payload field is hashed individually; the record's overall content hash is derived from the set of field-hashes. Redacting a field's *value* doesn't change its *hash*, so the record (and everything after it) still verifies. | ARCHITECTURE.md §Redaction Design |
| 5 | Pagination style (offset vs. cursor) | Offset/limit — simpler to reason about and sufficient for this scope; documented as a scaling limitation for very large result sets. | ARCHITECTURE.md §Limitations |
| 6 | Canonical serialization for hashing | Fields serialized as JSON with sorted keys and no insignificant whitespace before hashing, so the same logical event always produces the same hash regardless of field ordering in code. | Inline code comments + ARCHITECTURE.md |
| 7 | What "audit access to client account data" (Scenario C) actually means | Treated as its own clarification exercise — see `SCENARIO_C.md` once written. Not resolved here because the assignment explicitly wants the clarification process demonstrated separately. | SCENARIO_C.md (Day 2) |

## 4. Assumptions

- Single-writer prototype: no concurrent-write race-condition handling beyond what SQLite
  gives for free. Documented as a production gap, not solved here.
- "Client account data" (Scenario C) is assumed to map to specific `resourceType`s already
  flowing through the same audit log, not a separate system.
- Reviewers will run this locally (no hosted deployment expected) — setup instructions target
  a local Python environment, not containerized deployment.
- "Production quality" is interpreted as: clean structure, tests, documented trade-offs, and
  real engineering judgment — not as "every production concern fully implemented" given the
  explicit 2–3 day scope.

## 5. Open Questions (would ask a real product owner before proceeding, in a non-exercise context)

- What retention window is actually required by regulation for this data (drives the
  "configurable window" default)?
- Who exactly are "regulators" in Scenario C — an internal compliance role, or an external
  auditor with restricted, time-boxed access? This materially changes the auth/scoping design.
- Is caller-supplied `timestamp` ever expected to be *authoritative* over `receivedAt` for
  legal/compliance purposes, or is it purely informational?
