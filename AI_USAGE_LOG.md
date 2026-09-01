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
