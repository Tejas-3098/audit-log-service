# Scenario C — Compliance Reporting: Clarification & Scoped Design

## 1. The Requirement, As Given

> "Regulators need to be able to audit access to client account data."

This is deliberately under-specified — one sentence standing in for what would, in
reality, be a multi-stakeholder requirements conversation. Below is the clarification
process worked through before writing any code, per the assignment's explicit ask to
demonstrate that process rather than jump straight to an implementation.

## 2. Ambiguities Identified

| Ambiguity | Why it matters |
|---|---|
| **What counts as "access"?** Does this mean *read* operations specifically (someone viewing a client's account), or any operation touching account data (reads, writes, permission changes)? | Changes what gets included in the report. A narrow "reads only" definition undercounts if unauthorized *writes* are also a regulatory concern. |
| **What counts as "client account data"?** Is this scoped to `resourceType == "ACCOUNT"` specifically, or does it extend to related resources (e.g., transactions, statements) that reference an account? | This service only knows about `resourceType`/`resourceId` as declared by whatever system wrote the event — it has no independent knowledge of what "counts" as account data beyond that. |
| **Who are "regulators"?** An internal compliance team member with standing access? An external auditor given time-boxed, narrowly-scoped access for a specific investigation? | Materially changes the auth model — a standing internal role is very different from an external party who should see *only* a specific slice, for a limited window, then lose access. |
| **What time granularity / format do they need?** A live queryable API? A downloadable report (CSV/PDF) for a specific audit period? A scheduled recurring feed? | Regulators in real financial-services contexts often want a specific delivery format and cadence dictated by the regulation itself (which isn't specified here). |
| **Does the definition of "access" include the compliance team's own act of pulling this report?** | Arguably yes — a report showing who looked at account data, that itself doesn't get logged, has an obvious gap. |

## 3. Assumptions Made (documented, not silently baked in)

Given the assignment's scope and timebox, the following assumptions were made to
produce a concrete, defensible implementation rather than leaving this entirely
unimplemented:

1. **"Access" is interpreted broadly**: any event where `resourceType == "ACCOUNT"`,
   regardless of `eventType` (reads, writes, permission changes all included). This is
   the safer regulatory default — better to over-include and let a human filter down,
   than to silently exclude something a narrower definition would have missed.
2. **"Client account data" is assumed to map onto `resourceType == "ACCOUNT"`** in this
   service's existing data model — no separate account-classification system exists to
   consult, and none is assumed.
3. **"Regulators" are modeled as a distinct access scope** (a `compliance` API key
   scope, layered onto the minimal auth model already in place — see
   `ARCHITECTURE.md` §9), rather than building out a full external-auditor
   provisioning system. A real implementation would very likely need proper
   time-boxed, per-engagement access grants; that's out of scope here and is called
   out explicitly as a limitation below.
4. **Format**: JSON via a queryable API endpoint, not a scheduled export or PDF/CSV
   deliverable. This is consistent with how the rest of the service is built, and a
   downloadable file format is a presentation-layer concern that can sit on top of
   this endpoint later without changing the underlying query/access logic.
5. **The act of generating a compliance report is itself audited** — every call to the
   report endpoint writes its own `COMPLIANCE_REPORT_GENERATED` event back into the
   log (see §5), directly addressing ambiguity #5 above rather than leaving it as an
   acknowledged gap.

## 4. Questions That Would Actually Be Asked (in a real, non-exercise context)

Before shipping this to production, the honest next step would be to take these back
to a real product/compliance stakeholder:

- Is "access" meant to include internal employee reads, or is this specifically about
  external/regulatory access to the *audit log itself* (i.e., regulators auditing the
  bank's account-access controls, one level removed from the account access itself)?
  The assignment's phrasing is compatible with both readings.
- What specific regulation or framework is driving this (e.g., SOX, GLBA, a specific
  state regulator)? That would dictate retention period, required fields, and
  delivery format far more precisely than can be inferred from one sentence.
- Should regulators get a live queryable interface, or is a periodic static export the
  actual expectation (matching how many real regulatory reporting relationships
  work)?

## 5. What Was Implemented

**`GET /audit/compliance/account-access-report`** — a report endpoint that:
- Always filters to `resourceType == "ACCOUNT"` (assumption #2), combined with any of
  the existing filters (`actor_id`, `event_type`, time range) for narrowing.
- Reuses the existing query/pagination logic (`app/queries.py`) rather than
  duplicating it — this is a *view* over the same underlying data, not a separate
  reporting subsystem.
- Writes its own `COMPLIANCE_REPORT_GENERATED` audit event back into the log on every
  call, recording who generated the report (`actor_id`, expected to be the
  requesting regulator's identifier), the filters used, and how many records were
  returned. This means a report *about* who looked at account data is itself always
  visible to a subsequent audit — addressing ambiguity #5 directly rather than leaving
  it as a documented gap.

## 6. What Was Scoped Out, and Why

- **A separate external-auditor provisioning/access-grant system.** Building
  genuine time-boxed, per-engagement access control is a real, substantial feature —
  disproportionate to this assignment's timebox. The `compliance` API key scope
  stands in for it, documented explicitly as a simplification.
- **CSV/PDF export or scheduled delivery.** The underlying query logic is delivery-
  format-agnostic; adding a formatted export would be additive work on top of this
  endpoint, not a redesign, so it was left out to prioritize getting the clarification
  process and the core access-report logic right first.
- **Any narrower/configurable definition of "account data"** beyond
  `resourceType == "ACCOUNT"` — e.g., pattern-matching related resource types. Not
  attempted without a real stakeholder to confirm what "related" should mean here.
