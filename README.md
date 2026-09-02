# Audit Log Service

A tamper-evident, append-only audit log service built for the Charles Schwab
AI-Proficient Software Engineering assignment. Records are written once, never
mutated or deleted, and each record cryptographically commits to its own content and
to the record before it — forming a hash chain that makes any retroactive alteration
detectable.

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — components, data model, API design, hash
  chain design, and key trade-offs (retention, redaction, export).
- [`REQUIREMENTS.md`](REQUIREMENTS.md) — clarified requirements and identified
  ambiguities this build is based on.
- [`SCENARIO_C.md`](SCENARIO_C.md) — the clarification process for the deliberately
  ambiguous compliance-reporting requirement.
- [`PLAN.md`](PLAN.md) — task decomposition for Scenarios A and B.
- [`TESTING.md`](TESTING.md) — testing approach, what's covered, and known gaps.
- [`AI_USAGE_LOG.md`](AI_USAGE_LOG.md) — running log of AI-assisted work on this
  project.
- [`SUMMARY.md`](SUMMARY.md) — final engineering summary (plan, artifacts, risks,
  trade-offs, assumptions, limitations).

## Setup

Requires Python 3.11+.

```bash
git clone <this-repo>
cd audit-log-service
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running the service

```bash
uvicorn app.main:app --reload
```

The API is then available at `http://localhost:8000`. Interactive API docs (via
FastAPI's built-in Swagger UI) are at `http://localhost:8000/docs`.

The SQLite database file (`audit_log.db`) is created automatically on first startup
in the project root.

## Authentication

Every `/audit/*` endpoint requires an `X-API-Key` header. Three scopes exist — see
[`ARCHITECTURE.md`](ARCHITECTURE.md#9-authentication) for the full reasoning:

| Scope | Default key (local dev only) | Required for |
|---|---|---|
| `write` | `dev-write-key-CHANGE-ME` | `POST /audit/events`, `POST /audit/retention/archive`, `POST /audit/events/{id}/redact` |
| `read` | `dev-read-key-CHANGE-ME` | `GET /audit/events`, `GET /audit/verify`, `GET /audit/export` |
| `compliance` | `dev-compliance-key-CHANGE-ME` | `GET /audit/compliance/account-access-report` |

`GET /health` requires no auth.

**These default keys are for local development only.** For any real deployment,
override them via environment variables before starting the service:

```bash
export AUDIT_LOG_API_KEY_WRITE="<your-secret-write-key>"
export AUDIT_LOG_API_KEY_READ="<your-secret-read-key>"
export AUDIT_LOG_API_KEY_COMPLIANCE="<your-secret-compliance-key>"
```

## Example usage

Write an event:
```bash
curl -X POST http://localhost:8000/audit/events \
  -H "X-API-Key: dev-write-key-CHANGE-ME" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "USER_LOGIN",
    "actor_id": "user-123",
    "resource_type": "SESSION",
    "resource_id": "sess-1",
    "payload": {"ip": "10.0.0.1"},
    "timestamp": "2026-09-02T12:00:00+00:00"
  }'
```

Query events:
```bash
curl "http://localhost:8000/audit/events?actor_id=user-123" \
  -H "X-API-Key: dev-read-key-CHANGE-ME"
```

Verify the chain:
```bash
curl http://localhost:8000/audit/verify \
  -H "X-API-Key: dev-read-key-CHANGE-ME"
```

**To see tamper detection in action**, stop the server, open `audit_log.db` directly
(e.g., `sqlite3 audit_log.db "UPDATE events SET actor_id='attacker' WHERE id=1;"`),
restart the server, and call `/audit/verify` again — it will report the tampering and
identify the affected record.

Archive old records:
```bash
curl -X POST "http://localhost:8000/audit/retention/archive?older_than_days=90" \
  -H "X-API-Key: dev-write-key-CHANGE-ME"
```

Redact a payload field:
```bash
curl -X POST http://localhost:8000/audit/events/1/redact \
  -H "X-API-Key: dev-write-key-CHANGE-ME" \
  -H "Content-Type: application/json" \
  -d '{"fields": ["account_number"]}'
```

Export a verifiable bundle:
```bash
curl "http://localhost:8000/audit/export?resource_id=acct-1" \
  -H "X-API-Key: dev-read-key-CHANGE-ME"
```

Generate a compliance report (Scenario C):
```bash
curl "http://localhost:8000/audit/compliance/account-access-report?requested_by=regulator-1" \
  -H "X-API-Key: dev-compliance-key-CHANGE-ME"
```

## Running the tests

```bash
pytest tests/ -v
```

No network access or external services required. See [`TESTING.md`](TESTING.md) for
what's covered and what's deliberately out of scope.

