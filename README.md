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

## Authentication and Authorization

Every `/audit/*` endpoint requires a signed, short-lived bearer token — see
[`ARCHITECTURE.md`](ARCHITECTURE.md#9-authentication-and-authorization) for the full
design (authentication and authorization are treated as two distinct, separately
enforced concerns: 401 vs. 403).

**1. Exchange a client secret for a token:**
```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id": "my-service", "client_secret": "dev-write-secret-CHANGE-ME"}'
```
Response includes `access_token`, `scope` (derived from which secret you presented),
and `expires_in` (seconds — tokens are valid for 15 minutes).

**2. Use the token on subsequent requests:**
```bash
curl -X POST http://localhost:8000/audit/events \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

| Scope | Default client secret (local dev only) | Required for |
|---|---|---|
| `write` | `dev-write-secret-CHANGE-ME` | `POST /audit/events`, `POST /audit/retention/archive`, `POST /audit/events/{id}/redact` |
| `read` | `dev-read-secret-CHANGE-ME` | `GET /audit/events`, `GET /audit/verify`, `GET /audit/export` |
| `compliance` | `dev-compliance-secret-CHANGE-ME` | `GET /audit/compliance/account-access-report` |

`GET /health` and `POST /auth/token` itself require no auth.

**These default client secrets are for local development only.** For any real
deployment, override them — and the token-signing secret — via environment
variables before starting the service:

```bash
export AUDIT_LOG_CLIENT_SECRET_WRITE="<your-secret>"
export AUDIT_LOG_CLIENT_SECRET_READ="<your-secret>"
export AUDIT_LOG_CLIENT_SECRET_COMPLIANCE="<your-secret>"
export AUDIT_LOG_JWT_SIGNING_SECRET="<a-long-random-secret-distinct-from-the-above>"
```

## Example usage

The examples below assume you've obtained tokens as shown in the Authentication
section above and stored them, e.g.:
```bash
export WRITE_TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id": "cli", "client_secret": "dev-write-secret-CHANGE-ME"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
export READ_TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id": "cli", "client_secret": "dev-read-secret-CHANGE-ME"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
export COMPLIANCE_TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id": "cli", "client_secret": "dev-compliance-secret-CHANGE-ME"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```
Tokens expire after 15 minutes — re-run the relevant export above if a later command
starts returning 401.

Write an event:
```bash
curl -X POST http://localhost:8000/audit/events \
  -H "Authorization: Bearer $WRITE_TOKEN" \
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
  -H "Authorization: Bearer $READ_TOKEN"
```

Verify the chain:
```bash
curl http://localhost:8000/audit/verify \
  -H "Authorization: Bearer $READ_TOKEN"
```

**To see tamper detection in action**, stop the server, open `audit_log.db` directly
(e.g., `sqlite3 audit_log.db "UPDATE events SET actor_id='attacker' WHERE id=1;"`),
restart the server, and call `/audit/verify` again — it will report the tampering and
identify the affected record.

Archive old records:
```bash
curl -X POST "http://localhost:8000/audit/retention/archive?older_than_days=90" \
  -H "Authorization: Bearer $WRITE_TOKEN"
```

Redact a payload field:
```bash
curl -X POST http://localhost:8000/audit/events/1/redact \
  -H "Authorization: Bearer $WRITE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fields": ["account_number"]}'
```

Export a verifiable bundle:
```bash
curl "http://localhost:8000/audit/export?resource_id=acct-1" \
  -H "Authorization: Bearer $READ_TOKEN"
```

Generate a compliance report (Scenario C):
```bash
curl "http://localhost:8000/audit/compliance/account-access-report?requested_by=regulator-1" \
  -H "Authorization: Bearer $COMPLIANCE_TOKEN"
```

## Running the tests

```bash
pytest tests/ -v
```

No network access or external services required. See [`TESTING.md`](TESTING.md) for
what's covered and what's deliberately out of scope.

