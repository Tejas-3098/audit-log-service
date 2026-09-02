"""Shared pytest fixtures across all test modules.

Two fixtures apply automatically (autouse) to every test in this suite by default:

  - isolated_db: points the app at a throwaway SQLite file per test, so tests never
    touch or leak state into a real dev database. Consolidated here from what was
    previously a copy-pasted fixture in every test file. Patches app.db.DB_PATH
    directly (rather than relying on an env var read at import time) because module
    import order across test files is not guaranteed -- an env var set in one file
    could run after app.db has already been imported by another test module,
    silently leaving the real dev database in use. (This is also why app/auth.py
    reads its API keys from os.environ at request time rather than at import time --
    same lesson, applied consistently.)

  - bypass_auth: overrides the three API-key dependencies (require_write, require_read,
    require_compliance) to be no-ops, since most tests in this suite are about
    business logic (hash chains, queries, redaction, etc.), not auth enforcement
    itself. Auth enforcement is tested exhaustively and explicitly in
    tests/test_auth.py, which overrides THIS fixture locally (same name, shadows the
    autouse version for that module only) to restore real enforcement.
"""
import pytest

import app.db as db_module
from app.auth import require_compliance, require_read, require_write
from app.main import app


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    test_db_path = tmp_path / "test_audit_log.db"
    monkeypatch.setattr(db_module, "DB_PATH", test_db_path)
    db_module.init_db()
    yield


@pytest.fixture(autouse=True)
def bypass_auth():
    app.dependency_overrides[require_write] = lambda: None
    app.dependency_overrides[require_read] = lambda: None
    app.dependency_overrides[require_compliance] = lambda: None
    yield
    app.dependency_overrides.clear()
