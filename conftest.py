import tempfile
from pathlib import Path

import pytest

from database.app_db import initialize_app_database
from database.database import close_database, initialize_database


@pytest.fixture(autouse=True)
def isolate_test_storage(monkeypatch):
    """
    Automatic fixture applied to all pytest runs.
    Redirects SQLite database and JSON alert logs to an isolated temporary directory.
    Guarantees production sentinelx.db and alerts.json are never touched or contaminated.
    Uses tempfile.TemporaryDirectory directly to avoid Windows pytest-of-user permission collisions.
    """
    with tempfile.TemporaryDirectory(prefix="sentinelx_test_") as temp_dir:
        temp_path = Path(temp_dir)
        test_db = temp_path / "test_sentinelx.db"
        test_alerts = temp_path / "test_alerts.jsonl"

        monkeypatch.setenv("SENTINELX_DB_PATH", str(test_db))
        monkeypatch.setenv("SENTINELX_ALERT_LOG", str(test_alerts))
        monkeypatch.setenv("SENTINELX_APP_DB_PATH", str(temp_path / "test_app.db"))
        initialize_app_database()
        import backend.auth as auth_module
        from backend.ratelimit import limiter

        auth_module.throttle.reset()
        limiter.reset()
        # Rate limits are exercised explicitly in test_phase6c_api.py; elsewhere they must not interfere.
        monkeypatch.setattr(auth_module, "API_RATE_LIMIT_PER_MIN", 1_000_000)
        monkeypatch.setattr(auth_module, "LOGIN_RATE_LIMIT_PER_MIN", 1_000_000)

        # Initialize isolated test database schema
        initialize_database()

        try:
            yield {
                "db_path": test_db,
                "alert_log": test_alerts,
            }
        finally:
            close_database()
