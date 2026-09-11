import os
import tempfile
from pathlib import Path
import pytest

from database.database import initialize_database


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
        test_alerts = temp_path / "test_alerts.json"

        monkeypatch.setenv("SENTINELX_DB_PATH", str(test_db))
        monkeypatch.setenv("SENTINELX_ALERT_LOG", str(test_alerts))

        # Initialize isolated test database schema
        initialize_database()

        yield {
            "db_path": test_db,
            "alert_log": test_alerts,
        }
