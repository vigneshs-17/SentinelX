"""
app.db: the API process's own SQLite database (users, sessions, API keys, triage state, audit log arrive in
step 6b). Separate from alerts.db, which the API opens read-only. Same versioned-migration approach as alerts.db.
"""

import logging
import os
import sqlite3
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger("sentinelx.app_db")


class AppDatabaseError(RuntimeError):
    """app.db could not be opened, read or written (typically 'database is locked'). Not the sensor database."""


def get_app_database_path() -> Path:
    override = os.getenv("SENTINELX_APP_DB_PATH")
    if override:
        return Path(override)
    return Path(os.getenv("SENTINELX_DATA_DIR", "data")) / "app.db"


def get_app_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    target = Path(db_path).resolve() if db_path else get_app_database_path().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=10.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn


# Kept as one constant so the admin-only prune (backend/accounts.py prune_audit) recreates exactly this trigger.
AUDIT_NO_DELETE_TRIGGER = """
        CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


def _migration_1(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")


def _migration_2(conn: sqlite3.Connection) -> None:
    """Users, server-side sessions, API keys, triage state and the append-only audit log."""
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            last_login_at REAL
        );
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf_token TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_seen_at REAL NOT NULL,
            source_ip TEXT
        );
        CREATE INDEX idx_sessions_user ON sessions(user_id);
        CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL CHECK (role IN ('viewer', 'analyst')),
            created_by TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_used_at REAL,
            revoked_at REAL
        );
        CREATE TABLE triage (
            alert_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL CHECK (status IN ('new', 'acknowledged', 'investigating', 'resolved_tp', 'resolved_fp')),
            assignee TEXT,
            note TEXT,
            updated_by TEXT NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            source_ip TEXT,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT
        );
        CREATE INDEX idx_audit_ts ON audit_log(ts);
        CREATE INDEX idx_audit_target ON audit_log(target, action);
        CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
        """
        + AUDIT_NO_DELETE_TRIGGER
    )


# Append new migrations to this list; index + 1 is the schema version.
MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [_migration_1, _migration_2]


def initialize_app_database(db_path: Path | str | None = None) -> int:
    """Create app.db and apply pending migrations. Idempotent. Returns the schema version."""
    conn = get_app_connection(db_path)
    try:
        version = int(conn.execute("PRAGMA user_version;").fetchone()[0])
        for idx in range(version, len(MIGRATIONS)):
            with conn:
                MIGRATIONS[idx](conn)
                conn.execute(f"PRAGMA user_version = {idx + 1};")
            logger.info("app.db upgraded to user_version=%d", idx + 1)
        return len(MIGRATIONS)
    finally:
        conn.close()
