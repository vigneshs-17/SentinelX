"""
SQLite database persistence layer for SentinelX alerts.

Maintains a long-lived, thread-safe writer connection with WAL mode and NORMAL
synchronization configured once per connection. All writes are serialized via a mutex lock.
Readers open independent connections to leverage SQLite WAL concurrency.
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config.settings import SENSOR_ID
from database.migrations import apply_migrations

logger = logging.getLogger("sentinelx.database")

_writer_lock = threading.Lock()
_writer_connection: sqlite3.Connection | None = None
_writer_db_path: Path | None = None


def get_database_path() -> Path:
    """Returns the configured SQLite database file path."""
    override = os.getenv("SENTINELX_DB_PATH")
    if override:
        return Path(override)
    data_dir = Path(os.getenv("SENTINELX_DATA_DIR", "data"))
    return data_dir / "sentinelx.db"


# Preserve DATABASE_FILE for backwards compatibility
DATABASE_FILE = get_database_path()


def _open_connection(db_path: Path) -> sqlite3.Connection:
    """Helper to open and configure a SQLite connection with WAL mode."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(db_path),
        timeout=10.0,
        check_same_thread=False,
    )
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.row_factory = sqlite3.Row
    return conn


def get_writer_connection() -> sqlite3.Connection:
    """
    Returns the long-lived, thread-safe writer connection.
    Re-opens connection if the target database path has changed.
    """
    global _writer_connection, _writer_db_path
    resolved_path = get_database_path().resolve()
    with _writer_lock:
        if _writer_connection is not None and _writer_db_path != resolved_path:
            try:
                _writer_connection.close()
            except Exception as exc:
                logger.debug("Exception closing previous writer connection: %s", exc)
            _writer_connection = None

        if _writer_connection is None:
            _writer_connection = _open_connection(resolved_path)
            _writer_db_path = resolved_path

        return _writer_connection


def close_database() -> None:
    """
    Closes the long-lived writer connection and resets internal cache.
    Called on system shutdown and test fixture teardown to prevent Windows file locks.
    """
    global _writer_connection, _writer_db_path
    with _writer_lock:
        if _writer_connection is not None:
            try:
                _writer_connection.close()
            except Exception as exc:
                logger.debug("Exception closing writer connection: %s", exc)
            _writer_connection = None
            _writer_db_path = None


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """
    Opens an independent SQLite connection for reading or administrative tasks.
    In WAL mode, readers do not block writers.
    """
    target_path = Path(db_path).resolve() if db_path else get_database_path().resolve()
    return _open_connection(target_path)


def initialize_database(db_path: Path | str | None = None, local_tz: Any = None) -> None:
    """
    Idempotently initializes the database and applies all pending migrations.
    Safe to call multiple times at startup.
    """
    target_path = Path(db_path).resolve() if db_path else get_database_path().resolve()
    conn = get_connection(target_path)
    try:
        apply_migrations(conn, local_tz=local_tz)
    finally:
        conn.close()


def insert_alert(alert: dict[str, Any]) -> None:
    """
    Inserts a security alert record into SQLite using the long-lived writer connection.
    Thread-safe and guarded by _writer_lock.
    """
    # Note: In Phase 2, detected_at is recorded as processing time (ISO-8601 UTC with offset).
    # Phase 3 switches this to packet event time.
    detected_at = alert.get("detected_at")
    if not detected_at:
        detected_at = datetime.now(UTC).isoformat(timespec="seconds")

    timestamp = alert.get("timestamp") or detected_at

    evidence = alert.get("evidence")
    evidence_str: str | None = None
    if evidence is not None:
        if isinstance(evidence, str):
            evidence_str = evidence
        else:
            try:
                evidence_str = json.dumps(evidence)
            except Exception:
                evidence_str = str(evidence)

    conn = get_writer_connection()
    with _writer_lock:
        conn.execute(
            """
            INSERT INTO alerts (
                timestamp,
                detected_at,
                threat_type,
                scan_type,
                severity,
                confidence,
                source_ip,
                destination_ip,
                protocol,
                message,
                evidence,
                ml_score,
                ml_label,
                sensor_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                detected_at,
                alert["threat_type"],
                alert.get("scan_type"),
                alert["severity"],
                alert.get("confidence"),
                alert.get("source_ip"),
                alert.get("destination_ip"),
                alert.get("protocol"),
                alert.get("message"),
                evidence_str,
                alert.get("ml_score") if alert.get("ml_score") is not None else alert.get("ml_confidence"),
                alert.get("ml_label"),
                alert.get("sensor_id", SENSOR_ID),
            ),
        )
        conn.commit()


if __name__ == "__main__":
    initialize_database()
