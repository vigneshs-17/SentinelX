"""
SQLite database persistence layer for SentinelX alerts.

Maintains a long-lived, thread-safe writer connection with WAL mode and NORMAL
synchronization configured once per connection. All writes are serialized via a mutex lock.
Readers open independent connections to leverage SQLite WAL concurrency.
"""

import json
import logging
import os
import re
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
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
    return data_dir / "alerts.db"


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


def _open_ro(uri: str) -> sqlite3.Connection:
    """Open a read-only URI and force a real read now (sqlite3.connect is lazy, so a bad open would hide)."""
    conn = sqlite3.connect(uri, uri=True, timeout=10.0, check_same_thread=False)
    try:
        conn.execute("PRAGMA query_only=ON;")
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
    except sqlite3.Error:
        conn.close()
        raise
    conn.row_factory = sqlite3.Row
    return conn


def get_readonly_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """
    Opens alerts.db strictly read-only (mode=ro plus PRAGMA query_only): any write raises sqlite3.OperationalError.
    It never creates the file. This is what the API process uses.

    A WAL database needs its -wal/-shm files even to be read. On a read-only volume they cannot be created, so
    after a clean sensor shutdown (which removes them) mode=ro alone fails with "unable to open database file"
    (N2). In that case, and only when no -wal file exists (so no writer is mid-flight), retry with immutable=1:
    SQLite then reads the main file without locks or WAL, which is exact because nothing is writing.
    """
    target = Path(db_path).resolve() if db_path else get_database_path().resolve()
    base = target.as_uri()
    try:
        return _open_ro(f"{base}?mode=ro")
    except sqlite3.OperationalError:
        if not target.exists() or Path(f"{target}-wal").exists():
            raise
        return _open_ro(f"{base}?mode=ro&immutable=1")


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
    # detected_at is event time (packet time) when the engine supplies it, else wall-clock UTC.
    # ingested_at is always wall-clock UTC at insert; retention prunes by it (N1). The "ingested_at" key is a
    # test seam only: the engine never sets it.
    now_iso = datetime.now(UTC).isoformat(timespec="seconds")
    detected_at = alert.get("detected_at") or now_iso
    ingested_at = alert.get("ingested_at") or now_iso

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
                sensor_id,
                destination_port,
                ingested_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                alert.get("destination_port"),
                ingested_at,
            ),
        )
        conn.commit()


def prune_alerts(cutoff_utc_iso: str, db_path: Path | str | None = None) -> int:
    """
    Delete alerts whose ingested_at (wall-clock insert time, never event time) is strictly older than
    cutoff_utc_iso (ISO-8601 UTC with +00:00, which sorts lexically), then the triage rows of the deleted alerts.
    Uses its own connection, so it is safe next to a running sensor (WAL). Returns alerts deleted.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            deleted = conn.execute("DELETE FROM alerts WHERE ingested_at < ?", (cutoff_utc_iso,)).rowcount
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        return int(deleted)
    finally:
        conn.close()


def parse_age(text: str) -> timedelta:
    """Parse '30d' or '12h' (positive integer + unit) into a timedelta."""
    match = re.fullmatch(r"([1-9][0-9]*)([dh])", text.strip())
    if not match:
        raise ValueError(f"invalid age '{text}': use a positive integer with unit d or h, for example 30d")
    value, unit = int(match.group(1)), match.group(2)
    return timedelta(days=value) if unit == "d" else timedelta(hours=value)


def insert_sensor_status(status: dict[str, Any]) -> None:
    """Append one heartbeat row to sensor_status through the long-lived writer connection."""
    conn = get_writer_connection()
    with _writer_lock:
        conn.execute(
            """
            INSERT INTO sensor_status (
                sensor_id, last_seen, received, dropped, queue_depth, pps_10s,
                state_size, evictions, webhook_failures
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                status["sensor_id"],
                status["last_seen"],
                status["received"],
                status["dropped"],
                status["queue_depth"],
                status["pps_10s"],
                status["state_size"],
                status["evictions"],
                status["webhook_failures"],
            ),
        )
        conn.commit()


def prune_sensor_status(cutoff_utc_iso: str) -> int:
    """Delete heartbeat rows older than the cutoff (writer connection). Returns rows deleted."""
    conn = get_writer_connection()
    with _writer_lock:
        deleted = conn.execute("DELETE FROM sensor_status WHERE last_seen < ?", (cutoff_utc_iso,)).rowcount
        conn.commit()
    return int(deleted)


def fetch_latest_sensor_status(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Most recent heartbeat row across sensors, or None when the sensor has never reported."""
    row = conn.execute("SELECT * FROM sensor_status ORDER BY last_seen DESC, id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


if __name__ == "__main__":
    initialize_database()
