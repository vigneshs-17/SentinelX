"""
Versioned SQLite schema migrations for SentinelX.

Manages ordered, transaction-safe schema upgrades using SQLite PRAGMA user_version.
No ORM or external migration tooling required.
"""

import logging
import sqlite3
from datetime import UTC, datetime, tzinfo

logger = logging.getLogger("sentinelx.migrations")

CURRENT_SCHEMA_VERSION = 2


def convert_legacy_timestamp_to_utc(ts_str: str, local_tz: tzinfo | None = None) -> str:
    """
    Interprets a legacy naive local timestamp as local time and converts it
    to ISO-8601 UTC with +00:00 offset.

    When local_tz is None, converts naive_dt via naive_dt.astimezone(UTC), which
    applies OS local-time rules for that specific instant (handling DST per timestamp).
    When local_tz is provided, converts via naive_dt.replace(tzinfo=local_tz).astimezone(UTC).
    """
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is not None:
        dt_utc = dt.astimezone(UTC)
    elif local_tz is not None:
        dt_utc = dt.replace(tzinfo=local_tz).astimezone(UTC)
    else:
        dt_utc = dt.astimezone(UTC)
    return dt_utc.isoformat(timespec="seconds")


def migration_1(conn: sqlite3.Connection) -> None:
    """
    Migration 1: Base v1 alerts schema.

    Uses CREATE TABLE IF NOT EXISTS so that existing unversioned v1 databases
    (which already have the table created but PRAGMA user_version == 0)
    upgrade cleanly.
    """
    logger.info("Applying migration 1: v1 base schema")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            message TEXT
        );
        """
    )


def migration_2(conn: sqlite3.Connection, local_tz: tzinfo | None = None) -> None:
    """
    Migration 2: v2 schema upgrade.

    Adds event time (detected_at), classification, confidence, structured evidence,
    ML fields, and sensor identity to alerts table. Creates performance indexes on
    (detected_at), (threat_type, detected_at), and (source_ip).

    Assumption on Legacy Timestamps:
    Legacy SentinelX v1 stored naive local timestamps without timezone offsets.
    This migration backfills detected_at by interpreting existing naive timestamps
    as local time (per-timestamp local rules or explicit local_tz) and converting
    them to timezone-aware ISO-8601 UTC strings with +00:00 offset.

    Note on detected_at:
    In Phase 2, detected_at is recorded as processing time (ISO-8601 UTC with offset).
    Phase 3 switches this to packet event time.
    """
    logger.info("Applying migration 2: v2 schema columns and indexes")
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(alerts);")
    existing_cols = {row[1] for row in cursor.fetchall()}

    new_columns = [
        ("detected_at", "TEXT"),
        ("scan_type", "TEXT"),
        ("confidence", "REAL"),
        ("evidence", "TEXT"),
        ("ml_score", "REAL"),
        ("ml_label", "TEXT"),
        ("sensor_id", "TEXT"),
    ]

    for col_name, col_type in new_columns:
        if col_name not in existing_cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type};")

    # Create performance indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts(detected_at);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_detected ON alerts(threat_type, detected_at);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);")

    # Backfill detected_at for existing rows
    cursor.execute("SELECT id, timestamp FROM alerts WHERE detected_at IS NULL;")
    rows_to_backfill = cursor.fetchall()
    for alert_id, ts_val in rows_to_backfill:
        if ts_val:
            try:
                utc_ts = convert_legacy_timestamp_to_utc(ts_val, local_tz=local_tz)
            except Exception:
                utc_ts = datetime.now(UTC).isoformat(timespec="seconds")
        else:
            utc_ts = datetime.now(UTC).isoformat(timespec="seconds")

        conn.execute("UPDATE alerts SET detected_at = ? WHERE id = ?;", (utc_ts, alert_id))


def apply_migrations(conn: sqlite3.Connection, local_tz: tzinfo | None = None) -> int:
    """
    Idempotently inspects database PRAGMA user_version and applies all pending
    migrations in sequential order within immediate transactions.
    Accepts optional local_tz parameter for deterministic timezone conversion testing.
    """
    cursor = conn.cursor()
    cursor.execute("PRAGMA user_version;")
    current_version = cursor.fetchone()[0]

    if current_version < 1:
        with conn:
            migration_1(conn)
            conn.execute("PRAGMA user_version = 1;")
        current_version = 1
        logger.info("Database upgraded to user_version=1")

    if current_version < 2:
        with conn:
            migration_2(conn, local_tz=local_tz)
            conn.execute("PRAGMA user_version = 2;")
        current_version = 2
        logger.info("Database upgraded to user_version=2")

    return current_version
