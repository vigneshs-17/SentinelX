"""
Persistent alert logger for SentinelX.

Appends alert records to an append-only JSON Lines (.jsonl) file with size-based
rotation, and forwards alerts to SQLite persistence. All timestamps are timezone-aware UTC.
"""

import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from database.database import insert_alert

logger = logging.getLogger("sentinelx.logger")

DEFAULT_MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_LOG_BACKUPS = 5

_alert_log_lock = threading.Lock()


def get_alert_file_path() -> Path:
    """Returns the configured JSONL alert file path."""
    override = os.getenv("SENTINELX_ALERT_LOG")
    if override:
        return Path(override)
    data_dir = Path(os.getenv("SENTINELX_DATA_DIR", "data"))
    return data_dir / "alerts.jsonl"


# Preserve ALERT_FILE for backwards compatibility
ALERT_FILE = get_alert_file_path()


def _rotate_file(file_path: Path, max_backups: int = DEFAULT_MAX_LOG_BACKUPS) -> None:
    """
    Performs log file rotation when current file size reaches limit.
    Rotates:
        file.jsonl.4 -> file.jsonl.5 (if 5 exists, removed)
        file.jsonl.3 -> file.jsonl.4
        file.jsonl.2 -> file.jsonl.3
        file.jsonl.1 -> file.jsonl.2
        file.jsonl   -> file.jsonl.1
    """
    if max_backups <= 0:
        if file_path.exists():
            try:
                file_path.unlink()
            except OSError:
                pass
        return

    # Delete oldest backup if it exists
    oldest = file_path.with_name(f"{file_path.name}.{max_backups}")
    if oldest.exists():
        try:
            oldest.unlink()
        except OSError:
            pass

    # Shift backups down
    for i in range(max_backups - 1, 0, -1):
        src = file_path.with_name(f"{file_path.name}.{i}")
        dst = file_path.with_name(f"{file_path.name}.{i + 1}")
        if src.exists():
            try:
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
            except OSError:
                pass

    # Move current file to .1
    first_backup = file_path.with_name(f"{file_path.name}.1")
    if file_path.exists():
        try:
            if first_backup.exists():
                first_backup.unlink()
            file_path.rename(first_backup)
        except OSError:
            pass


def log_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Logs an alert record to append-only JSONL storage and SQLite.
    Timestamps are formatted as ISO-8601 UTC with explicit offset (+00:00).
    """
    # Note: In Phase 2, detected_at is recorded as processing time (ISO-8601 UTC with offset).
    # Phase 3 switches this to packet event time.
    now_utc = datetime.now(UTC).isoformat(timespec="seconds")
    detected_at = alert.get("detected_at") or now_utc
    timestamp = alert.get("timestamp") or detected_at

    alert_record = {
        **alert,
        "detected_at": detected_at,
        "timestamp": timestamp,
    }

    alert_file = get_alert_file_path()
    alert_file.parent.mkdir(parents=True, exist_ok=True)

    max_size = int(os.getenv("SENTINELX_MAX_LOG_SIZE", str(DEFAULT_MAX_LOG_SIZE)))
    max_backups = int(os.getenv("SENTINELX_MAX_LOG_BACKUPS", str(DEFAULT_MAX_LOG_BACKUPS)))

    with _alert_log_lock:
        if alert_file.exists() and alert_file.stat().st_size >= max_size:
            _rotate_file(alert_file, max_backups)

        line = json.dumps(alert_record, ensure_ascii=False) + "\n"
        with open(alert_file, "a", encoding="utf-8") as file:
            file.write(line)
            file.flush()

        # Store in SQLite database
        insert_alert(alert_record)

    return alert_record


def read_alerts(file_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Reads alerts from file storage.
    Supports append-only JSONL format and legacy files with corrupted line resilience.
    """
    target = Path(file_path) if file_path else get_alert_file_path()
    if not target.exists():
        return []

    alerts: list[dict[str, Any]] = []
    try:
        with open(target, encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []

            # Check if content starts with legacy JSON array
            if content.startswith("["):
                try:
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        return parsed
                except json.JSONDecodeError:
                    pass

            # Parse line by line as JSONL
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        alerts.append(record)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Gracefully skip malformed line
                    continue
    except OSError:
        return []

    return alerts


if __name__ == "__main__":
    logger.info("SentinelX Alert Logger loaded successfully.")
