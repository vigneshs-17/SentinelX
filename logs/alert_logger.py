import json
import os
from pathlib import Path
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any

from database.database import insert_alert


DEFAULT_JSONL_LOG = Path(__file__).parent / "alerts.jsonl"
DEFAULT_ALERT_FILE = DEFAULT_JSONL_LOG
ALERT_FILE = DEFAULT_ALERT_FILE

DEFAULT_MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_MAX_LOG_BACKUPS = 5

_alert_log_lock = threading.Lock()


def get_alert_file_path() -> Path:
    override = os.getenv("SENTINELX_ALERT_LOG")
    if override:
        return Path(override)
    return DEFAULT_ALERT_FILE


def _rotate_file(file_path: Path, max_backups: int = DEFAULT_MAX_LOG_BACKUPS):
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


def log_alert(alert: dict) -> dict:
    """
    Logs an alert record to persistent storage and SQLite.
    Supports append-only JSONL format with size-based rotation,
    while maintaining backward compatibility for files explicitly ending in .json.
    """
    alert_record = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        **alert
    }

    alert_file = get_alert_file_path()
    alert_file.parent.mkdir(parents=True, exist_ok=True)

    max_size = int(os.getenv("SENTINELX_MAX_LOG_SIZE", str(DEFAULT_MAX_LOG_SIZE)))
    max_backups = int(os.getenv("SENTINELX_MAX_LOG_BACKUPS", str(DEFAULT_MAX_LOG_BACKUPS)))

    with _alert_log_lock:
        if alert_file.suffix == ".json":
            # Backward compatibility: legacy JSON array format
            existing_alerts = []
            if alert_file.exists():
                try:
                    with open(alert_file, "r", encoding="utf-8") as file:
                        existing_alerts = json.load(file)
                except (json.JSONDecodeError, OSError):
                    existing_alerts = []

            existing_alerts.append(alert_record)

            with open(alert_file, "w", encoding="utf-8") as file:
                json.dump(existing_alerts, file, indent=4)
        else:
            # Modern P1 Hardening: Append-only JSON Lines with rotation
            if alert_file.exists() and alert_file.stat().st_size >= max_size:
                _rotate_file(alert_file, max_backups)

            line = json.dumps(alert_record, ensure_ascii=False) + "\n"
            with open(alert_file, "a", encoding="utf-8") as file:
                file.write(line)
                file.flush()

        # Store the same alert in SQLite
        insert_alert(alert_record)

    return alert_record


def read_alerts(file_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Reads alerts from file storage.
    Supports both append-only JSONL (.jsonl) and legacy JSON array (.json) formats.
    Resilient against corrupted or malformed lines.
    """
    target = Path(file_path) if file_path else get_alert_file_path()
    if not target.exists():
        return []

    alerts: List[Dict[str, Any]] = []
    try:
        with open(target, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []

            # Check if content is a legacy JSON array
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
    print("SentinelX Alert Logger")
    print("Alert logging module loaded successfully.")