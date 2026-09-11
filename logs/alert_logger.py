import json
import os
from datetime import datetime
from pathlib import Path

from database.database import insert_alert


DEFAULT_ALERT_FILE = Path(__file__).parent / "alerts.json"


def get_alert_file_path():
    override = os.getenv("SENTINELX_ALERT_LOG")
    if override:
        return Path(override)
    return DEFAULT_ALERT_FILE


# Preserve ALERT_FILE for backwards compatibility
ALERT_FILE = DEFAULT_ALERT_FILE


def log_alert(alert):
    alert_record = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        **alert
    }

    alert_file = get_alert_file_path()
    alert_file.parent.mkdir(parents=True, exist_ok=True)
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

    # Store the same alert in SQLite
    insert_alert(alert_record)

    return alert_record


if __name__ == "__main__":
    print("SentinelX Alert Logger")
    print("Alert logging module loaded successfully.")