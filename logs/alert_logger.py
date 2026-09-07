import json
from datetime import datetime
from pathlib import Path

from database.database import insert_alert


ALERT_FILE = Path(__file__).parent / "alerts.json"


def log_alert(alert):
    alert_record = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        **alert
    }

    existing_alerts = []

    if ALERT_FILE.exists():
        try:
            with open(ALERT_FILE, "r", encoding="utf-8") as file:
                existing_alerts = json.load(file)
        except (json.JSONDecodeError, OSError):
            existing_alerts = []

    existing_alerts.append(alert_record)

    with open(ALERT_FILE, "w", encoding="utf-8") as file:
        json.dump(existing_alerts, file, indent=4)

    # Store the same alert in SQLite
    insert_alert(alert_record)

    return alert_record


if __name__ == "__main__":
    print("SentinelX Alert Logger")
    print("Alert logging module loaded successfully.")