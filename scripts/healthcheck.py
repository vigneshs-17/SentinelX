"""
Container health checks (stdlib only).

    python scripts/healthcheck.py api      GET http://127.0.0.1:5000/health must return 200
    python scripts/healthcheck.py sensor   the newest sensor_status heartbeat in alerts.db must be < 30 s old

Exit code 0 = healthy, 1 = unhealthy.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

SENSOR_MAX_AGE_SECONDS = 30.0


def check_api() -> bool:
    port = os.getenv("SENTINELX_API_PORT", "5000")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as resp:  # noqa: S310  # nosec B310
            return bool(resp.status == 200)
    except OSError:
        return False


def check_sensor() -> bool:
    db = Path(os.getenv("SENTINELX_DB_PATH", "data/alerts.db"))
    if not db.exists():
        return False
    try:
        conn = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True, timeout=3)
        try:
            row = conn.execute("SELECT last_seen FROM sensor_status ORDER BY last_seen DESC LIMIT 1").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    if row is None:
        return False
    age = (datetime.now(UTC) - datetime.fromisoformat(row[0])).total_seconds()
    return age <= SENSOR_MAX_AGE_SECONDS


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1 or args[0] not in ("api", "sensor"):
        print("usage: healthcheck.py api|sensor", file=sys.stderr)
        return 2
    return 0 if (check_api() if args[0] == "api" else check_sensor()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
