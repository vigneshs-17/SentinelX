"""
API-process housekeeping on a schedule: expired sessions and triage rows whose alert retention has removed.

Lives in the API process because app.db is owned there; the sensor never touches it. Every task is wrapped so a
locked or unreadable database logs a warning and the loop carries on.
"""

from __future__ import annotations

import logging
import threading

from backend import accounts
from database.database import get_readonly_connection

logger = logging.getLogger("sentinelx.housekeeping")

INTERVAL_SECONDS = 900.0


def run_once() -> dict[str, int]:
    """One pass. Returns what was deleted; a task that fails is skipped and logged."""
    done = {"sessions": 0, "triage": 0}
    try:
        done["sessions"] = accounts.purge_expired_sessions()
    except Exception as exc:  # noqa: BLE001 - housekeeping must never take the API down
        logger.warning("housekeeping: session purge failed: %s", exc)
    try:
        alerts = get_readonly_connection()
        try:
            done["triage"] = accounts.prune_orphan_triage(alerts)
        finally:
            alerts.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("housekeeping: triage cleanup failed: %s", exc)
    if any(done.values()):
        logger.info(
            "housekeeping: removed %d expired sessions, %d orphan triage rows", done["sessions"], done["triage"]
        )
    return done


def start(stop: threading.Event | None = None, interval: float = INTERVAL_SECONDS) -> threading.Thread:
    """Start the daemon loop (first pass immediately). Pass an Event to stop it."""
    stop = stop or threading.Event()

    def loop() -> None:
        while True:
            run_once()
            if stop.wait(interval):
                return

    thread = threading.Thread(target=loop, name="ApiHousekeeping", daemon=True)
    thread.start()
    return thread
