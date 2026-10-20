"""
Seed a SentinelX data directory with demo users, synthetic alerts and sensor heartbeats, for local UI work and the
browser tests. This writes fabricated data: never point it at a real deployment.

    python scripts/seed_demo.py --data-dir demo-data --password 'a long demo passphrase' [--alerts 400] [--feed]

Users created (all with --password): demo-admin (admin), demo-analyst (analyst), demo-viewer (viewer).
--feed keeps running: a new alert every few seconds and a heartbeat every 5 s (Ctrl+C to stop).
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

SOURCES = ["198.51.100.50", "198.51.100.77", "203.0.113.9", "192.0.2.14", "10.20.30.40", "10.20.30.41", "172.16.5.5"]
TARGETS = ["192.168.1.10", "192.168.1.20", "192.168.1.100", "10.0.0.5"]
PORTS = [22, 80, 443, 445, 3389, 8080, 3306, 5432]
KINDS = [
    ("PORT_SCAN", "VERTICAL", "MEDIUM"),
    ("PORT_SCAN", "HORIZONTAL", "HIGH"),
    ("PORT_SCAN", "SLOW", "LOW"),
    ("SYN_FLOOD", None, "HIGH"),
    ("VOLUMETRIC", None, "MEDIUM"),
]


def make_alert(rng: random.Random, when: datetime) -> dict:
    threat, scan, severity = rng.choice(KINDS)
    src, dst, port = rng.choice(SOURCES), rng.choice(TARGETS), rng.choice(PORTS)
    return {
        "threat_type": threat,
        "scan_type": scan,
        "severity": severity,
        "confidence": round(rng.uniform(0.6, 0.99), 2),
        "source_ip": src,
        "destination_ip": dst,
        "destination_port": port,
        "protocol": "TCP",
        "detected_at": when.isoformat(timespec="seconds"),
        "timestamp": when.isoformat(timespec="seconds"),
        "message": f"{threat} {scan or ''} from {src} targeting {dst}:{port}".replace("  ", " "),
        "evidence": {
            "unique_ports_observed": rng.randint(10, 60),
            "window_seconds": 10.0,
            "sample_ports": rng.sample(PORTS, 4),
            "sample_targets": [dst],
        },
        "sensor_id": "demo-sensor",
    }


def heartbeat(rng: random.Random, n: int) -> dict:
    return {
        "sensor_id": "demo-sensor",
        "last_seen": datetime.now(UTC).isoformat(timespec="seconds"),
        "received": 10_000 + n * 50,
        "dropped": rng.randint(0, 3) * (n // 20),
        "queue_depth": rng.randint(0, 40),
        "pps_10s": round(rng.uniform(80, 400), 1),
        "state_size": rng.randint(300, 900),
        "evictions": 0,
        "webhook_failures": 0,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--password", required=True, help="password for the three demo users (12+ characters)")
    ap.add_argument("--alerts", type=int, default=400)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--feed", action="store_true")
    ap.add_argument(
        "--stale", action="store_true", help="make the last heartbeat 10 minutes old (sensor looks offline)"
    )
    args = ap.parse_args(argv)

    data = Path(args.data_dir).resolve()
    os.environ["SENTINELX_DATA_DIR"] = str(data)
    os.environ.setdefault("SENTINELX_DB_PATH", str(data / "alerts.db"))
    os.environ.setdefault("SENTINELX_APP_DB_PATH", str(data / "app.db"))

    from backend import accounts
    from database.app_db import initialize_app_database
    from database.database import initialize_database, insert_alert, insert_sensor_status

    initialize_database()
    initialize_app_database()
    for name, role in (("demo-admin", "admin"), ("demo-analyst", "analyst"), ("demo-viewer", "viewer")):
        if accounts.get_user_by_name(name) is None:
            accounts.create_user(name, args.password, role, actor="seed_demo")

    rng = random.Random(args.seed)
    now = datetime.now(UTC)
    for _ in range(args.alerts):
        insert_alert(make_alert(rng, now - timedelta(seconds=rng.randint(30, 24 * 3600))))
    shift = 600 if args.stale else 0
    for i in range(36):  # 30 minutes of heartbeats
        beat = heartbeat(rng, i)
        beat["last_seen"] = (now - timedelta(seconds=(36 - i) * 50 + shift)).isoformat(timespec="seconds")
        insert_sensor_status(beat)
    last = heartbeat(rng, 40)
    last["last_seen"] = (now - timedelta(seconds=shift)).isoformat(timespec="seconds")
    insert_sensor_status(last)
    print(f"[+] seeded {args.alerts} alerts into {data}")

    if args.feed:
        n = 41
        try:
            while True:
                insert_alert(make_alert(rng, datetime.now(UTC)))
                insert_sensor_status(heartbeat(rng, n))
                n += 1
                time.sleep(4)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
