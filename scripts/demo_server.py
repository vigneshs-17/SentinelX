"""
Run the real API (waitress) on freshly seeded demo data. Used by the browser tests and the screenshot script, and handy
for looking at the console by hand:

    python scripts/demo_server.py --password 'a long demo passphrase' [--port 5000]

Logins: demo-admin / demo-analyst / demo-viewer with that password. All data is fabricated.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class DemoServer:
    def __init__(
        self,
        data_dir: Path,
        password: str,
        port: int | None = None,
        alerts: int = 300,
        stale: bool = False,
        extra_env: dict[str, str] | None = None,
    ):
        self.data_dir, self.password, self.alerts, self.stale = Path(data_dir), password, alerts, stale
        self.port = port or free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.env = {
            **os.environ,
            "SENTINELX_DATA_DIR": str(self.data_dir),
            "SENTINELX_DB_PATH": str(self.data_dir / "alerts.db"),
            "SENTINELX_APP_DB_PATH": str(self.data_dir / "app.db"),
            "SENTINELX_API_HOST": "127.0.0.1",
            "SENTINELX_API_PORT": str(self.port),
            "SENTINELX_RATE_LIMIT": "1000000",
            "SENTINELX_LOGIN_RATE_LIMIT": "1000000",
            "SENTINELX_STREAM_INTERVAL": "0.5",
            "PYTHONUTF8": "1",
            **(extra_env or {}),
        }
        self.proc: subprocess.Popen[bytes] | None = None

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # nosec B603
            [sys.executable, *args], cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=120, check=True
        )  # noqa: S603

    def start(self) -> DemoServer:
        seed = [
            "scripts/seed_demo.py",
            "--data-dir",
            str(self.data_dir),
            "--password",
            self.password,
            "--alerts",
            str(self.alerts),
        ]
        self._run(seed + (["--stale"] if self.stale else []))
        self.proc = subprocess.Popen(  # nosec B603
            [sys.executable, "main.py", "api"],
            cwd=ROOT,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # noqa: S603
        deadline = time.time() + 40
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("API process exited during start-up")
            try:
                with urllib.request.urlopen(f"{self.base_url}/health", timeout=2) as resp:  # noqa: S310  # nosec B310
                    if resp.status == 200:
                        return self
            except (urllib.error.URLError, OSError):
                time.sleep(0.3)
        raise RuntimeError("API did not become healthy in time")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def add_alert(self, **fields: object) -> None:
        """Insert one alert through the sensor-side writer (a separate process, like the real sensor)."""
        code = (
            "import json,sys\n"
            "from datetime import UTC, datetime\n"
            "from database.database import insert_alert\n"
            "a = {'threat_type':'PORT_SCAN','scan_type':'VERTICAL','severity':'HIGH','source_ip':'198.51.100.250',"
            "'destination_ip':'192.168.1.10','destination_port':22,'protocol':'TCP','message':'e2e alert','sensor_id':'e2e'}\n"
            "a.update(json.loads(sys.argv[1]))\n"
            "now = datetime.now(UTC).isoformat(timespec='seconds')\n"
            "a.setdefault('detected_at', now); a.setdefault('timestamp', now)\n"
            "insert_alert(a)\n"
        )
        self._run(["-c", code, json.dumps(fields)])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="sentinelx_demo_") as tmp:
        server = DemoServer(Path(tmp), args.password, port=args.port).start()
        print(f"[+] demo console on {server.base_url}/  (demo-admin / demo-analyst / demo-viewer). Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
