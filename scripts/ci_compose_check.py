"""
End-to-end check of a running compose stack (stdlib only), used by CI and runnable by hand:

    python scripts/ci_compose_check.py --base http://127.0.0.1:5000 --key sx_... \
        --admin-user ci-admin --admin-password '...'

Expects the sensor to have replayed the Phase 4 `fast_vertical_scan` scenario. It then
  1. confirms the sensor heartbeat is online,
  2. waits for the expected PORT_SCAN alert (198.51.100.50 -> 192.168.1.100) to appear through the API,
  3. triages that alert with the analyst API key,
  4. logs in as admin and asserts the audit log holds the triage row for that actor and alert.
Exit code 0 only if every step holds.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

EXPECTED = {"threat_type": "PORT_SCAN", "source_ip": "198.51.100.50", "destination_ip": "192.168.1.100"}


def call(opener, base, method, path, *, key=None, csrf=None, body=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if csrf:
        headers["X-CSRF-Token"] = csrf
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)  # noqa: S310
    try:
        with opener.open(req, timeout=10) as resp:  # noqa: S310  # nosec B310
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, (json.loads(raw) if raw else None)


def fail(msg: str) -> int:
    print(f"[FAIL] {msg}")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:5000")
    ap.add_argument("--key", required=True, help="analyst API key")
    ap.add_argument("--admin-user", required=True)
    ap.add_argument("--admin-password", required=True)
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args(argv)
    plain = urllib.request.build_opener()

    status, metrics = call(plain, args.base, "GET", "/api/v1/sensor/status", key=args.key)
    if status != 200 or not metrics.get("sensor_online"):
        return fail(f"sensor not online: HTTP {status} {metrics}")
    print("[ok] sensor heartbeat online")

    deadline, match = time.time() + args.timeout, None
    while time.time() < deadline and match is None:
        status, alerts = call(plain, args.base, "GET", "/api/v1/alerts?threat_type=PORT_SCAN&limit=100", key=args.key)
        if status == 200:
            match = next((a for a in alerts if all(a.get(k) == v for k, v in EXPECTED.items())), None)
        if match is None:
            time.sleep(2)
    if match is None:
        return fail(f"expected alert {EXPECTED} did not appear within {args.timeout}s")
    print(f"[ok] expected alert #{match['id']} visible through the API")

    status, triage = call(
        plain,
        args.base,
        "POST",
        f"/api/v1/alerts/{match['id']}/triage",
        key=args.key,
        body={"status": "acknowledged", "note": "compose check"},
    )
    if status != 200 or triage.get("status") != "acknowledged":
        return fail(f"triage failed: HTTP {status} {triage}")
    print("[ok] alert triaged")

    jar = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    status, login = call(
        jar, args.base, "POST", "/login", body={"username": args.admin_user, "password": args.admin_password}
    )
    if status != 200:
        return fail(f"admin login failed: HTTP {status}")
    status, rows = call(jar, args.base, "GET", f"/api/v1/audit?action=triage.update&target=alert:{match['id']}")
    if (
        status != 200
        or not rows
        or not rows[0]["actor"].startswith("apikey:")
        or rows[0]["detail"].get("to") != "acknowledged"
    ):
        return fail(f"audit row missing or wrong: HTTP {status} {rows}")
    print(f"[ok] audit row present: actor={rows[0]['actor']} target={rows[0]['target']}")
    print("[PASS] compose integration check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
