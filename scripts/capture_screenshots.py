"""
Capture README screenshots of every console screen at 1440 px wide, light and dark, into docs/img/.

    python scripts/capture_screenshots.py [--out docs/img]

Starts the real API on freshly seeded, fabricated demo data (scripts/demo_server.py), so the images show the
console as shipped, not mock-ups. Needs Playwright with a Chromium build, or a system Chrome/Edge.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "scripts"))

from demo_server import DemoServer  # noqa: E402

PASSWORD = "shots-" + secrets.token_hex(8)  # throw-away: the demo database lives in a temp dir that is deleted
SCREENS = [
    ("overview", "#/overview", "svg.timeline"),
    ("live", "#/live", "tbody tr[data-id]"),
    ("alerts", "#/alerts?severity=HIGH", "tbody tr[data-id]"),
    ("graph", "#/graph", "svg.graph circle"),
    ("health", "#/health", "svg.spark"),
    ("admin-users", "#/admin", "tbody tr"),
    ("admin-keys", "#/admin?tab=keys", "#nk-name"),
    ("admin-audit", "#/admin?tab=audit", "tbody tr"),
]


def launch_args(p) -> dict[str, str]:
    channel = os.getenv("PW_CHANNEL")
    if channel:
        return {"channel": channel}
    if Path(p.chromium.executable_path).exists():
        return {}
    return {
        "channel": "chrome"
        if Path("C:/Program Files/Google/Chrome/Application/chrome.exe").exists() or shutil.which("google-chrome")
        else "msedge"
    }


def main(argv: list[str] | None = None) -> int:
    from playwright.sync_api import sync_playwright

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(repo_root / "docs" / "img"))
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="sentinelx_shots_") as tmp, sync_playwright() as p:
        server = DemoServer(Path(tmp), PASSWORD, alerts=400).start()
        try:
            browser = p.chromium.launch(**launch_args(p))
            for theme in ("dark", "light"):
                ctx = browser.new_context(
                    viewport={"width": 1440, "height": 900}, locale="en-GB", timezone_id="UTC", color_scheme=theme
                )
                page = ctx.new_page()
                page.add_init_script(f"try {{ localStorage.setItem('sx-theme', '{theme}'); }} catch (e) {{}}")
                page.goto(server.base_url + "/")
                page.locator("#username").wait_for()
                path = out / f"login-{theme}.png"
                page.screenshot(path=path)
                written.append(path)
                page.locator("#username").fill("demo-admin")
                page.locator("#password").fill(PASSWORD)
                page.get_by_role("button", name="Sign in").click()
                page.locator("#whoami").wait_for()
                for name, route, ready in SCREENS:
                    page.evaluate(f"location.hash = '{route}'")
                    page.locator(ready).first.wait_for()
                    page.wait_for_timeout(400)
                    path = out / f"{name}-{theme}.png"
                    page.screenshot(path=path)
                    written.append(path)
                page.evaluate("location.hash = '#/alerts'")
                page.locator("tbody tr[data-id] .rowlink").first.click()
                page.locator(".drawer #tri-status").wait_for()
                page.wait_for_timeout(300)
                path = out / f"alert-drawer-{theme}.png"
                page.screenshot(path=path)
                written.append(path)
                ctx.close()
            browser.close()
        finally:
            server.stop()
    for path in written:
        print(
            f"[+] {path.relative_to(repo_root) if path.is_relative_to(repo_root) else path} ({path.stat().st_size:,} bytes)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
