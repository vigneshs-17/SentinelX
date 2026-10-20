"""Browser tests: a real API process on seeded demo data, driven by Playwright. Run with `pytest -m e2e tests/e2e`."""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from demo_server import DemoServer  # noqa: E402

AXE_SOURCE = (Path(__file__).parent / "vendor" / "axe.min.js").read_text(encoding="utf-8")
PASSWORD = "e2e passphrase 2026 demo"
USERS = {"admin": "demo-admin", "analyst": "demo-analyst", "viewer": "demo-viewer"}


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/e2e" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.e2e)


@pytest.fixture(scope="session")
def browser_type_launch_args():
    """Use Playwright's bundled Chromium when installed; otherwise a system Chrome or Edge (local development)."""
    channel = os.getenv("PW_CHANNEL")
    if not channel:
        with sync_playwright() as p:
            bundled = Path(p.chromium.executable_path)
        if not bundled.exists():
            channel = (
                "chrome"
                if shutil.which("chrome") or Path("C:/Program Files/Google/Chrome/Application/chrome.exe").exists()
                else "msedge"
            )
    return {"channel": channel} if channel else {}


@pytest.fixture(scope="session")
def browser_context_args():
    return {"viewport": {"width": 1440, "height": 900}, "locale": "en-GB", "timezone_id": "UTC"}


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    s = DemoServer(tmp_path_factory.mktemp("e2e-main"), PASSWORD).start()
    yield s
    s.stop()


@pytest.fixture(scope="session")
def stale_server(tmp_path_factory):
    s = DemoServer(tmp_path_factory.mktemp("e2e-stale"), PASSWORD, stale=True).start()
    yield s
    s.stop()


@pytest.fixture
def scratch_server(tmp_path):
    """A throw-away server for tests that change global state (login lockout is per IP)."""
    s = DemoServer(tmp_path / "data", PASSWORD, alerts=20).start()
    yield s
    s.stop()


def login(page: Page, base_url: str, role: str, route: str = "overview") -> None:
    page.goto(f"{base_url}/#/{route}")
    page.locator("#username").fill(USERS[role])
    page.locator("#password").fill(PASSWORD)
    page.get_by_role("button", name="Sign in").click()
    expect(page.locator("#whoami")).to_contain_text(USERS[role])
    expect(page.locator("main h1").first).to_be_visible()


@pytest.fixture
def login_as(page, server):
    def do(role: str, route: str = "overview", srv=None):
        login(page, (srv or server).base_url, role, route)

    return do


@pytest.fixture
def axe_violations():
    """Returns a function that runs axe-core (vendored file, evaluated over CDP so the page CSP stays strict)."""

    def run(page: Page) -> list[dict]:
        page.evaluate(AXE_SOURCE)
        result = page.evaluate(
            "axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21a','wcag21aa']}})"
            ".then(r => r.violations.map(v => ({id: v.id, impact: v.impact, help: v.help,"
            " nodes: v.nodes.slice(0, 4).map(n => n.target.join(' ') + ' :: ' + n.failureSummary.replace(/\\s+/g, ' '))})))"
        )
        return [v for v in json.loads(json.dumps(result)) if v["impact"] in ("serious", "critical")]

    return run


def set_theme(page: Page, theme: str) -> None:
    page.evaluate("t => document.documentElement.setAttribute('data-theme', t)", theme)
