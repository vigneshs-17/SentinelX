"""axe-core (vendored, evaluated over CDP) on every screen in both themes: zero serious or critical violations."""

import pytest
from playwright.sync_api import expect

from tests.e2e.conftest import set_theme

THEMES = ["dark", "light"]
SCREENS = [
    ("overview", "overview", "main h1"),
    ("live", "live", "main h1"),
    ("alerts", "alerts", "tbody tr[data-id]"),
    ("graph", "graph", "svg.graph"),
    ("health", "health", "svg.spark"),
    ("admin-users", "admin", "tbody tr"),
    ("admin-keys", "admin?tab=keys", "#nk-name"),
    ("admin-audit", "admin?tab=audit", "tbody tr"),
]


def assert_clean(violations, label):
    assert not violations, f"{label}: " + "; ".join(f"{v['id']} ({v['impact']}): {v['nodes']}" for v in violations)


@pytest.mark.parametrize("theme", THEMES)
def test_login_screen_has_no_serious_violations(page, server, axe_violations, theme):
    page.goto(f"{server.base_url}/")
    expect(page.locator("#username")).to_be_visible()
    set_theme(page, theme)
    assert_clean(axe_violations(page), f"login/{theme}")


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize(("name", "route", "ready"), SCREENS)
def test_screen_has_no_serious_violations(page, login_as, axe_violations, name, route, ready, theme):
    login_as("admin", route)
    expect(page.locator(ready).first).to_be_visible()
    set_theme(page, theme)
    assert_clean(axe_violations(page), f"{name}/{theme}")


@pytest.mark.parametrize("theme", THEMES)
def test_alert_drawer_has_no_serious_violations(page, login_as, axe_violations, theme):
    login_as("analyst", "alerts")
    expect(page.locator("tbody tr[data-id]").first).to_be_visible()
    page.locator("tbody tr[data-id] .rowlink").first.click()
    expect(page.locator(".drawer #tri-status")).to_be_visible()
    set_theme(page, theme)
    assert_clean(axe_violations(page), f"drawer/{theme}")


@pytest.mark.parametrize("theme", THEMES)
def test_help_dialog_and_reset_password_dialog_have_no_serious_violations(page, login_as, axe_violations, theme):
    login_as("admin", "admin")
    expect(page.locator("tbody tr").first).to_be_visible()
    set_theme(page, theme)
    page.get_by_role("button", name="Reset password").first.click()
    expect(page.get_by_role("dialog")).to_be_visible()
    assert_clean(axe_violations(page), f"reset-dialog/{theme}")
    page.keyboard.press("Escape")
    page.locator("main h1").click()
    page.keyboard.press("?")
    expect(page.get_by_role("dialog", name="Keyboard shortcuts")).to_be_visible()
    assert_clean(axe_violations(page), f"help-dialog/{theme}")
