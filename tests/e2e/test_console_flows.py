"""User-visible flows in a real browser against the real API (seeded, fabricated data)."""

import csv
import re
import uuid

from playwright.sync_api import expect

from tests.e2e.conftest import PASSWORD, USERS


def rows(page):
    return page.locator("tbody tr[data-id]")


def open_first_alert(page):
    expect(rows(page).first).to_be_visible()
    rows(page).first.locator(".rowlink").click()
    expect(page.locator(".drawer")).to_be_visible()


# ------------------------------------------------------------------ login


def test_login_failure_shows_one_generic_message(page, server):
    page.goto(f"{server.base_url}/#/overview")
    page.locator("#username").fill(USERS["viewer"])
    page.locator("#password").fill("not the password at all")
    page.get_by_role("button", name="Sign in").click()
    expect(page.locator("#login-error")).to_have_text("Invalid username or password.")
    page.locator("#username").fill("nobody-here")
    page.locator("#password").fill("not the password at all")
    page.get_by_role("button", name="Sign in").click()
    expect(page.locator("#login-error")).to_have_text("Invalid username or password.")  # identical for unknown users
    expect(page.locator("#password")).to_have_value("")  # cleared after a failure


def test_login_success_lands_on_overview_and_sign_out_returns_to_login(page, login_as):
    login_as("viewer")
    expect(page.locator("main h1")).to_have_text("Overview")
    expect(page.locator("#whoami")).to_have_text(f"{USERS['viewer']} (viewer)")
    page.get_by_role("button", name="Sign out").click()
    expect(page.locator("#username")).to_be_visible()
    expect(page.locator("#topbar")).to_be_hidden()


def test_lockout_shows_the_wait_time_and_disables_the_button(page, scratch_server):
    page.goto(f"{scratch_server.base_url}/")
    for _ in range(5):
        page.locator("#username").fill(USERS["viewer"])
        page.locator("#password").fill("wrong wrong wrong")
        page.get_by_role("button", name="Sign in").click()
        expect(page.locator("#login-error")).to_have_text("Invalid username or password.")
    page.locator("#username").fill(USERS["viewer"])
    page.locator("#password").fill(PASSWORD)  # even the right password is refused while locked
    page.get_by_role("button", name="Sign in").click()
    expect(page.locator("#login-error")).to_contain_text("Too many attempts. Try again in")
    expect(page.locator("#login-error")).to_contain_text("second")
    expect(page.get_by_role("button", name="Sign in")).to_be_disabled()


# ------------------------------------------------------------------ roles and triage


def test_viewer_sees_no_triage_controls(page, login_as):
    login_as("viewer", "alerts")
    open_first_alert(page)
    drawer = page.locator(".drawer")
    expect(drawer).to_contain_text("Your role is read-only for triage.")
    expect(drawer.get_by_role("button", name="Save")).to_have_count(0)
    expect(drawer.locator("#tri-status")).to_have_count(0)


def test_analyst_triages_an_alert_and_sees_it_in_the_history(page, login_as):
    note = f"investigated {uuid.uuid4().hex[:8]}"
    login_as("analyst", "alerts")
    open_first_alert(page)
    alert_id = page.locator(".drawer h2").first.inner_text().split("#")[1]
    drawer = page.locator(".drawer")
    drawer.locator("#tri-status").select_option("investigating")
    drawer.locator("#tri-note").fill(note)
    drawer.get_by_role("button", name="Save").click()
    expect(page.locator(".drawer")).to_have_count(0)  # closes on success
    row = page.locator(f"tbody tr[data-id='{alert_id}']")
    expect(row.locator(".badge")).to_have_text("Investigating")
    row.locator(".rowlink").click()
    history = page.locator(".drawer .history").first
    expect(history).to_contain_text("New → Investigating")
    expect(history).to_contain_text(note)
    expect(history).to_contain_text(USERS["analyst"])


# ------------------------------------------------------------------ admin


def test_admin_creates_and_revokes_an_api_key(page, login_as, server):
    login_as("admin", "admin?tab=keys")
    page.locator("#nk-name").fill("e2e-key")
    page.get_by_role("button", name="Create key").click()
    keybox = page.locator(".keybox")
    expect(keybox).to_contain_text("sx_")
    key = keybox.inner_text().strip()
    ok = page.request.get(f"{server.base_url}/api/v1/stats", headers={"Authorization": f"Bearer {key}"})
    assert ok.status == 200
    page.get_by_role("button", name="I have stored it").click()
    expect(page.locator(".callout")).to_have_count(0)
    row = page.locator("tbody tr", has_text="e2e-key")
    expect(row).to_contain_text("Active")
    revoke = row.get_by_role("button", name="Revoke")
    revoke.click()  # first click only arms the button
    expect(revoke).to_have_text("Confirm revoke")
    revoke.click()
    expect(page.locator("tbody tr", has_text="e2e-key")).to_contain_text("Revoked")
    assert page.request.get(f"{server.base_url}/api/v1/stats", headers={"Authorization": f"Bearer {key}"}).status == 401


def test_non_admin_has_no_admin_menu_and_sees_a_notice(page, login_as):
    login_as("analyst")
    expect(page.locator("#nav").get_by_role("link", name="Admin")).to_have_count(0)
    page.evaluate("location.hash = '#/admin'")
    expect(page.get_by_text("You don't have permission for this.")).to_be_visible()


# ------------------------------------------------------------------ live and health


def test_live_view_shows_a_new_alert_after_the_sensor_writes_it(page, login_as, server):
    login_as("viewer", "live")
    expect(page.locator("#stream-status")).to_have_text("Live")
    marker = f"live-e2e-{uuid.uuid4().hex[:8]}"
    server.add_alert(message=marker)
    expect(page.locator("tbody tr", has_text=marker)).to_be_visible(timeout=15000)
    expect(page.locator("tbody tr.fresh", has_text=marker)).to_have_count(1)


def test_pause_live_buffers_new_alerts_until_resumed(page, login_as, server):
    login_as("viewer", "live")
    expect(page.locator("#stream-status")).to_have_text("Live")
    page.get_by_role("button", name="Pause live").click()
    marker = f"paused-e2e-{uuid.uuid4().hex[:8]}"
    server.add_alert(message=marker)
    expect(page.get_by_text("waiting")).to_be_visible(timeout=15000)
    expect(page.locator("tbody tr", has_text=marker)).to_have_count(0)
    page.get_by_role("button", name="Resume live").click()
    expect(page.locator("tbody tr", has_text=marker)).to_be_visible()


def test_offline_banner_when_the_heartbeat_is_stale(page, stale_server, login_as):
    login_as("viewer", "health", srv=stale_server)
    expect(page.get_by_role("alert").filter(has_text="sensor is offline")).to_be_visible()


def test_health_view_shows_online_sensor_and_sparklines(page, login_as):
    login_as("viewer", "health")
    expect(page.locator(".kpi", has=page.get_by_text("Sensor", exact=True))).to_contain_text("Online")
    expect(page.locator("svg.spark")).to_have_count(4)


# ------------------------------------------------------------------ filters, keyboard, graph, export


def test_filters_round_trip_through_the_url_hash(page, login_as):
    login_as("viewer", "alerts")
    page.locator("#f-severity").select_option("HIGH")
    expect(page).to_have_url(re.compile(r"severity=HIGH"))
    page.locator("#f-q").fill("PORT_SCAN")
    expect(page).to_have_url(re.compile(r"q=PORT_SCAN"))
    page.reload()
    expect(page.locator("#f-severity")).to_have_value("HIGH")
    expect(page.locator("#f-q")).to_have_value("PORT_SCAN")
    expect(rows(page).first).to_be_visible()
    severities = {t.strip() for t in rows(page).locator("td:nth-child(2)").all_inner_texts()}
    assert severities == {"HIGH"}
    page.get_by_role("button", name="Reset filters").click()
    expect(page.locator("#f-severity")).to_have_value("")


def test_sorting_by_a_column_updates_the_hash_and_aria_sort(page, login_as):
    login_as("viewer", "alerts")
    page.get_by_role("button", name=re.compile("^Source")).click()
    expect(page).to_have_url(re.compile(r"sort=source_ip"))
    expect(page.locator("th[aria-sort]", has_text="Source")).to_have_attribute("aria-sort", "descending")
    page.get_by_role("button", name=re.compile("^Source")).click()
    expect(page.locator("th[aria-sort]", has_text="Source")).to_have_attribute("aria-sort", "ascending")
    ips = rows(page).locator("td:nth-child(4)").all_inner_texts()
    assert ips == sorted(ips)


def test_keyboard_shortcuts(page, login_as):
    login_as("analyst", "alerts?status=new")
    expect(rows(page).first).to_be_visible()
    page.keyboard.press("/")
    expect(page.locator("#f-q")).to_be_focused()
    page.locator("main h1").click()
    page.keyboard.press("j")
    expect(rows(page).nth(0)).to_have_attribute("aria-selected", "true")
    page.keyboard.press("j")
    expect(rows(page).nth(1)).to_have_attribute("aria-selected", "true")
    page.keyboard.press("k")
    expect(rows(page).nth(0)).to_have_attribute("aria-selected", "true")
    page.keyboard.press("Enter")
    expect(page.locator(".drawer")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.locator(".drawer")).to_have_count(0)
    page.keyboard.press("?")
    expect(page.get_by_role("dialog", name="Keyboard shortcuts")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog")).to_have_count(0)
    first_id = rows(page).first.get_attribute("data-id")
    page.keyboard.press("a")  # acknowledge the selected alert (row 0 is still selected)
    expect(page.locator(f"tbody tr[data-id='{first_id}']")).to_have_count(
        0
    )  # no longer 'new', so it leaves the filtered list


def test_drawer_traps_focus_and_restores_it(page, login_as):
    login_as("analyst", "alerts")
    link = rows(page).first.locator(".rowlink")
    link.focus()
    link.press("Enter")
    drawer = page.locator(".drawer")
    expect(drawer).to_be_visible()
    for _ in range(40):  # tabbing never leaves the drawer
        page.keyboard.press("Tab")
        assert page.evaluate("!!document.activeElement.closest('.drawer')")
    page.keyboard.press("Escape")
    expect(drawer).to_have_count(0)
    assert page.evaluate("document.activeElement.classList.contains('rowlink')")


def test_clicking_a_graph_node_filters_the_alert_list(page, login_as):
    login_as("viewer", "graph")
    node = page.locator("svg.graph circle").first
    expect(node).to_be_visible()
    node.click(force=True)
    expect(page).to_have_url(re.compile(r"#/alerts\?.*(source_ip|destination_ip)="))
    expect(page.locator("main h1")).to_have_text("Alerts")
    expect(rows(page).first).to_be_visible()


def test_csv_export_neutralises_a_formula_injection_payload(page, login_as, server, tmp_path):
    payload = f'=HYPERLINK("http://evil.example/{uuid.uuid4().hex[:6]}","click")'
    server.add_alert(message=payload, source_ip="198.51.100.99")
    login_as("viewer", "alerts?source_ip=198.51.100.99")
    expect(rows(page).first).to_be_visible()
    with page.expect_download() as info:
        page.get_by_role("link", name="Export CSV").click()
    path = tmp_path / "export.csv"
    info.value.save_as(path)
    with open(path, newline="", encoding="utf-8") as f:
        data = list(csv.DictReader(f))
    messages = [r["message"] for r in data]
    assert messages and all(not m.startswith("=") for m in messages)
    assert "'" + payload in messages


def test_overview_tile_links_to_the_filtered_list_and_brush_sets_the_range(page, login_as):
    login_as("viewer", "overview")
    page.locator("a.kpi.kpi-HIGH").click()
    expect(page).to_have_url(re.compile(r"severity=HIGH"))
    page.go_back()
    chart = page.locator("svg.timeline")
    expect(chart).to_be_visible()
    box = chart.bounding_box()
    page.mouse.move(box["x"] + box["width"] * 0.3, box["y"] + box["height"] * 0.5)
    page.mouse.down()
    page.mouse.move(box["x"] + box["width"] * 0.6, box["y"] + box["height"] * 0.5, steps=6)
    page.mouse.up()
    expect(page).to_have_url(re.compile(r"since=.*until="))
