"""Console hardening: strict CSP header, no inline code, no external resources, XSS-safe DOM use, size budget."""

import re
from pathlib import Path

import pytest

from backend.api import CSP, DASHBOARD_DIR, STATIC_DIR, app
from tests.support import authed_client

ENDPOINTS = ["/", "/health", "/static/js/main.js", "/static/css/app.css", "/api/v1/alerts", "/api/v1/stats"]
FORBIDDEN_JS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function")
BUDGET_BYTES = 200 * 1024


def js_files():
    return sorted(STATIC_DIR.rglob("*.js"))


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return authed_client(app)


def test_csp_header_is_exact_and_present_everywhere(client):
    for ep in ENDPOINTS:
        assert client.get(ep).headers.get("Content-Security-Policy") == CSP, ep
    assert CSP.split("; ") == [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "img-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
    ]
    assert "unsafe-inline" not in CSP and "127.0.0.1" not in CSP


def test_permissions_policy_header_directives(client):
    for ep in ENDPOINTS:
        perm = client.get(ep).headers.get("Permissions-Policy", "")
        for token in ("camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"):
            assert token in perm, (ep, token)


def test_index_has_no_inline_script_style_or_handlers():
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    assert not re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html, re.I), "inline <script>"
    assert "<style" not in html.lower(), "inline <style>"
    assert not re.findall(r"\sstyle\s*=", html, re.I), "inline style attribute"
    assert not re.findall(r"\son[a-z]+\s*=", html, re.I), "inline event handler"
    assert 'http-equiv="Content-Security-Policy"' not in html  # the response header is the single source of truth
    assert '<script type="module" src="/static/js/main.js">' in html and 'href="/static/css/app.css"' in html


def test_no_markup_parsing_or_code_evaluating_apis_anywhere_in_static():
    """Phase 7 rule: textContent/createElement only; fails on any HTML-string sink or dynamic code."""
    assert js_files()
    for path in js_files():
        text = path.read_text(encoding="utf-8")
        for bad in FORBIDDEN_JS:
            assert bad not in text, f"{bad} in {path.name}"
        assert not re.search(r"setAttribute\(\s*['\"]style['\"]", text), f"inline style via setAttribute in {path.name}"
        assert ".cssText" not in text, path.name
        assert not re.search(r"[{,]\s*style\s*:", text), f"style prop passed to h() in {path.name}"
        assert not re.search(r"tabindex['\"]?\s*:\s*['\"]?[1-9]", text), f"positive tabindex in {path.name}"


def test_no_external_resources_in_html_css_or_js():
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    css = (STATIC_DIR / "css" / "app.css").read_text(encoding="utf-8")
    assert not re.findall(r'(?:src|href)=[\'"]https?://', html, re.I)
    assert "@import" not in css and not re.findall(r"url\(\s*['\"]?https?://", css, re.I)
    for path in js_files():
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"(?:fetch|import)\(\s*['\"`]https?://", text), path.name
        assert "XMLHttpRequest" not in text and "WebSocket(" not in text, path.name


def test_js_and_css_stay_under_the_200kb_budget():
    total = sum(p.stat().st_size for p in [*js_files(), *STATIC_DIR.rglob("*.css")])
    assert total < BUDGET_BYTES, f"{total} bytes of JS+CSS exceeds the {BUDGET_BYTES} byte budget"


def test_every_relative_import_resolves_to_a_file():
    for path in js_files():
        for spec in re.findall(r"""from\s+["'](\.{1,2}/[^"']+)["']""", path.read_text(encoding="utf-8")):
            assert (path.parent / spec).resolve().is_file(), f"{path.name} imports missing {spec}"


def test_every_api_path_the_console_calls_exists_on_the_server():
    """Contract test: the strings the JS passes to fetch/api.get/api.post must be routes Flask knows."""
    adapter = app.url_map.bind("localhost")
    seen = set()
    for path in js_files():
        for literal in re.findall(
            r"""["'`](/(?:api/v1/[A-Za-z0-9_/\-${}.]*|login))["'`]""", path.read_text(encoding="utf-8")
        ):
            seen.add(re.sub(r"\$\{[^}]*\}", "1", literal))
    assert {"/login", "/api/v1/alerts", "/api/v1/overview", "/api/v1/session", "/api/v1/logout"} <= seen
    for literal in seen:
        for method in ("GET", "POST", "DELETE"):
            try:
                adapter.match(literal, method=method)
                break
            except Exception:  # noqa: S112 - try the next method; fail below if none matches
                continue
        else:
            pytest.fail(f"console calls {literal} but no route matches")


def test_static_serving_is_confined_to_the_static_directory(client):
    assert client.get("/static/js/main.js").status_code == 200
    assert client.get("/static/js/main.js").mimetype in ("text/javascript", "application/javascript")
    assert client.get("/static/css/app.css").status_code == 200
    for evil in ("../index.html", "..%2findex.html", "%2e%2e/index.html", "js/../../index.html", "nope.js"):
        assert client.get(f"/static/{evil}").status_code == 404


def test_shell_has_the_accessibility_basics():
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    assert '<html lang="en">' in html and "<title>" in html and 'name="viewport"' in html
    assert 'class="skip-link" href="#main"' in html and '<main id="main"' in html
    assert "<header" in html and '<nav class="nav"' in html and 'aria-label="Primary"' in html
    assert 'aria-live="polite"' in html and 'role="status"' in html  # live regions for alerts and toasts


def test_reduced_motion_and_both_themes_are_defined():
    css = (STATIC_DIR / "css" / "app.css").read_text(encoding="utf-8")
    assert (
        "prefers-reduced-motion: reduce" in css and 'data-theme="light"' in css and "prefers-color-scheme: light" in css
    )
    assert "font-variant-numeric: tabular-nums" in css
    for sev in ("HIGH", "MEDIUM", "LOW"):
        assert f".sev-{sev}" in css
    for value in re.findall(r"transition:[^;]*?(\d*\.?\d+)s", css):  # transitions stay at or under 150 ms
        assert float(value) <= 0.15, f"transition {value}s is over 150 ms"


def test_keyboard_shortcuts_documented_in_the_help_overlay():
    main = (STATIC_DIR / "js" / "main.js").read_text(encoding="utf-8")
    for key in ('"j / k"', '"Enter"', '"a"', '"/"', '"?"', '"Esc"'):
        assert key in main
    assert Path(STATIC_DIR / "js" / "views" / "alerts.js").read_text(encoding="utf-8").count("shortcuts.set") == 1
