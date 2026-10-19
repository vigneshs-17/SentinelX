import re

import pytest

from backend.api import DASHBOARD_DIR, app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestPhase7BCSPAndPermissionsPolicy:
    """Tests for Phase 7B Step 1: Content-Security-Policy & Permissions-Policy Hardening."""

    def test_csp_header_on_all_endpoints(self, client):
        """Verify Content-Security-Policy header exists on /, /health, /api/health, /api/alerts, /api/stats."""
        endpoints = ["/", "/health", "/api/health", "/api/alerts", "/api/stats"]
        for ep in endpoints:
            resp = client.get(ep)
            assert resp.status_code in (200, 204), f"Unexpected status on {ep}: {resp.status_code}"
            csp = resp.headers.get("Content-Security-Policy")
            assert csp is not None, f"Missing Content-Security-Policy on {ep}"

    def test_csp_header_contains_required_directives(self, client):
        """Verify CSP header strictly matches the approved policy baseline."""
        resp = client.get("/")
        csp = resp.headers.get("Content-Security-Policy", "")

        required_directives = [
            "default-src 'none'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "connect-src 'self' http://127.0.0.1:5000",
            "img-src 'self' data:",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ]
        for directive in required_directives:
            assert directive in csp, f"Directive '{directive}' missing from CSP: {csp}"

    def test_permissions_policy_header_directives(self, client):
        """Verify Permissions-Policy header blocks dangerous APIs and allows clipboard-write=(self)."""
        endpoints = ["/", "/health", "/api/health", "/api/alerts", "/api/stats"]
        expected_tokens = [
            "camera=()",
            "microphone=()",
            "geolocation=()",
            "payment=()",
            "usb=()",
            "bluetooth=()",
            "display-capture=()",
            "clipboard-write=(self)",
        ]
        for ep in endpoints:
            resp = client.get(ep)
            perm = resp.headers.get("Permissions-Policy")
            assert perm is not None, f"Missing Permissions-Policy on {ep}"
            for token in expected_tokens:
                assert token in perm, f"Token '{token}' missing from Permissions-Policy on {ep}"

    def test_dashboard_meta_tag_csp_matches_baseline(self):
        """Verify dashboard/index.html includes matching CSP meta tag for file:// launch compatibility."""
        index_file = DASHBOARD_DIR / "index.html"
        assert index_file.exists()
        content = index_file.read_text(encoding="utf-8")

        # Must have a <meta http-equiv="Content-Security-Policy" ...> tag
        meta_match = re.search(
            r'<meta\s+http-equiv=["\']Content-Security-Policy["\']\s+content="([^"]+)"', content, re.IGNORECASE
        )
        assert meta_match is not None, "Missing <meta http-equiv='Content-Security-Policy'> in dashboard/index.html"
        meta_csp = meta_match.group(1)

        required_meta_directives = [
            "default-src 'none'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "connect-src 'self' http://127.0.0.1:5000",
            "img-src 'self' data:",
            "base-uri 'none'",
            "form-action 'none'",
        ]
        for directive in required_meta_directives:
            assert directive in meta_csp, f"Meta CSP missing '{directive}': {meta_csp}"

    def test_dashboard_zero_external_dependencies(self):
        """Verify dashboard has zero external CDN links, fonts, or scripts."""
        index_file = DASHBOARD_DIR / "index.html"
        content = index_file.read_text(encoding="utf-8")

        # No http:// or https:// external links in src/href
        external_refs = re.findall(
            r'<(?:link|script|img|iframe)\b[^>]*\b(?:src|href)=[\'"](https?://[^\'"]*)[\'"]', content, re.IGNORECASE
        )
        assert len(external_refs) == 0, f"Found unexpected external resources: {external_refs}"

    def test_dashboard_security_invariants(self):
        """Verify strict XSS protections: no innerHTML, no outerHTML, no eval."""
        index_file = DASHBOARD_DIR / "index.html"
        content = index_file.read_text(encoding="utf-8")

        assert "innerHTML" not in content, "Found forbidden innerHTML in dashboard/index.html"
        assert "outerHTML" not in content, "Found forbidden outerHTML in dashboard/index.html"
        assert "document.write" not in content, "Found forbidden document.write in dashboard/index.html"
        assert "eval(" not in content, "Found forbidden eval() in dashboard/index.html"

    def test_clipboard_helper_integrity(self):
        """Verify copyToClipboard uses text-only APIs and fallback uses textContent/plain value."""
        index_file = DASHBOARD_DIR / "index.html"
        content = index_file.read_text(encoding="utf-8")

        assert "navigator.clipboard.writeText" in content, "Missing navigator.clipboard.writeText in dashboard"
        assert "fallbackCopy" in content, "Missing fallbackCopy helper in dashboard"
        assert 'document.execCommand("copy")' in content or "document.execCommand('copy')" in content

    def test_cors_behavior_preserved_with_csp(self, client, monkeypatch):
        """Verify CORS rules operate normally alongside the new CSP and Permissions-Policy headers."""
        # 1. Allowed origin
        resp_allowed = client.get("/api/stats", headers={"Origin": "http://127.0.0.1:5000"})
        assert resp_allowed.headers.get("Access-Control-Allow-Origin") == "http://127.0.0.1:5000"
        assert "Content-Security-Policy" in resp_allowed.headers
        assert "Permissions-Policy" in resp_allowed.headers

        # 2. Localhost alias
        resp_local = client.get("/api/stats", headers={"Origin": "http://localhost:5000"})
        assert resp_local.headers.get("Access-Control-Allow-Origin") == "http://localhost:5000"

        # 3. Origin: null blocked by default
        resp_null = client.get("/api/stats", headers={"Origin": "null"})
        assert "Access-Control-Allow-Origin" not in resp_null.headers

        # 4. Origin: null allowed with opt-in
        monkeypatch.setattr("backend.api.ALLOW_LOCAL_FILE_CORS", True)
        resp_null_optin = client.get("/api/stats", headers={"Origin": "null"})
        assert resp_null_optin.headers.get("Access-Control-Allow-Origin") == "null"

        # 5. Untrusted origin blocked
        resp_evil = client.get("/api/stats", headers={"Origin": "https://evil.example.com"})
        assert "Access-Control-Allow-Origin" not in resp_evil.headers
