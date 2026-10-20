import concurrent.futures

import pytest

from backend.api import app
from config.settings import (
    API_DEFAULT_LIMIT,
    API_MAX_LIMIT,
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_VOLUMETRIC,
)
from database.database import insert_alert


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    return app.test_client()


class TestBackendApi:
    """Phase 5 API Hardening and Production Architecture test suite."""

    def test_home_serves_html(self, client):
        """Verify root endpoint serves the single-page dashboard HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.content_type
        html_content = response.get_data(as_text=True)
        assert "SentinelX" in html_content
        assert "Network Intrusion Detection & Threat Monitoring System" in html_content

    def test_dashboard_p0_features_and_xss_safety(self, client):
        """Verify dashboard/index.html implements P0 features, destination_ip, health probe, and XSS safety."""
        response = client.get("/")
        assert response.status_code == 200
        content = response.get_data(as_text=True)

        # Destination IP vector rendering
        assert "destination_ip" in content
        assert "vector-arrow" in content
        assert "ip-source" in content
        assert "ip-dest" in content

        # Live /health probe
        assert "/health" in content
        assert "checkHealth" in content
        assert "ENGINE ONLINE" in content

        # Keyed DOM reconciliation
        assert "data-alert-id" in content
        assert "insertBefore" in content

        # Human-friendly timestamp
        assert "formatTimestamp" in content

        # XSS safety: no innerHTML or insertAdjacentHTML anywhere in the file
        assert "innerHTML" not in content, "Found unsafe innerHTML in dashboard/index.html!"
        assert "insertAdjacentHTML" not in content
        assert "document.write" not in content

    def test_dashboard_p1_investigation_and_interaction_features(self, client):
        """Verify dashboard/index.html implements Phase 6B P1 features:
        search, threat filters, severity filters, threat distribution bar,
        detail inspection drawer with genuine API fields only, clipboard copy,
        and strict XSS prevention."""
        response = client.get("/")
        assert response.status_code == 200
        content = response.get_data(as_text=True)

        # 1. UI State Model
        assert "UI_STATE" in content
        assert "searchQuery" in content
        assert "threatFilter" in content
        assert "severityFilter" in content
        assert "expandedAlertId" in content

        # 2. Search input & clear button
        assert "alert-search" in content
        assert "search-clear-btn" in content
        assert "Search by IP, message, threat, ID..." in content

        # 3. Filter buttons (Threat & Severity)
        assert 'data-threat="ALL"' in content
        assert 'data-threat="PORT_SCAN"' in content
        assert 'data-threat="HIGH_TRAFFIC"' in content
        assert 'data-severity="ALL"' in content
        assert 'data-severity="HIGH"' in content
        assert 'data-severity="MEDIUM"' in content
        assert 'data-severity="LOW"' in content

        # 4. Result counter & empty state reset
        assert "alerts-count-badge" in content
        assert "filter-reset-btn" in content
        assert "empty-state-row" in content

        # 5. Cumulative Threat Distribution Bar
        assert "threat-distribution-card" in content
        assert "threat-distribution-bar" in content
        assert "dist-bar-scans" in content
        assert "dist-bar-traffic" in content
        assert "dist-bar-empty" in content
        assert "updateThreatDistribution" in content

        # 6. Expandable Detail Inspection Drawer
        assert "createAlertDetailRow" in content
        assert "alert-detail-row" in content
        assert "handleRowToggle" in content
        assert "evidence-box" in content
        assert "data-detail-for" in content

        # 7. Clipboard Copy
        assert "copyToClipboard" in content
        assert "copy-btn" in content

        # 8. Selection protection
        assert "window.getSelection" in content

        # 9. Strict rejection of fabricated/hallucinated fields (e.g. Unicast IPv4)
        assert "Unicast IPv4" not in content, "Found banned 'Unicast IPv4' field in dashboard/index.html!"
        assert "Vector: Unicast IPv4" not in content

        # 10. Strict XSS prevention: verify zero innerHTML, insertAdjacentHTML, document.write, or eval
        assert "innerHTML" not in content
        assert "insertAdjacentHTML" not in content
        assert "document.write" not in content
        assert "eval(" not in content

    def test_security_headers_present_on_all_responses(self, client):
        """Verify defensive HTTP security headers including CSP and Permissions-Policy are injected into all HTTP responses."""
        endpoints = ["/", "/health", "/api/health", "/api/alerts", "/api/stats"]
        expected_csp_parts = [
            "default-src 'none'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "connect-src 'self' http://127.0.0.1:5000",
            "img-src 'self' data:",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ]
        expected_perm_parts = [
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
            response = client.get(ep)
            assert response.headers.get("X-Content-Type-Options") == "nosniff", f"Missing nosniff on {ep}"
            assert response.headers.get("X-Frame-Options") == "SAMEORIGIN", f"Missing SAMEORIGIN on {ep}"
            assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin", (
                f"Missing Referrer-Policy on {ep}"
            )
            assert response.headers.get("X-XSS-Protection") == "1; mode=block", f"Missing X-XSS-Protection on {ep}"

            # Content-Security-Policy
            csp = response.headers.get("Content-Security-Policy", "")
            assert csp, f"Missing Content-Security-Policy on {ep}"
            for part in expected_csp_parts:
                assert part in csp, f"Directive '{part}' missing from CSP on {ep}"

            # Permissions-Policy
            perm = response.headers.get("Permissions-Policy", "")
            assert perm, f"Missing Permissions-Policy on {ep}"
            for part in expected_perm_parts:
                assert part in perm, f"Directive '{part}' missing from Permissions-Policy on {ep}"

    def test_dynamic_api_cache_control_headers(self, client):
        """Verify dynamic API and health endpoints forbid client/proxy caching."""
        for ep in ["/api/alerts", "/api/stats", "/health", "/api/health"]:
            response = client.get(ep)
            cache_ctrl = response.headers.get("Cache-Control", "")
            assert "no-store" in cache_ctrl
            assert "no-cache" in cache_ctrl
            assert response.headers.get("Pragma") == "no-cache"

        # Static / root page should not enforce no-store
        root_resp = client.get("/")
        assert "no-store" not in root_resp.headers.get("Cache-Control", "")

    def test_cors_origin_scoping(self, client, monkeypatch):
        """Verify CORS headers are returned for allowed local origins, rejected for Origin: null by default, allowed when opt-in enabled, and omitted for untrusted origins."""
        # Allowed local origin
        resp_allowed = client.get("/api/stats", headers={"Origin": "http://127.0.0.1:5000"})
        assert resp_allowed.headers.get("Access-Control-Allow-Origin") == "http://127.0.0.1:5000"
        assert resp_allowed.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"

        # By default, Origin: null (local file:// / sandboxed iframe) is REJECTED
        for ep in ["/api/stats", "/api/alerts"]:
            resp_null = client.get(ep, headers={"Origin": "null"})
            assert resp_null.status_code == 200
            assert "Access-Control-Allow-Origin" not in resp_null.headers

        # Untrusted origin
        resp_untrusted = client.get("/api/stats", headers={"Origin": "http://attacker.example.com"})
        assert "Access-Control-Allow-Origin" not in resp_untrusted.headers

        # With explicit opt-in (ALLOW_LOCAL_FILE_CORS = True), Origin: null is permitted
        monkeypatch.setattr("backend.api.ALLOW_LOCAL_FILE_CORS", True)
        for ep in ["/api/stats", "/api/alerts"]:
            resp_optin = client.get(ep, headers={"Origin": "null"})
            assert resp_optin.status_code == 200
            assert resp_optin.headers.get("Access-Control-Allow-Origin") == "null"
            assert resp_optin.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"

            resp_preflight = client.open(ep, method="OPTIONS", headers={"Origin": "null"})
            assert resp_preflight.status_code == 204
            assert resp_preflight.headers.get("Access-Control-Allow-Origin") == "null"
            assert resp_preflight.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"

    def test_health_check_endpoint(self, client):
        """Verify /health and /api/health return healthy status and database connectivity."""
        for path in ["/health", "/api/health"]:
            response = client.get(path)
            assert response.status_code == 200
            data = response.get_json()
            assert data["status"] == "healthy"
            assert data["service"] == "SentinelX API"
            assert data["database"] == "connected"
            assert "timestamp" in data

    def test_health_check_unhealthy_when_database_fails(self, client, monkeypatch):
        """Verify health check returns 503 Service Unavailable when DB connection fails."""

        def broken_conn():
            raise RuntimeError("Database unavailable")

        monkeypatch.setattr("backend.api.get_connection", broken_conn)
        response = client.get("/health")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "unhealthy"
        assert data["database"] == "disconnected"

    def test_alerts_default_pagination(self, client):
        """Verify /api/alerts defaults to API_DEFAULT_LIMIT (100) and returns a JSON list."""
        # Insert 110 test alerts
        for i in range(110):
            insert_alert(
                {
                    "timestamp": f"2026-09-11T10:00:{i % 60:02d}",
                    "threat_type": THREAT_TYPE_PORT_SCAN,
                    "severity": "HIGH",
                    "source_ip": f"10.0.0.{i % 255}",
                    "destination_ip": "10.0.0.1",
                    "protocol": "TCP",
                    "message": f"Alert {i}",
                }
            )

        response = client.get("/api/alerts")
        assert response.status_code == 200
        alerts = response.get_json()

        # Contract assertion: MUST be a raw list for dashboard/index.html alerts.forEach
        assert isinstance(alerts, list)
        assert len(alerts) == API_DEFAULT_LIMIT

        # Verify ordering is descending by id (latest first)
        assert alerts[0]["id"] > alerts[1]["id"]
        assert alerts[0]["id"] == 110

    def test_alerts_custom_pagination(self, client):
        """Verify custom limit and offset parameters operate accurately."""
        for i in range(1, 21):
            insert_alert(
                {
                    "timestamp": "2026-09-11T12:00:00",
                    "threat_type": THREAT_TYPE_PORT_SCAN,
                    "severity": "LOW",
                    "source_ip": f"192.168.1.{i}",
                    "destination_ip": "192.168.1.254",
                    "protocol": "TCP",
                    "message": f"Alert {i}",
                }
            )

        # Fetch 5 alerts skipping the first 5 (IDs should be 15, 14, 13, 12, 11)
        response = client.get("/api/alerts?limit=5&offset=5")
        assert response.status_code == 200
        alerts = response.get_json()
        assert len(alerts) == 5
        assert [a["id"] for a in alerts] == [15, 14, 13, 12, 11]

    def test_alerts_filtering_by_threat_type(self, client):
        """Verify filtering by threat_type."""
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:00",
                "threat_type": THREAT_TYPE_PORT_SCAN,
                "severity": "HIGH",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "protocol": "TCP",
                "message": "Scan alert",
            }
        )
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:01",
                "threat_type": THREAT_TYPE_VOLUMETRIC,
                "severity": "HIGH",
                "source_ip": "10.0.0.3",
                "destination_ip": "10.0.0.4",
                "protocol": "UDP",
                "message": "Traffic alert",
            }
        )

        resp_scan = client.get(f"/api/alerts?threat_type={THREAT_TYPE_PORT_SCAN}")
        assert resp_scan.status_code == 200
        scan_alerts = resp_scan.get_json()
        assert len(scan_alerts) == 1
        assert scan_alerts[0]["threat_type"] == THREAT_TYPE_PORT_SCAN

        resp_traffic = client.get(f"/api/alerts?threat_type={THREAT_TYPE_VOLUMETRIC}")
        assert resp_traffic.status_code == 200
        traffic_alerts = resp_traffic.get_json()
        assert len(traffic_alerts) == 1
        assert traffic_alerts[0]["threat_type"] == THREAT_TYPE_VOLUMETRIC

        # Backward compatibility filter check: API accepts legacy HIGH_TRAFFIC query
        resp_legacy = client.get("/api/alerts?threat_type=HIGH_TRAFFIC")
        assert resp_legacy.status_code == 200
        assert len(resp_legacy.get_json()) == 1

    def test_alerts_filtering_by_severity_and_source_ip(self, client):
        """Verify filtering by severity and source_ip."""
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:00",
                "threat_type": THREAT_TYPE_PORT_SCAN,
                "severity": "HIGH",
                "source_ip": "172.16.0.5",
                "destination_ip": "172.16.0.1",
                "protocol": "TCP",
                "message": "High alert",
            }
        )
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:01",
                "threat_type": THREAT_TYPE_PORT_SCAN,
                "severity": "LOW",
                "source_ip": "172.16.0.5",
                "destination_ip": "172.16.0.1",
                "protocol": "TCP",
                "message": "Low alert",
            }
        )
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:02",
                "threat_type": THREAT_TYPE_PORT_SCAN,
                "severity": "HIGH",
                "source_ip": "172.16.0.99",
                "destination_ip": "172.16.0.1",
                "protocol": "TCP",
                "message": "Other IP alert",
            }
        )

        # Filter by source_ip and severity
        resp = client.get("/api/alerts?source_ip=172.16.0.5&severity=HIGH")
        assert resp.status_code == 200
        alerts = resp.get_json()
        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "172.16.0.5"
        assert alerts[0]["severity"] == "HIGH"

    def test_alerts_parameter_validation_errors(self, client):
        """Verify structured 400 Bad Request responses on invalid query parameters."""
        test_cases = [
            ("/api/alerts?limit=-1", "must be between 1 and"),
            ("/api/alerts?limit=0", "must be between 1 and"),
            (f"/api/alerts?limit={API_MAX_LIMIT + 1}", "must be between 1 and"),
            ("/api/alerts?limit=abc", "must be an integer"),
            ("/api/alerts?offset=-5", "cannot be negative"),
            ("/api/alerts?offset=xyz", "must be an integer"),
            ("/api/alerts?threat_type=SQL_INJECTION", "must be one of"),
            ("/api/alerts?severity=SUPER_HIGH", "must be 'HIGH', 'MEDIUM', or 'LOW'"),
        ]

        for query, expected_snippet in test_cases:
            response = client.get(query)
            assert response.status_code == 400, f"Expected 400 for {query}"
            data = response.get_json()
            assert data["error"] == "Bad Request"
            assert data["status"] == 400
            assert expected_snippet in data["message"]

    def test_stats_atomic_aggregation(self, client):
        """Verify /api/stats returns accurate metrics computed via a single atomic SQL query."""
        # Insert 3 HIGH PORT_SCAN
        for _ in range(3):
            insert_alert(
                {
                    "timestamp": "2026-09-11T12:00:00",
                    "threat_type": THREAT_TYPE_PORT_SCAN,
                    "severity": "HIGH",
                    "source_ip": "192.168.1.10",
                    "destination_ip": "192.168.1.1",
                    "protocol": "TCP",
                    "message": "Port scan high",
                }
            )

        # Insert 2 LOW PORT_SCAN
        for _ in range(2):
            insert_alert(
                {
                    "timestamp": "2026-09-11T12:00:00",
                    "threat_type": THREAT_TYPE_PORT_SCAN,
                    "severity": "LOW",
                    "source_ip": "192.168.1.11",
                    "destination_ip": "192.168.1.1",
                    "protocol": "TCP",
                    "message": "Port scan low",
                }
            )

        # Insert 4 HIGH VOLUMETRIC
        for _ in range(4):
            insert_alert(
                {
                    "timestamp": "2026-09-11T12:00:00",
                    "threat_type": THREAT_TYPE_VOLUMETRIC,
                    "severity": "HIGH",
                    "source_ip": "192.168.1.12",
                    "destination_ip": "192.168.1.1",
                    "protocol": "UDP",
                    "message": "High traffic high",
                }
            )

        # Insert 1 MEDIUM VOLUMETRIC
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:00",
                "threat_type": THREAT_TYPE_VOLUMETRIC,
                "severity": "MEDIUM",
                "source_ip": "192.168.1.13",
                "destination_ip": "192.168.1.1",
                "protocol": "UDP",
                "message": "High traffic med",
            }
        )

        response = client.get("/api/stats")
        assert response.status_code == 200
        stats = response.get_json()

        # Contract assertion: exact keys and integer types
        assert stats["total_alerts"] == 10
        assert stats["high_severity"] == 7  # 3 port scan + 4 high traffic
        assert stats["port_scans"] == 5  # 3 high + 2 low
        assert stats["high_traffic"] == 5  # 4 high + 1 med
        for k in ["total_alerts", "high_severity", "port_scans", "high_traffic"]:
            assert isinstance(stats[k], int)

    def test_empty_database_handling(self, client):
        """Verify API handles an empty database gracefully without null/None crashes."""
        resp_alerts = client.get("/api/alerts")
        assert resp_alerts.status_code == 200
        assert resp_alerts.get_json() == []

        resp_stats = client.get("/api/stats")
        assert resp_stats.status_code == 200
        stats = resp_stats.get_json()
        assert stats == {
            "total_alerts": 0,
            "high_severity": 0,
            "port_scans": 0,
            "syn_floods": 0,
            "volumetric": 0,
            "high_traffic": 0,
        }

    def test_standardized_error_handlers(self, client):
        """Verify 404 and 405 error handlers return structured JSON envelopes."""
        # 404 Not Found
        resp_404 = client.get("/nonexistent-endpoint-path")
        assert resp_404.status_code == 404
        data_404 = resp_404.get_json()
        assert data_404["error"] == "Not Found"
        assert data_404["status"] == 404
        assert "not found" in data_404["message"].lower()

        # 405 Method Not Allowed
        resp_405 = client.post("/health")
        assert resp_405.status_code == 405
        data_405 = resp_405.get_json()
        assert data_405["error"] == "Method Not Allowed"
        assert data_405["status"] == 405
        assert "not allowed" in data_405["message"].lower()

    def test_concurrent_api_requests(self, client):
        """Verify concurrent API requests and DB operations execute safely under SQLite WAL mode."""
        # Seed 10 alerts
        for i in range(10):
            insert_alert(
                {
                    "timestamp": "2026-09-11T12:00:00",
                    "threat_type": THREAT_TYPE_PORT_SCAN,
                    "severity": "HIGH",
                    "source_ip": f"10.1.1.{i}",
                    "destination_ip": "10.1.1.254",
                    "protocol": "TCP",
                    "message": f"Concurrent seed {i}",
                }
            )

        def request_worker(task_id):
            c = app.test_client()
            if task_id % 3 == 0:
                resp = c.get("/api/alerts")
            elif task_id % 3 == 1:
                resp = c.get("/api/stats")
            else:
                resp = c.get("/health")
            return resp.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(request_worker, i) for i in range(40)]
            results = [f.result() for f in futures]

        assert all(code == 200 for code in results)
