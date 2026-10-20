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
from tests.support import authed_client


@pytest.fixture
def client():
    """Flask test client fixture."""
    app.config["TESTING"] = True
    return authed_client(app)


class TestBackendApi:
    """Phase 5 API Hardening and Production Architecture test suite."""

    def test_home_serves_html(self, client):
        """Verify root endpoint serves the single-page dashboard HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.content_type
        html_content = response.get_data(as_text=True)
        assert "SentinelX" in html_content
        assert '<main id="main"' in html_content and "/static/js/main.js" in html_content

    def test_health_check_endpoint(self, client):
        """Verify /health returns healthy status and database connectivity."""
        for path in ["/health"]:
            response = client.get(path)
            assert response.status_code == 200
            data = response.get_json()
            assert data["status"] == "healthy"
            assert data["service"] == "SentinelX API"
            assert data["database"] == "readable"
            assert "timestamp" in data

    def test_health_check_unhealthy_when_database_fails(self, client, monkeypatch):
        """Verify health check returns 503 Service Unavailable when DB connection fails."""

        def broken_conn():
            raise RuntimeError("Database unavailable")

        monkeypatch.setattr("backend.api.get_readonly_connection", broken_conn)
        response = client.get("/health")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "degraded"
        assert data["database"] == "unreadable"

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

        response = client.get("/api/v1/alerts")
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
        response = client.get("/api/v1/alerts?limit=5&offset=5")
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

        resp_scan = client.get(f"/api/v1/alerts?threat_type={THREAT_TYPE_PORT_SCAN}")
        assert resp_scan.status_code == 200
        scan_alerts = resp_scan.get_json()
        assert len(scan_alerts) == 1
        assert scan_alerts[0]["threat_type"] == THREAT_TYPE_PORT_SCAN

        resp_traffic = client.get(f"/api/v1/alerts?threat_type={THREAT_TYPE_VOLUMETRIC}")
        assert resp_traffic.status_code == 200
        traffic_alerts = resp_traffic.get_json()
        assert len(traffic_alerts) == 1
        assert traffic_alerts[0]["threat_type"] == THREAT_TYPE_VOLUMETRIC

        # Backward compatibility filter check: API accepts legacy HIGH_TRAFFIC query
        resp_legacy = client.get("/api/v1/alerts?threat_type=HIGH_TRAFFIC")
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
        resp = client.get("/api/v1/alerts?source_ip=172.16.0.5&severity=HIGH")
        assert resp.status_code == 200
        alerts = resp.get_json()
        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == "172.16.0.5"
        assert alerts[0]["severity"] == "HIGH"

    def test_alerts_parameter_validation_errors(self, client):
        """Verify structured 400 Bad Request responses on invalid query parameters."""
        test_cases = [
            ("/api/v1/alerts?limit=-1", "must be between 1 and"),
            ("/api/v1/alerts?limit=0", "must be between 1 and"),
            (f"/api/v1/alerts?limit={API_MAX_LIMIT + 1}", "must be between 1 and"),
            ("/api/v1/alerts?limit=abc", "must be an integer"),
            ("/api/v1/alerts?offset=-5", "must be between 0 and"),
            ("/api/v1/alerts?offset=xyz", "must be an integer"),
            ("/api/v1/alerts?threat_type=SQL_INJECTION", "must be one of"),
            ("/api/v1/alerts?severity=SUPER_HIGH", "must be 'HIGH', 'MEDIUM', or 'LOW'"),
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

        response = client.get("/api/v1/stats")
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
        resp_alerts = client.get("/api/v1/alerts")
        assert resp_alerts.status_code == 200
        assert resp_alerts.get_json() == []

        resp_stats = client.get("/api/v1/stats")
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
            c = authed_client(app)
            if task_id % 3 == 0:
                resp = c.get("/api/v1/alerts")
            elif task_id % 3 == 1:
                resp = c.get("/api/v1/stats")
            else:
                resp = c.get("/health")
            return resp.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(request_worker, i) for i in range(40)]
            results = [f.result() for f in futures]

        assert all(code == 200 for code in results)
