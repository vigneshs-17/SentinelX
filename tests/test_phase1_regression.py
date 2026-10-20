import hashlib
import os
from pathlib import Path

from backend.api import app
from config.settings import (
    CANONICAL_THREAT_TYPES,
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_VOLUMETRIC,
)
from database.database import (
    get_connection,
    insert_alert,
)
from logs.alert_logger import log_alert

PROD_DB_FILE = Path(__file__).resolve().parent.parent / "database" / "sentinelx.db"
PROD_ALERT_FILE = Path(__file__).resolve().parent.parent / "logs" / "alerts.json"


def get_file_sha256(filepath):
    if not filepath.exists():
        return None
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestPhase1Regression:
    """Regression test suite for Phase 1 Critical Fixes."""

    def test_production_db_and_json_never_contaminated(self):
        """Verify tests run against isolated storage and never mutate production files."""
        # Record initial hashes of production files
        initial_db_hash = get_file_sha256(PROD_DB_FILE)
        initial_alert_hash = get_file_sha256(PROD_ALERT_FILE)

        # Ensure our test environment is pointing to a temporary location
        db_env = os.getenv("SENTINELX_DB_PATH")
        alert_env = os.getenv("SENTINELX_ALERT_LOG")
        assert db_env is not None and "test_sentinelx.db" in db_env
        assert alert_env is not None and "test_alerts.json" in alert_env

        # Execute test inserts and logging
        for i in range(5):
            alert = {
                "threat_type": THREAT_TYPE_PORT_SCAN,
                "severity": "HIGH",
                "source_ip": f"10.0.0.{i}",
                "destination_ip": "10.0.0.254",
                "protocol": "TCP",
                "message": f"Test alert {i}",
            }
            log_alert(alert)

        # Verify production hashes are 100% unchanged
        final_db_hash = get_file_sha256(PROD_DB_FILE)
        final_alert_hash = get_file_sha256(PROD_ALERT_FILE)

        assert final_db_hash == initial_db_hash, "Production sentinelx.db was contaminated by test!"
        assert final_alert_hash == initial_alert_hash, "Production alerts.json was contaminated by test!"

    def test_sqlite_wal_mode_enabled(self):
        """Verify SQLite connections enable WAL journal mode and normal synchronous mode."""
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA journal_mode;")
        journal_mode = cursor.fetchone()[0].lower()

        cursor.execute("PRAGMA synchronous;")
        sync_mode = cursor.fetchone()[0]

        conn.close()

        assert journal_mode == "wal", f"Expected WAL mode, got {journal_mode}"
        # SQLite PRAGMA synchronous NORMAL is integer 1
        assert sync_mode in (1, "1", "NORMAL", "normal"), f"Expected NORMAL synchronous mode, got {sync_mode}"

    def test_canonical_threat_types_and_stats_api(self):
        """Verify threat statistics query canonical threat types accurately without phantom types."""
        # Insert known test records into the isolated database
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:00",
                "threat_type": THREAT_TYPE_PORT_SCAN,
                "severity": "HIGH",
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.1",
                "protocol": "TCP",
                "message": "Port scan 1",
            }
        )
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:01",
                "threat_type": THREAT_TYPE_PORT_SCAN,
                "severity": "LOW",
                "source_ip": "192.168.1.51",
                "destination_ip": "192.168.1.1",
                "protocol": "TCP",
                "message": "Port scan 2",
            }
        )
        insert_alert(
            {
                "timestamp": "2026-09-11T12:00:02",
                "threat_type": THREAT_TYPE_VOLUMETRIC,
                "severity": "HIGH",
                "source_ip": "192.168.1.60",
                "destination_ip": "192.168.1.1",
                "protocol": "UDP",
                "message": "High traffic 1",
            }
        )

        client = app.test_client()
        response = client.get("/api/stats")
        assert response.status_code == 200
        stats = response.get_json()

        assert stats["total_alerts"] == 3
        assert stats["high_severity"] == 2
        assert stats["port_scans"] == 2
        assert stats["high_traffic"] == 1

        # Verify CANONICAL_THREAT_TYPES
        assert THREAT_TYPE_PORT_SCAN in CANONICAL_THREAT_TYPES
        assert THREAT_TYPE_VOLUMETRIC in CANONICAL_THREAT_TYPES
        assert "ML_PORT_SCAN" not in CANONICAL_THREAT_TYPES
        assert "ML_HIGH_TRAFFIC" not in CANONICAL_THREAT_TYPES

    def test_dashboard_xss_protection_source_code(self):
        """Verify dashboard/index.html uses textContent and createElement instead of unsafe innerHTML for alert rendering."""
        dashboard_html_path = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
        assert dashboard_html_path.exists()

        content = dashboard_html_path.read_text(encoding="utf-8")

        # Must not have innerHTML inside alerts.forEach
        assert "row.innerHTML =" not in content, "Found unsafe row.innerHTML in dashboard/index.html!"
        # Must have textContent assignments
        assert "cell.textContent =" in content, "Expected cell.textContent assignment for safe DOM rendering"

    def test_stored_xss_payload_safety_in_api(self):
        """Verify XSS vectors stored in database are cleanly returned as JSON and not executable markup."""
        xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
        alert_record = {
            "timestamp": "2026-09-11T12:00:00",
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "severity": "HIGH",
            "source_ip": xss_payload,
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "message": f"Attack payload: {xss_payload}",
        }
        insert_alert(alert_record)

        client = app.test_client()
        response = client.get("/api/alerts")
        assert response.status_code == 200
        alerts = response.get_json()

        matching = [a for a in alerts if a["source_ip"] == xss_payload]
        assert len(matching) == 1
        # When served via JSON, the payload remains plain text data
        assert matching[0]["source_ip"] == xss_payload

    def test_utf8_encoding_integrity(self):
        """Verify UTF-8 encoding across requirements, json logs, and database with Unicode characters."""
        req_file = Path(__file__).resolve().parent.parent / "requirements.txt"
        content = req_file.read_text(encoding="utf-8")
        assert "Flask==" in content
        assert "Werkzeug==" in content

        req_dev_file = Path(__file__).resolve().parent.parent / "requirements-dev.txt"
        dev_content = req_dev_file.read_text(encoding="utf-8")
        assert "pytest==" in dev_content

        # Verify Unicode text can be inserted and retrieved from SQLite and alert logger without crash
        unicode_message = "Alerte de sécurité: Détection d'anomalie réseau 🛡️ (port scan)"
        unicode_alert = {
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "severity": "HIGH",
            "source_ip": "192.168.1.99",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "message": unicode_message,
        }
        saved = log_alert(unicode_alert)
        assert saved["message"] == unicode_message

        # Verify it reads back from the isolated JSON file cleanly
        from logs.alert_logger import read_alerts

        data = read_alerts()
        assert any(item.get("message") == unicode_message for item in data)
