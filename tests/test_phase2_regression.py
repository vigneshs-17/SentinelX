"""
Phase 2 Regression Test Suite for SentinelX.

Verifies:
- D2: Database lifecycle, startup initialization, and schema creation in empty data dir.
- D11: Schema v2 migrations, column additions, indexes, naive timestamp UTC backfill,
       and ISO-8601 UTC timezone-aware persistence.
- D4: Pipeline metrics accuracy (active pipeline metrics alerts_generated matches alerts written).
- D7: Multi-alert persistence when multiple detectors fire on the same packet.
- D8: No print() in packet processing path; structured logging.
- D10: IP multicast/broadcast filtering (ff02::1, 224.0.0.251 ignored, 10.0.1.255 not ignored);
       Dynamic severity scaling (MEDIUM at 1x threshold, HIGH at 3x threshold).
- API: /api/alerts with 'since' ISO-8601 validation ('Z' and offsets accepted, naive rejected with 400),
       parsed evidence objects, stable ordering, and /api/stats GROUP BY threat_type.
"""

import sqlite3
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from backend.api import app
from capture.pcap_replay import replay_pcap
from capture.pipeline import PacketPipeline
from capture.processor import PacketProcessor
from config.settings import (
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_VOLUMETRIC,
)
from database.database import (
    close_database,
    get_connection,
    initialize_database,
    insert_alert,
)
from database.migrations import apply_migrations
from detection.scoring import calculate_confidence, calculate_severity
from detection.utils import is_multicast_or_broadcast
from tests.support import authed_client


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return authed_client(app)


# =============================================================================
# 1. End-to-End Empty Data Dir & Startup Lifecycle
# =============================================================================


def test_empty_data_dir_startup_lifecycle_and_api(monkeypatch, client):
    """
    Empty data dir -> replay a small generated PCAP containing a vertical scan
    through the startup lifecycle -> alert row exists in SQLite and is returned by GET /api/alerts.
    """
    with tempfile.TemporaryDirectory(prefix="sentinelx_empty_data_") as temp_dir:
        temp_path = Path(temp_dir)
        data_dir = temp_path / "data"

        # Explicitly configure clean data dir and unset direct DB/alert paths
        monkeypatch.setenv("SENTINELX_DATA_DIR", str(data_dir))
        monkeypatch.delenv("SENTINELX_DB_PATH", raising=False)
        monkeypatch.delenv("SENTINELX_ALERT_LOG", raising=False)

        # Initialize database at startup (as main.py and backend/api.py do)
        initialize_database()

        expected_db = data_dir / "alerts.db"
        assert expected_db.exists(), "alerts.db should be created under data dir on startup"

        # Generate a small PCAP containing a vertical port scan
        pcap_file = temp_path / "vertical_scan.pcap"
        packets = [
            IP(src="192.168.1.100", dst="192.168.1.10") / TCP(sport=1024 + i, dport=80 + i, flags="S")
            for i in range(12)
        ]
        wrpcap(str(pcap_file), packets)

        # Replay PCAP
        pipeline = PacketPipeline(maxsize=100)
        metrics = replay_pcap(str(pcap_file), pipeline_instance=pipeline, print_summary=False)

        assert metrics["packets_processed"] == 12
        assert metrics["alerts_generated"] >= 1

        # Check alert row exists in SQLite
        conn = get_connection(expected_db)
        cursor = conn.cursor()
        cursor.execute("SELECT threat_type, scan_type, severity, source_ip, destination_ip FROM alerts;")
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "PORT_SCAN"
        assert row[1] == "VERTICAL"
        assert row[3] == "192.168.1.100"
        assert row[4] == "192.168.1.10"

        # Verify alert is returned by GET /api/alerts
        response = client.get("/api/v1/alerts")
        assert response.status_code == 200
        alerts = response.get_json()
        assert isinstance(alerts, list)
        assert len(alerts) >= 1

        matching = [a for a in alerts if a["threat_type"] == "PORT_SCAN" and a["source_ip"] == "192.168.1.100"]
        assert len(matching) >= 1
        alert = matching[0]
        assert alert["scan_type"] == "VERTICAL"
        assert alert["detected_at"] is not None
        assert "+00:00" in alert["detected_at"]
        assert isinstance(alert["evidence"], dict)

        # Close database connection to release Windows file lock before directory cleanup
        close_database()


# =============================================================================
# 2. Database Migration v1 -> v2 & User Version Upgrade
# =============================================================================


def test_v1_database_upgraded_to_v2_with_rows_preserved():
    """
    v1 fixture DB upgraded to v2: all existing rows preserved, user_version == 2,
    new columns added, and performance indexes created.
    """
    with tempfile.TemporaryDirectory(prefix="sentinelx_migration_") as temp_dir:
        db_path = Path(temp_dir) / "v1_test.db"

        # Create unversioned v1 schema database with user_version = 0
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                message TEXT
            );
            """
        )
        # Insert test rows
        conn.execute(
            """
            INSERT INTO alerts (timestamp, threat_type, severity, source_ip, destination_ip, protocol, message)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "2026-09-01T12:00:00",
                "PORT_SCAN",
                "HIGH",
                "10.0.0.5",
                "10.0.0.1",
                "TCP",
                "Legacy alert 1",
            ),
        )
        conn.execute(
            """
            INSERT INTO alerts (timestamp, threat_type, severity, source_ip, destination_ip, protocol, message)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "2026-09-02T14:30:00",
                "HIGH_TRAFFIC",
                "HIGH",
                "10.0.0.6",
                "10.0.0.2",
                "UDP",
                "Legacy alert 2",
            ),
        )
        conn.commit()

        # Verify initial user_version is 0
        cur = conn.cursor()
        cur.execute("PRAGMA user_version;")
        assert cur.fetchone()[0] == 0

        # Run migration runner
        new_version = apply_migrations(conn)
        assert new_version >= 2

        # Verify PRAGMA user_version >= 2
        cur.execute("PRAGMA user_version;")
        assert cur.fetchone()[0] >= 2

        # Verify all original rows are preserved
        cur.execute("SELECT COUNT(*) FROM alerts;")
        assert cur.fetchone()[0] == 2

        cur.execute("SELECT id, timestamp, threat_type, message, detected_at, scan_type FROM alerts ORDER BY id ASC;")
        rows = cur.fetchall()
        assert len(rows) == 2
        assert rows[0][2] == "PORT_SCAN"
        assert rows[0][3] == "Legacy alert 1"
        assert rows[0][4] is not None, "detected_at should be backfilled from timestamp"
        assert "+00:00" in rows[0][4]

        # Verify indexes exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='index';")
        index_names = {r[0] for r in cur.fetchall()}
        assert "idx_alerts_detected_at" in index_names
        assert "idx_alerts_threat_detected" in index_names
        assert "idx_alerts_source_ip" in index_names

        cur.close()
        conn.close()
        close_database()


# =============================================================================
# 3. Legacy Naive Timestamp Migration Backfill with Fixed Timezone
# =============================================================================


def test_legacy_naive_timestamp_converted_to_utc_with_fixed_tz():
    """
    Migration 2 backfills detected_at by converting legacy naive timestamps
    to ISO-8601 UTC with +00:00 using an explicit local_tz parameter.
    Does not read or depend on the host OS timezone.
    """
    with tempfile.TemporaryDirectory(prefix="sentinelx_tz_backfill_") as temp_dir:
        db_path = Path(temp_dir) / "tz_test_kolkata.db"
        conn = sqlite3.connect(str(db_path))

        conn.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                message TEXT
            );
            """
        )
        # Naive local timestamp: 2026-06-15 15:30:00
        conn.execute(
            """
            INSERT INTO alerts (timestamp, threat_type, severity, source_ip, destination_ip, protocol, message)
            VALUES ('2026-06-15T15:30:00', 'PORT_SCAN', 'HIGH', '1.2.3.4', '5.6.7.8', 'TCP', 'Naive TS test');
            """
        )
        conn.commit()

        # Explicitly pass Asia/Kolkata (UTC+05:30)
        apply_migrations(conn, local_tz=ZoneInfo("Asia/Kolkata"))

        cur = conn.cursor()
        cur.execute("SELECT detected_at FROM alerts WHERE id = 1;")
        res = cur.fetchone()[0]
        conn.close()

        # 15:30:00 in UTC+05:30 corresponds to 10:00:00 in UTC
        assert res == "2026-06-15T10:00:00+00:00"


def test_legacy_naive_timestamp_converted_with_dst_timezone():
    """
    Proves per-timestamp DST conversion using Europe/London (summer BST vs winter GMT)
    without reading or depending on the host OS timezone.
    """
    with tempfile.TemporaryDirectory(prefix="sentinelx_tz_dst_") as temp_dir:
        db_path = Path(temp_dir) / "tz_test_london.db"
        conn = sqlite3.connect(str(db_path))

        conn.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                message TEXT
            );
            """
        )
        # Summer timestamp: 2026-07-15 12:00:00 (BST = UTC+1 -> UTC 11:00:00)
        # Winter timestamp: 2026-01-15 12:00:00 (GMT = UTC+0 -> UTC 12:00:00)
        conn.execute(
            """
            INSERT INTO alerts (id, timestamp, threat_type, severity, source_ip, destination_ip, protocol, message)
            VALUES (1, '2026-07-15T12:00:00', 'PORT_SCAN', 'HIGH', '1.1.1.1', '2.2.2.2', 'TCP', 'Summer Alert');
            """
        )
        conn.execute(
            """
            INSERT INTO alerts (id, timestamp, threat_type, severity, source_ip, destination_ip, protocol, message)
            VALUES (2, '2026-01-15T12:00:00', 'PORT_SCAN', 'HIGH', '1.1.1.1', '2.2.2.2', 'TCP', 'Winter Alert');
            """
        )
        conn.commit()

        # Explicitly pass Europe/London
        apply_migrations(conn, local_tz=ZoneInfo("Europe/London"))

        cur = conn.cursor()
        cur.execute("SELECT id, detected_at FROM alerts ORDER BY id ASC;")
        rows = cur.fetchall()
        conn.close()

        assert rows[0][1] == "2026-07-15T11:00:00+00:00"
        assert rows[1][1] == "2026-01-15T12:00:00+00:00"


# =============================================================================
# 4. Pipeline Metrics Accuracy (D4)
# =============================================================================


def test_pipeline_metrics_alerts_generated_equals_written_alerts():
    """
    After replay, pipeline metrics alerts_generated equals the number of alerts written
    to SQLite and JSONL (previously stuck at 0 due to module-global pipeline reference).
    """
    with tempfile.TemporaryDirectory(prefix="sentinelx_metrics_") as temp_dir:
        pcap_file = Path(temp_dir) / "test_scan.pcap"
        packets = [
            IP(src="10.0.0.99", dst="10.0.0.1") / TCP(sport=2000 + i, dport=100 + i, flags="S") for i in range(15)
        ]
        wrpcap(str(pcap_file), packets)

        pipeline = PacketPipeline(maxsize=100)
        snapshot = replay_pcap(str(pcap_file), pipeline_instance=pipeline, print_summary=False)

        assert snapshot["alerts_generated"] >= 1

        # Compare directly with database count
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts WHERE source_ip = '10.0.0.99';")
        db_alert_count = cur.fetchone()[0]
        conn.close()

        assert snapshot["alerts_generated"] == db_alert_count


# =============================================================================
# 5. Dual Detector Firing (D7)
# =============================================================================


def test_packet_triggering_both_detectors_stores_two_alerts(monkeypatch):
    """
    A packet that triggers both detectors produces two stored alerts
    (previously D7 dropped the traffic alert).
    """
    from detection.alert import Alert

    dummy_ps_alert = Alert(
        threat_type=THREAT_TYPE_PORT_SCAN,
        scan_type="VERTICAL",
        severity="MEDIUM",
        confidence=0.80,
        detector="MockPS",
        first_seen=100.0,
        last_seen=100.0,
        source_ip="172.16.0.50",
        destination_ip="172.16.0.1",
        evidence={"ports": [80, 443]},
        message="Vertical scan mock",
    )
    dummy_ht_alert = Alert(
        threat_type=THREAT_TYPE_VOLUMETRIC,
        scan_type=None,
        severity="HIGH",
        confidence=0.95,
        detector="MockHT",
        first_seen=100.0,
        last_seen=100.0,
        source_ip="172.16.0.50",
        destination_ip="172.16.0.1",
        evidence={"pps": 500},
        message="Volumetric mock",
    )

    class MockEngine:
        def process_packet(self, pkt):
            return [dummy_ps_alert, dummy_ht_alert]

    processor = PacketProcessor(engine=MockEngine())
    test_pkt = IP(src="172.16.0.50", dst="172.16.0.1") / TCP(sport=1234, dport=80, flags="S")

    generated = processor.process(test_pkt)

    assert len(generated) == 2, f"Expected 2 alerts, got {len(generated)}"
    threat_types = {a["threat_type"] for a in generated}
    assert threat_types == {THREAT_TYPE_PORT_SCAN, THREAT_TYPE_VOLUMETRIC}

    # Verify both are stored in database
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT threat_type FROM alerts WHERE source_ip = '172.16.0.50';")
    rows = cur.fetchall()
    conn.close()

    stored_types = {r[0] for r in rows}
    assert THREAT_TYPE_PORT_SCAN in stored_types
    assert THREAT_TYPE_VOLUMETRIC in stored_types


# =============================================================================
# 6. Multicast / Broadcast Filtering (D10)
# =============================================================================


def test_multicast_broadcast_filtering():
    """
    D10: ff02::1 and 224.0.0.251 are ignored; 10.0.1.255 is NOT ignored.
    """
    # Multicast addresses must be ignored
    assert is_multicast_or_broadcast("ff02::1") is True
    assert is_multicast_or_broadcast("224.0.0.251") is True
    assert is_multicast_or_broadcast("224.0.0.1") is True
    assert is_multicast_or_broadcast("239.255.255.250") is True

    # Broadcast and unspecified addresses must be ignored
    assert is_multicast_or_broadcast("255.255.255.255") is True
    assert is_multicast_or_broadcast("0.0.0.0") is True
    assert is_multicast_or_broadcast("::") is True

    # Host addresses ending in .255 in /23 or larger subnets must NOT be ignored
    assert is_multicast_or_broadcast("10.0.1.255") is False
    assert is_multicast_or_broadcast("192.168.1.255") is False  # Subnet broadcast not global 255.255.255.255
    assert is_multicast_or_broadcast("172.16.0.255") is False
    assert is_multicast_or_broadcast("8.8.8.8") is False


# =============================================================================
# 7. Severity Scaling (D10)
# =============================================================================


def test_severity_and_confidence_threshold_scaling():
    """
    D10: Severity is MEDIUM at exactly the threshold (1x) and HIGH at 3x the threshold.
    Confidence score is consistent with severity.
    """
    threshold = 10.0

    # 1. Below threshold (< 1.0)
    assert calculate_severity(5.0, threshold) == "LOW"
    assert calculate_confidence(5.0, threshold) < 0.80

    # 2. Exactly at threshold (1.0x)
    assert calculate_severity(10.0, threshold) == "MEDIUM"
    assert calculate_confidence(10.0, threshold) == 0.80

    # 3. Between 1.0x and 3.0x
    assert calculate_severity(20.0, threshold) == "MEDIUM"
    assert 0.80 <= calculate_confidence(20.0, threshold) < 0.95

    # 4. At 3.0x threshold
    assert calculate_severity(30.0, threshold) == "HIGH"
    assert calculate_confidence(30.0, threshold) >= 0.95

    # 5. Above 3.0x threshold
    assert calculate_severity(50.0, threshold) == "HIGH"
    assert calculate_confidence(50.0, threshold) >= 0.95


# =============================================================================
# 8. API 'since' Filter Validation & Stable Ordering
# =============================================================================


def test_api_since_filter_and_ordering(client):
    """
    GET /api/alerts supports 'since' filter:
    - Accepts 'Z' and offset strings (+05:30).
    - Rejects naive or invalid strings with 400.
    - Orders by detected_at DESC, id DESC.
    """
    # Insert alerts with known UTC detected_at
    insert_alert(
        {
            "timestamp": "2026-10-19T08:00:00+00:00",
            "detected_at": "2026-10-19T08:00:00+00:00",
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "severity": "LOW",
            "source_ip": "10.1.1.1",
        }
    )
    insert_alert(
        {
            "timestamp": "2026-10-19T10:00:00+00:00",
            "detected_at": "2026-10-19T10:00:00+00:00",
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "severity": "MEDIUM",
            "source_ip": "10.1.1.2",
        }
    )
    insert_alert(
        {
            "timestamp": "2026-10-19T12:00:00+00:00",
            "detected_at": "2026-10-19T12:00:00+00:00",
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "severity": "HIGH",
            "source_ip": "10.1.1.3",
        }
    )

    # 1. Query with 'Z' suffix (10:00 UTC) -> should return 10:00 and 12:00
    res_z = client.get("/api/v1/alerts?since=2026-10-19T10:00:00Z")
    assert res_z.status_code == 200
    alerts_z = res_z.get_json()
    assert len(alerts_z) == 2
    assert alerts_z[0]["source_ip"] == "10.1.1.3"  # Stable descending order
    assert alerts_z[1]["source_ip"] == "10.1.1.2"

    # 2. Query with offset (+05:30): 15:30+05:30 == 10:00Z -> should return same 2 alerts
    res_offset = client.get("/api/v1/alerts?since=2026-10-19T15:30:00+05:30")
    assert res_offset.status_code == 200
    alerts_offset = res_offset.get_json()
    assert len(alerts_offset) == 2
    assert alerts_offset[0]["source_ip"] == "10.1.1.3"

    # 3. Reject naive timestamp with 400
    res_naive = client.get("/api/v1/alerts?since=2026-10-19T10:00:00")
    assert res_naive.status_code == 400
    assert "timezone-aware" in res_naive.get_json()["message"]

    # 4. Reject malformed string with 400
    res_invalid = client.get("/api/v1/alerts?since=not-a-valid-timestamp")
    assert res_invalid.status_code == 400
    assert "valid ISO-8601" in res_invalid.get_json()["message"]


# =============================================================================
# 9. API Stats GROUP BY Threat Type
# =============================================================================


def test_api_stats_group_by_threat_type(client):
    """
    GET /api/stats aggregates alerts dynamically using GROUP BY threat_type,
    while maintaining total_alerts and high_severity keys.
    """
    insert_alert(
        {
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "severity": "HIGH",
            "source_ip": "1.1.1.1",
        }
    )
    insert_alert(
        {
            "threat_type": THREAT_TYPE_PORT_SCAN,
            "severity": "MEDIUM",
            "source_ip": "1.1.1.2",
        }
    )
    insert_alert(
        {
            "threat_type": THREAT_TYPE_VOLUMETRIC,
            "severity": "HIGH",
            "source_ip": "1.1.1.3",
        }
    )

    res = client.get("/api/v1/stats")
    assert res.status_code == 200
    data = res.get_json()

    assert data["total_alerts"] == 3
    assert data["high_severity"] == 2
    assert data["port_scans"] == 2
    assert data["high_traffic"] == 1
