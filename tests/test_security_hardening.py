import hashlib
import json
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.all import ARP, IP, TCP, UDP, Ether, IPv6

from capture.packet_parser import parse_packet
from config.settings import ALLOW_LOCAL_FILE_CORS, CORS_ALLOWED_ORIGINS
from logs.alert_logger import (
    log_alert,
    read_alerts,
)
from ml.predictor import (
    MODEL_PATH,
    ModelIntegrityError,
    calculate_model_sha256,
    get_model,
    verify_model_integrity,
)


@pytest.fixture
def temp_dir():
    """Windows-safe temporary directory fixture avoiding pytest-of-user permission collisions."""
    with tempfile.TemporaryDirectory(prefix="sentinelx_sec_") as d:
        yield Path(d)


# =============================================================================
# 1. P0 — ML Model Integrity Verification Tests
# =============================================================================


class TestMLModelIntegrity:
    """Tests for cryptographic checksum verification of ML models."""

    def test_production_model_sha256_matches_metadata(self):
        """Verify the production sentinelx_model.pkl matches model_metadata.json."""
        meta_path = MODEL_PATH.parent / "model_metadata.json"
        assert meta_path.exists(), "model_metadata.json must exist"
        with open(meta_path, encoding="utf-8") as f:
            metadata = json.load(f)

        expected_hash = metadata.get("model_sha256")
        assert expected_hash is not None, "metadata must contain model_sha256"
        actual_hash = calculate_model_sha256(MODEL_PATH)
        assert actual_hash.lower() == expected_hash.lower()

        # verify_model_integrity should succeed without error
        verified = verify_model_integrity(MODEL_PATH)
        assert verified == expected_hash.lower()

    def test_tampered_model_raises_integrity_error(self, temp_dir):
        """Verify that any bit alteration in the model file raises ModelIntegrityError."""
        fake_model = temp_dir / "tampered_model.pkl"
        fake_meta = temp_dir / "model_metadata.json"

        fake_model.write_bytes(b"LEGITIMATE_MODEL_CONTENT_12345")
        correct_hash = hashlib.sha256(b"LEGITIMATE_MODEL_CONTENT_12345").hexdigest()
        fake_meta.write_text(json.dumps({"model_sha256": correct_hash}), encoding="utf-8")

        # Verify legitimate state passes
        assert verify_model_integrity(fake_model, fake_meta) == correct_hash

        # Tamper with the model file
        fake_model.write_bytes(b"TAMPERED_MALICIOUS_PAYLOAD_67890")

        with pytest.raises(ModelIntegrityError, match="integrity verification failed"):
            verify_model_integrity(fake_model, fake_meta)

    def test_missing_metadata_raises_integrity_error(self, temp_dir):
        """Verify that missing metadata raises ModelIntegrityError."""
        model_file = temp_dir / "model.pkl"
        model_file.write_bytes(b"some_model_data")
        missing_meta = temp_dir / "non_existent_metadata.json"

        with pytest.raises(ModelIntegrityError, match="metadata file missing"):
            verify_model_integrity(model_file, missing_meta)

    def test_malformed_metadata_json_raises_integrity_error(self, temp_dir):
        """Verify that malformed metadata JSON raises ModelIntegrityError."""
        model_file = temp_dir / "model.pkl"
        model_file.write_bytes(b"some_model_data")
        bad_meta = temp_dir / "model_metadata.json"
        bad_meta.write_text("{ NOT_VALID_JSON }", encoding="utf-8")

        with pytest.raises(ModelIntegrityError, match="Malformed model metadata"):
            verify_model_integrity(model_file, bad_meta)

    def test_missing_sha256_field_in_metadata_raises_integrity_error(self, temp_dir):
        """Verify that metadata missing model_sha256 field raises ModelIntegrityError."""
        model_file = temp_dir / "model.pkl"
        model_file.write_bytes(b"some_model_data")
        bad_meta = temp_dir / "model_metadata.json"
        bad_meta.write_text(json.dumps({"model_version": "2.0.0"}), encoding="utf-8")

        with pytest.raises(ModelIntegrityError, match="Missing 'model_sha256'"):
            verify_model_integrity(model_file, bad_meta)

    def test_joblib_load_never_called_when_checksum_fails(self, temp_dir):
        """Verify that joblib.load is NEVER invoked if the checksum check fails."""
        fake_model = temp_dir / "tampered.pkl"
        fake_meta = temp_dir / "model_metadata.json"
        fake_model.write_bytes(b"TAMPERED")
        fake_meta.write_text(
            json.dumps({"model_sha256": "0000000000000000000000000000000000000000000000000000000000000000"}),
            encoding="utf-8",
        )

        with patch("joblib.load") as mock_joblib:
            with pytest.raises(ModelIntegrityError):
                get_model(custom_path=fake_model, metadata_path=fake_meta)
            mock_joblib.assert_not_called()


# =============================================================================
# 2. P1 — Alert Logger Hardening Tests
# =============================================================================


class TestAlertLoggerHardening:
    """Tests for append-only JSONL format, size-based rotation, and crash resilience."""

    def test_append_only_jsonl_write_format(self, temp_dir, monkeypatch):
        """Verify that alerts logged to a .jsonl file are formatted as discrete single-line JSON records."""
        log_file = temp_dir / "alerts.jsonl"
        monkeypatch.setenv("SENTINELX_ALERT_LOG", str(log_file))

        alert1 = {"threat_type": "PORT_SCAN", "severity": "HIGH", "source_ip": "10.0.0.1", "message": "Scan 1"}
        alert2 = {"threat_type": "HIGH_TRAFFIC", "severity": "MEDIUM", "source_ip": "10.0.0.2", "message": "Traffic 1"}

        log_alert(alert1)
        log_alert(alert2)

        assert log_file.exists()
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2

        rec1 = json.loads(lines[0])
        rec2 = json.loads(lines[1])
        assert rec1["threat_type"] == "PORT_SCAN"
        assert rec2["threat_type"] == "HIGH_TRAFFIC"
        assert "timestamp" in rec1 and "timestamp" in rec2

    def test_read_alerts_helper_with_jsonl(self, temp_dir):
        """Verify read_alerts correctly parses multi-line JSONL files."""
        log_file = temp_dir / "test.jsonl"
        records = [
            {"timestamp": "2026-09-11T12:00:00", "threat_type": "PORT_SCAN", "severity": "HIGH"},
            {"timestamp": "2026-09-11T12:01:00", "threat_type": "HIGH_TRAFFIC", "severity": "LOW"},
        ]
        log_file.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

        alerts = read_alerts(log_file)
        assert len(alerts) == 2
        assert alerts[0]["threat_type"] == "PORT_SCAN"
        assert alerts[1]["threat_type"] == "HIGH_TRAFFIC"

    def test_read_alerts_helper_with_legacy_json_array(self, temp_dir):
        """Verify read_alerts backward compatibility with formatted legacy JSON array files."""
        log_file = temp_dir / "legacy_alerts.json"
        records = [
            {"timestamp": "2026-09-11T12:00:00", "threat_type": "PORT_SCAN", "severity": "HIGH"},
            {"timestamp": "2026-09-11T12:01:00", "threat_type": "HIGH_TRAFFIC", "severity": "MEDIUM"},
        ]
        log_file.write_text(json.dumps(records, indent=4), encoding="utf-8")

        alerts = read_alerts(log_file)
        assert len(alerts) == 2
        assert alerts[0]["threat_type"] == "PORT_SCAN"
        assert alerts[1]["threat_type"] == "HIGH_TRAFFIC"

    def test_read_alerts_skips_malformed_lines_gracefully(self, temp_dir):
        """Verify read_alerts does not crash when encountering malformed lines or mid-write crashes."""
        log_file = temp_dir / "corrupted.jsonl"
        valid_rec = json.dumps({"timestamp": "2026-09-11T12:00:00", "threat_type": "PORT_SCAN"})
        malformed_line = '{"timestamp": "corrupted_mid_write_line_without_closing_brace'
        valid_rec2 = json.dumps({"timestamp": "2026-09-11T12:02:00", "threat_type": "HIGH_TRAFFIC"})

        log_file.write_text(f"{valid_rec}\n{malformed_line}\n{valid_rec2}\n", encoding="utf-8")

        alerts = read_alerts(log_file)
        assert len(alerts) == 2
        assert alerts[0]["threat_type"] == "PORT_SCAN"
        assert alerts[1]["threat_type"] == "HIGH_TRAFFIC"

    def test_log_rotation_bounded_files(self, temp_dir, monkeypatch):
        """Verify log rotation triggers when max size is reached and preserves max_backups limit."""
        log_file = temp_dir / "rotated.jsonl"
        monkeypatch.setenv("SENTINELX_ALERT_LOG", str(log_file))
        monkeypatch.setenv("SENTINELX_MAX_LOG_SIZE", "200")
        monkeypatch.setenv("SENTINELX_MAX_LOG_BACKUPS", "3")

        for i in range(15):
            log_alert({"threat_type": "PORT_SCAN", "severity": "HIGH", "seq": i, "payload": "x" * 40})

        assert log_file.exists()
        backup_1 = log_file.with_name("rotated.jsonl.1")
        backup_2 = log_file.with_name("rotated.jsonl.2")
        backup_3 = log_file.with_name("rotated.jsonl.3")
        backup_4 = log_file.with_name("rotated.jsonl.4")

        assert backup_1.exists()
        assert backup_2.exists()
        assert backup_3.exists()
        assert not backup_4.exists()

    def test_legacy_json_path_backward_compatibility(self, temp_dir, monkeypatch):
        """Verify read_alerts reads legacy JSON array files."""
        legacy_file = temp_dir / "legacy_array.json"
        legacy_data = [
            {"threat_type": "PORT_SCAN", "severity": "HIGH", "msg": "first"},
            {"threat_type": "PORT_SCAN", "severity": "HIGH", "msg": "second"},
        ]
        with open(legacy_file, "w", encoding="utf-8") as f:
            json.dump(legacy_data, f)

        data = read_alerts(legacy_file)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["msg"] == "first"
        assert data[1]["msg"] == "second"

    def test_concurrent_jsonl_logging(self, temp_dir, monkeypatch):
        """Verify that concurrent threads writing to .jsonl do not corrupt lines."""
        log_file = temp_dir / "concurrent.jsonl"
        monkeypatch.setenv("SENTINELX_ALERT_LOG", str(log_file))

        threads = []
        errors = []

        def worker(thread_id):
            try:
                for j in range(20):
                    log_alert({"threat_type": "PORT_SCAN", "severity": "LOW", "thread_id": thread_id, "item": j})
            except Exception as e:
                errors.append(e)

        for t_idx in range(5):
            t = threading.Thread(target=worker, args=(t_idx,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert not errors, f"Concurrent logging produced errors: {errors}"
        alerts = read_alerts(log_file)
        assert len(alerts) == 100


# =============================================================================
# 3. P1 — CORS Origin: null Lockdown Tests
# =============================================================================


class TestCORSSecurityLockdown:
    """Tests for CORS Origin: null rejection and opt-in security."""

    @pytest.fixture
    def client(self):
        from backend.api import app

        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_default_cors_settings_do_not_contain_null(self):
        """Verify that null is not in CORS_ALLOWED_ORIGINS by default."""
        assert "null" not in CORS_ALLOWED_ORIGINS
        assert ALLOW_LOCAL_FILE_CORS is False

    def test_origin_null_blocked_by_default_on_all_endpoints(self, client):
        """Verify that requests presenting Origin: null do not receive Access-Control-Allow-Origin."""
        for endpoint in ["/api/stats", "/api/alerts"]:
            resp = client.get(endpoint, headers={"Origin": "null"})
            assert resp.status_code == 200
            assert "Access-Control-Allow-Origin" not in resp.headers

    def test_options_preflight_origin_null_blocked_by_default(self, client):
        """Verify OPTIONS preflight requests presenting Origin: null do not receive CORS permission."""
        for endpoint in ["/api/stats", "/api/alerts"]:
            resp = client.open(endpoint, method="OPTIONS", headers={"Origin": "null"})
            assert resp.status_code == 204
            assert "Access-Control-Allow-Origin" not in resp.headers

    def test_origin_null_allowed_when_opt_in_enabled(self, client, monkeypatch):
        """Verify that setting ALLOW_LOCAL_FILE_CORS permits Origin: null."""
        monkeypatch.setattr("backend.api.ALLOW_LOCAL_FILE_CORS", True)

        for endpoint in ["/api/stats", "/api/alerts"]:
            resp = client.get(endpoint, headers={"Origin": "null"})
            assert resp.status_code == 200
            assert resp.headers.get("Access-Control-Allow-Origin") == "null"
            assert resp.headers.get("Access-Control-Allow-Methods") == "GET, OPTIONS"

    def test_untrusted_origins_always_blocked(self, client):
        """Verify arbitrary external origins are rejected."""
        untrusted = ["http://attacker.com", "https://phishing.site", "http://192.168.1.50:8080"]
        for origin in untrusted:
            resp = client.get("/api/stats", headers={"Origin": origin})
            assert "Access-Control-Allow-Origin" not in resp.headers


# =============================================================================
# 4. P1 — IPv6 Packet Parsing Support Tests
# =============================================================================


class TestIPv6PacketParsing:
    """Tests for IPv6 dissection and protocol extraction in parse_packet."""

    def test_ipv6_tcp_syn_packet(self):
        """Verify IPv6 TCP SYN packet is parsed correctly with tcp_syn=True."""
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=54321, dport=80, flags="S")
        parsed = parse_packet(pkt)

        assert parsed["source_ip"] == "2001:db8::1"
        assert parsed["destination_ip"] == "2001:db8::2"
        assert parsed["protocol"] == "TCP"
        assert parsed["source_port"] == 54321
        assert parsed["destination_port"] == 80
        assert parsed["tcp_syn"] is True

    def test_ipv6_tcp_ack_packet(self):
        """Verify IPv6 TCP non-SYN packet has tcp_syn=False."""
        pkt = IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=443, dport=60000, flags="A")
        parsed = parse_packet(pkt)

        assert parsed["source_ip"] == "fe80::1"
        assert parsed["destination_ip"] == "fe80::2"
        assert parsed["protocol"] == "TCP"
        assert parsed["tcp_syn"] is False

    def test_ipv6_udp_packet(self):
        """Verify IPv6 UDP packet extraction."""
        pkt = IPv6(src="2001:db8::cafe", dst="2001:db8::beef") / UDP(sport=5353, dport=53)
        parsed = parse_packet(pkt)

        assert parsed["source_ip"] == "2001:db8::cafe"
        assert parsed["destination_ip"] == "2001:db8::beef"
        assert parsed["protocol"] == "UDP"
        assert parsed["source_port"] == 5353
        assert parsed["destination_port"] == 53
        assert parsed["tcp_syn"] is False

    def test_ipv6_other_packet(self):
        """Verify IPv6 packet without TCP/UDP reports protocol='IPv6'."""
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2")
        parsed = parse_packet(pkt)

        assert parsed["source_ip"] == "2001:db8::1"
        assert parsed["destination_ip"] == "2001:db8::2"
        assert parsed["protocol"] == "IPv6"
        assert parsed["source_port"] is None
        assert parsed["destination_port"] is None
        assert parsed["tcp_syn"] is False

    def test_non_ip_packet_remains_other(self):
        """Verify ARP / link-layer packets continue to report protocol='OTHER'."""
        pkt = Ether() / ARP()
        parsed = parse_packet(pkt)

        assert parsed["source_ip"] is None
        assert parsed["destination_ip"] is None
        assert parsed["protocol"] == "OTHER"

    def test_ipv4_regression_preserved(self):
        """Verify IPv4 parsing remains 100% identical."""
        pkt = IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=1234, dport=80, flags="S")
        parsed = parse_packet(pkt)

        assert parsed["source_ip"] == "192.168.1.10"
        assert parsed["destination_ip"] == "192.168.1.1"
        assert parsed["protocol"] == "TCP"
        assert parsed["tcp_syn"] is True


class TestPacketParserValidation:
    """Regression tests ensuring parse_packet handles non-packet and invalid inputs safely."""

    def test_parse_packet_none(self):
        """parse_packet(None) must return safe default structure with packet_size=0 and no exception."""
        parsed = parse_packet(None)
        assert isinstance(parsed, dict)
        assert parsed["source_ip"] is None
        assert parsed["destination_ip"] is None
        assert parsed["protocol"] == "OTHER"
        assert parsed["source_port"] is None
        assert parsed["destination_port"] is None
        assert parsed["packet_size"] == 0
        assert parsed["tcp_syn"] is False

    def test_parse_packet_without_len(self):
        """Objects without __len__ (e.g. int, object) must return default structure with packet_size=0."""
        for invalid in [12345, object(), True]:
            parsed = parse_packet(invalid)
            assert isinstance(parsed, dict)
            assert parsed["protocol"] == "OTHER"
            assert parsed["packet_size"] == 0

    def test_parse_packet_with_len_invalid_packet(self):
        """Objects with __len__ but invalid packet structure must return default structure safely."""
        for invalid in ["not_a_packet", b"arbitrary_binary_payload", [1, 2, 3], {}]:
            parsed = parse_packet(invalid)
            assert isinstance(parsed, dict)
            assert parsed["protocol"] == "OTHER"
            assert parsed["packet_size"] == len(invalid)

    def test_parse_packet_valid_ipv4_tcp(self):
        """Valid IPv4 TCP SYN packet extracts IPs, ports, size, and protocol."""
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=8080, dport=443, flags="S")
        parsed = parse_packet(pkt)
        assert parsed["source_ip"] == "10.0.0.1"
        assert parsed["destination_ip"] == "10.0.0.2"
        assert parsed["protocol"] == "TCP"
        assert parsed["source_port"] == 8080
        assert parsed["destination_port"] == 443
        assert parsed["tcp_syn"] is True
        assert parsed["packet_size"] == len(pkt)

    def test_parse_packet_valid_ipv4_udp(self):
        """Valid IPv4 UDP packet extracts IPs, ports, size, and protocol."""
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=12345)
        parsed = parse_packet(pkt)
        assert parsed["source_ip"] == "10.0.0.1"
        assert parsed["destination_ip"] == "10.0.0.2"
        assert parsed["protocol"] == "UDP"
        assert parsed["source_port"] == 53
        assert parsed["destination_port"] == 12345
        assert parsed["tcp_syn"] is False
        assert parsed["packet_size"] == len(pkt)

    def test_parse_packet_valid_ipv6_tcp(self):
        """Valid IPv6 TCP packet extracts IPv6 addresses, ports, and protocol."""
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=9000, dport=22, flags="S")
        parsed = parse_packet(pkt)
        assert parsed["source_ip"] == "2001:db8::1"
        assert parsed["destination_ip"] == "2001:db8::2"
        assert parsed["protocol"] == "TCP"
        assert parsed["source_port"] == 9000
        assert parsed["destination_port"] == 22
        assert parsed["tcp_syn"] is True
        assert parsed["packet_size"] == len(pkt)

    def test_parse_packet_valid_ipv6_udp(self):
        """Valid IPv6 UDP packet extracts IPv6 addresses, ports, and protocol."""
        pkt = IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5353, dport=5353)
        parsed = parse_packet(pkt)
        assert parsed["source_ip"] == "fe80::1"
        assert parsed["destination_ip"] == "fe80::2"
        assert parsed["protocol"] == "UDP"
        assert parsed["source_port"] == 5353
        assert parsed["destination_port"] == 5353
        assert parsed["tcp_syn"] is False
        assert parsed["packet_size"] == len(pkt)
