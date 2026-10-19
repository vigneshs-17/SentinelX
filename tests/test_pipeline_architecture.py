import os
import tempfile
import threading
import time
from pathlib import Path

from scapy.all import IP, TCP, wrpcap

from capture.metrics import PipelineMetrics
from capture.pcap_replay import replay_pcap
from capture.pipeline import PacketPipeline
from database.database import get_connection
from detection.rule_engine import (
    connection_tracker,
    last_scan_alert_time,
)
from logs.alert_logger import get_alert_file_path, log_alert


def make_test_packet(dport: int = 80, flags: str = "S"):
    return IP(src="192.168.1.100", dst="192.168.1.10") / TCP(sport=50000, dport=dport, flags=flags)


class TestPipelineArchitecture:
    """Comprehensive test suite for Phase 2 Architecture & Pipeline components."""

    def test_pipeline_metrics_tracking(self):
        """Verify PipelineMetrics correctly increments and returns atomic snapshots."""
        metrics = PipelineMetrics()
        metrics.record_received(10)
        metrics.record_queued(8)
        metrics.record_dropped(2)
        metrics.record_processed(7)
        metrics.record_error(1)
        metrics.record_alert(3)

        snap = metrics.get_snapshot()
        assert snap["packets_received"] == 10
        assert snap["packets_queued"] == 8
        assert snap["packets_dropped"] == 2
        assert snap["packets_processed"] == 7
        assert snap["processing_errors"] == 1
        assert snap["alerts_generated"] == 3

        metrics.reset()
        clean_snap = metrics.get_snapshot()
        assert clean_snap["packets_received"] == 0
        assert clean_snap["packets_processed"] == 0

    def test_queue_insertion_and_consumption(self):
        """Verify packets placed in queue are consumed and processed by the worker."""
        processed_packets = []

        def dummy_processor(packet):
            processed_packets.append(packet)

        pipeline = PacketPipeline(maxsize=50, worker_count=1, processor=dummy_processor)
        pipeline.start()

        for port in range(5):
            success = pipeline.enqueue(make_test_packet(dport=port))
            assert success is True

        pipeline.stop(drain=True, timeout=3.0)

        assert len(processed_packets) == 5
        snap = pipeline.get_snapshot()
        assert snap["packets_received"] == 5
        assert snap["packets_queued"] == 5
        assert snap["packets_processed"] == 5
        assert snap["packets_dropped"] == 0

    def test_queue_full_drop_behavior(self):
        """Verify bounded queue rejects items when saturated and updates drop counter."""
        # Queue maxsize = 3, worker not started so queue fills up
        pipeline = PacketPipeline(maxsize=3, worker_count=1)

        results = []
        for port in range(6):
            results.append(pipeline.enqueue(make_test_packet(dport=port)))

        # First 3 should succeed, remaining 3 should be dropped
        assert results == [True, True, True, False, False, False]

        snap = pipeline.get_snapshot()
        assert snap["packets_received"] == 6
        assert snap["packets_queued"] == 3
        assert snap["packets_dropped"] == 3
        assert snap["current_queue_size"] == 3

    def test_worker_clean_shutdown(self):
        """Verify worker threads terminate cleanly without hung processes."""
        pipeline = PacketPipeline(maxsize=100, worker_count=2, processor=lambda p: time.sleep(0.01))
        pipeline.start()

        for worker in pipeline.workers:
            assert worker.is_alive()

        for port in range(10):
            pipeline.enqueue(make_test_packet(dport=port))

        pipeline.stop(drain=True, timeout=4.0)

        assert len(pipeline.workers) == 0
        snap = pipeline.get_snapshot()
        assert snap["packets_processed"] == 10

    def test_malformed_packet_resilience(self):
        """Verify malformed objects do not crash worker threads."""
        processed_good = []

        def brittle_processor(item):
            if item == "corrupted_packet":
                raise ValueError("Corrupted packet payload!")
            processed_good.append(item)

        pipeline = PacketPipeline(maxsize=20, worker_count=1, processor=brittle_processor)
        pipeline.start()

        pipeline.enqueue(make_test_packet(80))
        pipeline.enqueue("corrupted_packet")  # should trigger processing_error
        pipeline.enqueue(make_test_packet(443))

        pipeline.stop(drain=True, timeout=3.0)

        snap = pipeline.get_snapshot()
        assert snap["packets_processed"] == 2
        assert snap["processing_errors"] == 1
        assert len(processed_good) == 2

    def test_pcap_replay_mode_synthetic(self):
        """Verify offline PCAP replay processes packets and triggers detection."""
        connection_tracker.clear()
        last_scan_alert_time.clear()

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_file = Path(temp_dir) / "test_syn_scan.pcap"
            packets = [make_test_packet(dport=p, flags="S") for p in range(20, 32)]
            wrpcap(str(pcap_file), packets)

            from capture.packet_capture import process_packet

            pipeline = PacketPipeline(maxsize=100, worker_count=1, processor=process_packet)

            metrics = replay_pcap(str(pcap_file), pipeline_instance=pipeline, print_summary=False)

            assert metrics["packets_processed"] == 12
            assert metrics["packets_dropped"] == 0
            assert metrics["processing_errors"] == 0

            # Verify an alert was generated and stored in the isolated database
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM alerts WHERE threat_type = 'PORT_SCAN'")
            port_scan_alerts = cur.fetchone()[0]
            conn.close()

            assert port_scan_alerts >= 1

    def test_concurrent_alert_logging_safety(self):
        """Verify concurrent alert logging with threads does not corrupt JSON or database."""
        alert_log_file = get_alert_file_path()
        if alert_log_file.exists():
            try:
                alert_log_file.unlink()
            except Exception:
                pass

        def worker_log(thread_id):
            for i in range(10):
                log_alert(
                    {
                        "threat_type": "PORT_SCAN",
                        "severity": "HIGH",
                        "source_ip": f"10.0.{thread_id}.{i}",
                        "destination_ip": "10.0.0.1",
                        "protocol": "TCP",
                        "message": f"Concurrent test alert from worker {thread_id} - {i}",
                    }
                )

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        initial_db_count = cur.fetchone()[0]
        conn.close()

        threads = [threading.Thread(target=worker_log, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Check that JSONL file is valid and contains exactly 40 items
        assert alert_log_file.exists()
        from logs.alert_logger import read_alerts

        data = read_alerts(alert_log_file)
        assert len(data) == 40

        # Check that SQLite database contains exactly 40 additional records
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        final_db_count = cur.fetchone()[0]
        conn.close()
        assert final_db_count - initial_db_count == 40


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temp_dir:
        os.environ["SENTINELX_DB_PATH"] = os.path.join(temp_dir, "test.db")
        os.environ["SENTINELX_ALERT_LOG"] = os.path.join(temp_dir, "test.json")
        from database.database import initialize_database

        initialize_database()

        suite = TestPipelineArchitecture()
        suite.test_pipeline_metrics_tracking()
        suite.test_queue_insertion_and_consumption()
        suite.test_queue_full_drop_behavior()
        suite.test_worker_clean_shutdown()
        suite.test_malformed_packet_resilience()
        suite.test_pcap_replay_mode_synthetic()
        suite.test_concurrent_alert_logging_safety()
        print("All pipeline architecture tests passed!")
