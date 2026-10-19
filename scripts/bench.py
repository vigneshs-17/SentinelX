"""
Benchmark script for SentinelX Phase 3 Detection Engine.

Generates a 200,000-packet synthetic traffic stream containing normal traffic
interleaved with port scans, SYN floods, and volumetric bursts.
Measures processing throughput (packets per second) and peak memory usage via tracemalloc.
"""

import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from detection.engine import DetectionEngine  # noqa: E402


def generate_benchmark_packets(total_packets: int = 200_000) -> list[dict[str, Any]]:
    """Generate deterministic synthetic packets for benchmarking."""
    print(f"[*] Generating {total_packets:,} synthetic benchmark packets...")
    packets: list[dict[str, Any]] = []

    base_ts = 1_700_000_000.0

    for i in range(total_packets):
        # Progressively advance event time by 1 ms per packet (1,000 pps rate)
        ts = base_ts + (i * 0.001)

        packet_type = i % 100

        if packet_type < 80:
            # Benign background TCP/UDP traffic across 250 internal endpoints
            src_octet = (i % 250) + 1
            dst_octet = ((i // 250) % 250) + 1
            packets.append(
                {
                    "ts": ts,
                    "source_ip": f"192.168.1.{src_octet}",
                    "destination_ip": f"10.0.0.{dst_octet}",
                    "source_port": 30000 + (i % 20000),
                    "destination_port": 443 if (i % 2 == 0) else 80,
                    "protocol": "TCP",
                    "tcp_syn": False,
                    "tcp_ack": True,
                    "tcp_syn_ack": False,
                    "tcp_rst": False,
                    "packet_size": 128 + (i % 1024),
                }
            )
        elif packet_type < 90:
            # Vertical port scan burst from one attacker
            packets.append(
                {
                    "ts": ts,
                    "source_ip": "198.51.100.77",
                    "destination_ip": "10.0.0.50",
                    "source_port": 50000 + (i % 1000),
                    "destination_port": 1 + (i % 1000),
                    "protocol": "TCP",
                    "tcp_syn": True,
                    "tcp_ack": False,
                    "tcp_syn_ack": False,
                    "tcp_rst": False,
                    "packet_size": 60,
                }
            )
        elif packet_type < 95:
            # SYN flood burst from rotating spoofed sources
            packets.append(
                {
                    "ts": ts,
                    "source_ip": f"203.0.113.{(i % 254) + 1}",
                    "destination_ip": "10.0.0.80",
                    "source_port": 40000 + (i % 10000),
                    "destination_port": 80,
                    "protocol": "TCP",
                    "tcp_syn": True,
                    "tcp_ack": False,
                    "tcp_syn_ack": False,
                    "tcp_rst": False,
                    "packet_size": 60,
                }
            )
        else:
            # Volumetric UDP flood
            packets.append(
                {
                    "ts": ts,
                    "source_ip": f"198.18.0.{(i % 200) + 1}",
                    "destination_ip": "10.0.0.99",
                    "source_port": 10000 + (i % 5000),
                    "destination_port": 53,
                    "protocol": "UDP",
                    "tcp_syn": False,
                    "tcp_ack": False,
                    "tcp_syn_ack": False,
                    "tcp_rst": False,
                    "packet_size": 1400,
                }
            )

    return packets


def run_benchmark(total_packets: int = 200_000) -> dict[str, Any]:
    packets = generate_benchmark_packets(total_packets)

    engine = DetectionEngine()

    print("[*] Starting tracemalloc profiling and engine processing...")
    tracemalloc.start()
    start_time = time.perf_counter()

    alert_count = 0
    for p in packets:
        alerts = engine.process_packet(p)
        if alerts:
            alert_count += len(alerts)

    elapsed = time.perf_counter() - start_time
    curr_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    pps = total_packets / elapsed if elapsed > 0 else 0.0
    peak_mb = peak_mem / (1024 * 1024)
    engine_metrics = engine.get_metrics()

    print("\n" + "=" * 65)
    print("        SENTINELX PHASE 3 DETECTION BENCHMARK RESULTS")
    print("=" * 65)
    print(f"Packets Processed      : {total_packets:,}")
    print(f"Elapsed Time           : {elapsed:.3f} seconds")
    print(f"Throughput             : {pps:,.1f} packets/second")
    print(f"Alerts Triggered       : {alert_count:,}")
    print(f"Peak Memory (tracemalloc): {peak_mb:.2f} MB")
    print("\nPartition Store State:")
    for part_name, stats in engine_metrics["partitions"].items():
        print(f"  - {part_name:<22}: size={stats['size']:<6} cap={stats['capacity']:<6} evictions={stats['evictions']}")
    print("=" * 65)

    return {
        "total_packets": total_packets,
        "elapsed_seconds": elapsed,
        "throughput_pps": pps,
        "peak_memory_mb": peak_mb,
        "alerts_triggered": alert_count,
        "partitions": engine_metrics["partitions"],
    }


if __name__ == "__main__":
    run_benchmark(200_000)
