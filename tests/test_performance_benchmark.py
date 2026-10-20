import time

from scapy.all import IP, TCP

from capture.packet_parser import parse_packet
from capture.pipeline import PacketPipeline
from detection.engine import DetectionEngine


def make_benchmark_packet(port: int):
    pkt = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=40000 + (port % 1000), dport=port, flags="S")
    pkt.time = 1000.0 + (port * 0.001)
    return pkt


def test_performance_benchmark_queue_vs_synchronous():
    """
    Controlled benchmark measuring producer latency:
    Compares synchronous processing overhead against non-blocking queue enqueue.
    """
    engine = DetectionEngine()
    packet_count = 500
    packets = [make_benchmark_packet(p) for p in range(packet_count)]

    # 1. Measure synchronous in-band processing
    def synchronous_handler(packet):
        data = parse_packet(packet)
        engine.process_packet(data)

    sync_start = time.perf_counter()
    for pkt in packets:
        synchronous_handler(pkt)
    sync_duration = time.perf_counter() - sync_start

    # 2. Measure decoupled producer queue enqueue
    pipeline = PacketPipeline(maxsize=10000, processor=synchronous_handler)
    pipeline.start()

    enqueue_start = time.perf_counter()
    for pkt in packets:
        pipeline.enqueue(pkt)
    enqueue_duration = time.perf_counter() - enqueue_start

    # Wait for pipeline to finish draining
    pipeline.stop(drain=True, timeout=5.0)

    sync_pps = packet_count / sync_duration if sync_duration > 0 else float("inf")
    enqueue_pps = packet_count / enqueue_duration if enqueue_duration > 0 else float("inf")
    speedup = sync_duration / enqueue_duration if enqueue_duration > 0 else 1.0

    print("\n" + "=" * 60)
    print("      PERFORMANCE BENCHMARK: PRODUCER LATENCY")
    print("=" * 60)
    print(f"[*] Total Packets       : {packet_count}")
    print(f"[*] Synchronous Ingest  : {sync_duration * 1000:.2f} ms ({sync_pps:.1f} packets/sec)")
    print(f"[*] Queue Enqueue Ingest: {enqueue_duration * 1000:.2f} ms ({enqueue_pps:.1f} packets/sec)")
    print(f"[*] Ingestion Speedup   : {speedup:.2f}x faster producer release")
    print("=" * 60 + "\n")

    # Producer enqueue must be faster than full synchronous execution
    assert enqueue_duration < sync_duration, "Queue enqueue should be faster than full synchronous processing!"


if __name__ == "__main__":
    test_performance_benchmark_queue_vs_synchronous()
