import argparse
import time
from pathlib import Path

from scapy.all import PcapReader

from capture.pipeline import PacketPipeline


def replay_pcap(
    pcap_path: str,
    pipeline_instance: PacketPipeline | None = None,
    delay: float = 0.0,
    print_summary: bool = True,
) -> dict:
    """
    Replays a PCAP file through the SentinelX packet processing pipeline.

    Streams packets sequentially into a bounded producer-consumer queue,
    allowing offline evaluation and testing without live network traffic
    or administrator privileges.
    """
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    active_pipeline = pipeline_instance or PacketPipeline()

    if print_summary:
        print("=" * 60)
        print("        SENTINELX PCAP REPLAY MODE")
        print("=" * 60)
        print(f"[*] PCAP File : {path.resolve()}")
        print(f"[*] Queue Size: {active_pipeline.maxsize}")
        print(f"[*] Workers   : {active_pipeline.worker_count}")
        print(f"[*] Delay/Pkt : {delay}s\n")

    active_pipeline.start()

    start_time = time.time()
    packet_count = 0

    try:
        with PcapReader(str(path)) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                active_pipeline.enqueue(packet)
                if delay > 0:
                    time.sleep(delay)
    except Exception as error:
        print(f"[!] Error reading PCAP: {error}")
        raise
    finally:
        # Wait for all enqueued packets to finish processing
        active_pipeline.stop(drain=True)

    elapsed = time.time() - start_time
    snapshot = active_pipeline.get_snapshot()

    if print_summary:
        print("\n" + "=" * 60)
        print("        REPLAY SUMMARY")
        print("=" * 60)
        print(f"[+] Total packets read     : {packet_count}")
        print(f"[+] Packets processed     : {snapshot['packets_processed']}")
        print(f"[+] Packets dropped       : {snapshot['packets_dropped']}")
        print(f"[+] Processing errors     : {snapshot['processing_errors']}")
        print(f"[+] Alerts generated      : {snapshot['alerts_generated']}")
        print(f"[+] Elapsed time          : {elapsed:.2f}s")
        if elapsed > 0:
            pps = packet_count / elapsed
            print(f"[+] Throughput            : {pps:.1f} packets/sec")
        print("=" * 60 + "\n")

    return snapshot


def main():
    parser = argparse.ArgumentParser(description="SentinelX PCAP Replay Tool")
    parser.add_argument("pcap", help="Path to PCAP capture file")
    parser.add_argument("--workers", type=int, default=1, help="Worker threads (default: 1)")
    parser.add_argument("--delay", type=float, default=0.0, help="Artificial delay between packets in seconds")

    args = parser.parse_args()

    pipeline_instance = PacketPipeline(worker_count=args.workers)
    replay_pcap(args.pcap, pipeline_instance=pipeline_instance, delay=args.delay)


if __name__ == "__main__":
    main()
