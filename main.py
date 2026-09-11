import argparse
import sys
import threading
import time

from backend.api import app
from capture.packet_capture import start_capture, process_packet
from capture.pipeline import PacketPipeline
from capture.pcap_replay import replay_pcap
from config.settings import (
    CAPTURE_MODE,
    CAPTURE_INTERFACE,
    PCAP_FILE_PATH,
    WORKER_COUNT,
    QUEUE_MAXSIZE,
    API_HOST,
    API_PORT,
    API_DEBUG,
)


def start_dashboard():
    print(f"[*] Starting SentinelX dashboard on {API_HOST}:{API_PORT}...")
    app.run(
        host=API_HOST,
        port=API_PORT,
        debug=API_DEBUG,
        use_reloader=False
    )


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="SentinelX - Network Intrusion Detection & Threat Monitoring System"
    )
    parser.add_argument(
        "--mode",
        choices=["live", "pcap"],
        default=CAPTURE_MODE,
        help="Capture mode: 'live' for network sniffing, 'pcap' for offline file replay (default: live)",
    )
    parser.add_argument(
        "--pcap",
        default=PCAP_FILE_PATH,
        help="Path to PCAP file (required if --mode is pcap)",
    )
    parser.add_argument(
        "--interface",
        default=CAPTURE_INTERFACE,
        help="Network interface to monitor in live mode (default: system default)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=WORKER_COUNT,
        help=f"Number of packet processing worker threads (default: {WORKER_COUNT})",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    print("=" * 60)
    print("        SENTINELX")
    print("        Network Intrusion Detection &")
    print("        Threat Monitoring System")
    print("=" * 60)

    print("\n[*] Starting SentinelX components...\n")

    # Start Flask dashboard in background
    dashboard_thread = threading.Thread(
        target=start_dashboard,
        daemon=True
    )
    dashboard_thread.start()

    # Give Flask a moment to start
    time.sleep(2)

    print("[+] Dashboard available at:")
    print(f"[+] http://{API_HOST}:{API_PORT}/\n")

    pipeline = PacketPipeline(
        maxsize=QUEUE_MAXSIZE,
        worker_count=args.workers,
        processor=process_packet,
    )

    if args.mode == "pcap":
        if not args.pcap:
            print("[!] Error: --pcap <file> is required when --mode is 'pcap'.")
            sys.exit(1)

        print(f"[*] Starting PCAP replay from: {args.pcap}\n")
        replay_pcap(args.pcap, pipeline_instance=pipeline)
    else:
        print("[*] Starting network monitoring...\n")
        start_capture(iface=args.interface, pipeline_instance=pipeline)


if __name__ == "__main__":
    main()