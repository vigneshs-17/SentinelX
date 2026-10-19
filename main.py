import argparse
import sys
import threading
import time

from backend.api import app
from capture.packet_capture import start_capture
from capture.pcap_replay import replay_pcap
from capture.pipeline import PacketPipeline
from config.logging_config import configure_logging
from config.settings import (
    API_DEBUG,
    API_HOST,
    API_PORT,
    CAPTURE_INTERFACE,
    CAPTURE_MODE,
    PCAP_FILE_PATH,
    QUEUE_MAXSIZE,
)
from database.database import initialize_database


def start_dashboard():
    print(f"[*] Starting SentinelX dashboard on {API_HOST}:{API_PORT}...")
    app.run(host=API_HOST, port=API_PORT, debug=API_DEBUG, use_reloader=False)


def parse_arguments():
    parser = argparse.ArgumentParser(description="SentinelX - Network Intrusion Detection & Threat Monitoring System")
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
    return parser.parse_args()


def main():
    args = parse_arguments()

    # Configure centralized logging and database schema
    configure_logging()
    initialize_database()

    print("=" * 60)
    print("        SENTINELX")
    print("        Network Intrusion Detection &")
    print("        Threat Monitoring System")
    print("=" * 60)

    print("\n[*] Starting SentinelX components...\n")

    # Start Flask dashboard in background
    dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
    dashboard_thread.start()

    # Give Flask a moment to start
    time.sleep(2)

    print("[+] Dashboard available at:")
    print(f"[+] http://{API_HOST}:{API_PORT}/\n")

    pipeline = PacketPipeline(maxsize=QUEUE_MAXSIZE)

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
