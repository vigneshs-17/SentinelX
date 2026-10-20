"""
SentinelX Intrusion Detection System - Main Entry Point.
Provides CLI subcommands:
  - run: Live packet capture and monitoring
  - replay: Offline PCAP replay
  - eval: Automated scenario evaluation benchmark and reporting
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

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
    PCAP_FILE_PATH,
    QUEUE_MAXSIZE,
)
from database.database import initialize_database
from eval.runner import run_external_pcap_benchmark, run_scenario_benchmark


def start_dashboard() -> None:
    """Starts the Flask dashboard in the background."""
    print(f"[*] Starting SentinelX dashboard on {API_HOST}:{API_PORT}...")
    app.run(host=API_HOST, port=API_PORT, debug=API_DEBUG, use_reloader=False)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses command-line arguments and subcommands."""
    parser = argparse.ArgumentParser(description="SentinelX - Network Intrusion Detection & Threat Monitoring System")
    subparsers = parser.add_subparsers(dest="command", help="Operational subcommands")

    # 1. run subcommand
    parser_run = subparsers.add_parser("run", help="Start live network monitoring")
    parser_run.add_argument(
        "--interface",
        default=CAPTURE_INTERFACE,
        help="Network interface to monitor (default: system default)",
    )

    # 2. replay subcommand
    parser_replay = subparsers.add_parser("replay", help="Replay a PCAP file offline")
    parser_replay.add_argument(
        "pcap",
        nargs="?",
        default=PCAP_FILE_PATH,
        help="Path to PCAP file to replay",
    )

    # 3. eval subcommand
    parser_eval = subparsers.add_parser("eval", help="Run detection evaluation benchmark")
    parser_eval.add_argument(
        "--scenarios",
        default="all",
        help="Comma-separated scenario names or 'all' (default: all)",
    )
    parser_eval.add_argument(
        "--out",
        default="eval_output",
        help="Directory where report.json and report.md will be saved (default: eval_output)",
    )
    parser_eval.add_argument(
        "--pcap",
        default=None,
        help="Path to external labelled PCAP file",
    )
    parser_eval.add_argument(
        "--labels",
        default=None,
        help="Path to external ground truth labels JSON file",
    )
    parser_eval.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic scenario generation (default: 42)",
    )

    # Legacy options for backward compatibility
    parser.add_argument("--mode", choices=["live", "pcap"], default=None, help=argparse.SUPPRESS)
    parser.add_argument("--pcap", dest="legacy_pcap", default=None, help=argparse.SUPPRESS)

    args = parser.parse_args(argv)

    # Handle fallback if command was omitted
    if args.command is None:
        if args.mode == "pcap" or args.legacy_pcap:
            args.command = "replay"
            args.pcap = args.legacy_pcap or PCAP_FILE_PATH
        else:
            args.command = "run"
            args.interface = getattr(args, "interface", CAPTURE_INTERFACE)

    return args


def handle_eval(args: argparse.Namespace) -> None:
    """Executes the eval subcommand and outputs reports."""
    print("=" * 60)
    print("        SENTINELX EVALUATION BENCHMARK")
    print("=" * 60)

    if args.pcap and args.labels:
        summary = run_external_pcap_benchmark(
            pcap_path=args.pcap,
            labels_path=args.labels,
            out_dir=args.out,
        )
    else:
        summary = run_scenario_benchmark(
            scenario_names=args.scenarios,
            out_dir=args.out,
            seed=args.seed,
        )

    out_md = Path(args.out) / "report.md"
    if out_md.exists():
        with open(out_md, encoding="utf-8") as f:
            print("\n" + f.read() + "\n")

    if summary["status"] != "PASS" or summary["overall"]["f1"] < 1.0:
        print("[!] Evaluation benchmark FAILED expectations or F1 < 1.0.")
        sys.exit(1)
    else:
        print("[+] Evaluation benchmark PASSED all expectations (F1 = 1.0).")
        sys.exit(0)


def main() -> None:
    """Main CLI execution router."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    args = parse_arguments()

    if args.command == "eval":
        handle_eval(args)
        return

    # Configure centralized logging and database schema for live/replay runs
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
    time.sleep(2)

    print("[+] Dashboard available at:")
    print(f"[+] http://{API_HOST}:{API_PORT}/\n")

    pipeline = PacketPipeline(maxsize=QUEUE_MAXSIZE)

    if args.command == "replay":
        if not args.pcap:
            print("[!] Error: PCAP file path is required for 'replay' command.")
            sys.exit(1)
        print(f"[*] Starting PCAP replay from: {args.pcap}\n")
        replay_pcap(args.pcap, pipeline_instance=pipeline)
    else:
        print("[*] Starting network monitoring...\n")
        start_capture(iface=getattr(args, "interface", CAPTURE_INTERFACE), pipeline_instance=pipeline)


if __name__ == "__main__":
    main()
