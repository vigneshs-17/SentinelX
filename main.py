"""
SentinelX Intrusion Detection System - Main Entry Point.
Provides CLI subcommands:
  - sensor: Live capture + detection engine + alert writers (no HTTP). Writes alerts.db.
  - api: Dashboard + REST API served by waitress. Opens alerts.db read-only; owns app.db.
  - run --dev: Sensor and Flask dev server in one process, for local development only
  - replay: Offline PCAP replay through the sensor (writes alerts.db, no HTTP)
  - db prune: Delete alerts ingested more than a given age ago
  - db prune-audit: Admin-run audit-log retention (the only way audit rows are ever deleted)
  - eval: Automated scenario evaluation benchmark and reporting (optionally rules-only vs rules+ML replay)
  - train: Train the flow-level ML model from a flows.csv.gz and write a signed model artifact

Heavy imports (scapy, Flask, scikit-learn) happen inside the handlers so each process loads only what it uses;
in particular the api process never imports the packet-capture stack.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from config.settings import API_HOST, API_PORT, API_THREADS, CAPTURE_INTERFACE


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses command-line arguments and subcommands."""
    parser = argparse.ArgumentParser(description="SentinelX - Network Intrusion Detection & Threat Monitoring System")
    subparsers = parser.add_subparsers(dest="command", help="Operational subcommands")

    # 1. sensor / api / run / replay / db
    parser_sensor = subparsers.add_parser("sensor", help="Run the sensor: capture + engine + alert writers, no HTTP")
    parser_sensor.add_argument(
        "--interface", default=CAPTURE_INTERFACE, help="Network interface (default: system default)"
    )

    subparsers.add_parser("api", help="Serve the dashboard and REST API with waitress (alerts.db opened read-only)")

    parser_run = subparsers.add_parser("run", help="Local development: sensor + Flask dev server in one process")
    parser_run.add_argument("--dev", action="store_true", help="required: acknowledges this is not a deployment mode")
    parser_run.add_argument(
        "--interface", default=CAPTURE_INTERFACE, help="Network interface (default: system default)"
    )

    parser_replay = subparsers.add_parser("replay", help="Replay a PCAP file through the sensor (no HTTP)")
    parser_replay.add_argument("pcap", help="Path to PCAP file to replay")

    parser_db = subparsers.add_parser("db", help="Database maintenance")
    db_sub = parser_db.add_subparsers(dest="db_command", required=True)
    parser_prune = db_sub.add_parser("prune", help="Delete alerts older than an age")
    parser_prune.add_argument("--older-than", required=True, help="Age such as 30d or 12h")
    db_sub.add_parser(
        "prune-audit",
        help="Admin only: delete audit-log rows older than SENTINELX_AUDIT_RETENTION_DAYS (0 = keep forever)",
    )

    parser_user = subparsers.add_parser("user", help="Manage users (no public sign-up; CLI and admin API only)")
    user_sub = parser_user.add_subparsers(dest="user_command", required=True)
    p_add = user_sub.add_parser("add", help="Create a user (password is prompted, never an argument)")
    p_add.add_argument("username")
    p_add.add_argument("--role", required=True, choices=["admin", "analyst", "viewer"])
    for name, text in (("disable", "Disable a user and end their sessions"), ("enable", "Re-enable a user")):
        user_sub.add_parser(name, help=text).add_argument("username")
    user_sub.add_parser(
        "reset-password", help="Set a new password (prompted) and end the user's sessions"
    ).add_argument("username")
    user_sub.add_parser("list", help="List users")

    parser_key = subparsers.add_parser("apikey", help="Manage API keys for scripts and SIEM")
    key_sub = parser_key.add_subparsers(dest="key_command", required=True)
    k_create = key_sub.add_parser("create", help="Create a key; it is printed once")
    k_create.add_argument("--role", required=True, choices=["viewer", "analyst"])
    k_create.add_argument("--name", required=True)
    key_sub.add_parser("revoke", help="Revoke a key by id").add_argument("key_id", type=int)
    key_sub.add_parser("list", help="List keys (prefix only)")

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
        nargs="+",
        default=None,
        help="Path(s) to external labelled PCAP file(s)",
    )
    parser_eval.add_argument(
        "--ml-model",
        default=None,
        help="Model directory: replay --pcap through rules-only and rules+ML, score both, decide the gate",
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

    # 4. train subcommand
    parser_train = subparsers.add_parser("train", help="Train the flow-level ML model (needs SENTINELX_MODEL_KEY)")
    parser_train.add_argument("--flows", required=True, help="flows.csv.gz produced by scripts/build_flows.py")
    parser_train.add_argument("--out", default="models", help="Output model directory (default: models)")
    parser_train.add_argument("--schedule", default=None, help="Attack schedule JSON (default: CIC-IDS2017)")
    parser_train.add_argument("--utc-offset-hours", type=float, default=None)
    parser_train.add_argument(
        "--short-class-policy",
        choices=["test", "train"],
        default="test",
        help="Single-day classes too short to split: hold out as zero-shot test (default) or train on them",
    )
    parser_train.add_argument(
        "--smoke",
        action="store_true",
        help="CI only: fit on all rows of a tiny synthetic flow set; no held-out claims, never gate-eligible",
    )

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        parser.exit(2)
    return args


def handle_eval(args: argparse.Namespace) -> None:
    """Executes the eval subcommand and outputs reports."""
    from eval.ml_compare import run_ml_comparison
    from eval.runner import run_external_pcap_benchmark, run_scenario_benchmark
    from ml.artifact import ModelSecurityError

    print("=" * 60)
    print("        SENTINELX EVALUATION BENCHMARK")
    print("=" * 60)

    if args.ml_model:
        if not (args.pcap and args.labels):
            print("[!] --ml-model needs --pcap and --labels.")
            sys.exit(2)
        try:
            ml_summary = run_ml_comparison(args.pcap, args.labels, args.ml_model, args.out)
        except (ModelSecurityError, FileNotFoundError, ValueError) as exc:
            print(f"[!] ML comparison failed: {exc}")
            sys.exit(2)
        gate = ml_summary["gate"]
        print(f"[+] Gate: {gate['decision']} - {gate['reason']}")
        print(f"[+] Wrote {Path(args.out) / 'ml_eval.json'}")
        sys.exit(0)

    if args.pcap and args.labels:
        if len(args.pcap) != 1:
            print("[!] Multiple --pcap files need --ml-model.")
            sys.exit(2)
        summary = run_external_pcap_benchmark(
            pcap_path=args.pcap[0],
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


def handle_train(args: argparse.Namespace) -> None:
    """Executes the train subcommand."""
    from ml.artifact import ModelSecurityError
    from ml.model import TrainingError, train_from_flows

    kwargs = {"utc_offset_hours": args.utc_offset_hours, "short_class_policy": args.short_class_policy}
    if args.schedule:
        kwargs["schedule_path"] = args.schedule
    try:
        report = train_from_flows(args.flows, args.out, smoke=args.smoke, **kwargs)
    except (ModelSecurityError, TrainingError, FileNotFoundError) as exc:
        print(f"[!] Training failed: {exc}")
        sys.exit(2)
    print(f"[+] Trained ({report['mode']}) on {report['total_flows']:,} flows in {report['wall_clock_seconds']:.1f}s")
    print(f"[+] Model + signature + train_report.json written to {args.out}")


def handle_sensor(args: argparse.Namespace) -> None:
    """Sensor process: capture + engine + alert writers. No HTTP."""
    from capture.sensor import Sensor
    from config.logging_config import configure_logging

    configure_logging()
    Sensor().run_capture(getattr(args, "interface", None))


def handle_replay(args: argparse.Namespace) -> None:
    """Replay a PCAP through the sensor pipeline; alerts land in alerts.db."""
    from capture.sensor import Sensor
    from config.logging_config import configure_logging

    configure_logging()
    Sensor().run_replay(args.pcap)


def handle_api(args: argparse.Namespace) -> None:
    """API process: waitress serving the dashboard and API. Needs no capture privileges."""
    import waitress

    from backend.api import app
    from config.logging_config import configure_logging
    from config.settings import MAX_STREAMS
    from database.app_db import initialize_app_database
    from database.database import get_database_path

    configure_logging()
    if API_THREADS < MAX_STREAMS + 4:
        print(
            f"[!] SENTINELX_API_THREADS={API_THREADS} leaves no headroom for {MAX_STREAMS} live streams "
            f"(each holds a thread). Use at least {MAX_STREAMS + 4} threads or lower SENTINELX_MAX_STREAMS."
        )
        sys.exit(2)
    alerts_db = get_database_path()
    if not alerts_db.exists():
        print(
            f"[!] {alerts_db} does not exist. Start the sensor first (python main.py sensor); it creates and migrates it."
        )
        sys.exit(2)
    initialize_app_database()
    from backend.accounts import admin_exists

    if not admin_exists():
        print("[!] No admin user exists, so the API will not serve. Create one first:")
        print("      python main.py user add <name> --role admin")
        sys.exit(2)
    from backend import housekeeping

    housekeeping.start()
    print(f"[+] SentinelX API on http://{API_HOST}:{API_PORT}/ (waitress, {API_THREADS} threads)")
    waitress.serve(app, host=API_HOST, port=API_PORT, threads=API_THREADS)


def handle_run(args: argparse.Namespace) -> None:
    """Local development only: Flask dev server in a thread plus the sensor in this process."""
    if not args.dev:
        print(
            "[!] 'run' is a development mode and needs --dev. For real use run 'sensor' and 'api' as separate processes."
        )
        sys.exit(2)
    from backend.api import app
    from capture.sensor import Sensor
    from config.logging_config import configure_logging
    from database.app_db import initialize_app_database
    from database.database import initialize_database

    configure_logging()
    initialize_database()
    initialize_app_database()
    threading.Thread(
        target=lambda: app.run(host=API_HOST, port=API_PORT, debug=False, use_reloader=False),
        name="FlaskDevServer",
        daemon=True,
    ).start()
    time.sleep(1)
    print(f"[+] DEV MODE dashboard on http://{API_HOST}:{API_PORT}/ (Flask dev server; do not expose)")
    Sensor().run_capture(getattr(args, "interface", None))


def _prompt_password() -> str:
    import getpass

    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        print("[!] Passwords do not match.")
        sys.exit(2)
    return first


def handle_user(args: argparse.Namespace) -> None:
    """User management from the CLI (audited as actor 'cli')."""
    from backend import accounts
    from database.app_db import initialize_app_database

    initialize_app_database()
    try:
        if args.user_command == "add":
            accounts.create_user(args.username, _prompt_password(), args.role)
            print(f"[+] Created {args.role} '{args.username}'.")
        elif args.user_command == "disable":
            accounts.set_disabled(args.username, True)
            print(f"[+] Disabled '{args.username}' and ended their sessions.")
        elif args.user_command == "enable":
            accounts.set_disabled(args.username, False)
            print(f"[+] Enabled '{args.username}'.")
        elif args.user_command == "reset-password":
            accounts.set_password(args.username, _prompt_password())
            print(f"[+] Password changed for '{args.username}'; their sessions were ended.")
        else:
            for u in accounts.list_users():
                print(f"{u['id']:>4}  {u['username']:<24} {u['role']:<8} {'disabled' if u['disabled'] else 'active'}")
    except accounts.AccountError as exc:
        print(f"[!] {exc}")
        sys.exit(2)


def handle_apikey(args: argparse.Namespace) -> None:
    """API key management from the CLI. A new key is printed exactly once."""
    from backend import accounts
    from database.app_db import initialize_app_database

    initialize_app_database()
    try:
        if args.key_command == "create":
            key_id, raw = accounts.create_api_key(args.name, args.role)
            print(f"[+] API key #{key_id} ({args.role}). Store it now; it will not be shown again:")
            print(raw)
        elif args.key_command == "revoke":
            accounts.revoke_api_key(args.key_id)
            print(f"[+] Revoked API key #{args.key_id}.")
        else:
            for k in accounts.list_api_keys():
                state = "revoked" if k["revoked_at"] else "active"
                print(f"{k['id']:>4}  {k['prefix']}...  {k['role']:<8} {state:<8} {k['name']}")
    except accounts.AccountError as exc:
        print(f"[!] {exc}")
        sys.exit(2)


def handle_db(args: argparse.Namespace) -> None:
    """Database maintenance: prune old alerts, or (admin) old audit-log rows."""
    from database.database import get_database_path, get_readonly_connection, parse_age, prune_alerts

    if args.db_command == "prune-audit":
        from backend import accounts
        from config.settings import AUDIT_RETENTION_DAYS
        from database.app_db import initialize_app_database

        if AUDIT_RETENTION_DAYS <= 0:
            print("[+] SENTINELX_AUDIT_RETENTION_DAYS is 0: the audit log is kept forever, nothing to prune.")
            return
        initialize_app_database()
        deleted = accounts.prune_audit(AUDIT_RETENTION_DAYS)
        print(f"[+] Deleted {deleted} audit rows older than {AUDIT_RETENTION_DAYS} days.")
        return

    try:
        age = parse_age(args.older_than)
    except ValueError as exc:
        print(f"[!] {exc}")
        sys.exit(2)
    if not get_database_path().exists():
        print(f"[!] {get_database_path()} does not exist.")
        sys.exit(2)
    cutoff = (datetime.now(UTC) - age).isoformat(timespec="seconds")
    deleted = prune_alerts(cutoff)
    print(f"[+] Deleted {deleted} alerts ingested more than {args.older_than} ago (ingested_at < {cutoff})")
    from backend import accounts
    from database.app_db import get_app_database_path, initialize_app_database

    if get_app_database_path().exists():
        initialize_app_database()
        alerts_conn = get_readonly_connection()
        try:
            orphaned = accounts.prune_orphan_triage(alerts_conn)
        finally:
            alerts_conn.close()
        print(f"[+] Deleted {orphaned} triage rows of removed alerts.")


def main() -> None:
    """Main CLI execution router."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    args = parse_arguments()
    handlers = {
        "sensor": handle_sensor,
        "api": handle_api,
        "run": handle_run,
        "replay": handle_replay,
        "db": handle_db,
        "user": handle_user,
        "apikey": handle_apikey,
        "eval": handle_eval,
        "train": handle_train,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
