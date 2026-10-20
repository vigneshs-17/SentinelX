"""
Build a labelled flow table from raw PCAPs and the published attack schedule.

    python scripts/build_flows.py D:/datasets/cicids2017/*.pcap --out flows.csv.gz

Streams with scapy PcapReader (never loads a capture into memory). Labels come from the schedule JSON, not from
any third-party CSV. Writes <out> and <out>.meta.json (file sizes, SHA-256, packet/flow/label counts, timings).
Files that do not exist are listed as MISSING in the metadata; nothing is invented.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from config.settings import FLOW_ACTIVE_TIMEOUT, FLOW_IDLE_TIMEOUT  # noqa: E402
from ml.build import build_flows, build_scenario_flows, window_warnings  # noqa: E402
from ml.dataset import DEFAULT_SCHEDULE, load_schedule  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="*", help="PCAP files (processed in the order given)")
    ap.add_argument("--schedule", default=str(DEFAULT_SCHEDULE), help="attack schedule JSON")
    ap.add_argument("--out", default="flows.csv.gz")
    ap.add_argument(
        "--utc-offset-hours", type=float, default=None, help="override the schedule's local-time UTC offset"
    )
    ap.add_argument("--label-slack-seconds", type=float, default=0.0)
    ap.add_argument("--active-timeout", type=float, default=FLOW_ACTIVE_TIMEOUT)
    ap.add_argument("--idle-timeout", type=float, default=FLOW_IDLE_TIMEOUT)
    ap.add_argument("--no-hash", action="store_true", help="skip SHA-256 of input files")
    ap.add_argument("--max-packets", type=int, default=None, help="debug: stop each file after N packets")
    ap.add_argument(
        "--from-scenarios", default=None, help="CI smoke: comma list or 'all' of Phase 4 scenarios instead of PCAPs"
    )
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    out = Path(args.out)
    if args.from_scenarios:
        meta = build_scenario_flows(args.from_scenarios, out, args.seed)
        warnings: list[str] = []
    else:
        if not args.pcaps:
            ap.error("give PCAP paths or --from-scenarios")
        windows = load_schedule(args.schedule, args.utc_offset_hours)
        meta = build_flows(
            [Path(p) for p in args.pcaps],
            windows,
            out,
            args.active_timeout,
            args.idle_timeout,
            args.label_slack_seconds,
            hash_files=not args.no_hash,
            max_packets=args.max_packets,
            progress=lambda name, n: print(f"[*] {name}: {n:,} packets", file=sys.stderr),
        )
        warnings = window_warnings(windows, meta)
    meta["warnings"] = warnings
    meta_path = out.with_name(out.name + ".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    for f in meta["files"]:
        print(f"[{f['status']}] {f['name']}", {k: f[k] for k in ("packets", "flows", "label_counts") if k in f})
    for w in warnings:
        print("[WARN]", w)
    if meta["missing"]:
        print("[WARN] missing files (not processed):", ", ".join(meta["missing"]))
    print(f"[+] wrote {out} and {meta_path} in {meta.get('wall_clock_seconds', 0.0):.1f}s")
    return 0 if any(f["status"] != "MISSING" for f in meta["files"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
