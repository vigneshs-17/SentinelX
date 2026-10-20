"""
PCAP -> labelled flow table (flows.csv.gz). Streaming: PcapReader yields one packet at a time and flows are
written as they finish, so memory is bounded by the flow table cap, never by capture size.

Labels come only from the published attack schedule (ml/dataset.py); third-party CSV labels are not read.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import time
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from scapy.all import PcapReader

from capture.packet_parser import parse_packet
from config.settings import FLOW_ACTIVE_TIMEOUT, FLOW_IDLE_TIMEOUT
from ml.dataset import AttackWindow, label_flow, scenario_windows
from ml.flows import FEATURE_NAMES, FinishedFlow, FlowExtractor

COLUMNS = [
    "file",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "start_ts",
    "end_ts",
    "end_reason",
    "label",
    *FEATURE_NAMES,
]
PROGRESS_EVERY = 1_000_000


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _row(file: str, flow: FinishedFlow, label: str) -> list[Any]:
    return [
        file,
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        flow.protocol,
        repr(flow.start_ts),
        repr(flow.end_ts),
        flow.end_reason,
        label,
        *(repr(v) for v in flow.features),
    ]


def extract_labelled(
    file: str,
    packets: Iterable[Any],
    windows: list[AttackWindow],
    writer: Any,
    active_timeout: float = FLOW_ACTIVE_TIMEOUT,
    idle_timeout: float = FLOW_IDLE_TIMEOUT,
    slack: float = 0.0,
    max_packets: int | None = None,
    progress: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    """Stream packets through FlowExtractor, label each finished flow, write rows. Returns per-file stats."""
    extractor = FlowExtractor(active_timeout=active_timeout, idle_timeout=idle_timeout)
    labels: Counter[str] = Counter()
    n_packets = n_flows = 0
    first_ts: float | None = None
    last_ts: float | None = None

    def write(flows: list[FinishedFlow]) -> None:
        nonlocal n_flows
        for fl in flows:
            lab = label_flow(windows, fl.src_ip, fl.dst_ip, fl.start_ts, slack)
            labels[lab] += 1
            n_flows += 1
            writer.writerow(_row(file, fl, lab))

    for pkt in packets:
        n_packets += 1
        data = parse_packet(pkt)
        ts = data.get("ts")
        if ts is not None:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        write(extractor.process(data))
        if progress and n_packets % PROGRESS_EVERY == 0:
            progress(n_packets)
        if max_packets is not None and n_packets >= max_packets:
            break
    write(extractor.flush())
    return {
        "packets": n_packets,
        "packets_skipped_non_tcp_udp": extractor.packets_skipped,
        "flows": n_flows,
        "evictions": extractor.evictions,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "label_counts": dict(sorted(labels.items())),
    }


def _bind_progress(progress: Callable[[str, int], None] | None, name: str) -> Callable[[int], None] | None:
    if progress is None:
        return None

    def report(n: int) -> None:
        progress(name, n)

    return report


def build_flows(
    pcaps: list[Path],
    windows: list[AttackWindow],
    out_path: Path,
    active_timeout: float = FLOW_ACTIVE_TIMEOUT,
    idle_timeout: float = FLOW_IDLE_TIMEOUT,
    slack: float = 0.0,
    hash_files: bool = True,
    max_packets: int | None = None,
    progress: Callable[[str, int], None] | None = None,
) -> dict[str, Any]:
    """Process existing PCAPs into out_path (csv.gz). Missing files are recorded, not invented."""
    wall = time.perf_counter()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    files_meta: list[dict[str, Any]] = []
    with gzip.open(out_path, "wt", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for pcap in pcaps:
            if not pcap.is_file():
                files_meta.append({"name": pcap.name, "path": str(pcap), "status": "MISSING"})
                continue
            t0 = time.perf_counter()
            with PcapReader(str(pcap)) as reader:
                stats = extract_labelled(
                    pcap.name,
                    reader,
                    windows,
                    writer,
                    active_timeout,
                    idle_timeout,
                    slack,
                    max_packets,
                    _bind_progress(progress, pcap.name),
                )
            files_meta.append(
                {
                    "name": pcap.name,
                    "path": str(pcap),
                    "status": "PROCESSED",
                    "size_bytes": pcap.stat().st_size,
                    "sha256": sha256_file(pcap) if hash_files else None,
                    "seconds": time.perf_counter() - t0,
                    **stats,
                }
            )
    return {
        "output": str(out_path),
        "active_timeout": active_timeout,
        "idle_timeout": idle_timeout,
        "label_slack_seconds": slack,
        "files": files_meta,
        "missing": [m["name"] for m in files_meta if m["status"] == "MISSING"],
        "wall_clock_seconds": time.perf_counter() - wall,
    }


def window_warnings(windows: list[AttackWindow], meta: dict[str, Any]) -> list[str]:
    """Windows that fall inside a processed capture's time span but labelled no flow of their class."""
    warnings = []
    for f in meta["files"]:
        if f.get("status") != "PROCESSED" or f.get("first_ts") is None:
            continue
        for w in windows:
            inside = w.start_ts < f["last_ts"] and w.end_ts > f["first_ts"]
            if inside and f["label_counts"].get(w.cls, 0) == 0:
                warnings.append(
                    f"{f['name']}: window {w.cls} [{w.start_ts:.0f},{w.end_ts:.0f}] labelled 0 flows "
                    "(check --utc-offset-hours and NAT address assumptions)"
                )
    return sorted(set(warnings))


def build_scenario_flows(names: list[str] | str, out_path: Path, seed: int = 42) -> dict[str, Any]:
    """CI smoke path: flows from the Phase 4 synthetic scenarios, labelled from their ground truth."""
    from eval.scenarios import SCENARIO_NAMES, generate_scenario

    targets = (
        list(SCENARIO_NAMES) if names in ("all", ["all"]) else (names.split(",") if isinstance(names, str) else names)
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    files_meta = []
    with gzip.open(out_path, "wt", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for name in targets:
            packets, labels, _ = generate_scenario(name.strip(), seed=seed)
            stats = extract_labelled(name.strip(), packets, scenario_windows(labels), writer)
            files_meta.append({"name": name.strip(), "status": "SYNTHETIC", **stats})
    return {"output": str(out_path), "files": files_meta, "missing": [], "mode": "scenarios"}
