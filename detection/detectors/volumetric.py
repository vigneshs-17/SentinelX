"""
Volumetric Anomaly Detector for SentinelX.

Evaluates inbound traffic aggregate by destination IP across a 10s window.
Uses fixed 1-second ring buckets, EWMA baseline, warm-up gating,
and bounded top-talker tracking (Correction 2, Correction 3).
"""

from typing import Any

from config.settings import (
    LOCAL_NETWORKS,
    THREAT_TYPE_VOLUMETRIC,
    VOLUMETRIC_ALERT_COOLDOWN,
    VOLUMETRIC_EWMA_ALPHA,
    VOLUMETRIC_FLOOR_BPS,
    VOLUMETRIC_FLOOR_PPS,
    VOLUMETRIC_HARD_CEILING_BPS,
    VOLUMETRIC_HARD_CEILING_PPS,
    VOLUMETRIC_MIN_ELAPSED_SEC,
    VOLUMETRIC_MIN_PACKETS,
    VOLUMETRIC_MULTIPLIER_K,
    VOLUMETRIC_TIME_WINDOW,
    VOLUMETRIC_TOP_TALKERS_MAX,
    VOLUMETRIC_WARMUP_WINDOWS,
)
from detection.alert import Alert
from detection.detectors.base import BaseDetector
from detection.scoring import calculate_confidence, calculate_severity
from detection.state_store import PartitionedStateStore
from detection.utils import is_ip_in_networks, is_multicast_or_broadcast


class VolumetricAnomalyDetector(BaseDetector):
    """
    Detects distributed and volumetric DDoS/flood anomalies targeted at destination hosts.
    Inbound aggregate across all sources is keyed by destination_ip.
    """

    VERSION = "VolumetricAnomalyDetector v2.0"

    def __init__(self, config: dict[str, Any], state_store: PartitionedStateStore):
        super().__init__(config, state_store)
        self.store = state_store.get_partition("volumetric")
        self.window = float(self.config.get("VOLUMETRIC_TIME_WINDOW", VOLUMETRIC_TIME_WINDOW))
        self.alpha = float(self.config.get("VOLUMETRIC_EWMA_ALPHA", VOLUMETRIC_EWMA_ALPHA))
        self.warmup_windows = int(self.config.get("VOLUMETRIC_WARMUP_WINDOWS", VOLUMETRIC_WARMUP_WINDOWS))
        self.ceiling_pps = float(self.config.get("VOLUMETRIC_HARD_CEILING_PPS", VOLUMETRIC_HARD_CEILING_PPS))
        self.ceiling_bps = float(self.config.get("VOLUMETRIC_HARD_CEILING_BPS", VOLUMETRIC_HARD_CEILING_BPS))
        self.floor_pps = float(self.config.get("VOLUMETRIC_FLOOR_PPS", VOLUMETRIC_FLOOR_PPS))
        self.floor_bps = float(self.config.get("VOLUMETRIC_FLOOR_BPS", VOLUMETRIC_FLOOR_BPS))
        self.multiplier_k = float(self.config.get("VOLUMETRIC_MULTIPLIER_K", VOLUMETRIC_MULTIPLIER_K))
        self.min_packets = int(self.config.get("VOLUMETRIC_MIN_PACKETS", VOLUMETRIC_MIN_PACKETS))
        self.min_elapsed = float(self.config.get("VOLUMETRIC_MIN_ELAPSED_SEC", VOLUMETRIC_MIN_ELAPSED_SEC))
        self.cooldown = float(self.config.get("VOLUMETRIC_ALERT_COOLDOWN", VOLUMETRIC_ALERT_COOLDOWN))
        self.top_talkers_max = int(self.config.get("VOLUMETRIC_TOP_TALKERS_MAX", VOLUMETRIC_TOP_TALKERS_MAX))

        local_nets_cfg = self.config.get("LOCAL_NETWORKS", LOCAL_NETWORKS)
        if isinstance(local_nets_cfg, str):
            self.local_networks = [c.strip() for c in local_nets_cfg.split(",") if c.strip()]
        else:
            self.local_networks = list(local_nets_cfg or [])

    def observe(self, event: dict[str, Any], engine_clock: float) -> list[Alert]:
        destination_ip = event.get("destination_ip")
        source_ip = event.get("source_ip")
        protocol = event.get("protocol")
        packet_size = event.get("packet_size", 60)
        event_time = event.get("ts", engine_clock)

        if not destination_ip:
            return []
        if is_multicast_or_broadcast(destination_ip):
            return []
        if self.local_networks and not is_ip_in_networks(destination_ip, self.local_networks):
            return []

        curr_sec = int(event_time)
        window_sec = int(self.window)

        entry = self.store.get(destination_ip)
        if entry is None:
            entry = {
                "completed_windows": 0,
                "ewma_pps": 0.0,
                "ewma_bps": 0.0,
                "window_start_sec": curr_sec,
                "buckets": {},  # sec -> {"packets": int, "bytes": int}
                "talkers": {},  # src_ip -> int
                "first_seen": event_time,
                "last_seen": event_time,
            }

        buckets: dict[int, dict[str, int]] = entry["buckets"]
        talkers: dict[str, int] = entry["talkers"]

        # Check completed window transition for EWMA update
        window_start_sec = entry["window_start_sec"]
        if curr_sec - window_start_sec >= window_sec:
            # Window completed: calculate average over completed window
            w_packets = sum(
                b["packets"] for s, b in buckets.items() if window_start_sec <= s < (window_start_sec + window_sec)
            )
            w_bytes = sum(
                b["bytes"] for s, b in buckets.items() if window_start_sec <= s < (window_start_sec + window_sec)
            )
            w_pps = w_packets / self.window
            w_bps = w_bytes / self.window

            comp = entry["completed_windows"]
            if comp == 0:
                entry["ewma_pps"] = w_pps
                entry["ewma_bps"] = w_bps
            else:
                entry["ewma_pps"] = self.alpha * w_pps + (1.0 - self.alpha) * entry["ewma_pps"]
                entry["ewma_bps"] = self.alpha * w_bps + (1.0 - self.alpha) * entry["ewma_bps"]

            entry["completed_windows"] += 1
            entry["window_start_sec"] = curr_sec
            # Reset talkers periodically on window rotation
            talkers.clear()

        # Prune ring buckets older than sliding window
        min_sec = curr_sec - window_sec
        entry["buckets"] = {s: b for s, b in buckets.items() if s > min_sec}
        buckets = entry["buckets"]

        # Record packet into current 1s bucket
        if curr_sec not in buckets:
            buckets[curr_sec] = {"packets": 0, "bytes": 0}
        buckets[curr_sec]["packets"] += 1
        buckets[curr_sec]["bytes"] += packet_size

        # Record top talker (bounded)
        if source_ip:
            if source_ip in talkers:
                talkers[source_ip] += 1
            elif len(talkers) < self.top_talkers_max:
                talkers[source_ip] = 1

        entry["last_seen"] = event_time
        self.store.put(destination_ip, entry)

        # -------------------------------------------------------------
        # Evaluation Gate
        # -------------------------------------------------------------
        tot_packets = sum(b["packets"] for b in buckets.values())
        tot_bytes = sum(b["bytes"] for b in buckets.values())
        min_bucket_sec = min(buckets.keys()) if buckets else curr_sec
        elapsed = max(self.min_elapsed, min(self.window, float(curr_sec - min_bucket_sec + 1)))

        if tot_packets < self.min_packets or elapsed < self.min_elapsed:
            return []

        curr_pps = tot_packets / elapsed
        curr_bps = tot_bytes / elapsed

        completed = entry["completed_windows"]
        is_anomaly = False
        thresh_pps = self.ceiling_pps
        thresh_bps = self.ceiling_bps

        if completed < self.warmup_windows:
            # Warm-up phase: only hard ceiling triggers
            if curr_pps >= self.ceiling_pps or curr_bps >= self.ceiling_bps:
                is_anomaly = True
                thresh_pps = self.ceiling_pps
                thresh_bps = self.ceiling_bps
        else:
            # Post warm-up phase: alert when rate > max(floor, k * EWMA)
            thresh_pps = max(self.floor_pps, self.multiplier_k * entry["ewma_pps"])
            thresh_bps = max(self.floor_bps, self.multiplier_k * entry["ewma_bps"])

            if (
                curr_pps > thresh_pps
                or curr_bps > thresh_bps
                or curr_pps >= self.ceiling_pps
                or curr_bps >= self.ceiling_bps
            ):
                is_anomaly = True

        if not is_anomaly:
            return []

        # Check cooldown
        cooldown_key = ("VOLUMETRIC", destination_ip)
        if self.is_in_cooldown(cooldown_key, event_time, self.cooldown):
            return []

        self.record_cooldown(cooldown_key, event_time)

        # Top 5 source IPs by packet count
        top_talkers_list: list[dict[str, Any]] = sorted(
            [{"source_ip": str(ip), "packet_count": int(count)} for ip, count in talkers.items()],
            key=lambda x: x["packet_count"],  # type: ignore[arg-type, return-value]
            reverse=True,
        )[:5]

        ratio_pps = curr_pps / max(1.0, thresh_pps)
        ratio_bps = curr_bps / max(1.0, thresh_bps)
        max_ratio = max(ratio_pps, ratio_bps)

        severity = calculate_severity(max_ratio, 1.0)
        confidence = calculate_confidence(max_ratio, 1.0)

        evidence = {
            "destination_ip": destination_ip,
            "window_seconds": self.window,
            "packet_count": tot_packets,
            "total_bytes": tot_bytes,
            "packet_rate_pps": round(curr_pps, 1),
            "packet_rate_threshold_pps": round(thresh_pps, 1),
            "byte_rate_bps": round(curr_bps, 1),
            "byte_rate_threshold_bps": round(thresh_bps, 1),
            "ewma_pps": round(entry["ewma_pps"], 1),
            "ewma_bps": round(entry["ewma_bps"], 1),
            "completed_warmup_windows": completed,
            "top_talkers": top_talkers_list,
        }

        primary_source: str | None = (
            str(top_talkers_list[0]["source_ip"]) if top_talkers_list else (str(source_ip) if source_ip else None)
        )

        alert = Alert(
            threat_type=THREAT_TYPE_VOLUMETRIC,
            scan_type=None,
            severity=severity,
            confidence=confidence,
            detector=self.VERSION,
            first_seen=entry["first_seen"],
            last_seen=event_time,
            source_ip=primary_source,
            destination_ip=destination_ip,
            protocol=protocol or "IP",
            evidence=evidence,
            message=(
                f"Volumetric anomaly detected targeting {destination_ip} "
                f"({curr_pps:.1f} pps, {curr_bps / 1000000.0:.1f} MB/s in {self.window:.0f}s)"
            ),
        )
        return [alert]
