"""
Stateful SYN Flood Detector with isolated aggregates and half-open connection tracking.

Uses fixed 1-second ring buckets over the sliding window to evaluate SYN arrival rate
and handshake completion ratio (Correction 3).
"""

from typing import Any

from config.settings import (
    SYN_FLOOD_ALERT_COOLDOWN,
    SYN_FLOOD_COMPLETION_RATIO,
    SYN_FLOOD_HALF_OPEN_TTL,
    SYN_FLOOD_THRESHOLD,
    SYN_FLOOD_TIME_WINDOW,
    THREAT_TYPE_SYN_FLOOD,
)
from detection.alert import Alert
from detection.detectors.base import BaseDetector
from detection.scoring import calculate_confidence, calculate_severity
from detection.state_store import PartitionedStateStore
from detection.utils import is_multicast_or_broadcast


class SynFloodDetector(BaseDetector):
    """
    Detects TCP SYN Flood attacks by tracking:
    1. Aggregates per (destination_ip, destination_port) in 'syn_flood_aggregates'.
    2. Half-open 4-tuples in 'syn_flood_half_open'.
    3. Cooldown suppression in 'cooldowns'.
    """

    VERSION = "SynFloodDetector v2.0"

    def __init__(self, config: dict[str, Any], state_store: PartitionedStateStore):
        super().__init__(config, state_store)
        self.aggregates = state_store.get_partition("syn_flood_aggregates")
        self.half_open = state_store.get_partition("syn_flood_half_open")
        self.threshold = int(self.config.get("SYN_FLOOD_THRESHOLD", SYN_FLOOD_THRESHOLD))
        self.window = float(self.config.get("SYN_FLOOD_TIME_WINDOW", SYN_FLOOD_TIME_WINDOW))
        self.completion_ratio_thresh = float(self.config.get("SYN_FLOOD_COMPLETION_RATIO", SYN_FLOOD_COMPLETION_RATIO))
        self.cooldown = float(self.config.get("SYN_FLOOD_ALERT_COOLDOWN", SYN_FLOOD_ALERT_COOLDOWN))
        self.half_open_ttl = float(self.config.get("SYN_FLOOD_HALF_OPEN_TTL", SYN_FLOOD_HALF_OPEN_TTL))

    def observe(self, event: dict[str, Any], engine_clock: float) -> list[Alert]:
        protocol = event.get("protocol")
        if protocol != "TCP":
            return []

        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        source_port = event.get("source_port")
        destination_port = event.get("destination_port")
        event_time = event.get("ts", engine_clock)

        if not source_ip or not destination_ip or destination_port is None:
            return []
        if is_multicast_or_broadcast(destination_ip):
            return []

        tcp_syn = event.get("tcp_syn", False)
        tcp_ack = event.get("tcp_ack", False)
        tcp_rst = event.get("tcp_rst", False)

        curr_sec = int(event_time)
        window_sec = int(self.window)

        # -------------------------------------------------------------
        # 1. Connection Lifecycle Tracking
        # -------------------------------------------------------------
        # Forward 4-tuple from client to server
        fwd_tuple = (source_ip, source_port, destination_ip, destination_port)
        # Reverse 4-tuple from server to client
        rev_tuple = (destination_ip, destination_port, source_ip, source_port)

        agg_key = (destination_ip, destination_port)
        agg_entry = self.aggregates.get(agg_key)
        if agg_entry is None:
            agg_entry = {
                "buckets": {},  # sec -> {"syns": int, "acks": int}
                "first_seen": event_time,
                "last_seen": event_time,
            }

        buckets: dict[int, dict[str, int]] = agg_entry["buckets"]
        # Prune buckets older than window
        min_sec = curr_sec - window_sec
        agg_entry["buckets"] = {s: b for s, b in buckets.items() if s > min_sec}
        buckets = agg_entry["buckets"]

        if curr_sec not in buckets:
            buckets[curr_sec] = {"syns": 0, "acks": 0}

        if tcp_syn:
            # Client SYN initiation
            self.half_open.put(fwd_tuple, event_time)
            buckets[curr_sec]["syns"] += 1
            agg_entry["last_seen"] = event_time
            self.aggregates.put(agg_key, agg_entry)

        elif tcp_ack:
            # Check if this ACK completes a previously half-open connection
            # If client ACKing server:
            if self.half_open.pop(fwd_tuple, None) is not None:
                buckets[curr_sec]["acks"] += 1
                agg_entry["last_seen"] = event_time
                self.aggregates.put(agg_key, agg_entry)
            # Or if it's the 3-way handshake final ACK
            elif self.half_open.pop(rev_tuple, None) is not None:
                rev_agg_key = (source_ip, source_port)
                rev_agg = self.aggregates.get(rev_agg_key)
                if rev_agg:
                    rev_buckets = rev_agg.get("buckets", {})
                    if curr_sec in rev_buckets:
                        rev_buckets[curr_sec]["acks"] += 1

        elif tcp_rst:
            # RST packet closes half-open connection
            self.half_open.pop(fwd_tuple, None)
            self.half_open.pop(rev_tuple, None)

        # -------------------------------------------------------------
        # 2. Threshold & Anomaly Evaluation
        # -------------------------------------------------------------
        total_syns = sum(b["syns"] for b in buckets.values())
        total_acks = sum(b["acks"] for b in buckets.values())

        if total_syns < self.threshold:
            return []

        elapsed = max(1.0, min(self.window, event_time - agg_entry["first_seen"]))
        syn_rate = total_syns / elapsed
        completion_ratio = total_acks / max(1, total_syns)

        if syn_rate >= self.threshold and completion_ratio < self.completion_ratio_thresh:
            cooldown_key = ("SYN_FLOOD", destination_ip, destination_port)
            if not self.is_in_cooldown(cooldown_key, event_time, self.cooldown):
                self.record_cooldown(cooldown_key, event_time)

                severity = calculate_severity(syn_rate, self.threshold)
                confidence = calculate_confidence(syn_rate, self.threshold)

                evidence = {
                    "syn_rate_pps": round(syn_rate, 1),
                    "threshold_pps": self.threshold,
                    "total_syns": total_syns,
                    "total_acks": total_acks,
                    "completion_ratio": round(completion_ratio, 3),
                    "completion_ratio_threshold": self.completion_ratio_thresh,
                    "window_seconds": self.window,
                    "target_host": destination_ip,
                    "target_port": destination_port,
                }

                alert = Alert(
                    threat_type=THREAT_TYPE_SYN_FLOOD,
                    scan_type=None,
                    severity=severity,
                    confidence=confidence,
                    detector=self.VERSION,
                    first_seen=agg_entry["first_seen"],
                    last_seen=event_time,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    protocol="TCP",
                    evidence=evidence,
                    message=(
                        f"TCP SYN flood detected targeting {destination_ip}:{destination_port} "
                        f"({syn_rate:.1f} SYN pps, completion ratio {completion_ratio:.1%} in {self.window:.0f}s)"
                    ),
                )
                return [alert]

        return []
