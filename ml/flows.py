"""
Bidirectional flow extraction shared by ML training (scripts/build_flows.py) and serving (ml/runtime.py).

One module on purpose: the feature vector is computed in exactly one place, so training and serving
cannot drift. Input is the normalized packet dict from capture.packet_parser.parse_packet. Time is event
time only (packet capture timestamps); no wall clock is read anywhere in this module.

Flow table: capped LRU table (detection.state_store.BoundedStateStore, same cap/eviction rules as the
detection engine). Flows are emitted when idle/active timeouts expire, when the table evicts them, or on
flush(). Features are documented in docs/ML_FEATURES.md.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from config.settings import (
    FLOW_ACTIVE_TIMEOUT,
    FLOW_IDLE_TIMEOUT,
    PARTITION_CAP_FLOW_SOURCES,
    PARTITION_CAP_FLOWS,
)
from detection.state_store import BoundedStateStore

FEATURE_NAMES: tuple[str, ...] = (
    "duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_max",
    "iat_mean",
    "iat_std",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "handshake_completed",
    "bytes_per_s",
    "packets_per_s",
    "dst_port_class",
    "is_tcp",
    "src_unique_dst_ports_60s",
    "src_unique_dst_hosts_60s",
)

CONTEXT_WINDOW_SECONDS = 60.0
MIN_RATE_DURATION = 1e-3  # seconds; floor for rate denominators so 1-packet flows stay finite
SOURCE_HISTORY_MAXLEN = 1024  # ponytail: per-source context saturates at 1024 flow starts; raise if scanners need more

_TCP = "TCP"
_UDP = "UDP"

_FIN, _SYN, _RST, _PSH, _ACK = 0x01, 0x02, 0x04, 0x08, 0x10

FlowKey = tuple[str, str, int, int, str]  # (lo_ip, hi_ip, lo_port, hi_port, protocol) canonical, order-independent


def canonical_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> FlowKey:
    """Canonical 5-tuple: both directions of a conversation map to the same key."""
    a, b = (src_ip, src_port), (dst_ip, dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo[0], hi[0], lo[1], hi[1], protocol)


def dst_port_class(port: int) -> int:
    """0 = well-known (<1024), 1 = registered (1024-49151), 2 = ephemeral (>=49152)."""
    if port < 1024:
        return 0
    if port < 49152:
        return 1
    return 2


class _Welford:
    __slots__ = ("m2", "mean", "n")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    def std(self) -> float:
        """Population standard deviation (0.0 for fewer than 2 samples)."""
        return math.sqrt(self.m2 / self.n) if self.n > 1 else 0.0


class _Flow:
    __slots__ = (
        "ack",
        "bwd_bytes",
        "bwd_ip",
        "bwd_pkts",
        "bwd_port",
        "closed",
        "fin",
        "fin_dirs",
        "fwd_bytes",
        "fwd_ip",
        "fwd_pkts",
        "fwd_port",
        "handshake",
        "iat",
        "key",
        "last_ts",
        "len_max",
        "lens",
        "protocol",
        "psh",
        "rst",
        "start_ts",
        "syn",
    )

    def __init__(self, key: FlowKey, pkt: dict[str, Any]) -> None:
        self.key = key
        self.protocol = pkt["protocol"]
        self.fwd_ip, self.bwd_ip = pkt["source_ip"], pkt["destination_ip"]
        self.fwd_port, self.bwd_port = pkt["source_port"], pkt["destination_port"]
        self.start_ts = self.last_ts = float(pkt["ts"])
        self.fwd_pkts = self.bwd_pkts = self.fwd_bytes = self.bwd_bytes = 0
        self.len_max = 0
        self.lens = _Welford()
        self.iat = _Welford()
        self.syn = self.ack = self.fin = self.rst = self.psh = 0
        self.fin_dirs = 0  # bit 0 = fwd FIN seen, bit 1 = bwd FIN seen
        self.handshake = 0  # 0 none, 1 SYN seen, 2 SYN-ACK seen, 3 completed
        self.closed = False

    def add(self, pkt: dict[str, Any], first: bool) -> None:
        ts = float(pkt["ts"])
        size = int(pkt.get("packet_size") or 0)
        is_fwd = pkt["source_ip"] == self.fwd_ip and pkt["source_port"] == self.fwd_port
        if not first:
            self.iat.add(max(0.0, ts - self.last_ts))
        self.last_ts = max(self.last_ts, ts)
        self.start_ts = min(self.start_ts, ts)
        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += size
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += size
        self.lens.add(size)
        self.len_max = max(self.len_max, size)

        if self.protocol != _TCP:
            return
        flags = int(pkt.get("tcp_flags") or 0)
        syn, ack = bool(flags & _SYN), bool(flags & _ACK)
        self.syn += syn
        self.ack += ack
        self.psh += bool(flags & _PSH)
        if flags & _FIN:
            self.fin += 1
            self.fin_dirs |= 1 if is_fwd else 2
        if flags & _RST:
            self.rst += 1
            self.closed = True
        if self.fin_dirs == 3:
            self.closed = True
        if is_fwd and syn and not ack:
            self.handshake = max(self.handshake, 1)
        elif not is_fwd and syn and ack and self.handshake == 1:
            self.handshake = 2
        elif is_fwd and ack and not syn and self.handshake == 2:
            self.handshake = 3


@dataclass(frozen=True)
class FinishedFlow:
    """A completed flow. IPs/ports are metadata for labelling and alerting, never model features."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float
    end_ts: float
    end_reason: str
    features: tuple[float, ...]

    def feature_dict(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.features, strict=True))


class FlowExtractor:
    """Event-time bidirectional flow extractor with a bounded flow table."""

    def __init__(
        self,
        active_timeout: float = FLOW_ACTIVE_TIMEOUT,
        idle_timeout: float = FLOW_IDLE_TIMEOUT,
        max_flows: int = PARTITION_CAP_FLOWS,
        max_sources: int = PARTITION_CAP_FLOW_SOURCES,
    ) -> None:
        if active_timeout <= 0 or idle_timeout <= 0:
            raise ValueError("flow timeouts must be positive")
        self.active_timeout = float(active_timeout)
        self.idle_timeout = float(idle_timeout)
        self._pending: list[tuple[_Flow, str]] = []
        self._table: BoundedStateStore[_Flow] = BoundedStateStore(
            "flows", max_flows, on_evict=lambda _k, flow: self._pending.append((flow, "evicted"))
        )
        self._sources: BoundedStateStore[deque[tuple[float, str, int]]] = BoundedStateStore("flow_sources", max_sources)
        self._clock = 0.0
        self._last_sweep = 0.0
        self._sweep_interval = max(0.5, self.idle_timeout / 3.0)
        self.packets_seen = 0
        self.packets_skipped = 0

    @property
    def table_size(self) -> int:
        return self._table.size()

    @property
    def evictions(self) -> int:
        return self._table.evictions

    def process(self, pkt: dict[str, Any]) -> list[FinishedFlow]:
        """Feed one parsed packet; returns flows that finished as a consequence (possibly none)."""
        self.packets_seen += 1
        ts = pkt.get("ts")
        proto = pkt.get("protocol")
        if (
            ts is None
            or proto not in (_TCP, _UDP)
            or pkt.get("source_ip") is None
            or pkt.get("destination_ip") is None
            or pkt.get("source_port") is None
            or pkt.get("destination_port") is None
        ):
            self.packets_skipped += 1
            return []
        ts = float(ts)
        if ts > self._clock:
            self._clock = ts

        key = canonical_key(pkt["source_ip"], pkt["destination_ip"], pkt["source_port"], pkt["destination_port"], proto)
        flow = self._table.get(key)
        if flow is not None and self._must_restart(flow, pkt, ts):
            self._table.pop(key)
            self._pending.append((flow, self._restart_reason(flow, ts)))
            flow = None
        if flow is None:
            flow = _Flow(key, pkt)
            self._record_source_start(flow, ts)
            flow.add(pkt, first=True)
        else:
            flow.add(pkt, first=False)
        self._table.put(key, flow)

        if self._clock - self._last_sweep >= self._sweep_interval:
            self._sweep()
        return self._drain()

    def flush(self) -> list[FinishedFlow]:
        """Emit every remaining flow (end of capture), oldest first."""
        for key, flow in self._table.items_snapshot():
            self._table.pop(key)
            self._pending.append((flow, "flush"))
        return self._drain()

    def run(self, packets: Iterable[dict[str, Any]]) -> list[FinishedFlow]:
        """Convenience: process an iterable of packet dicts and flush."""
        out: list[FinishedFlow] = []
        for pkt in packets:
            out.extend(self.process(pkt))
        out.extend(self.flush())
        return out

    # -- internals ---------------------------------------------------------------------------------

    def _must_restart(self, flow: _Flow, pkt: dict[str, Any], ts: float) -> bool:
        if ts - flow.last_ts > self.idle_timeout or ts - flow.start_ts > self.active_timeout:
            return True
        # A fresh SYN on a flow that already closed (FIN/FIN or RST) is a new connection reusing the 5-tuple.
        flags = int(pkt.get("tcp_flags") or 0)
        return flow.closed and bool(flags & _SYN) and not flags & _ACK

    def _restart_reason(self, flow: _Flow, ts: float) -> str:
        if ts - flow.last_ts > self.idle_timeout:
            return "idle"
        if ts - flow.start_ts > self.active_timeout:
            return "active"
        return "closed"

    def _sweep(self) -> None:
        self._last_sweep = self._clock
        for _key, flow in self._table.pop_expired_front(self._clock - self.idle_timeout, lambda f: f.last_ts):
            self._pending.append((flow, "idle"))

    def _record_source_start(self, flow: _Flow, ts: float) -> None:
        hist = self._sources.get(flow.fwd_ip)
        if hist is None:
            hist = deque(maxlen=SOURCE_HISTORY_MAXLEN)
        hist.append((ts, flow.bwd_ip, flow.bwd_port))
        self._sources.put(flow.fwd_ip, hist)

    def _context(self, flow: _Flow) -> tuple[int, int]:
        hist = self._sources.get(flow.fwd_ip)
        if not hist:
            return 0, 0
        end = flow.last_ts
        lo = end - CONTEXT_WINDOW_SECONDS
        ports: set[int] = set()
        hosts: set[str] = set()
        for ts, host, port in hist:
            if lo <= ts <= end:
                ports.add(port)
                hosts.add(host)
        return len(ports), len(hosts)

    def _drain(self) -> list[FinishedFlow]:
        if not self._pending:
            return []
        done = [self._finish(flow, reason) for flow, reason in self._pending]
        self._pending.clear()
        return done

    def _finish(self, flow: _Flow, reason: str) -> FinishedFlow:
        if reason in ("idle", "closed") and flow.closed:
            reason = "rst" if flow.rst else "fin"
        duration = flow.last_ts - flow.start_ts
        packets = flow.fwd_pkts + flow.bwd_pkts
        total_bytes = flow.fwd_bytes + flow.bwd_bytes
        rate_den = max(duration, MIN_RATE_DURATION)
        ports, hosts = self._context(flow)
        features = (
            duration,
            float(flow.fwd_pkts),
            float(flow.bwd_pkts),
            float(flow.fwd_bytes),
            float(flow.bwd_bytes),
            flow.lens.mean,
            flow.lens.std(),
            float(flow.len_max),
            flow.iat.mean,
            flow.iat.std(),
            float(flow.syn),
            float(flow.ack),
            float(flow.fin),
            float(flow.rst),
            float(flow.psh),
            1.0 if flow.handshake == 3 else 0.0,
            total_bytes / rate_den,
            packets / rate_den,
            float(dst_port_class(flow.bwd_port)),
            1.0 if flow.protocol == _TCP else 0.0,
            float(ports),
            float(hosts),
        )
        return FinishedFlow(
            src_ip=flow.fwd_ip,
            dst_ip=flow.bwd_ip,
            src_port=flow.fwd_port,
            dst_port=flow.bwd_port,
            protocol=flow.protocol,
            start_ts=flow.start_ts,
            end_ts=flow.last_ts,
            end_reason=reason,
            features=features,
        )
