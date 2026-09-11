from collections import defaultdict, deque
import time
from typing import Dict, Set, Tuple, Optional

from config.settings import DETECTION_STATE_TTL, MAX_TRACKED_ENTRIES


class HostActivity:
    """Tracks behavioral connection history for a single source IP."""

    def __init__(self, first_seen: float):
        self.first_seen: float = first_seen
        self.last_seen: float = first_seen
        # Deque of SYN connection events: (timestamp, destination_ip, destination_port)
        self.syn_events = deque()
        # Deque of all traffic events: (timestamp, byte_size, destination_ip, protocol)
        self.traffic_events = deque()

    def add_syn_event(self, timestamp: float, destination_ip: str, destination_port: int):
        self.last_seen = timestamp
        self.syn_events.append((timestamp, destination_ip, destination_port))

    def add_traffic_event(self, timestamp: float, byte_size: int, destination_ip: str, protocol: str):
        self.last_seen = timestamp
        self.traffic_events.append((timestamp, byte_size, destination_ip, protocol))

    def prune_syn_events(self, cutoff_time: float):
        while self.syn_events and self.syn_events[0][0] < cutoff_time:
            self.syn_events.popleft()

    def prune_traffic_events(self, cutoff_time: float):
        while self.traffic_events and self.traffic_events[0][0] < cutoff_time:
            self.traffic_events.popleft()


class FlowTracker:
    """
    Session and behavioral flow tracking layer with bounded memory and TTL eviction.
    Tracks connection patterns across source and destination hosts to detect
    vertical and horizontal port scans, as well as volumetric traffic anomalies.
    """

    def __init__(
        self,
        ttl: float = DETECTION_STATE_TTL,
        max_entries: int = MAX_TRACKED_ENTRIES,
    ):
        self.ttl = ttl
        self.max_entries = max_entries
        self.hosts: Dict[str, HostActivity] = {}
        self._last_cleanup = time.time()
        self._cleanup_interval = 10.0  # seconds between opportunistic TTL sweeps

    def record_packet(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: Optional[int],
        protocol: str,
        packet_size: int = 0,
        tcp_syn: bool = False,
        current_time: Optional[float] = None,
    ):
        """Record packet event and update behavioral state."""
        now = current_time if current_time is not None else time.time()

        # Opportunistic TTL sweep
        if now - self._last_cleanup >= self._cleanup_interval:
            self.cleanup_expired(now)
            self._last_cleanup = now

        # Capacity check
        if len(self.hosts) >= self.max_entries and source_ip not in self.hosts:
            self.evict_lru()

        if source_ip not in self.hosts:
            self.hosts[source_ip] = HostActivity(first_seen=now)

        host = self.hosts[source_ip]

        # Record traffic volume
        host.add_traffic_event(now, packet_size, destination_ip, protocol)

        # Record SYN scanning event if TCP SYN
        if tcp_syn and destination_port is not None:
            host.add_syn_event(now, destination_ip, destination_port)

    def get_vertical_scan_ports(
        self,
        source_ip: str,
        destination_ip: str,
        window: float,
        current_time: Optional[float] = None,
    ) -> Set[int]:
        """
        Get unique destination ports targeted on the specific destination IP
        within the sliding time window.
        """
        if source_ip not in self.hosts:
            return set()

        now = current_time if current_time is not None else time.time()
        cutoff = now - window

        host = self.hosts[source_ip]
        host.prune_syn_events(cutoff)

        ports = {
            event[2]
            for event in host.syn_events
            if event[1] == destination_ip and event[0] >= cutoff
        }
        return ports

    def get_horizontal_scan_targets(
        self,
        source_ip: str,
        destination_port: int,
        window: float,
        current_time: Optional[float] = None,
    ) -> Set[str]:
        """
        Get unique destination target IPs targeted on the specific destination port
        within the sliding time window.
        """
        if source_ip not in self.hosts:
            return set()

        now = current_time if current_time is not None else time.time()
        cutoff = now - window

        host = self.hosts[source_ip]
        host.prune_syn_events(cutoff)

        targets = {
            event[1]
            for event in host.syn_events
            if event[2] == destination_port and event[0] >= cutoff
        }
        return targets

    def get_traffic_rate(
        self,
        source_ip: str,
        window: float,
        current_time: Optional[float] = None,
    ) -> Tuple[int, float, int, float, float]:
        """
        Get traffic rate statistics for source IP over sliding window:
        Returns: (packet_count, packet_rate_pps, byte_count, byte_rate_bps, window_duration)
        """
        if source_ip not in self.hosts:
            return 0, 0.0, 0, 0.0, window

        now = current_time if current_time is not None else time.time()
        cutoff = now - window

        host = self.hosts[source_ip]
        host.prune_traffic_events(cutoff)

        packet_count = len(host.traffic_events)
        byte_count = sum(event[1] for event in host.traffic_events)

        effective_window = max(0.1, window)
        packet_rate = packet_count / effective_window
        byte_rate = byte_count / effective_window

        return packet_count, packet_rate, byte_count, byte_rate, effective_window

    def cleanup_expired(self, current_time: Optional[float] = None, ttl: Optional[float] = None) -> int:
        """Purge inactive host entries whose last_seen is older than ttl."""
        now = current_time if current_time is not None else time.time()
        max_age = ttl if ttl is not None else self.ttl
        cutoff = now - max_age

        expired_ips = [
            ip for ip, host in self.hosts.items()
            if host.last_seen < cutoff
        ]

        for ip in expired_ips:
            del self.hosts[ip]

        return len(expired_ips)

    def evict_lru(self, target_count: Optional[int] = None) -> int:
        """Evict oldest entries when max capacity is reached."""
        limit = target_count if target_count is not None else int(self.max_entries * 0.9)
        if len(self.hosts) <= limit:
            return 0

        # Sort by last_seen ascending (oldest first)
        sorted_ips = sorted(self.hosts.keys(), key=lambda ip: self.hosts[ip].last_seen)
        num_to_evict = len(self.hosts) - limit

        evicted = 0
        for ip in sorted_ips[:num_to_evict]:
            del self.hosts[ip]
            evicted += 1

        return evicted

    def clear(self):
        """Reset all tracked state."""
        self.hosts.clear()
        self._last_cleanup = time.time()
