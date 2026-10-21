"""
Handshake outcome tracking shared by the scan detectors (event time only, bounded state).

A scan probes hosts or ports that do not answer, or answer with RST. Ordinary browsing completes the TCP
handshake. So a destination counts toward a scan only if the attempt did NOT complete:

  SYN seen                      -> attempt recorded (counts as unanswered for now)
  SYN-ACK from the server       -> attempt marked answered (still counts: a half-open scan such as `nmap -sS`
                                   to an open port is answered and then reset by the scanner)
  client ACK on a recorded attempt -> handshake completed: remember (source, destination, port) as completed
  RST                           -> nothing to do: the attempt stays unanswered and keeps counting

Detectors drop a target whose completion is at or after its latest SYN (`completed`), before applying their
threshold. Both tables are capped partitions of the engine's state store, so a SYN flood cannot grow them.
"""

from __future__ import annotations

from typing import Any

from detection.state_store import PartitionedStateStore


class HandshakeTracker:
    def __init__(self, state_store: PartitionedStateStore):
        self.attempts = state_store.get_partition("scan_attempts")
        self.done = state_store.get_partition("scan_completed")

    def observe(self, event: dict[str, Any]) -> None:
        """Update attempt state from one packet. Call once per packet, before the detectors run."""
        if event.get("protocol") != "TCP":
            return
        src, dst = event.get("source_ip"), event.get("destination_ip")
        sport, dport = event.get("source_port"), event.get("destination_port")
        ts = event.get("ts")
        if not src or not dst or sport is None or dport is None or ts is None:
            return

        if event.get("tcp_syn"):
            self.attempts.put((src, sport, dst, dport), {"state": "syn", "last_seen": ts})
        elif event.get("tcp_syn_ack"):
            key = (dst, dport, src, sport)  # the client's 4-tuple
            if key in self.attempts:
                self.attempts.put(key, {"state": "synack", "last_seen": ts})
        elif event.get("tcp_ack"):
            if self.attempts.pop((src, sport, dst, dport)) is not None:
                self.done.put((src, dst, dport), ts)

    def completed(self, source_ip: str, destination_ip: str, port: int, since: float) -> bool:
        """True if a handshake from source to destination:port completed at or after `since`."""
        done_at = self.done.get((source_ip, destination_ip, port))
        return done_at is not None and done_at >= since
