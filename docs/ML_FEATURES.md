# ML flow features

Single source of truth: `ml/flows.py` (`FEATURE_NAMES`). The same module builds the training table
(`scripts/build_flows.py`) and the serving vector (`ml/runtime.py`), so the two cannot drift; a test
(`test_train_serve_feature_parity`) compares them on identical packets.

## Flow definition

- Bidirectional, keyed by the canonical 5-tuple (`ml.flows.canonical_key`): both directions of a conversation
  map to one flow. TCP and UDP only (other packets are counted as skipped).
- **Forward** = the direction of the first packet seen for the flow (normally the initiator). If a capture
  starts mid-connection, forward is whichever side was seen first.
- Event time only (packet capture timestamps). No wall clock.
- A flow ends on **idle timeout** (default 15 s with no packet), **active timeout** (default 120 s since the
  first packet), table **eviction** (LRU at the cap, `SENTINELX_CAP_FLOWS`, default 50 000, the same bounded
  store and eviction rule as the detection engine), or **flush** at end of capture. A flow closed by RST or by
  FIN in both directions stays in the table to absorb trailing ACKs; a new pure SYN on that 5-tuple starts a new flow.
- Timeouts are configurable: `SENTINELX_FLOW_ACTIVE_TIMEOUT`, `SENTINELX_FLOW_IDLE_TIMEOUT`.
- Rates use a 1 ms floor on duration so single-packet flows stay finite.
- No raw IP addresses and no raw port numbers are features. IPs/ports are kept only as metadata columns used
  for labelling, alert text and splitting.

## Features (22)

| # | Feature | Definition |
|---|---------|------------|
| 1 | `duration` | Seconds from first to last packet. |
| 2 | `fwd_packets` | Packets in the forward direction. |
| 3 | `bwd_packets` | Packets in the backward direction. |
| 4 | `fwd_bytes` | Sum of captured frame lengths, forward. |
| 5 | `bwd_bytes` | Sum of captured frame lengths, backward. |
| 6 | `pkt_len_mean` | Mean frame length over all packets of the flow. |
| 7 | `pkt_len_std` | Population standard deviation of frame length. |
| 8 | `pkt_len_max` | Largest frame length. |
| 9 | `iat_mean` | Mean inter-arrival time (seconds) between consecutive packets of the flow, both directions; negative gaps from reordering are clamped to 0. 0 for one-packet flows. |
| 10 | `iat_std` | Population standard deviation of inter-arrival time. |
| 11 | `syn_count` | Packets with the SYN flag (SYN and SYN-ACK). 0 for UDP. |
| 12 | `ack_count` | Packets with the ACK flag. |
| 13 | `fin_count` | Packets with the FIN flag. |
| 14 | `rst_count` | Packets with the RST flag. |
| 15 | `psh_count` | Packets with the PSH flag. |
| 16 | `handshake_completed` | 1 if forward SYN, backward SYN-ACK, then forward ACK were seen in order; else 0. |
| 17 | `bytes_per_s` | `(fwd_bytes + bwd_bytes) / max(duration, 0.001)`. |
| 18 | `packets_per_s` | `(fwd_packets + bwd_packets) / max(duration, 0.001)`. |
| 19 | `dst_port_class` | Class of the forward destination port: 0 well-known (<1024), 1 registered (1024-49151), 2 ephemeral (>=49152). The port number itself is not a feature. |
| 20 | `is_tcp` | 1 for TCP, 0 for UDP. |
| 21 | `src_unique_dst_ports_60s` | Distinct destination ports contacted by the flow's source (forward IP) in flows that started in the 60 s ending at this flow's last packet, including this flow. |
| 22 | `src_unique_dst_hosts_60s` | Distinct destination hosts contacted by that source over the same window. |

Features 21-22 are per-source context at flow end. They come from a bounded per-source history
(5 000 sources, 1 024 flow starts each); counts saturate at the history size.

## Known limits

- Frame length (`len(packet)`) is used rather than payload length, so features include link/IP/TCP header bytes.
- Flows are not reassembled across the 120 s active timeout: a long connection becomes several flows.
- A model trained on a capture's addressing quirks (for example NAT) can only learn them through these
  behavioural features, not through addresses; that is deliberate.
