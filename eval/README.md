# SentinelX Detection Scenario Suite & Evaluation Benchmark

This module provides a deterministic, seeded synthetic traffic generator and automated evaluation harness for the SentinelX intrusion detection engine.

> [!IMPORTANT]
> **Synthetic Regression Harness Notice:**
> The scenario suite in `eval/` is a regression net on deterministic synthetic traffic designed to enforce that detectors, time windows, state stores, and eviction mechanisms function correctly across builds and in CI.
>
> This benchmark is **NOT a real-world accuracy claim**. Synthetic scenarios with known traffic models do not represent the full complexity, noise, and evasion techniques found in real operational enterprise or carrier networks. Real-world precision, recall, and detection accuracy are evaluated separately on external labelled PCAP datasets (e.g. CIC-IDS, UNSW-NB15) in Phase 5.

---

## Scenarios

1. `benign_web_browsing`: Multiple internal clients initiating complete 3-way handshakes, TLS client/server hello exchanges, and clean teardowns across legitimate web endpoints.
2. `benign_bulk_download`: Sustained transfer (~50 Mbit/s) below the volumetric anomaly threshold.
3. `benign_lan_noise`: Broadcast and multicast discovery traffic (DNS, NTP, mDNS, SSDP) that must not trigger scan or flood alerts.
4. `fast_vertical_scan`: Single attacker probing 30 distinct destination ports in randomized order within 3 seconds.
5. `horizontal_sweep`: Single attacker probing port 445 (SMB) across 20 distinct targets within 2 seconds.
6. `slow_scan`: Stealthy vertical port scan (25 ports spaced 5 seconds apart over 120 seconds) bypassing the short vertical window and caught by the slow scan detector.
7. `syn_flood_spoofed`: 600 client SYN packets targeting port 80 at 200 pps with spoofed source IPs and zero handshake completions.
8. `udp_flood_inbound`: Distributed inbound UDP burst (6,000 packets across 1,000 distinct source IPs in 1 second) exceeding the volumetric ceiling.
9. `mixed`: 10-minute continuous background timeline interleaving legitimate network noise with all 5 attack vectors at designated intervals.

---

## Usage

Run the full evaluation suite and generate reports:

```bash
python main.py eval --scenarios all --out eval_output
```

Evaluate against an external labelled PCAP dataset:

```bash
python main.py eval --pcap traffic.pcap --labels labels.json --out eval_output
```
