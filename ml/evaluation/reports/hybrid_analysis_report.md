# SentinelX Architecture: Rule vs. Machine Learning vs. Hybrid Analysis

## 1. Executive Summary
SentinelX combines deterministic, stateful rule heuristics (Phase 3) with secondary
statistical machine learning verification (Phase 4). This experiment benchmarks
how each component behaves individually versus when operating in SentinelX's hybrid architecture.

## 2. Experimental Scenarios

| Traffic Scenario | Injected Packets | Ground Truth | ML-Only Behavior | Rule-Only Behavior | Hybrid Pipeline Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Vertical Port Scan** | 15 TCP SYNs | Attack (`PORT_SCAN`) | 15 individual alerts | 1 coordinated event alert | 1 Confirmed Alert (`ml_confirmed=True`) |
| **High-Traffic Volumetric Flood** | 1050 Packets | Attack (`HIGH_TRAFFIC`) | 1050 packet flags | 1 volumetric alert (with pps/Bps) | 1 Confirmed Alert (`ml_confirmed=True`) |
| **Benign Single HTTPS Packet** | 1 Packet (1400B) | Normal Traffic | Single-packet inference | Zero Alerts (Volume < threshold) | Zero Alerts (Gated by rule engine) |

## 3. Key Findings

### A. Technical Scope: ML-Only Packet-Level Detection is Unsuitable for Reliable Volumetric Detection in the Current SentinelX Architecture
- **Lack of State & Temporal Context**: Machine learning on isolated packets has no memory of connection history. It cannot distinguish an isolated 1400-byte HTTPS packet from an ongoing Denial of Service flood.
- **Alert Fatigue**: Standalone packet-by-packet ML would emit individual alerts for every packet during a flood, generating severe alert fatigue rather than identifying a single aggregated security incident.

### B. Why Rules Alone Are Vulnerable
- Deterministic rules rely on static thresholds. Slow or low-rate attacks positioned just below thresholds evade rule matching.

### C. The Strength of the SentinelX Hybrid Model
- **Production Pipeline Gating**: In SentinelX's production packet capture pipeline (`capture/packet_capture.py`), ML inference is only invoked after a rule-based alert triggers (`rule_alert is not None`). If traffic remains below rule thresholds, the callback returns early (`return None`) without invoking ML inference.
- **Secondary Verification**: When a rule does trigger, ML acts as an independent sanity check on packet header characteristics.
- **False Alarm Containment**: Because the stateful rule engine gates execution in the production capture pipeline, isolated benign packets that might match high-traffic packet profiles never trigger unverified alerts during normal operations.