# SentinelX

## Network Intrusion Detection & Threat Monitoring System

SentinelX is a hybrid network intrusion detection and threat monitoring system built with Python. It monitors network traffic in real time, analyzes packet-level features, detects suspicious behavior using rule-based detection, and uses machine learning as a secondary confirmation layer.

The project demonstrates practical cybersecurity concepts including network traffic analysis, intrusion detection, packet capture, machine learning, alert logging, database storage, REST APIs, and security monitoring.

---

## Features

- Real-time network packet capture
- Packet parsing using Scapy
- TCP SYN port-scan detection
- High-traffic anomaly detection
- Machine-learning based threat classification
- Hybrid rule-based and ML detection
- JSON alert logging
- SQLite alert storage
- Flask REST API
- Web-based security dashboard
- Automated detection tests
- Configurable detection thresholds

---

## System Architecture

```text
                    Network Traffic
                          |
                          v
                +-------------------+
                |   Packet Capture  |
                |  Scapy + Npcap    |
                +-------------------+
                          |
                          v
                +-------------------+
                |  Packet Parser    |
                | Feature Extraction|
                +-------------------+
                          |
                          v
                +-------------------+
                |   Rule Engine     |
                +-------------------+
                    /           \
                   /             \
                  v               v
          +-------------+   +-------------+
          | Port Scan   |   | High Traffic|
          | Detection   |   | Detection   |
          +-------------+   +-------------+
                  \             /
                   \           /
                    v         v
                Suspicious Behavior
                         |
                         v
                +-------------------+
                | Machine Learning  |
                | Secondary Check   |
                +-------------------+
                         |
                         v
                +-------------------+
                |   Alert Logger    |
                +-------------------+
                    /           \
                   v             v
              alerts.json    SQLite DB
                                |
                                v
                         Flask REST API
                                |
                                v
                         Web Dashboard