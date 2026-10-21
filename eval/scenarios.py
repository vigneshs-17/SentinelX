"""
Deterministic scenario traffic generator for SentinelX intrusion detection benchmarks.
Generates Scapy packet streams and ground-truth labels at runtime without committing PCAP files.
Byte-identical reproducibility is guaranteed for the same seed.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, UDP, IPv6, Raw, wrpcap

SCENARIO_NAMES = [
    "benign_web_browsing",
    "benign_bulk_download",
    "benign_lan_noise",
    "benign_many_tabs_browsing",
    "benign_slow_browsing_ipv6",
    "benign_background_apps",
    "fast_vertical_scan",
    "horizontal_sweep",
    "slow_scan",
    "slow_horizontal_scan",
    "syn_flood_spoofed",
    "udp_flood_inbound",
    "mixed",
]

DEFAULT_BASE_TS = 1_790_000_000.0


def _build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    flags: str,
    ts: float,
    payload: bytes = b"",
    seq: int = 1000,
    ack: int = 0,
) -> Any:
    """Builds a deterministic TCP packet with exact field definitions."""
    pkt = (
        IP(src=src_ip, dst=dst_ip, id=0, ttl=64, chksum=0)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=8192, chksum=0)
        / Raw(load=payload)
    )
    pkt.time = float(ts)
    return pkt


def _build_tcp6_packet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    flags: str,
    ts: float,
    payload: bytes = b"",
    seq: int = 1000,
    ack: int = 0,
) -> Any:
    """IPv6 twin of _build_tcp_packet."""
    pkt = (
        IPv6(src=src_ip, dst=dst_ip, hlim=64)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=8192, chksum=0)
        / Raw(load=payload)
    )
    pkt.time = float(ts)
    return pkt


def _build_udp_packet(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    ts: float,
    payload: bytes = b"",
) -> Any:
    """Builds a deterministic UDP packet with exact field definitions."""
    pkt = (
        IP(src=src_ip, dst=dst_ip, id=0, ttl=64, chksum=0) / UDP(sport=sport, dport=dport, chksum=0) / Raw(load=payload)
    )
    pkt.time = float(ts)
    return pkt


def generate_benign_web_browsing(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates benign web browsing: multiple internal clients performing complete
    HTTPS handshakes and data exchange to legitimate external servers.
    Expected alerts: 0.
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    clients = [f"192.168.1.{i}" for i in range(10, 15)]
    servers = [
        "93.184.216.34",
        "151.101.1.69",
        "172.217.16.206",
        "104.16.132.229",
    ]

    curr_ts = base_ts
    for client in clients:
        # Each client visits 2 distinct servers
        client_servers = rng.sample(servers, 2)
        for srv in client_servers:
            sport = rng.randint(40000, 60000)
            dport = 443
            # 1. SYN
            packets.append(_build_tcp_packet(client, srv, sport, dport, "S", curr_ts))
            curr_ts += 0.02
            # 2. SYN-ACK
            packets.append(_build_tcp_packet(srv, client, dport, sport, "SA", curr_ts, ack=1001))
            curr_ts += 0.02
            # 3. ACK
            packets.append(_build_tcp_packet(client, srv, sport, dport, "A", curr_ts, seq=1001, ack=2001))
            curr_ts += 0.05
            # 4. Data (Client Hello)
            packets.append(
                _build_tcp_packet(client, srv, sport, dport, "PA", curr_ts, payload=b"\x16\x03\x01" + b"X" * 150)
            )
            curr_ts += 0.05
            # 5. Data (Server Response)
            packets.append(
                _build_tcp_packet(srv, client, dport, sport, "PA", curr_ts, payload=b"\x16\x03\x03" + b"Y" * 600)
            )
            curr_ts += 0.1
            # 6. FIN-ACK from client
            packets.append(_build_tcp_packet(client, srv, sport, dport, "FA", curr_ts))
            curr_ts += 0.02
            # 7. FIN-ACK from server
            packets.append(_build_tcp_packet(srv, client, dport, sport, "FA", curr_ts))
            curr_ts += 0.5

    duration = curr_ts - base_ts
    meta = {"duration_seconds": duration, "benign_duration_seconds": duration}
    return packets, [], meta


def generate_benign_many_tabs_browsing(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Many browser tabs: one IPv4 client and one IPv6 client (NAT64 destinations, as seen on a real capture) each open
    HTTPS connections to 14 different servers on port 443 within about 7 s. Every connection completes the three-way
    handshake, so this is not a scan even though it exceeds the 10-host horizontal threshold.
    Expected alerts: 0.
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    flows = [
        (_build_tcp_packet, "192.168.1.20", [f"203.0.113.{i}" for i in range(10, 24)]),
        (
            _build_tcp6_packet,
            "2409:40f4:2013:6428:5189:4555:6426:7405",
            [f"64:ff9b::2d1f:{i:x}" for i in range(0x8D00, 0x8D0E)],
        ),
    ]
    end_ts = base_ts
    for build, client, servers in flows:
        curr_ts = base_ts + (0.25 if build is _build_tcp6_packet else 0.0)
        for srv in servers:
            sport = rng.randint(40000, 60000)
            packets.append(build(client, srv, sport, 443, "S", curr_ts))
            packets.append(build(srv, client, 443, sport, "SA", curr_ts + 0.03, ack=1001))
            packets.append(build(client, srv, sport, 443, "A", curr_ts + 0.06, seq=1001, ack=2001))
            packets.append(build(client, srv, sport, 443, "PA", curr_ts + 0.1, b"" + b"X" * 150, 1001, 2001))
            packets.append(build(srv, client, 443, sport, "PA", curr_ts + 0.15, b"" + b"Y" * 600, 2001, 1151))
            curr_ts += 0.5
        end_ts = max(end_ts, curr_ts)
    packets.sort(key=lambda p: float(p.time))
    duration = end_ts - base_ts
    return packets, [], {"duration_seconds": duration, "benign_duration_seconds": duration}


def generate_benign_bulk_download(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates a sustained benign download of ~50 Mbit/s (~6.25 MB/s) from a CDN to a local client.
    60s of one server -> one client TCP traffic at ~4,200 packets/s with 1,500-byte packets (~50 Mbit/s),
    starting cold (no prior baseline for that destination).
    Expected alerts: 0.
    """
    packets: list[Any] = []
    server = "198.51.100.20"
    client = "192.168.1.50"
    sport = 443
    dport = 48123

    # Handshake
    curr_ts = base_ts
    packets.append(_build_tcp_packet(client, server, dport, sport, "S", curr_ts))
    curr_ts += 0.001
    packets.append(_build_tcp_packet(server, client, sport, dport, "SA", curr_ts))
    curr_ts += 0.001
    packets.append(_build_tcp_packet(client, server, dport, sport, "A", curr_ts))
    curr_ts += 0.001

    # Bulk transfer: 60 s at ~4,200 packets/s with 1,500-byte packets (1,460 payload) = 252,000 packets
    total_data_packets = 252_000
    pkt_interval = 60.0 / total_data_packets
    template = _build_tcp_packet(server, client, sport, dport, "A", curr_ts, payload=b"D" * 1460)

    for _ in range(total_data_packets):
        pkt = template.copy()
        pkt.time = curr_ts
        packets.append(pkt)
        curr_ts += pkt_interval

    duration = curr_ts - base_ts
    meta = {"duration_seconds": duration, "benign_duration_seconds": duration}
    return packets, [], meta


def generate_benign_lan_noise(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates normal background LAN traffic: DNS, NTP, mDNS, and SSDP multicast.
    Multicast and broadcast traffic is properly ignored by detection.
    Expected alerts: 0.
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    client = "192.168.1.50"
    dns_server = "192.168.1.1"

    curr_ts = base_ts
    for _ in range(20):
        # DNS query and response
        sport = rng.randint(40000, 60000)
        packets.append(_build_udp_packet(client, dns_server, sport, 53, curr_ts, payload=b"\x00\x01dns query"))
        curr_ts += 0.01
        packets.append(_build_udp_packet(dns_server, client, 53, sport, curr_ts, payload=b"\x81\x80dns answer"))
        curr_ts += 0.1

        # NTP query
        packets.append(_build_udp_packet(client, dns_server, 123, 123, curr_ts, payload=b"\x1b" + b"\x00" * 47))
        curr_ts += 0.1

        # mDNS multicast
        packets.append(_build_udp_packet(client, "224.0.0.251", 5353, 5353, curr_ts, payload=b"mdns-discovery"))
        curr_ts += 0.1

        # SSDP multicast
        packets.append(
            _build_udp_packet(client, "239.255.255.250", 1900, 1900, curr_ts, payload=b"M-SEARCH * HTTP/1.1\r\n")
        )
        curr_ts += 0.2

    duration = curr_ts - base_ts
    meta = {"duration_seconds": duration, "benign_duration_seconds": duration}
    return packets, [], meta


def generate_fast_vertical_scan(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates a fast vertical TCP SYN port scan: single attacker probes 30 distinct ports
    on a target host within 3 seconds (random port order, jitter).
    Threshold is 15 ports in 10s (PORT_SCAN_TIME_WINDOW).
    Expected alerts: 1 PORT_SCAN (VERTICAL).
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    attacker = "198.51.100.50"
    victim = "192.168.1.100"

    ports = list(range(20, 50))
    rng.shuffle(ports)

    curr_ts = base_ts
    start_ts = curr_ts
    for port in ports:
        packets.append(_build_tcp_packet(attacker, victim, rng.randint(40000, 60000), port, "S", curr_ts))
        curr_ts += rng.uniform(0.05, 0.15)
    end_ts = curr_ts

    labels = [
        {
            "attack_type": "PORT_SCAN",
            "scan_type": "VERTICAL",
            "attacker_ips": [attacker],
            "victim_ip": victim,
            "victim_port": None,
            "start_ts": start_ts,
            "end_ts": end_ts,
        }
    ]
    meta = {"duration_seconds": end_ts - base_ts, "benign_duration_seconds": 0.0}
    return packets, labels, meta


def generate_horizontal_sweep(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates a horizontal port scan sweep: single attacker probes port 445 (SMB)
    across 20 distinct hosts within 2 seconds.
    Threshold is 10 hosts in 10s (PORT_SCAN_TIME_WINDOW).
    Expected alerts: 1 PORT_SCAN (HORIZONTAL).
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    attacker = "198.51.100.50"
    target_port = 445

    hosts = [f"192.168.1.{i}" for i in range(1, 21)]
    rng.shuffle(hosts)

    curr_ts = base_ts
    start_ts = curr_ts
    for host in hosts:
        packets.append(_build_tcp_packet(attacker, host, rng.randint(40000, 60000), target_port, "S", curr_ts))
        curr_ts += rng.uniform(0.05, 0.15)
    end_ts = curr_ts

    labels = [
        {
            "attack_type": "PORT_SCAN",
            "scan_type": "HORIZONTAL",
            "attacker_ips": [attacker],
            "victim_ip": None,
            "victim_port": target_port,
            "start_ts": start_ts,
            "end_ts": end_ts,
        }
    ]
    meta = {"duration_seconds": end_ts - base_ts, "benign_duration_seconds": 0.0}
    return packets, labels, meta


def generate_slow_scan(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates a stealthy slow port scan: 25 distinct ports probed over 120 seconds (5s intervals).
    Since rate is < 15 ports per 10s window (PORT_SCAN_TIME_WINDOW), Vertical detector does not trigger.
    SlowScanDetector (threshold 20, window 300s) detects it.
    Expected alerts: 1 PORT_SCAN (SLOW).
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    attacker = "198.51.100.50"
    victim = "192.168.1.100"

    ports = list(range(100, 125))
    rng.shuffle(ports)

    curr_ts = base_ts
    start_ts = curr_ts
    for port in ports:
        packets.append(_build_tcp_packet(attacker, victim, rng.randint(40000, 60000), port, "S", curr_ts))
        curr_ts += 5.0
    end_ts = curr_ts

    labels = [
        {
            "attack_type": "PORT_SCAN",
            "scan_type": "SLOW",
            "attacker_ips": [attacker],
            "victim_ip": victim,
            "victim_port": None,
            "start_ts": start_ts,
            "end_ts": end_ts,
        }
    ]
    meta = {"duration_seconds": end_ts - base_ts, "benign_duration_seconds": 0.0}
    return packets, labels, meta


def generate_slow_horizontal_scan(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Stealthy slow horizontal sweep: one source probes SSH (port 22) on 24 hosts, one every 5 s (120 s), below the
    10-host/10 s fast window. Most hosts are silent, some answer RST (closed), two are open and answer SYN-ACK to
    a half-open probe that the scanner resets. No handshake completes. The slow detector must still catch it
    after it started requiring failures to dominate the attempts.
    Expected alerts: 1 PORT_SCAN (SLOW).
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    attacker = "198.51.100.51"
    hosts = [f"192.168.2.{i}" for i in range(1, 25)]
    rng.shuffle(hosts)

    curr_ts = base_ts
    start_ts = curr_ts
    for i, host in enumerate(hosts):
        sport = rng.randint(40000, 60000)
        packets.append(_build_tcp_packet(attacker, host, sport, 22, "S", curr_ts))
        if i % 5 == 1:  # closed port: RST/ACK
            packets.append(_build_tcp_packet(host, attacker, 22, sport, "RA", curr_ts + 0.02, ack=1001))
        elif i % 15 == 2:  # open port: SYN-ACK, then the scanner resets instead of completing
            packets.append(_build_tcp_packet(host, attacker, 22, sport, "SA", curr_ts + 0.02, ack=1001))
            packets.append(_build_tcp_packet(attacker, host, sport, 22, "R", curr_ts + 0.04, seq=1001))
        curr_ts += 5.0
    end_ts = curr_ts

    labels = [
        {
            "attack_type": "PORT_SCAN",
            "scan_type": "SLOW",
            "attacker_ips": [attacker],
            "victim_ip": None,
            "victim_port": 22,
            "start_ts": start_ts,
            "end_ts": end_ts,
        }
    ]
    meta = {"duration_seconds": end_ts - base_ts, "benign_duration_seconds": 0.0}
    return packets, labels, meta


def generate_syn_flood_spoofed(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates a SYN flood attack with spoofed source IPs targeting victim port 80.
    600 SYN packets sent over 3.0 seconds (200 pps >= 100 pps threshold, 0 completions).
    Expected alerts: 1 SYN_FLOOD.
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    victim = "192.168.1.100"
    victim_port = 80

    curr_ts = base_ts
    start_ts = curr_ts
    packet_count = 600
    interval = 3.0 / packet_count

    for _ in range(packet_count):
        spoofed_src = f"198.51.{rng.randint(1, 250)}.{rng.randint(1, 254)}"
        sport = rng.randint(1024, 65535)
        packets.append(_build_tcp_packet(spoofed_src, victim, sport, victim_port, "S", curr_ts))
        curr_ts += interval
    end_ts = curr_ts

    labels = [
        {
            "attack_type": "SYN_FLOOD",
            "scan_type": None,
            "attacker_ips": ["*"],
            "victim_ip": victim,
            "victim_port": victim_port,
            "start_ts": start_ts,
            "end_ts": end_ts,
        }
    ]
    meta = {"duration_seconds": end_ts - base_ts, "benign_duration_seconds": 0.0}
    return packets, labels, meta


def generate_udp_flood_inbound(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates a distributed inbound UDP flood: 35s of warm-up baseline traffic followed by
    6,000 UDP packets from 1,000 distinct source IPs within 1.0 second.
    Expected alerts: 1 VOLUMETRIC.
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    victim = "192.168.1.100"
    victim_port = 8080

    # 1. Warm-up baseline: 35 seconds of gentle background traffic (3 completed 10s windows)
    curr_ts = base_ts
    while curr_ts < (base_ts + 35.0):
        packets.append(
            _build_tcp_packet("192.168.1.50", victim, rng.randint(40000, 60000), 80, "PA", curr_ts, payload=b"normal")
        )
        curr_ts += 1.0

    # 2. Inbound UDP flood burst
    sources = [
        f"203.0.113.{(i % 250) + 1}" if i < 250 else f"198.51.{(i // 250)}.{((i % 250) + 1)}" for i in range(1, 1001)
    ]

    start_ts = curr_ts
    total_packets = 12000
    interval = 2.0 / total_packets
    payload = b"U" * 64

    for i in range(total_packets):
        src_ip = sources[i % len(sources)]
        sport = rng.randint(1024, 65535)
        packets.append(_build_udp_packet(src_ip, victim, sport, victim_port, curr_ts, payload=payload))
        curr_ts += interval
    end_ts = curr_ts

    labels = [
        {
            "attack_type": "VOLUMETRIC",
            "scan_type": None,
            "attacker_ips": ["*"],
            "victim_ip": victim,
            "victim_port": victim_port,
            "start_ts": start_ts,
            "end_ts": end_ts,
        }
    ]
    meta = {"duration_seconds": end_ts - base_ts, "benign_duration_seconds": 35.0}
    return packets, labels, meta


def generate_mixed(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Simulates a 10-minute (600 s) timeline containing background benign traffic
    interleaved with all 5 distinct attack patterns at designated intervals.
    Expected alerts: 5 alerts (1 Vertical, 1 Horizontal, 1 Slow, 1 SYN flood, 1 Volumetric).
    Zero false alerts.
    """
    rng = random.Random(seed)
    all_packets: list[Any] = []
    labels: list[dict[str, Any]] = []

    # 1. Background traffic: 1 packet every 1-2 seconds across 600s
    curr_ts = base_ts
    end_timeline = base_ts + 600.0
    while curr_ts < end_timeline:
        pkt_type = rng.choice(["dns", "web", "victim_req", "ping"])
        if pkt_type == "dns":
            all_packets.append(
                _build_udp_packet("192.168.1.50", "192.168.1.1", rng.randint(40000, 60000), 53, curr_ts, b"dns")
            )
        elif pkt_type == "web":
            sport = rng.randint(40000, 60000)
            all_packets.append(
                _build_tcp_packet("192.168.1.50", "93.184.216.34", sport, 443, "PA", curr_ts, b"http-get")
            )
        elif pkt_type == "victim_req":
            sport = rng.randint(40000, 60000)
            all_packets.append(
                _build_tcp_packet("192.168.1.50", "192.168.1.100", sport, 80, "PA", curr_ts, b"normal-req")
            )
        else:
            all_packets.append(_build_udp_packet("192.168.1.50", "192.168.1.1", 1000, 1000, curr_ts, b"ping"))
        curr_ts += rng.uniform(1.0, 2.5)

    # 2. Embedded Attack 1: Fast Vertical Scan at t = base_ts + 60.0
    pkts_v, lbls_v, _ = generate_fast_vertical_scan(seed=seed + 1, base_ts=base_ts + 60.0)
    all_packets.extend(pkts_v)
    labels.extend(lbls_v)

    # 3. Embedded Attack 2: Horizontal Sweep at t = base_ts + 180.0
    pkts_h, lbls_h, _ = generate_horizontal_sweep(seed=seed + 2, base_ts=base_ts + 180.0)
    all_packets.extend(pkts_h)
    labels.extend(lbls_h)

    # 4. Embedded Attack 3: Slow Scan at t = base_ts + 260.0 (spans 120s to 380s)
    pkts_s, lbls_s, _ = generate_slow_scan(seed=seed + 3, base_ts=base_ts + 260.0)
    all_packets.extend(pkts_s)
    labels.extend(lbls_s)

    # 5. Embedded Attack 4: SYN Flood Spoofed at t = base_ts + 430.0
    pkts_syn, lbls_syn, _ = generate_syn_flood_spoofed(seed=seed + 4, base_ts=base_ts + 430.0)
    all_packets.extend(pkts_syn)
    labels.extend(lbls_syn)

    # 6. Embedded Attack 5: UDP Flood Inbound at t = base_ts + 520.0
    pkts_udp, lbls_udp, _ = generate_udp_flood_inbound(seed=seed + 5, base_ts=base_ts + 520.0)
    all_packets.extend(pkts_udp)
    labels.extend(lbls_udp)

    # Sort all packets deterministically by timestamp
    all_packets.sort(key=lambda p: float(p.time))

    total_duration = 600.0
    benign_duration = total_duration - (3.0 + 2.0 + 120.0 + 3.0 + 1.0)
    meta = {"duration_seconds": total_duration, "benign_duration_seconds": max(0.0, benign_duration)}
    return all_packets, labels, meta


CLIENT_V6 = "2409:40f4:2013:6428:5189:4555:6426:7405"
CLIENT_V4 = "192.168.1.20"


def _v6_host(i: int) -> str:
    return f"2606:4700:{i // 256:x}:{i % 256:x}::443"


def _v4_host(i: int) -> str:
    return f"104.{16 + i // 250}.{i % 250 + 1}.{(i * 7) % 250 + 1}"


def _connect_ok(build: Any, client: str, srv: str, sport: int, ts: float, packets: list[Any]) -> None:
    """A browser connection that completes: SYN, SYN-ACK, ACK, one request/response."""
    packets.append(build(client, srv, sport, 443, "S", ts))
    packets.append(build(srv, client, 443, sport, "SA", ts + 0.04, ack=1001))
    packets.append(build(client, srv, sport, 443, "A", ts + 0.08, seq=1001, ack=2001))
    packets.append(build(client, srv, sport, 443, "PA", ts + 0.12, b"\x16\x03\x01" + b"X" * 120, 1001, 2001))
    packets.append(build(srv, client, 443, sport, "PA", ts + 0.2, b"\x16\x03\x03" + b"Y" * 300, 2001, 1121))


def _connect_unanswered(build: Any, client: str, srv: str, sport: int, ts: float, packets: list[Any]) -> None:
    """A path that never answers (blackholed IPv6 prefix, losing happy-eyeballs address): SYN plus two retransmits."""
    for delay in (0.0, 1.0, 3.0):
        packets.append(build(client, srv, sport, 443, "S", ts + delay, seq=1000))


def _connect_reset(build: Any, client: str, srv: str, sport: int, ts: float, packets: list[Any]) -> None:
    """Server answers SYN-ACK late; the application already gave up, so the client resets."""
    packets.append(build(client, srv, sport, 443, "S", ts))
    packets.append(build(srv, client, 443, sport, "SA", ts + 0.3, ack=1001))
    packets.append(build(client, srv, sport, 443, "R", ts + 0.31, seq=1001))


def generate_benign_slow_browsing_ipv6(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    12 minutes of ordinary browsing from an IPv6 laptop (YouTube, Instagram-style sites with many CDN hosts):
    a new site every 3 s, 240 distinct servers on port 443 in all. Every site is raced over IPv6 and IPv4 (happy
    eyeballs); for 30% of the sites the IPv6 path is dead, so that address never answers and the IPv4 one wins.
    Well over 20 distinct unanswered hosts fall inside every 300 s window, yet 70%+ of the attempts complete.
    Expected alerts: 0.
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    for i in range(240):
        ts = base_ts + i * 3.0
        sport = rng.randint(40000, 60000)
        v6, v4 = _v6_host(i), _v4_host(i)
        if i % 10 in (1, 4, 8):  # 30%: v6 blackholed, v4 wins the race
            _connect_unanswered(_build_tcp6_packet, CLIENT_V6, v6, sport, ts, packets)
            _connect_ok(_build_tcp_packet, CLIENT_V4, v4, sport + 1, ts + 0.25, packets)
        else:
            _connect_ok(_build_tcp6_packet, CLIENT_V6, v6, sport, ts, packets)
    packets.sort(key=lambda p: float(p.time))
    duration = 240 * 3.0
    return packets, [], {"duration_seconds": duration, "benign_duration_seconds": duration}


def generate_benign_background_apps(
    seed: int = 42, base_ts: float = DEFAULT_BASE_TS
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    12 minutes of background applications on a dual-stack laptop: sync clients, ad and telemetry endpoints and
    update checks reaching a new server on 443 every 2.5 s (288 distinct hosts, IPv4 and IPv6 mixed), plus six
    fixed telemetry beacons every 30 s. One attempt in four is abandoned (no answer, or an application that gave
    up so the client resets a late SYN-ACK). More than 20 distinct hosts fail in every 300 s window; 75% succeed.
    Expected alerts: 0.
    """
    rng = random.Random(seed)
    packets: list[Any] = []
    for i in range(288):
        ts = base_ts + i * 2.5
        sport = rng.randint(40000, 60000)
        use_v6 = i % 2 == 0
        build = _build_tcp6_packet if use_v6 else _build_tcp_packet
        client = CLIENT_V6 if use_v6 else CLIENT_V4
        srv = _v6_host(1000 + i) if use_v6 else _v4_host(1000 + i)
        if i % 4 == 3:
            (_connect_unanswered if i % 8 == 3 else _connect_reset)(build, client, srv, sport, ts, packets)
        else:
            _connect_ok(build, client, srv, sport, ts, packets)
    for beat in range(24):
        for b in range(6):
            _connect_ok(
                _build_tcp_packet,
                CLIENT_V4,
                f"198.51.100.{10 + b}",
                rng.randint(40000, 60000),
                base_ts + beat * 30.0 + b * 0.4,
                packets,
            )
    packets.sort(key=lambda p: float(p.time))
    duration = 288 * 2.5
    return packets, [], {"duration_seconds": duration, "benign_duration_seconds": duration}


GENERATORS = {
    "benign_web_browsing": generate_benign_web_browsing,
    "benign_bulk_download": generate_benign_bulk_download,
    "benign_lan_noise": generate_benign_lan_noise,
    "benign_many_tabs_browsing": generate_benign_many_tabs_browsing,
    "benign_slow_browsing_ipv6": generate_benign_slow_browsing_ipv6,
    "benign_background_apps": generate_benign_background_apps,
    "fast_vertical_scan": generate_fast_vertical_scan,
    "horizontal_sweep": generate_horizontal_sweep,
    "slow_scan": generate_slow_scan,
    "slow_horizontal_scan": generate_slow_horizontal_scan,
    "syn_flood_spoofed": generate_syn_flood_spoofed,
    "udp_flood_inbound": generate_udp_flood_inbound,
    "mixed": generate_mixed,
}


def generate_scenario(
    name: str,
    seed: int = 42,
    base_ts: float = DEFAULT_BASE_TS,
) -> tuple[list[Any], list[dict[str, Any]], dict[str, float]]:
    """
    Generates a scenario by name.
    Returns (packets, labels, metadata).
    """
    if name not in GENERATORS:
        raise ValueError(f"Unknown scenario '{name}'. Available: {list(GENERATORS.keys())}")
    return GENERATORS[name](seed=seed, base_ts=base_ts)


def write_scenario_files(
    name: str,
    out_dir: Path | str,
    seed: int = 42,
    base_ts: float = DEFAULT_BASE_TS,
) -> tuple[Path, Path]:
    """
    Generates scenario traffic and writes `{name}.pcap` and `{name}_labels.json` to out_dir.
    Returns (pcap_path, labels_path).
    """
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    packets, labels, _ = generate_scenario(name, seed=seed, base_ts=base_ts)
    pcap_file = out_path / f"{name}.pcap"
    labels_file = out_path / f"{name}_labels.json"

    wrpcap(str(pcap_file), packets)

    import json

    with open(labels_file, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2)

    return pcap_file, labels_file
