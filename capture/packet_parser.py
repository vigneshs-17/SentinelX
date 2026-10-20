from typing import Any

from scapy.all import IP, TCP, UDP, IPv6


def parse_packet(packet: Any) -> dict[str, Any]:
    packet_data: dict[str, Any] = {
        "ts": None,
        "source_ip": None,
        "destination_ip": None,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "packet_size": 0,
        "tcp_syn": False,
        "tcp_ack": False,
        "tcp_syn_ack": False,
        "tcp_rst": False,
        "tcp_fin": False,
        "tcp_flags": 0,
    }

    if packet is None:
        return packet_data

    # Extract event timestamp (packet.time)
    try:
        ts_val = getattr(packet, "time", None)
        if ts_val is not None:
            packet_data["ts"] = float(ts_val)
    except (TypeError, ValueError):
        packet_data["ts"] = None

    # Safely extract packet_size if packet supports len()
    try:
        packet_data["packet_size"] = len(packet)
    except (TypeError, AttributeError):
        packet_data["packet_size"] = 0

    # Ensure packet supports Scapy layer membership checking
    try:
        has_ip = IP in packet
        has_ipv6 = IPv6 in packet
    except (TypeError, AttributeError):
        return packet_data

    if has_ip:
        packet_data["source_ip"] = packet[IP].src
        packet_data["destination_ip"] = packet[IP].dst
        default_proto = "IP"
    elif has_ipv6:
        packet_data["source_ip"] = packet[IPv6].src
        packet_data["destination_ip"] = packet[IPv6].dst
        default_proto = "IPv6"
    else:
        return packet_data

    if TCP in packet:
        packet_data["protocol"] = "TCP"
        packet_data["source_port"] = packet[TCP].sport
        packet_data["destination_port"] = packet[TCP].dport

        try:
            tcp_flags = int(packet[TCP].flags)
        except (TypeError, ValueError, AttributeError):
            tcp_flags = 0

        packet_data["tcp_flags"] = tcp_flags
        is_syn = bool(tcp_flags & 0x02)
        is_ack = bool(tcp_flags & 0x10)
        is_rst = bool(tcp_flags & 0x04)
        is_fin = bool(tcp_flags & 0x01)

        packet_data["tcp_syn"] = is_syn and not is_ack
        packet_data["tcp_ack"] = is_ack and not is_syn
        packet_data["tcp_syn_ack"] = is_syn and is_ack
        packet_data["tcp_rst"] = is_rst
        packet_data["tcp_fin"] = is_fin

    elif UDP in packet:
        packet_data["protocol"] = "UDP"
        packet_data["source_port"] = packet[UDP].sport
        packet_data["destination_port"] = packet[UDP].dport

    else:
        packet_data["protocol"] = default_proto

    return packet_data


if __name__ == "__main__":
    print("SentinelX Packet Parser")
    print("Parser module loaded successfully.")
