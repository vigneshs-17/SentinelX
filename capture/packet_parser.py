from scapy.all import IP, IPv6, TCP, UDP


def parse_packet(packet):
    packet_data = {
        "source_ip": None,
        "destination_ip": None,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "packet_size": 0,
        "tcp_syn": False,
    }

    if packet is None:
        return packet_data

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

        # Detect TCP SYN packets without ACK
        tcp_flags = int(packet[TCP].flags)

        if (tcp_flags & 0x02) and not (tcp_flags & 0x10):
            packet_data["tcp_syn"] = True

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