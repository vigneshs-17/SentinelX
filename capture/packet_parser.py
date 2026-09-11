from scapy.all import IP, IPv6, TCP, UDP


def parse_packet(packet):
    packet_data = {
        "source_ip": None,
        "destination_ip": None,
        "protocol": "OTHER",
        "source_port": None,
        "destination_port": None,
        "packet_size": len(packet),
        "tcp_syn": False
    }

    if IP in packet:
        packet_data["source_ip"] = packet[IP].src
        packet_data["destination_ip"] = packet[IP].dst
        default_proto = "IP"
    elif IPv6 in packet:
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