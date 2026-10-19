def extract_features(packet_data):
    """
    Convert parsed packet information into numerical
    features suitable for machine-learning models.
    """

    protocol_map = {"TCP": 1, "UDP": 2, "IP": 3, "OTHER": 0}

    raw_packet_size = packet_data.get("packet_size")
    raw_tcp_syn = packet_data.get("tcp_syn")

    features = {
        "packet_size": int(raw_packet_size) if raw_packet_size is not None else 0,
        "source_port": int(packet_data.get("source_port") or 0),
        "destination_port": int(packet_data.get("destination_port") or 0),
        "protocol": protocol_map.get(packet_data.get("protocol"), 0),
        "tcp_syn": int(bool(raw_tcp_syn)) if raw_tcp_syn is not None else 0,
    }

    return features


if __name__ == "__main__":
    sample_packet = {
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 443,
        "packet_size": 60,
        "tcp_syn": True,
    }

    print("Extracted ML features:")
    print(extract_features(sample_packet))
