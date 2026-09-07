def extract_features(packet_data):
    """
    Convert parsed packet information into numerical
    features suitable for machine-learning models.
    """

    protocol_map = {
        "TCP": 1,
        "UDP": 2,
        "IP": 3,
        "OTHER": 0
    }

    features = {
        "packet_size": packet_data.get("packet_size", 0),
        "source_port": packet_data.get("source_port") or 0,
        "destination_port": packet_data.get("destination_port") or 0,
        "protocol": protocol_map.get(
            packet_data.get("protocol"),
            0
        ),
        "tcp_syn": int(
            packet_data.get("tcp_syn", False)
        )
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
        "tcp_syn": True
    }

    print("Extracted ML features:")
    print(extract_features(sample_packet))