import random
import pandas as pd
from pathlib import Path


random.seed(42)


def generate_normal_samples(count=1000):
    samples = []

    for _ in range(count):
        protocol = random.choice([1, 2])
        packet_size = random.randint(40, 1500)
        source_port = random.randint(1024, 65535)
        destination_port = random.choice(
            [53, 80, 443, 22, 123]
        )

        samples.append([
            packet_size,
            source_port,
            destination_port,
            protocol,
            0,
            "NORMAL"
        ])

    return samples


def generate_port_scan_samples(count=500):
    samples = []

    for _ in range(count):
        packet_size = random.randint(40, 100)
        source_port = random.randint(1024, 65535)
        destination_port = random.randint(1, 1024)
        protocol = 1
        tcp_syn = 1

        samples.append([
            packet_size,
            source_port,
            destination_port,
            protocol,
            tcp_syn,
            "PORT_SCAN"
        ])

    return samples


def generate_high_traffic_samples(count=500):
    samples = []

    for _ in range(count):
        protocol = random.choice([1, 2])
        packet_size = random.randint(500, 1500)
        source_port = random.randint(1024, 65535)
        destination_port = random.choice(
            [53, 80, 443]
        )

        samples.append([
            packet_size,
            source_port,
            destination_port,
            protocol,
            0,
            "HIGH_TRAFFIC"
        ])

    return samples


def create_dataset():
    normal = generate_normal_samples()
    port_scan = generate_port_scan_samples()
    high_traffic = generate_high_traffic_samples()

    all_samples = normal + port_scan + high_traffic

    columns = [
        "packet_size",
        "source_port",
        "destination_port",
        "protocol",
        "tcp_syn",
        "label"
    ]

    dataset = pd.DataFrame(
        all_samples,
        columns=columns
    )

    output_path = (
        Path(__file__).parent / "network_traffic.csv"
    )

    dataset.to_csv(output_path, index=False)

    print("[+] Dataset created successfully.")
    print(f"[+] Total samples: {len(dataset)}")
    print(f"[+] Saved to: {output_path}")
    print("\n[+] Class distribution:")
    print(dataset["label"].value_counts())


if __name__ == "__main__":
    create_dataset()