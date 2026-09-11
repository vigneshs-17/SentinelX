from collections import defaultdict
import sys
import time
from scapy.all import sniff

from capture.packet_parser import parse_packet
from capture.pipeline import PacketPipeline
from config.settings import CAPTURE_INTERFACE, ML_ALERT_COOLDOWN
from detection.rule_engine import detect_port_scan
from detection.traffic_rules import detect_high_traffic
from logs.alert_logger import log_alert
from ml.predictor import predict_threat


last_ml_alert = defaultdict(float)


def safe_print(*args, **kwargs):
    """Safely print to stdout, handling Windows charmap/cp1252 encoding limitations."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        clean_args = [
            str(arg).encode(encoding, errors="backslashreplace").decode(encoding, errors="ignore")
            for arg in args
        ]
        print(*clean_args, **kwargs)


# =========================================================
# PACKET PROCESSOR (Worker Consumer Logic)
# =========================================================

def process_packet(packet):
    """
    Full packet processing executed asynchronously by pipeline worker(s).
    Performs header parsing, rule engine checks, ML secondary check,
    and alert logging.
    """
    packet_data = parse_packet(packet)

    safe_print(
        f"[PACKET] "
        f"{packet_data['source_ip']} -> "
        f"{packet_data['destination_ip']} | "
        f"{packet_data['protocol']} | "
        f"{packet_data['source_port']} -> "
        f"{packet_data['destination_port']} | "
        f"Size: {packet_data['packet_size']} bytes"
    )

    # =====================================================
    # RULE-BASED DETECTION
    # =====================================================
    port_scan_alert = detect_port_scan(packet_data)
    traffic_alert = detect_high_traffic(packet_data)
    rule_alert = port_scan_alert or traffic_alert

    # Normal traffic does not need ML inference
    if rule_alert is None:
        safe_print("[ML] No rule-based threat detected")
        return None

    # =====================================================
    # RULE ALERT FOUND - RUN SECONDARY ML CONFIRMATION
    # =====================================================
    threat_type = rule_alert["threat_type"]
    source_ip = rule_alert.get("source_ip", packet_data["source_ip"])
    ml_prediction = None

    try:
        ml_prediction = predict_threat(packet_data)
    except Exception as error:
        safe_print(f"[ML ERROR] {error}")

    # =====================================================
    # ML CONFIRMS RULE ALERT
    # =====================================================
    if ml_prediction is not None and ml_prediction == threat_type:
        confirmed_alert = {
            "threat_type": threat_type,
            "severity": rule_alert["severity"],
            "source_ip": source_ip,
            "destination_ip": packet_data["destination_ip"],
            "protocol": packet_data["protocol"],
            "message": (
                f"Rule engine and machine learning "
                f"model both detected possible "
                f"{threat_type}"
            ),
        }

        safe_print(
            f"\n[ALERT - CONFIRMED] "
            f"{threat_type} | "
            f"Severity: {confirmed_alert['severity']} | "
            f"Source: {source_ip}"
        )
        log_alert(confirmed_alert)
        return confirmed_alert

    # =====================================================
    # RULE DETECTED BUT ML DID NOT CONFIRM
    # =====================================================
    rule_alert["destination_ip"] = packet_data["destination_ip"]
    rule_alert["protocol"] = packet_data["protocol"]

    safe_print(
        f"\n[ALERT - RULE] "
        f"{threat_type} | "
        f"Severity: {rule_alert['severity']} | "
        f"Source: {source_ip}"
    )
    log_alert(rule_alert)
    return rule_alert


# Global pipeline instance initialized with process_packet worker
pipeline = PacketPipeline(processor=process_packet)


# =========================================================
# LIGHTWEIGHT CAPTURE CALLBACK (Producer)
# =========================================================

def packet_callback(packet):
    """
    Lightweight capture callback for Scapy sniff.
    Enqueues the packet into the bounded queue and returns immediately.
    """
    return pipeline.enqueue(packet)


# =========================================================
# START PACKET CAPTURE
# =========================================================

def start_capture(iface=None, pipeline_instance=None):
    """
    Start packet capture using the decoupled producer-consumer pipeline.
    """
    active_pipeline = pipeline_instance or pipeline
    interface = iface or CAPTURE_INTERFACE

    safe_print("[*] SentinelX IDS started...")
    safe_print(
        f"[*] Mode: Producer-Consumer (Queue size: {active_pipeline.maxsize}, "
        f"Workers: {active_pipeline.worker_count})"
    )
    if interface:
        safe_print(f"[*] Interface: {interface}")
    safe_print("[*] Monitoring network traffic...")
    safe_print("[*] Press Ctrl+C to stop.\n")

    active_pipeline.start()

    try:
        sniff_kwargs = {
            "prn": active_pipeline.enqueue,
            "store": False,
        }
        if interface:
            sniff_kwargs["iface"] = interface

        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        safe_print("\n[*] Stopping packet capture...")
    finally:
        active_pipeline.stop(drain=True)
        snapshot = active_pipeline.get_snapshot()
        safe_print("\n[+] Final Pipeline Metrics:")
        for k, v in snapshot.items():
            safe_print(f"    {k}: {v}")


if __name__ == "__main__":
    start_capture()