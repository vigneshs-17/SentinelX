from collections import defaultdict
import time

from scapy.all import sniff

from capture.packet_parser import parse_packet
from detection.rule_engine import detect_port_scan
from detection.traffic_rules import detect_high_traffic
from logs.alert_logger import log_alert
from ml.predictor import predict_threat


# =========================================================
# ML ALERT SETTINGS
# =========================================================

ML_ALERT_COOLDOWN = 30

last_ml_alert = defaultdict(float)


# =========================================================
# PACKET CALLBACK
# =========================================================

def packet_callback(packet):

    packet_data = parse_packet(packet)

    print(
        f"[PACKET] "
        f"{packet_data['source_ip']} → "
        f"{packet_data['destination_ip']} | "
        f"{packet_data['protocol']} | "
        f"{packet_data['source_port']} → "
        f"{packet_data['destination_port']} | "
        f"Size: {packet_data['packet_size']} bytes"
    )

    # =====================================================
    # RULE-BASED DETECTION
    # =====================================================

    port_scan_alert = detect_port_scan(packet_data)

    traffic_alert = detect_high_traffic(packet_data)

    rule_alert = port_scan_alert or traffic_alert

    # =====================================================
    # NO RULE ALERT
    #
    # Normal traffic does not need ML inference.
    # This keeps live packet processing lightweight.
    # =====================================================

    if rule_alert is None:

        print("[🤖 ML] No rule-based threat detected")

        return

    # =====================================================
    # RULE ALERT FOUND
    #
    # Run ML only when the rule engine detects suspicious
    # behavior. ML acts as a secondary confirmation layer.
    # =====================================================

    threat_type = rule_alert["threat_type"]

    source_ip = rule_alert.get(
        "source_ip",
        packet_data["source_ip"]
    )

    ml_prediction = None

    try:

        ml_prediction = predict_threat(packet_data)

    except Exception as error:

        print(f"[ML ERROR] {error}")

    # =====================================================
    # ML CONFIRMS RULE ALERT
    # =====================================================

    if (
        ml_prediction is not None
        and ml_prediction == threat_type
    ):

        confirmed_alert = {
            "threat_type": threat_type,
            "severity": rule_alert["severity"],
            "source_ip": source_ip,
            "destination_ip": packet_data[
                "destination_ip"
            ],
            "protocol": packet_data[
                "protocol"
            ],
            "message": (
                f"Rule engine and machine learning "
                f"model both detected possible "
                f"{threat_type}"
            )
        }

        print(
            f"\n[🚨 CONFIRMED ALERT] "
            f"{threat_type} | "
            f"Severity: {confirmed_alert['severity']} | "
            f"Source: {source_ip}"
        )

        log_alert(confirmed_alert)

        return

    # =====================================================
    # RULE DETECTED BUT ML DID NOT CONFIRM
    # =====================================================

    rule_alert["destination_ip"] = packet_data[
        "destination_ip"
    ]

    rule_alert["protocol"] = packet_data[
        "protocol"
    ]

    print(
        f"\n[🚨 RULE ALERT] "
        f"{threat_type} | "
        f"Severity: {rule_alert['severity']} | "
        f"Source: {source_ip}"
    )

    log_alert(rule_alert)


# =========================================================
# START PACKET CAPTURE
# =========================================================

def start_capture():

    print("[*] SentinelX IDS started...")
    print("[*] Monitoring network traffic...")
    print("[*] Press Ctrl+C to stop.\n")

    sniff(
        prn=packet_callback,
        store=False
    )


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    start_capture()