"""
Packet processor for SentinelX pipeline workers.

Encapsulates packet parsing, multi-rule evaluation (D7), secondary ML confirmation,
metrics recording on the active pipeline instance (D4), and persistence sink forwarding.
All prints in the packet path are replaced with standard logging (D8).
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from capture.metrics import PipelineMetrics
from capture.packet_parser import parse_packet
from config.settings import SENSOR_ID
from detection.rule_engine import detect_port_scan
from detection.traffic_rules import detect_high_traffic
from logs.alert_logger import log_alert
from ml.predictor import predict_threat_with_confidence

logger = logging.getLogger("sentinelx.processor")


class PacketProcessor:
    """
    Context-aware packet processor executed asynchronously by pipeline consumer workers.
    Holds explicit references to the running pipeline's metrics and alert persistence sink.
    """

    def __init__(
        self,
        metrics: PipelineMetrics | None = None,
        alert_sink: Callable[[dict[str, Any]], Any] | None = None,
        sensor_id: str | None = None,
    ):
        self.metrics = metrics or PipelineMetrics()
        self.alert_sink = alert_sink or log_alert
        self.sensor_id = sensor_id or SENSOR_ID

    def process(self, packet: Any) -> list[dict[str, Any]]:
        """
        Process a single raw packet through the IDS processing pipeline:
        1. Parse network headers into normalized packet dictionary.
        2. Evaluate all stateful rule detectors (both port scan and high traffic).
        3. If one or more rules fire, perform secondary ML confirmation per alert.
        4. Record alert metric on the active pipeline.
        5. Persist each alert to SQLite and JSONL via alert_sink.
        """
        packet_data = parse_packet(packet)

        logger.debug(
            "Packet: %s:%s -> %s:%s | %s | %d bytes",
            packet_data.get("source_ip"),
            packet_data.get("source_port"),
            packet_data.get("destination_ip"),
            packet_data.get("destination_port"),
            packet_data.get("protocol"),
            packet_data.get("packet_size", 0),
        )

        rule_alerts: list[dict[str, Any]] = []

        # Evaluate port scan detector
        if ps_alert := detect_port_scan(packet_data):
            rule_alerts.append(ps_alert)

        # Evaluate volumetric high traffic detector
        if ht_alert := detect_high_traffic(packet_data):
            rule_alerts.append(ht_alert)

        if not rule_alerts:
            logger.debug("No rule-based threat detected for packet from %s", packet_data.get("source_ip"))
            return []

        generated_alerts: list[dict[str, Any]] = []

        # Note: In Phase 2, detected_at is recorded as processing time (ISO-8601 UTC with offset).
        # Phase 3 switches this to packet event time.
        now_utc = datetime.now(UTC).isoformat(timespec="seconds")

        for alert in rule_alerts:
            threat_type = alert["threat_type"]
            source_ip = alert.get("source_ip", packet_data.get("source_ip"))

            alert["sensor_id"] = self.sensor_id
            alert["destination_ip"] = packet_data.get("destination_ip")
            alert["protocol"] = packet_data.get("protocol")
            alert["detected_at"] = now_utc
            alert["timestamp"] = now_utc

            # Secondary ML Confirmation
            ml_prediction = None
            ml_confidence = None
            try:
                ml_prediction, ml_confidence = predict_threat_with_confidence(packet_data)
            except Exception as error:
                logger.debug("ML secondary confirmation encountered error: %s", error)

            if ml_prediction is not None and ml_prediction == threat_type:
                alert["ml_confirmed"] = True
                alert["ml_confidence"] = ml_confidence
                alert["ml_score"] = ml_confidence
                alert["ml_label"] = ml_prediction
                alert["message"] = f"Rule engine and machine learning model both detected possible {threat_type}"
                logger.info(
                    "[ALERT - CONFIRMED] %s | Severity: %s | Source: %s",
                    threat_type,
                    alert["severity"],
                    source_ip,
                )
            else:
                alert["ml_confirmed"] = False
                alert["ml_confidence"] = ml_confidence
                alert["ml_score"] = ml_confidence
                alert["ml_label"] = ml_prediction
                logger.info(
                    "[ALERT - RULE] %s | Severity: %s | Source: %s",
                    threat_type,
                    alert["severity"],
                    source_ip,
                )

            # Record alert on the active pipeline instance (D4)
            self.metrics.record_alert()

            # Forward alert to persistent sink (SQLite and JSONL)
            try:
                self.alert_sink(alert)
            except Exception as exc:
                logger.error("Failed to persist alert: %s", exc)

            generated_alerts.append(alert)

        return generated_alerts
