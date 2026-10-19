"""
Packet processor for SentinelX pipeline workers.

Encapsulates packet parsing, event-time DetectionEngine evaluation,
secondary ML confirmation, metrics recording on the active pipeline instance,
and persistence sink forwarding. All prints in the packet path are replaced
with standard logging.
"""

import logging
from collections.abc import Callable
from typing import Any

from capture.metrics import PipelineMetrics
from capture.packet_parser import parse_packet
from config.settings import SENSOR_ID
from detection.engine import DetectionEngine
from logs.alert_logger import log_alert
from ml.predictor import predict_threat_with_confidence

logger = logging.getLogger("sentinelx.processor")


class PacketProcessor:
    """
    Context-aware packet processor executed asynchronously by pipeline consumer workers.
    Holds explicit references to the running pipeline's metrics, alert persistence sink,
    and event-time DetectionEngine.
    """

    def __init__(
        self,
        metrics: PipelineMetrics | None = None,
        alert_sink: Callable[[dict[str, Any]], Any] | None = None,
        sensor_id: str | None = None,
        engine: DetectionEngine | None = None,
        config: dict[str, Any] | None = None,
    ):
        self.metrics = metrics or PipelineMetrics()
        self.alert_sink = alert_sink or log_alert
        self.sensor_id = sensor_id or SENSOR_ID
        self.engine = engine or DetectionEngine(config=config)

    def process(self, packet: Any) -> list[dict[str, Any]]:
        """
        Process a single raw packet through the IDS processing pipeline:
        1. Parse network headers into normalized packet dictionary.
        2. Validate event timestamp; skip packet and record parse error if missing (Correction 5).
        3. Evaluate stateful rule detectors via DetectionEngine.
        4. If alerts fire, perform secondary ML confirmation per alert.
        5. Record alert metric on the active pipeline.
        6. Persist each alert to SQLite and JSONL via alert_sink.
        """
        packet_data = parse_packet(packet)

        # Correction 5: Skip packets missing a valid event timestamp
        if packet_data.get("ts") is None:
            self.metrics.record_parse_error()
            return []

        logger.debug(
            "Packet [ts=%.3f]: %s:%s -> %s:%s | %s | %d bytes",
            packet_data["ts"],
            packet_data.get("source_ip"),
            packet_data.get("source_port"),
            packet_data.get("destination_ip"),
            packet_data.get("destination_port"),
            packet_data.get("protocol"),
            packet_data.get("packet_size", 0),
        )

        rule_alerts = self.engine.process_packet(packet_data)
        if not rule_alerts:
            logger.debug("No rule-based threat detected for packet from %s", packet_data.get("source_ip"))
            return []

        generated_alerts: list[dict[str, Any]] = []

        for alert_obj in rule_alerts:
            alert = alert_obj.to_dict()
            threat_type = alert["threat_type"]
            source_ip = alert.get("source_ip", packet_data.get("source_ip"))

            alert["sensor_id"] = self.sensor_id
            if not alert.get("destination_ip"):
                alert["destination_ip"] = packet_data.get("destination_ip")
            if not alert.get("protocol"):
                alert["protocol"] = packet_data.get("protocol")

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

            # Record alert on the active pipeline instance
            self.metrics.record_alert()

            # Forward alert to persistent sink (SQLite and JSONL)
            try:
                self.alert_sink(alert)
            except Exception as exc:
                logger.error("Failed to persist alert: %s", exc)

            generated_alerts.append(alert)

        return generated_alerts
