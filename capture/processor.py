"""
Packet processor for SentinelX pipeline workers.

Encapsulates packet parsing, event-time DetectionEngine evaluation, metrics recording on the active
pipeline instance, and persistence sink forwarding. Rule alerts are built and persisted first and never
depend on ML. The optional flow model (SENTINELX_ML=on, gated) can only ADD an ML_ANOMALY alert and
ml_score/ml_label on same-call rule alerts; it cannot suppress, delay or alter a rule alert.
"""

import logging
from collections.abc import Callable
from typing import Any

from capture.metrics import PipelineMetrics
from capture.packet_parser import parse_packet
from config.settings import SENSOR_ID
from detection.engine import DetectionEngine
from logs.alert_logger import log_alert
from ml.runtime import MLScorer

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
        ml_scorer: MLScorer | None = None,
    ):
        self.metrics = metrics or PipelineMetrics()
        self.alert_sink = alert_sink or log_alert
        self.sensor_id = sensor_id or SENSOR_ID
        self.engine = engine or DetectionEngine(config=config)
        self.ml = ml_scorer if ml_scorer is not None else MLScorer.from_env()

    def _emit(self, alert: dict[str, Any]) -> None:
        self.metrics.record_alert()
        try:
            self.alert_sink(alert)
        except Exception as exc:
            logger.error("Failed to persist alert: %s", exc)

    def process(self, packet: Any) -> list[dict[str, Any]]:
        """
        Process a single raw packet:
        1. Parse headers; skip and count a parse error when the event timestamp is missing.
        2. Evaluate stateful rule detectors; persist every rule alert (independent of ML).
        3. If ML is enabled, feed the packet to the flow model and persist any ML_ANOMALY alerts.
        """
        packet_data = parse_packet(packet)

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

        generated_alerts: list[dict[str, Any]] = []
        for alert_obj in self.engine.process_packet(packet_data):
            alert = alert_obj.to_dict()
            alert["sensor_id"] = self.sensor_id
            if not alert.get("destination_ip"):
                alert["destination_ip"] = packet_data.get("destination_ip")
            if not alert.get("protocol"):
                alert["protocol"] = packet_data.get("protocol")
            logger.info(
                "[ALERT - RULE] %s | Severity: %s | Source: %s",
                alert["threat_type"],
                alert["severity"],
                alert.get("source_ip", packet_data.get("source_ip")),
            )
            self._emit(alert)
            generated_alerts.append(alert)

        if self.ml is not None:
            generated_alerts.extend(self._ml_step(packet_data, generated_alerts))
        return generated_alerts

    def _ml_step(self, packet_data: dict[str, Any], rule_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Additive only; any ML failure is logged and swallowed so the rule path is unaffected."""
        assert self.ml is not None  # nosec B101
        try:
            for rule_alert in rule_alerts:
                self.ml.note_rule_alert(rule_alert)
            ml_alerts = self.ml.observe(packet_data)
        except Exception as exc:
            logger.error("ML scoring failed; rule alerts unaffected: %s", exc)
            return []
        for ml_alert in ml_alerts:
            ml_alert["sensor_id"] = self.sensor_id
            for rule_alert in rule_alerts:
                if rule_alert.get("source_ip") == ml_alert.get("source_ip"):
                    self.ml.annotate(rule_alert, ml_alert)
            logger.info(
                "[ALERT - ML] %s | Severity: %s | Source: %s",
                ml_alert["threat_type"],
                ml_alert["severity"],
                ml_alert["source_ip"],
            )
            self._emit(ml_alert)
        return ml_alerts
