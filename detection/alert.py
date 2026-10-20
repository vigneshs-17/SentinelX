"""
Canonical Alert dataclass for SentinelX intrusion detection engine.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class Alert:
    """
    Standardized, strongly-typed intrusion detection alert.
    All timestamps reflect event time (float seconds since Unix epoch).
    """

    threat_type: str
    severity: str
    confidence: float
    detector: str
    first_seen: float
    last_seen: float
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    scan_type: str | None = None
    protocol: str = "TCP"
    evidence: dict[str, Any] = field(default_factory=dict)
    message: str | None = None
    sensor_id: str | None = None

    def __post_init__(self):
        if self.message is None:
            self.message = self._generate_message()

    def _generate_message(self) -> str:
        target = f"{self.destination_ip}:{self.destination_port}" if self.destination_port else f"{self.destination_ip}"
        if self.scan_type:
            return f"{self.scan_type} scan detected from {self.source_ip} targeting {target} [{self.detector}]"
        return f"{self.threat_type} detected: {self.source_ip} -> {target} [{self.detector}]"

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to dictionary representation matching database and API schemas."""
        detected_at = datetime.fromtimestamp(self.last_seen, tz=UTC).isoformat(timespec="seconds")
        return {
            "threat_type": self.threat_type,
            "scan_type": self.scan_type,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "detected_at": detected_at,
            "timestamp": detected_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "destination_port_count": self.evidence.get("unique_ports_observed", 1 if self.destination_port else 0),
            "target_count": self.evidence.get("unique_targets_observed", 1 if self.destination_ip else 0),
            "ports_sample": self.evidence.get("sample_ports", []),
            "sample_targets": self.evidence.get("sample_targets", []),
            "evidence": self.evidence,
            "detector": self.detector,
            "message": self.message,
            "sensor_id": self.sensor_id,
        }

    def to_json(self) -> str:
        """Serialize alert to JSON string."""
        return json.dumps(self.to_dict())
