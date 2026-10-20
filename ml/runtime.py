"""
Optional ML role in the alert path (only if the decision gate passed): scores finished flows.

Contract:
  * Off unless SENTINELX_ML=on. Even then, loading requires a verified, signed model AND a signed gate.json
    saying PASS for that exact model file. Any failure disables ML (fail closed) and is logged.
  * ML never suppresses, downgrades or delays a rule alert. It can only ADD: a separate ML_ANOMALY alert
    (LOW or MEDIUM) when a finished flow scores above the validation-calibrated threshold, and ml_score /
    ml_label on the rule alerts it can be linked to.
  * Time is event time. Features come from the same ml.flows module used for training.
"""

from __future__ import annotations

import logging
import os
from collections import deque
from typing import Any

import numpy as np

from config.settings import ML_ALERT_COOLDOWN, ML_MODEL_DIR, THREAT_TYPE_ML_ANOMALY
from detection.alert import Alert
from ml.artifact import ModelSecurityError, load_bundle
from ml.flows import FEATURE_NAMES, FinishedFlow, FlowExtractor

logger = logging.getLogger("sentinelx.ml.runtime")

RELATED_ALERT_LOOKBACK_SECONDS = 300.0
RECENT_ALERTS_MAX = 512
COOLDOWN_KEYS_MAX = 4096


def ml_enabled() -> bool:
    return os.environ.get("SENTINELX_ML", "off").strip().lower() == "on"


class MLScorer:
    """Wraps a verified model bundle and a FlowExtractor; feed it parsed packets, get ML_ANOMALY alerts back."""

    def __init__(
        self,
        bundle: dict[str, Any],
        extractor: FlowExtractor | None = None,
        cooldown: float = ML_ALERT_COOLDOWN,
    ) -> None:
        self.model = bundle["model"]
        self.classes: list[str] = [str(c) for c in bundle["classes"]]
        self.benign_label: str = str(bundle["benign_label"])
        self.threshold = float(bundle["threshold"])
        self.medium_threshold = float(bundle["medium_threshold"])
        self.extractor = extractor or FlowExtractor()
        self.cooldown = float(cooldown)
        self._last_alert: dict[tuple[str, str], float] = {}
        self._recent_rule_alerts: deque[dict[str, Any]] = deque(maxlen=RECENT_ALERTS_MAX)

    @classmethod
    def from_env(cls) -> MLScorer | None:
        """Return a scorer only when SENTINELX_ML=on and the model + gate verify; otherwise None."""
        if not ml_enabled():
            return None
        try:
            return cls(load_bundle(ML_MODEL_DIR, require_gate=True))
        except (ModelSecurityError, OSError) as exc:
            logger.error("SENTINELX_ML=on but ML stays disabled (fail closed): %s", exc)
            return None

    # -- scoring -----------------------------------------------------------------------------------

    def score_flows(self, flows: list[FinishedFlow]) -> list[tuple[FinishedFlow, float, str]]:
        if not flows:
            return []
        x = np.asarray([f.features for f in flows], dtype=float)
        if x.shape[1] != len(FEATURE_NAMES):
            raise ValueError("feature vector width mismatch")
        proba = self.model.predict_proba(x)
        benign_idx = self.classes.index(self.benign_label) if self.benign_label in self.classes else None
        out = []
        for i, flow in enumerate(flows):
            score = float(1.0 - proba[i, benign_idx]) if benign_idx is not None else 0.0
            label = self.classes[int(np.argmax(proba[i]))]
            out.append((flow, score, label))
        return out

    def note_rule_alert(self, alert: dict[str, Any]) -> None:
        """Remember a rule alert so a later ML alert can link to it. Never alters the alert."""
        self._recent_rule_alerts.append(alert)

    def observe(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        """Feed one parsed packet; returns ML_ANOMALY alert dicts for flows that finished and scored high."""
        return self._alerts_for(self.extractor.process(packet))

    def flush(self) -> list[dict[str, Any]]:
        return self._alerts_for(self.extractor.flush())

    def _alerts_for(self, flows: list[FinishedFlow]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        for flow, score, label in self.score_flows(flows):
            if score < self.threshold:
                continue
            key = (flow.src_ip, flow.dst_ip)
            last = self._last_alert.get(key)
            if last is not None and flow.end_ts - last < self.cooldown:
                continue
            self._last_alert[key] = flow.end_ts
            if len(self._last_alert) > COOLDOWN_KEYS_MAX:
                self._last_alert.pop(next(iter(self._last_alert)))
            alerts.append(self._build_alert(flow, score, label))
        return alerts

    def _build_alert(self, flow: FinishedFlow, score: float, label: str) -> dict[str, Any]:
        related = [
            {"threat_type": a.get("threat_type"), "last_seen": a.get("last_seen")}
            for a in self._recent_rule_alerts
            if a.get("source_ip") == flow.src_ip
            and a.get("destination_ip") in (flow.dst_ip, None)
            and flow.start_ts - RELATED_ALERT_LOOKBACK_SECONDS
            <= float(a.get("last_seen") or 0.0)
            <= flow.end_ts + RELATED_ALERT_LOOKBACK_SECONDS
        ]
        alert = Alert(
            threat_type=THREAT_TYPE_ML_ANOMALY,
            severity="MEDIUM" if score >= self.medium_threshold else "LOW",
            confidence=score,
            detector="ml_flow_model",
            first_seen=flow.start_ts,
            last_seen=flow.end_ts,
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            destination_port=flow.dst_port,
            protocol=flow.protocol,
            evidence={
                "ml_label": label,
                "ml_score": score,
                "flow_end_reason": flow.end_reason,
                "related_rule_alerts": related,
            },
            message=f"ML flow model flagged {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} as {label} (score {score:.3f})",
        ).to_dict()
        alert["ml_score"] = score
        alert["ml_label"] = label
        return alert

    def annotate(self, rule_alert: dict[str, Any], ml_alert: dict[str, Any]) -> None:
        """Add ml_score/ml_label to a rule alert dict (additive only)."""
        rule_alert["ml_score"] = ml_alert["ml_score"]
        rule_alert["ml_label"] = ml_alert["ml_label"]
