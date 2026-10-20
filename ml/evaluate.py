"""
Evaluation metrics for the flow model and for alert-level rules-only vs rules+ML comparison, plus the decision gate.

Flow level (model only): per-class precision/recall/F1, confusion matrix, PR-AUC.
Alert level (what a SOC sees; same labels, same test replay for both systems):
  * recall   = share of attack-minutes (60 s buckets of each labelled attack window) with at least one
               alert for that attacker/victim pair; also instance recall (windows with >= 1 alert).
  * alerts that match no attack window (pair + time) are false alerts; false alerts per benign hour is
    false alerts divided by replayed test time that lies outside every attack window.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support

from ml.dataset import BENIGN, AttackWindow, scenario_windows

BUCKET_SECONDS = 60.0
ALERT_TOLERANCE_SECONDS = 10.0


def flow_metrics(
    y_true: np.ndarray,
    proba: np.ndarray,
    classes: list[str],
    trained_classes: set[str],
    threshold: float,
    benign_label: str = BENIGN,
) -> dict[str, Any]:
    """Flow-level metrics on a held-out split. Zero-shot classes (absent from training) are kept out of headline numbers."""
    classes_arr = np.asarray(classes)
    y_pred = classes_arr[np.argmax(proba, axis=1)]
    labels = list(classes) + sorted(set(np.unique(y_true)) - set(classes))
    prec, rec, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    per_class: dict[str, Any] = {}
    for i, c in enumerate(labels):
        pr_auc = None
        if c in classes and (y_true == c).any():
            idx = classes.index(c)
            pr_auc = float(average_precision_score(y_true == c, proba[:, idx]))
        per_class[c] = {
            "precision": float(prec[i]),
            "recall": float(rec[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
            "pr_auc": pr_auc,
            "in_training": c in trained_classes or c == benign_label,
        }

    benign_idx = classes.index(benign_label) if benign_label in classes else None
    attack_score = 1.0 - proba[:, benign_idx] if benign_idx is not None else np.zeros(len(y_true))
    full_attack_score = attack_score
    # Headline binary numbers cover benign + classes seen in training; zero-shot rows are reported separately.
    in_scope = np.array([c == benign_label or c in trained_classes for c in y_true])
    is_attack = (y_true != benign_label)[in_scope]
    attack_score = attack_score[in_scope]
    flagged = attack_score >= threshold
    tp, fp, fn = int((flagged & is_attack).sum()), int((flagged & ~is_attack).sum()), int((~flagged & is_attack).sum())
    binary = {
        "threshold": float(threshold),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "pr_auc": float(average_precision_score(is_attack, attack_score)) if is_attack.any() else None,
    }

    headline = [c for c in labels if c != benign_label and per_class[c]["in_training"] and per_class[c]["support"] > 0]
    zero_shot = {
        c: {
            "support": per_class[c]["support"],
            "flagged_as_attack_rate": float((full_attack_score[y_true == c] >= threshold).mean()),
        }
        for c in labels
        if c != benign_label and not per_class[c]["in_training"] and per_class[c]["support"] > 0
    }
    return {
        "labels": labels,
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "binary_attack_vs_benign": binary,
        "headline_classes": headline,
        "headline_macro_f1": float(np.mean([per_class[c]["f1"] for c in headline])) if headline else None,
        "zero_shot": zero_shot,
    }


def windows_from_labels(labels: list[dict[str, Any]]) -> list[AttackWindow]:
    return scenario_windows(labels)


def _window_hit(w: AttackWindow, alert: dict[str, Any], tol: float) -> bool:
    """Alert is for this attack if its endpoints are an attacker/victim pair and its time is in the window (+tol)."""
    ts = float(alert.get("last_seen") or alert.get("ts") or 0.0)
    if not (w.start_ts - 1.0 <= ts <= w.end_ts + tol):
        return False
    return w.matches(str(alert.get("source_ip")), str(alert.get("destination_ip")), w.start_ts)


def alert_metrics(
    alerts: list[dict[str, Any]],
    labels: list[dict[str, Any]],
    benign_seconds: float,
    headline_classes: set[str] | None = None,
    tolerance: float = ALERT_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    """Alert-level metrics for one system against the labelled attack windows."""
    windows = windows_from_labels(labels)
    matched_alert = [False] * len(alerts)
    per_class: dict[str, dict[str, Any]] = {}
    for w in windows:
        c = per_class.setdefault(w.cls, {"buckets": 0, "buckets_hit": 0, "instances": 0, "instances_hit": 0})
        n_buckets = max(1, int(np.ceil((w.end_ts - w.start_ts) / BUCKET_SECONDS)))
        hit_buckets = set()
        any_hit = False
        for i, a in enumerate(alerts):
            if not _window_hit(w, a, tolerance):
                continue
            matched_alert[i] = True
            any_hit = True
            ts = float(a.get("last_seen") or a.get("ts") or 0.0)
            hit_buckets.add(min(n_buckets - 1, max(0, int((ts - w.start_ts) // BUCKET_SECONDS))))
        c["buckets"] += n_buckets
        c["buckets_hit"] += len(hit_buckets)
        c["instances"] += 1
        c["instances_hit"] += int(any_hit)

    tp_alerts = sum(matched_alert)
    fp_alerts = len(alerts) - tp_alerts
    benign_hours = benign_seconds / 3600.0
    for c in per_class.values():
        c["recall"] = c["buckets_hit"] / c["buckets"] if c["buckets"] else None
        c["instance_recall"] = c["instances_hit"] / c["instances"] if c["instances"] else None

    def pooled(names: set[str] | None) -> float | None:
        sel = [v for k, v in per_class.items() if names is None or k in names]
        total = sum(v["buckets"] for v in sel)
        return sum(v["buckets_hit"] for v in sel) / total if total else None

    precision = tp_alerts / len(alerts) if alerts else None
    recall_all = pooled(None)
    f1 = None
    if precision is not None and recall_all is not None and precision + recall_all > 0:
        f1 = 2 * precision * recall_all / (precision + recall_all)
    return {
        "alerts": len(alerts),
        "true_alerts": tp_alerts,
        "false_alerts": fp_alerts,
        "alert_precision": precision,
        "recall_all_classes": recall_all,
        "recall_headline": pooled(headline_classes) if headline_classes is not None else recall_all,
        "f1_all_classes": f1,
        "benign_hours": benign_hours,
        "false_alerts_per_benign_hour": (fp_alerts / benign_hours) if benign_hours > 0 else None,
        "per_class": per_class,
    }


def decide_gate(rules: dict[str, Any], hybrid: dict[str, Any], min_gain: float = 0.01) -> dict[str, Any]:
    """
    ML stays in the alert path only if rules+ML beats rules-only on headline recall (by at least `min_gain`,
    absolute) at equal or lower false alerts per benign hour. Anything else, including missing data, is not a PASS.
    """
    r_rec, h_rec = rules.get("recall_headline"), hybrid.get("recall_headline")
    r_fp, h_fp = rules.get("false_alerts_per_benign_hour"), hybrid.get("false_alerts_per_benign_hour")
    out: dict[str, Any] = {
        "rules_recall": r_rec,
        "hybrid_recall": h_rec,
        "rules_false_alerts_per_benign_hour": r_fp,
        "hybrid_false_alerts_per_benign_hour": h_fp,
        "min_recall_gain": min_gain,
    }
    if r_rec is None or h_rec is None or r_fp is None or h_fp is None:
        return {
            **out,
            "decision": "INCONCLUSIVE",
            "reason": "recall or benign-hour data missing; ML stays out of the alert path",
        }
    gain = h_rec - r_rec
    out["recall_gain"] = gain
    if gain >= min_gain and h_fp <= r_fp:
        return {
            **out,
            "decision": "PASS",
            "reason": "rules+ML recall beats rules-only at equal or lower false alerts per benign hour",
        }
    reasons = []
    if gain < min_gain:
        reasons.append(f"recall gain {gain:+.4f} < required {min_gain}")
    if h_fp > r_fp:
        reasons.append(f"false alerts per benign hour rose {r_fp:.4f} -> {h_fp:.4f}")
    return {**out, "decision": "FAIL", "reason": "; ".join(reasons)}
