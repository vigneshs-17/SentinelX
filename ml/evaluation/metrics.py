import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize


def compute_comprehensive_metrics(
    y_true: List[str],
    y_pred: List[str],
    y_prob: Optional[np.ndarray] = None,
    classes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes a complete, scientifically defensible evaluation metric suite
    for multi-class threat classification.
    """
    if classes is None:
        classes = sorted(list(set(y_true) | set(y_pred)))

    n_samples = len(y_true)
    acc = float(accuracy_score(y_true, y_pred))

    # Macro & Weighted metrics
    macro_p = float(precision_score(y_true, y_pred, labels=classes, average="macro", zero_division=0))
    macro_r = float(recall_score(y_true, y_pred, labels=classes, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, labels=classes, average="macro", zero_division=0))

    weighted_p = float(precision_score(y_true, y_pred, labels=classes, average="weighted", zero_division=0))
    weighted_r = float(recall_score(y_true, y_pred, labels=classes, average="weighted", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, labels=classes, average="weighted", zero_division=0))

    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred, labels=classes)

    # Per-Class Statistics (TP, FP, FN, TN, FPR, FNR, Precision, Recall, F1)
    per_class = {}
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0

    for idx, c in enumerate(classes):
        tp = int(cm[idx, idx])
        fn = int(np.sum(cm[idx, :]) - tp)
        fp = int(np.sum(cm[:, idx]) - tp)
        tn = int(n_samples - (tp + fp + fn))

        support = int(np.sum(cm[idx, :]))
        p = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        r = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * p * r / (p + r)) if (p + r) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        per_class[c] = {
            "support": support,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
        }
        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tn += tn

    # Multi-class average FPR / FNR
    macro_fpr = float(np.mean([per_class[c]["false_positive_rate"] for c in classes]))
    macro_fnr = float(np.mean([per_class[c]["false_negative_rate"] for c in classes]))

    # ROC-AUC if probability outputs are available
    roc_auc_ovr = None
    roc_auc_ovo = None
    per_class_roc_auc = {}

    if y_prob is not None:
        try:
            roc_auc_ovr = float(roc_auc_score(y_true, y_prob, labels=classes, multi_class="ovr"))
            roc_auc_ovo = float(roc_auc_score(y_true, y_prob, labels=classes, multi_class="ovo"))

            y_bin = label_binarize(y_true, classes=classes)
            for idx, c in enumerate(classes):
                try:
                    per_class_roc_auc[c] = round(float(roc_auc_score(y_bin[:, idx], y_prob[:, idx])), 4)
                except Exception:
                    per_class_roc_auc[c] = None
        except Exception:
            pass

    return {
        "n_samples": n_samples,
        "classes": classes,
        "accuracy": round(acc, 4),
        "macro_precision": round(macro_p, 4),
        "macro_recall": round(macro_r, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_precision": round(weighted_p, 4),
        "weighted_recall": round(weighted_r, 4),
        "weighted_f1": round(weighted_f1, 4),
        "macro_false_positive_rate": round(macro_fpr, 4),
        "macro_false_negative_rate": round(macro_fnr, 4),
        "roc_auc_ovr": round(roc_auc_ovr, 4) if roc_auc_ovr is not None else None,
        "roc_auc_ovo": round(roc_auc_ovo, 4) if roc_auc_ovo is not None else None,
        "per_class_roc_auc": per_class_roc_auc,
        "confusion_matrix": cm.tolist(),
        "per_class": per_class,
    }


def format_confusion_matrix_ascii(cm: List[List[int]], classes: List[str]) -> str:
    """Formats a confusion matrix as a clear text table."""
    col_width = max(len(c) for c in classes) + 4
    header = f"{'Actual \\ Predicted':<{col_width}}" + "".join(f"{c:>{col_width}}" for c in classes)
    separator = "-" * len(header)
    rows = [header, separator]

    for idx, actual in enumerate(classes):
        row_str = f"{actual:<{col_width}}" + "".join(f"{cm[idx][j]:>{col_width}}" for j in range(len(classes)))
        rows.append(row_str)

    return "\n".join(rows)


def format_metrics_markdown_table(metrics: Dict[str, Any], title: str = "Evaluation Metrics") -> str:
    """Generates a clean markdown table summarizing metrics."""
    lines = [
        f"### {title}",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Samples Evaluated** | {metrics['n_samples']} |",
        f"| **Accuracy** | {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%) |",
        f"| **Macro F1-Score** | {metrics['macro_f1']:.4f} |",
        f"| **Weighted F1-Score** | {metrics['weighted_f1']:.4f} |",
        f"| **Macro Precision** | {metrics['macro_precision']:.4f} |",
        f"| **Macro Recall** | {metrics['macro_recall']:.4f} |",
        f"| **Macro False Positive Rate** | {metrics['macro_false_positive_rate']:.4f} |",
        f"| **Macro False Negative Rate** | {metrics['macro_false_negative_rate']:.4f} |",
    ]

    if metrics.get("roc_auc_ovr") is not None:
        lines.append(f"| **ROC-AUC (OvR)** | {metrics['roc_auc_ovr']:.4f} |")
        lines.append(f"| **ROC-AUC (OvO)** | {metrics['roc_auc_ovo']:.4f} |")

    lines.extend([
        "",
        "#### Per-Class Performance",
        "",
        "| Class | Support | TP | FP | FN | TN | Precision | Recall | F1-Score | FPR | FNR |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for c in metrics["classes"]:
        p = metrics["per_class"][c]
        lines.append(
            f"| `{c}` | {p['support']} | {p['true_positives']} | {p['false_positives']} | "
            f"{p['false_negatives']} | {p['true_negatives']} | {p['precision']:.4f} | "
            f"{p['recall']:.4f} | {p['f1_score']:.4f} | {p['false_positive_rate']:.4f} | "
            f"{p['false_negative_rate']:.4f} |"
        )

    return "\n".join(lines)
