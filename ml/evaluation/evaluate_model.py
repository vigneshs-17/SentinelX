import argparse
import json
from pathlib import Path
import sys
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split

from ml.evaluation.metrics import (
    compute_comprehensive_metrics,
    format_confusion_matrix_ascii,
    format_metrics_markdown_table,
)


FEATURE_COLUMNS = [
    "packet_size",
    "source_port",
    "destination_port",
    "protocol",
    "tcp_syn",
]


def evaluate_model_pipeline(
    model_path: str,
    dataset_path: str,
    test_size: float = 0.2,
    random_state: int = 42,
    output_json: str = None,
    model_label: str = "Model",
) -> dict:
    """
    Evaluates a serialized model on the holdout test split.
    Guarantees strict train/test separation using a fixed random seed.
    """
    data_file = Path(dataset_path).resolve()
    if not data_file.exists():
        raise FileNotFoundError(f"Dataset not found: {data_file}")

    mod_file = Path(model_path).resolve()
    if not mod_file.exists():
        raise FileNotFoundError(f"Model file not found: {mod_file}")

    # Load dataset
    df = pd.read_csv(data_file, encoding="utf-8")
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Load model
    model = joblib.load(mod_file)
    classes = list(getattr(model, "classes_", sorted(list(y.unique()))))

    # Inference
    y_pred = model.predict(X_test)
    y_prob = None
    if hasattr(model, "predict_proba"):
        try:
            y_prob = model.predict_proba(X_test)
        except Exception:
            pass

    metrics = compute_comprehensive_metrics(
        y_true=y_test.tolist(),
        y_pred=list(y_pred),
        y_prob=y_prob,
        classes=classes,
    )

    metrics["model_label"] = model_label
    metrics["model_path"] = str(mod_file)
    metrics["dataset_path"] = str(data_file)
    metrics["test_size"] = test_size
    metrics["random_state"] = random_state

    # Format text outputs
    ascii_cm = format_confusion_matrix_ascii(metrics["confusion_matrix"], metrics["classes"])
    md_table = format_metrics_markdown_table(metrics, title=f"{model_label} Evaluation Results")

    print("\n" + "=" * 70)
    print(f" EVALUATION: {model_label.upper()}")
    print("=" * 70)
    print(f"Model Artifact : {mod_file.name}")
    print(f"Dataset Samples: {len(df)} total ({len(X_test)} in test holdout)")
    print(f"Test Split     : {test_size*100:.0f}% (Stratified, seed={random_state})")
    print(f"Accuracy       : {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Macro F1-Score : {metrics['macro_f1']:.4f}")
    print(f"Weighted F1    : {metrics['weighted_f1']:.4f}")
    print(f"Macro FPR      : {metrics['macro_false_positive_rate']:.4f}")
    print(f"Macro FNR      : {metrics['macro_false_negative_rate']:.4f}")
    if metrics.get("roc_auc_ovr") is not None:
        print(f"ROC-AUC (OvR)  : {metrics['roc_auc_ovr']:.4f}")
        print(f"ROC-AUC (OvO)  : {metrics['roc_auc_ovo']:.4f}")

    print("\n[+] Confusion Matrix:")
    print(ascii_cm)

    print("\n[+] Per-Class Performance:")
    for c in classes:
        p = metrics["per_class"][c]
        print(
            f"  Class {c:<14}: Prec={p['precision']:.4f}  Rec={p['recall']:.4f}  "
            f"F1={p['f1_score']:.4f}  FPR={p['false_positive_rate']:.4f}  FNR={p['false_negative_rate']:.4f}  "
            f"(TP={p['true_positives']}, FP={p['false_positives']}, FN={p['false_negatives']})"
        )

    if output_json:
        out_path = Path(output_json).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(f"\n[+] Saved metrics JSON to: {out_path}")

    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelX Model Evaluation CLI")
    parser.add_argument(
        "--model-path",
        default="ml/models/sentinelx_model.pkl",
        help="Path to serialized model pickle",
    )
    parser.add_argument(
        "--dataset-path",
        default="ml/data/network_traffic.csv",
        help="Path to dataset CSV",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of data for test split",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for split reproducibility",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Path to save evaluation metrics JSON",
    )
    parser.add_argument(
        "--label",
        default="SentinelX Model",
        help="Label for the model",
    )

    args = parser.parse_args()
    evaluate_model_pipeline(
        model_path=args.model_path,
        dataset_path=args.dataset_path,
        test_size=args.test_size,
        random_state=args.random_state,
        output_json=args.output_json,
        model_label=args.label,
    )
