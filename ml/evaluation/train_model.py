import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier

from ml.evaluation.metrics import (
    compute_comprehensive_metrics,
    format_confusion_matrix_ascii,
)


FEATURE_COLUMNS = [
    "packet_size",
    "source_port",
    "destination_port",
    "protocol",
    "tcp_syn",
]


def train_and_evaluate_improved_model(
    dataset_path: str = "ml/data/network_traffic.csv",
    models_dir: str = "ml/models",
    reports_dir: str = "ml/evaluation/reports",
    random_state: int = 42,
    cv_folds: int = 5,
) -> dict:
    """
    Trains an improved, regularized Random Forest model using Stratified K-Fold
    cross-validation on the training split only. Evaluates against the holdout test
    split and saves versioned model artifacts and metadata.
    """
    data_file = Path(dataset_path).resolve()
    mod_dir = Path(models_dir).resolve()
    rep_dir = Path(reports_dir).resolve()
    mod_dir.mkdir(parents=True, exist_ok=True)
    rep_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print(" SENTINELX ML TRAINING & CROSS-VALIDATION PIPELINE")
    print("=" * 70)

    # 1. Load Dataset
    print(f"[*] Loading dataset from: {data_file}")
    df = pd.read_csv(data_file, encoding="utf-8")
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    print(f"[+] Total samples: {len(df)}")
    print(f"[+] Class counts:\n{df['label'].value_counts().to_string()}")

    # 2. Strict Train/Test Separation (Test set remains strictly unseen)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_state, stratify=y
    )
    print(f"\n[+] Train split: {len(X_train)} samples")
    print(f"[+] Test split : {len(X_test)} samples (Holdout, seed={random_state})")

    # 3. Stratified Cross-Validation on TRAINING SET ONLY
    print(f"\n[*] Performing {cv_folds}-Fold Stratified Cross-Validation on training data...")
    param_grid = {
        "n_estimators": [100, 150],
        "max_depth": [6, 8, 10, None],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "class_weight": ["balanced", None],
    }

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    base_rf = RandomForestClassifier(random_state=random_state)

    grid = GridSearchCV(
        base_rf,
        param_grid=param_grid,
        cv=cv,
        scoring="f1_macro",
        n_jobs=-1,
        verbose=0,
    )
    grid.fit(X_train, y_train)

    best_params = grid.best_params_
    best_cv_score = float(grid.best_score_)
    print(f"[+] Optimal Hyperparameters: {best_params}")
    print(f"[+] Best Cross-Validation Macro F1: {best_cv_score:.4f}")

    # 4. Fit Best Model on Full Training Set
    best_model = grid.best_estimator_

    # Check for overfitting: Train vs Test Accuracy
    train_preds = best_model.predict(X_train)
    train_acc = float((train_preds == y_train).mean())

    # 5. Final Unbiased Evaluation on Test Holdout
    test_preds = best_model.predict(X_test)
    test_prob = best_model.predict_proba(X_test)

    classes = list(best_model.classes_)
    metrics = compute_comprehensive_metrics(
        y_true=y_test.tolist(),
        y_pred=list(test_preds),
        y_prob=test_prob,
        classes=classes,
    )

    metrics["model_label"] = "Improved Model (v2)"
    metrics["training_accuracy"] = round(train_acc, 4)
    metrics["best_cv_macro_f1"] = round(best_cv_score, 4)
    metrics["best_hyperparameters"] = best_params

    print("\n" + "-" * 70)
    print(" EVALUATION ON UNSEEN TEST HOLDOUT")
    print("-" * 70)
    print(f"Training Accuracy : {train_acc:.4f} ({train_acc*100:.2f}%)")
    print(f"Test Accuracy     : {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Test Macro F1     : {metrics['macro_f1']:.4f}")
    print(f"Test Weighted F1  : {metrics['weighted_f1']:.4f}")
    print(f"Test Macro FPR    : {metrics['macro_false_positive_rate']:.4f}")
    print(f"Test Macro FNR    : {metrics['macro_false_negative_rate']:.4f}")
    if metrics.get("roc_auc_ovr"):
        print(f"Test ROC-AUC (OvR): {metrics['roc_auc_ovr']:.4f}")

    print("\n[+] Confusion Matrix:")
    print(format_confusion_matrix_ascii(metrics["confusion_matrix"], classes))

    print("\n[+] Per-Class Performance:")
    for c in classes:
        p = metrics["per_class"][c]
        print(
            f"  Class {c:<14}: Prec={p['precision']:.4f}  Rec={p['recall']:.4f}  "
            f"F1={p['f1_score']:.4f}  FPR={p['false_positive_rate']:.4f}  FNR={p['false_negative_rate']:.4f}"
        )

    # 6. Save Versioned Models
    v2_path = mod_dir / "sentinelx_model_v2.pkl"
    prod_path = mod_dir / "sentinelx_model.pkl"

    joblib.dump(best_model, v2_path)
    joblib.dump(best_model, prod_path)
    print(f"\n[+] Saved improved model to: {v2_path}")
    print(f"[+] Updated active model at: {prod_path}")

    # 7. Write Model Metadata
    metadata = {
        "model_version": "2.0.0",
        "model_type": "RandomForestClassifier",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "random_state": random_state,
        "features": FEATURE_COLUMNS,
        "classes": classes,
        "hyperparameters": best_params,
        "cross_validation": {
            "folds": cv_folds,
            "metric": "f1_macro",
            "score": round(best_cv_score, 4),
        },
        "performance": {
            "training_accuracy": round(train_acc, 4),
            "test_accuracy": metrics["accuracy"],
            "macro_f1": metrics["macro_f1"],
            "weighted_f1": metrics["weighted_f1"],
            "roc_auc_ovr": metrics.get("roc_auc_ovr"),
        },
        "provenance": {
            "dataset": str(data_file.name),
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
        },
        "limitations": [
            "Dataset is synthetic, generated from fixed distribution ranges.",
            "HIGH_TRAFFIC and NORMAL feature distributions heavily overlap on single packets.",
            "Single-packet features cannot measure temporal rate (pps, bps).",
            "PORT_SCAN detection relies heavily on tcp_syn==1 artifact.",
        ],
    }

    metadata_path = mod_dir / "model_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved model metadata to: {metadata_path}")

    # 8. Save Evaluation JSON Report
    report_json_path = rep_dir / "improved_evaluation.json"
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Saved evaluation report to: {report_json_path}")

    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and regularize SentinelX ML model")
    parser.add_argument("--dataset", default="ml/data/network_traffic.csv")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--cv", type=int, default=5)
    args = parser.parse_args()

    train_and_evaluate_improved_model(
        dataset_path=args.dataset,
        random_state=args.random_state,
        cv_folds=args.cv,
    )
