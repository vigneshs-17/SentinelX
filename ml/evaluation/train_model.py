import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import warnings
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier

from ml.evaluation.metrics import (
    compute_comprehensive_metrics,
    format_confusion_matrix_ascii,
)
from ml.predictor import (
    calculate_model_sha256,
    _model_lock,
    invalidate_model_cache,
)


class ModelActivationError(RuntimeError):
    """Raised when machine learning model or metadata activation fails during deployment."""
    pass


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

    # 6. Save Versioned Model Archive
    v2_path = mod_dir / "sentinelx_model_v2.pkl"
    joblib.dump(best_model, v2_path)
    print(f"\n[+] Saved improved model archive to: {v2_path}")

    # -------------------------------------------------------------------------
    # TWO-PHASE STAGING, BACKUP, CONTROLLED ACTIVATION & ROLLBACK SEQUENCE
    # -------------------------------------------------------------------------
    # Filesystem-level atomicity limitation:
    # Standard operating system filesystems (such as NTFS, ext4, APFS) do not provide
    # atomic replacement across multiple distinct directory entries in a single
    # filesystem transaction.
    #
    # To guarantee application-level consistency and prevent desynchronization
    # between model weights (sentinelx_model.pkl) and integrity checksums (model_metadata.json):
    #   1. Phase A (Staging): Serialize candidate model and metadata to isolated
    #      temporary files (.tmp). Cryptographic SHA256 is computed directly on the
    #      staged model bytes before any activation.
    #   2. Phase B (Backup): Snapshot currently active production artifacts to
    #      backup files (.prev) in the same directory.
    #   3. Phase C (Controlled Activation & Concurrency Protection): Under _model_lock,
    #      sequentially replace the model then metadata using filesystem replacement.
    #      If any error occurs during replacement or post-verification, both artifacts
    #      are immediately rolled back from .prev, restoring previous state.
    #   4. Post-Activation Verification: Live active model SHA256 is verified against
    #      metadata, in-memory model cache is invalidated, and backups are purged.
    #   5. Predictor Fail-Closed Design: If an unexpected crash occurs between the
    #      two atomic file replacements, the predictor fails closed (ModelIntegrityError)
    #      rather than running with mismatched or untrusted weights.
    # -------------------------------------------------------------------------

    prod_path = mod_dir / "sentinelx_model.pkl"
    metadata_path = mod_dir / "model_metadata.json"

    staged_model_path = prod_path.with_name(f"{prod_path.name}.tmp")
    staged_metadata_path = metadata_path.with_name(f"{metadata_path.name}.tmp")
    backup_model_path = prod_path.with_name(f"{prod_path.name}.prev")
    backup_metadata_path = metadata_path.with_name(f"{metadata_path.name}.prev")

    # Issue 1: Handle existing metadata and detect corruption
    existing_meta = {}
    if metadata_path.exists():
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                existing_meta = json.load(f)
        except Exception as err:
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            corrupt_backup = metadata_path.with_name(f"{metadata_path.name}.corrupt.{timestamp_str}.bak")
            if corrupt_backup.exists():
                timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
                corrupt_backup = metadata_path.with_name(f"{metadata_path.name}.corrupt.{timestamp_str}.bak")
            shutil.copy2(metadata_path, corrupt_backup)
            warn_msg = (
                f"Existing model metadata at '{metadata_path}' was malformed JSON ({err}). "
                f"Preserved corrupt metadata to '{corrupt_backup.name}'. Generating fresh metadata."
            )
            warnings.warn(warn_msg, UserWarning)
            print(f"\n[!] WARNING: {warn_msg}")
            existing_meta = {}

    # Phase A: Staging candidate artifacts
    # 1. Serialize model to staging file
    joblib.dump(best_model, staged_model_path)

    # 2. Compute cryptographic SHA256 on the staged candidate model file
    staged_sha256 = calculate_model_sha256(staged_model_path)
    print(f"[+] Staged candidate model SHA256: {staged_sha256}")

    # 3. Assemble and serialize staged metadata
    metadata = {
        **existing_meta,
        "model_version": "2.0.0",
        "model_type": "RandomForestClassifier",
        "model_sha256": staged_sha256,
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

    with open(staged_metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Phase B: Backup active production artifacts
    had_active_model = prod_path.exists()
    had_active_metadata = metadata_path.exists()

    if had_active_model:
        shutil.copy2(prod_path, backup_model_path)
    if had_active_metadata:
        shutil.copy2(metadata_path, backup_metadata_path)

    # Phase C: Controlled Activation & Rollback under Concurrency Protection
    model_replaced = False
    metadata_replaced = False

    with _model_lock:
        try:
            # 1. Replace model file
            staged_model_path.replace(prod_path)
            model_replaced = True

            # 2. Replace metadata file
            staged_metadata_path.replace(metadata_path)
            metadata_replaced = True

            # 3. Post-activation verification
            active_sha256 = calculate_model_sha256(prod_path)
            if active_sha256.lower() != staged_sha256.lower():
                raise ModelActivationError(
                    f"Post-activation checksum mismatch! Staged: {staged_sha256}, Active: {active_sha256}"
                )

            # 4. Invalidate predictor in-memory cache
            invalidate_model_cache()

            # 5. Clean up backup files on success
            if backup_model_path.exists():
                backup_model_path.unlink()
            if backup_metadata_path.exists():
                backup_metadata_path.unlink()

            print(f"[+] Successfully activated production model at: {prod_path}")
            print(f"[+] Successfully activated model metadata at: {metadata_path}")

        except Exception as exc:
            print(f"\n[!] CRITICAL ERROR during model activation: {exc}")
            print("[*] Initiating rollback to previous artifacts...")

            # Rollback sequence
            if model_replaced:
                if had_active_model and backup_model_path.exists():
                    try:
                        backup_model_path.replace(prod_path)
                    except Exception as r_err:
                        print(f"[!] Rollback model replacement failed: {r_err}")
                elif not had_active_model:
                    prod_path.unlink(missing_ok=True)

            if metadata_replaced:
                if had_active_metadata and backup_metadata_path.exists():
                    try:
                        backup_metadata_path.replace(metadata_path)
                    except Exception as r_err:
                        print(f"[!] Rollback metadata replacement failed: {r_err}")
                elif not had_active_metadata:
                    metadata_path.unlink(missing_ok=True)

            # Clean up residual staging and backup files
            if staged_model_path.exists():
                staged_model_path.unlink(missing_ok=True)
            if staged_metadata_path.exists():
                staged_metadata_path.unlink(missing_ok=True)
            if backup_model_path.exists():
                backup_model_path.unlink(missing_ok=True)
            if backup_metadata_path.exists():
                backup_metadata_path.unlink(missing_ok=True)

            # Re-invalidate cache to ensure predictor doesn't hold stale state
            invalidate_model_cache()

            raise ModelActivationError(
                f"Model activation failed and was safely rolled back: {exc}"
            ) from exc

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
