"""
Flow-level model: split, train, calibrate, evaluate on held-out data, and score.

Model: scikit-learn HistGradientBoostingClassifier with balanced class weights (no deep learning).
Attack score = 1 - P(BENIGN). The alert threshold is calibrated on the validation split only; final numbers
come from the separate test split.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance

from config.settings import FLOW_ACTIVE_TIMEOUT
from ml.artifact import save_bundle
from ml.dataset import BENIGN, DEFAULT_SCHEDULE, AttackWindow, load_schedule
from ml.evaluate import flow_metrics
from ml.flows import FEATURE_NAMES
from ml.splits import TEST, TRAIN, VAL, ClassWindow, SplitPlan, build_split_plan

META_COLUMNS = [
    "file",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "start_ts",
    "end_ts",
    "end_reason",
    "label",
]
FLOW_COLUMNS = META_COLUMNS + list(FEATURE_NAMES)
TARGET_FPR = 0.001
SEED = 42
IMPORTANCE_MAX_ROWS = 20000


class TrainingError(ValueError):
    pass


def git_sha() -> str:
    try:
        out = subprocess.run(  # nosec B603 B607
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, check=False
        )
        sha = out.stdout.strip()
        if out.returncode != 0 or not sha:
            return "unknown"
        dirty = subprocess.run(  # nosec B603 B607
            ["git", "status", "--porcelain"], capture_output=True, text=True, timeout=30, check=False
        )
        return sha + ("+uncommitted-changes" if dirty.stdout.strip() else "")
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def read_flows(path: Path | str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in FLOW_COLUMNS if c not in df.columns]
    if missing:
        raise TrainingError(f"flows file is missing columns: {missing}")
    return df


def file_spans(df: pd.DataFrame) -> dict[str, tuple[float, float]]:
    g = df.groupby("file").agg(lo=("start_ts", "min"), hi=("end_ts", "max"))
    return {str(f): (float(r.lo), float(r.hi)) for f, r in g.iterrows()}


def class_windows(windows: list[AttackWindow], spans: dict[str, tuple[float, float]]) -> list[ClassWindow]:
    """Assign each schedule window to the capture file it overlaps; windows outside every file are dropped."""
    out: list[ClassWindow] = []
    for w in windows:
        best, best_overlap = None, 0.0
        for f, (lo, hi) in spans.items():
            overlap = min(hi, w.end_ts) - max(lo, w.start_ts)
            if overlap > best_overlap:
                best, best_overlap = f, overlap
        if best is not None:
            out.append(ClassWindow(w.cls, best, w.start_ts, w.end_ts))
    return out


def assign_splits(df: pd.DataFrame, plan: SplitPlan) -> pd.DataFrame:
    out = df.copy()
    out["split"] = [
        plan.split_of(f, s, e) or "purged"
        for f, s, e in zip(out["file"].astype(str), out["start_ts"], out["end_ts"], strict=True)
    ]
    return out


def split_table(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Exact split table: per (file, split) the kept time range and class counts."""
    rows: list[dict[str, Any]] = []
    for (file, split), g in df.groupby(["file", "split"], sort=True):
        rows.append(
            {
                "file": str(file),
                "split": str(split),
                "start_ts": float(g["start_ts"].min()),
                "end_ts": float(g["end_ts"].max()),
                "flows": int(len(g)),
                "class_counts": {str(k): int(v) for k, v in g["label"].value_counts().sort_index().items()},
            }
        )
    return rows


def fit_model(train: pd.DataFrame, seed: int = SEED) -> HistGradientBoostingClassifier:
    if train["label"].nunique() < 2:
        raise TrainingError("training split needs at least two classes (benign and one attack class)")
    model = HistGradientBoostingClassifier(
        class_weight="balanced", max_iter=200, random_state=seed, early_stopping=False
    )
    model.fit(train[list(FEATURE_NAMES)].to_numpy(dtype=float), train["label"].astype(str).to_numpy())
    return model


def attack_scores(model: HistGradientBoostingClassifier, X: np.ndarray, benign: str = BENIGN) -> np.ndarray:
    proba = model.predict_proba(X)
    classes = list(model.classes_)
    return 1.0 - proba[:, classes.index(benign)] if benign in classes else np.zeros(len(X))


def calibrate_threshold(
    y_true: np.ndarray, scores: np.ndarray, target_fpr: float = TARGET_FPR, benign: str = BENIGN
) -> dict[str, Any]:
    """Lowest threshold (floor 0.5) whose benign flow false-positive rate on VALIDATION data is <= target_fpr."""
    is_attack = y_true != benign
    neg, pos = scores[~is_attack], scores[is_attack]
    if len(neg) == 0 or len(pos) == 0:
        return {
            "threshold": 0.5,
            "method": "fallback_no_validation_signal",
            "val_negatives": int(len(neg)),
            "val_positives": int(len(pos)),
        }
    allowed = int(np.floor(target_fpr * len(neg)))
    ranked = np.sort(neg)[::-1]
    thr = float(np.nextafter(ranked[allowed], 1.0)) if allowed < len(ranked) else 0.0
    thr = float(min(max(thr, 0.5), 0.999))
    return {
        "threshold": thr,
        "method": f"lowest threshold with validation benign flow FPR <= {target_fpr}",
        "val_negatives": int(len(neg)),
        "val_positives": int(len(pos)),
        "val_fpr_at_threshold": float((neg >= thr).mean()),
        "val_recall_at_threshold": float((pos >= thr).mean()),
    }


def test_labels_payload(
    windows: list[AttackWindow], plan: SplitPlan, trained: set[str], zero_shot: list[str], pcaps: list[str]
) -> dict[str, Any]:
    """Labels + test segments consumed by `main.py eval --pcap ... --labels ...`."""
    segs = plan.segments(TEST)
    labels: list[dict[str, Any]] = []
    for w in windows:
        for file, a, b in segs:
            lo, hi = max(a, w.start_ts), min(b, w.end_ts)
            if hi > lo:
                labels.append(
                    {
                        "attack_type": w.cls,
                        "file": file,
                        "attacker_ips": sorted(w.attackers) + [str(n) for n in w.attacker_nets],
                        "victim_ips": sorted(w.victims) + [str(n) for n in w.victim_nets],
                        "start_ts": lo,
                        "end_ts": hi,
                    }
                )
    return {
        "format": "sentinelx-ml-eval-labels-1",
        "labels": labels,
        "segments": [{"file": f, "start_ts": a, "end_ts": b} for f, a, b in segs],
        "trained_classes": sorted(trained),
        "zero_shot_classes": zero_shot,
        "pcaps": pcaps,
    }


def train_from_flows(
    flows_path: Path | str,
    out_dir: Path | str,
    schedule_path: Path | str = DEFAULT_SCHEDULE,
    utc_offset_hours: float | None = None,
    active_timeout: float = FLOW_ACTIVE_TIMEOUT,
    short_class_policy: str = "test",
    smoke: bool = False,
    key: bytes | str | None = None,
) -> dict[str, Any]:
    """
    Full training run. Normal mode: split by plan, fit on train, calibrate on val, report on test, permutation
    importance on test. Smoke mode (CI): fit on all rows of a tiny synthetic flow set, no held-out claims.
    """
    wall = time.perf_counter()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    df = read_flows(flows_path)
    df["label"] = df["label"].astype(str)
    report: dict[str, Any] = {
        "mode": "smoke" if smoke else "full",
        "git_sha": git_sha(),
        "flows_path": Path(flows_path).name,
        "feature_names": list(FEATURE_NAMES),
        "seed": SEED,
        "total_flows": int(len(df)),
    }

    if smoke:
        model = fit_model(df)
        classes = [str(c) for c in model.classes_]
        meta = {"mode": "smoke", "git_sha": report["git_sha"]}
        save_bundle(
            {
                "model": model,
                "classes": classes,
                "benign_label": BENIGN,
                "threshold": 0.5,
                "medium_threshold": 0.75,
                "trained_classes": sorted(set(classes)),
                "meta_json": json.dumps(meta),
            },
            out,
            key,
        )
        report.update(
            {
                "threshold": {"threshold": 0.5, "method": "smoke_default"},
                "classes": classes,
                "note": "smoke model: code-path exercise only, no accuracy claim",
            }
        )
        report["wall_clock_seconds"] = time.perf_counter() - wall
        (out / "train_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report

    windows = load_schedule(schedule_path, utc_offset_hours)
    spans = file_spans(df)
    plan = build_split_plan(class_windows(windows, spans), spans, active_timeout, short_class_policy=short_class_policy)
    df = assign_splits(df, plan)
    report["split_table"] = split_table(df)
    report["purge_gap_seconds"] = plan.purge_gap
    report["class_split_policy"] = plan.class_policy
    report["purged_flows"] = int((df["split"] == "purged").sum())

    train, val, test = (df[df["split"] == s] for s in (TRAIN, VAL, TEST))
    if train.empty:
        raise TrainingError("empty training split")
    model = fit_model(train)
    classes = [str(c) for c in model.classes_]
    trained = {c for c in classes if c != BENIGN}
    feats = list(FEATURE_NAMES)

    cal = calibrate_threshold(
        val["label"].to_numpy(), attack_scores(model, val[feats].to_numpy(dtype=float)) if len(val) else np.array([])
    )
    thr = float(cal["threshold"])
    report["threshold"] = cal

    if len(test):
        proba = model.predict_proba(test[feats].to_numpy(dtype=float))
        y_test = test["label"].to_numpy()
        zero_shot = sorted(set(np.unique(y_test)) - set(classes) - {BENIGN})
        report["flow_metrics_test"] = flow_metrics(y_test, proba, classes, trained, thr)
        sample = test.sample(n=min(len(test), IMPORTANCE_MAX_ROWS), random_state=SEED) if len(test) else test
        imp = permutation_importance(
            model,
            sample[feats].to_numpy(dtype=float),
            sample["label"].to_numpy(),
            scoring="f1_macro",
            n_repeats=5,
            random_state=SEED,
            n_jobs=1,
        )
        order = np.argsort(imp.importances_mean)[::-1]
        report["permutation_importance_test"] = [
            {
                "feature": feats[i],
                "importance_mean": float(imp.importances_mean[i]),
                "importance_std": float(imp.importances_std[i]),
            }
            for i in order
        ]
        report["permutation_importance_top10"] = report["permutation_importance_test"][:10]
    else:
        zero_shot = []
        report["flow_metrics_test"] = None

    meta = {"git_sha": report["git_sha"], "flows": report["flows_path"], "trained_classes": sorted(trained)}
    save_bundle(
        {
            "model": model,
            "classes": classes,
            "benign_label": BENIGN,
            "threshold": thr,
            "medium_threshold": thr + (1.0 - thr) / 2.0,
            "trained_classes": sorted(trained),
            "meta_json": json.dumps(meta),
        },
        out,
        key,
    )
    report["trained_classes"] = sorted(trained)
    report["zero_shot_classes"] = zero_shot
    pcaps = sorted(spans)
    (out / "test_labels.json").write_text(
        json.dumps(test_labels_payload(windows, plan, trained, zero_shot, pcaps), indent=2), encoding="utf-8"
    )
    report["wall_clock_seconds"] = time.perf_counter() - wall
    (out / "train_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "model_card.json").write_text(
        json.dumps({"informational_only_not_trusted": True, **meta, "threshold": thr}, indent=2), encoding="utf-8"
    )
    return report
