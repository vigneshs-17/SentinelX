"""
Render docs/ML_REPORT.md from machine-generated JSON (train_report.json, ml_eval.json, flows.csv.gz.meta.json).
Every number in the report is read from those files; nothing is typed by hand. With no inputs it renders an
honest NOT RUN report.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DATASET_BEGIN = "<!-- DATASET_FILES_BEGIN -->"
DATASET_END = "<!-- DATASET_FILES_END -->"


def _f(x: Any, nd: int = 4) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, bool):
        return str(x)
    if isinstance(x, int):
        return f"{x:,}"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def _ts(x: float) -> str:
    return datetime.fromtimestamp(x, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return out + [""]


def dataset_files_table(meta: dict[str, Any] | None) -> list[str]:
    if not meta or not meta.get("files"):
        return ["No PCAP files were processed (no build metadata available).", ""]
    rows = []
    for f in meta["files"]:
        rows.append(
            [
                f"`{f['name']}`",
                f["status"],
                _f(f.get("size_bytes")),
                f"`{f['sha256']}`" if f.get("sha256") else "n/a",
                _f(f.get("packets")),
                _f(f.get("flows")),
            ]
        )
    return _table(["File", "Status", "Size (bytes)", "SHA-256", "Packets", "Flows"], rows)


def update_dataset_doc(doc_path: Path, meta: dict[str, Any] | None) -> None:
    """Replace the generated files table between the markers in docs/DATASET.md."""
    text = doc_path.read_text(encoding="utf-8")
    block = DATASET_BEGIN + "\n" + "\n".join(dataset_files_table(meta)) + "\n" + DATASET_END
    pattern = re.compile(re.escape(DATASET_BEGIN) + r".*?" + re.escape(DATASET_END), re.S)
    if not pattern.search(text):
        raise ValueError("DATASET.md is missing the generated-table markers")
    doc_path.write_text(pattern.sub(lambda _m: block, text), encoding="utf-8")


def _gate_section(ev: dict[str, Any] | None) -> list[str]:
    lines = ["## Gate decision", ""]
    if not ev:
        return lines + [
            "**Decision: NOT RUN.** No held-out replay evaluation exists, so ML has not earned a place in the alert path. "
            "ML stays disabled (`SENTINELX_ML` defaults to off, and a model is refused at load without a signed PASS gate).",
            "",
        ]
    g = ev["gate"]
    lines += [f"**Decision: {g['decision']}.** {g['reason']}", ""]
    r, h = ev["rules_only"], ev["rules_plus_ml"]
    lines += _table(
        ["Metric (test replay)", "Rules only", "Rules + ML"],
        [
            [
                "Headline recall (attack-minutes, classes seen in training)",
                _f(r["recall_headline"]),
                _f(h["recall_headline"]),
            ],
            [
                "False alerts per benign hour",
                _f(r["false_alerts_per_benign_hour"]),
                _f(h["false_alerts_per_benign_hour"]),
            ],
            ["Alerts", _f(r["alerts"]), _f(h["alerts"])],
            ["False alerts", _f(r["false_alerts"]), _f(h["false_alerts"])],
            ["Alert precision", _f(r["alert_precision"]), _f(h["alert_precision"])],
            ["Recall, all classes incl. zero-shot", _f(r["recall_all_classes"]), _f(h["recall_all_classes"])],
            ["F1, all classes", _f(r["f1_all_classes"]), _f(h["f1_all_classes"])],
        ],
    )
    lines += [
        f"Required: recall gain >= {_f(g['min_recall_gain'])} (absolute) at equal or lower false alerts per benign hour. "
        f"Observed recall gain: {_f(g.get('recall_gain'))}.",
        "",
    ]
    if g["decision"] != "PASS":
        lines += ["**ML is out of the runtime alert path and is documented as an experiment.**", ""]
    return lines


def _alert_class_section(ev: dict[str, Any]) -> list[str]:
    classes = sorted(set(ev["rules_only"]["per_class"]) | set(ev["rules_plus_ml"]["per_class"]))
    rows = []
    for c in classes:
        r = ev["rules_only"]["per_class"].get(c, {})
        h = ev["rules_plus_ml"]["per_class"].get(c, {})
        tag = "zero-shot" if c in ev["zero_shot_classes"] else "headline"
        rows.append(
            [
                c,
                tag,
                _f(r.get("recall")),
                _f(h.get("recall")),
                _f(r.get("instance_recall")),
                _f(h.get("instance_recall")),
            ]
        )
    return [
        "## Alert-level recall per class (test replay)",
        "",
        "Recall = share of 60 s buckets of each labelled attack window with at least one alert for that attacker/victim pair. "
        "Zero-shot classes (absent from training) are reported but excluded from headline numbers.",
        "",
        *_table(
            ["Class", "Kind", "Recall rules", "Recall rules+ML", "Windows hit rules", "Windows hit rules+ML"], rows
        ),
    ]


def _flow_section(tr: dict[str, Any]) -> list[str]:
    fm = tr.get("flow_metrics_test")
    if not fm:
        return ["## Flow model (held-out test split)", "", "No test split flows were available.", ""]
    rows = []
    for c in fm["labels"]:
        m = fm["per_class"][c]
        rows.append(
            [
                c,
                _f(m["precision"]),
                _f(m["recall"]),
                _f(m["f1"]),
                _f(m["support"]),
                _f(m["pr_auc"]),
                "yes" if m["in_training"] else "no (zero-shot)",
            ]
        )
    b = fm["binary_attack_vs_benign"]
    lines = [
        "## Flow model (held-out test split)",
        "",
        *_table(["Class", "Precision", "Recall", "F1", "Support", "PR-AUC", "In training"], rows),
        f"Headline macro-F1 (attack classes seen in training): {_f(fm['headline_macro_f1'])}.",
        "",
        f"Attack-vs-benign at the validation-calibrated threshold {_f(b['threshold'])}: precision {_f(b['precision'])}, "
        f"recall {_f(b['recall'])}, PR-AUC {_f(b['pr_auc'])} (TP {_f(b['tp'])}, FP {_f(b['fp'])}, FN {_f(b['fn'])}).",
        "",
        "### Confusion matrix (rows = true, columns = predicted)",
        "",
        *_table(
            ["true \\ pred", *fm["labels"]],
            [[lab, *[_f(v) for v in row]] for lab, row in zip(fm["labels"], fm["confusion_matrix"], strict=True)],
        ),
    ]
    if fm["zero_shot"]:
        lines += ["### Zero-shot classes (not in training, not in headline numbers)", ""]
        lines += _table(
            ["Class", "Test flows", "Flagged as attack"],
            [[c, _f(v["support"]), _f(v["flagged_as_attack_rate"])] for c, v in fm["zero_shot"].items()],
        )
    return lines


def render_report(
    train: dict[str, Any] | None,
    ev: dict[str, Any] | None,
    meta: dict[str, Any] | None,
    git_sha: str,
    sources: list[str],
) -> str:
    L: list[str] = ["# ML flow model report", ""]
    L += [
        f"Generated by `scripts/gen_ml_report.py` from: {', '.join(f'`{s}`' for s in sources) if sources else 'no inputs'}. "
        "Do not edit by hand; re-generate.",
        "",
        f"- Git commit: `{git_sha}`",
    ]
    if ev:
        L += [f"- Model SHA-256: `{ev['model_sha256']}`", f"- Replay PCAPs: {', '.join(f'`{p}`' for p in ev['pcaps'])}"]
    L.append("")
    L += _gate_section(ev)
    if train is None:
        L += [
            "## Status",
            "",
            "No training run and no evaluation exist for this commit: the CIC-IDS2017 PCAPs were not available on the build machine, "
            "and no numbers are invented. See `docs/DATASET.md` for the exact files, the attack schedule and how to run "
            "`scripts/build_flows.py`, `main.py train` and `main.py eval --pcap ... --labels ... --ml-model ...`.",
            "",
        ]
    else:
        if train.get("mode") == "smoke":
            L += [
                "## Smoke model",
                "",
                "Trained only to exercise the code path. It makes no accuracy claim and is never gate-eligible.",
                "",
            ]
        else:
            L += _flow_section(train)
            L += [
                "## Split table",
                "",
                f"Purge gap: {_f(train['purge_gap_seconds'])} s. Purged flows: {_f(train['purged_flows'])}.",
                "",
            ]
            rows = [
                [
                    f"`{r['file']}`",
                    r["split"],
                    f"{_ts(r['start_ts'])} - {_ts(r['end_ts'])} UTC",
                    _f(r["flows"]),
                    ", ".join(f"{k}: {v:,}" for k, v in r["class_counts"].items()),
                ]
                for r in train["split_table"]
            ]
            L += _table(["File", "Split", "Time range (UTC)", "Flows", "Class counts"], rows)
            L += ["### Class split policy", ""] + _table(
                ["Class", "Policy"], [[c, p] for c, p in sorted(train["class_split_policy"].items())]
            )
            L += ["## Permutation importance (test split, top 10)", ""]
            L += _table(
                ["Feature", "Mean importance", "Std"],
                [
                    [f"`{x['feature']}`", _f(x["importance_mean"]), _f(x["importance_std"])]
                    for x in train.get("permutation_importance_top10", [])
                ],
            )
        thr = train.get("threshold", {})
        L += [
            "## Threshold calibration (validation split only)",
            "",
            f"Threshold {_f(thr.get('threshold'))}; method: {thr.get('method', 'n/a')}.",
            "",
        ]
    if ev:
        L += _alert_class_section(ev)
        L += [
            "## Replay details",
            "",
            f"Packets read {_f(ev['packets_read'])}, replayed {_f(ev['packets_replayed'])}; replay time {_f(ev['replay_seconds'], 1)} s of which attack {_f(ev['attack_seconds'], 1)} s "
            f"and benign {_f(ev['benign_seconds'], 1)} s. ML alerts raised: {_f(ev['ml_alert_count'])}.",
            "",
        ]
    L += ["## Dataset files", "", *dataset_files_table(meta)]
    if meta and meta.get("warnings"):
        L += ["### Build warnings", "", *[f"- {w}" for w in meta["warnings"]], ""]
    if meta and meta.get("missing"):
        L += ["### Missing files (not processed)", "", *[f"- `{m}`" for m in meta["missing"]], ""]
    L += ["## Wall-clock time", ""]
    rows = []
    if meta and any(f.get("status") == "PROCESSED" for f in meta.get("files", [])):
        rows.append(["Build flows (all files)", f"{_f(meta.get('wall_clock_seconds'), 1)} s"])
    if train:
        rows.append(["Train", f"{_f(train.get('wall_clock_seconds'), 1)} s"])
    if ev:
        rows.append(["Replay evaluation", f"{_f(ev.get('wall_clock_seconds'), 1)} s"])
    L += _table(["Step", "Time"], rows) if rows else ["Not measured (no runs).", ""]
    L += [
        "## Model artifact security",
        "",
        "Model files are build outputs and are not committed. They are written with `skops` (no pickle) and signed with "
        "HMAC-SHA256 using the key in the environment variable `SENTINELX_MODEL_KEY`; the key is never stored in the repository.",
        "",
        "Before loading, the signature is checked with `hmac.compare_digest`; then skops loads with an explicit allow-list of types; "
        "then the feature schema must match the running extractor; at runtime a signed `gate.json` bound to the model's SHA-256 must say PASS.",
        "",
        "**This stops:** a tampered, truncated, swapped or unsigned model file; a model file that tries to instantiate "
        "arbitrary classes; loading a model whose features do not match the code; enabling a model that did not pass the gate.",
        "",
        "**This does not stop:** a compromised training machine (it can train and sign a malicious model); a stolen or leaked "
        "`SENTINELX_MODEL_KEY` (whoever holds it can sign anything); poisoned training data; an attacker who can both "
        "replace the model and read the key from the host environment.",
        "",
    ]
    return "\n".join(L)
