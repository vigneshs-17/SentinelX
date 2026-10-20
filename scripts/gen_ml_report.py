"""
Generate docs/ML_REPORT.md (and the files table in docs/DATASET.md) from machine-written JSON. No hand-typed numbers.

    python scripts/gen_ml_report.py --train models/train_report.json --eval eval_output/ml_eval.json \
        --meta flows.csv.gz.meta.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from ml.model import git_sha  # noqa: E402
from ml.report import render_report, update_dataset_doc  # noqa: E402


def _load(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train", help="models/train_report.json")
    ap.add_argument("--eval", help="eval_output/ml_eval.json")
    ap.add_argument("--meta", help="flows.csv.gz.meta.json")
    ap.add_argument("--out", default=str(repo_root / "docs" / "ML_REPORT.md"))
    ap.add_argument(
        "--dataset-doc", default=str(repo_root / "docs" / "DATASET.md"), help="'' to leave DATASET.md alone"
    )
    args = ap.parse_args(argv)

    train, ev, meta = _load(args.train), _load(args.eval), _load(args.meta)
    sources = [Path(p).name for p in (args.train, args.eval, args.meta) if p]
    text = render_report(train, ev, meta, git_sha(), sources)
    Path(args.out).write_text(text, encoding="utf-8")
    if args.dataset_doc:
        update_dataset_doc(Path(args.dataset_doc), meta)
    print(f"[+] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
