"""
Fail the build on OWASP ZAP alerts of risk Medium or higher unless .zap/rules.tsv justifies them.

    python scripts/zap_gate.py report_json.json .zap/rules.tsv

rules.tsv lines: <pluginid><TAB>IGNORE<TAB><justification>. An IGNORE without a justification is an error, so a
rule cannot be silenced silently. Exit 0 = clean, 1 = unjustified Medium/High alert, 2 = bad input.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MEDIUM = 2  # ZAP riskcode: 0 info, 1 low, 2 medium, 3 high


def load_rules(path: Path) -> dict[str, str]:
    ignored: dict[str, str] = {}
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3 or parts[1].upper() != "IGNORE" or not parts[2].strip():
            raise ValueError(
                f"{path}:{n}: expected '<pluginid>\\tIGNORE\\t<justification>' with a non-empty justification"
            )
        ignored[parts[0].strip()] = parts[2].strip()
    return ignored


def blocking_alerts(report: dict, ignored: dict[str, str]) -> list[tuple[str, str, str, int]]:
    out = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            if risk >= MEDIUM and str(alert.get("pluginid")) not in ignored:
                out.append(
                    (
                        str(alert.get("pluginid")),
                        alert.get("name") or alert.get("alert", "?"),
                        alert.get("riskdesc", ""),
                        risk,
                    )
                )
    return out


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 2:
        print("usage: zap_gate.py report_json.json rules.tsv", file=sys.stderr)
        return 2
    try:
        report = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        ignored = load_rules(Path(args[1]))
    except (OSError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    blocking = blocking_alerts(report, ignored)
    for pid, name, desc, _ in blocking:
        print(f"[FAIL] ZAP {pid}: {name} ({desc})")
    print(f"ZAP gate: {len(blocking)} unjustified medium/high alert(s); {len(ignored)} justified ignore rule(s).")
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
