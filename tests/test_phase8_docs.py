"""Phase 8: the documentation set stays true to the code it describes."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scripts import gen_config_docs

ROOT = Path(__file__).resolve().parent.parent
DOCS = [
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    ROOT / "docs" / "DESIGN.md",
    ROOT / "docs" / "THREAT_MODEL.md",
    ROOT / "docs" / "OPERATIONS.md",
    ROOT / "docs" / "WALKTHROUGH.md",
]
BANNED = ("production-grade", "enterprise", "military-grade")
REF = re.compile(r"`([\w./-]+\.\w+):(\d+)` — `([^`]+)`")
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")


def test_config_table_in_operations_is_not_stale():
    assert gen_config_docs.main(["--check"]) == 0


def test_every_setting_has_a_description():
    text = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    assert "(add a description" not in text


@pytest.mark.parametrize("path", DOCS, ids=lambda p: p.name)
def test_no_unsupported_marketing_adjectives(path):
    text = path.read_text(encoding="utf-8").lower()
    assert not [word for word in BANNED if word in text]


@pytest.mark.parametrize("path", DOCS, ids=lambda p: p.name)
def test_relative_links_and_images_resolve(path):
    missing = []
    for target in LINK.findall(path.read_text(encoding="utf-8")):
        if re.match(r"[a-z]+:", target) or target.startswith("#"):
            continue
        if not (path.parent / target.split("#")[0]).exists():
            missing.append(target)
    assert not missing


def test_walkthrough_references_point_at_their_symbols():
    text = (ROOT / "docs" / "WALKTHROUGH.md").read_text(encoding="utf-8")
    refs = REF.findall(text)
    assert len(refs) >= 25
    stale = []
    for rel, line, symbol in refs:
        lines = (ROOT / rel).read_text(encoding="utf-8").splitlines()
        number = int(line)
        if number > len(lines) or symbol not in lines[number - 1]:
            stale.append(f"{rel}:{line} {symbol!r}")
    assert not stale, stale


def test_walkthrough_has_fifteen_questions():
    text = (ROOT / "docs" / "WALKTHROUGH.md").read_text(encoding="utf-8")
    section = text.split("## Fifteen questions")[1]
    assert len(re.findall(r"^\d+\. \*\*", section, flags=re.M)) == 15


def test_readme_results_block_is_generated_and_reproducible():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    block = text.split("<!-- RESULTS:BEGIN")[1].split("<!-- RESULTS:END -->")[0]
    assert "python main.py eval --scenarios all --out eval_output" in block
    assert re.search(r"Commit: `[0-9a-f]{40}`", block)
    assert "ML gate" in block


def test_readme_has_mermaid_architecture_and_required_sections():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "```mermaid" in text
    for heading in (
        "## 60-second quickstart",
        "## Detectors",
        "## Results",
        "## Security model",
        "## Limitations",
        "## Roadmap",
    ):
        assert heading in text


def test_detector_table_matches_settings_defaults():
    from config import settings

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("| Vertical scan")).lower()
    assert f"at least {settings.VERTICAL_SCAN_THRESHOLD} distinct ports" in row
    assert f"within {settings.PORT_SCAN_TIME_WINDOW:.0f} s" in row
    flood = next(line for line in text.splitlines() if line.startswith("| SYN flood")).lower()
    assert f"at least {settings.SYN_FLOOD_THRESHOLD} syn/s" in flood
    assert f"below {settings.SYN_FLOOD_COMPLETION_RATIO}" in flood
