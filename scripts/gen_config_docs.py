"""
Generate the configuration reference in docs/OPERATIONS.md from config/settings.py (and a scan for other SENTINELX_*
variables). Nothing in the table is typed by hand.

    python scripts/gen_config_docs.py            # rewrite the table between the markers
    python scripts/gen_config_docs.py --check    # exit 1 if the committed table is stale (used in CI and in a test)
"""

from __future__ import annotations

import argparse
import ast
import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = ROOT / "config" / "settings.py"
DOC = ROOT / "docs" / "OPERATIONS.md"
BEGIN, END = "<!-- CONFIG_TABLE_BEGIN -->", "<!-- CONFIG_TABLE_END -->"
SKIP_DIRS = {
    ".venv",
    "tests",
    "docs",
    "node_modules",
    "__pycache__",
    ".git",
    "dashboard",
    "models",
    "data",
    "eval_output",
}

# Variables read outside config/settings.py: purpose is documented here (the names and files are found by scanning).
OTHER_ENV = {
    "SENTINELX_DB_PATH": "Full path of alerts.db (default: `<SENTINELX_DATA_DIR>/alerts.db`).",
    "SENTINELX_APP_DB_PATH": "Full path of app.db: users, sessions, API keys, triage state, audit log (default: `<SENTINELX_DATA_DIR>/app.db`).",
    "SENTINELX_ALERT_LOG": "Full path of the JSONL alert log (default: `<SENTINELX_DATA_DIR>/alerts.jsonl`).",
    "SENTINELX_MAX_LOG_SIZE": "Size in bytes at which alerts.jsonl rotates (default 10485760).",
    "SENTINELX_MAX_LOG_BACKUPS": "Rotated JSONL files to keep (default 5).",
    "SENTINELX_WEBHOOK_URL": "SECRET. Webhook destination; enables the webhook sink when set. Never logged or returned by the API.",
    "SENTINELX_MODEL_KEY": "SECRET. HMAC key (16+ bytes) to sign and verify ML model files. Never stored in the repository.",
    "SENTINELX_ML": "`on` enables the flow model, but only if the model verifies and its signed gate says PASS. Default off.",
}

# One-line meaning per setting (units included). The generator fails its test if a setting has no entry here.
MEANING = {
    "SENTINELX_CAP_VERTICAL": "Max (source, target) pairs tracked by the vertical-scan detector (LRU eviction beyond it).",
    "SENTINELX_CAP_HORIZONTAL": "Max (source, port) pairs tracked by the horizontal-scan detector.",
    "SENTINELX_CAP_SLOW_SCAN": "Max sources tracked by the slow-scan detector.",
    "SENTINELX_CAP_SYN_FLOOD_AGGREGATES": "Max (target, port) SYN aggregates tracked.",
    "SENTINELX_CAP_SYN_FLOOD_HALF_OPEN": "Max half-open connection 4-tuples tracked.",
    "SENTINELX_CAP_VOLUMETRIC": "Max destination hosts tracked by the volumetric detector.",
    "SENTINELX_CAP_COOLDOWNS": "Max alert-cooldown keys tracked.",
    "SENTINELX_CAP_FLOWS": "Max concurrent flows in the ML flow table (LRU eviction emits the evicted flow).",
    "SENTINELX_CAP_FLOW_SOURCES": "Max sources with per-source flow history (ML context features).",
    "SENTINELX_STATE_TTL": "Seconds of event time after which idle detector state is evicted.",
    "SENTINELX_PORT_SCAN_THRESHOLD": "Default distinct-port threshold for vertical scans.",
    "SENTINELX_VERTICAL_SCAN_THRESHOLD": "Distinct ports to one target inside the window that raises a vertical scan alert.",
    "SENTINELX_HORIZONTAL_SCAN_THRESHOLD": "Distinct targets on one port inside the window that raises a horizontal scan alert.",
    "SENTINELX_PORT_SCAN_WINDOW": "Seconds of event time for fast scans.",
    "SENTINELX_PORT_SCAN_COOLDOWN": "Seconds before the same scan alerts again.",
    "SENTINELX_SLOW_SCAN_THRESHOLD": "Distinct ports (or targets) in the slow window that raises a slow scan alert.",
    "SENTINELX_SLOW_SCAN_WINDOW": "Seconds of event time for slow scans.",
    "SENTINELX_SLOW_SCAN_COOLDOWN": "Seconds before the same slow scan alerts again.",
    "SENTINELX_SYN_FLOOD_THRESHOLD": "SYNs per second to one (target, port) that can raise a SYN flood alert.",
    "SENTINELX_SYN_FLOOD_WINDOW": "Seconds of event time over which the SYN rate is measured.",
    "SENTINELX_SYN_FLOOD_COMPLETION_RATIO": "Handshake completion ratio (ACKs/SYNs) below which a high SYN rate counts as a flood.",
    "SENTINELX_SYN_FLOOD_COOLDOWN": "Seconds before the same target alerts again.",
    "SENTINELX_SYN_FLOOD_HALF_OPEN_TTL": "Seconds a half-open connection is remembered.",
    "SENTINELX_VOLUMETRIC_WINDOW": "Seconds of event time per volumetric measurement window.",
    "SENTINELX_VOLUMETRIC_EWMA_ALPHA": "EWMA smoothing factor for the per-destination baseline (0 < alpha <= 1).",
    "SENTINELX_VOLUMETRIC_WARMUP_WINDOWS": "Completed windows before the adaptive baseline is trusted; only the hard ceilings apply until then.",
    "SENTINELX_VOLUMETRIC_CEILING_PPS": "Packets per second that alerts regardless of baseline.",
    "SENTINELX_VOLUMETRIC_CEILING_BPS": "Bytes per second that alerts regardless of baseline.",
    "SENTINELX_VOLUMETRIC_FLOOR_PPS": "Minimum packets per second the adaptive threshold can fall to.",
    "SENTINELX_VOLUMETRIC_FLOOR_BPS": "Minimum bytes per second the adaptive threshold can fall to.",
    "SENTINELX_VOLUMETRIC_MULTIPLIER_K": "Alert when the rate exceeds K times the EWMA baseline (and the floor).",
    "SENTINELX_VOLUMETRIC_MIN_PACKETS": "Packets that must be seen in the window before it is evaluated.",
    "SENTINELX_VOLUMETRIC_MIN_ELAPSED_SEC": "Minimum seconds of observation before it is evaluated.",
    "SENTINELX_VOLUMETRIC_COOLDOWN": "Seconds before the same destination alerts again.",
    "SENTINELX_VOLUMETRIC_TOP_TALKERS_MAX": "Max distinct sources recorded per destination window (top 5 go into the alert).",
    "SENTINELX_LOCAL_NETWORKS": "Comma-separated CIDRs treated as local by the volumetric detector.",
    "SENTINELX_INTERFACE": "Network interface for `main.py sensor` (default: system default).",
    "SENTINELX_QUEUE_SIZE": "Capacity of the bounded packet queue; packets arriving when it is full are dropped and counted.",
    "SENTINELX_QUEUE_TIMEOUT": "Seconds the consumer waits on an empty queue before re-checking for shutdown.",
    "SENTINELX_LOG_LEVEL": "Python logging level.",
    "SENTINELX_ML_ALERT_COOLDOWN": "Seconds before the ML model raises another ML_ANOMALY alert for the same source/target pair.",
    "SENTINELX_FLOW_ACTIVE_TIMEOUT": "ML flows are cut after this many seconds of event time.",
    "SENTINELX_FLOW_IDLE_TIMEOUT": "ML flows end after this many seconds without a packet.",
    "SENTINELX_ML_MODEL_DIR": "Directory holding the signed model and gate file (used only when SENTINELX_ML=on).",
    "SENTINELX_API_HOST": "Address the API binds to. Keep 127.0.0.1 unless a reverse proxy or container publishes it.",
    "SENTINELX_API_PORT": "API port.",
    "SENTINELX_API_DEFAULT_LIMIT": "Default page size of the alert list.",
    "SENTINELX_API_MAX_LIMIT": "Largest page size of the alert list.",
    "SENTINELX_DATA_DIR": "Directory for alerts.db, app.db and alerts.jsonl.",
    "SENTINELX_SENSOR_ID": "Name this sensor writes into alerts and heartbeats.",
    "SENTINELX_STATS_INTERVAL": "Seconds between pipeline throughput log lines.",
    "SENTINELX_RETENTION_DAYS": "Alerts older than this are pruned daily by the sensor; 0 disables pruning.",
    "SENTINELX_AUDIT_RETENTION_DAYS": "Audit-log rows older than this are deleted only by the admin command `python main.py db prune-audit`; 0 keeps them forever.",
    "SENTINELX_RETENTION_INTERVAL": "Seconds between automatic prune runs.",
    "SENTINELX_STATUS_INTERVAL": "Seconds between sensor heartbeat rows.",
    "SENTINELX_SENSOR_OFFLINE_AFTER": "Seconds without a heartbeat after which the API reports the sensor offline.",
    "SENTINELX_STATUS_RETENTION_HOURS": "Hours of heartbeat history kept (feeds the health sparklines).",
    "SENTINELX_API_THREADS": "Waitress threads. Must leave headroom over SENTINELX_MAX_STREAMS (checked at start-up).",
    "SENTINELX_RATE_LIMIT": "API requests per minute per user, API key or anonymous IP on /api/v1/*.",
    "SENTINELX_LOGIN_RATE_LIMIT": "Requests per minute per IP to /login.",
    "SENTINELX_RATE_LIMIT_BUCKETS": "Max rate-limit buckets kept in memory (LRU).",
    "SENTINELX_TRUSTED_PROXIES": "Comma-separated IPs/CIDRs allowed to set X-Forwarded-For; empty trusts none.",
    "SENTINELX_MAX_STREAMS": "Max concurrent live-update streams (SSE); further requests get 429 and the console falls back to polling.",
    "SENTINELX_STREAM_INTERVAL": "Seconds between live-update events.",
    "SENTINELX_STREAM_HEARTBEAT": "Seconds of silence before an SSE comment heartbeat is sent.",
    "SENTINELX_EXPORT_MAX_ROWS": "Hard cap on rows in a CSV/JSON export.",
    "SENTINELX_GRAPH_MAX_NODES": "Max hosts returned for the attack graph.",
    "SENTINELX_GRAPH_MAX_EDGES": "Max connections returned for the attack graph.",
    "SENTINELX_DROP_WARN_RATIO": "Health view warns when the dropped/received ratio over 30 minutes exceeds this.",
    "SENTINELX_HTTPS": "Set to true when served over HTTPS: adds the Secure cookie flag and HSTS.",
    "SENTINELX_SESSION_IDLE": "Seconds of inactivity before a browser session expires.",
    "SENTINELX_SESSION_ABSOLUTE": "Seconds after which any session expires regardless of activity.",
    "SENTINELX_PASSWORD_MIN_LENGTH": "Minimum password length for new or reset passwords.",  # nosec B105
    "SENTINELX_LOGIN_MAX_FAILURES": "Failures per IP and per username inside the window before lockout starts.",
    "SENTINELX_LOGIN_WINDOW": "Seconds over which login failures are counted.",
    "SENTINELX_LOGIN_LOCK_BASE": "First lockout length in seconds; doubles with each further failure.",
    "SENTINELX_LOGIN_LOCK_MAX": "Longest lockout in seconds.",
    "SENTINELX_WEBHOOK_MODE": "Payload format: generic, slack or discord.",
    "SENTINELX_WEBHOOK_COOLDOWN": "Seconds (event time) before the same (threat type, source) is sent again.",
    "SENTINELX_WEBHOOK_QUEUE": "Bounded webhook queue; overflow is dropped and counted as a failure.",
    "SENTINELX_WEBHOOK_RETRIES": "Retries after the first failed delivery (exponential backoff).",
    "SENTINELX_WEBHOOK_BACKOFF": "First retry delay in seconds; doubles each retry.",
    "SENTINELX_WEBHOOK_TIMEOUT": "Seconds before one delivery attempt times out.",
    "SENTINELX_SEVERITY_RATIO_HIGH": "Observed/threshold ratio at or above which severity is HIGH.",
    "SENTINELX_SEVERITY_RATIO_MEDIUM": "Observed/threshold ratio at or above which severity is MEDIUM (below it: LOW).",
}


def _comments(source: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            out[tok.start[0]] = tok.string.lstrip("# ").strip()
    return out


def _env_call(node: ast.AST) -> ast.Call | None:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr in ("getenv", "get")
                and sub.args
                and isinstance(sub.args[0], ast.Constant)
                and isinstance(sub.args[0].value, str)
            ):
                if str(sub.args[0].value).startswith("SENTINELX_"):
                    return sub
    return None


def _type_of(value: ast.AST) -> str:
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in ("int", "float"):
        return value.func.id
    if isinstance(value, ast.Compare):
        return "bool"
    if isinstance(value, ast.ListComp):
        return "list"
    return "string"


RUNTIME_DIRS = ("backend", "capture", "config", "database", "detection", "eval", "logs", "ml")
RUNTIME_FILES = ("main.py", "scripts/healthcheck.py")
ENV_LINE = re.compile(r"getenv\(|environ\[|environ\.get|[A-Z_]+_ENV")


def _runtime_sources() -> list[Path]:
    files = [p for d in RUNTIME_DIRS for p in (ROOT / d).rglob("*.py")]
    files += [ROOT / f for f in RUNTIME_FILES]
    return [p for p in files if p != SETTINGS and "__pycache__" not in p.parts]


def _settings_uses(name: str, tree: ast.AST) -> int:
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load))


def _used(name: str, env: str, tree: ast.AST) -> bool:
    """A setting is used if code outside settings.py names it, reads its env var directly, or settings.py derives from it."""
    if _settings_uses(name, tree):
        return True
    pattern = re.compile(rf"\b{re.escape(name)}\b|\b{re.escape(env)}\b")
    return any(pattern.search(p.read_text(encoding="utf-8")) for p in _runtime_sources())


def parse_settings() -> list[dict[str, str]]:
    source = SETTINGS.read_text(encoding="utf-8")
    comments = _comments(source)
    lines = source.splitlines()
    tree = ast.parse(source)
    rows: list[dict[str, str]] = []
    section = "General"
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.targets[0], ast.Name):
            continue
        # section = nearest standalone comment line above that follows a blank line (or starts the file)
        i = node.lineno - 2
        while i >= 0 and lines[i].lstrip().startswith("#"):
            i -= 1
        for j in range(node.lineno - 2, i, -1):
            if j - 1 < 0 or not lines[j - 1].strip():
                section = comments.get(j + 1, section)
        call = _env_call(node.value)
        if call is None:
            continue
        default = call.args[1] if len(call.args) > 1 else None
        if isinstance(default, ast.Constant):
            shown = repr(default.value) if default.value != "" else "(empty)"
            shown = shown.strip("'\"") if isinstance(default.value, str) and default.value else shown
        elif default is None:
            shown = "(none)"
        else:
            shown = "computed: " + ast.unparse(default)[:48].replace("`", "")
        env_name = str(call.args[0].value)  # type: ignore[attr-defined]
        note = (
            MEANING.get(env_name)
            or comments.get(node.end_lineno or node.lineno, "")
            or "(add a description to MEANING)"
        )
        if not _used(node.targets[0].id, env_name, tree):
            note = f"UNUSED: no code reads it. {note}"
        rows.append(
            {
                "section": section,
                "env": str(call.args[0].value),  # type: ignore[attr-defined]
                "setting": node.targets[0].id,
                "default": shown,
                "type": _type_of(node.value),
                "note": note,
            }
        )
    return rows


def other_env_rows(known: set[str]) -> list[tuple[str, str, str]]:
    found: dict[str, set[str]] = {}
    for path in _runtime_sources():
        for line in path.read_text(encoding="utf-8").splitlines():
            if ENV_LINE.search(line):
                for name in re.findall(r"SENTINELX_[A-Z0-9_]+", line):
                    found.setdefault(name, set()).add(path.relative_to(ROOT).as_posix())
    # secrets whose name is held in a constant such as WEBHOOK_URL_ENV = "SENTINELX_WEBHOOK_URL"
    for node in ast.parse(SETTINGS.read_text(encoding="utf-8")).body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id.endswith("_ENV")
            and isinstance(node.value, ast.Constant)
        ):
            const, env = node.targets[0].id, str(node.value.value)
            for path in _runtime_sources():
                if any(
                    const in line and ENV_LINE.search(line) for line in path.read_text(encoding="utf-8").splitlines()
                ):
                    found.setdefault(env, set()).add(path.relative_to(ROOT).as_posix())
    rows = []
    for name in sorted(found):
        if name in known:
            continue
        rows.append(
            (
                name,
                ", ".join(f"`{p}`" for p in sorted(found[name])),
                OTHER_ENV.get(name, "(add a description to OTHER_ENV in scripts/gen_config_docs.py)"),
            )
        )
    return rows


def render() -> str:
    rows = parse_settings()
    out = ["Generated by `scripts/gen_config_docs.py` from `config/settings.py`. Do not edit between the markers.", ""]
    sections: dict[str, list[dict[str, str]]] = {}
    for r in rows:
        sections.setdefault(r["section"], []).append(r)
    for name, items in sections.items():
        out += [f"#### {name}", "", "| Environment variable | Default | Type | Meaning |", "| --- | --- | --- | --- |"]
        for r in items:
            out.append(f"| `{r['env']}` | `{r['default']}` | {r['type']} | {r['note']} |")
        out.append("")
    other = other_env_rows({r["env"] for r in rows})
    out += [
        "#### Other variables (read outside `config/settings.py`)",
        "",
        "| Environment variable | Read in | Meaning |",
        "| --- | --- | --- |",
    ]
    out += [f"| `{n}` | {files} | {desc} |" for n, files, desc in other]
    return "\n".join(out).rstrip() + "\n"


def splice(text: str, table: str) -> str:
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
    if not pattern.search(text):
        raise SystemExit(f"{DOC} is missing the {BEGIN} / {END} markers")
    return pattern.sub(lambda _m: f"{BEGIN}\n{table}{END}", text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    current = DOC.read_text(encoding="utf-8")
    updated = splice(current, render())
    if args.check:
        if updated != current:
            print(
                "docs/OPERATIONS.md configuration table is stale: run python scripts/gen_config_docs.py",
                file=sys.stderr,
            )
            return 1
        print("docs/OPERATIONS.md configuration table is up to date")
        return 0
    DOC.write_text(updated, encoding="utf-8")
    print(f"[+] updated {DOC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
