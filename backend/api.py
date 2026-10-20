"""
SentinelX API: dashboard shell, static assets, and the /api/v1 REST + SSE endpoints.

Every view carries @public or @require(...) (default deny, see backend/auth.py). alerts.db is opened read-only;
this process never writes alerts. There is no CORS: the dashboard is same-origin.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, Response, g, jsonify, request, send_from_directory

from backend import accounts, admin_routes, auth_routes
from backend.accounts import TRIAGE_STATUSES
from backend.auth import auth_metrics, client_ip, current_identity, init_auth, public, require
from backend.common import error_response
from config.settings import (
    API_DEFAULT_LIMIT,
    API_MAX_LIMIT,
    CANONICAL_THREAT_TYPES,
    DROP_WARN_RATIO,
    EXPORT_MAX_ROWS,
    GRAPH_MAX_EDGES,
    GRAPH_MAX_NODES,
    HTTPS_ENABLED,
    MAX_STREAMS,
    SENSOR_OFFLINE_AFTER,
    STREAM_HEARTBEAT_SECONDS,
    STREAM_INTERVAL_SECONDS,
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_SYN_FLOOD,
    THREAT_TYPE_VOLUMETRIC,
)
from database.app_db import AppDatabaseError, get_app_database_path
from database.database import fetch_latest_sensor_status, get_readonly_connection

app = Flask(__name__, static_folder=None)

# The API never creates or migrates alerts.db: the sensor owns it. Every connection here is read-only.
# Default deny: init_auth installs a before_request hook; every view must carry @public or @require(...).
init_auth(app)
app.register_blueprint(auth_routes.bp)
app.register_blueprint(admin_routes.bp)

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
STATIC_DIR = DASHBOARD_DIR / "static"

SCAN_TYPES = ("VERTICAL", "HORIZONTAL", "SLOW", "SLOW_VERTICAL", "SLOW_HORIZONTAL")
SEVERITIES = ("HIGH", "MEDIUM", "LOW")
MAX_OFFSET = 1_000_000


logger = logging.getLogger("sentinelx.api")


def utcnow() -> datetime:
    """Current UTC time (module-level so tests can pin it)."""
    return datetime.now(UTC)


# =============================================================================
# Validation helpers
# =============================================================================


def reject_unknown_params(allowed: set[str]) -> str | None:
    unknown = sorted(set(request.args) - allowed)
    return f"Unknown query parameter(s): {', '.join(unknown)}." if unknown else None


def _parse_ts(name: str, raw: str) -> tuple[str | None, str | None]:
    """Timezone-aware ISO-8601 -> UTC string. A '+' in the offset may arrive as a space after URL decoding."""
    cleaned = raw
    if " " in cleaned and not cleaned.endswith("Z"):
        head, _, tail = cleaned.rpartition(" ")
        if ":" in tail or tail.isdigit():
            cleaned = f"{head}+{tail}"
    try:
        dt = datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None, f"Invalid parameter '{name}': must be a valid ISO-8601 timestamp."
    if dt.tzinfo is None:
        return None, f"Invalid parameter '{name}': timestamp must be timezone-aware (include UTC offset or 'Z')."
    return dt.astimezone(UTC).isoformat(timespec="seconds"), None


def _int_param(name: str, default: int | None, low: int, high: int) -> tuple[int | None, str | None]:
    raw = request.args.get(name)
    if raw is None:
        return default, None
    try:
        value = int(raw)
    except ValueError:
        return None, f"Invalid parameter '{name}': must be an integer."
    if not low <= value <= high:
        return None, f"Parameter '{name}' must be between {low} and {high}."
    return value, None


def parse_alert_filters() -> tuple[dict[str, Any] | None, str | None]:
    """Strictly validate alert filter query parameters (shared by the list and the overview)."""
    a = request.args
    for name, value in a.items():
        if len(value) > 100:
            return None, f"Parameter '{name}' is too long."
    f: dict[str, Any] = {}

    threat_type = a.get("threat_type")
    if threat_type == "HIGH_TRAFFIC":
        threat_type = "VOLUMETRIC"
    if threat_type is not None and threat_type not in CANONICAL_THREAT_TYPES:
        return None, f"Invalid parameter 'threat_type': must be one of [{', '.join(CANONICAL_THREAT_TYPES)}]."
    f["threat_type"] = threat_type

    scan_type = a.get("scan_type")
    if scan_type is not None and scan_type not in SCAN_TYPES:
        return None, f"Invalid parameter 'scan_type': must be one of [{', '.join(SCAN_TYPES)}]."
    f["scan_type"] = scan_type

    severity = a.get("severity")
    if severity is not None:
        severity = severity.upper()
        if severity not in SEVERITIES:
            return None, "Invalid parameter 'severity': must be 'HIGH', 'MEDIUM', or 'LOW'."
    f["severity"] = severity

    status = a.get("status")
    if status is not None and status not in TRIAGE_STATUSES:
        return None, f"Invalid parameter 'status': must be one of [{', '.join(TRIAGE_STATUSES)}]."
    f["status"] = status

    source_ip = a.get("source_ip")
    if source_ip is not None:
        try:
            ipaddress.ip_network(source_ip, strict=False)
        except ValueError:
            return None, "Invalid parameter 'source_ip': must be an IP address or CIDR."
    f["source_ip"] = source_ip

    destination_ip = a.get("destination_ip")
    if destination_ip is not None:
        try:
            ipaddress.ip_network(destination_ip, strict=False)
        except ValueError:
            return None, "Invalid parameter 'destination_ip': must be an IP address or CIDR."
    f["destination_ip"] = destination_ip

    for key in ("since", "until"):
        f[key] = None
        if a.get(key) is not None:
            f[key], err = _parse_ts(key, a[key])
            if err:
                return None, err

    q = a.get("q")
    f["q"] = q if q and q.strip() else None

    for key, low, high in (("dport", 0, 65535), ("min_id", 0, 2**62)):
        f[key], err = _int_param(key, None, low, high)
        if err:
            return None, err
    return f, None


ALERT_SORTS = {
    "detected_at": "a.detected_at",
    "id": "a.id",
    "severity": "CASE a.severity WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END",
    "threat_type": "a.threat_type",
    "source_ip": "a.source_ip",
    "destination_ip": "a.destination_ip",
    "destination_port": "a.destination_port",
    "confidence": "a.confidence",
    "status": "COALESCE(t.status, 'new')",
}


def build_conditions(f: dict[str, Any]) -> tuple[list[str], list[Any]]:
    """Conditions + params for alerts a LEFT JOIN appdb.triage t."""
    conds: list[str] = []
    params: list[Any] = []
    for column, key in (("a.threat_type", "threat_type"), ("a.scan_type", "scan_type"), ("a.severity", "severity")):
        if f[key]:
            conds.append(f"{column} = ?")
            params.append(f[key])
    if f["status"] == "new":
        conds.append("(t.status IS NULL OR t.status = 'new')")
    elif f["status"]:
        conds.append("t.status = ?")
        params.append(f["status"])
    if f["source_ip"]:
        conds.append("in_cidr(a.source_ip, ?) = 1" if "/" in f["source_ip"] else "a.source_ip = ?")
        params.append(f["source_ip"])
    if f["destination_ip"]:
        conds.append("in_cidr(a.destination_ip, ?) = 1" if "/" in f["destination_ip"] else "a.destination_ip = ?")
        params.append(f["destination_ip"])
    if f["since"]:
        conds.append("a.detected_at >= ?")
        params.append(f["since"])
    if f["until"]:
        conds.append("a.detected_at <= ?")
        params.append(f["until"])
    if f["q"]:
        esc = "\\"
        escaped = f["q"].replace(esc, esc + esc).replace("%", esc + "%").replace("_", esc + "_")
        conds.append("a.message LIKE ? ESCAPE '" + esc + "'")
        params.append(f"%{escaped}%")
    if f["dport"] is not None:
        conds.append("a.destination_port = ?")
        params.append(f["dport"])
    if f["min_id"] is not None:
        conds.append("a.id > ?")
        params.append(f["min_id"])
    return conds, params


def where_sql(conds: list[str]) -> str:
    return f"WHERE {' AND '.join(conds)}" if conds else ""


def open_alert_connection() -> sqlite3.Connection:
    """Read-only alerts.db with read-only app.db attached as appdb (triage state) and the in_cidr() helper."""
    connection = get_readonly_connection()
    try:
        connection.create_function("in_cidr", 2, _in_cidr, deterministic=True)
        connection.execute("ATTACH DATABASE ? AS appdb", (f"{get_app_database_path().resolve().as_uri()}?mode=ro",))
    except sqlite3.Error as exc:
        connection.close()
        raise AppDatabaseError(str(exc)) from exc
    return connection


def _in_cidr(ip: str | None, cidr: str | None) -> int:
    try:
        return int(
            ip is not None and cidr is not None and ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        )
    except ValueError:
        return 0


# =============================================================================
# Response headers
# =============================================================================

CSP = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "img-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
    ]
)
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), display-capture=(), clipboard-write=(self)"


@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Defensive headers on every response. No CORS headers are ever sent (same-origin dashboard)."""
    h = response.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Content-Security-Policy"] = CSP
    h["Permissions-Policy"] = PERMISSIONS_POLICY
    if HTTPS_ENABLED:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.path.startswith("/static/") and request.path != "/":
        h["Cache-Control"] = "no-store"
    decision = getattr(g, "ratelimit", None)
    if decision is not None:
        h["RateLimit-Limit"] = str(decision.limit)
        h["RateLimit-Remaining"] = str(decision.remaining)
        h["RateLimit-Reset"] = str(decision.reset_seconds)
    return response


# =============================================================================
# Routes
# =============================================================================


@app.route("/")
@public
def home():
    """Serves the SentinelX single-page dashboard shell (no data)."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/static/<path:filename>")
@public
def static_files(filename: str):
    """Dashboard JS/CSS. send_from_directory refuses paths that escape the directory."""
    return send_from_directory(STATIC_DIR, filename)


@app.route("/health")
@public
def health_check():
    """
    Readiness probe: the process responds AND alerts.db can really be read (a real query on the alerts table,
    not just an open). Any failure is "degraded" with HTTP 503, never "healthy".
    """
    try:
        connection = get_readonly_connection()
        try:
            connection.execute("SELECT 1 FROM alerts LIMIT 1").fetchone()
        finally:
            connection.close()
    except Exception as exc:  # noqa: BLE001 - any failure to read means not healthy
        logger.warning("health: alerts.db is not readable: %s", exc)
        return jsonify(
            {
                "status": "degraded",
                "service": "SentinelX API",
                "database": "unreadable",
                "timestamp": utcnow().isoformat(),
            }
        ), 503
    return jsonify(
        {
            "status": "healthy",
            "service": "SentinelX API",
            "database": "readable",
            "timestamp": utcnow().isoformat(),
        }
    ), 200


def sensor_metrics(connection: sqlite3.Connection) -> dict[str, Any]:
    """Latest sensor heartbeat plus online flag; shared by /metrics and the SSE stream."""
    status = fetch_latest_sensor_status(connection)
    if status is None:
        return {"sensor_online": False, "last_seen": None, "age_seconds": None, "sensor_id": None}
    age = (utcnow() - datetime.fromisoformat(status["last_seen"])).total_seconds()
    body = {k: v for k, v in status.items() if k != "id"}
    body.update({"sensor_online": age <= SENSOR_OFFLINE_AFTER, "age_seconds": round(age, 1)})
    return body


@app.route("/api/v1/metrics", methods=["GET"])
@require("metrics:read")
def get_metrics():
    """Latest sensor heartbeat. sensor_online is false when it is older than SENSOR_OFFLINE_AFTER seconds."""
    err = reject_unknown_params(set())
    if err:
        return error_response(err, 400)
    connection = get_readonly_connection()
    try:
        body = sensor_metrics(connection)
    finally:
        connection.close()
    body["api"] = dict(auth_metrics)
    return jsonify(body), 200


@app.route("/api/v1/alerts", methods=["GET"])
@require("alerts:read")
def get_alerts():
    """Alerts with strictly validated filters, sorting and pagination. X-Total-Count = matches before paging."""
    f, err = parse_alert_filters()
    if err or f is None:
        return error_response(err or "Invalid request.", 400)
    limit, err = _int_param("limit", API_DEFAULT_LIMIT, 1, API_MAX_LIMIT)
    offset, err2 = _int_param("offset", 0, 0, MAX_OFFSET)
    if err or err2:
        return error_response(err or err2 or "Invalid request.", 400)
    sort, order = request.args.get("sort", "detected_at"), request.args.get("order", "desc").lower()
    if sort not in ALERT_SORTS:
        return error_response(f"Invalid parameter 'sort': must be one of [{', '.join(ALERT_SORTS)}].", 400)
    if order not in ("asc", "desc"):
        return error_response("Invalid parameter 'order': must be 'asc' or 'desc'.", 400)

    conds, params = build_conditions(f)
    base = f"FROM alerts a LEFT JOIN appdb.triage t ON t.alert_id = a.id {where_sql(conds)}"  # nosec B608
    direction = order.upper()
    query = f"SELECT {ALERT_COLUMNS} {base} ORDER BY {ALERT_SORTS[sort]} {direction}, a.id {direction} LIMIT ? OFFSET ?"  # nosec B608
    connection = open_alert_connection()
    try:
        rows = connection.execute(query, [*params, limit, offset]).fetchall()
        total = connection.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]  # nosec B608
    finally:
        connection.close()

    resp = jsonify([alert_dict(row) for row in rows])
    resp.headers["X-Total-Count"] = str(total)
    return resp, 200


ALERT_COLUMNS = (
    "a.id, a.timestamp, a.detected_at, a.threat_type, a.scan_type, a.severity, a.confidence, "
    "a.source_ip, a.destination_ip, a.destination_port, a.protocol, a.message, a.evidence, a.ml_score, "
    "a.ml_label, a.sensor_id, COALESCE(t.status, 'new'), t.assignee"
)


def alert_dict(row: Any) -> dict[str, Any]:
    evidence_obj: Any = None
    if row[12]:
        try:
            evidence_obj = json.loads(row[12])
        except ValueError:
            evidence_obj = row[12]
    return {
        "id": row[0],
        "timestamp": row[1],
        "detected_at": row[2],
        "threat_type": row[3],
        "scan_type": row[4],
        "severity": row[5],
        "confidence": row[6],
        "source_ip": row[7],
        "destination_ip": row[8],
        "destination_port": row[9],
        "protocol": row[10],
        "message": row[11],
        "evidence": evidence_obj,
        "ml_score": row[13],
        "ml_label": row[14],
        "sensor_id": row[15],
        "triage_status": row[16],
        "assignee": row[17],
    }


OVERVIEW_DEFAULT_HOURS = 24
OVERVIEW_MAX_BUCKETS = 300
TOP_N = 10


@app.route("/api/v1/overview", methods=["GET"])
@require("alerts:read")
def get_overview():
    """Dashboard aggregates for a time window (default: last 24 h): severity, triage, timeline, top sources/ports."""
    f, err = parse_alert_filters()
    if err or f is None:
        return error_response(err or "Invalid request.", 400)
    now = utcnow()
    f["since"] = f["since"] or (now - timedelta(hours=OVERVIEW_DEFAULT_HOURS)).isoformat(timespec="seconds")
    conds, params = build_conditions(f)
    base = "FROM alerts a LEFT JOIN appdb.triage t ON t.alert_id = a.id "
    where = where_sql(conds)
    with_source = where_sql([*conds, "a.source_ip IS NOT NULL"])
    with_port = where_sql([*conds, "a.destination_port IS NOT NULL"])

    connection = open_alert_connection()
    try:
        q = connection.execute
        severity = dict(q(f"SELECT a.severity, COUNT(*) {base}{where} GROUP BY a.severity", params).fetchall())  # nosec B608
        triage = dict(q(f"SELECT COALESCE(t.status, 'new'), COUNT(*) {base}{where} GROUP BY 1", params).fetchall())  # nosec B608
        minutes = q(
            f"SELECT substr(a.detected_at, 1, 16), COUNT(*) {base}{where} GROUP BY 1 ORDER BY 1", params
        ).fetchall()  # nosec B608
        sources = q(  # nosec B608
            f"SELECT a.source_ip, COUNT(*) AS n {base}{with_source} GROUP BY a.source_ip ORDER BY n DESC, a.source_ip LIMIT {TOP_N}",
            params,
        ).fetchall()
        ports = q(  # nosec B608
            f"SELECT a.destination_port, COUNT(*) AS n {base}{with_port} GROUP BY a.destination_port ORDER BY n DESC, a.destination_port LIMIT {TOP_N}",
            params,
        ).fetchall()
    finally:
        connection.close()

    window_start = datetime.fromisoformat(f["since"])
    window_end = datetime.fromisoformat(f["until"]) if f["until"] else now
    span_minutes = max(1, int((window_end - window_start).total_seconds() // 60) + 1)
    bucket = max(1, -(-span_minutes // OVERVIEW_MAX_BUCKETS))
    buckets: dict[int, int] = {}
    for minute, n in minutes:
        key = int(datetime.fromisoformat(minute + ":00+00:00").timestamp() // 60) // bucket
        buckets[key] = buckets.get(key, 0) + n
    timeline = [
        {"t": datetime.fromtimestamp(k * bucket * 60, tz=UTC).isoformat(timespec="seconds"), "count": n}
        for k, n in sorted(buckets.items())
    ]
    statuses = {st: triage.get(st, 0) for st in TRIAGE_STATUSES}
    return jsonify(
        {
            "since": f["since"],
            "until": f["until"] or now.isoformat(timespec="seconds"),
            "bucket_minutes": bucket,
            "total": sum(severity.values()),
            "severity": {sv: severity.get(sv, 0) for sv in SEVERITIES},
            "triage": statuses,
            "open": statuses["new"] + statuses["acknowledged"] + statuses["investigating"],
            "resolved": statuses["resolved_tp"] + statuses["resolved_fp"],
            "timeline": timeline,
            "top_sources": [{"value": r[0], "count": r[1]} for r in sources],
            "top_ports": [{"value": r[0], "count": r[1]} for r in ports],
        }
    ), 200


@app.route("/api/v1/stats", methods=["GET"])
@require("alerts:read")
def get_stats():
    """Aggregated alert counts for the dashboard cards."""
    err = reject_unknown_params(set())
    if err:
        return error_response(err, 400)
    connection = get_readonly_connection()
    try:
        row = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0) FROM alerts"
        ).fetchone()
        total_alerts, high_severity = int(row[0]), int(row[1])
        threat_counts = {
            r[0]: int(r[1]) for r in connection.execute("SELECT threat_type, COUNT(*) FROM alerts GROUP BY threat_type")
        }
    finally:
        connection.close()
    volumetric = threat_counts.get(THREAT_TYPE_VOLUMETRIC, 0) + threat_counts.get("HIGH_TRAFFIC", 0)
    return jsonify(
        {
            "total_alerts": total_alerts,
            "high_severity": high_severity,
            "port_scans": threat_counts.get(THREAT_TYPE_PORT_SCAN, 0),
            "syn_floods": threat_counts.get(THREAT_TYPE_SYN_FLOOD, 0),
            "volumetric": volumetric,
            "high_traffic": volumetric,
        }
    ), 200


# =============================================================================
# Attack graph, sensor history, export
# =============================================================================


@app.route("/api/v1/graph", methods=["GET"])
@require("alerts:read")
def get_graph():
    """Source -> target edges for the current filter (default window: last 24 h), capped for the console."""
    f, err = parse_alert_filters()
    if err or f is None:
        return error_response(err or "Invalid request.", 400)
    f["since"] = f["since"] or (utcnow() - timedelta(hours=OVERVIEW_DEFAULT_HOURS)).isoformat(timespec="seconds")
    conds, params = build_conditions(f)
    where = where_sql([*conds, "a.source_ip IS NOT NULL", "a.destination_ip IS NOT NULL"])
    connection = open_alert_connection()
    try:
        sql = (  # fixed fragments plus a where clause built from literals; every value is bound as a parameter
            f"SELECT a.source_ip, a.destination_ip, a.threat_type, COUNT(*) AS n FROM alerts a LEFT JOIN appdb.triage t ON t.alert_id = a.id {where} "  # nosec B608
            f"GROUP BY a.source_ip, a.destination_ip, a.threat_type ORDER BY n DESC LIMIT {int(GRAPH_MAX_EDGES) + 1}"  # nosec B608
        )
        edges = connection.execute(sql, params).fetchall()
    finally:
        connection.close()
    truncated = len(edges) > GRAPH_MAX_EDGES
    edges = edges[:GRAPH_MAX_EDGES]
    weight: dict[str, int] = {}
    for src, dst, _threat, n in edges:
        weight[src] = weight.get(src, 0) + n
        weight[dst] = weight.get(dst, 0) + n
    keep = {ip for ip, _ in sorted(weight.items(), key=lambda kv: (-kv[1], kv[0]))[:GRAPH_MAX_NODES]}
    truncated = truncated or len(keep) < len(weight)
    kept_edges = [e for e in edges if e[0] in keep and e[1] in keep]
    sources = {e[0] for e in kept_edges}
    targets = {e[1] for e in kept_edges}
    used = sources | targets
    return jsonify(
        {
            "since": f["since"],
            "truncated": truncated,
            "total_nodes": len(weight),
            "nodes": [
                {
                    "id": ip,
                    "count": weight[ip],
                    "role": "both" if ip in sources and ip in targets else ("source" if ip in sources else "target"),
                }
                for ip in sorted(used, key=lambda ip: (-weight[ip], ip))
            ],
            "edges": [{"source": e[0], "target": e[1], "threat_type": e[2], "count": e[3]} for e in kept_edges],
        }
    ), 200


@app.route("/api/v1/metrics/history", methods=["GET"])
@require("metrics:read")
def metrics_history():
    """Sensor heartbeat history for sparklines, plus the configured drop-rate warning threshold."""
    minutes, err = _int_param("minutes", 30, 1, 180)
    if err or minutes is None:
        return error_response(err or "Invalid request.", 400)
    cutoff = (utcnow() - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    connection = get_readonly_connection()
    try:
        latest = fetch_latest_sensor_status(connection)
        rows = (
            connection.execute(
                "SELECT last_seen, pps_10s, received, dropped, queue_depth, state_size, evictions FROM sensor_status "
                "WHERE sensor_id = ? AND last_seen >= ? ORDER BY last_seen, id",
                (latest["sensor_id"], cutoff),
            ).fetchall()
            if latest
            else []
        )
    finally:
        connection.close()
    points = [dict(r) for r in rows]
    drop_rate = None
    if len(points) >= 2 and points[-1]["received"] > points[0]["received"]:
        drop_rate = (points[-1]["dropped"] - points[0]["dropped"]) / (points[-1]["received"] - points[0]["received"])
    return jsonify(
        {"window_minutes": minutes, "points": points, "drop_rate": drop_rate, "drop_warn_ratio": DROP_WARN_RATIO}
    ), 200


CSV_COLUMNS = (
    "id",
    "detected_at",
    "severity",
    "threat_type",
    "scan_type",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "confidence",
    "triage_status",
    "assignee",
    "message",
)


def csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection: a text cell starting with = + - @ (or tab/CR) gets a leading quote."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


@app.route("/api/v1/alerts/export", methods=["GET"])
@require("alerts:read")
def export_alerts():
    """Download the filtered alert list as CSV or JSON. Same filters and sort as the list; row-capped."""
    fmt = request.args.get("format", "csv")
    if fmt not in ("csv", "json"):
        return error_response("Invalid parameter 'format': must be 'csv' or 'json'.", 400)
    f, err = parse_alert_filters()
    if err or f is None:
        return error_response(err or "Invalid request.", 400)
    limit, err = _int_param("limit", EXPORT_MAX_ROWS, 1, EXPORT_MAX_ROWS)
    if err or limit is None:
        return error_response(err or "Invalid request.", 400)
    sort, order = request.args.get("sort", "detected_at"), request.args.get("order", "desc").lower()
    if sort not in ALERT_SORTS or order not in ("asc", "desc"):
        return error_response("Invalid 'sort' or 'order'.", 400)

    conds, params = build_conditions(f)
    base = f"FROM alerts a LEFT JOIN appdb.triage t ON t.alert_id = a.id {where_sql(conds)}"  # nosec B608
    direction = order.upper()
    connection = open_alert_connection()
    try:
        rows = connection.execute(  # nosec B608
            f"SELECT {ALERT_COLUMNS} {base} ORDER BY {ALERT_SORTS[sort]} {direction}, a.id {direction} LIMIT ?",
            [*params, limit],
        ).fetchall()
        total = connection.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]  # nosec B608
    finally:
        connection.close()

    alerts = [alert_dict(r) for r in rows]
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    if fmt == "json":
        body = json.dumps(alerts, indent=2)
        mimetype = "application/json"
    else:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(CSV_COLUMNS)
        for a in alerts:
            writer.writerow([csv_safe(a[c]) for c in CSV_COLUMNS])
        body = out.getvalue()
        mimetype = "text/csv"
    identity = current_identity()
    accounts.audit(
        "alerts.export",
        identity.actor if identity else "unknown",
        client_ip(),
        None,
        {"format": fmt, "rows": len(alerts), "truncated": total > len(alerts)},
    )
    resp = Response(body, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="sentinelx-alerts-{stamp}.{fmt}"'
    resp.headers["X-Total-Count"] = str(total)
    resp.headers["X-Export-Truncated"] = "true" if total > len(alerts) else "false"
    return resp


# =============================================================================
# Server-Sent Events
# =============================================================================

_stream_lock = threading.Lock()
_open_streams = 0


class AlertStream:
    """
    SSE body: every STREAM_INTERVAL_SECONDS emit {new_alert_ids, latest_alert_id, metrics}; emit a comment
    heartbeat when idle for STREAM_HEARTBEAT_SECONDS. close() is idempotent and releases the stream slot, so a
    disconnecting client (waitress calls close) always frees its thread budget.
    """

    def __init__(self, after_id: int) -> None:
        self._last_id = after_id
        self._first = True
        self._closed = threading.Event()
        self._released = False
        self._next_tick = 0.0
        self._last_output = time.monotonic()

    def __iter__(self) -> AlertStream:
        return self

    def _snapshot(self) -> str:
        connection = get_readonly_connection()
        try:
            ids = [
                r[0]
                for r in connection.execute(
                    "SELECT id FROM alerts WHERE id > ? ORDER BY id LIMIT 100", (self._last_id,)
                )
            ]
            metrics = sensor_metrics(connection)
        finally:
            connection.close()
        if ids:
            self._last_id = ids[-1]
        payload = {"new_alert_ids": ids, "latest_alert_id": self._last_id, "metrics": metrics}
        return f"event: update\ndata: {json.dumps(payload)}\n\n"

    def __next__(self) -> str:
        if self._first:
            self._first = False
            self._next_tick = time.monotonic() + STREAM_INTERVAL_SECONDS
            self._last_output = time.monotonic()
            return "retry: 5000\n\n" + self._snapshot()
        while not self._closed.is_set():
            now = time.monotonic()
            if now >= self._next_tick:
                self._next_tick = now + STREAM_INTERVAL_SECONDS
                self._last_output = now
                return self._snapshot()
            if now - self._last_output >= STREAM_HEARTBEAT_SECONDS:
                self._last_output = now
                return ": heartbeat\n\n"
            self._closed.wait(min(0.25, max(0.01, self._next_tick - now)))
        raise StopIteration

    def close(self) -> None:
        global _open_streams
        self._closed.set()
        with _stream_lock:
            if not self._released:
                self._released = True
                _open_streams -= 1


def open_stream_count() -> int:
    return _open_streams


@app.route("/api/v1/stream", methods=["GET"])
@require("alerts:read")
def stream():
    """Live updates over Server-Sent Events. Capped at MAX_STREAMS concurrent connections."""
    global _open_streams
    err = reject_unknown_params({"after_id"})
    if err:
        return error_response(err, 400)
    after_id = request.args.get("after_id")
    if after_id is not None and not (after_id.isdigit() and len(after_id) <= 12):
        return error_response("Invalid parameter 'after_id': must be a non-negative integer.", 400)
    with _stream_lock:
        if _open_streams >= MAX_STREAMS:
            resp = error_response(f"Too many open streams (limit {MAX_STREAMS}); use polling instead.", 429)
            resp[0].headers["Retry-After"] = "5"
            return resp
        _open_streams += 1
    try:
        if after_id is None:
            connection = get_readonly_connection()
            try:
                after = int(connection.execute("SELECT COALESCE(MAX(id), 0) FROM alerts").fetchone()[0])
            finally:
                connection.close()
        else:
            after = int(after_id)
    except Exception:
        with _stream_lock:
            _open_streams -= 1
        raise
    body = AlertStream(after)
    return Response(
        body, mimetype="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
    )


# =============================================================================
# Error handlers (one JSON envelope)
# =============================================================================


@app.errorhandler(400)
def bad_request_handler(error):
    return error_response(getattr(error, "description", "Bad request."), 400)


@app.errorhandler(401)
def unauthorized_handler(error):
    return error_response("Authentication required.", 401)


@app.errorhandler(403)
def forbidden_handler(error):
    return error_response("You don't have permission for this.", 403)


@app.errorhandler(404)
def not_found_handler(error):
    return error_response("The requested resource was not found.", 404)


@app.errorhandler(405)
def method_not_allowed_handler(error):
    resp = error_response("The HTTP method is not allowed for this endpoint.", 405)
    allowed = getattr(error, "valid_methods", None)
    if allowed:
        resp[0].headers["Allow"] = ", ".join(sorted(allowed))  # RFC 9110 requires Allow on a 405
    return resp


@app.errorhandler(413)
def too_large_handler(error):
    return error_response("Request body too large.", 413)


@app.errorhandler(AppDatabaseError)
def app_database_error_handler(error):
    logger.warning("app.db error: %s", error)
    resp = error_response("The application database is busy or unavailable. Try again in a moment.", 503)
    resp[0].headers["Retry-After"] = "1"
    return resp


@app.errorhandler(sqlite3.Error)
def database_error_handler(error):
    logger.warning("alerts.db error: %s", error)
    return error_response("The sensor database is not available yet.", 503)


@app.errorhandler(500)
def internal_server_error_handler(error):
    return error_response("An internal server error occurred.", 500)


app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # no endpoint takes a large body
