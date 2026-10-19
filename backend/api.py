import json
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from config.settings import (
    ALLOW_LOCAL_FILE_CORS,
    API_DEBUG,
    API_DEFAULT_LIMIT,
    API_HOST,
    API_MAX_LIMIT,
    API_PORT,
    CANONICAL_THREAT_TYPES,
    CORS_ALLOWED_ORIGINS,
    THREAT_TYPE_HIGH_TRAFFIC,
    THREAT_TYPE_PORT_SCAN,
)
from database.database import get_connection, initialize_database

app = Flask(__name__)

# Initialize database schema and apply pending migrations on app creation
initialize_database()

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


# =============================================================================
# Helper Functions & Input Validation
# =============================================================================


def error_response(message: str, status_code: int = 400, error_name: str | None = None):
    """Generate a structured, standardized JSON error envelope."""
    default_names = {
        400: "Bad Request",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }
    return jsonify(
        {
            "error": error_name or default_names.get(status_code, "Error"),
            "message": message,
            "status": status_code,
        }
    ), status_code


def parse_alert_query_params() -> tuple[
    int | None,
    int | None,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
]:
    """
    Validates and parses query parameters for GET /api/alerts:
    - limit: integer between 1 and API_MAX_LIMIT
    - offset: integer >= 0
    - threat_type: canonical threat type string
    - severity: 'HIGH', 'MEDIUM', or 'LOW'
    - source_ip: string
    - since: ISO-8601 string (must include timezone offset or 'Z')
    Returns: (limit, offset, threat_type, severity, source_ip, since_utc_str, error_message)
    """
    limit_str = request.args.get("limit")
    offset_str = request.args.get("offset")
    threat_type = request.args.get("threat_type")
    severity = request.args.get("severity")
    source_ip = request.args.get("source_ip")
    since_str = request.args.get("since")

    limit = API_DEFAULT_LIMIT
    if limit_str is not None:
        try:
            limit = int(limit_str)
        except ValueError:
            return None, None, None, None, None, None, "Invalid parameter 'limit': must be an integer."
        if limit < 1 or limit > API_MAX_LIMIT:
            return None, None, None, None, None, None, f"Parameter 'limit' must be between 1 and {API_MAX_LIMIT}."

    offset = 0
    if offset_str is not None:
        try:
            offset = int(offset_str)
        except ValueError:
            return None, None, None, None, None, None, "Invalid parameter 'offset': must be an integer."
        if offset < 0:
            return None, None, None, None, None, None, "Parameter 'offset' cannot be negative."

    if threat_type and threat_type not in CANONICAL_THREAT_TYPES:
        allowed = ", ".join(CANONICAL_THREAT_TYPES)
        return None, None, None, None, None, None, f"Invalid parameter 'threat_type': must be one of [{allowed}]."

    valid_severities = ("HIGH", "MEDIUM", "LOW")
    if severity and severity.upper() not in valid_severities:
        return None, None, None, None, None, None, "Invalid parameter 'severity': must be 'HIGH', 'MEDIUM', or 'LOW'."

    since_utc_str = None
    if since_str is not None:
        # Handle cases where '+' in URL query was decoded by HTTP parser to a space
        cleaned_since = since_str
        if " " in cleaned_since and not cleaned_since.endswith("Z"):
            parts = cleaned_since.rsplit(" ", 1)
            if len(parts) == 2 and (":" in parts[1] or parts[1].isdigit()):
                cleaned_since = f"{parts[0]}+{parts[1]}"

        try:
            dt = datetime.fromisoformat(cleaned_since)
        except (ValueError, TypeError):
            return None, None, None, None, None, None, "Invalid parameter 'since': must be a valid ISO-8601 timestamp."

        if dt.tzinfo is None:
            return (
                None,
                None,
                None,
                None,
                None,
                None,
                "Invalid parameter 'since': timestamp must be timezone-aware (include UTC offset or 'Z').",
            )

        dt_utc = dt.astimezone(UTC)
        since_utc_str = dt_utc.isoformat(timespec="seconds")

    return (
        limit,
        offset,
        threat_type,
        (severity.upper() if severity else None),
        source_ip,
        since_utc_str,
        None,
    )


# =============================================================================
# Security Headers & CORS Interceptors
# =============================================================================


@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Inject defensive HTTP security headers and scoped CORS permissions."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    csp_directives = [
        "default-src 'none'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "connect-src 'self' http://127.0.0.1:5000",
        "img-src 'self' data:",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

    permissions_directives = [
        "camera=()",
        "microphone=()",
        "geolocation=()",
        "payment=()",
        "usb=()",
        "bluetooth=()",
        "display-capture=()",
        "clipboard-write=(self)",
    ]
    response.headers["Permissions-Policy"] = ", ".join(permissions_directives)

    if request.path != "/":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    origin = request.headers.get("Origin")
    if origin:
        allowed = False
        if origin == "null":
            if ALLOW_LOCAL_FILE_CORS or "null" in CORS_ALLOWED_ORIGINS:
                allowed = True
        elif origin in CORS_ALLOWED_ORIGINS:
            allowed = True

        if allowed:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"

    return response


# =============================================================================
# Routes
# =============================================================================


@app.route("/")
def home():
    """Serves the SentinelX single-page monitoring dashboard."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/health")
@app.route("/api/health")
def health_check():
    """
    Health and readiness probe.
    Verifies process responsiveness and database connectivity.
    """
    try:
        connection = get_connection()
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
        finally:
            connection.close()

        return jsonify(
            {
                "status": "healthy",
                "service": "SentinelX API",
                "database": "connected",
                "timestamp": datetime.now(UTC).isoformat(),
            }
        ), 200
    except Exception:
        return jsonify(
            {
                "status": "unhealthy",
                "service": "SentinelX API",
                "database": "disconnected",
                "error": "Database connectivity probe failed",
                "timestamp": datetime.now(UTC).isoformat(),
            }
        ), 503


@app.route("/api/alerts", methods=["GET", "OPTIONS"])
def get_alerts():
    """
    Fetches security alerts with bounded pagination, since timestamp filter,
    and stable ordering (detected_at DESC, id DESC).
    Returns a JSON array of alerts with parsed evidence objects.
    """
    if request.method == "OPTIONS":
        return Response("", status=204)

    limit, offset, threat_type, severity, source_ip, since_utc, err = parse_alert_query_params()
    if err:
        return error_response(err, 400)

    # Build parameterized query safely
    conditions = []
    params = []

    if threat_type:
        conditions.append("threat_type = ?")
        params.append(threat_type)

    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)

    if since_utc:
        conditions.append("detected_at >= ?")
        params.append(since_utc)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = (
        "SELECT id, timestamp, detected_at, threat_type, scan_type, severity, "
        "confidence, source_ip, destination_ip, protocol, message, evidence, "
        "ml_score, ml_label, sensor_id "
        f"FROM alerts {where_clause} "  # nosec: B608  # Parameterized query with strict parameter binding
        "ORDER BY detected_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])

    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
    finally:
        connection.close()

    alerts = []
    for row in rows:
        evidence_val = row[11]
        evidence_obj = None
        if evidence_val:
            try:
                evidence_obj = json.loads(evidence_val)
            except Exception:
                evidence_obj = evidence_val

        alerts.append(
            {
                "id": row[0],
                "timestamp": row[1],
                "detected_at": row[2],
                "threat_type": row[3],
                "scan_type": row[4],
                "severity": row[5],
                "confidence": row[6],
                "source_ip": row[7],
                "destination_ip": row[8],
                "protocol": row[9],
                "message": row[10],
                "evidence": evidence_obj,
                "ml_score": row[12],
                "ml_label": row[13],
                "sensor_id": row[14],
            }
        )

    return jsonify(alerts), 200


@app.route("/api/stats", methods=["GET", "OPTIONS"])
def get_stats():
    """
    Returns aggregated alert statistics for dashboard metric cards.
    Counts threat types dynamically using GROUP BY threat_type.
    """
    if request.method == "OPTIONS":
        return Response("", status=204)

    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0)
            FROM alerts
        """
        )
        row = cursor.fetchone()
        total_alerts = int(row[0]) if row and row[0] is not None else 0
        high_severity = int(row[1]) if row and row[1] is not None else 0

        cursor.execute("SELECT threat_type, COUNT(*) FROM alerts GROUP BY threat_type")
        threat_counts = {r[0]: int(r[1]) for r in cursor.fetchall()}
    finally:
        connection.close()

    port_scans = threat_counts.get(THREAT_TYPE_PORT_SCAN, 0)
    high_traffic = threat_counts.get(THREAT_TYPE_HIGH_TRAFFIC, 0)

    return jsonify(
        {
            "total_alerts": total_alerts,
            "high_severity": high_severity,
            "port_scans": port_scans,
            "high_traffic": high_traffic,
        }
    ), 200


# =============================================================================
# Standardized Error Handlers
# =============================================================================


@app.errorhandler(400)
def bad_request_handler(error):
    msg = getattr(error, "description", "Bad request.")
    return error_response(msg, 400)


@app.errorhandler(404)
def not_found_handler(error):
    return error_response("The requested resource was not found.", 404)


@app.errorhandler(405)
def method_not_allowed_handler(error):
    return error_response("The HTTP method is not allowed for this endpoint.", 405)


@app.errorhandler(500)
def internal_server_error_handler(error):
    return error_response("An internal server error occurred.", 500)


if __name__ == "__main__":
    from config.logging_config import configure_logging

    configure_logging()
    app.run(
        host=API_HOST,
        port=API_PORT,
        debug=API_DEBUG,
        use_reloader=False,
    )
