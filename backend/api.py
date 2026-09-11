from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Tuple, Optional, Any, List

from flask import Flask, jsonify, request, send_from_directory, Response

from config.settings import (
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_HIGH_TRAFFIC,
    CANONICAL_THREAT_TYPES,
    API_HOST,
    API_PORT,
    API_DEBUG,
    API_DEFAULT_LIMIT,
    API_MAX_LIMIT,
    ALLOW_LOCAL_FILE_CORS,
    CORS_ALLOWED_ORIGINS,
)
from database.database import get_connection


app = Flask(__name__)

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


# =============================================================================
# Helper Functions & Input Validation
# =============================================================================

def error_response(message: str, status_code: int = 400, error_name: Optional[str] = None):
    """Generate a structured, standardized JSON error envelope."""
    default_names = {
        400: "Bad Request",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }
    return jsonify({
        "error": error_name or default_names.get(status_code, "Error"),
        "message": message,
        "status": status_code,
    }), status_code


def parse_alert_query_params() -> Tuple[Optional[int], Optional[int], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Validates and parses query parameters for GET /api/alerts:
    - limit: integer between 1 and API_MAX_LIMIT
    - offset: integer >= 0
    - threat_type: canonical threat type string
    - severity: 'HIGH', 'MEDIUM', or 'LOW'
    - source_ip: string
    Returns: (limit, offset, threat_type, severity, source_ip, error_message)
    """
    limit_str = request.args.get("limit")
    offset_str = request.args.get("offset")
    threat_type = request.args.get("threat_type")
    severity = request.args.get("severity")
    source_ip = request.args.get("source_ip")

    limit = API_DEFAULT_LIMIT
    if limit_str is not None:
        try:
            limit = int(limit_str)
        except ValueError:
            return None, None, None, None, None, "Invalid parameter 'limit': must be an integer."
        if limit < 1 or limit > API_MAX_LIMIT:
            return None, None, None, None, None, f"Parameter 'limit' must be between 1 and {API_MAX_LIMIT}."

    offset = 0
    if offset_str is not None:
        try:
            offset = int(offset_str)
        except ValueError:
            return None, None, None, None, None, "Invalid parameter 'offset': must be an integer."
        if offset < 0:
            return None, None, None, None, None, "Parameter 'offset' cannot be negative."

    if threat_type and threat_type not in CANONICAL_THREAT_TYPES:
        allowed = ", ".join(CANONICAL_THREAT_TYPES)
        return None, None, None, None, None, f"Invalid parameter 'threat_type': must be one of [{allowed}]."

    valid_severities = ("HIGH", "MEDIUM", "LOW")
    if severity and severity.upper() not in valid_severities:
        return None, None, None, None, None, "Invalid parameter 'severity': must be 'HIGH', 'MEDIUM', or 'LOW'."

    return limit, offset, threat_type, (severity.upper() if severity else None), source_ip, None


# =============================================================================
# Security Headers & CORS Interceptors
# =============================================================================

@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Inject defensive HTTP security headers and scoped CORS permissions."""
    # Standard defensive headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Restrictive Content-Security-Policy & Permissions-Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' http://127.0.0.1:5000; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'none';"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "bluetooth=(), display-capture=(), clipboard-write=(self)"
    )

    # Prevent caching of dynamic security alerts and statistics
    if request.path.startswith("/api/") or request.path in ("/health", "/api/health"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    # CORS permissions scoped to allowed local origins
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

        return jsonify({
            "status": "healthy",
            "service": "SentinelX API",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200
    except Exception as err:
        return jsonify({
            "status": "unhealthy",
            "service": "SentinelX API",
            "database": "disconnected",
            "error": "Database connectivity probe failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 503


@app.route("/api/alerts", methods=["GET", "OPTIONS"])
def get_alerts():
    """
    Fetches security alerts with bounded pagination and optional filtering.
    Returns a JSON array to maintain 100% backward compatibility with dashboard.
    """
    if request.method == "OPTIONS":
        return Response("", status=204)

    limit, offset, threat_type, severity, source_ip, err = parse_alert_query_params()
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

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT
            id,
            timestamp,
            threat_type,
            severity,
            source_ip,
            destination_ip,
            protocol,
            message
        FROM alerts
        {where_clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
    finally:
        connection.close()

    alerts = [
        {
            "id": row[0],
            "timestamp": row[1],
            "threat_type": row[2],
            "severity": row[3],
            "source_ip": row[4],
            "destination_ip": row[5],
            "protocol": row[6],
            "message": row[7],
        }
        for row in rows
    ]

    return jsonify(alerts), 200


@app.route("/api/stats", methods=["GET", "OPTIONS"])
def get_stats():
    """
    Returns aggregated alert statistics for dashboard metric cards.
    Uses a single atomic SQL query to reduce lock acquisition overhead.
    """
    if request.method == "OPTIONS":
        return Response("", status=204)

    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN threat_type = ? THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN threat_type = ? THEN 1 ELSE 0 END), 0)
            FROM alerts
        """, (THREAT_TYPE_PORT_SCAN, THREAT_TYPE_HIGH_TRAFFIC))
        row = cursor.fetchone()
    finally:
        connection.close()

    total_alerts = int(row[0]) if row and row[0] is not None else 0
    high_severity = int(row[1]) if row and row[1] is not None else 0
    port_scans = int(row[2]) if row and row[2] is not None else 0
    high_traffic = int(row[3]) if row and row[3] is not None else 0

    return jsonify({
        "total_alerts": total_alerts,
        "high_severity": high_severity,
        "port_scans": port_scans,
        "high_traffic": high_traffic,
    }), 200


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
    app.run(
        host=API_HOST,
        port=API_PORT,
        debug=API_DEBUG,
        use_reloader=False,
    )