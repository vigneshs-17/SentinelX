"""Shared HTTP helpers for the API modules."""

from flask import jsonify

DEFAULT_ERROR_NAMES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    429: "Too Many Requests",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


MAX_ID = 2**63 - 1  # SQLite INTEGER range; larger path ids cannot exist


def valid_id(value: int) -> bool:
    return 1 <= value <= MAX_ID


def error_response(message: str, status_code: int = 400, error_name: str | None = None):
    """Generate the standard JSON error envelope."""
    return jsonify(
        {
            "error": error_name or DEFAULT_ERROR_NAMES.get(status_code, "Error"),
            "message": message,
            "status": status_code,
        }
    ), status_code


# Query parameters each endpoint accepts. Anything else is a 400 (enforced centrally in backend/auth.py).
_FILTERS = frozenset(
    {"threat_type", "scan_type", "severity", "source_ip", "destination_ip", "since", "until", "q", "status", "dport"}
)
QUERY_PARAMS: dict[str, frozenset[str]] = {
    "get_alerts": _FILTERS | {"limit", "offset", "min_id", "sort", "order"},
    "get_overview": _FILTERS,
    "get_graph": _FILTERS,
    "export_alerts": _FILTERS | {"format", "limit", "sort", "order"},
    "metrics_history": frozenset({"minutes"}),
    "stream": frozenset({"after_id"}),
    "admin.read_audit": frozenset({"limit", "offset", "action", "actor", "since", "target"}),
}
