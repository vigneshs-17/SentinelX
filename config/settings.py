import os
from ipaddress import ip_network
from pathlib import Path
from typing import Any

# SentinelX Detection Configuration

# Canonical Threat Types
THREAT_TYPE_PORT_SCAN = "PORT_SCAN"
THREAT_TYPE_SYN_FLOOD = "SYN_FLOOD"
THREAT_TYPE_VOLUMETRIC = "VOLUMETRIC"

THREAT_TYPE_ML_ANOMALY = "ML_ANOMALY"  # only ever raised by the optional, gated flow model (SENTINELX_ML=on)

CANONICAL_THREAT_TYPES = (
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_SYN_FLOOD,
    THREAT_TYPE_VOLUMETRIC,
    THREAT_TYPE_ML_ANOMALY,
)

# Scan Types
SCAN_TYPE_VERTICAL = "VERTICAL"
SCAN_TYPE_HORIZONTAL = "HORIZONTAL"
SCAN_TYPE_SLOW = "SLOW"
SCAN_TYPE_SLOW_VERTICAL = "SLOW_VERTICAL"
SCAN_TYPE_SLOW_HORIZONTAL = "SLOW_HORIZONTAL"

# State Store Partition Capacities (Correction 1)
PARTITION_CAP_VERTICAL = int(os.getenv("SENTINELX_CAP_VERTICAL", "2500"))
PARTITION_CAP_HORIZONTAL = int(os.getenv("SENTINELX_CAP_HORIZONTAL", "2500"))
PARTITION_CAP_SLOW_SCAN = int(os.getenv("SENTINELX_CAP_SLOW_SCAN", "2000"))
PARTITION_CAP_SYN_FLOOD_AGGREGATES = int(os.getenv("SENTINELX_CAP_SYN_FLOOD_AGGREGATES", "1000"))
PARTITION_CAP_SYN_FLOOD_HALF_OPEN = int(os.getenv("SENTINELX_CAP_SYN_FLOOD_HALF_OPEN", "10000"))
PARTITION_CAP_VOLUMETRIC = int(os.getenv("SENTINELX_CAP_VOLUMETRIC", "1000"))
PARTITION_CAP_COOLDOWNS = int(os.getenv("SENTINELX_CAP_COOLDOWNS", "1000"))
PARTITION_CAP_SCAN_ATTEMPTS = int(os.getenv("SENTINELX_CAP_SCAN_ATTEMPTS", "20000"))
PARTITION_CAP_SCAN_COMPLETED = int(os.getenv("SENTINELX_CAP_SCAN_COMPLETED", "20000"))
PARTITION_CAP_FLOWS = int(os.getenv("SENTINELX_CAP_FLOWS", "50000"))
PARTITION_CAP_FLOW_SOURCES = int(os.getenv("SENTINELX_CAP_FLOW_SOURCES", "5000"))

DETECTION_STATE_TTL = float(os.getenv("SENTINELX_STATE_TTL", "60.0"))

# Port scan detection
PORT_SCAN_THRESHOLD = int(os.getenv("SENTINELX_PORT_SCAN_THRESHOLD", "10"))
VERTICAL_SCAN_THRESHOLD = int(os.getenv("SENTINELX_VERTICAL_SCAN_THRESHOLD", str(PORT_SCAN_THRESHOLD)))
HORIZONTAL_SCAN_THRESHOLD = int(os.getenv("SENTINELX_HORIZONTAL_SCAN_THRESHOLD", "10"))
PORT_SCAN_TIME_WINDOW = float(os.getenv("SENTINELX_PORT_SCAN_WINDOW", "10.0"))
PORT_SCAN_ALERT_COOLDOWN = float(os.getenv("SENTINELX_PORT_SCAN_COOLDOWN", "30.0"))

# Slow scan detection
SLOW_SCAN_THRESHOLD = int(os.getenv("SENTINELX_SLOW_SCAN_THRESHOLD", "20"))
SLOW_SCAN_TIME_WINDOW = float(os.getenv("SENTINELX_SLOW_SCAN_WINDOW", "300.0"))
SLOW_SCAN_ALERT_COOLDOWN = float(os.getenv("SENTINELX_SLOW_SCAN_COOLDOWN", "60.0"))
SLOW_SCAN_MIN_FAILURE_RATIO = float(os.getenv("SENTINELX_SLOW_SCAN_MIN_FAILURE_RATIO", "0.8"))

# SYN flood detection
SYN_FLOOD_THRESHOLD = int(os.getenv("SENTINELX_SYN_FLOOD_THRESHOLD", "100"))  # SYN packets per second
SYN_FLOOD_TIME_WINDOW = float(os.getenv("SENTINELX_SYN_FLOOD_WINDOW", "5.0"))
SYN_FLOOD_COMPLETION_RATIO = float(os.getenv("SENTINELX_SYN_FLOOD_COMPLETION_RATIO", "0.2"))
SYN_FLOOD_ALERT_COOLDOWN = float(os.getenv("SENTINELX_SYN_FLOOD_COOLDOWN", "30.0"))
SYN_FLOOD_HALF_OPEN_TTL = float(os.getenv("SENTINELX_SYN_FLOOD_HALF_OPEN_TTL", "30.0"))

# Volumetric anomaly detection
VOLUMETRIC_TIME_WINDOW = float(os.getenv("SENTINELX_VOLUMETRIC_WINDOW", "10.0"))
VOLUMETRIC_EWMA_ALPHA = float(os.getenv("SENTINELX_VOLUMETRIC_EWMA_ALPHA", "0.2"))
VOLUMETRIC_WARMUP_WINDOWS = int(os.getenv("SENTINELX_VOLUMETRIC_WARMUP_WINDOWS", "3"))
VOLUMETRIC_HARD_CEILING_PPS = float(os.getenv("SENTINELX_VOLUMETRIC_CEILING_PPS", "50000.0"))
VOLUMETRIC_HARD_CEILING_BPS = float(os.getenv("SENTINELX_VOLUMETRIC_CEILING_BPS", "500000000.0"))  # 500 MB/s
VOLUMETRIC_FLOOR_PPS = float(os.getenv("SENTINELX_VOLUMETRIC_FLOOR_PPS", "1000.0"))
VOLUMETRIC_FLOOR_BPS = float(os.getenv("SENTINELX_VOLUMETRIC_FLOOR_BPS", "10000000.0"))  # 10 MB/s
VOLUMETRIC_MULTIPLIER_K = float(os.getenv("SENTINELX_VOLUMETRIC_MULTIPLIER_K", "5.0"))
VOLUMETRIC_MIN_PACKETS = int(os.getenv("SENTINELX_VOLUMETRIC_MIN_PACKETS", "200"))
VOLUMETRIC_MIN_ELAPSED_SEC = float(os.getenv("SENTINELX_VOLUMETRIC_MIN_ELAPSED_SEC", "1.0"))
VOLUMETRIC_ALERT_COOLDOWN = float(os.getenv("SENTINELX_VOLUMETRIC_COOLDOWN", "30.0"))
VOLUMETRIC_TOP_TALKERS_MAX = int(os.getenv("SENTINELX_VOLUMETRIC_TOP_TALKERS_MAX", "50"))
LOCAL_NETWORKS = os.getenv("SENTINELX_LOCAL_NETWORKS", "")

# Pipeline & Architecture Configuration
CAPTURE_INTERFACE = os.getenv("SENTINELX_INTERFACE", None)
QUEUE_MAXSIZE = int(os.getenv("SENTINELX_QUEUE_SIZE", "10000"))
QUEUE_TIMEOUT = float(os.getenv("SENTINELX_QUEUE_TIMEOUT", "0.5"))
LOG_LEVEL = os.getenv("SENTINELX_LOG_LEVEL", "INFO")
ML_ALERT_COOLDOWN = float(os.getenv("SENTINELX_ML_ALERT_COOLDOWN", "30"))
# Flow extraction (shared by ML training and serving)
FLOW_ACTIVE_TIMEOUT = float(os.getenv("SENTINELX_FLOW_ACTIVE_TIMEOUT", "120.0"))
FLOW_IDLE_TIMEOUT = float(os.getenv("SENTINELX_FLOW_IDLE_TIMEOUT", "15.0"))
# ML runtime role: off unless SENTINELX_ML=on, and even then only with a verified model + passing gate.
ML_MODEL_DIR = os.getenv("SENTINELX_ML_MODEL_DIR", "models")

# Backend & REST API Configuration
API_HOST = os.getenv("SENTINELX_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("SENTINELX_API_PORT", "5000"))
API_DEFAULT_LIMIT = int(os.getenv("SENTINELX_API_DEFAULT_LIMIT", "100"))
API_MAX_LIMIT = int(os.getenv("SENTINELX_API_MAX_LIMIT", "500"))

# Storage & Sensor Configuration
DATA_DIR = Path(os.getenv("SENTINELX_DATA_DIR", "data"))
DEFAULT_DATABASE_FILE = DATA_DIR / "alerts.db"  # written by the sensor, opened read-only by the API
DEFAULT_APP_DATABASE_FILE = DATA_DIR / "app.db"  # owned by the API: users, sessions, triage, audit log
DEFAULT_ALERT_FILE = DATA_DIR / "alerts.jsonl"
SENSOR_ID = os.getenv("SENTINELX_SENSOR_ID", "sensor-1")
STATS_INTERVAL = float(os.getenv("SENTINELX_STATS_INTERVAL", "10.0"))

# Sensor operations
RETENTION_DAYS = int(os.getenv("SENTINELX_RETENTION_DAYS", "30"))  # 0 disables the automatic daily prune
AUDIT_RETENTION_DAYS = int(os.getenv("SENTINELX_AUDIT_RETENTION_DAYS", "365"))  # 0 = keep the audit log forever
RETENTION_INTERVAL_SECONDS = float(os.getenv("SENTINELX_RETENTION_INTERVAL", "86400"))
SENSOR_STATUS_INTERVAL = float(os.getenv("SENTINELX_STATUS_INTERVAL", "10.0"))
SENSOR_OFFLINE_AFTER = float(os.getenv("SENTINELX_SENSOR_OFFLINE_AFTER", "30.0"))
SENSOR_STATUS_RETENTION_HOURS = float(os.getenv("SENTINELX_STATUS_RETENTION_HOURS", "48"))
API_THREADS = int(os.getenv("SENTINELX_API_THREADS", "16"))

# API protection
API_RATE_LIMIT_PER_MIN = int(os.getenv("SENTINELX_RATE_LIMIT", "120"))  # per identity (user/key) or IP, on /api/v1/*
LOGIN_RATE_LIMIT_PER_MIN = int(os.getenv("SENTINELX_LOGIN_RATE_LIMIT", "10"))  # per IP, on /login
RATE_LIMIT_MAX_BUCKETS = int(os.getenv("SENTINELX_RATE_LIMIT_BUCKETS", "10000"))
TRUSTED_PROXIES = [p.strip() for p in os.getenv("SENTINELX_TRUSTED_PROXIES", "").split(",") if p.strip()]
MAX_STREAMS = int(os.getenv("SENTINELX_MAX_STREAMS", "8"))  # concurrent SSE connections; each holds a waitress thread
STREAM_INTERVAL_SECONDS = float(os.getenv("SENTINELX_STREAM_INTERVAL", "2.0"))
STREAM_HEARTBEAT_SECONDS = float(os.getenv("SENTINELX_STREAM_HEARTBEAT", "15.0"))

# Console data limits
EXPORT_MAX_ROWS = int(os.getenv("SENTINELX_EXPORT_MAX_ROWS", "10000"))  # hard cap on CSV/JSON export size
GRAPH_MAX_NODES = int(os.getenv("SENTINELX_GRAPH_MAX_NODES", "200"))
GRAPH_MAX_EDGES = int(os.getenv("SENTINELX_GRAPH_MAX_EDGES", "600"))
DROP_WARN_RATIO = float(os.getenv("SENTINELX_DROP_WARN_RATIO", "0.01"))  # sensor health warning threshold

# Authentication & sessions
HTTPS_ENABLED = os.getenv("SENTINELX_HTTPS", "false").lower() == "true"  # sets the Secure cookie flag
SESSION_IDLE_SECONDS = float(os.getenv("SENTINELX_SESSION_IDLE", "1800"))  # 30 min
SESSION_ABSOLUTE_SECONDS = float(os.getenv("SENTINELX_SESSION_ABSOLUTE", "43200"))  # 12 h
PASSWORD_MIN_LENGTH = int(os.getenv("SENTINELX_PASSWORD_MIN_LENGTH", "12"))
LOGIN_MAX_FAILURES = int(os.getenv("SENTINELX_LOGIN_MAX_FAILURES", "5"))  # per IP and per username, in the window
LOGIN_WINDOW_SECONDS = float(os.getenv("SENTINELX_LOGIN_WINDOW", "900"))
LOGIN_LOCK_BASE_SECONDS = float(os.getenv("SENTINELX_LOGIN_LOCK_BASE", "30"))  # doubles with each further failure
LOGIN_LOCK_MAX_SECONDS = float(os.getenv("SENTINELX_LOGIN_LOCK_MAX", "900"))
TRIAGE_NOTE_MAX_CHARS = 2000

# Alert notifications (webhook). The URL itself is a secret: read only from the environment variable named
# below, never stored in this module, logged, or returned by the API.
WEBHOOK_URL_ENV = "SENTINELX_WEBHOOK_URL"
WEBHOOK_MODE = os.getenv("SENTINELX_WEBHOOK_MODE", "generic").lower()  # generic | slack | discord
WEBHOOK_COOLDOWN = float(os.getenv("SENTINELX_WEBHOOK_COOLDOWN", "60.0"))  # per (threat_type, source_ip), event time
WEBHOOK_QUEUE_MAXSIZE = int(os.getenv("SENTINELX_WEBHOOK_QUEUE", "1000"))
WEBHOOK_RETRIES = int(os.getenv("SENTINELX_WEBHOOK_RETRIES", "3"))
WEBHOOK_BACKOFF_SECONDS = float(os.getenv("SENTINELX_WEBHOOK_BACKOFF", "1.0"))
WEBHOOK_TIMEOUT_SECONDS = float(os.getenv("SENTINELX_WEBHOOK_TIMEOUT", "5.0"))

# Severity Ratio Thresholds (Observed / Threshold)
SEVERITY_RATIO_HIGH = float(os.getenv("SENTINELX_SEVERITY_RATIO_HIGH", "3.0"))
SEVERITY_RATIO_MEDIUM = float(os.getenv("SENTINELX_SEVERITY_RATIO_MEDIUM", "1.0"))


def validate_config(config_dict: dict[str, Any] | None = None) -> None:
    """Validate detection and pipeline configuration values.

    Raises ValueError if any configuration setting is invalid.
    """
    cfg = config_dict or globals()

    positive_int_keys = [
        "VERTICAL_SCAN_THRESHOLD",
        "HORIZONTAL_SCAN_THRESHOLD",
        "SLOW_SCAN_THRESHOLD",
        "SYN_FLOOD_THRESHOLD",
        "PARTITION_CAP_VERTICAL",
        "PARTITION_CAP_HORIZONTAL",
        "PARTITION_CAP_SLOW_SCAN",
        "PARTITION_CAP_SYN_FLOOD_AGGREGATES",
        "PARTITION_CAP_SYN_FLOOD_HALF_OPEN",
        "PARTITION_CAP_VOLUMETRIC",
        "PARTITION_CAP_COOLDOWNS",
        "PARTITION_CAP_SCAN_ATTEMPTS",
        "PARTITION_CAP_SCAN_COMPLETED",
        "PARTITION_CAP_FLOWS",
        "PARTITION_CAP_FLOW_SOURCES",
        "API_THREADS",
        "EXPORT_MAX_ROWS",
        "GRAPH_MAX_NODES",
        "GRAPH_MAX_EDGES",
        "API_RATE_LIMIT_PER_MIN",
        "LOGIN_RATE_LIMIT_PER_MIN",
        "RATE_LIMIT_MAX_BUCKETS",
        "MAX_STREAMS",
        "LOGIN_MAX_FAILURES",
        "PASSWORD_MIN_LENGTH",
        "WEBHOOK_QUEUE_MAXSIZE",
        "VOLUMETRIC_WARMUP_WINDOWS",
        "VOLUMETRIC_MIN_PACKETS",
        "VOLUMETRIC_TOP_TALKERS_MAX",
    ]
    for key in positive_int_keys:
        val = cfg.get(key)
        if val is not None and (not isinstance(val, int) or val <= 0):
            raise ValueError(f"Configuration {key} must be a positive integer, got: {val}")

    positive_float_keys = [
        "PORT_SCAN_TIME_WINDOW",
        "PORT_SCAN_ALERT_COOLDOWN",
        "SLOW_SCAN_TIME_WINDOW",
        "SLOW_SCAN_ALERT_COOLDOWN",
        "SYN_FLOOD_TIME_WINDOW",
        "SYN_FLOOD_ALERT_COOLDOWN",
        "SYN_FLOOD_HALF_OPEN_TTL",
        "VOLUMETRIC_TIME_WINDOW",
        "VOLUMETRIC_FLOOR_PPS",
        "VOLUMETRIC_FLOOR_BPS",
        "VOLUMETRIC_MULTIPLIER_K",
        "VOLUMETRIC_ALERT_COOLDOWN",
        "DETECTION_STATE_TTL",
        "FLOW_ACTIVE_TIMEOUT",
        "FLOW_IDLE_TIMEOUT",
        "RETENTION_INTERVAL_SECONDS",
        "SENSOR_STATUS_INTERVAL",
        "SENSOR_OFFLINE_AFTER",
        "SENSOR_STATUS_RETENTION_HOURS",
        "WEBHOOK_COOLDOWN",
        "WEBHOOK_BACKOFF_SECONDS",
        "WEBHOOK_TIMEOUT_SECONDS",
        "STREAM_INTERVAL_SECONDS",
        "DROP_WARN_RATIO",
        "STREAM_HEARTBEAT_SECONDS",
        "SESSION_IDLE_SECONDS",
        "SESSION_ABSOLUTE_SECONDS",
        "LOGIN_WINDOW_SECONDS",
        "LOGIN_LOCK_BASE_SECONDS",
        "LOGIN_LOCK_MAX_SECONDS",
    ]
    for key in positive_float_keys:
        val = cfg.get(key)
        if val is not None and (not isinstance(val, (int, float)) or val <= 0):
            raise ValueError(f"Configuration {key} must be a positive number, got: {val}")

    retention = cfg.get("RETENTION_DAYS")
    if retention is not None and (not isinstance(retention, int) or retention < 0):
        raise ValueError(f"RETENTION_DAYS must be an integer >= 0 (0 disables pruning), got: {retention}")

    audit_retention = cfg.get("AUDIT_RETENTION_DAYS")
    if audit_retention is not None and (not isinstance(audit_retention, int) or audit_retention < 0):
        raise ValueError(
            f"AUDIT_RETENTION_DAYS must be an integer >= 0 (0 keeps the audit log forever), got: {audit_retention}"
        )

    retries = cfg.get("WEBHOOK_RETRIES")
    if retries is not None and (not isinstance(retries, int) or retries < 0):
        raise ValueError(f"WEBHOOK_RETRIES must be an integer >= 0, got: {retries}")

    mode = cfg.get("WEBHOOK_MODE")
    if mode is not None and mode not in ("generic", "slack", "discord"):
        raise ValueError(f"WEBHOOK_MODE must be generic, slack or discord, got: {mode}")

    failure_ratio = cfg.get("SLOW_SCAN_MIN_FAILURE_RATIO")
    if failure_ratio is not None and (not isinstance(failure_ratio, (int, float)) or not (0.0 < failure_ratio <= 1.0)):
        raise ValueError(f"SLOW_SCAN_MIN_FAILURE_RATIO must be in (0.0, 1.0], got: {failure_ratio}")

    alpha = cfg.get("VOLUMETRIC_EWMA_ALPHA")
    if alpha is not None and (not isinstance(alpha, (int, float)) or not (0.0 < alpha <= 1.0)):
        raise ValueError(f"VOLUMETRIC_EWMA_ALPHA must be in (0.0, 1.0], got: {alpha}")

    ratio = cfg.get("SYN_FLOOD_COMPLETION_RATIO")
    if ratio is not None and (not isinstance(ratio, (int, float)) or not (0.0 < ratio <= 1.0)):
        raise ValueError(f"SYN_FLOOD_COMPLETION_RATIO must be in (0.0, 1.0], got: {ratio}")

    local_nets = cfg.get("LOCAL_NETWORKS")
    if local_nets:
        if isinstance(local_nets, str):
            cidrs = [c.strip() for c in local_nets.split(",") if c.strip()]
        else:
            cidrs = list(local_nets)
        for cidr in cidrs:
            try:
                ip_network(cidr, strict=False)
            except ValueError as err:
                raise ValueError(f"Invalid CIDR in LOCAL_NETWORKS: '{cidr}'") from err
