import os
from ipaddress import ip_network
from pathlib import Path
from typing import Any

# SentinelX Detection Configuration

# Canonical Threat Types
THREAT_TYPE_PORT_SCAN = "PORT_SCAN"
THREAT_TYPE_SYN_FLOOD = "SYN_FLOOD"
THREAT_TYPE_VOLUMETRIC = "VOLUMETRIC"

CANONICAL_THREAT_TYPES = (
    THREAT_TYPE_PORT_SCAN,
    THREAT_TYPE_SYN_FLOOD,
    THREAT_TYPE_VOLUMETRIC,
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

MAX_TRACKED_ENTRIES = int(
    os.getenv(
        "SENTINELX_MAX_TRACKED_ENTRIES",
        str(
            PARTITION_CAP_VERTICAL
            + PARTITION_CAP_HORIZONTAL
            + PARTITION_CAP_SLOW_SCAN
            + PARTITION_CAP_SYN_FLOOD_AGGREGATES
            + PARTITION_CAP_VOLUMETRIC
            + PARTITION_CAP_COOLDOWNS
        ),
    )
)
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
CAPTURE_MODE = os.getenv("SENTINELX_MODE", "live").lower()
CAPTURE_INTERFACE = os.getenv("SENTINELX_INTERFACE", None)
PCAP_FILE_PATH = os.getenv("SENTINELX_PCAP_PATH", None)
QUEUE_MAXSIZE = int(os.getenv("SENTINELX_QUEUE_SIZE", "10000"))
QUEUE_TIMEOUT = float(os.getenv("SENTINELX_QUEUE_TIMEOUT", "0.5"))
LOG_LEVEL = os.getenv("SENTINELX_LOG_LEVEL", "INFO")
ML_ALERT_COOLDOWN = int(os.getenv("SENTINELX_ML_ALERT_COOLDOWN", "30"))

# Backend & REST API Configuration
API_HOST = os.getenv("SENTINELX_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("SENTINELX_API_PORT", "5000"))
API_DEBUG = os.getenv("SENTINELX_API_DEBUG", "false").lower() == "true"
API_DEFAULT_LIMIT = int(os.getenv("SENTINELX_API_DEFAULT_LIMIT", "100"))
API_MAX_LIMIT = int(os.getenv("SENTINELX_API_MAX_LIMIT", "500"))
ALLOW_LOCAL_FILE_CORS = os.getenv("SENTINELX_ALLOW_LOCAL_FILE_CORS", "false").lower() == "true"
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("SENTINELX_CORS_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000").split(",")
    if origin.strip()
]

# Storage & Sensor Configuration
DATA_DIR = Path(os.getenv("SENTINELX_DATA_DIR", "data"))
DEFAULT_DATABASE_FILE = DATA_DIR / "sentinelx.db"
DEFAULT_ALERT_FILE = DATA_DIR / "alerts.jsonl"
SENSOR_ID = os.getenv("SENTINELX_SENSOR_ID", "sensor-1")
STATS_INTERVAL = float(os.getenv("SENTINELX_STATS_INTERVAL", "10.0"))

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
    ]
    for key in positive_float_keys:
        val = cfg.get(key)
        if val is not None and (not isinstance(val, (int, float)) or val <= 0):
            raise ValueError(f"Configuration {key} must be a positive number, got: {val}")

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
