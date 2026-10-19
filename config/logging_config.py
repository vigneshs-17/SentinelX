"""
Centralized logging configuration for SentinelX.

Exposes configure_logging() for explicit initialization by application
entry points (main.py and backend API). Importing this module does NOT
configure or alter logging state.
"""

import logging
import os
import sys

from config.settings import LOG_LEVEL

_configured = False


def configure_logging(level: str | None = None) -> None:
    """
    Configure root and sentinelx loggers with standardized formatting and level.

    Handles Windows console encoding limits cleanly with sys.stdout.
    Must be called explicitly from entry points.
    """
    global _configured
    log_level_name = (level or os.getenv("SENTINELX_LOG_LEVEL") or LOG_LEVEL).upper()
    numeric_level = getattr(logging, log_level_name, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers if called multiple times
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    else:
        for h in root_logger.handlers:
            h.setLevel(numeric_level)

    _configured = True
