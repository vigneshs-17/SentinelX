"""
Scoring and classification logic for SentinelX intrusion detection alerts.

Provides transparent, deterministic calculation of alert severity levels
and confidence scores based on threshold excess ratios.
"""

from config.settings import SEVERITY_RATIO_HIGH, SEVERITY_RATIO_MEDIUM


def calculate_severity(observed: float, threshold: float) -> str:
    """
    Calculate alert severity based on threshold excess ratio.

    Threshold excess ratio = observed / threshold:
    - ratio >= SEVERITY_RATIO_HIGH (default 3.0) -> "HIGH"
    - ratio >= SEVERITY_RATIO_MEDIUM (default 1.0) -> "MEDIUM"
    - ratio < SEVERITY_RATIO_MEDIUM -> "LOW" (informational / ML-only detections)
    """
    if threshold <= 0:
        return "HIGH"
    ratio = observed / threshold
    if ratio >= SEVERITY_RATIO_HIGH:
        return "HIGH"
    if ratio >= SEVERITY_RATIO_MEDIUM:
        return "MEDIUM"
    return "LOW"


def calculate_confidence(observed: float, threshold: float) -> float:
    """
    Calculate detection confidence score [0.0 - 1.0] consistent with severity.

    - At ratio == 1.0 -> 0.80 (baseline MEDIUM alert)
    - At ratio >= 3.0 -> >= 0.95 (HIGH alert, up to 0.99)
    - Below 1.0 -> scaled below 0.80 (minimum 0.50)
    """
    if threshold <= 0:
        return 1.0
    ratio = observed / threshold
    if ratio >= SEVERITY_RATIO_HIGH:
        return round(min(0.95 + 0.01 * (ratio - SEVERITY_RATIO_HIGH), 0.99), 2)
    if ratio >= SEVERITY_RATIO_MEDIUM:
        # Scale smoothly from 0.80 to 0.95 across [1.0, 3.0]
        score = 0.80 + 0.15 * ((ratio - SEVERITY_RATIO_MEDIUM) / (SEVERITY_RATIO_HIGH - SEVERITY_RATIO_MEDIUM))
        return round(score, 2)
    return round(max(0.50, 0.80 * ratio), 2)
