"""
SentinelX Evaluation & Benchmark Package.
"""

from eval.scenarios import SCENARIO_NAMES, generate_scenario
from eval.score import evaluate_scenario, generate_markdown_report

__all__ = [
    "SCENARIO_NAMES",
    "generate_scenario",
    "evaluate_scenario",
    "generate_markdown_report",
]
