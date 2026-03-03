"""
PhishSentinel Agent Module
LangGraph-powered agentic system for phishing email analysis.
"""

from .graph import run_analysis, create_analysis_graph
from .state import PhishingAnalysisState, get_initial_state

# Import node functions for direct use
from .nodes import (
    parse_email_node,
    analyze_headers_node,
    extract_iocs_node,
    analyze_body_node,
    calculate_score_node,
    generate_report_node,
    sqlite_storage_node,
)

__all__ = [
    "run_analysis",
    "create_analysis_graph",
    "PhishingAnalysisState",
    "get_initial_state",
    "parse_email_node",
    "analyze_headers_node",
    "extract_iocs_node",
    "analyze_body_node",
    "calculate_score_node",
    "generate_report_node",
    "sqlite_storage_node",
]
