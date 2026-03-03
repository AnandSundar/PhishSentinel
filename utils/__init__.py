"""
PhishSentinel Utilities Module
Helper functions for email parsing, scoring, and database operations.
"""

from .email_parser import parse_raw_email, extract_headers, extract_body
from .homoglyph import detect_homoglyphs, normalize_domain
from .scoring import calculate_threat_score, get_threat_level
from .db import init_database, save_analysis, get_analysis, get_analysis_history

__all__ = [
    "parse_raw_email",
    "extract_headers",
    "extract_body",
    "detect_homoglyphs",
    "normalize_domain",
    "calculate_threat_score",
    "get_threat_level",
    "init_database",
    "save_analysis",
    "get_analysis",
    "get_analysis_history",
]
