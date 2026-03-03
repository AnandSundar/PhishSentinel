"""
State Definition for PhishSentinel LangGraph Agent
Defines the TypedDict for the phishing analysis state.
"""

from typing import TypedDict, Dict, List, Optional, Any


class PhishingAnalysisState(TypedDict):
    """
    State dictionary for the PhishingAnalysisState graph.
    Contains all data collected and computed during the analysis pipeline.
    """

    # Input
    raw_email: str  # Raw email content (pasted or from file)

    # Parsed data
    parsed_headers: Dict[str, Any]  # Parsed email headers
    parsed_body: str  # Plain text body

    # Analysis results
    indicator_results: Dict[str, int]  # Results from each of the 12 checks

    # Extracted IOCs
    ioc_list: List[Dict[str, str]]  # Extracted IOCs (type, value, context)

    # Final scores
    threat_score: int  # 0-100
    threat_level: str  # "Safe", "Suspicious", "Likely Phishing", "Critical"

    # Report
    summary_report: str  # LLM-generated markdown narrative

    # Metadata
    analysis_id: str  # Unique identifier for this analysis

    # Additional fields for UI
    sender_email: Optional[str]  # Extracted sender email
    subject: Optional[str]  # Email subject

    # Body analysis details (for detailed reporting)
    body_analysis_details: Optional[Dict[str, Any]]  # Detailed body analysis from LLM


def get_initial_state(raw_email: str, analysis_id: str) -> PhishingAnalysisState:
    """
    Create initial state for the analysis graph.

    Args:
        raw_email: Raw email content
        analysis_id: Unique analysis identifier

    Returns:
        Initial state dictionary
    """
    return {
        "raw_email": raw_email,
        "parsed_headers": {},
        "parsed_body": "",
        "indicator_results": {},
        "ioc_list": [],
        "threat_score": 0,
        "threat_level": "Safe ✅",
        "summary_report": "",
        "analysis_id": analysis_id,
        "sender_email": None,
        "subject": None,
        "body_analysis_details": None,
    }
