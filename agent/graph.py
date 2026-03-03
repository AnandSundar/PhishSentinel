"""
LangGraph Agent Implementation for PhishSentinel
Defines the graph nodes and workflow for phishing analysis with LLM enhancement.
"""

import os
import json
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI

# Import project modules
from agent.state import PhishingAnalysisState, get_initial_state
from agent.schemas import (
    BodyAnalysisResult,
    ThreatReport,
    format_body_analysis_prompt,
    format_report_generation_prompt,
)
from utils import email_parser, homoglyph, scoring


# LLM Configuration
def get_llm(temperature: float = 0.0) -> Optional[ChatOpenAI]:
    """
    Get configured LLM instance.

    Args:
        temperature: LLM temperature setting

    Returns:
        ChatOpenAI instance or None if no API key
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Warning: OPENAI_API_KEY not set. LLM features will be disabled.")
        return None

    return ChatOpenAI(model="gpt-4", temperature=temperature, api_key=api_key)


# Node Functions
def parse_email_node(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Parse raw email content into headers and body.

    Args:
        state: Current analysis state

    Returns:
        Updated state with parsed content
    """
    raw_email = state.get("raw_email", "")

    if not raw_email:
        return state

    try:
        headers, body = email_parser.parse_raw_email(raw_email)
        state["parsed_headers"] = headers
        state["parsed_body"] = body

        # Extract sender and subject
        state["sender_email"] = headers.get("From")
        state["subject"] = headers.get("Subject", "No Subject")

    except Exception as e:
        print(f"Error parsing email: {e}")
        # Fallback: treat entire content as body
        state["parsed_body"] = raw_email

    return state


def extract_sender_domain(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Extract sender domain from parsed headers.

    Args:
        state: Current analysis state

    Returns:
        Updated state with sender domain
    """
    sender_email = state.get("sender_email")
    if sender_email:
        sender_domain = email_parser.extract_domain_from_email(sender_email)
        state["sender_domain"] = sender_domain

    return state


def analyze_headers_node(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Analyze email headers for authentication and anomalies.

    Args:
        state: Current analysis state

    Returns:
        Updated state with header analysis results
    """
    headers = state.get("parsed_headers", {})
    sender_email = state.get("sender_email")
    sender_domain = state.get("sender_domain")

    indicator_results = state.get("indicator_results", {})

    # Parse authentication results
    auth_results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if "Authentication-Results" in headers:
        auth_results = email_parser.parse_authentication_results(
            headers["Authentication-Results"]
        )

    # Check for Reply-To mismatch
    reply_to_mismatch = False
    if "Reply-To" in headers and sender_domain:
        reply_to_domain = email_parser.extract_domain_from_email(headers["Reply-To"])
        if reply_to_domain and reply_to_domain != sender_domain:
            reply_to_mismatch = True

    # Check for Return-Path mismatch
    return_path_mismatch = False
    if "Return-Path" in headers and sender_domain:
        return_path_domain = email_parser.extract_domain_from_email(
            headers["Return-Path"]
        )
        if return_path_domain and return_path_domain != sender_domain:
            return_path_mismatch = True

    # Calculate header scores
    header_scores = scoring.calculate_header_score(
        auth_results=auth_results,
        reply_to_mismatch=reply_to_mismatch,
        return_path_mismatch=return_path_mismatch,
        suspicious_received=False,
        message_id_anomaly=False,
    )

    indicator_results.update(header_scores)
    state["indicator_results"] = indicator_results

    return state


def extract_iocs_node(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Extract IOCs from email body.

    Args:
        state: Current analysis state

    Returns:
        Updated state with extracted IOCs
    """
    body = state.get("parsed_body", "")

    if not body:
        return state

    iocs = []

    # Extract URLs
    urls = email_parser.extract_urls_from_body(body)
    import re

    ip_pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"

    for url_info in urls:
        url = url_info.get("url", "")
        if not url:
            continue

        is_ip = bool(re.match(ip_pattern, url))

        iocs.append(
            {
                "type": "url",
                "value": url,
                "context": url_info.get("anchor_text", "Link in email body"),
                "severity": "high" if is_ip else "medium",
            }
        )

    # Extract email addresses
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    emails = re.findall(email_pattern, body)
    for email in emails:
        iocs.append(
            {
                "type": "email",
                "value": email,
                "context": "Found in email body",
                "severity": "low",
            }
        )

    # Extract IP addresses from body
    ip_extract_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_extract_pattern, body)
    for ip in ips:
        # Filter out common false positives
        if not ip.startswith(("0.", "255.", "127.")):
            iocs.append(
                {
                    "type": "ip",
                    "value": ip,
                    "context": "Found in email body",
                    "severity": "medium",
                }
            )

    state["ioc_list"] = iocs
    return state


def analyze_body_node(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Analyze email body for phishing indicators using rule-based analysis.

    Args:
        state: Current analysis state

    Returns:
        Updated state with body analysis results
    """
    body = state.get("parsed_body", "")

    if not body:
        return state

    indicator_results = state.get("indicator_results", {})
    body_lower = body.lower()

    # Initialize scores
    urgency_score = 0
    credential_score = 0
    impersonation_score = 0
    suspicious_links_score = 0
    homoglyph_score = 0

    # Urgency keywords
    urgency_keywords = [
        "urgent",
        "immediately",
        "act now",
        "account suspended",
        "verify now",
        "24 hours",
        "limited time",
        "action required",
        "final notice",
        "suspend",
        "lock",
        "unauthorized",
    ]
    urgency_phrases_found = []
    for keyword in urgency_keywords:
        if keyword in body_lower:
            urgency_score = min(10, urgency_score + 2)
            urgency_phrases_found.append(keyword)

    # Credential harvesting keywords
    credential_keywords = [
        "password",
        "login",
        "verify account",
        "confirm identity",
        "update payment",
        "bank account",
        "credit card",
        "ssn",
        "social security",
        "verify your identity",
        "unlock account",
    ]
    credential_phrases_found = []
    for keyword in credential_keywords:
        if keyword in body_lower:
            credential_score = min(10, credential_score + 2)
            credential_phrases_found.append(keyword)

    # Brand impersonation
    known_brands = [
        "paypal",
        "amazon",
        "microsoft",
        "apple",
        "google",
        "netflix",
        "bank of america",
        "wells fargo",
        "chase",
        "irs",
        "social security",
        "adobe",
        "dropbox",
        "facebook",
    ]
    impersonated_brands = []
    for brand in known_brands:
        if brand in body_lower:
            impersonation_score = min(10, impersonation_score + 3)
            impersonated_brands.append(brand)

    # Analyze links
    urls = email_parser.extract_urls_from_body(body)
    if urls:
        for url_info in urls:
            url = url_info.get("url", "")
            if not url:
                continue

            # Check for IP-based URL
            if re.match(r"https?://\d{1,3}\.", url):
                suspicious_links_score = min(10, suspicious_links_score + 5)

            # Check for shortened URLs
            shortened_domains = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
            for short_domain in shortened_domains:
                if short_domain in url:
                    suspicious_links_score = min(10, suspicious_links_score + 3)
                    break

            # Check for homoglyphs in domain
            url_domain_match = re.search(r"https?://([^/]+)", url)
            if url_domain_match:
                url_domain = url_domain_match.group(1)
                has_homoglyph, _ = homoglyph.detect_homoglyphs(url_domain)
                if has_homoglyph:
                    homoglyph_score = min(10, homoglyph_score + 5)

    # Calculate body scores
    body_scores = scoring.calculate_body_score(
        urgency_score=urgency_score,
        credential_score=credential_score,
        impersonation_score=impersonation_score,
        suspicious_links_score=suspicious_links_score,
        homoglyph_score=homoglyph_score,
    )

    indicator_results.update(body_scores)
    state["indicator_results"] = indicator_results

    # Store detailed analysis
    state["body_analysis_details"] = {
        "urgency_phrases": urgency_phrases_found,
        "credential_phrases": credential_phrases_found,
        "impersonated_brands": impersonated_brands,
        "urls_found": len(urls),
        "suspicious_links_count": suspicious_links_score // 3,
        "homoglyph_count": homoglyph_score // 2,
    }

    return state


def llm_body_analysis_node(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Use LLM for enhanced body analysis.

    Args:
        state: Current analysis state

    Returns:
        Updated state with LLM analysis results
    """
    llm = get_llm()
    if not llm:
        print("LLM not available, skipping enhanced analysis")
        return state

    body = state.get("parsed_body", "")
    if not body:
        return state

    try:
        # Format prompt
        prompt = format_body_analysis_prompt(body)

        # Get LLM response
        response = llm.invoke(prompt)
        content = response.content

        # Parse JSON response
        try:
            # Try to extract JSON from response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]

            analysis = json.loads(content)

            # Update indicator results with LLM scores
            indicator_results = state.get("indicator_results", {})

            if "urgency_score" in analysis:
                indicator_results["urgency_signals"] = analysis["urgency_score"]
            if "credential_harvesting_score" in analysis:
                indicator_results["credential_harvesting_cues"] = analysis[
                    "credential_harvesting_score"
                ]
            if "impersonation_score" in analysis:
                indicator_results["impersonation_signals"] = analysis[
                    "impersonation_score"
                ]

            state["indicator_results"] = indicator_results
            state["body_analysis_details"] = analysis

        except json.JSONDecodeError as e:
            print(f"Error parsing LLM response: {e}")

    except Exception as e:
        print(f"Error in LLM body analysis: {e}")

    return state


def calculate_score_node(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Calculate overall threat score.

    Args:
        state: Current analysis state

    Returns:
        Updated state with threat score
    """
    indicator_results = state.get("indicator_results", {})
    ioc_list = state.get("ioc_list", [])

    threat_score, threat_level = scoring.calculate_threat_score(
        indicator_results, ioc_list
    )

    state["threat_score"] = threat_score
    state["threat_level"] = threat_level

    return state


def generate_report_node(state: PhishingAnalysisState) -> PhishingAnalysisState:
    """
    Generate final threat report.

    Args:
        state: Current analysis state

    Returns:
        Updated state with summary report
    """
    indicator_results = state.get("indicator_results", {})
    ioc_list = state.get("ioc_list", [])
    body_analysis = state.get("body_analysis_details", {})

    # Try LLM report generation
    llm = get_llm()

    if llm:
        try:
            prompt = format_report_generation_prompt(
                indicator_results=indicator_results,
                ioc_list=ioc_list,
                body_analysis=body_analysis,
            )

            response = llm.invoke(prompt)
            content = response.content

            # Parse JSON response
            try:
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]

                report = json.loads(content)

                # Build summary from LLM report
                summary_parts = []
                if "executive_summary" in report:
                    summary_parts.append(report["executive_summary"])

                summary_parts.append(
                    f"\n\n**Overall Assessment:** {report.get('overall_assessment', 'N/A')}"
                )
                summary_parts.append(
                    f"\n**Confidence Level:** {report.get('confidence_level', 'N/A')}"
                )

                if "recommended_actions" in report:
                    summary_parts.append("\n\n**Recommended Actions:**")
                    for action in report["recommended_actions"]:
                        summary_parts.append(f"\n- {action}")

                state["summary_report"] = "\n".join(summary_parts)

            except json.JSONDecodeError:
                # Fall back to rule-based summary
                state["summary_report"] = scoring.format_score_summary(
                    state["threat_score"], state["threat_level"], indicator_results
                )

        except Exception as e:
            print(f"Error in LLM report generation: {e}")
            # Fall back to rule-based summary
            state["summary_report"] = scoring.format_score_summary(
                state["threat_score"], state["threat_level"], indicator_results
            )
    else:
        # Use rule-based summary
        state["summary_report"] = scoring.format_score_summary(
            state["threat_score"], state["threat_level"], indicator_results
        )

    return state


def should_skip_llm(state: PhishingAnalysisState) -> bool:
    """
    Determine if LLM analysis should be skipped.

    Args:
        state: Current analysis state

    Returns:
        True if LLM should be skipped
    """
    # Skip if no API key
    if not os.environ.get("OPENAI_API_KEY"):
        return True

    # Skip if threat is clearly critical (score > 80)
    # Proceed with LLM for nuanced analysis
    return False


# Build the graph
def create_analysis_graph() -> StateGraph:
    """
    Create the LangGraph analysis workflow.

    Returns:
        Compiled StateGraph
    """
    graph = StateGraph(PhishingAnalysisState)

    # Add nodes
    graph.add_node("parse_email", parse_email_node)
    graph.add_node("extract_sender_domain", extract_sender_domain)
    graph.add_node("analyze_headers", analyze_headers_node)
    graph.add_node("extract_iocs", extract_iocs_node)
    graph.add_node("analyze_body", analyze_body_node)
    graph.add_node("llm_body_analysis", llm_body_analysis_node)
    graph.add_node("calculate_score", calculate_score_node)
    graph.add_node("generate_report", generate_report_node)

    # Define edges
    graph.add_edge("__start__", "parse_email")
    graph.add_edge("parse_email", "extract_sender_domain")
    graph.add_edge("extract_sender_domain", "analyze_headers")
    graph.add_edge("analyze_headers", "extract_iocs")
    graph.add_edge("extract_iocs", "analyze_body")

    # Conditional edge for LLM analysis
    graph.add_conditional_edges(
        "analyze_body",
        should_skip_llm,
        {True: "calculate_score", False: "llm_body_analysis"},
    )

    graph.add_edge("llm_body_analysis", "calculate_score")
    graph.add_edge("calculate_score", "generate_report")
    graph.add_edge("generate_report", END)

    return graph.compile()


def run_analysis(
    raw_email: str, analysis_id: Optional[str] = None, use_llm: bool = True
) -> Dict[str, Any]:
    """
    Run the full analysis pipeline.

    Args:
        raw_email: Raw email content
        analysis_id: Optional analysis ID
        use_llm: Whether to use LLM analysis

    Returns:
        Final analysis state
    """
    # Create initial state
    if not analysis_id:
        analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    state = get_initial_state(raw_email, analysis_id)

    # Disable LLM if requested or not available
    if not use_llm or not os.environ.get("OPENAI_API_KEY"):
        os.environ.pop("OPENAI_API_KEY", None)

    # Run graph
    graph = create_analysis_graph()
    final_state = graph.invoke(state)

    return final_state


# Import regex for use in other functions
import re


# For backward compatibility
__all__ = [
    "create_analysis_graph",
    "run_analysis",
    "parse_email_node",
    "analyze_headers_node",
    "extract_iocs_node",
    "analyze_body_node",
    "llm_body_analysis_node",
    "calculate_score_node",
    "generate_report_node",
]
