"""
Node Functions for PhishSentinel LangGraph Agent
Contains all analysis node functions for the phishing detection pipeline.
"""

import re
import os
import json
import uuid
from typing import Dict, List, Any, Optional

# Import utilities
from utils.email_parser import (
    parse_raw_email,
    extract_domain_from_email,
    parse_authentication_results,
    extract_urls_from_body,
)
from utils.homoglyph import detect_homoglyphs, get_homoglyph_details
from utils.scoring import (
    calculate_threat_score,
    get_threat_level,
    calculate_header_score,
    calculate_body_score,
    should_skip_deep_inspection,
)
from agent.schemas import BodyAnalysisResult, ThreatReport


# ============================================
# Node 1: Parse Email
# ============================================


def parse_email_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse raw email content and extract headers and body.

    Args:
        state: Current analysis state

    Returns:
        Updated state with parsed headers and body
    """
    raw_email = state.get("raw_email", "")
    analysis_id = state.get("analysis_id", str(uuid.uuid4()))

    if not raw_email:
        return {**state, "error": "No email content provided"}

    try:
        # Parse email
        headers, body = parse_raw_email(raw_email)

        # Extract sender email and subject
        sender_email = headers.get("From", "")
        subject = headers.get("Subject", "")

        # Parse authentication results
        auth_header = headers.get("Authentication-Results", "")
        auth_results = parse_authentication_results(auth_header)

        # Add auth results to headers
        headers["auth_results"] = auth_results

        return {
            **state,
            "analysis_id": analysis_id,
            "parsed_headers": headers,
            "parsed_body": body,
            "sender_email": sender_email,
            "subject": subject,
            "error": None,
        }

    except Exception as e:
        return {**state, "error": f"Failed to parse email: {str(e)}"}


# ============================================
# Node 2: Header Analysis
# ============================================


def analyze_headers_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze email headers for authentication and anomalies.

    Checks:
    - SPF, DKIM, DMARC status
    - Reply-To mismatch
    - Return-Path mismatch
    - Suspicious received chain
    - Message-ID anomaly

    Args:
        state: Current analysis state

    Returns:
        Updated state with header analysis results
    """
    headers = state.get("parsed_headers", {})
    sender_email = headers.get("From", "")

    # Get authentication results
    auth_results = headers.get("auth_results", {})

    # Extract domains
    from_domain = extract_domain_from_email(sender_email)
    reply_to = headers.get("Reply-To", "")
    reply_to_domain = extract_domain_from_email(reply_to)
    return_path = headers.get("Return-Path", "")
    return_path_domain = extract_domain_from_email(return_path)
    message_id = headers.get("Message-ID", "")
    message_id_domain = extract_domain_from_email(message_id)

    # Check for mismatches
    reply_to_mismatch = (
        reply_to_domain is not None
        and from_domain is not None
        and reply_to_domain != from_domain
    )

    return_path_mismatch = (
        return_path_domain is not None
        and from_domain is not None
        and return_path_domain != from_domain
    )

    message_id_anomaly = (
        message_id_domain is not None
        and from_domain is not None
        and message_id_domain != from_domain
    )

    # Check received chain
    received = headers.get("Received", [])
    if isinstance(received, str):
        received = [received]

    suspicious_received = False
    if received:
        # Check for excessive hops
        if len(received) > 5:
            suspicious_received = True

        # Check for private IP ranges
        private_ip_pattern = r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"
        for recv in received:
            if re.search(private_ip_pattern, recv):
                suspicious_received = True
                break

    # Calculate header scores
    header_scores = calculate_header_score(
        auth_results=auth_results,
        reply_to_mismatch=reply_to_mismatch,
        return_path_mismatch=return_path_mismatch,
        suspicious_received=suspicious_received,
        message_id_anomaly=message_id_anomaly,
    )

    # Store indicator results
    indicator_results = state.get("indicator_results", {})
    indicator_results.update(header_scores)

    return {
        **state,
        "indicator_results": indicator_results,
        "header_analysis_complete": True,
    }


# ============================================
# Node 3: IOC Extraction
# ============================================


def extract_iocs_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract Indicators of Compromise from email body.

    Extracts:
    - URLs
    - Email addresses
    - IP addresses
    - Domains

    Args:
        state: Current analysis state

    Returns:
        Updated state with extracted IOCs
    """
    body = state.get("parsed_body", "")
    headers = state.get("parsed_headers", {})

    ioc_list = []

    # Extract URLs from body
    urls = extract_urls_from_body(body)
    for url_info in urls:
        url = url_info["url"]
        anchor_text = url_info["anchor_text"]

        # Determine severity
        severity = "low"
        if "verify" in anchor_text.lower() or "login" in anchor_text.lower():
            severity = "high"
        elif "click" in anchor_text.lower():
            severity = "medium"

        ioc_list.append(
            {
                "type": "url",
                "value": url,
                "context": f"Found in link: {anchor_text}",
                "severity": severity,
            }
        )

    # Extract email addresses
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    for match in re.finditer(email_pattern, body):
        email = match.group()
        if email not in ioc_list:
            ioc_list.append(
                {
                    "type": "email",
                    "value": email,
                    "context": "Found in body text",
                    "severity": "medium",
                }
            )

    # Extract IP addresses from Received headers
    received = headers.get("Received", [])
    if isinstance(received, str):
        received = [received]

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    for recv in received:
        for match in re.finditer(ip_pattern, recv):
            ip = match.group()
            # Skip private IPs
            if not ip.startswith(("10.", "172.", "192.168.", "127.")):
                if not any(ioc["value"] == ip for ioc in ioc_list):
                    ioc_list.append(
                        {
                            "type": "ip",
                            "value": ip,
                            "context": "Found in Received header",
                            "severity": "medium",
                        }
                    )

    # Extract domains from various sources
    domains_found = set()

    # From sender
    from_domain = extract_domain_from_email(headers.get("From", ""))
    if from_domain:
        domains_found.add(from_domain)

    # From reply-to
    reply_to_domain = extract_domain_from_email(headers.get("Reply-To", ""))
    if reply_to_domain:
        domains_found.add(reply_to_domain)

    # From URLs
    for url_info in urls:
        url = url_info["url"]
        domain_match = re.search(r"://([^/:]+)", url)
        if domain_match:
            domains_found.add(domain_match.group(1))

    # Check for homoglyphs
    for domain in list(domains_found):
        is_suspicious, normalized = detect_homoglyphs(domain)
        if is_suspicious:
            ioc_list.append(
                {
                    "type": "domain",
                    "value": domain,
                    "context": f"Homoglyph detected (normalizes to: {normalized})",
                    "severity": "high",
                }
            )

    return {**state, "ioc_list": ioc_list}


# ============================================
# Node 4: Body Analysis (Rule-based)
# ============================================


def analyze_body_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze email body for phishing indicators using rule-based detection.

    Checks:
    - Urgency signals
    - Credential harvesting cues
    - Brand impersonation
    - Suspicious links
    - Homoglyph domains

    Args:
        state: Current analysis state

    Returns:
        Updated state with body analysis results
    """
    body = state.get("parsed_body", "")
    headers = state.get("parsed_headers", {})

    indicator_results = state.get("indicator_results", {})

    # 1. Urgency signals
    urgency_patterns = [
        r"\b(urgent|immediately|act now|within 24 hours|account suspended|"
        r"final warning|expire|unauthorized|limited|restricted|"
        r"lock|terminate|cancel|close)\b",
        r"\b(verify your account|confirm your identity|update your information)\b",
    ]

    urgency_phrases = []
    for pattern in urgency_patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        urgency_phrases.extend(matches)

    urgency_count = len(set(urgency_phrases))
    urgency_score = min(10, urgency_count * 2)  # Max 10

    # 2. Credential harvesting
    credential_patterns = [
        r"\b(password|login|sign in|verify|confirm|update|bank account|"
        r"credit card|social security|ssn|date of birth|address|phone)\b",
        r"\b(account information|personal information|security details)\b",
    ]

    credential_phrases = []
    for pattern in credential_patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        credential_phrases.extend(matches)

    credential_count = len(set(credential_phrases))
    credential_score = min(10, credential_count * 2)

    # 3. Impersonation signals
    known_brands = [
        "paypal",
        "amazon",
        "microsoft",
        "apple",
        "google",
        "netflix",
        "bank of america",
        "chase",
        "wells fargo",
        "citi",
        "irs",
        "fedex",
        "ups",
    ]

    impersonated_brands = []
    body_lower = body.lower()
    for brand in known_brands:
        if brand in body_lower:
            impersonated_brands.append(brand)

    impersonation_score = min(10, len(impersonated_brands) * 3)

    # 4. Suspicious links
    urls = extract_urls_from_body(body)
    suspicious_link_score = 0

    for url_info in urls:
        url = url_info["url"]
        anchor_text = url_info["anchor_text"]

        # Check for IP-based URL
        if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
            suspicious_link_score += 3
            continue

        # Check for shortened URLs
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]
        if any(s in url for s in shorteners):
            suspicious_link_score += 2
            continue

        # Check for mismatched anchor (basic check)
        if anchor_text and "http" in anchor_text.lower():
            suspicious_link_score += 1

    suspicious_link_score = min(10, suspicious_link_score)

    # 5. Homoglyph domains in links
    homoglyph_score = 0
    for url_info in urls:
        url = url_info["url"]
        domain_match = re.search(r"://([^/:]+)", url)
        if domain_match:
            domain = domain_match.group(1)
            is_suspicious, _ = detect_homoglyphs(domain)
            if is_suspicious:
                homoglyph_score = 10
                break

    # Calculate body scores
    body_scores = calculate_body_score(
        urgency_score=urgency_score,
        credential_score=credential_score,
        impersonation_score=impersonation_score,
        suspicious_links_score=suspicious_link_score,
        homoglyph_score=homoglyph_score,
    )

    indicator_results.update(body_scores)

    # Store body analysis details
    body_analysis_details = {
        "urgency_phrases": list(set(urgency_phrases)),
        "credential_phrases": list(set(credential_phrases)),
        "impersonated_brands": impersonated_brands,
        "total_links": len(urls),
    }

    return {
        **state,
        "indicator_results": indicator_results,
        "body_analysis_details": body_analysis_details,
    }


# ============================================
# Node 5: Score Aggregation
# ============================================


def calculate_score_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate final threat score from all indicator results.

    Uses weighted scoring:
    - Header checks: 1.0x weight
    - Body checks: 1.5x weight
    - IOC penalty: up to 20 points

    Args:
        state: Current analysis state

    Returns:
        Updated state with threat score and level
    """
    indicator_results = state.get("indicator_results", {})
    ioc_list = state.get("ioc_list", [])

    # Calculate threat score
    threat_score, threat_level = calculate_threat_score(
        indicator_results=indicator_results, ioc_list=ioc_list
    )

    return {**state, "threat_score": threat_score, "threat_level": threat_level}


# ============================================
# Node 6: Report Generation
# ============================================


def generate_report_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate markdown threat report.

    Creates a comprehensive narrative report including:
    - Executive summary
    - Header findings
    - Body findings
    - IOC list
    - Recommended actions

    Args:
        state: Current analysis state

    Returns:
        Updated state with summary report
    """
    threat_score = state.get("threat_score", 0)
    threat_level = state.get("threat_level", "Unknown")
    indicator_results = state.get("indicator_results", {})
    ioc_list = state.get("ioc_list", [])
    body_analysis = state.get("body_analysis_details", {})
    headers = state.get("parsed_headers", {})

    # Build report sections
    lines = []
    lines.append("# 🕵️ PhishSentinel Threat Analysis Report\n")

    # Executive Summary
    lines.append("## 📋 Executive Summary\n")

    if threat_score <= 20:
        summary = f"This email appears to be **SAFE** with a threat score of {threat_score}/100. "
        summary += "No significant phishing indicators were detected."
    elif threat_score <= 45:
        summary = (
            f"This email is **SUSPICIOUS** with a threat score of {threat_score}/100. "
        )
        summary += "Some indicators warrant attention but don't definitively indicate phishing."
    elif threat_score <= 74:
        summary = f"This email is likely a **PHISHING ATTEMPT** with a threat score of {threat_score}/100. "
        summary += "Multiple suspicious indicators were detected."
    else:
        summary = f"⚠️ This email is a **CRITICAL PHISHING THREAT** with a threat score of {threat_score}/100. "
        summary += "Immediate action is recommended."

    lines.append(summary + "\n")

    # Header Analysis
    lines.append("## 🔍 Header Analysis\n")

    auth_results = headers.get("auth_results", {})
    spf_status = auth_results.get("spf", "unknown").upper()
    dkim_status = auth_results.get("dkim", "unknown").upper()
    dmarc_status = auth_results.get("dmarc", "unknown").upper()

    lines.append(f"| Check | Status | Risk Score |")
    lines.append(f"|-------|--------|------------|")
    lines.append(f"| SPF | {spf_status} | {indicator_results.get('spf_check', 0)}/10 |")
    lines.append(
        f"| DKIM | {dkim_status} | {indicator_results.get('dkim_check', 0)}/10 |"
    )
    lines.append(
        f"| DMARC | {dmarc_status} | {indicator_results.get('dmarc_check', 0)}/10 |"
    )

    if indicator_results.get("reply_to_mismatch", 0) > 0:
        lines.append(
            f"| Reply-To Mismatch | ⚠️ Yes | {indicator_results.get('reply_to_mismatch')}/10 |"
        )

    if indicator_results.get("return_path_mismatch", 0) > 0:
        lines.append(
            f"| Return-Path Mismatch | ⚠️ Yes | {indicator_results.get('return_path_mismatch')}/10 |"
        )

    lines.append("")

    # Body Analysis
    lines.append("## 📧 Body Analysis\n")

    urgency_phrases = body_analysis.get("urgency_phrases", [])
    if urgency_phrases:
        lines.append(f"**Urgency Signals Found:** {', '.join(urgency_phrases[:5])}")

    credential_phrases = body_analysis.get("credential_phrases", [])
    if credential_phrases:
        lines.append(
            f"**Credential Harvesting Cues:** {', '.join(credential_phrases[:5])}"
        )

    impersonated_brands = body_analysis.get("impersonated_brands", [])
    if impersonated_brands:
        lines.append(
            f"**Potential Brand Impersonation:** {', '.join(impersonated_brands)}"
        )

    lines.append("")

    # IOCs
    if ioc_list:
        lines.append("## 🎯 Indicators of Compromise (IOCs)\n")
        lines.append(f"**Total IOCs Found:** {len(ioc_list)}\n")
        lines.append("| Type | Value | Severity |")
        lines.append("|------|-------|----------|")

        for ioc in ioc_list[:20]:  # Limit to 20 for display
            ioc_type = ioc.get("type", "unknown")
            ioc_value = ioc.get("value", "")[:50]
            severity = ioc.get("severity", "medium")
            lines.append(f"| {ioc_type} | {ioc_value} | {severity} |")

        lines.append("")

    # Recommended Actions
    lines.append("## ✅ Recommended Actions\n")

    if threat_score > 45:
        lines.append("1. **Do NOT click** any links in this email")
        lines.append("2. **Do NOT reply** to this email")
        lines.append("3. **Block the sender** and mark as phishing")
        lines.append("4. **If clicked:** Change passwords immediately and enable 2FA")
    else:
        lines.append("1. Continue to exercise caution with unexpected emails")
        lines.append("2. Verify sender identity through official channels if needed")

    lines.append("")
    lines.append(f"---\n")
    lines.append(f"*Analysis ID: {state.get('analysis_id', 'N/A')}*")
    lines.append(f"*Generated by PhishSentinel AI Analyzer*")

    summary_report = "\n".join(lines)

    return {**state, "summary_report": summary_report}


# ============================================
# Node 7: SQLite Storage
# ============================================


def sqlite_storage_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Persist analysis results to SQLite database.

    Args:
        state: Current analysis state

    Returns:
        Updated state with storage status
    """
    from utils.db import save_analysis

    try:
        analysis_id = state.get("analysis_id", str(uuid.uuid4()))
        threat_score = state.get("threat_score", 0)
        threat_level = state.get("threat_level", "Unknown")
        summary_report = state.get("summary_report", "")
        sender_email = state.get("sender_email")
        subject = state.get("subject")

        # Save to database
        success = save_analysis(
            analysis_id=analysis_id,
            threat_score=threat_score,
            threat_level=threat_level,
            summary=summary_report,
            raw_state=state,
            sender_email=sender_email,
            subject=subject,
        )

        return {**state, "saved_to_db": success}

    except Exception as e:
        return {**state, "saved_to_db": False, "storage_error": str(e)}
