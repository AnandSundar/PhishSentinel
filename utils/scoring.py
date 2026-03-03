"""
Scoring Module for PhishSentinel
Provides score aggregation logic for phishing analysis.
"""

from typing import Dict, List, Tuple


# Weights for different indicator categories
HEADER_WEIGHT = 1.0
BODY_WEIGHT = 1.5
IOC_WEIGHT = 2.0

# Threat level thresholds
THREAT_LEVELS = {
    (0, 20): "Safe ✅",
    (21, 45): "Suspicious ⚠️",
    (46, 74): "Likely Phishing 🚨",
    (75, 100): "Critical ☠️",
}


def calculate_threat_score(
    indicator_results: Dict[str, any], ioc_list: List[Dict]
) -> Tuple[int, str]:
    """
    Calculate overall threat score from indicator results.

    Args:
        indicator_results: Dictionary of indicator results
        ioc_list: List of extracted IOCs

    Returns:
        Tuple of (threat_score, threat_level)
    """
    total_score = 0.0
    max_score = 0.0

    # Header analysis scores (weight: 1.0)
    header_indicators = [
        "spf_check",
        "dkim_check",
        "dmarc_check",
        "reply_to_mismatch",
        "return_path_mismatch",
        "suspicious_received_chain",
        "message_id_anomaly",
    ]

    for indicator in header_indicators:
        if indicator in indicator_results:
            score = indicator_results[indicator]
            max_score += 10 * HEADER_WEIGHT
            total_score += score * HEADER_WEIGHT

    # Body analysis scores (weight: 1.5)
    body_indicators = [
        "urgency_signals",
        "credential_harvesting_cues",
        "impersonation_signals",
        "suspicious_links",
        "homoglyph_domains",
    ]

    for indicator in body_indicators:
        if indicator in indicator_results:
            score = indicator_results[indicator]
            max_score += 10 * BODY_WEIGHT
            total_score += score * BODY_WEIGHT

    # IOC penalty
    if ioc_list:
        ioc_count = len(ioc_list)
        ioc_penalty = min(ioc_count * IOC_WEIGHT, 20)  # Cap at 20 points
        total_score += ioc_penalty
        max_score += 20

    # Normalize to 0-100
    if max_score > 0:
        normalized_score = int((total_score / max_score) * 100)
    else:
        normalized_score = 0

    # Ensure score is within bounds
    normalized_score = max(0, min(100, normalized_score))

    # Determine threat level
    threat_level = get_threat_level(normalized_score)

    return normalized_score, threat_level


def get_threat_level(score: int) -> str:
    """
    Get threat level from score.

    Args:
        score: Threat score (0-100)

    Returns:
        Threat level string
    """
    for (low, high), level in THREAT_LEVELS.items():
        if low <= score <= high:
            return level

    return "Unknown"


def calculate_header_score(
    auth_results: Dict[str, str],
    reply_to_mismatch: bool,
    return_path_mismatch: bool,
    suspicious_received: bool,
    message_id_anomaly: bool,
) -> Dict[str, int]:
    """
    Calculate individual header indicator scores.

    Args:
        auth_results: SPF/DKIM/DMARC results
        reply_to_mismatch: Whether Reply-To differs from From
        return_path_mismatch: Whether Return-Path differs from From
        suspicious_received: Whether received chain is suspicious
        message_id_anomaly: Whether Message-ID domain is anomalous

    Returns:
        Dictionary of indicator scores
    """
    scores = {}

    # SPF check (0-10)
    spf_status = auth_results.get("spf", "unknown")
    if spf_status == "pass":
        scores["spf_check"] = 0
    elif spf_status == "softfail":
        scores["spf_check"] = 5
    elif spf_status == "fail":
        scores["spf_check"] = 10
    else:  # unknown or none
        scores["spf_check"] = 3

    # DKIM check (0-10)
    dkim_status = auth_results.get("dkim", "unknown")
    if dkim_status == "pass":
        scores["dkim_check"] = 0
    elif dkim_status == "fail":
        scores["dkim_check"] = 10
    else:  # unknown or none
        scores["dkim_check"] = 3

    # DMARC check (0-10)
    dmarc_status = auth_results.get("dmarc", "unknown")
    if dmarc_status == "pass":
        scores["dmarc_check"] = 0
    elif dmarc_status == "fail":
        scores["dmarc_check"] = 10
    else:  # unknown or none
        scores["dmarc_check"] = 3

    # Reply-To mismatch (0-10)
    scores["reply_to_mismatch"] = 10 if reply_to_mismatch else 0

    # Return-Path mismatch (0-10)
    scores["return_path_mismatch"] = 10 if return_path_mismatch else 0

    # Suspicious received chain (0-10)
    scores["suspicious_received_chain"] = 10 if suspicious_received else 0

    # Message-ID anomaly (0-10)
    scores["message_id_anomaly"] = 10 if message_id_anomaly else 0

    return scores


def calculate_body_score(
    urgency_score: int,
    credential_score: int,
    impersonation_score: int,
    suspicious_links_score: int,
    homoglyph_score: int,
) -> Dict[str, int]:
    """
    Calculate individual body indicator scores.

    Args:
        urgency_score: Urgency language score (0-10)
        credential_score: Credential harvesting score (0-10)
        impersonation_score: Impersonation score (0-10)
        suspicious_links_score: Suspicious links score (0-10)
        homoglyph_score: Homoglyph domain score (0-10)

    Returns:
        Dictionary of indicator scores
    """
    return {
        "urgency_signals": min(10, urgency_score),
        "credential_harvesting_cues": min(10, credential_score),
        "impersonation_signals": min(10, impersonation_score),
        "suspicious_links": min(10, suspicious_links_score),
        "homoglyph_domains": min(10, homoglyph_score),
    }


def should_skip_deep_inspection(indicator_results: Dict[str, int]) -> bool:
    """
    Determine if deep inspection can be skipped based on header analysis.
    If SPF + DKIM + DMARC all pass AND no reply_to_mismatch, skip suspicious_received_chain.

    Args:
        indicator_results: Dictionary of indicator scores

    Returns:
        True if deep inspection can be skipped
    """
    # Check if all authentication checks pass
    spf_pass = indicator_results.get("spf_check", -1) == 0
    dkim_pass = indicator_results.get("dkim_check", -1) == 0
    dmarc_pass = indicator_results.get("dmarc_check", -1) == 0

    # Check if no reply-to mismatch
    no_reply_mismatch = indicator_results.get("reply_to_mismatch", 10) == 0

    return spf_pass and dkim_pass and dmarc_pass and no_reply_mismatch


def get_score_color(score: int) -> str:
    """
    Get color for threat score visualization.

    Args:
        score: Threat score (0-100)

    Returns:
        Color hex code
    """
    if score <= 20:
        return "#22c55e"  # Green
    elif score <= 45:
        return "#eab308"  # Yellow
    elif score <= 74:
        return "#f97316"  # Orange
    else:
        return "#ef4444"  # Red


def format_score_summary(
    threat_score: int, threat_level: str, indicator_results: Dict
) -> str:
    """
    Format a summary of scoring results.

    Args:
        threat_score: Final threat score
        threat_level: Threat level string
        indicator_results: All indicator results

    Returns:
        Formatted summary string
    """
    lines = [
        f"## Threat Score Summary",
        f"",
        f"**Overall Score:** {threat_score}/100",
        f"**Threat Level:** {threat_level}",
        f"",
        f"### Header Analysis",
    ]

    # Add header scores
    header_keys = [
        "spf_check",
        "dkim_check",
        "dmarc_check",
        "reply_to_mismatch",
        "return_path_mismatch",
        "suspicious_received_chain",
        "message_id_anomaly",
    ]

    for key in header_keys:
        if key in indicator_results:
            score = indicator_results[key]
            indicator_name = key.replace("_", " ").title()
            lines.append(f"- {indicator_name}: {score}/10")

    lines.append(f"")
    lines.append(f"### Body Analysis")

    # Add body scores
    body_keys = [
        "urgency_signals",
        "credential_harvesting_cues",
        "impersonation_signals",
        "suspicious_links",
        "homoglyph_domains",
    ]

    for key in body_keys:
        if key in indicator_results:
            score = indicator_results[key]
            indicator_name = key.replace("_", " ").title()
            lines.append(f"- {indicator_name}: {score}/10")

    return "\n".join(lines)
