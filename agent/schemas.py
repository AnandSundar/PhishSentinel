"""
Pydantic Schemas for PhishSentinel
Defines structured models for LLM output in phishing analysis.
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class SuspiciousLink(BaseModel):
    """Model for a suspicious link found in email body."""

    url: str = Field(description="The actual URL")
    anchor_text: str = Field(description="The visible anchor text")
    is_mismatched: bool = Field(
        description="Whether anchor text differs from actual URL"
    )
    is_ip_based: bool = Field(
        description="Whether URL uses IP address instead of domain"
    )
    is_shortened: bool = Field(description="Whether URL is a shortened URL")
    risk_score: int = Field(ge=0, le=10, description="Risk score 0-10")


class BodyAnalysisResult(BaseModel):
    """Model for body analysis results from LLM."""

    urgency_score: int = Field(
        ge=0, le=10, description="Score for urgency language (0-10)"
    )
    urgency_phrases: List[str] = Field(
        default_factory=list, description="Found urgency phrases"
    )

    credential_harvesting_score: int = Field(
        ge=0, le=10, description="Score for credential harvesting cues (0-10)"
    )
    credential_phrases: List[str] = Field(
        default_factory=list, description="Found credential harvesting phrases"
    )

    impersonation_score: int = Field(
        ge=0, le=10, description="Score for brand impersonation (0-10)"
    )
    impersonated_brands: List[str] = Field(
        default_factory=list, description="Impersonated brand names"
    )

    suspicious_links: List[SuspiciousLink] = Field(
        default_factory=list, description="Suspicious links found"
    )

    homoglyph_domains: List[str] = Field(
        default_factory=list, description="Domains with homoglyph characters"
    )

    # Additional analysis
    total_links_found: int = Field(default=0, description="Total number of links found")
    total_urgency_phrases: int = Field(
        default=0, description="Count of urgency phrases"
    )
    total_credential_phrases: int = Field(
        default=0, description="Count of credential phrases"
    )


class IOCResult(BaseModel):
    """Model for an extracted IOC."""

    type: str = Field(description="IOC type: url, ip, domain, hash, email")
    value: str = Field(description="IOC value")
    context: str = Field(description="Where/how the IOC was found")
    severity: str = Field(default="medium", description="Severity: low, medium, high")


class ThreatReport(BaseModel):
    """Model for the final threat report."""

    executive_summary: str = Field(description="2-3 sentence executive summary")

    header_findings: str = Field(description="Detailed header analysis findings")
    body_findings: str = Field(description="Detailed body analysis findings")
    ioc_findings: str = Field(description="IOC analysis findings")

    recommended_actions: List[str] = Field(
        default_factory=list, description="Recommended actions"
    )

    overall_assessment: str = Field(description="Overall threat assessment")

    confidence_level: str = Field(description="Analysis confidence: low, medium, high")


def format_body_analysis_prompt(body_text: str) -> str:
    """
    Format the prompt for body analysis.

    Args:
        body_text: Email body text

    Returns:
        Formatted prompt string
    """
    return f"""You are a cybersecurity analyst specializing in phishing email detection. 
Analyze the following email body for phishing indicators and provide structured output.

Email Body:
{body_text[:4000]}  # Limit to first 4000 chars

Analyze for:
1. Urgency signals (words like "act now", "account suspended", "verify immediately", "urgent", "24 hours")
2. Credential harvesting cues (password, login, verify, confirm, update account)
3. Brand impersonation (PayPal, Microsoft, Amazon, IRS, banks, etc.)
4. Suspicious links (mismatched anchor text, IP-based URLs, shortened URLs)
5. Homoglyph domains (Unicode lookalike characters in domains)

Provide a detailed analysis with specific phrases found and URLs identified.

Respond with valid JSON matching the BodyAnalysisResult schema."""


def format_report_generation_prompt(
    indicator_results: dict, ioc_list: list, body_analysis: dict
) -> str:
    """
    Format the prompt for report generation.

    Args:
        indicator_results: All indicator scores
        ioc_list: Extracted IOCs
        body_analysis: Body analysis details

    Returns:
        Formatted prompt string
    """
    return f"""You are a senior cybersecurity analyst preparing a threat report. 
Generate a comprehensive markdown report based on the following analysis data.

## Indicator Results:
{indicator_results}

## Extracted IOCs:
{ioc_list}

## Body Analysis:
{body_analysis}

Generate a professional threat report with:
1. Executive Summary (2-3 sentences)
2. Detailed findings per category
3. IOC table
4. Recommended actions
5. Overall assessment

Respond with valid JSON matching the ThreatReport schema."""
