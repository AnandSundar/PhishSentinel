"""
Email Parser Module for PhishSentinel
Provides functions to parse raw email content and extract headers and body.
"""

import email
from email import policy
from email.parser import BytesParser
from email.policy import default
from email.message import Message
from typing import Tuple, Dict, Optional
import re


def parse_raw_email(raw_email: str) -> Tuple[Dict[str, str], str]:
    """
    Parse raw email content and extract headers and body.

    Args:
        raw_email: Raw email content as string

    Returns:
        Tuple of (headers dict, body string)
    """
    try:
        # Try to parse as email message
        msg = email.message_from_string(raw_email, policy=default)
    except Exception:
        # Fallback for bytes
        try:
            msg = email.message_from_bytes(raw_email.encode("utf-8"), policy=default)
        except Exception as e:
            raise ValueError(f"Failed to parse email: {str(e)}")

    # Extract headers
    headers = extract_headers(msg)

    # Extract body
    body = extract_body(msg)

    return headers, body


def extract_headers(msg: Message) -> Dict[str, str]:
    """
    Extract relevant headers from email message.

    Args:
        msg: Email message object

    Returns:
        Dictionary of headers
    """
    # List of important headers to extract
    important_headers = [
        "From",
        "Reply-To",
        "Return-Path",
        "Received",
        "X-Originating-IP",
        "Authentication-Results",
        "DKIM-Signature",
        "Message-ID",
        "Date",
        "Subject",
        "To",
        "Cc",
        "MIME-Version",
        "Content-Type",
        "X-Mailer",
        "X-Priority",
        "X-MS-Exchange-Organization-AuthSource",
    ]

    headers = {}
    for header in important_headers:
        value = msg.get(header)
        if value:
            headers[header] = value

    # Also get all Received headers (there can be multiple)
    received_headers = msg.get_all("Received")
    if received_headers:
        headers["Received"] = received_headers

    return headers


def extract_body(msg: Message) -> str:
    """
    Extract plain text and HTML body from email message.

    Args:
        msg: Email message object

    Returns:
        Combined body text
    """
    body_parts = []

    if msg.is_multipart():
        # Walk through all parts
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in content_disposition:
                continue

            # Get text content
            if content_type == "text/plain":
                try:
                    body = part.get_content()
                    if body:
                        body_parts.append(body)
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    html_body = part.get_content()
                    if html_body:
                        # Strip HTML tags for plain text version
                        text = strip_html_tags(html_body)
                        body_parts.append(text)
                except Exception:
                    pass
    else:
        # Not multipart - get content directly
        try:
            body = msg.get_content()
            if body:
                content_type = msg.get_content_type()
                if content_type == "text/html":
                    body = strip_html_tags(body)
                body_parts.append(body)
        except Exception:
            pass

    return "\n".join(body_parts)


def strip_html_tags(html: str) -> str:
    """
    Strip HTML tags from text.

    Args:
        html: HTML content

    Returns:
        Plain text
    """
    # Remove script and style elements
    text = re.sub(
        r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE
    )
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)

    # Replace common HTML entities
    text = text.replace("&nbsp;", " ")
    text = text.replace("&amp;", "&")
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    text = text.replace("&quot;", '"')
    text = text.replace("&#39;", "'")

    # Remove all HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_domain_from_email(email_addr: str) -> Optional[str]:
    """
    Extract domain from email address.

    Args:
        email_addr: Email address string

    Returns:
        Domain or None
    """
    if not email_addr:
        return None

    # Match pattern: name@domain.com
    match = re.search(r"@([a-zA-Z0-9.-]+)", email_addr)
    if match:
        return match.group(1).lower()

    return None


def parse_authentication_results(auth_results: str) -> Dict[str, str]:
    """
    Parse Authentication-Results header to extract SPF, DKIM, DMARC status.

    Args:
        auth_results: Authentication-Results header value

    Returns:
        Dictionary with spf, dkim, dmarc status
    """
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    if not auth_results:
        return result

    # Check SPF
    if "spf=pass" in auth_results.lower():
        result["spf"] = "pass"
    elif "spf=fail" in auth_results.lower():
        result["spf"] = "fail"
    elif "spf=softfail" in auth_results.lower():
        result["spf"] = "softfail"
    elif "spf=none" in auth_results.lower():
        result["spf"] = "none"

    # Check DKIM
    if "dkim=pass" in auth_results.lower():
        result["dkim"] = "pass"
    elif "dkim=fail" in auth_results.lower():
        result["dkim"] = "fail"
    elif "dkim=none" in auth_results.lower():
        result["dkim"] = "none"

    # Check DMARC
    if "dmarc=pass" in auth_results.lower():
        result["dmarc"] = "pass"
    elif "dmarc=fail" in auth_results.lower():
        result["dmarc"] = "fail"
    elif "dmarc=none" in auth_results.lower():
        result["dmarc"] = "none"

    return result


def extract_urls_from_body(body: str) -> list[Dict[str, str]]:
    """
    Extract URLs from email body.

    Args:
        body: Email body text

    Returns:
        List of URL dictionaries with url, anchor_text, and position
    """
    urls = []

    # Pattern to match href in HTML
    href_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>'

    for match in re.finditer(href_pattern, body, re.IGNORECASE):
        url = match.group(1)
        anchor_text = match.group(2).strip()

        # Skip mailto and tel links
        if url.startswith(("mailto:", "tel:", "javascript:")):
            continue

        urls.append({"url": url, "anchor_text": anchor_text, "position": match.start()})

    # Also match plain URLs (not in href)
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'

    for match in re.finditer(url_pattern, body):
        url = match.group(0)

        # Check if this URL is already captured in href
        if not any(u["url"] == url for u in urls):
            urls.append({"url": url, "anchor_text": url, "position": match.start()})

    return urls


def read_eml_file(file_path: str) -> str:
    """
    Read .eml file content.

    Args:
        file_path: Path to .eml file

    Returns:
        Raw email content as string
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()
