"""
Homoglyph Detection Module for PhishSentinel
Provides detection of Unicode lookalike characters used in phishing domains.
"""

from typing import Tuple, List, Dict


# Comprehensive mapping of Unicode homoglyphs to ASCII equivalents
# These are characters that look similar but are from different scripts
HOMOGLYPHS: Dict[str, str] = {
    # Cyrillic letters that look like Latin
    "а": "a",  # Cyrillic 'a' -> Latin 'a'
    "е": "e",  # Cyrillic 'e' -> Latin 'e'
    "о": "o",  # Cyrillic 'o' -> Latin 'o'
    "р": "p",  # Cyrillic 'p' -> Latin 'p'
    "с": "c",  # Cyrillic 'c' -> Latin 'c'
    "х": "x",  # Cyrillic 'x' -> Latin 'x'
    "у": "y",  # Cyrillic 'y' -> Latin 'y'
    "і": "i",  # Cyrillic 'i' -> Latin 'i'
    "ј": "j",  # Cyrillic 'j' -> Latin 'j'
    "ѕ": "s",  # Cyrillic 's' -> Latin 's'
    "ԁ": "d",  # Cyrillic 'd' -> Latin 'd'
    "ɡ": "g",  # Latin IPA 'g' -> Latin 'g'
    # Greek letters that look like Latin
    "ν": "v",  # Greek 'nu' -> Latin 'v'
    "ω": "w",  # Greek 'omega' -> Latin 'w'
    "ɑ": "a",  # IPA 'a' -> Latin 'a'
    "ο": "o",  # Greek 'omicron' -> Latin 'o'
    "Τ": "T",  # Greek 'Tau' -> Latin 'T'
    "Η": "H",  # Greek 'Eta' -> Latin 'H'
    "Ρ": "P",  # Greek 'Rho' -> Latin 'P'
    "Α": "A",  # Greek 'Alpha' -> Latin 'A'
    "Κ": "K",  # Greek 'Kappa' -> Latin 'K'
    "Χ": "X",  # Greek 'Chi' -> Latin 'X'
    "Ε": "E",  # Greek 'Epsilon' -> Latin 'E'
    "Υ": "Y",  # Greek 'Upsilon' -> Latin 'Y'
    "Ο": "O",  # Greek 'Omicron' -> Latin 'O'
    # Common lookalikes for numbers
    "0": "O",  # Zero -> Letter O
    "1": "I",  # One -> Letter I
    "5": "S",  # Five -> Letter S
    "8": "B",  # Eight -> Letter B
    # Additional homoglyphs
    "ɩ": "l",  # Greek iota -> Latin l
    "ι": "l",  # Greek iota -> Latin l
    "ẁ": "w",  # Vietnamese w -> Latin w
    "ẃ": "w",  # Vietnamese w -> Latin w
    "ŵ": "w",  # Latin w -> Latin w
    "ώ": "w",  # Greek omega -> Latin w
    "ҽ": "x",  # Cyrillic x -> Latin x
}

# Reverse mapping for normalization
ASCII_TO_HOMOGLYPH: Dict[str, List[str]] = {}
for homoglyph, ascii_char in HOMOGLYPHS.items():
    if ascii_char not in ASCII_TO_HOMOGLYPH:
        ASCII_TO_HOMOGLYPH[ascii_char] = []
    ASCII_TO_HOMOGLYPH[ascii_char].append(homoglyph)


def detect_homoglyphs(domain: str) -> Tuple[bool, str]:
    """
    Detect if a domain contains homoglyph characters.

    Args:
        domain: Domain name to check

    Returns:
        Tuple of (is_suspicious, normalized_domain)
    """
    if not domain:
        return False, ""

    normalized = ""
    has_homoglyph = False
    homoglyph_chars = []

    for char in domain.lower():
        if char in HOMOGLYPHS:
            normalized += HOMOGLYPHS[char]
            has_homoglyph = True
            homoglyph_chars.append(char)
        else:
            normalized += char

    return has_homoglyph, normalized


def get_homoglyph_details(domain: str) -> Dict[str, any]:
    """
    Get detailed information about homoglyphs in a domain.

    Args:
        domain: Domain name to analyze

    Returns:
        Dictionary with homoglyph analysis details
    """
    if not domain:
        return {
            "is_suspicious": False,
            "normalized": "",
            "original": "",
            "homoglyph_count": 0,
            "homoglyph_positions": [],
            "homoglyph_chars": [],
        }

    original = domain.lower()
    normalized = ""
    homoglyph_positions = []
    homoglyph_chars = []

    for i, char in enumerate(original):
        if char in HOMOGLYPHS:
            normalized += HOMOGLYPHS[char]
            homoglyph_positions.append(i)
            homoglyph_chars.append(char)
        else:
            normalized += char

    return {
        "is_suspicious": len(homoglyph_chars) > 0,
        "normalized": normalized,
        "original": original,
        "homoglyph_count": len(homoglyph_chars),
        "homoglyph_positions": homoglyph_positions,
        "homoglyph_chars": homoglyph_chars,
    }


def is_domain_suspicious(
    domain: str, known_brands: List[str] = None
) -> Tuple[bool, str]:
    """
    Check if a domain is suspicious based on homoglyphs or brand impersonation.

    Args:
        domain: Domain to check
        known_brands: List of known brand domains to check against

    Returns:
        Tuple of (is_suspicious, reason)
    """
    if not domain:
        return False, ""

    domain_lower = domain.lower()

    # Check for homoglyphs
    has_homoglyph, normalized = detect_homoglyphs(domain_lower)
    if has_homoglyph and normalized != domain_lower:
        return (
            True,
            f"Contains homoglyph characters: {', '.join(get_homoglyph_details(domain_lower)['homoglyph_chars'])}",
        )

    # Check against known brands if provided
    if known_brands:
        for brand in known_brands:
            brand_lower = brand.lower()
            # Check if domain is trying to impersonate a known brand
            if brand_lower in domain_lower and brand_lower != domain_lower:
                return True, f"Potential brand impersonation: contains '{brand}'"

            # Check for common brand typosquatting patterns
            if domain_lower.replace(".", "") != brand_lower.replace(".", ""):
                # Levenshtein distance check could be added here
                pass

    return False, ""


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain by replacing homoglyphs with ASCII equivalents.

    Args:
        domain: Domain to normalize

    Returns:
        Normalized domain
    """
    if not domain:
        return ""

    _, normalized = detect_homoglyphs(domain.lower())
    return normalized
