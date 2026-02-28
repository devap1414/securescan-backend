"""
SecureScan AI – Heuristic URL Analyzer
Performs pattern-based analysis: HTTPS checks, typosquatting detection,
suspicious TLDs, URL shorteners, IP-based URLs, keyword analysis.
"""

import re
from urllib.parse import urlparse
from Levenshtein import distance as levenshtein_distance
from config import (
    POPULAR_DOMAINS,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
    URL_SHORTENERS,
)


def analyze_url(url: str) -> dict:
    """
    Run all heuristic checks on a URL.
    Returns: {
        "flags": [{"title": str, "description": str, "severity": str, "points": float}],
        "score": float (0-100),
    }
    """
    flags = []
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    full_url = url.lower()

    # --- 1. HTTPS Check ---
    if parsed.scheme != "https":
        flags.append({
            "title": "No HTTPS",
            "description": f"This URL uses '{parsed.scheme}://' instead of secure 'https://'. Data sent to this site is not encrypted.",
            "severity": "medium",
            "points": 15,
        })

    # --- 2. IP-based URL ---
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if hostname and ip_pattern.match(hostname):
        flags.append({
            "title": "IP Address URL",
            "description": f"URL uses raw IP address ({hostname}) instead of a domain name. Legitimate sites rarely do this.",
            "severity": "high",
            "points": 25,
        })

    # --- 2b. Numeric Domain Detection ---
    # Flag domains like "75.55.co" that use numbers to look like IPs
    if hostname:
        domain_parts = hostname.split(".")
        main_part = domain_parts[0] if domain_parts else ""
        # Check if the main domain part is mostly numeric
        digit_count = sum(1 for c in main_part if c.isdigit())
        if len(main_part) > 0 and digit_count / len(main_part) >= 0.5:
            flags.append({
                "title": "Numeric Domain Name",
                "description": f"Domain '{hostname}' uses mostly numbers, which is unusual for legitimate websites and often indicates phishing or malware.",
                "severity": "high",
                "points": 20,
            })

    # --- 2c. Ultra-Short Domain ---
    if hostname:
        domain_name = hostname.split(".")[0] if hostname.split(".") else ""
        if 0 < len(domain_name) <= 3:
            flags.append({
                "title": "Suspiciously Short Domain",
                "description": f"Domain name '{domain_name}' is unusually short ({len(domain_name)} chars). Short domains are often used for redirection or phishing.",
                "severity": "medium",
                "points": 15,
            })

    # --- 3. Typosquatting Detection ---
    if hostname:
        domain_parts = hostname.split(".")
        # Get the main domain (e.g., "g00gle" from "g00gle-login.tk")
        main_domain = domain_parts[0] if len(domain_parts) > 0 else ""
        # Also check without hyphens
        clean_domain = main_domain.replace("-", "").replace("_", "")

        for popular in POPULAR_DOMAINS:
            popular_base = popular.split(".")[0]
            # Check Levenshtein distance
            dist = min(
                levenshtein_distance(clean_domain, popular_base),
                levenshtein_distance(main_domain, popular_base),
            )
            # Flag if very similar but not exact match
            if 0 < dist <= 2 and hostname != popular:
                flags.append({
                    "title": "Typosquatting Detected",
                    "description": f"Domain '{hostname}' looks suspiciously similar to '{popular}' (edit distance: {dist}). This is a common phishing technique.",
                    "severity": "high",
                    "points": 30,
                })
                break
            # Also check for character substitution (0 for o, 1 for l, etc.)
            if dist == 0 and hostname != popular:
                flags.append({
                    "title": "Domain Impersonation",
                    "description": f"Domain '{hostname}' appears to impersonate '{popular}'.",
                    "severity": "high",
                    "points": 30,
                })
                break

    # --- 4. Suspicious TLD ---
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append({
                "title": "Suspicious Domain Extension",
                "description": f"The domain uses '{tld}' which is frequently associated with malicious websites.",
                "severity": "medium",
                "points": 15,
            })
            break

    # --- 5. URL Shortener ---
    for shortener in URL_SHORTENERS:
        if hostname == shortener or hostname.endswith(f".{shortener}"):
            flags.append({
                "title": "URL Shortener Detected",
                "description": f"This URL uses a shortening service ({shortener}). The actual destination is hidden and could be malicious.",
                "severity": "medium",
                "points": 10,
            })
            break

    # --- 6. Suspicious Keywords in URL ---
    high_confidence_keywords = {"phishing", "malware"}
    found_keywords = []
    found_high_confidence = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full_url:
            if kw in high_confidence_keywords:
                found_high_confidence.append(kw)
            else:
                found_keywords.append(kw)

    if found_high_confidence:
        points = min(len(found_high_confidence) * 25, 40)
        flags.append({
            "title": "Phishing/Malware Keywords in URL",
            "description": f"URL contains high-risk keywords: {', '.join(found_high_confidence)}. This is a strong indicator of a malicious site.",
            "severity": "high",
            "points": points,
        })

    if found_keywords:
        severity = "high" if len(found_keywords) >= 3 else "medium"
        points = min(len(found_keywords) * 5, 20)
        flags.append({
            "title": "Suspicious Keywords in URL",
            "description": f"URL contains suspicious keywords often used in phishing: {', '.join(found_keywords)}",
            "severity": severity,
            "points": points,
        })

    # --- 7. Excessive URL Length ---
    if len(url) > 100:
        flags.append({
            "title": "Unusually Long URL",
            "description": f"URL is {len(url)} characters long. Extremely long URLs can be used to hide the true destination.",
            "severity": "low",
            "points": 5,
        })

    # --- 8. Many Subdomains ---
    if hostname:
        subdomain_count = len(hostname.split(".")) - 2  # Subtract domain + TLD
        if subdomain_count >= 3:
            flags.append({
                "title": "Excessive Subdomains",
                "description": f"URL has {subdomain_count} subdomains, which can be used to create misleading URLs (e.g., 'login.google.com.evil.com').",
                "severity": "medium",
                "points": 15,
            })

    # --- 9. Special Characters in Domain ---
    if hostname and re.search(r"[@!#$%^&*]", hostname):
        flags.append({
            "title": "Special Characters in Domain",
            "description": "Domain contains unusual special characters that are atypical for legitimate websites.",
            "severity": "medium",
            "points": 15,
        })

    # --- 10. Suspicious Path Patterns ---
    if re.search(r"\.(exe|zip|rar|bat|cmd|msi|scr|js|vbs|ps1)$", path, re.IGNORECASE):
        flags.append({
            "title": "Direct File Download",
            "description": "URL points directly to a potentially dangerous file download.",
            "severity": "high",
            "points": 25,
        })

    # Calculate total score (capped at 100)
    total_score = min(sum(f["points"] for f in flags), 100)

    return {
        "flags": flags,
        "score": total_score,
    }
