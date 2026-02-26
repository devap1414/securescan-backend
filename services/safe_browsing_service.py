"""
SecureScan AI – Google Safe Browsing API Service
Checks URLs against Google's threat lists (malware, phishing, social engineering).
"""

import httpx
from config import SAFE_BROWSING_API_KEY


SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_url(url: str) -> dict:
    """
    Check a URL against Google Safe Browsing API.
    Returns: {
        "is_threat": bool,
        "threats": [str],
        "score": float (0-100),
        "details": str,
    }
    """
    if not SAFE_BROWSING_API_KEY:
        return {
            "is_threat": False,
            "threats": [],
            "score": 0.0,
            "details": "Safe Browsing API key not configured",
        }

    payload = {
        "client": {
            "clientId": "securescan-ai",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                SB_URL,
                params={"key": SAFE_BROWSING_API_KEY},
                json=payload,
            )

            if resp.status_code != 200:
                return {
                    "is_threat": False,
                    "threats": [],
                    "score": 0.0,
                    "details": f"Safe Browsing API error: {resp.status_code}",
                }

            data = resp.json()
            matches = data.get("matches", [])

            if not matches:
                return {
                    "is_threat": False,
                    "threats": [],
                    "score": 0.0,
                    "details": "No threats found in Google Safe Browsing database",
                }

            # Extract threat types
            threat_types = list(set(m.get("threatType", "UNKNOWN") for m in matches))
            threat_labels = {
                "MALWARE": "Malware",
                "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
                "UNWANTED_SOFTWARE": "Unwanted Software",
                "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful App",
            }
            threats = [threat_labels.get(t, t) for t in threat_types]

            # Score based on threat severity
            severity_scores = {
                "MALWARE": 100,
                "SOCIAL_ENGINEERING": 90,
                "UNWANTED_SOFTWARE": 70,
                "POTENTIALLY_HARMFUL_APPLICATION": 60,
            }
            score = max(severity_scores.get(t, 50) for t in threat_types)

            return {
                "is_threat": True,
                "threats": threats,
                "score": float(score),
                "details": f"Found in Google Safe Browsing: {', '.join(threats)}",
            }

    except httpx.TimeoutException:
        return {
            "is_threat": False,
            "threats": [],
            "score": 0.0,
            "details": "Safe Browsing request timed out",
        }
    except Exception as e:
        return {
            "is_threat": False,
            "threats": [],
            "score": 0.0,
            "details": f"Safe Browsing error: {str(e)}",
        }
