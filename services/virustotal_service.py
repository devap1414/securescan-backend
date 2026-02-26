"""
SecureScan AI – VirusTotal API Service
Submits URLs and retrieves threat analysis results via VirusTotal API v3.
"""

import base64
import httpx
from config import VIRUSTOTAL_API_KEY


VT_BASE = "https://www.virustotal.com/api/v3"


async def analyze_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal and return analysis summary.
    Returns: {
        "positives": int,
        "total": int,
        "threats": [str],
        "score": float (0-100),
        "details": str,
    }
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "positives": 0,
            "total": 0,
            "threats": [],
            "score": 0.0,
            "details": "VirusTotal API key not configured",
        }

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # URL-safe base64 encode the URL (VirusTotal API v3 requirement)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        async with httpx.AsyncClient(timeout=30.0) as client:
            # First, try to get existing analysis
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)

            if resp.status_code == 404:
                # URL not in VirusTotal DB — submit for scanning
                submit_resp = await client.post(
                    f"{VT_BASE}/urls",
                    headers=headers,
                    data={"url": url},
                )
                if submit_resp.status_code != 200:
                    return {
                        "positives": 0,
                        "total": 0,
                        "threats": [],
                        "score": 0.0,
                        "details": f"VirusTotal submission failed: {submit_resp.status_code}",
                    }
                # Re-fetch analysis
                resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)

            if resp.status_code != 200:
                return {
                    "positives": 0,
                    "total": 0,
                    "threats": [],
                    "score": 0.0,
                    "details": f"VirusTotal lookup failed: {resp.status_code}",
                }

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            threats = []

            # Collect threat names from detailed results
            results = attrs.get("last_analysis_results", {})
            for engine_name, result in results.items():
                if result.get("category") in ("malicious", "suspicious"):
                    threat = result.get("result", "Unknown threat")
                    threats.append(f"{engine_name}: {threat}")

            # Calculate score (0-100)
            if total > 0:
                detection_rate = positives / total
                score = min(detection_rate * 100 * 5, 100)  # Amplify: 20% detection = 100 score
            else:
                score = 0.0

            return {
                "positives": positives,
                "total": total,
                "threats": threats[:10],  # Cap at 10 for readability
                "score": round(score, 1),
                "details": f"{positives}/{total} security vendors flagged this URL",
            }

    except httpx.TimeoutException:
        return {
            "positives": 0,
            "total": 0,
            "threats": [],
            "score": 0.0,
            "details": "VirusTotal request timed out",
        }
    except Exception as e:
        return {
            "positives": 0,
            "total": 0,
            "threats": [],
            "score": 0.0,
            "details": f"VirusTotal error: {str(e)}",
        }
