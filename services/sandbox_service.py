"""
SecureScan AI – Sandbox Analysis Service
Submits URLs to urlscan.io for sandboxed browser analysis.
Returns: malware detection, screenshot, domain info, redirects, technologies.
"""

import asyncio
import httpx
from config import URLSCAN_API_KEY


async def scan_url(url: str) -> dict:
    """
    Submit a URL to urlscan.io and retrieve sandbox analysis results.
    Returns a dict with sandbox findings, or empty result if API key missing.
    """
    default_result = {
        "available": False,
        "is_malicious": False,
        "malicious_score": 0,
        "screenshot_url": "",
        "page_title": "",
        "server_ip": "",
        "server_country": "",
        "domain": "",
        "redirects": [],
        "technologies": [],
        "details": "Sandbox analysis not available",
        "score": 0,
    }

    if not URLSCAN_API_KEY:
        default_result["details"] = "urlscan.io API key not configured. Add URLSCAN_API_KEY to .env for sandbox analysis."
        return default_result

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            # Step 1: Submit the URL for scanning
            submit_response = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers={
                    "API-Key": URLSCAN_API_KEY,
                    "Content-Type": "application/json",
                },
                json={
                    "url": url,
                    "visibility": "unlisted",  # Don't make scans public
                },
            )

            if submit_response.status_code == 429:
                default_result["details"] = "Sandbox rate limit reached. Try again later."
                return default_result

            if submit_response.status_code != 200:
                default_result["details"] = f"Sandbox submission failed (HTTP {submit_response.status_code})"
                return default_result

            submit_data = submit_response.json()
            result_uuid = submit_data.get("uuid", "")
            result_url = submit_data.get("api", "")

            if not result_url:
                result_url = f"https://urlscan.io/api/v1/result/{result_uuid}/"

            # Step 2: Poll for results (up to ~24s to capture screenshot)
            max_retries = 8
            for attempt in range(max_retries):
                await asyncio.sleep(3)  # Wait 3 seconds between polls

                result_response = await client.get(result_url)

                if result_response.status_code == 200:
                    data = result_response.json()
                    parsed = _parse_result(data)
                    # Fetch screenshot and convert to base64 (async)
                    raw_ss = parsed.get("screenshot_url", "")
                    if raw_ss and raw_ss.startswith("https://"):
                        try:
                            import base64
                            print(f"[SANDBOX] Fetching screenshot: {raw_ss}")
                            ss_resp = await client.get(raw_ss, follow_redirects=True)
                            print(f"[SANDBOX] Screenshot status: {ss_resp.status_code}, size: {len(ss_resp.content)}")
                            if ss_resp.status_code == 200:
                                ct = ss_resp.headers.get("content-type", "image/png")
                                b64 = base64.b64encode(ss_resp.content).decode("utf-8")
                                parsed["screenshot_url"] = f"data:{ct};base64,{b64}"
                                print(f"[SANDBOX] Base64 encoded! Length: {len(parsed['screenshot_url'])}")
                            else:
                                print(f"[SANDBOX] Screenshot fetch failed: {ss_resp.status_code}")
                        except Exception as e:
                            print(f"[SANDBOX] Screenshot error: {e}")
                    return parsed
                elif result_response.status_code == 404:
                    # Still processing
                    continue
                else:
                    break

            default_result["details"] = "Sandbox analysis timed out. The URL may take longer to analyze."
            default_result["available"] = True
            return default_result

    except httpx.TimeoutException:
        default_result["details"] = "Sandbox analysis timed out."
        return default_result
    except Exception as e:
        default_result["details"] = f"Sandbox analysis error: {str(e)}"
        return default_result


def _parse_result(data: dict) -> dict:
    """Parse urlscan.io result into our format."""
    verdicts = data.get("verdicts", {})
    page = data.get("page", {})
    lists = data.get("lists", {})
    task = data.get("task", {})
    stats = data.get("stats", {})

    # Overall malicious verdict
    overall = verdicts.get("overall", {})
    is_malicious = overall.get("malicious", False)
    malicious_score = overall.get("score", 0)

    # Get categories/brands detected
    categories = overall.get("categories", [])
    brands = overall.get("brands", [])

    # Technologies from the page
    technologies = []
    for tech in lists.get("technologies", []):
        if isinstance(tech, dict):
            technologies.append(tech.get("app", str(tech)))
        else:
            technologies.append(str(tech))

    # Redirect chain
    redirects = []
    for redirect in lists.get("urls", [])[:5]:  # Limit to 5
        if isinstance(redirect, str):
            redirects.append(redirect)

    # Build detailed description
    details_parts = []
    if is_malicious:
        details_parts.append(f"⚠ MALICIOUS - Sandbox detected threats (score: {malicious_score})")
    else:
        details_parts.append("✓ No malware detected in sandbox")

    if categories:
        details_parts.append(f"Categories: {', '.join(categories)}")
    if brands:
        details_parts.append(f"Impersonated brands: {', '.join([b.get('name', str(b)) if isinstance(b, dict) else str(b) for b in brands])}")

    return {
        "available": True,
        "is_malicious": is_malicious,
        "malicious_score": malicious_score,
        "screenshot_url": task.get("screenshotURL", ""),
        "page_title": page.get("title", ""),
        "server_ip": page.get("ip", ""),
        "server_country": page.get("country", ""),
        "domain": page.get("domain", ""),
        "redirects": redirects,
        "technologies": technologies[:10],  # Limit to 10
        "categories": categories,
        "brands": [b.get("name", str(b)) if isinstance(b, dict) else str(b) for b in brands],
        "details": " | ".join(details_parts),
        "score": min(malicious_score * 10, 100) if is_malicious else 0,
    }

