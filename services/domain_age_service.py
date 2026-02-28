"""
SecureScan AI – Domain Age Service
Uses python-whois to look up domain registration date and calculate age.
Falls back to RDAP (modern WHOIS replacement) when python-whois fails.
"""

import asyncio
import whois
import httpx
from urllib.parse import urlparse
from datetime import datetime

_DEFAULT_RESULT = {
    "domain_age_days": -1,
    "registration_date": "",
    "registrar": "",
    "is_new_domain": False,
}

# Reusable HTTP client for RDAP fallback
_rdap_client = httpx.AsyncClient(timeout=10.0)


def _extract_domain(url: str) -> str:
    """Extract the registrable domain from a URL."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _whois_lookup_sync(url: str) -> dict:
    """Synchronous WHOIS lookup (runs in thread pool)."""
    result = dict(_DEFAULT_RESULT)

    domain = _extract_domain(url)
    if not domain or "." not in domain:
        return result

    w = whois.whois(domain)

    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if creation_date and isinstance(creation_date, datetime):
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)
        age_days = (datetime.now() - creation_date).days
        result["domain_age_days"] = age_days
        result["registration_date"] = creation_date.strftime("%Y-%m-%d")
        result["is_new_domain"] = age_days < 90

    registrar = w.registrar
    if registrar:
        if isinstance(registrar, list):
            registrar = registrar[0]
        result["registrar"] = str(registrar)

    return result


async def _rdap_lookup(url: str) -> dict:
    """Fallback: look up domain via RDAP (modern, faster WHOIS replacement)."""
    result = dict(_DEFAULT_RESULT)

    domain = _extract_domain(url)
    if not domain or "." not in domain:
        return result

    try:
        resp = await _rdap_client.get(
            f"https://rdap.org/domain/{domain}",
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return result

        data = resp.json()

        # Parse events for registration date
        events = data.get("events", [])
        for event in events:
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate", "")
                if date_str:
                    # Parse ISO format date
                    creation_date = datetime.fromisoformat(
                        date_str.replace("Z", "+00:00")
                    ).replace(tzinfo=None)
                    age_days = (datetime.now() - creation_date).days
                    result["domain_age_days"] = age_days
                    result["registration_date"] = creation_date.strftime("%Y-%m-%d")
                    result["is_new_domain"] = age_days < 90
                    break

        # Parse registrar from entities
        entities = data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            result["registrar"] = item[3]
                            break
                # Also try handle as registrar name
                if not result["registrar"]:
                    result["registrar"] = entity.get("handle", "")
                break

    except Exception as e:
        print(f"[RDAP] Error: {e}")

    return result


async def get_domain_age(url: str) -> dict:
    """
    Async domain age lookup — tries WHOIS first (8s timeout),
    then falls back to RDAP if WHOIS fails or times out.
    """
    # Try WHOIS first
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_whois_lookup_sync, url),
            timeout=8.0,
        )
        if result["domain_age_days"] >= 0:
            return result
    except asyncio.TimeoutError:
        print(f"[WHOIS] Timed out after 8s for {url}, trying RDAP fallback...")
    except Exception as e:
        print(f"[WHOIS] Error: {e}, trying RDAP fallback...")

    # Fallback to RDAP
    try:
        result = await asyncio.wait_for(
            _rdap_lookup(url),
            timeout=8.0,
        )
        if result["domain_age_days"] >= 0:
            print(f"[RDAP] Successfully got domain age via RDAP fallback")
            return result
    except asyncio.TimeoutError:
        print(f"[RDAP] Timed out after 8s for {url}")
    except Exception as e:
        print(f"[RDAP] Error: {e}")

    return dict(_DEFAULT_RESULT)
