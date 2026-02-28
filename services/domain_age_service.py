"""
SecureScan AI – Domain Age Service
Uses python-whois to look up domain registration date and calculate age.
Now async to avoid blocking the event loop.
"""

import asyncio
import whois
from urllib.parse import urlparse
from datetime import datetime

_DEFAULT_RESULT = {
    "domain_age_days": -1,
    "registration_date": "",
    "registrar": "",
    "is_new_domain": False,
}


def _whois_lookup_sync(url: str) -> dict:
    """Synchronous WHOIS lookup (runs in thread pool)."""
    result = dict(_DEFAULT_RESULT)

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

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


async def get_domain_age(url: str) -> dict:
    """
    Async WHOIS lookup — runs in a thread pool with a 5s timeout
    so it never blocks the event loop or delays the response.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_whois_lookup_sync, url),
            timeout=5.0,
        )
    except asyncio.TimeoutError:
        print(f"[WHOIS] Timed out after 5s for {url}")
        return dict(_DEFAULT_RESULT)
    except Exception as e:
        print(f"[WHOIS] Error looking up domain: {e}")
        return dict(_DEFAULT_RESULT)
