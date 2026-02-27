"""
SecureScan AI – Domain Age Service
Uses python-whois to look up domain registration date and calculate age.
"""

import whois
from urllib.parse import urlparse
from datetime import datetime


def get_domain_age(url: str) -> dict:
    """
    Look up WHOIS data for a URL's domain and return age info.
    Returns dict with domain_age_days, registration_date, and registrar.
    """
    result = {
        "domain_age_days": -1,       # -1 means unknown
        "registration_date": "",
        "registrar": "",
        "is_new_domain": False,      # True if < 90 days old
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove port and www
        domain = domain.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        if not domain or "." not in domain:
            return result

        w = whois.whois(domain)

        # Get creation date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date and isinstance(creation_date, datetime):
            # Strip timezone info to avoid naive/aware mismatch
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age_days = (datetime.now() - creation_date).days
            result["domain_age_days"] = age_days
            result["registration_date"] = creation_date.strftime("%Y-%m-%d")
            result["is_new_domain"] = age_days < 90

        # Get registrar
        registrar = w.registrar
        if registrar:
            if isinstance(registrar, list):
                registrar = registrar[0]
            result["registrar"] = str(registrar)

    except Exception as e:
        print(f"[WHOIS] Error looking up domain: {e}")

    return result
