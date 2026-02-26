"""
SecureScan AI – Backend Configuration
Loads API keys from environment variables.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# --- API Keys ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

# --- Risk Score Weights ---
WEIGHT_VIRUSTOTAL = 0.40
WEIGHT_SAFE_BROWSING = 0.35
WEIGHT_HEURISTIC = 0.60  # Higher weight so heuristics alone can flag threats

# --- Thresholds ---
SAFE_THRESHOLD = 15          # score <= 15 → Safe
SUSPICIOUS_THRESHOLD = 45    # score <= 45 → Suspicious, else Dangerous

# --- Heuristic Config ---
POPULAR_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "netflix.com", "instagram.com",
    "twitter.com", "linkedin.com", "whatsapp.com", "youtube.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
    "dropbox.com", "github.com", "yahoo.com", "outlook.com",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".buzz", ".work", ".click", ".link", ".info", ".site",
    ".online", ".icu", ".club", ".space", ".fun", ".co", ".ru",
    ".cn", ".ws", ".biz", ".surf", ".rest", ".monster",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "signin", "suspend", "alert", "urgent",
    "wallet", "prize", "winner", "free", "claim", "reward",
    "unauthorized", "expire", "limited",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
]
