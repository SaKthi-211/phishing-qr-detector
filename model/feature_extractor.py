"""
feature_extractor.py
---------------------
This module extracts lexical and heuristic features from a URL.
It is used identically by both the training script and the live Flask
app (so the features used during training and prediction always match -
this is critical, otherwise model accuracy would drop).

All feature extraction is purely offline - it only analyzes the URL
string itself and never makes a live network request (fast + reliable).
"""

import re
from urllib.parse import urlparse

# Commonly used URL shortening services - phishing links frequently use
# these to hide the real destination domain.
SHORTENER_SERVICES = [
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc", "rb.gy"
]

# Keywords that frequently appear on phishing pages (used to spoof
# login/verification pages).
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "banking", "confirm",
    "signin", "webscr", "ebayisapi", "password", "pay", "billing",
    "suspend", "unlock", "recover", "wallet", "authenticate", "security"
]

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bankofamerica", "instagram", "whatsapp", "flipkart"
]


def _has_ip_address(hostname: str) -> int:
    """Checks if a raw IP address is used instead of a domain name
    (e.g. http://192.168.1.1/login) - this is a strong phishing signal."""
    if hostname is None:
        return 0
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return 1 if re.match(ipv4_pattern, hostname) else 0


def _count_char(text: str, char: str) -> int:
    return text.count(char)


def _is_shortened(hostname: str) -> int:
    if hostname is None:
        return 0
    return 1 if any(service in hostname for service in SHORTENER_SERVICES) else 0


def _has_suspicious_keyword(url: str) -> int:
    url_lower = url.lower()
    return 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0


def _brand_in_subdomain_or_path(url: str, hostname: str) -> int:
    """Detects when a brand name (paypal, amazon, etc.) appears only in
    the subdomain/path and not in the actual registered domain - this is
    a typical brand-impersonation phishing pattern.
    Example: paypal-secure-login.verify-account.com"""
    url_lower = url.lower()
    if hostname is None:
        return 0
    for brand in BRAND_KEYWORDS:
        if brand in url_lower:
            # check whether the brand name exactly matches the root domain
            registered_domain = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
            if brand not in registered_domain:
                return 1
    return 0


def extract_features(url: str) -> dict:
    """Takes a URL and returns a dict of numeric features for the ML
    model. This is the core logic of the entire system."""

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        # add a scheme if missing before parsing (keeps heuristics consistent)
        parsed_url = "http://" + url
    else:
        parsed_url = url

    parsed = urlparse(parsed_url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "count_dots": _count_char(url, "."),
        "count_hyphens": _count_char(hostname, "-"),
        "count_at": _count_char(url, "@"),
        "count_question_mark": _count_char(url, "?"),
        "count_underscore": _count_char(url, "_"),
        "count_percent": _count_char(url, "%"),
        "count_equal": _count_char(url, "="),
        "count_digits": sum(c.isdigit() for c in url),
        "count_subdomains": max(hostname.count(".") - 1, 0),
        "has_ip_address": _has_ip_address(hostname),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "is_shortened": _is_shortened(hostname),
        "has_double_slash_redirect": 1 if url.rfind("//") > 7 else 0,
        "has_suspicious_keyword": _has_suspicious_keyword(url),
        "brand_impersonation": _brand_in_subdomain_or_path(url, hostname),
        "has_port": 1 if parsed.port else 0,
        "tld_suspicious": 1 if hostname.split(".")[-1] in
        {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "loan"} else 0,
    }
    return features


FEATURE_ORDER = [
    "url_length", "hostname_length", "path_length", "count_dots",
    "count_hyphens", "count_at", "count_question_mark", "count_underscore",
    "count_percent", "count_equal", "count_digits", "count_subdomains",
    "has_ip_address", "has_https", "is_shortened", "has_double_slash_redirect",
    "has_suspicious_keyword", "brand_impersonation", "has_port", "tld_suspicious"
]


def features_to_vector(features: dict) -> list:
    """Converts the feature dict into a consistently ordered vector
    (for model.predict)."""
    return [features[f] for f in FEATURE_ORDER]
