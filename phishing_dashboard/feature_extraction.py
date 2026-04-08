"""
feature_extraction.py — URL Feature Extraction Module
Phishing Detection Dashboard

Extracts 38 lexical, structural, entropy, and WHOIS-based
features from a given URL for ML-based detection.
"""
import re
import math
import socket
import logging
import urllib.parse
from datetime import datetime, timezone
from collections import Counter

logger = logging.getLogger(__name__)


# ─── Suspicious keyword lists ───────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "paypal", "ebay", "amazon", "apple", "microsoft",
    "password", "confirm", "suspend", "unusual", "activity",
    "click", "free", "winner", "congratulation", "prize",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".club", ".online", ".site", ".live", ".buzz",
]

SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "cutt.ly", "short.io",
]


# ─── Helpers ────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _count_special(s: str, chars: str) -> int:
    return sum(s.count(c) for c in chars)


# ─── Main extractor ─────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract 32 numerical features from a URL.

    Returns
    -------
    dict  feature_name → numeric value
    """
    features = {}

    # Normalize
    raw = url.strip()
    url_lower = raw.lower()
    if not url_lower.startswith(("http://", "https://")):
        url_lower = "http://" + url_lower
        raw = "http://" + raw

    # Parse
    try:
        parsed = urllib.parse.urlparse(url_lower)
        scheme = parsed.scheme or ""
        netloc = parsed.netloc or ""
        path   = parsed.path or ""
        query  = parsed.query or ""
        fragment = parsed.fragment or ""
    except Exception:
        parsed = None
        scheme = netloc = path = query = fragment = ""

    # Strip port from netloc for hostname
    hostname = netloc.split(":")[0] if netloc else ""
    tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    # ── 1. URL length ───────────────────────────────────────────────────────
    features["url_length"] = len(raw)

    # ── 2. Hostname length ──────────────────────────────────────────────────
    features["hostname_length"] = len(hostname)

    # ── 3. Path length ──────────────────────────────────────────────────────
    features["path_length"] = len(path)

    # ── 4. Query length ─────────────────────────────────────────────────────
    features["query_length"] = len(query)

    # ── 5. Number of dots in URL ────────────────────────────────────────────
    features["count_dots"] = raw.count(".")

    # ── 6. Number of hyphens ────────────────────────────────────────────────
    features["count_hyphens"] = raw.count("-")

    # ── 7. Number of underscores ────────────────────────────────────────────
    features["count_underscores"] = raw.count("_")

    # ── 8. Number of slashes ────────────────────────────────────────────────
    features["count_slashes"] = raw.count("/")

    # ── 9. Number of @ symbols ──────────────────────────────────────────────
    features["count_at"] = raw.count("@")

    # ── 10. Number of ? symbols ─────────────────────────────────────────────
    features["count_question"] = raw.count("?")

    # ── 11. Number of = symbols ─────────────────────────────────────────────
    features["count_equals"] = raw.count("=")

    # ── 12. Number of & symbols ─────────────────────────────────────────────
    features["count_ampersand"] = raw.count("&")

    # ── 13. Number of % (encoded chars) ─────────────────────────────────────
    features["count_percent"] = raw.count("%")

    # ── 14. Number of digits in URL ─────────────────────────────────────────
    features["count_digits"] = sum(c.isdigit() for c in raw)

    # ── 15. Number of letters in URL ────────────────────────────────────────
    features["count_letters"] = sum(c.isalpha() for c in raw)

    # ── 16. Ratio digits / URL length ───────────────────────────────────────
    features["digit_ratio"] = features["count_digits"] / max(len(raw), 1)

    # ── 17. HTTPS used? ──────────────────────────────────────────────────────
    features["is_https"] = 1 if scheme == "https" else 0

    # ── 18. IP address as hostname? ─────────────────────────────────────────
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$|"
        r"^\[?[0-9a-fA-F:]+\]?$"
    )
    features["has_ip"] = 1 if ip_pattern.match(hostname) else 0

    # ── 19. Port in URL? ────────────────────────────────────────────────────
    features["has_port"] = 1 if ":" in netloc else 0

    # ── 20. Number of subdomains ────────────────────────────────────────────
    parts = hostname.split(".")
    features["subdomain_count"] = max(len(parts) - 2, 0)

    # ── 21. Phishing keyword in URL? ────────────────────────────────────────
    features["has_phish_keyword"] = int(
        any(kw in url_lower for kw in PHISHING_KEYWORDS)
    )

    # ── 22. Suspicious TLD? ─────────────────────────────────────────────────
    features["suspicious_tld"] = int(tld in SUSPICIOUS_TLDS)

    # ── 23. URL shortening service? ─────────────────────────────────────────
    features["is_shortened"] = int(
        any(svc in hostname for svc in SHORTENING_SERVICES)
    )

    # ── 24. Double slash in path? ───────────────────────────────────────────
    features["double_slash_in_path"] = int("//" in path)

    # ── 25. Hyphen in domain? ───────────────────────────────────────────────
    features["hyphen_in_domain"] = int("-" in hostname)

    # ── 26. Shannon entropy of hostname ─────────────────────────────────────
    features["entropy_hostname"] = round(_entropy(hostname), 4)

    # ── 27. Shannon entropy of path ─────────────────────────────────────────
    features["entropy_path"] = round(_entropy(path), 4)

    # ── 28. Number of query parameters ──────────────────────────────────────
    features["query_param_count"] = len(urllib.parse.parse_qs(query))

    # ── 29. Fragment in URL? ────────────────────────────────────────────────
    features["has_fragment"] = 1 if fragment else 0

    # ── 30. Number of dots in hostname ──────────────────────────────────────
    features["dots_in_hostname"] = hostname.count(".")

    # ── 31. Digit-only subdomain? ───────────────────────────────────────────
    sub = ".".join(parts[:-2]) if len(parts) > 2 else ""
    features["digit_only_subdomain"] = int(bool(sub) and sub.replace(".", "").isdigit())

    # ── 32. Special character density ───────────────────────────────────────
    special = _count_special(raw, "!#$%^*(){}[]|\\<>")
    features["special_char_density"] = round(special / max(len(raw), 1), 4)

    # ── 33–38. WHOIS / DNS enrichment ───────────────────────────────────────
    whois_feats = get_whois_features(hostname)
    features.update(whois_feats)

    return features


# ─── WHOIS feature block ─────────────────────────────────────────────────────

def get_whois_features(hostname: str) -> dict:
    """
    Query WHOIS for domain registration metadata.
    Returns 6 features; all default to safe/unknown values on failure
    so the ML pipeline never receives NaN.

    Features
    --------
    domain_age_days   : days since domain was registered (-1 = unknown)
    is_new_domain     : 1 if domain younger than NEW_DOMAIN_THRESHOLD days
    whois_available   : 1 if WHOIS data was retrievable
    domain_country    : numeric hash of registrar country (0 = unknown)
    has_privacy_guard : 1 if registrant is hidden by a privacy service
    dns_resolves      : 1 if hostname resolves to at least one IP
    """
    from config import config

    feats = {
        "domain_age_days":   -1,
        "is_new_domain":      0,
        "whois_available":    0,
        "domain_country":     0,
        "has_privacy_guard":  0,
        "dns_resolves":       0,
    }

    if not hostname or hostname.replace(".", "").isdigit():
        return feats   # IP address — skip WHOIS

    # ── DNS resolution check ─────────────────────────────────────────────────
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname(hostname)
        feats["dns_resolves"] = 1
    except Exception:
        feats["dns_resolves"] = 0

    # ── WHOIS lookup ─────────────────────────────────────────────────────────
    try:
        import whois                          # python-whois
        import signal

        def _timeout_handler(signum, frame):
            raise TimeoutError()

        try:
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(config.WHOIS_TIMEOUT)
        except (AttributeError, OSError):
            pass                              # SIGALRM not available on Windows

        try:
            w = whois.whois(hostname)
        finally:
            try:
                signal.alarm(0)
            except (AttributeError, OSError):
                pass

        if w:
            feats["whois_available"] = 1

            # Domain age
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - created).days
                feats["domain_age_days"] = max(age, 0)
                feats["is_new_domain"] = int(age < config.NEW_DOMAIN_THRESHOLD)

            # Country (hashed to a small int so it's ordinal)
            country = (w.country or "").strip().upper()
            feats["domain_country"] = abs(hash(country)) % 256 if country else 0

            # Privacy guard detection
            registrant = " ".join([
                str(w.registrant_name or ""),
                str(w.org or ""),
                str(w.emails or ""),
            ]).lower()
            privacy_keywords = [
                "privacy", "protect", "proxy", "guard",
                "whoisguard", "redacted", "withheld",
            ]
            feats["has_privacy_guard"] = int(
                any(kw in registrant for kw in privacy_keywords)
            )

    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", hostname, exc)

    return feats


def get_feature_names() -> list:
    """Return ordered list of feature names (matches model training order)."""
    sample = extract_features("http://example.com")
    return list(sample.keys())
