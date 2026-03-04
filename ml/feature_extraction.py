import re
import ipaddress
from urllib.parse import urlparse

# feature extraction functions reused from original app but in standalone form

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan", ".work"}


def get_tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""


def is_ip_address(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def count_subdomains(domain: str) -> int:
    return max(0, domain.count(".") - 1)


def extract_features(url: str) -> dict:
    """Return a dictionary of numerical features for the given URL."""
    normalized = url.strip()
    if not normalized.startswith(("http://", "https://")):
        normalized = "http://" + normalized
    domain = extract_domain(normalized)

    features = {}
    features["url_length"] = len(normalized)
    features["has_at_symbol"] = "@" in normalized
    features["num_dots"] = normalized.count(".")
    features["has_https"] = normalized.startswith("https")
    features["contains_ip"] = is_ip_address(domain)
    features["subdomain_count"] = count_subdomains(domain)

    # suspicious keywords
    keywords = ["login", "verify", "secure", "account", "update", "bank", "paypal", "confirm"]
    for kw in keywords:
        features[f"keyword_{kw}"] = kw in normalized.lower()

    # other structural features
    features["has_at_symbol"] = "@" in normalized
    features["tld_suspicious"] = get_tld(domain) in SUSPICIOUS_TLDS

    return features


def vectorize_url_list(urls: list) -> list:
    """Convert a list of URLs into a list of feature dicts suitable for ML."""
    return [extract_features(u) for u in urls]
