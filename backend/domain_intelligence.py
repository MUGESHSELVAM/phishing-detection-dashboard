import socket
import logging
import os
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

try:
    import whois as _whois
except Exception:
    _whois = None


def analyze_domain(domain: str) -> Dict[str, Any]:
    """Return domain intelligence: WHOIS age, DNS resolution, basic hosting checks.

    This function degrades gracefully if optional dependencies aren't installed.
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "age_days": None,
        "resolved_ips": [],
        "suspicious_score": 0.0,
        "whois_raw": None,
    }

    if not domain:
        return result

    # DNS resolution
    try:
        infos = socket.gethostbyname_ex(domain)
        ips = infos[2]
        result["resolved_ips"] = ips
    except Exception as e:
        logger.debug(f"DNS resolution failed for {domain}: {e}")

    # WHOIS lookup (optional)
    if _whois:
        try:
            w = _whois.whois(domain)
            result["whois_raw"] = dict(w)
            # try to compute age
            creation = w.get("creation_date")
            if creation:
                # creation may be list
                if isinstance(creation, list):
                    creation = creation[0]
                if isinstance(creation, datetime):
                    delta = datetime.utcnow() - creation
                    result["age_days"] = delta.days
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")

    # basic heuristics: if domain resolves but IPs are in private ranges, suspicious
    for ip in result.get("resolved_ips", []):
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
            result["suspicious_score"] += 0.2

    # if no resolved IPs, slightly suspicious
    if not result.get("resolved_ips"):
        result["suspicious_score"] += 0.3

    # clamp
    result["suspicious_score"] = min(max(result["suspicious_score"], 0.0), 1.0)
    return result
