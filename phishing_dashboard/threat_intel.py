"""
threat_intel.py — Threat Intelligence Layer
Phishing Detection Dashboard

Queries external threat intelligence APIs as a second-opinion layer
alongside the local ML model:

  • VirusTotal v3 URL scan
  • Google Safe Browsing v4 lookup

Both are optional. If API keys are not configured, the functions return
a structured "unavailable" response instead of raising exceptions so the
core scan pipeline is never blocked by a missing key.

Setup:
    export VT_API_KEY="your-virustotal-api-key"
    export GSB_API_KEY="your-google-safe-browsing-api-key"
"""
import base64
import json
import logging
import hashlib
import time
import requests
from urllib.parse import urlparse

from config import config

logger = logging.getLogger(__name__)


# ─── VirusTotal ───────────────────────────────────────────────────────────────

VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_url_id(url: str) -> str:
    """VirusTotal URL identifier: URL-safe base64 of the URL, no padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check_virustotal(url: str) -> dict:
    """
    Query VirusTotal for an existing URL analysis.

    Returns
    -------
    dict with keys:
        available     : bool   — True if API key configured and call succeeded
        malicious     : int    — engines that flagged as malicious
        suspicious    : int    — engines that flagged as suspicious
        harmless      : int    — engines that flagged as harmless
        total_engines : int    — total engines that returned a verdict
        vt_verdict    : str    — 'malicious' | 'suspicious' | 'clean' | 'unknown'
        vt_score      : float  — 0–100 danger score (malicious/total * 100)
        permalink     : str    — link to full VT report
        error         : str    — error message if call failed
    """
    result = {
        "available":     False,
        "malicious":     0,
        "suspicious":    0,
        "harmless":      0,
        "total_engines": 0,
        "vt_verdict":    "unknown",
        "vt_score":      0.0,
        "permalink":     "",
        "error":         "",
    }

    api_key = config.VIRUSTOTAL_API_KEY
    if not api_key:
        result["error"] = "VirusTotal API key not configured (set VT_API_KEY)."
        return result

    url_id  = _vt_url_id(url)
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        resp = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers=headers,
            timeout=config.THREAT_INTEL_TIMEOUT,
        )

        # If URL not yet analyzed, submit it
        if resp.status_code == 404:
            submit = requests.post(
                f"{VT_BASE}/urls",
                headers=headers,
                data={"url": url},
                timeout=config.THREAT_INTEL_TIMEOUT,
            )
            if submit.status_code not in (200, 201):
                result["error"] = f"VT submission failed: HTTP {submit.status_code}"
                return result

            # Poll for result (up to 3 tries)
            analysis_id = submit.json().get("data", {}).get("id", "")
            for _ in range(3):
                time.sleep(2)
                poll = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=config.THREAT_INTEL_TIMEOUT,
                )
                if poll.status_code == 200:
                    stats = (
                        poll.json()
                        .get("data", {})
                        .get("attributes", {})
                        .get("stats", {})
                    )
                    if stats:
                        resp = poll
                        break
            else:
                result["error"] = "VT analysis pending — try again in a moment."
                return result

        if resp.status_code != 200:
            result["error"] = f"VT API error: HTTP {resp.status_code}"
            return result

        data  = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        if total == 0:
            result["error"] = "No engine results available yet."
            return result

        vt_score = round((malicious + suspicious * 0.5) / total * 100, 1)

        if malicious >= 3:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 2:
            verdict = "suspicious"
        else:
            verdict = "clean"

        result.update({
            "available":     True,
            "malicious":     malicious,
            "suspicious":    suspicious,
            "harmless":      harmless,
            "total_engines": total,
            "vt_verdict":    verdict,
            "vt_score":      vt_score,
            "permalink":     f"https://www.virustotal.com/gui/url/{url_id}",
        })

    except requests.exceptions.Timeout:
        result["error"] = "VT API timed out."
    except requests.exceptions.ConnectionError:
        result["error"] = "Cannot connect to VirusTotal."
    except Exception as exc:
        result["error"] = f"VT error: {exc}"
        logger.exception("VirusTotal check failed for %s", url[:60])

    return result


# ─── Google Safe Browsing ─────────────────────────────────────────────────────

GSB_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

GSB_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_google_safebrowsing(url: str) -> dict:
    """
    Query Google Safe Browsing v4 for a URL.

    Returns
    -------
    dict with keys:
        available    : bool
        is_threat    : bool
        threat_types : list[str]   — e.g. ['SOCIAL_ENGINEERING']
        gsb_verdict  : str         — 'threat' | 'clean' | 'unknown'
        error        : str
    """
    result = {
        "available":    False,
        "is_threat":    False,
        "threat_types": [],
        "gsb_verdict":  "unknown",
        "error":        "",
    }

    api_key = config.GOOGLE_SAFEBROWSING_KEY
    if not api_key:
        result["error"] = "Google Safe Browsing key not configured (set GSB_API_KEY)."
        return result

    payload = {
        "client":    {"clientId": "PhishyGuard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      GSB_THREAT_TYPES,
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            GSB_BASE,
            params={"key": api_key},
            json=payload,
            timeout=config.THREAT_INTEL_TIMEOUT,
        )

        if resp.status_code != 200:
            result["error"] = f"GSB API error: HTTP {resp.status_code}"
            return result

        data    = resp.json()
        matches = data.get("matches", [])

        threat_types = list({m.get("threatType", "") for m in matches
                              if m.get("threatType")})

        result.update({
            "available":    True,
            "is_threat":    bool(matches),
            "threat_types": threat_types,
            "gsb_verdict":  "threat" if matches else "clean",
        })

    except requests.exceptions.Timeout:
        result["error"] = "GSB API timed out."
    except requests.exceptions.ConnectionError:
        result["error"] = "Cannot connect to Google Safe Browsing."
    except Exception as exc:
        result["error"] = f"GSB error: {exc}"
        logger.exception("GSB check failed for %s", url[:60])

    return result


# ─── Combined enrichment ──────────────────────────────────────────────────────

def enrich_scan(url: str) -> dict:
    """
    Run both threat intel checks in parallel and return a combined enrichment
    dict to attach to the scan result.

    Always returns a dict — never raises.
    """
    import concurrent.futures

    enrichment = {
        "virustotal":        None,
        "safe_browsing":     None,
        "combined_verdict":  "unknown",  # 'malicious' | 'suspicious' | 'clean' | 'unknown'
        "combined_score":    0.0,         # 0–100 threat score from external sources
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        vt_future  = pool.submit(check_virustotal, url)
        gsb_future = pool.submit(check_google_safebrowsing, url)

        vt_result  = vt_future.result()
        gsb_result = gsb_future.result()

    enrichment["virustotal"]    = vt_result
    enrichment["safe_browsing"] = gsb_result

    # Combine verdicts
    is_malicious = (
        vt_result.get("vt_verdict")  == "malicious" or
        gsb_result.get("gsb_verdict") == "threat"
    )
    is_suspicious = (
        vt_result.get("vt_verdict") == "suspicious"
    )

    if is_malicious:
        enrichment["combined_verdict"] = "malicious"
        enrichment["combined_score"]   = max(
            vt_result.get("vt_score", 0) or 0, 85.0
        )
    elif is_suspicious:
        enrichment["combined_verdict"] = "suspicious"
        enrichment["combined_score"]   = vt_result.get("vt_score", 45.0) or 45.0
    elif vt_result.get("available") or gsb_result.get("available"):
        enrichment["combined_verdict"] = "clean"
        enrichment["combined_score"]   = vt_result.get("vt_score", 0) or 0
    else:
        enrichment["combined_verdict"] = "unknown"

    logger.info(
        "Threat intel for %s — VT: %s | GSB: %s | combined: %s",
        url[:60],
        vt_result.get("vt_verdict", "n/a"),
        gsb_result.get("gsb_verdict", "n/a"),
        enrichment["combined_verdict"],
    )

    return enrichment
