import os
import socket
import ssl
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from ml.feature_extraction import extract_features
import joblib

try:
    # when package-installed or running as package
    from .domain_intelligence import analyze_domain
except Exception:
    # fallback when running as script from backend/ working dir
    from domain_intelligence import analyze_domain

logger = logging.getLogger(__name__)

# Blacklist path (one domain per line)
BLACKLIST_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "blacklist.txt"))


def load_blacklist() -> set:
    try:
        if os.path.exists(BLACKLIST_PATH):
            with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
                return set(line.strip().lower() for line in f if line.strip())
    except Exception as e:
        logger.warning(f"Failed to load blacklist: {e}")
    return set()


def ssl_check(hostname: str, timeout: int = 5) -> Dict[str, Any]:
    """Perform a TLS certificate check for the hostname. Returns a dict with findings."""
    result = {"valid": False, "expires_in_days": None, "issuer": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # parse notBefore / notAfter
                not_after = cert.get("notAfter")
                issuer = cert.get("issuer")
                result["issuer"] = issuer
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    delta = exp - datetime.utcnow()
                    result["expires_in_days"] = delta.days
                    result["valid"] = delta.days >= 0
    except Exception as e:
        result["error"] = str(e)
        logger.debug(f"SSL check error for {hostname}: {e}")
    return result


class SecurityEngine:
    def __init__(self, model_path: Optional[str] = None):
        # load model
        self.model_path = model_path or os.environ.get(
            "MODEL_PATH",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")),
        )
        self.model = None
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                logger.info(f"SecurityEngine loaded model from {self.model_path}")
        except Exception as e:
            logger.exception(f"Failed to load model: {e}")

        self.blacklist = load_blacklist()

    def model_score(self, url: str) -> Dict[str, Any]:
        features = extract_features(url)
        import pandas as pd
        X = pd.DataFrame([features])
        score = 0.0
        confidence = None
        if self.model is not None:
            try:
                if hasattr(self.model, "predict_proba"):
                    prob = self.model.predict_proba(X)[0]
                    # assume class 1 is phishing
                    confidence = float(prob[1])
                    score = confidence * 100.0
                else:
                    pred = int(self.model.predict(X)[0])
                    score = 100.0 if pred == 1 else 0.0
                    confidence = float(score / 100.0)
            except Exception as e:
                logger.exception(f"Model scoring failed: {e}")
        return {"ml_score": score, "confidence": confidence}

    def heuristic_score(self, url: str) -> Dict[str, Any]:
        features = extract_features(url)
        reasons: List[str] = []
        score = 0

        # URL length
        if features.get("url_length", 0) > 75:
            score += 10
            reasons.append("Long URL length")

        # many subdomains
        if features.get("subdomain_count", 0) > 2:
            score += 15
            reasons.append("Excessive subdomain count")

        # special chars
        special_chars = sum(features.get(k, False) for k in features if isinstance(features[k], bool) and features[k] and k.startswith("keyword_"))
        if special_chars:
            add = min(10, special_chars * 2)
            score += add
            reasons.append("Suspicious keywords in URL")

        # IP in URL
        if features.get("contains_ip"):
            score += 20
            reasons.append("URL uses an IP address")

        # missing HTTPS
        if not features.get("has_https"):
            score += 10
            reasons.append("No HTTPS")

        # suspicious TLD
        if features.get("tld_suspicious"):
            score += 10
            reasons.append("Suspicious top-level domain")

        # cap heuristic
        score = min(score, 40)
        return {"heuristic_score": score, "heuristic_reasons": reasons}

    def blacklist_check(self, domain: str) -> Dict[str, Any]:
        dom = domain.lower().strip()
        hit = dom in self.blacklist
        return {"blacklisted": hit}

    def scan_url(self, url: str) -> Dict[str, Any]:
        """Run a multi-layer scan and return a risk assessment."""
        reasons: List[str] = []
        # extract domain
        from urllib.parse import urlparse

        parsed = urlparse(url if url.startswith(("http://", "https://")) else ("http://" + url))
        domain = parsed.hostname or ""

        ml = self.model_score(url)
        heur = self.heuristic_score(url)
        domain_info = analyze_domain(domain)
        ssl = ssl_check(domain) if domain else {"valid": False, "error": "no-host"}
        black = self.blacklist_check(domain)

        # collect reasons
        if ml.get("confidence") is not None:
            reasons.append(f"ML model confidence: {ml['confidence']:.2f}")
        reasons.extend(heur.get("heuristic_reasons", []))
        if domain_info.get("age_days") is not None and domain_info.get("age_days") < 30:
            reasons.append("Domain age is less than 30 days")
        if ssl.get("error"):
            reasons.append(f"SSL check error: {ssl.get('error')}")
        elif not ssl.get("valid"):
            reasons.append("Invalid or expired TLS certificate")
        if black.get("blacklisted"):
            reasons.append("Domain is on the blacklist")

        # combine scores with weights
        w_ml = 0.5
        w_heur = 0.25
        w_domain = 0.15
        w_ssl = 0.05
        w_black = 0.05

        ml_score = ml.get("ml_score", 0) or 0
        heur_score = heur.get("heuristic_score", 0) or 0
        domain_score = float(domain_info.get("suspicious_score", 0)) * 100.0
        ssl_score = 0.0 if ssl.get("valid") else 100.0
        black_score = 100.0 if black.get("blacklisted") else 0.0

        combined = (
            w_ml * ml_score
            + w_heur * heur_score
            + w_domain * domain_score
            + w_ssl * ssl_score
            + w_black * black_score
        )

        risk_score = int(min(max(combined, 0), 100))
        status = "Phishing" if risk_score >= 50 else "Legitimate"

        return {
            "risk_score": risk_score,
            "status": status,
            "confidence": ml.get("confidence"),
            "reasons": reasons,
            "details": {
                "ml": ml,
                "heuristic": heur,
                "domain_intel": domain_info,
                "ssl": ssl,
                "blacklist": black,
            },
        }


# convenience instance
engine = SecurityEngine()


def scan_url(url: str) -> Dict[str, Any]:
    return engine.scan_url(url)
