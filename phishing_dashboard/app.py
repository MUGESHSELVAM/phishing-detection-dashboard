"""
app.py — Flask API Server
Phishing Detection Dashboard

Routes:
  GET  /login                → login page
  POST /login                → authenticate
  GET  /logout               → sign out
  GET  /                     → index (auth required)
  GET  /dashboard            → dashboard (auth required)
  POST /api/scan             → scan URL (rate limited, auth required)
  GET  /api/stats            → statistics (auth required)
  GET  /api/recent           → recent scans (auth required)
  GET  /api/scan/<id>        → scan detail (auth required)
  GET  /api/logs             → event logs (auth required)
  GET  /api/model/info       → model metadata (auth required)
  GET  /api/threat-intel/<url> → external threat intel (auth required)
"""
import os, sys, json, logging, joblib
import numpy as np
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template, abort, redirect, url_for
from flask_login import login_required, current_user

from config import config
from feature_extraction import extract_features, get_feature_names
from database import (
    init_db, seed_demo_data, save_scan,
    get_recent_scans, get_scan_by_id,
    get_statistics, get_recent_logs,
    search_url_history, log_event,
)
from auth import login_manager, init_auth_tables, create_default_admin, register_auth_routes
from rate_limiter import rate_limit, start_cleanup_thread
from threat_intel import enrich_scan

# ─── Logging ─────────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.from_object(config)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=config.SESSION_LIFETIME_HOURS)

# Auth
login_manager.init_app(app)
register_auth_routes(app)

# ─── Model ────────────────────────────────────────────────────────────────────
MODEL = None
FEATURE_NAMES = None
MODEL_METRICS = {}


def load_model():
    global MODEL, FEATURE_NAMES, MODEL_METRICS
    if not os.path.exists(config.MODEL_PATH):
        logger.warning("Model not found at %s — run: python model_training.py", config.MODEL_PATH)
        return False
    MODEL = joblib.load(config.MODEL_PATH)
    FEATURE_NAMES = joblib.load(config.FEATURES_PATH)
    metrics_path = config.MODEL_PATH.replace(".pkl", "_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            MODEL_METRICS = json.load(f)
    logger.info("Model loaded from %s", config.MODEL_PATH)
    return True


def model_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if MODEL is None:
            return jsonify({"success": False,
                            "error": "Model not loaded. Run python model_training.py first.",
                            "code": "MODEL_NOT_LOADED"}), 503
        return f(*args, **kwargs)
    return wrapper


def validate_url(url: str):
    if not url:
        return False, "URL is required."
    if len(url) > 2048:
        return False, "URL exceeds maximum length of 2048 characters."
    if not any(url.startswith(p) for p in ("http://", "https://", "www.", "ftp://")):
        if "." not in url:
            return False, "Invalid URL format."
    return True, ""


def compute_risk_score(phishing_proba: float) -> dict:
    score = round(phishing_proba * 100, 1)
    if score >= config.RISK_HIGH:
        level, color = "HIGH", "danger"
    elif score >= config.RISK_MEDIUM:
        level, color = "MEDIUM", "warning"
    else:
        level, color = "LOW", "success"
    return {"score": score, "level": level, "color": color}


# ─── Page routes ──────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=current_user.username,
    )


# ─── API — scan —──────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@login_required
@rate_limit
@model_required
def scan_url():
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    run_threat_intel = bool(data.get("threat_intel", False))

    valid, err = validate_url(url)
    if not valid:
        log_event("error", f"Invalid URL: {url[:60]}", {"error": err})
        return jsonify({"success": False, "error": err}), 400

    if not url.startswith(("http://", "https://", "ftp://")):
        url = "https://" + url

    try:
        # Feature extraction (includes WHOIS if configured)
        features = extract_features(url)
        feature_vector = np.array(
            [features.get(name, 0) for name in FEATURE_NAMES]
        ).reshape(1, -1)

        # ML inference
        prediction      = int(MODEL.predict(feature_vector)[0])
        probabilities   = MODEL.predict_proba(feature_vector)[0]
        phishing_proba  = float(probabilities[1])
        legit_proba     = float(probabilities[0])
        verdict         = "phishing" if prediction == 1 else "legitimate"
        risk            = compute_risk_score(phishing_proba)
        confidence      = round(max(phishing_proba, legit_proba) * 100, 1)

        # External threat intelligence (optional — client can request it)
        enrichment = None
        if run_threat_intel:
            enrichment = enrich_scan(url)
            # Upgrade verdict if VT or GSB flags it
            if enrichment.get("combined_verdict") == "malicious":
                verdict = "phishing"
                risk["score"] = max(risk["score"], enrichment["combined_score"])
                risk["level"] = "HIGH"

        ip      = request.remote_addr or "unknown"
        ua      = request.headers.get("User-Agent", "")[:200]
        scan_id = save_scan(
            url=url, verdict=verdict,
            risk_score=risk["score"], confidence=confidence,
            features=features, ip_address=ip, user_agent=ua,
        )

        logger.info("Scan #%d by %s — %s → %s (%.1f%%)",
                    scan_id, current_user.username, url[:60], verdict.upper(), risk["score"])

        response = {
            "success":    True,
            "scan_id":    scan_id,
            "url":        url,
            "verdict":    verdict,
            "risk":       risk,
            "confidence": confidence,
            "probabilities": {
                "phishing":   round(phishing_proba * 100, 1),
                "legitimate": round(legit_proba    * 100, 1),
            },
            "features": {
                k: v for k, v in features.items()
                if k in ("url_length", "count_dots", "is_https", "has_ip",
                         "has_phish_keyword", "suspicious_tld", "is_shortened",
                         "subdomain_count", "entropy_hostname", "hyphen_in_domain",
                         "domain_age_days", "is_new_domain", "whois_available",
                         "has_privacy_guard", "dns_resolves")
            },
            "scanned_at": datetime.utcnow().isoformat() + "Z",
        }
        if enrichment:
            response["threat_intel"] = enrichment

        return jsonify(response)

    except Exception as exc:
        logger.exception("Scan failed for %s: %s", url[:60], exc)
        log_event("error", f"Scan exception: {exc}", {"url": url})
        return jsonify({"success": False, "error": "Scan failed. See logs."}), 500


# ─── API — threat intel (standalone endpoint) ─────────────────────────────────

@app.route("/api/threat-intel")
@login_required
@rate_limit
def api_threat_intel():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"success": False, "error": "url param required"}), 400
    result = enrich_scan(url)
    return jsonify({"success": True, "url": url, "enrichment": result})


# ─── API — stats / history ────────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    try:
        return jsonify({"success": True, "stats": get_statistics()})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/recent")
@login_required
def api_recent():
    limit = min(int(request.args.get("limit", 20)), 100)
    try:
        return jsonify({"success": True, "scans": get_recent_scans(limit)})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/scan/<int:scan_id>")
@login_required
def api_scan_detail(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
    return jsonify({"success": True, "scan": scan})


@app.route("/api/logs")
@login_required
def api_logs():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"success": True, "logs": get_recent_logs(limit)})


@app.route("/api/history/search")
@login_required
def api_history_search():
    q = request.args.get("q", "")
    return jsonify({"success": True, "results": search_url_history(q, limit=20)})


@app.route("/api/model/info")
@login_required
def api_model_info():
    if MODEL is None:
        return jsonify({"success": False, "loaded": False, "error": "Model not loaded."})
    return jsonify({
        "success": True, "loaded": True,
        "type": type(MODEL).__name__,
        "features": len(FEATURE_NAMES or []),
        "metrics": MODEL_METRICS,
    })


# ─── Health check (public) ────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status":      "ok",
        "model_ready": MODEL is not None,
        "timestamp":   datetime.utcnow().isoformat() + "Z",
    })


# ─── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Not found."}), 404
    return redirect(url_for("auth_login"))


@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"success": False, "error": "Rate limit exceeded."}), 429


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "Internal server error."}), 500


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Initializing database …")
    init_db()
    init_auth_tables()
    create_default_admin()
    seed_demo_data()

    logger.info("Loading ML model …")
    if not load_model():
        logger.warning("⚠ Run `python model_training.py` first.")

    start_cleanup_thread()
    logger.info("Starting Flask server on %s:%d", config.HOST, config.PORT)
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
