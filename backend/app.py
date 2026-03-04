import os
import sys
import joblib
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# make sure parent directory is on path so `ml` package is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_cors import CORS
from datetime import datetime
from urllib.parse import urlparse

from db import log_scan
from ml.feature_extraction import extract_features

# dashboard blueprint (optional admin UI)
from dashboard import admin_bp

# security engine
from security_engine import scan_url as security_scan
from middleware.auth_middleware import token_required

# ======================
# Flask Setup
# ======================
app = Flask(__name__)
CORS(app, supports_credentials=True)
# simple rate limiter to prevent abuse
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"], storage_uri="memory://")

# register admin dashboard blueprint if available
app.register_blueprint(admin_bp)

# register auth blueprint
from routes.auth import auth_bp
app.register_blueprint(auth_bp, url_prefix="/auth")


# Load model at startup
MODEL_PATH = os.environ.get("MODEL_PATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")))
model = None
try:
    model = joblib.load(MODEL_PATH)
    print(f"Loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"Failed to load model: {e}")


# ======================
# Utility functions
# =====================

def predict_url(url: str):
    # legacy helper kept for compatibility; prefer security_scan
    features = extract_features(url)
    import pandas as pd
    X = pd.DataFrame([features])
    pred = model.predict(X)[0]
    prob = None
    if hasattr(model, "predict_proba"):
        prob = model.predict_proba(X)[0][1]
    return pred, prob


def sanitize_url(url: str) -> str:
    # basic sanitation: strip whitespace, lower-case
    return url.strip()


def get_client_ip():
    # trust X-Forwarded-For if behind proxy
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr


# ======================
# Routes
# ======================

@app.route("/predict", methods=["POST"])
@limiter.limit("30 per minute")
@token_required
def predict():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field."}), 400

    url = sanitize_url(data["url"])
    if not url:
        return jsonify({"error": "Empty URL."}), 400

    try:
        # use multi-layer security engine
        assessment = security_scan(url)
        record = {
            "url": url,
            "prediction": assessment.get("status"),
            "confidence_score": assessment.get("confidence"),
            "risk_score": assessment.get("risk_score"),
            "reasons": assessment.get("reasons"),
            "details": assessment.get("details"),
            "timestamp": datetime.utcnow(),
            "ip": get_client_ip(),
            "user_id": getattr(__import__('flask').g, 'current_user', {}).get('id') if getattr(__import__('flask').g, 'current_user', None) else None,
        }
        try:
            log_scan(record)
        except Exception as e:
            app.logger.warning(f"Failed to log to database: {e}")

        # ensure backward compatible field names
        assessment_out = dict(assessment)
        assessment_out["prediction"] = assessment_out.get("status")
        assessment_out["risk_score"] = assessment_out.get("risk_score")
        return jsonify(assessment_out)
    except Exception as e:
        app.logger.error(f"Error during prediction: {e}")
        return jsonify({"error": "Internal server error."}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/scan", methods=["POST"])
@limiter.limit("60 per minute")
@token_required
def api_scan():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field."}), 400

    url = sanitize_url(data["url"])
    if not url:
        return jsonify({"error": "Empty URL."}), 400

    try:
        assessment = security_scan(url)
        record = {
            "url": url,
            "prediction": assessment.get("status"),
            "confidence_score": assessment.get("confidence"),
            "risk_score": assessment.get("risk_score"),
            "reasons": assessment.get("reasons"),
            "details": assessment.get("details"),
            "timestamp": datetime.utcnow(),
            "ip": get_client_ip(),
            "user_id": getattr(__import__('flask').g, 'current_user', {}).get('id') if getattr(__import__('flask').g, 'current_user', None) else None,
        }
        try:
            log_scan(record)
        except Exception as e:
            app.logger.warning(f"Failed to log to database: {e}")

        # fast response: include key fields only
        out = {
            "risk_score": assessment.get("risk_score"),
            "status": assessment.get("status"),
            "confidence": assessment.get("confidence"),
            "reasons": assessment.get("reasons"),
        }
        return jsonify(out)
    except Exception as e:
        app.logger.error(f"Error during scan: {e}")
        return jsonify({"error": "Internal server error."}), 500
@app.route("/")
def home():
    return {"message": "Phishing Detection API is running"}

if __name__ == "__main__":
    # Production-ready logging
    import logging
    from logging.handlers import RotatingFileHandler

    handler = RotatingFileHandler('backend.log', maxBytes=10 * 1024 * 1024, backupCount=5)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # Run development server only for local testing; production should use Gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 8000)), debug=False)
