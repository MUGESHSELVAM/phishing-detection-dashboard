"""
config.py — Application configuration module
Phishing Detection Dashboard
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "phish-detector-secret-2024")
    DEBUG = os.environ.get("DEBUG", "True") == "True"
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))

    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, "data", "phishing.db")

    # Model
    MODEL_PATH    = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
    FEATURES_PATH = os.path.join(BASE_DIR, "models", "feature_names.pkl")

    # Logging
    LOG_FILE  = os.path.join(BASE_DIR, "data", "app.log")
    LOG_LEVEL = "INFO"

    # Detection thresholds
    RISK_HIGH   = 75   # >= 75  → HIGH RISK
    RISK_MEDIUM = 45   # >= 45  → MEDIUM RISK

    # ── Rate limiting (sliding window) ──────────────────────────────────────
    RATE_LIMIT_REQUESTS = 30   # max requests …
    RATE_LIMIT_WINDOW   = 60   # … per this many seconds (per IP)

    # ── Threat intelligence APIs ─────────────────────────────────────────────
    # Set these as environment variables — never commit real keys to source.
    VIRUSTOTAL_API_KEY      = os.environ.get("VT_API_KEY", "")
    GOOGLE_SAFEBROWSING_KEY = os.environ.get("GSB_API_KEY", "")

    # Timeouts for external API calls (seconds)
    THREAT_INTEL_TIMEOUT = 5

    # ── WHOIS enrichment ─────────────────────────────────────────────────────
    WHOIS_TIMEOUT         = 4   # seconds per lookup
    NEW_DOMAIN_THRESHOLD  = 180 # days — domains younger than this are flagged

    # ── Authentication ───────────────────────────────────────────────────────
    # Default admin credentials (change immediately in production!)
    DEFAULT_ADMIN_USER     = os.environ.get("ADMIN_USER",     "admin")
    DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "PhishyGuard123")
    SESSION_LIFETIME_HOURS = 8

    # reCAPTCHA (set in environment for migration compatibility)
    RECAPTCHA_SITE_KEY      = os.environ.get("RECAPTCHA_SITE_KEY", "")
    RECAPTCHA_SECRET_KEY    = os.environ.get("RECAPTCHA_SECRET_KEY", "")

    # ── Dataset ──────────────────────────────────────────────────────────────
    DATASET_DIR  = os.path.join(BASE_DIR, "data")
    DATASET_PATH = os.path.join(BASE_DIR, "data", "phishing_dataset.csv")

config = Config()
