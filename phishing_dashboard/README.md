# PhishyGuard — ML-Powered Phishing Detection Dashboard (v2)

A production-grade cybersecurity project built for SOC environments.

---

## What's new in v2

| Area | Improvement |
|------|-------------|
| **Real dataset** | Downloads PhiUSIIIT (235k+ labeled URLs from UCI ML Repository). Falls back to 200 hand-verified URLs if offline. Feature CSV is cached locally so re-training is fast. |
| **WHOIS features** | 6 new features: `domain_age_days`, `is_new_domain`, `whois_available`, `domain_country`, `has_privacy_guard`, `dns_resolves`. New domains (< 180 days) are flagged. |
| **Threat intel** | Optional VirusTotal v3 + Google Safe Browsing v4 second-opinion layer. Both run in parallel. Results are merged with the ML verdict. Gracefully skipped if API keys are not set. |
| **Rate limiting** | Real sliding-window rate limiter (30 req/60s per IP). Returns `429` with `Retry-After` header. No Redis needed — pure Python thread-safe implementation. |
| **Authentication** | Session-based login with bcrypt-hashed passwords and Flask-Login. Lockout after 5 failed attempts (15-min cooldown). Role system (`admin` / `analyst`). Password change API. |
| **Unit tests** | 40 tests across feature extractor, WHOIS structure, edge cases, feature consistency, and rate limiter. Run with `pytest`. |

---

## Project Structure

```
phishing_dashboard/
├── app.py                    Flask API server
├── config.py                 All configuration
├── feature_extraction.py     38-feature URL extractor (incl. WHOIS)
├── dataset_loader.py         Real dataset downloader (PhiUSIIIT + fallback)
├── model_training.py         ML training (RF + optional LR comparison)
├── database.py               SQLite layer
├── threat_intel.py           VirusTotal + Google Safe Browsing
├── rate_limiter.py           Sliding-window per-IP rate limiter
├── auth.py                   Session auth, bcrypt, lockout
├── requirements.txt
├── data/
│   ├── phishing.db           SQLite (auto-created)
│   ├── app.log               Application log (auto-created)
│   ├── phiusiit_raw.csv      Cached raw dataset (after first download)
│   └── features_labeled.csv  Cached feature matrix (after training)
├── models/
│   ├── phishing_model.pkl    Trained model
│   ├── feature_names.pkl     Feature name list
│   └── phishing_model_metrics.json
├── templates/
│   ├── login.html
│   ├── index.html
│   └── dashboard.html
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
└── tests/
    └── test_features.py      40 unit tests
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. (Optional) Set API keys for threat intelligence
```bash
export VT_API_KEY="your-virustotal-api-key"
export GSB_API_KEY="your-google-safe-browsing-key"
```
Both are completely optional. The app runs fine without them — threat intel results will show "API key not configured" rather than crashing.

### 3. Train the model
```bash
# Fast (fallback URLs, ~30 seconds):
python model_training.py --samples 200

# Standard (downloads PhiUSIIIT, ~5 min first run, cached after):
python model_training.py

# Full with model comparison:
python model_training.py --samples 5000 --compare
```

### 4. Start the server
```bash
python app.py
```

Open http://localhost:5000 — you'll be redirected to the login page.

**Default credentials:** `admin` / `PhishyGuard123`
Change immediately via env vars: `ADMIN_USER` and `ADMIN_PASSWORD`.

### 5. Run tests
```bash
python -m pytest tests/ -v
```

---

## API Reference

All endpoints require authentication (`/login` first).

| Method | Route | Auth | Rate Limited | Description |
|--------|-------|------|--------------|-------------|
| GET/POST | `/login` | No | No | Login page |
| GET | `/logout` | Yes | No | Sign out |
| POST | `/api/scan` | Yes | Yes (30/min) | Scan a URL |
| GET | `/api/threat-intel?url=…` | Yes | Yes | Standalone threat intel |
| GET | `/api/stats` | Yes | No | Dashboard statistics |
| GET | `/api/recent` | Yes | No | Recent scans |
| GET | `/api/scan/<id>` | Yes | No | Scan detail |
| GET | `/api/model/info` | Yes | No | Model metrics |
| GET | `/api/logs` | Yes | No | Event logs |
| GET | `/health` | No | No | Health check |

### Scan request with threat intel
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -b "session=..." \
  -d '{"url": "http://paypal-verify.tk/login", "threat_intel": true}'
```

### Rate limit headers on every response
```
X-RateLimit-Limit:     30
X-RateLimit-Remaining: 29
X-RateLimit-Window:    60
```

---

## ML Model Details

| Property | Value |
|----------|-------|
| Algorithm | Random Forest (300 trees, depth 20) |
| Pipeline | StandardScaler → RandomForestClassifier |
| Features | 38 (32 lexical + 6 WHOIS/DNS) |
| Dataset | PhiUSIIIT (up to 3000/class sampled) |
| Evaluation | 5-fold stratified CV + held-out 20% test set |
| Metrics | Accuracy, Precision, Recall, F1, AUC-ROC, Avg Precision |

### Feature categories
| Category | Count | Examples |
|----------|-------|---------|
| Length-based | 4 | `url_length`, `hostname_length`, `path_length`, `query_length` |
| Character counts | 9 | `count_dots`, `count_hyphens`, `count_digits`, `count_at` |
| Structural | 6 | `is_https`, `has_ip`, `has_port`, `subdomain_count` |
| Content-based | 5 | `has_phish_keyword`, `suspicious_tld`, `is_shortened` |
| Entropy | 2 | `entropy_hostname`, `entropy_path` |
| Ratios | 2 | `digit_ratio`, `special_char_density` |
| WHOIS / DNS | 6 | `domain_age_days`, `is_new_domain`, `dns_resolves` |

---

## Security Notes

- Passwords are hashed with bcrypt (cost factor 12)
- Accounts lock out for 15 minutes after 5 failed login attempts
- All API keys are read from environment variables — never from source code
- Rate limiting prevents automated URL submission abuse
- WHOIS and threat intel calls have configurable timeouts (default 4–5s)
