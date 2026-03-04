# AI-Based Real-Time Phishing Detection with Browser Extension

This repository contains a complete production‑style project for detecting phishing URLs using machine
learning, exposing a Flask API for predictions, and alerting users through a Chrome/Edge browser extension.
An optional admin dashboard provides usage statistics and recent alerts.

## Project Structure
```
ml/                # Machine learning module (data, training, evaluation)
    data_preprocessing.py
    feature_extraction.py
    train_model.py
    evaluate_model.py
    # trained model will be saved to ../models/phishing_model.pkl

backend/           # Flask API and admin dashboard
    app.py
    db.py
    dashboard.py      # blueprint for admin UI
    templates/
        admin.html
    requirements.txt

extension/         # Browser extension (Manifest V3)
    manifest.json
    background.js
    content.js
    popup.html
    popup.js
    icons/           # optional icons

models/            # trained ML models (pkl files)

# other legacy files/folders (can be removed): root app.py, scan_history.json, static/, templates/, test_api.py, dashboard/ 

README.md
requirements.txt    # top-level (includes ML and general dependencies)
```

> **Note:** The original `app.py` at the root is legacy and part of the earlier rule-based demo; the new system lives in the subdirectories.

## Setup Instructions

1. **Python environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # or `venv\Scripts\activate` on Windows
   pip install -r requirements.txt
   pip install -r backend/requirements.txt
   ```

2. **Obtain dataset**
   - Download a phishing dataset (e.g., UCI or Kaggle).
   - Ensure CSV has columns `url` and `label` (1=phishing, 0=legitimate).

3. **Train model**
   ```bash
   cd ml
   python train_model.py --data ../data/phishing_urls.csv
   ```
   - `best_model.pkl` will be created.
   - Evaluate accuracy with:
     ```bash
     python evaluate_model.py --data ../data/phishing_urls.csv
     ```

4. **Configure database**
   - Start MongoDB locally or set `MONGO_URI` env var.
   - Default database name `phishing_detector`.

5. **Run backend API**
   ```bash
   cd backend
   export MODEL_PATH=../models/phishing_model.pkl
   export MONGO_URI=mongodb://localhost:27017/
   python app.py
   ```
   - API endpoints:
     - `POST /predict` accepts `{ "url": "https://..." }`
     - `GET /health` for simple health check
     - `GET /admin` shows admin dashboard (optional)

6. **Install browser extension**
   - Open Chrome/Edge and navigate to `chrome://extensions`.
   - Enable "Developer mode".
   - Click "Load unpacked" and select the `extension/` directory.
   - The popup will automatically query `http://localhost:8000/predict` when opened.

## Deployment

- Use Docker or a cloud provider for both Flask API and MongoDB.
- Build the ML model ahead of time; do **not** expose `phishing_model.pkl` through the web server.
- Secure the API with rate limiting, authentication, and input validation.

## Testing

- `backend` includes simple manual tests keyed via curl or Python.
- Browser extension can be tested by loading it unpacked and visiting known phishing URLs.

## Security Notes

- Inputs are sanitized; model predictions are logged server-side only.
- Rate limiting should be added (e.g., via `flask-limiter`).
- Do not serve the ML model file; it is loaded on the server only.

## Requirements

| Component | File |
|-----------|------|
| Python dependencies | `requirements.txt` and `backend/requirements.txt` |
| Browser extension | none (Chrome/Edge) |


---

This README will evolve as you develop features. Refer to each module's docstrings for more detail.