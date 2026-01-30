from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from threading import Timer
import webbrowser
import re
import socket
import json
import os

app = Flask(__name__)
CORS(app)

# ======================
# DEMO USERS
# ======================
USERS = {
    "admin@gmail.com": "admin123",
    "student@gmail.com": "student123"
}

# ======================
# HISTORY FILE
# ======================
HISTORY_FILE = "scan_history.json"

if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "w") as f:
        json.dump([], f)

# ======================
# HELPERS
# ======================
def extract_features(url):
    return {
        "length": len(url),
        "has_https": int(url.startswith("https")),
        "has_ip": int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))),
        "has_login": int("login" in url),
        "has_verify": int("verify" in url),
        "has_bank": int("bank" in url),
        "has_secure": int("secure" in url)
    }

def domain_exists(url):
    try:
        domain = re.sub(r"https?://", "", url).split("/")[0]
        socket.gethostbyname(domain)
        return True
    except:
        return False

# ======================
# ROUTES
# ======================
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if USERS.get(data.get("email")) == data.get("password"):
        return jsonify({"success": True})
    return jsonify({"success": False}), 401

@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json()
    url = data.get("url", "").lower().strip()

    if not url:
        return jsonify({"result": "❌ No URL", "risk_score": 0})

    if not domain_exists(url):
        result = "⚠️ Suspicious / Unreachable Domain"
        risk = 3
    else:
        f = extract_features(url)
        risk = 0
        if f["has_ip"]: risk += 2
        if f["has_login"]: risk += 1
        if f["has_verify"]: risk += 1
        if f["has_bank"]: risk += 2
        if not f["has_https"]: risk += 1

        result = "⚠️ Phishing Detected" if risk >= 2 else "✅ Safe Website"

    record = {"url": url, "result": result, "risk_score": risk}

    with open(HISTORY_FILE, "r+") as f:
        data = json.load(f)
        data.insert(0, record)
        f.seek(0)
        json.dump(data, f, indent=2)

    return jsonify(record)

@app.route("/api/history")
def history():
    with open(HISTORY_FILE) as f:
        return jsonify(json.load(f))

# ======================
if __name__ == "__main__":
    Timer(2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(debug=False, use_reloader=False)
