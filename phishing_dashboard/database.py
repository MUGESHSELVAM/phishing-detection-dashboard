"""
database.py — Database Layer
Phishing Detection Dashboard

Manages SQLite storage for scan results, URL history,
event logs, and detection statistics.
"""
import sqlite3
import os
import json
import logging
from datetime import datetime, timedelta
from contextlib import contextmanager

from config import config

logger = logging.getLogger(__name__)


# ─── Connection helper ───────────────────────────────────────────────────────

@contextmanager
def get_db():
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Schema ──────────────────────────────────────────────────────────────────

def init_db():
    """Create tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            verdict     TEXT    NOT NULL,   -- 'phishing' | 'legitimate'
            risk_score  REAL    NOT NULL,   -- 0.0 – 100.0
            confidence  REAL    NOT NULL,   -- 0.0 – 100.0
            features    TEXT,               -- JSON of extracted features
            ip_address  TEXT,
            user_agent  TEXT,
            scanned_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS url_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT    NOT NULL,
            scan_count INTEGER DEFAULT 1,
            last_seen  TEXT    DEFAULT (datetime('now')),
            is_flagged INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS event_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT    NOT NULL,   -- 'scan' | 'error' | 'api_call'
            message    TEXT,
            details    TEXT,               -- JSON
            logged_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_scan_results_scanned_at
            ON scan_results (scanned_at);
        CREATE INDEX IF NOT EXISTS idx_url_history_url
            ON url_history (url);
        """)
    logger.info("Database initialized at %s", config.DATABASE_PATH)


# ─── Scan results ─────────────────────────────────────────────────────────────

def save_scan(url: str, verdict: str, risk_score: float,
              confidence: float, features: dict,
              ip_address: str = "", user_agent: str = "") -> int:
    """Insert a scan result and update URL history. Returns new row id."""
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO scan_results
               (url, verdict, risk_score, confidence, features, ip_address, user_agent)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (url, verdict, risk_score, confidence,
             json.dumps(features), ip_address, user_agent),
        )
        row_id = cursor.lastrowid

        # Upsert URL history
        existing = conn.execute(
            "SELECT id, scan_count FROM url_history WHERE url = ?", (url,)
        ).fetchone()

        if existing:
            conn.execute(
                """UPDATE url_history
                   SET scan_count = scan_count + 1,
                       last_seen  = datetime('now'),
                       is_flagged = ?
                   WHERE url = ?""",
                (1 if verdict == "phishing" else 0, url),
            )
        else:
            conn.execute(
                """INSERT INTO url_history (url, is_flagged)
                   VALUES (?, ?)""",
                (url, 1 if verdict == "phishing" else 0),
            )

    log_event("scan", f"URL scanned: {url[:60]}",
              {"verdict": verdict, "risk_score": risk_score})
    return row_id


def get_recent_scans(limit: int = 20) -> list:
    """Return the most recent scan results."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, url, verdict, risk_score, confidence, scanned_at
               FROM scan_results
               ORDER BY scanned_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scan_results WHERE id = ?", (scan_id,)
        ).fetchone()
    if row:
        r = dict(row)
        r["features"] = json.loads(r["features"] or "{}")
        return r
    return None


# ─── Statistics ───────────────────────────────────────────────────────────────

def get_statistics() -> dict:
    """Aggregate stats for the dashboard overview cards."""
    with get_db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM scan_results"
        ).fetchone()[0]

        phishing_count = conn.execute(
            "SELECT COUNT(*) FROM scan_results WHERE verdict = 'phishing'"
        ).fetchone()[0]

        legit_count = conn.execute(
            "SELECT COUNT(*) FROM scan_results WHERE verdict = 'legitimate'"
        ).fetchone()[0]

        avg_risk = conn.execute(
            "SELECT AVG(risk_score) FROM scan_results"
        ).fetchone()[0] or 0.0

        today_count = conn.execute(
            """SELECT COUNT(*) FROM scan_results
               WHERE date(scanned_at) = date('now')"""
        ).fetchone()[0]

        # Last 7 days daily breakdown
        daily = conn.execute(
            """SELECT date(scanned_at) as day,
                      SUM(CASE WHEN verdict='phishing'   THEN 1 ELSE 0 END) as phishing,
                      SUM(CASE WHEN verdict='legitimate' THEN 1 ELSE 0 END) as legitimate
               FROM scan_results
               WHERE scanned_at >= datetime('now', '-7 days')
               GROUP BY day
               ORDER BY day ASC"""
        ).fetchall()

        # Top phishing URLs
        top_threats = conn.execute(
            """SELECT url, risk_score, scanned_at
               FROM scan_results
               WHERE verdict = 'phishing'
               ORDER BY risk_score DESC
               LIMIT 5"""
        ).fetchall()

    return {
        "total_scans":    total,
        "phishing_count": phishing_count,
        "legit_count":    legit_count,
        "avg_risk_score": round(avg_risk, 1),
        "today_count":    today_count,
        "detection_rate": round(phishing_count / max(total, 1) * 100, 1),
        "daily_breakdown": [dict(r) for r in daily],
        "top_threats":    [dict(r) for r in top_threats],
    }


# ─── URL history ──────────────────────────────────────────────────────────────

def search_url_history(query: str, limit: int = 10) -> list:
    with get_db() as conn:
        rows = conn.execute(
            """SELECT * FROM url_history
               WHERE url LIKE ?
               ORDER BY last_seen DESC LIMIT ?""",
            (f"%{query}%", limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ─── Event logging ────────────────────────────────────────────────────────────

def log_event(event_type: str, message: str, details: dict = None):
    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO event_logs (event_type, message, details)
                   VALUES (?, ?, ?)""",
                (event_type, message, json.dumps(details or {})),
            )
    except Exception as e:
        logger.error("Failed to log event: %s", e)


def get_recent_logs(limit: int = 50) -> list:
    with get_db() as conn:
        rows = conn.execute(
            """SELECT * FROM event_logs
               ORDER BY logged_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ─── Seed demo data ───────────────────────────────────────────────────────────

def seed_demo_data():
    """Insert demo scan records so the dashboard looks populated on first run."""
    import random
    random.seed(99)

    demo_urls = [
        ("https://www.google.com",                       "legitimate", 5.2,  98.1),
        ("https://github.com/login",                     "legitimate", 8.0,  95.4),
        ("http://paypal-secure-verify.tk/login",         "phishing",   92.3, 97.8),
        ("https://stackoverflow.com/questions/tagged",   "legitimate", 3.1,  99.2),
        ("http://apple-id-suspended.xyz/verify",         "phishing",   88.5, 96.3),
        ("https://www.amazon.com/dp/B09X1",              "legitimate", 6.7,  94.0),
        ("http://free-iphone-winner.club/claim",         "phishing",   95.0, 98.9),
        ("https://linkedin.com/in/user",                 "legitimate", 4.4,  97.1),
        ("http://192.168.0.1/banking/login.php",         "phishing",   87.2, 95.6),
        ("https://wikipedia.org/wiki/Machine_learning",  "legitimate", 2.8,  99.5),
        ("http://bit.ly/fakeprize99",                    "phishing",   79.1, 91.2),
        ("https://mail.google.com/mail/u/0",             "legitimate", 9.3,  93.8),
    ]

    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]

    if count == 0:
        from feature_extraction import extract_features
        for url, verdict, risk, conf in demo_urls:
            feats = extract_features(url)
            save_scan(url, verdict, risk, conf, feats,
                      ip_address="127.0.0.1", user_agent="demo-seeder")
