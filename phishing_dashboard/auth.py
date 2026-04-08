"""
auth.py — User Authentication Module
Phishing Detection Dashboard

Provides session-based authentication with:
  - bcrypt password hashing
  - Flask-Login integration
  - Multi-user support stored in SQLite (same DB as scans)
  - Login attempt tracking and lockout after 5 failed attempts
  - Decorator for protecting routes

Default admin account is created automatically on first run.
Change credentials immediately in production via environment variables:
    export ADMIN_USER="yourname"
    export ADMIN_PASSWORD="a-strong-password"
"""
import bcrypt
import logging
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import (
    request, redirect, url_for, session,
    jsonify, render_template, flash,
)
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user, login_required,
    current_user,
)

from config import config
from database import get_db

logger = logging.getLogger(__name__)

# ─── Flask-Login setup ────────────────────────────────────────────────────────

login_manager = LoginManager()
login_manager.login_view          = "auth_login"
login_manager.login_message       = "Please log in to access PhishyGuard."
login_manager.login_message_category = "warning"

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES     = 15


# ─── Schema ───────────────────────────────────────────────────────────────────

def init_auth_tables():
    """Create users and login_attempts tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            username       TEXT    NOT NULL UNIQUE,
            password_hash  TEXT    NOT NULL,
            role           TEXT    DEFAULT 'analyst',   -- 'admin' | 'analyst'
            email          TEXT    UNIQUE,
            email_verified INTEGER DEFAULT 0,
            is_active      INTEGER DEFAULT 1,
            created_at     TEXT    DEFAULT (datetime('now')),
            last_login     TEXT
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL,
            ip_address   TEXT,
            success      INTEGER NOT NULL,   -- 1 = success, 0 = failure
            attempted_at TEXT    DEFAULT (datetime('now'))
        );
        """)

        # Backward compatibility for old schema
        existing = conn.execute("PRAGMA table_info(users)").fetchall()
        existing_cols = {r[1] for r in existing}
        if "email" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "email_verified" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")


def create_default_admin():
    """Create the default admin user if no users exist yet."""
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            hashed = bcrypt.hashpw(
                config.DEFAULT_ADMIN_PASSWORD.encode(),
                bcrypt.gensalt(rounds=12),
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, role, email, email_verified) VALUES (?, ?, ?, ?, 1)",
                (
                    config.DEFAULT_ADMIN_USER,
                    hashed.decode(),
                    "admin",
                    os.environ.get("ADMIN_EMAIL", "admin@phishyguard.local"),
                ),
            )
            logger.info(
                "Default admin account created: username='%s'  "
                "— change this password immediately!",
                config.DEFAULT_ADMIN_USER,
            )


# ─── User model ───────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, id: int, username: str, role: str, is_active: bool):
        self.id        = id
        self.username  = username
        self.role      = role
        self._is_active = is_active

    @property
    def is_active(self):
        return self._is_active

    @staticmethod
    def get_by_id(user_id: int) -> "User | None":
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, role, is_active FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row:
            return User(row["id"], row["username"], row["role"], bool(row["is_active"]))
        return None

    @staticmethod
    def get_by_username(username: str) -> "User | None":
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, role, is_active FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row:
            return User(row["id"], row["username"], row["role"], bool(row["is_active"]))
        return None

    @staticmethod
    def verify_password(username: str, password: str) -> "User | None":
        """Returns the User if credentials are valid, else None."""
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, role, is_active "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if not row:
            return None
        try:
            ok = bcrypt.checkpw(password.encode(), row["password_hash"].encode())
        except Exception:
            return None
        if ok:
            return User(row["id"], row["username"], row["role"], bool(row["is_active"]))
        return None

    @staticmethod
    def get_user_by_email(email: str) -> "User | None":
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, role, is_active FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        if row:
            return User(row["id"], row["username"], row["role"], bool(row["is_active"]))
        return None

    def update_last_login(self):
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET last_login = datetime('now') WHERE id = ?",
                (self.id,),
            )


# ─── Lockout helpers ──────────────────────────────────────────────────────────

def _record_attempt(username: str, ip: str, success: bool):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
            (username, ip, 1 if success else 0),
        )


def _is_locked_out(username: str) -> bool:
    """True if `username` has >= MAX_FAILED_ATTEMPTS in the last LOCKOUT_MINUTES."""
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        count = conn.execute(
            """SELECT COUNT(*) FROM login_attempts
               WHERE username = ? AND success = 0
               AND attempted_at >= ?""",
            (username, cutoff),
        ).fetchone()[0]
    return count >= MAX_FAILED_ATTEMPTS


# ─── Flask-Login loader ───────────────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))


def _get_serializer():
    return URLSafeTimedSerializer(config.SECRET_KEY, salt="phishyguard-auth")


def generate_token(email: str, purpose: str) -> str:
    return _get_serializer().dumps({"email": email, "purpose": purpose})


def verify_token(token: str, purpose: str, max_age: int):
    try:
        payload = _get_serializer().loads(token, max_age=max_age)
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"
    if payload.get("purpose") != purpose:
        return None, "wrong-purpose"
    return payload, None


# ─── Route handlers (registered on the Flask app) ────────────────────────────

def register_auth_routes(app):
    """Attach auth routes to `app`. Call once in app.py."""

    def _seed_captcha():
        a = random.randint(2, 8)
        b = random.randint(2, 9)
        session["captcha_answer"] = str(a + b)
        return f"What is {a} + {b}?"

    @app.route("/login", methods=["GET", "POST"])
    def auth_login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        error = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            ip       = request.remote_addr or "unknown"

            if _is_locked_out(username):
                error = (f"Account temporarily locked after {MAX_FAILED_ATTEMPTS} "
                         f"failed attempts. Try again in {LOCKOUT_MINUTES} minutes.")
                logger.warning("Login locked out: user=%s ip=%s", username, ip)
            else:
                user = User.verify_password(username, password)
                if user and user.is_active:
                    _record_attempt(username, ip, success=True)
                    user.update_last_login()
                    login_user(user, remember=False)
                    logger.info("Login success: user=%s ip=%s", username, ip)
                    next_page = request.args.get("next") or url_for("dashboard")
                    # Safety: only allow relative redirects
                    if not next_page.startswith("/"):
                        next_page = url_for("dashboard")
                    return redirect(next_page)
                else:
                    _record_attempt(username, ip, success=False)
                    logger.warning("Login failed: user=%s ip=%s", username, ip)
                    error = "Invalid username or password."

        return render_template("login.html", error=error)

    @app.route("/register", methods=["GET", "POST"])
    def auth_register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        error = None
        success = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            confirm = request.form.get("confirm") or ""

            if not username or not email or not password:
                error = "Please fill all fields."
            elif len(password) < 8:
                error = "Password must be at least 8 characters."
            elif password != confirm:
                error = "Passwords do not match."
            else:
                with get_db() as conn:
                    existing = conn.execute(
                        "SELECT id FROM users WHERE username = ? OR email = ?",
                        (username, email),
                    ).fetchone()
                    if existing:
                        error = "Username or email already in use."
                    else:
                        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
                        conn.execute(
                            "INSERT INTO users (username, email, password_hash, role, email_verified) VALUES (?, ?, ?, ?, 0)",
                            (username, email, pw_hash, "analyst"),
                        )
                        token = generate_token(email, "verify-email")
                        verify_link = url_for("verify_email", token=token, _external=True)
                        success = (
                            "Account created. Please verify your email. "
                            f"(In this demo, open link: {verify_link})"
                        )
                        logger.info("New user registered: %s", username)

        return render_template(
            "register.html",
            error=error,
            success=success,
        )

    @app.route("/verify-email/<token>")
    def verify_email(token):
        payload, err = verify_token(token, "verify-email", max_age=86400)
        if err:
            return render_template("message.html", title="Verification Failed", message="Invalid or expired verification link.")
        email = payload.get("email")
        with get_db() as conn:
            conn.execute("UPDATE users SET email_verified = 1 WHERE email = ?", (email,))
        return render_template("message.html", title="Email Verified", message="Email verified. You can now log in.")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        error = None
        success = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            with get_db() as conn:
                row = conn.execute(
                    "SELECT email FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                if not row or not row["email"]:
                    error = "User not found or email not set."
                else:
                    email = row["email"]
                    token = generate_token(email, "reset-password")
                    reset_link = url_for("reset_password", token=token, _external=True)
                    success = (
                        "Password reset link generated. "
                        f"(In this demo, open link: {reset_link})"
                    )
        return render_template("forgot_password.html", error=error, success=success)

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token):
        payload, err = verify_token(token, "reset-password", max_age=3600)
        if err:
            return render_template("message.html", title="Reset Failed", message="Invalid or expired reset link.")
        email = payload.get("email")
        error = None
        success = None
        if request.method == "POST":
            new_pw = request.form.get("password") or ""
            confirm = request.form.get("confirm") or ""
            if len(new_pw) < 8:
                error = "Password must be at least 8 characters."
            elif new_pw != confirm:
                error = "Passwords do not match."
            else:
                hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
                with get_db() as conn:
                    conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashed, email))
                success = "Password updated. You can now log in."
        return render_template("reset_password.html", error=error, success=success, email=email)

    @app.route("/logout")
    @login_required
    def auth_logout():
        logger.info("Logout: user=%s", current_user.username)
        logout_user()
        return redirect(url_for("auth_login"))

    @app.route("/api/auth/me")
    @login_required
    def api_me():
        return jsonify({
            "success":  True,
            "username": current_user.username,
            "role":     current_user.role,
        })

    @app.route("/api/auth/change-password", methods=["POST"])
    @login_required
    def api_change_password():
        data        = request.get_json(silent=True) or {}
        old_pw      = data.get("old_password", "")
        new_pw      = data.get("new_password", "")

        if len(new_pw) < 8:
            return jsonify({"success": False,
                            "error": "New password must be at least 8 characters."}), 400

        user = User.verify_password(current_user.username, old_pw)
        if not user:
            return jsonify({"success": False, "error": "Current password is incorrect."}), 403

        new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, current_user.id),
            )
        logger.info("Password changed for user=%s", current_user.username)
        return jsonify({"success": True, "message": "Password updated."})


# ─── Decorators ───────────────────────────────────────────────────────────────

def admin_required(f):
    """Route decorator: requires the logged-in user to have role='admin'."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth_login"))
        if current_user.role != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"success": False,
                                "error": "Admin access required."}), 403
            return render_template("login.html",
                                   error="Admin access required."), 403
        return f(*args, **kwargs)
    return wrapper
