import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify

from db import create_user, find_user_by_email

auth_bp = Blueprint("auth", __name__)

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-prod")
JWT_EXP_MINUTES = int(os.environ.get("JWT_EXP_MINUTES", "60"))


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required."}), 400

    existing = find_user_by_email(email)
    if existing:
        return jsonify({"error": "User already exists."}), 400

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user = {"email": email, "password_hash": pw_hash, "created_at": datetime.utcnow()}
    uid = create_user(user)
    return jsonify({"user_id": uid}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required."}), 400

    user = find_user_by_email(email)
    if not user:
        return jsonify({"error": "Invalid credentials."}), 401

    pw_hash = user.get("password_hash", "").encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), pw_hash):
        return jsonify({"error": "Invalid credentials."}), 401

    payload = {
        "sub": str(user.get("_id")),
        "email": user.get("email"),
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"access_token": token})
