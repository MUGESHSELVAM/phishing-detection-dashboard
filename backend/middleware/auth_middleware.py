import os
import jwt
from functools import wraps
from flask import request, jsonify, g
from db import get_db, get_db as _get_db
from db import get_user_by_id

SECRET = os.environ.get("JWT_SECRET", "change-me-in-prod")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()

        if not token:
            return jsonify({"error": "Token is missing."}), 401
        try:
            data = jwt.decode(token, SECRET, algorithms=["HS256"])
            user_id = data.get("sub")
            if not user_id:
                return jsonify({"error": "Invalid token."}), 401
            user = get_user_by_id(user_id)
            if not user:
                return jsonify({"error": "User not found."}), 401
            # attach user info to flask.g
            g.current_user = {
                "id": str(user.get("_id")),
                "email": user.get("email")
            }
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired."}), 401
        except Exception:
            return jsonify({"error": "Token is invalid."}), 401
        return f(*args, **kwargs)

    return decorated
