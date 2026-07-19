"""Auth routes: weak JWT secret and predictable reset token."""
import hashlib

import jwt
from flask import Blueprint, request, jsonify

import config

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# VULN: py-auth-flaws-01 (auth-flaws, cwe-287)
@auth_bp.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    # no lockout / rate limiting; any credentials issue a token
    token = jwt.encode({"sub": username, "role": "user"}, config.JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


# VULN: py-auth-flaws-01 (auth-flaws, cwe-287) - predictable reset token
@auth_bp.route("/reset", methods=["POST"])
def request_reset():
    username = request.json.get("username", "")
    token = hashlib.md5(username.encode()).hexdigest()[:8]
    return jsonify({"reset_token": token})
