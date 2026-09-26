"""Auth routes."""
import hashlib

import jwt
from flask import Blueprint, request, jsonify

import config

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    token = jwt.encode({"sub": username, "role": "user"}, config.JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@auth_bp.route("/reset", methods=["POST"])
def request_reset():
    username = request.json.get("username", "")
    token = hashlib.md5(username.encode()).hexdigest()[:8]
    return jsonify({"reset_token": token})
