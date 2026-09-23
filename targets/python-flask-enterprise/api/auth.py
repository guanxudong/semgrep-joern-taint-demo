"""Auth routes: login, logout, password reset."""
from flask import Blueprint, g, jsonify, request

from core.security import require_auth
from services.auth_service import auth_service
from utils import validators

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    try:
        validators.require_fields(payload, ["username", "password"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    token = auth_service.login(payload["username"], payload["password"])
    if not token:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": token})


@auth_bp.route("/logout", methods=["POST"])
@require_auth
def logout():
    auth = request.headers.get("Authorization", "")
    auth_service.logout(auth[7:])
    return jsonify({"ok": True})


@auth_bp.route("/me")
@require_auth
def me():
    return jsonify({k: v for k, v in g.user.items() if k != "password_hash"})


@auth_bp.route("/password-reset/request", methods=["POST"])
def request_reset():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "")
    if not validators.is_email(email):
        return jsonify({"error": "invalid email"}), 400
    auth_service.request_password_reset(email)
    # always 200 to avoid account enumeration
    return jsonify({"ok": True})


@auth_bp.route("/password-reset/confirm", methods=["POST"])
def confirm_reset():
    payload = request.get_json(silent=True) or {}
    ok = auth_service.confirm_password_reset(
        payload.get("email", ""), payload.get("token", ""),
        payload.get("new_password", ""))
    if not ok:
        return jsonify({"error": "invalid token"}), 400
    return jsonify({"ok": True})
