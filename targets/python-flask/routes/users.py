"""User account routes."""
from flask import Blueprint, request, jsonify

from data import db
from services.user_service import user_service

users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db.query_unsafe(f"SELECT id, username FROM users WHERE username LIKE '%{q}%'")
    return jsonify(rows)


@users_bp.route("/lookup")
def lookup():
    name = request.args.get("name", "")
    user_service.stage_name(name)
    rows = user_service.find_staged()
    return jsonify(rows)


@users_bp.route("/<int:user_id>")
def get_user(user_id):
    rows = user_service.find_by_id(user_id)
    return jsonify(rows)


@users_bp.route("/search_safe")
def search_safe():
    q = request.args.get("q", "")
    rows = db.query_safe("SELECT id, username FROM users WHERE username LIKE ?", ("%" + q + "%",))
    return jsonify(rows)


@users_bp.route("/me/<int:user_id>")
def get_own_profile(user_id):
    session_user = int(request.headers.get("X-User-Id", "-1"))
    if session_user != user_id:
        return jsonify({"error": "forbidden"}), 403
    rows = user_service.find_by_id_safe(user_id)
    return jsonify(rows)
