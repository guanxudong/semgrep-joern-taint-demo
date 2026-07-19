"""User routes: SQL injection (shallow + deep), IDOR, plus safe counter-examples."""
from flask import Blueprint, request, jsonify

from data import db
from services.user_service import user_service

users_bp = Blueprint("users", __name__, url_prefix="/users")


# VULN: py-sqli-01 (sqli, cwe-89) [shallow]
@users_bp.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db.query_unsafe(f"SELECT id, username FROM users WHERE username LIKE '%{q}%'")
    return jsonify(rows)


# VULN: py-sqli-02 (sqli, cwe-89) [deep, taint via instance field]
@users_bp.route("/lookup")
def lookup():
    name = request.args.get("name", "")
    user_service.stage_name(name)
    rows = user_service.find_staged()
    return jsonify(rows)


# VULN: py-idor-01 (idor, cwe-639)
@users_bp.route("/<int:user_id>")
def get_user(user_id):
    rows = user_service.find_by_id(user_id)
    return jsonify(rows)


# SAFE: py-safe-01 (mimics sqli) - parameterized query
@users_bp.route("/search_safe")
def search_safe():
    q = request.args.get("q", "")
    rows = db.query_safe("SELECT id, username FROM users WHERE username LIKE ?", ("%" + q + "%",))
    return jsonify(rows)


# SAFE: py-safe-02 (mimics idor) - ownership checked against session user
@users_bp.route("/me/<int:user_id>")
def get_own_profile(user_id):
    session_user = int(request.headers.get("X-User-Id", "-1"))
    if session_user != user_id:
        return jsonify({"error": "forbidden"}), 403
    rows = user_service.find_by_id_safe(user_id)
    return jsonify(rows)
