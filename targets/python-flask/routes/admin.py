"""Admin routes."""
from flask import Blueprint, jsonify, request

from data import db

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/users")
def list_all_users():
    rows = db.query_unsafe("SELECT id, username, email, role FROM users")
    return jsonify(rows)


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    db.execute_unsafe("DELETE FROM users WHERE id = %s" % user_id)
    return jsonify({"deleted": user_id})
