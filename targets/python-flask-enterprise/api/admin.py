"""Admin routes: audit log, role management, cache restore."""
from flask import Blueprint, jsonify, request

from core.security import require_auth, require_role
from data.db import db
from services.cache_service import cache_service
from services.user_service import user_service

admin_bp = Blueprint("admin", __name__, url_prefix="/api/v1/admin")


@admin_bp.route("/audit-log")
def audit_log():
    rows = db.query(
        "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (200,))
    return jsonify(rows)


@admin_bp.route("/promote", methods=["POST"])
@require_auth
def promote():
    payload = request.get_json(silent=True) or {}
    updated = user_service.set_role(
        int(payload.get("user_id", 0)), str(payload.get("role", "")))
    return jsonify({"updated": updated})


@admin_bp.route("/cache/restore", methods=["POST"])
@require_role("admin")
def restore_cache():
    snapshot = cache_service.restore(request.data)
    return jsonify({"restored": sorted(snapshot.keys())
                    if isinstance(snapshot, dict) else "ok"})


@admin_bp.route("/users")
@require_role("admin")
def list_all_users():
    rows = db.query("SELECT id, username, email, role, is_active FROM users")
    return jsonify(rows)


@admin_bp.route("/stats")
@require_role("admin")
def stats():
    return jsonify({
        "users": db.query_one("SELECT COUNT(*) AS n FROM users"),
        "orders": db.query_one("SELECT COUNT(*) AS n FROM orders"),
        "audit": db.query_one("SELECT COUNT(*) AS n FROM audit_log"),
    })
