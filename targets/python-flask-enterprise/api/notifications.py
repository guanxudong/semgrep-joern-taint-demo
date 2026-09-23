"""Notification routes."""
from flask import Blueprint, jsonify, request

from core.security import require_auth, require_role
from repositories.user_repo import user_repo
from services.notification_service import notification_service

notifications_bp = Blueprint(
    "notifications", __name__, url_prefix="/api/v1/notifications")


@notifications_bp.route("/preview", methods=["POST"])
@require_role("staff")
def preview():
    payload = request.get_json(silent=True) or {}
    return jsonify({"html": notification_service.render_preview(
        str(payload.get("template", "")))})


@notifications_bp.route("/send-welcome", methods=["POST"])
@require_role("staff")
def send_welcome():
    payload = request.get_json(silent=True) or {}
    user = user_repo.find_by_id(int(payload.get("user_id", 0)))
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(notification_service.send_welcome(user))


@notifications_bp.route("")
@require_auth
def list_notifications():
    return jsonify({"notifications": []})
