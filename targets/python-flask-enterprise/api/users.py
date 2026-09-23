"""User routes: search, profiles, cards."""
from flask import Blueprint, g, jsonify, request

from core.pagination import page_params
from core.security import require_auth, require_role
from repositories.user_repo import user_repo
from services.user_service import user_service

users_bp = Blueprint("users", __name__, url_prefix="/api/v1/users")


@users_bp.route("/search")
@require_auth
def search():
    name = request.args.get("q", "")
    return jsonify(user_service.search_users(name))


@users_bp.route("/<int:user_id>")
@require_auth
def get_user(user_id):
    user = user_service.get_user(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    user.pop("password_hash", None)
    return jsonify(user)


@users_bp.route("/<int:user_id>/card")
@require_auth
def user_card(user_id):
    card = user_service.render_card(user_id)
    if card is None:
        return jsonify({"error": "not found"}), 404
    return card


@users_bp.route("/me", methods=["PATCH"])
@require_auth
def update_me():
    payload = request.get_json(silent=True) or {}
    updated = user_service.update_profile(g.user["id"], payload)
    return jsonify({"updated": updated})


@users_bp.route("/me/profile", methods=["PATCH"])
@require_auth
def update_me_profile():
    payload = request.get_json(silent=True) or {}
    updated = user_service.update_profile_fields(g.user["id"], payload)
    return jsonify({"updated": updated})


@users_bp.route("")
@require_auth
def list_users():
    limit, _offset = page_params()
    rows = user_repo.find_all(limit)
    for row in rows:
        row.pop("password_hash", None)
    return jsonify(rows)


@users_bp.route("/<int:user_id>/deactivate", methods=["POST"])
@require_role("admin")
def deactivate(user_id):
    updated = user_repo.update_fields(user_id, {"is_active": False})
    return jsonify({"updated": updated})
