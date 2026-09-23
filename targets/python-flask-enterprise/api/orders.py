"""Order routes."""
from flask import Blueprint, g, jsonify, request

from core.pagination import page_params
from core.security import require_auth
from services.order_service import order_service

orders_bp = Blueprint("orders", __name__, url_prefix="/api/v1/orders")


@orders_bp.route("")
@require_auth
def list_orders():
    sort = request.args.get("sort", "id")
    limit, _offset = page_params()
    return jsonify(order_service.list_orders(sort, limit))


@orders_bp.route("/<int:order_id>")
@require_auth
def get_order(order_id):
    order = order_service.get_order(order_id)
    if not order:
        return jsonify({"error": "not found"}), 404
    return jsonify(order)


@orders_bp.route("/<int:order_id>/receipt")
@require_auth
def get_receipt(order_id):
    order = order_service.get_order_for_user(order_id, g.user["id"])
    if not order:
        return jsonify({"error": "not found"}), 404
    return jsonify(order)


@orders_bp.route("", methods=["POST"])
@require_auth
def create_order():
    payload = request.get_json(silent=True) or {}
    order = order_service.create_order(g.user["id"], payload)
    return jsonify(order), 201


@orders_bp.route("/quote", methods=["POST"])
@require_auth
def quote_order():
    payload = request.get_json(silent=True) or {}
    quote = order_service.quote_order(payload)
    if quote is None:
        return jsonify({"error": "invalid quote request"}), 400
    return jsonify(quote)


@orders_bp.route("/<int:order_id>/cancel", methods=["POST"])
@require_auth
def cancel_order(order_id):
    if not order_service.cancel_order(order_id, g.user["id"]):
        return jsonify({"error": "cannot cancel"}), 409
    return jsonify({"ok": True})
