"""Inventory routes."""
from flask import Blueprint, jsonify, request

from core.security import require_auth, require_role
from services.inventory_service import inventory_service
from repositories.product_repo import product_repo

inventory_bp = Blueprint("inventory", __name__, url_prefix="/api/v1/inventory")


@inventory_bp.route("")
@require_auth
def list_inventory():
    return jsonify(inventory_service.list_inventory())


@inventory_bp.route("/<int:product_id>")
@require_auth
def get_product(product_id):
    product = product_repo.find_by_id(product_id)
    if not product:
        return jsonify({"error": "not found"}), 404
    return jsonify(product)


@inventory_bp.route("/search")
@require_auth
def search_products():
    name = request.args.get("name", "")
    return jsonify(product_repo.search_by_name(name))


@inventory_bp.route("/<int:product_id>/adjust", methods=["POST"])
@require_role("manager")
def adjust_stock(product_id):
    payload = request.get_json(silent=True) or {}
    quantity = int(payload.get("quantity", 0))
    result = inventory_service.adjust_stock(product_id, quantity)
    if result is None:
        return jsonify({"error": "not found"}), 404
    if "error" in result:
        return jsonify(result), 409
    return jsonify(result)


@inventory_bp.route("/<int:product_id>/reserve", methods=["POST"])
@require_auth
def reserve_stock(product_id):
    payload = request.get_json(silent=True) or {}
    quantity = int(payload.get("quantity", 0))
    if quantity <= 0:
        return jsonify({"error": "quantity must be positive"}), 400
    result = inventory_service.reserve_stock(product_id, quantity)
    if "error" in result:
        return jsonify(result), 409
    return jsonify(result)
