"""Order/wallet routes: business-logic bypass, race condition, safe variant."""
from flask import Blueprint, request, jsonify

from services import order_service

orders_bp = Blueprint("orders", __name__, url_prefix="/orders")


# VULN: py-business-logic-01 (business-logic, cwe-840) - negative amount accepted
@orders_bp.route("/transfer", methods=["POST"])
def transfer():
    body = request.json
    new_balance = order_service.transfer(body["src"], body["dst"], float(body["amount"]))
    return jsonify({"balance": new_balance})


# VULN: py-business-logic-01 (business-logic, cwe-840) - coupon never invalidated
@orders_bp.route("/coupon", methods=["POST"])
def coupon():
    body = request.json
    ok = order_service.apply_coupon(body["user"], body["coupon"])
    return jsonify({"applied": ok})


# VULN: py-race-condition-01 (race-condition, cwe-367)
@orders_bp.route("/withdraw", methods=["POST"])
def withdraw():
    body = request.json
    ok = order_service.withdraw(body["user"], float(body["amount"]))
    return jsonify({"ok": ok})


# SAFE: py-safe-05 (mimics race-condition) - lock-protected withdraw
@orders_bp.route("/withdraw_safe", methods=["POST"])
def withdraw_safe():
    body = request.json
    ok = order_service.withdraw_safe(body["user"], float(body["amount"]))
    return jsonify({"ok": ok})
