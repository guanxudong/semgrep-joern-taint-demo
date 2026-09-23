"""Diagnostics routes (admin tooling)."""
from flask import Blueprint, jsonify, request

from core.security import require_role
from services.diagnostics_service import diagnostics_service

diagnostics_bp = Blueprint(
    "diagnostics", __name__, url_prefix="/api/v1/diagnostics")


@diagnostics_bp.route("/ping")
@require_role("admin")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return jsonify({"output": diagnostics_service.ping(host)})


@diagnostics_bp.route("/trace")
@require_role("admin")
def trace():
    host = request.args.get("host", "127.0.0.1")
    return jsonify({"output": diagnostics_service.trace(host)})


@diagnostics_bp.route("/dns")
@require_role("admin")
def dns():
    name = request.args.get("name", "localhost")
    return jsonify({"output": diagnostics_service.dns(name)})
