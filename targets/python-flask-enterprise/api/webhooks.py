"""Webhook ingestion routes."""
import json

import yaml
from flask import Blueprint, jsonify, request

from core.security import require_role
from utils import validators

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/v1/webhooks")


@webhooks_bp.route("/import", methods=["POST"])
@require_role("staff")
def import_webhook():
    doc = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify({"received": doc})


@webhooks_bp.route("/import-json", methods=["POST"])
@require_role("staff")
def import_webhook_json():
    try:
        doc = json.loads(request.data)
        validators.require_fields(doc, ["event", "payload"])
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"received": {"event": doc["event"]}})


@webhooks_bp.route("")
@require_role("staff")
def list_webhooks():
    return jsonify({"webhooks": []})
