"""File download routes: path traversal plus a whitelisted variant."""
from flask import Blueprint, request, jsonify

from services import file_service

files_bp = Blueprint("files", __name__, url_prefix="/files")


# VULN: py-path-traversal-01 (path-traversal, cwe-22) [medium]
@files_bp.route("/download")
def download():
    name = request.args.get("name", "")
    content = file_service.read_user_file(name)
    return jsonify({"content": content})


# SAFE: py-safe-04 (mimics path-traversal) - whitelist validation
@files_bp.route("/download_safe")
def download_safe():
    name = request.args.get("name", "")
    try:
        content = file_service.read_whitelisted(name)
    except ValueError:
        return jsonify({"error": "file not allowed"}), 400
    return jsonify({"content": content})
