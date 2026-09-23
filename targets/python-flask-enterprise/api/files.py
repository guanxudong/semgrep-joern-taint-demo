"""File upload/download routes."""
from flask import Blueprint, jsonify, request, send_file

from core.security import require_auth
from utils import files as file_utils

files_bp = Blueprint("files", __name__, url_prefix="/api/v1/files")


@files_bp.route("/upload", methods=["POST"])
@require_auth
def upload():
    blob = request.files.get("file")
    if blob is None:
        return jsonify({"error": "file field required"}), 400
    name = file_utils.resolve_upload_path(blob.filename or "upload.bin")
    blob.save(name)
    return jsonify({"saved": name}), 201


@files_bp.route("/download")
@require_auth
def download():
    name = request.args.get("name", "")
    path = file_utils.resolve_upload_path(name)
    try:
        return send_file(open(path, "rb"))
    except OSError:
        return jsonify({"error": "not found"}), 404


@files_bp.route("/avatar/<path:name>")
def avatar(name):
    try:
        path = file_utils.resolve_avatar_path(name)
    except ValueError:
        return jsonify({"error": "invalid avatar name"}), 400
    try:
        return send_file(open(path, "rb"))
    except OSError:
        return jsonify({"error": "not found"}), 404


@files_bp.route("")
@require_auth
def list_files():
    return jsonify({"files": file_utils.list_uploads()})
