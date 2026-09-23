"""Reporting routes: previews, computed columns, exports."""
from flask import Blueprint, Response, jsonify, request

from core.security import require_auth, require_role
from repositories.order_repo import order_repo
from services.report_service import report_service

reports_bp = Blueprint("reports", __name__, url_prefix="/api/v1/reports")


@reports_bp.route("/preview")
@require_auth
def preview():
    title = request.args.get("title", "Report")
    note = request.args.get("note", "")
    return report_service.preview_html(title, note)


@reports_bp.route("/computed", methods=["POST"])
@require_role("analyst")
def computed():
    payload = request.get_json(silent=True) or {}
    expression = payload.get("expression", "0")
    rows = order_repo.find_where({}, limit=50)
    return jsonify({"results": report_service.computed_column(expression, rows)})


@reports_bp.route("/directory")
@require_auth
def directory():
    return report_service.directory_html()


@reports_bp.route("/summary")
@require_auth
def summary():
    return jsonify(report_service.summary())


@reports_bp.route("/export")
@require_role("manager")
def export():
    rows = order_repo.find_where({}, limit=1000)
    csv_text = report_service.export_csv(rows)
    return Response(csv_text, mimetype="text/csv")
