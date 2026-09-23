"""Invoice import routes (XML + JSON)."""
from flask import Blueprint, jsonify, request
from lxml import etree

from core.security import require_auth, require_role
from repositories.invoice_repo import invoice_repo
from utils import crypto

invoices_bp = Blueprint("invoices", __name__, url_prefix="/api/v1/invoices")


def _parse_invoice_xml(raw):
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    root = etree.fromstring(raw, parser)
    return {
        "order_id": int(root.findtext("order_id", "0")),
        "amount": float(root.findtext("amount", "0")),
        "issued_to": root.findtext("issued_to", ""),
    }


def _parse_invoice_xml_hardened(raw):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    root = etree.fromstring(raw, parser)
    return {
        "order_id": int(root.findtext("order_id", "0")),
        "amount": float(root.findtext("amount", "0")),
        "issued_to": root.findtext("issued_to", ""),
    }


@invoices_bp.route("")
@require_auth
def list_invoices():
    return jsonify(invoice_repo.find_all(200))


@invoices_bp.route("/import", methods=["POST"])
@require_role("manager")
def import_invoice():
    data = _parse_invoice_xml(request.data)
    invoice_no = crypto.generate_invoice_no()
    invoice_repo.insert_invoice(
        data["order_id"], invoice_no, data["amount"], data["issued_to"])
    return jsonify({"invoice_no": invoice_no}), 201


@invoices_bp.route("/preview-xml", methods=["POST"])
@require_role("manager")
def preview_invoice():
    try:
        data = _parse_invoice_xml_hardened(request.data)
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": f"invalid xml: {exc}"}), 400
    return jsonify(data)
