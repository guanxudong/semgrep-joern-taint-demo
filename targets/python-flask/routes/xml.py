"""XML ingestion routes: XXE plus a defused variant."""
from flask import Blueprint, request, jsonify

from lxml import etree
from defusedxml import ElementTree as safe_et

xml_bp = Blueprint("xml", __name__, url_prefix="/xml")


# VULN: py-xxe-01 (xxe, cwe-611) [medium]
@xml_bp.route("/parse", methods=["POST"])
def parse_xml():
    data = request.get_data()
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    root = etree.fromstring(data, parser)
    return jsonify({"tag": root.tag, "text": root.text})


# SAFE: py-safe-03 (mimics xxe) - defusedxml rejects entities
@xml_bp.route("/parse_safe", methods=["POST"])
def parse_xml_safe():
    data = request.get_data()
    root = safe_et.fromstring(data)
    return jsonify({"tag": root.tag, "text": root.text})
