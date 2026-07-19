"""Diagnostic tool routes: command injection (shallow + deep) and RCE."""
import os

from flask import Blueprint, request, jsonify

from services.tool_service import tool_service

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")


# VULN: py-cmdi-01 (cmdi, cwe-78) [shallow]
@tools_bp.route("/ping")
def ping():
    host = request.args.get("host", "")
    rc = os.system("ping -c 1 " + host)
    return jsonify({"rc": rc})


# VULN: py-cmdi-02 (cmdi, cwe-78) [deep, taint via instance field]
@tools_bp.route("/diagnose")
def diagnose():
    host = request.args.get("host", "")
    tool_service.stage_target(host)
    rc = tool_service.run_staged_diag()
    return jsonify({"rc": rc})


# VULN: py-rce-01 (rce, cwe-94) [medium]
@tools_bp.route("/calc", methods=["POST"])
def calc():
    expr = request.json.get("expr", "0")
    result = eval(expr)
    return jsonify({"result": result})
