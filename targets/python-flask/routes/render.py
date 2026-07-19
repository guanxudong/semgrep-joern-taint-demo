"""Rendering routes: SSTI and reflected XSS."""
from flask import Blueprint, request, render_template_string

render_bp = Blueprint("render", __name__, url_prefix="/render")


# VULN: py-ssti-01 (ssti, cwe-1336) [medium]
@render_bp.route("/preview")
def preview():
    tpl = request.args.get("tpl", "")
    return render_template_string(tpl)


# VULN: py-xss-01 (xss, cwe-79) [shallow]
@render_bp.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"
