"""Rendering routes."""
from flask import Blueprint, request, render_template_string

render_bp = Blueprint("render", __name__, url_prefix="/render")


@render_bp.route("/preview")
def preview():
    tpl = request.args.get("tpl", "")
    return render_template_string(tpl)


@render_bp.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"
