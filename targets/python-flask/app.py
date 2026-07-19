"""Entry point: registers all blueprints (overview of all HTTP entrypoints)."""
from flask import Flask

from routes.users import users_bp
from routes.admin import admin_bp
from routes.files import files_bp
from routes.tools import tools_bp
from routes.xml import xml_bp
from routes.render import render_bp
from routes.auth import auth_bp
from routes.orders import orders_bp
from routes.profile import profile_bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(users_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(xml_bp)
    app.register_blueprint(render_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(profile_bp)
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000, debug=True)
