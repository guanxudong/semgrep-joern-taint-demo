"""Application factory."""
from flask import Flask, jsonify

from api import register_blueprints
from config.logging_conf import init_logging
from config.settings import get_config
from core.errors import register_error_handlers
from core.middleware import init_middleware


def create_app():
    app = Flask(__name__)
    app.config.from_object(get_config()())
    init_logging(app)
    init_middleware(app)
    register_error_handlers(app)
    register_blueprints(app)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/v1/version")
    def version():
        return jsonify({"name": "orderflow", "version": "1.4.2"})

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
