"""JSON error handlers."""
from flask import jsonify


def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(_err):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_err):
        return jsonify({"error": "method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error(_err):
        return jsonify({"error": "internal server error"}), 500
