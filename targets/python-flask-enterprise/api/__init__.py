"""Blueprint registry."""


def register_blueprints(app):
    from api.admin import admin_bp
    from api.auth import auth_bp
    from api.diagnostics import diagnostics_bp
    from api.files import files_bp
    from api.inventory import inventory_bp
    from api.invoices import invoices_bp
    from api.notifications import notifications_bp
    from api.orders import orders_bp
    from api.reports import reports_bp
    from api.users import users_bp
    from api.webhooks import webhooks_bp

    for bp in (auth_bp, users_bp, orders_bp, inventory_bp, reports_bp,
               files_bp, invoices_bp, admin_bp, diagnostics_bp,
               notifications_bp, webhooks_bp):
        app.register_blueprint(bp)
