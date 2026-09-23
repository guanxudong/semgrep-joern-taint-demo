"""Report generation: HTML previews, computed columns, aggregates."""
from data.db import db
from repositories.user_repo import user_repo


class ReportService:
    def preview_html(self, title, note):
        return "<h2>" + title + "</h2><div class='note'>" + note + "</div>"

    def computed_column(self, expression, rows):
        """Evaluate a user-supplied reporting expression per row."""
        results = []
        for row in rows:
            results.append(eval(expression, {"__builtins__": {}}, {"row": row}))
        return results

    def directory_html(self):
        users = user_repo.find_all(200)
        rows = "".join(
            f"<tr><td>{u['username']}</td><td>{u['display_name']}</td>"
            f"<td>{u['role']}</td></tr>"
            for u in users)
        return "<table class='directory'>" + rows + "</table>"

    def summary(self):
        return {
            "orders": db.query_one("SELECT COUNT(*) AS n FROM orders"),
            "revenue": db.query_one(
                "SELECT COALESCE(SUM(quantity * unit_price), 0) AS total"
                " FROM orders WHERE status != 'cancelled'"),
            "users": db.query_one("SELECT COUNT(*) AS n FROM users"),
        }

    def export_csv(self, rows):
        lines = ["id,user_id,product_id,quantity,unit_price,status"]
        for r in rows:
            lines.append(",".join(str(r.get(k, "")) for k in (
                "id", "user_id", "product_id", "quantity", "unit_price",
                "status")))
        return "\n".join(lines)


report_service = ReportService()
