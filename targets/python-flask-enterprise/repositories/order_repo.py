"""Order repository."""
from repositories.base import BaseRepository


class OrderRepository(BaseRepository):
    table = "orders"
    columns = ("user_id", "product_id", "quantity", "unit_price", "status", "note")

    def list_sorted(self, sort, limit=100):
        return self.find_where({}, order_by=sort, limit=limit)

    def find_by_id_and_user(self, order_id, user_id):
        return self.db.query_one(
            "SELECT * FROM orders WHERE id = ? AND user_id = ?",
            (order_id, user_id))

    def insert_order(self, user_id, product_id, quantity, unit_price, note):
        return self.db.insert(
            "INSERT INTO orders (user_id, product_id, quantity, unit_price,"
            " status, note) VALUES (?, ?, ?, ?, 'pending', ?)",
            (user_id, product_id, quantity, unit_price, note))

    def update_status(self, order_id, status):
        return self.db.execute(
            "UPDATE orders SET status = ? WHERE id = ?", (status, order_id))


order_repo = OrderRepository()
