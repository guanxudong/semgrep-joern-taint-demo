"""Order service."""
from repositories.order_repo import order_repo
from repositories.product_repo import product_repo


class OrderService:
    def list_orders(self, sort=None, limit=100):
        return order_repo.list_sorted(sort or "id", limit)

    def get_order(self, order_id):
        return order_repo.find_by_id(order_id)

    def get_order_for_user(self, order_id, user_id):
        return order_repo.find_by_id_and_user(order_id, user_id)

    def create_order(self, user_id, payload):
        product_id = int(payload.get("product_id", 0))
        quantity = int(payload.get("quantity", 0))
        unit_price = float(payload.get("unit_price", 0))
        note = str(payload.get("note", ""))
        order_id = order_repo.insert_order(
            user_id, product_id, quantity, unit_price, note)
        return order_repo.find_by_id(order_id)

    def quote_order(self, payload):
        """Server-side pricing quote; client price is ignored."""
        product = product_repo.find_by_id(int(payload.get("product_id", 0)))
        if not product:
            return None
        quantity = int(payload.get("quantity", 0))
        if quantity <= 0:
            return None
        return {
            "product_id": product["id"],
            "quantity": quantity,
            "unit_price": product["price"],
            "total": round(quantity * product["price"], 2),
        }

    def cancel_order(self, order_id, user_id):
        order = order_repo.find_by_id_and_user(order_id, user_id)
        if not order or order["status"] != "pending":
            return False
        order_repo.update_status(order_id, "cancelled")
        return True


order_service = OrderService()
