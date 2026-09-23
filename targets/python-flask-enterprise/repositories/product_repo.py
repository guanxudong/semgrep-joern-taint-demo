"""Product / inventory repository."""
from repositories.base import BaseRepository


class ProductRepository(BaseRepository):
    table = "products"
    columns = ("sku", "name", "price", "stock")

    def search_by_name(self, name):
        return self.db.query(
            "SELECT * FROM products WHERE name LIKE ? LIMIT ?",
            ("%" + name + "%", 100))

    def set_stock(self, product_id, new_stock):
        return self.db.execute(
            "UPDATE products SET stock = ? WHERE id = ?", (new_stock, product_id))

    def decrease_stock_atomic(self, product_id, quantity):
        return self.db.execute(
            "UPDATE products SET stock = stock - ?"
            " WHERE id = ? AND stock >= ?",
            (quantity, product_id, quantity))


product_repo = ProductRepository()
