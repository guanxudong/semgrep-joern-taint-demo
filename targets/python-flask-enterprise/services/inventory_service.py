"""Inventory service: stock adjustments."""
from repositories.product_repo import product_repo


class InventoryService:
    def adjust_stock(self, product_id, quantity):
        """Decrease stock after checking availability."""
        product = product_repo.find_by_id(product_id)
        if not product:
            return None
        if product["stock"] < quantity:
            return {"error": "insufficient stock"}
        new_stock = product["stock"] - quantity
        product_repo.set_stock(product_id, new_stock)
        return {"product_id": product_id, "stock": new_stock}

    def reserve_stock(self, product_id, quantity):
        """Atomic reservation: single conditional UPDATE."""
        updated = product_repo.decrease_stock_atomic(product_id, quantity)
        if not updated:
            return {"error": "insufficient stock"}
        product = product_repo.find_by_id(product_id)
        return {"product_id": product_id, "stock": product["stock"]}

    def list_inventory(self, limit=200):
        return product_repo.find_all(limit)


inventory_service = InventoryService()
