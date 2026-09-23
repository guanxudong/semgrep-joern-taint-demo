"""Order model."""
from dataclasses import dataclass


@dataclass
class Order:
    id: int = 0
    user_id: int = 0
    product_id: int = 0
    quantity: int = 0
    unit_price: float = 0.0
    status: str = "pending"
    note: str = ""

    @property
    def total(self):
        return round(self.quantity * self.unit_price, 2)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "quantity": self.quantity,
            "unit_price": self.unit_price,
            "total": self.total,
            "status": self.status,
            "note": self.note,
        }
