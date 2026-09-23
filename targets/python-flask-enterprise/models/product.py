"""Product / inventory model."""
from dataclasses import dataclass


@dataclass
class Product:
    id: int = 0
    sku: str = ""
    name: str = ""
    price: float = 0.0
    stock: int = 0

    def to_dict(self):
        return {
            "id": self.id,
            "sku": self.sku,
            "name": self.name,
            "price": self.price,
            "stock": self.stock,
        }
