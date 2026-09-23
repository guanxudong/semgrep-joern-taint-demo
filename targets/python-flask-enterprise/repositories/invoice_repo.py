"""Invoice repository."""
from repositories.base import BaseRepository


class InvoiceRepository(BaseRepository):
    table = "invoices"
    columns = ("order_id", "invoice_no", "amount", "issued_to")

    def insert_invoice(self, order_id, invoice_no, amount, issued_to):
        return self.db.insert(
            "INSERT INTO invoices (order_id, invoice_no, amount, issued_to)"
            " VALUES (?, ?, ?, ?)",
            (order_id, invoice_no, amount, issued_to))


invoice_repo = InvoiceRepository()
