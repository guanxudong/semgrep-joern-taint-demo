"""Reconciliation staging, settlement booking and statement lookup."""
import pickle


def load_snapshot(blob):
    return pickle.loads(blob)


class ReconService:
    """Stages execution reports and books reconciliation adjustments."""

    def __init__(self):
        self._pending_account = None
        self._pending_symbol = None
        self._pending_amount = None
        self._processed_files = set()
        self.operator_role = "clerk"

    def stage_execution(self, payload):
        self._pending_account = payload["account"]
        self._pending_symbol = payload["symbol"]
        self._pending_amount = float(payload["amount"])

    def flush_staged(self):
        if self._pending_account is None:
            return
        from repositories import recon_repo
        recon_repo.insert_record(
            self._pending_account, self._pending_symbol, self._pending_amount)
        self._pending_account = None

    def get_statement(self, account):
        from repositories import recon_repo
        return recon_repo.find_statement(account)

    def apply_settlement(self, file_id, rows):
        from services import money_service
        for row in rows:
            diff = row["settled"] - row["expected"]
            if abs(diff) <= 0.01:
                money_service.adjust("ROUNDING", diff)
        self._processed_files.add(file_id)

    def set_operator(self, role):
        self.operator_role = role

    def admin_adjust(self, rows):
        from services import money_service
        for row in rows:
            money_service.adjust(row["account"], row["settled"] - row["expected"])

    def run_full_reconcile(self, trade_date):
        from repositories import recon_repo
        return recon_repo.find_unmatched_safe(trade_date)


_svc = ReconService()
