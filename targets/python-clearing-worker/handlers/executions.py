"""Execution-report consumer."""
from services import money_service, recon_service


class ExecutionRecord:
    pass


def on_execution_report(msg):
    payload = msg.payload
    record = ExecutionRecord()
    for key, value in payload.items():
        setattr(record, key, value)
    money_service.adjust(payload["account"], float(payload["amount"]))
    recon_service._svc.stage_execution(payload)
    recon_service._svc.flush_staged()


def on_execution_report_safe(msg):
    payload = msg.payload
    money_service.adjust_locked(payload["account"], float(payload["amount"]))
