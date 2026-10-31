"""Bootstrap: register bus subscribers and directory watchers."""
from config import settings
from handlers import executions, notifications, reconciliation, settlement
from ingest import bus, watcher


def main():
    bus.subscribe("execution.report", executions.on_execution_report)
    bus.subscribe("execution.report_safe", executions.on_execution_report_safe)
    bus.subscribe("reconcile.diff", reconciliation.on_diff_query)
    bus.subscribe("reconcile.diff_safe", reconciliation.on_diff_query_safe)
    bus.subscribe("reconcile.request", reconciliation.on_request)
    bus.subscribe("reconcile.request_safe", reconciliation.on_request_safe)
    bus.subscribe("alert.rule", reconciliation.on_alert_rule)
    bus.subscribe("snapshot.load", reconciliation.on_load_snapshot)
    bus.subscribe("ops.run_batch", reconciliation.on_run_batch)
    bus.subscribe("reconcile.done", reconciliation.on_reconcile_done)
    bus.subscribe("notify.send", notifications.on_notify)
    watcher.watch(settings.INBOX_DIR, settlement.on_settlement_file)
    watcher.watch(settings.INBOX_DIR + "_safe", settlement.on_settlement_file_safe)
    watcher.scan_once()


if __name__ == "__main__":
    main()
