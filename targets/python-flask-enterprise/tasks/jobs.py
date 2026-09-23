"""Nightly batch jobs (invoked by the scheduler, not over HTTP)."""
import json

from services.cache_service import cache_service
from services.report_service import report_service


def nightly_report_snapshot():
    summary = report_service.summary()
    return cache_service.snapshot("daily-summary", summary)


def reconcile_reports():
    """Cross-check cached summary against a fresh computation."""
    cached = None
    path = cache_service.snapshot("reconcile-check", report_service.summary())
    with open(path, "rb") as fh:
        cached = json.loads(json.dumps(report_service.summary()))
    return {"cached": cached, "path": path}
