"""Reconciliation request handlers."""
import hashlib

from config import settings
from ingest import uploader
from repositories import recon_repo
from services import notify_service, recon_service, rule_engine


def _token_ok(account, trade_date, token):
    expected = hashlib.md5(f"{account}|{trade_date}".encode()).hexdigest()
    return token == expected


def on_diff_query(msg):
    account = msg.payload["account"]
    rows = recon_repo.find_unmatched(account)
    return rows


def on_diff_query_safe(msg):
    account = msg.payload["account"]
    return recon_repo.find_unmatched_safe(account)


def on_request(msg):
    payload = msg.payload
    if not _token_ok(payload["account"], payload["date"], msg.headers.get("token", "")):
        return None
    rows = recon_service._svc.get_statement(payload["account"])
    uploader.put(settings.SFTP_HOST, settings.SFTP_USER, settings.SFTP_PASSWORD,
                 payload["account"], rows)
    return rows


def on_request_safe(msg):
    payload = msg.payload
    if msg.headers.get("requester") != payload["account"]:
        return None
    return recon_service._svc.get_statement(payload["account"])


def on_alert_rule(msg):
    expr = msg.payload["expr"]
    return rule_engine.evaluate(expr, msg.payload["data"])


def on_load_snapshot(msg):
    return recon_service.load_snapshot(msg.payload["blob"])


def on_run_batch(msg):
    return recon_service._svc.run_full_reconcile(msg.payload["date"])


def on_reconcile_done(msg):
    return notify_service.render_result_email(
        msg.payload["account"], msg.payload["rows"])
