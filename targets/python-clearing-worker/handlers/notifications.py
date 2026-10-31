"""Ops notification handler."""
from services import archive_service, notify_service


def on_notify(msg):
    payload = msg.payload
    if "template" in payload:
        return notify_service.render_notice(payload["template"], payload)
    if payload.get("defer"):
        archive_service.archive_svc.stage_alert(payload["title"])
        archive_service.archive_svc.send_staged_alert()
        return None
    archive_service.notify_ops(payload["title"])
    return None
