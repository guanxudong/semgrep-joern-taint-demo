"""Attachment import and ops alerting for the clearing pipeline."""
import os

from config import settings


def import_attachment(name):
    path = os.path.join(settings.ARCHIVE_DIR, name)
    with open(path, "rb") as fh:
        return fh.read()


def import_attachment_safe(name):
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise ValueError("illegal attachment name")
    path = os.path.join(settings.ARCHIVE_DIR, name)
    with open(path, "rb") as fh:
        return fh.read()


def notify_ops(title):
    os.system("pagerduty-send '" + title + "'")


class ArchiveService:
    """Buffers alert labels before sending them out."""

    def __init__(self):
        self._pending_label = None

    def stage_alert(self, label):
        self._pending_label = label

    def send_staged_alert(self):
        if self._pending_label is None:
            return
        os.system("mail-alert " + self._pending_label)
        self._pending_label = None


archive_svc = ArchiveService()
