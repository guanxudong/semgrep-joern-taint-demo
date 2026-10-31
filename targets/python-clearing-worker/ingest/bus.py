"""Message-bus stub with subject-based subscription."""
import json


class Message:
    def __init__(self, subject, headers, payload):
        self.subject = subject
        self.headers = headers
        self.payload = payload

    @classmethod
    def from_raw(cls, subject, raw):
        envelope = json.loads(raw)
        return cls(subject, envelope.get("headers", {}), envelope.get("payload", {}))


_HANDLERS = {}


def subscribe(subject, handler):
    _HANDLERS.setdefault(subject, []).append(handler)


def publish(subject, raw):
    for handler in _HANDLERS.get(subject, []):
        handler(Message.from_raw(subject, raw))
