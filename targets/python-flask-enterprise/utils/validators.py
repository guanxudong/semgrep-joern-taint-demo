"""Request payload validators."""
import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


def is_email(value):
    return bool(EMAIL_RE.match(str(value or "")))


def is_username(value):
    return bool(USERNAME_RE.match(str(value or "")))


def is_positive_int(value):
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


def require_fields(payload, fields):
    missing = [f for f in fields if payload.get(f) in (None, "")]
    if missing:
        raise ValueError("missing fields: " + ", ".join(missing))
    return payload
