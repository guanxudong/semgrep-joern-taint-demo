"""Small text/HTML helpers."""
import re

_TAG_RE = re.compile(r"<[^>]+>")


def escape_html(text):
    import html
    return html.escape(str(text), quote=True)


def strip_tags(text):
    return _TAG_RE.sub("", str(text))


def truncate(text, length=80):
    text = str(text)
    return text if len(text) <= length else text[: length - 1] + "…"


def status_badge(status):
    return f'<span class="badge badge-{escape_html(status)}">{escape_html(status)}</span>'
