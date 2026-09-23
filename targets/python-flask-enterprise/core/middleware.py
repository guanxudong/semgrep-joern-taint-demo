"""Request middleware: request ids, rate limiting, audit logging."""
import time
import uuid
from collections import defaultdict, deque

from flask import g, jsonify, request

from data.db import db

_RATE_BUCKETS = defaultdict(deque)
_RATE_EXEMPT_PREFIXES = ("/api/v1/auth/",)  # login endpoints must stay reachable
_WINDOW_SECONDS = 60
_MAX_PER_WINDOW = 120


def _rate_limited(ip):
    if request.path.startswith(_RATE_EXEMPT_PREFIXES):
        return False
    now = time.time()
    bucket = _RATE_BUCKETS[ip]
    while bucket and bucket[0] < now - _WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= _MAX_PER_WINDOW:
        return True
    bucket.append(now)
    return False


def init_middleware(app):
    @app.before_request
    def _before():
        g.request_id = uuid.uuid4().hex[:12]
        if _rate_limited(request.remote_addr or "unknown"):
            return jsonify({"error": "rate limit exceeded"}), 429

    @app.after_request
    def _after(response):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                db.execute(
                    "INSERT INTO audit_log (request_id, method, path, status, ts)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (g.get("request_id", "-"), request.method, request.path,
                     response.status_code, int(time.time())),
                )
            except Exception:
                app.logger.warning("audit log write failed")
        response.headers["X-Request-Id"] = g.get("request_id", "-")
        return response
