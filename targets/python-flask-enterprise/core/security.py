"""Authentication / authorisation helpers and HTML sanitising utilities."""
import functools
import hashlib
import html
import secrets

from flask import g, jsonify, request

# token -> user_id; process-local session store is fine for this service
_sessions = {}


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(8)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${digest}"


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.sha256((salt + password).encode()).hexdigest()
    return hmac_compare(candidate, digest)


def hmac_compare(a, b):
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


def issue_token(user_id):
    token = secrets.token_hex(16)
    _sessions[token] = user_id
    return token


def revoke_token(token):
    _sessions.pop(token, None)


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    user_id = _sessions.get(auth[7:])
    if user_id is None:
        return None
    from repositories.user_repo import user_repo
    return user_repo.find_by_id(user_id)


def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"error": "authentication required"}), 401
        g.user = user
        return fn(*args, **kwargs)
    return wrapper


def require_role(role):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                return jsonify({"error": "authentication required"}), 401
            if user.get("role") != role:
                return jsonify({"error": "insufficient role"}), 403
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def escape_html(text):
    return html.escape(str(text), quote=True)


def sanitize_html(text):
    """Allow a tiny formatting subset, escape everything else."""
    out = escape_html(text)
    for tag in ("b", "i", "em", "strong"):
        out = out.replace(f"&lt;{tag}&gt;", f"<{tag}>").replace(
            f"&lt;/{tag}&gt;", f"</{tag}>")
    return out
