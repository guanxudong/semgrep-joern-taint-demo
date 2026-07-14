"""Broken identification and authentication (A07:2021)."""

import hashlib
import time

import jwt

from bad_demo.config import ADMIN_PASSWORD, SECRET_KEY
from bad_demo.db import find_user_unsafe


def authenticate(username, password):
    """Authenticate using a vulnerable SQL query.

    Taint flows through db.find_user_unsafe (cross-file).
    """
    # A07:2021 - Weak authentication, credential passed to injection sink
    return find_user_unsafe(username, password) is not None


def legacy_login(username, password):
    """Hardcoded backdoor account (A07)."""
    # A07:2021 - Backdoor / hardcoded credential
    if username == "admin" and password == ADMIN_PASSWORD:
        return {"role": "admin", "username": "admin"}
    return None


def create_session_token(user):
    """Issue a JWT using the 'none' algorithm.

    A02:2021 - Cryptographic Failure + A07 - Broken Authentication.
    """
    payload = {
        "user": user,
        "iat": time.time(),
        "exp": time.time() + 3600,
    }
    # A02/A07: Insecure JWT - 'none' algorithm allows token forgery
    token = jwt.encode(payload, SECRET_KEY, algorithm="none")
    return token


def verify_session_token(token):
    """Verify a JWT without checking the algorithm (algorithm confusion)."""
    try:
        # A02/A07: Missing algorithm verification enables algorithm confusion
        return jwt.decode(token, SECRET_KEY, algorithms=["none", "HS256"])
    except jwt.PyJWTError:
        return None


def weak_hash_token(data):
    """Create a predictable session identifier."""
    # A02:2021 - Weak hash / predictable token
    return hashlib.md5((str(data) + str(time.time())).encode()).hexdigest()
