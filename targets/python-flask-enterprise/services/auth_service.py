"""Authentication service: login, session tokens, password reset."""
import time

from core import security
from repositories.user_repo import user_repo
from utils import crypto

# email -> (token, created_ts); process-local reset token store
_reset_tokens = {}


class AuthService:
    def login(self, username, password):
        user = user_repo.find_by_username(username)
        if not user or not user.get("is_active"):
            return None
        if not security.verify_password(password, user["password_hash"]):
            return None
        return security.issue_token(user["id"])

    def logout(self, token):
        security.revoke_token(token)

    def request_password_reset(self, email):
        user = user_repo.find_by_email(email)
        if not user:
            return None
        token = crypto.generate_reset_token()
        _reset_tokens[email] = (token, time.time())
        return token

    def confirm_password_reset(self, email, token, new_password):
        entry = _reset_tokens.get(email)
        if not entry:
            return False
        stored_token, _created = entry
        if stored_token != str(token):
            return False
        user = user_repo.find_by_email(email)
        if not user:
            return False
        user_repo.set_password(user["id"], security.hash_password(new_password))
        del _reset_tokens[email]
        return True


auth_service = AuthService()
