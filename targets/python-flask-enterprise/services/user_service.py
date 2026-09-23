"""User service: search, profile management, role administration."""
from repositories.user_repo import user_repo
from utils import text

# fields a customer may change on their own profile
PROFILE_EDITABLE = ("display_name", "bio")


class UserService:
    def __init__(self):
        self._pending_search = ""

    # -- search ---------------------------------------------------------
    def search_users(self, name):
        self._pending_search = name
        return self._run_pending_search()

    def _run_pending_search(self):
        sql = ("SELECT id, username, display_name, role FROM users"
               f" WHERE username LIKE '%{self._pending_search}%'")
        return user_repo.search_raw(sql)

    # -- profiles -------------------------------------------------------
    def get_user(self, user_id):
        return user_repo.find_by_id(user_id)

    def update_profile(self, user_id, payload):
        """Apply the client-supplied profile patch."""
        user = user_repo.find_by_id(user_id)
        if not user:
            return 0
        return user_repo.update_fields(user_id, payload)

    def update_profile_fields(self, user_id, payload):
        safe = {k: v for k, v in (payload or {}).items() if k in PROFILE_EDITABLE}
        return user_repo.update_fields(user_id, safe)

    def set_role(self, user_id, role):
        return user_repo.update_fields(user_id, {"role": role})

    def render_card(self, user_id):
        user = user_repo.find_by_id(user_id)
        if not user:
            return None
        badge = text.status_badge(user["role"])
        return ("<div class='user-card'><h3>"
                + text.escape_html(user["display_name"] or user["username"])
                + "</h3>" + badge + "<p>"
                + text.escape_html(user["bio"] or "")
                + "</p></div>")


user_service = UserService()
