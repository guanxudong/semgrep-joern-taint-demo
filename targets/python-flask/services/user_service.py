"""User lookup logic; holds tainted input in an instance field between calls."""
from data import db


class UserService:
    def __init__(self):
        self._pending_name = ""

    def stage_name(self, name):
        """Store user-controlled input in a field (taint via field)."""
        self._pending_name = name

    def find_staged(self):
        """Reads the staged field and reaches the sink (deep chain end)."""
        sql = "SELECT id, username, email FROM users WHERE username = '%s'" % self._pending_name
        return db.query_unsafe(sql)

    def find_by_name(self, name):
        sql = "SELECT id, username, email FROM users WHERE username = '%s'" % name
        return db.query_unsafe(sql)

    def find_by_id(self, user_id):
        sql = "SELECT id, username, email, role FROM users WHERE id = %s" % user_id
        return db.query_unsafe(sql)

    def find_by_id_safe(self, user_id):
        return db.query_safe("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))


user_service = UserService()
