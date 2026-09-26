"""User lookup logic."""
from data import db


class UserService:
    def __init__(self):
        self._pending_name = ""

    def stage_name(self, name):
        """Store the given name in a field."""
        self._pending_name = name

    def find_staged(self):
        """Read the staged field and run the lookup."""
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
