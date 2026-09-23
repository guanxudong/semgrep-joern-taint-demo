"""User repository."""
from repositories.base import BaseRepository


class UserRepository(BaseRepository):
    table = "users"
    columns = ("username", "email", "role", "display_name", "bio", "is_active")

    def find_by_username(self, username):
        return self.db.query_one(
            "SELECT * FROM users WHERE username = ?", (username,))

    def find_by_email(self, email):
        return self.db.query_one(
            "SELECT * FROM users WHERE email = ?", (email,))

    def search_raw(self, sql):
        return self.raw_query(sql)

    def set_password(self, user_id, password_hash):
        return self.db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id))


user_repo = UserRepository()
