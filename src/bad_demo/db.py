"""Database helpers with intentional injection sinks (A03:2021)."""

import sqlite3

from bad_demo.config import get_db_path


def get_connection():
    """Open a SQLite connection."""
    db_path = get_db_path().replace("sqlite:///", "")
    return sqlite3.connect(db_path)


def find_user_unsafe(username, password):
    """Authenticate a user using string-concatenated SQL.

    Taint source -> username/password -> SQL sink.
    """
    conn = get_connection()
    cursor = conn.cursor()
    # A03:2021 - SQL Injection via f-string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row


def search_users_unsafe(term):
    """Search users with an injected ORDER BY clause.

    Demonstrates cross-file taint from HTTP parameter to ORDER BY sink.
    """
    conn = get_connection()
    cursor = conn.cursor()
    # A03:2021 - SQL Injection in ORDER BY (often missed by simple scanners)
    query = "SELECT id, username FROM users WHERE username LIKE '%" + term + "%'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return rows


def delete_user_unsafe(user_id):
    """Delete a user by id without parameterization."""
    conn = get_connection()
    cursor = conn.cursor()
    # A03:2021 - SQL Injection
    cursor.execute("DELETE FROM users WHERE id = " + str(user_id))
    conn.commit()
    conn.close()
