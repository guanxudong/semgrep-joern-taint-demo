"""SQLite access layer.

Two API tiers on purpose: `query`/`execute` take bound parameters, while
`query_raw`/`execute_raw` accept a complete SQL string for the (few) legacy
callers that still assemble SQL by hand.
"""
import sqlite3
import threading
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "orderflow.db"


class Database:
    def __init__(self, path=DB_PATH):
        self._path = str(path)
        self._local = threading.local()

    def connect(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def query(self, sql, params=()):
        cur = self.connect().execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def query_one(self, sql, params=()):
        cur = self.connect().execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

    def execute(self, sql, params=()):
        conn = self.connect()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.rowcount

    def query_raw(self, sql):
        cur = self.connect().execute(sql)
        return [dict(r) for r in cur.fetchall()]

    def execute_raw(self, sql):
        conn = self.connect()
        cur = conn.execute(sql)
        conn.commit()
        return cur.rowcount

    def insert(self, sql, params=()):
        conn = self.connect()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid


db = Database()
