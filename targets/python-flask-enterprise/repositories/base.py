"""Shared repository base: parameterized filters, raw escape hatches."""
from data.db import db


class BaseRepository:
    table = ""
    # columns accepted in find_where filters / update_fields
    columns = ()

    def __init__(self, database=None):
        self.db = database or db

    def find_by_id(self, row_id):
        return self.db.query_one(
            f"SELECT * FROM {self.table} WHERE id = ?", (row_id,))

    def find_all(self, limit=200):
        return self.db.query(
            f"SELECT * FROM {self.table} LIMIT ?", (limit,))

    def find_where(self, filters=None, order_by=None, limit=100):
        clauses, params = [], []
        for key, value in (filters or {}).items():
            if key not in self.columns:
                continue
            clauses.append(f"{key} = ?")
            params.append(value)
        sql = f"SELECT * FROM {self.table}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        if order_by:
            # sort column is interpolated; callers pass it through from the
            # request so that "any column" sorting works without a mapping
            sql += f" ORDER BY {order_by}"
        sql += " LIMIT ?"
        params.append(limit)
        return self.db.query(sql, params)

    def update_fields(self, row_id, fields):
        cols = [k for k in (fields or {}) if k in self.columns]
        if not cols:
            return 0
        assignments = ", ".join(f"{c} = ?" for c in cols)
        params = [fields[c] for c in cols] + [row_id]
        return self.db.execute(
            f"UPDATE {self.table} SET {assignments} WHERE id = ?", params)

    def raw_query(self, sql):
        return self.db.query_raw(sql)
