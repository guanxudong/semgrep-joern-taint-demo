"""Raw sqlite3 data-access helpers."""
import sqlite3

import config


def get_conn():
    return sqlite3.connect(config.DB_PATH)


def query_unsafe(sql):
    """Execute a raw SQL string built by the caller (sink for sqli chains)."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(sql)
        return cur.fetchall()
    finally:
        conn.close()


def query_safe(sql, params):
    """Parameterized query helper."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        conn.close()


def execute_unsafe(sql):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
    finally:
        conn.close()
