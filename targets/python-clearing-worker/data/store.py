"""Sqlite access helpers."""
import sqlite3

from config import settings


def get_conn():
    return sqlite3.connect(settings.DB_PATH)


def query_unsafe(sql):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(sql)
        return cur.fetchall()
    finally:
        conn.close()


def query_safe(sql, params):
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
