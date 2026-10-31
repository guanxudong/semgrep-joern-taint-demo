"""Recon-record persistence."""
from data import store


def find_unmatched(account):
    sql = f"SELECT * FROM recon_diffs WHERE account = '{account}' AND matched = 0"
    return store.query_unsafe(sql)


def find_unmatched_safe(account):
    return store.query_safe(
        "SELECT * FROM recon_diffs WHERE account = ? AND matched = 0", (account,))


def find_statement(account):
    return store.query_safe(
        "SELECT * FROM fund_statements WHERE account = ?", (account,))


def insert_record(account, symbol, amount):
    sql = (
        "INSERT INTO recon_diffs (account, symbol, amount, matched) "
        f"VALUES ('{account}', '{symbol}', {amount}, 0)"
    )
    store.execute_unsafe(sql)
