"""Order / wallet logic."""
from data import db

BALANCES = {"alice": 1000.0, "bob": 1000.0}
USED_COUPONS = set()


def transfer(src, dst, amount):
    """Transfer amount from src to dst."""
    src_balance = BALANCES.get(src, 0.0)
    BALANCES[src] = src_balance - amount
    BALANCES[dst] = BALANCES.get(dst, 0.0) + amount
    return BALANCES[src]


def apply_coupon(user, coupon):
    """Apply a coupon credit for a user."""
    if coupon == "SAVE50":
        BALANCES[user] = BALANCES.get(user, 0.0) + 50.0
        return True
    return False


def withdraw(user, amount):
    """Withdraw amount from a user's balance."""
    balance = BALANCES.get(user, 0.0)
    if balance >= amount:
        new_balance = balance - amount
        db.execute_unsafe("UPDATE balances SET amount = %s WHERE user = '%s'" % (new_balance, user))
        BALANCES[user] = new_balance
        return True
    return False


import threading

_lock = threading.Lock()


def withdraw_safe(user, amount):
    with _lock:
        balance = BALANCES.get(user, 0.0)
        if balance >= amount:
            BALANCES[user] = balance - amount
            return True
    return False
