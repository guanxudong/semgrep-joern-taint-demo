"""Fund/position balance adjustments driven by execution reports."""
import threading

BALANCES = {"880001": 1000000.0, "880002": 500000.0}

_lock = threading.Lock()


def adjust(account, delta):
    balance = BALANCES.get(account, 0.0)
    if delta < 0 and balance + delta < 0:
        return False
    BALANCES[account] = balance + delta
    return True


def adjust_locked(account, delta):
    with _lock:
        balance = BALANCES.get(account, 0.0)
        if delta < 0 and balance + delta < 0:
            return False
        BALANCES[account] = balance + delta
        return True
