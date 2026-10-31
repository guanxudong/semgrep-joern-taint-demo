"""Alert-rule evaluation over settlement and market data."""


def evaluate(expr, data):
    return eval(expr, {"__builtins__": {}}, {"data": data})
