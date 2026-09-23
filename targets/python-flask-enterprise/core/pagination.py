"""Pagination helpers shared by list endpoints."""
from flask import request

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def page_params():
    try:
        limit = min(int(request.args.get("limit", DEFAULT_PAGE_SIZE)), MAX_PAGE_SIZE)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        limit, offset = DEFAULT_PAGE_SIZE, 0
    return limit, offset
