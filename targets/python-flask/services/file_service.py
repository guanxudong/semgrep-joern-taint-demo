"""File retrieval logic."""
import os

import config

ALLOWED_FILES = {"readme.txt", "help.txt"}


def read_user_file(name):
    """Concatenates user-controlled name into a filesystem path (sink)."""
    path = os.path.join(config.UPLOAD_DIR, name)
    with open(path, "r") as f:
        return f.read()


def read_whitelisted(name):
    if name not in ALLOWED_FILES:
        raise ValueError("file not allowed")
    path = os.path.join(config.UPLOAD_DIR, name)
    with open(path, "r") as f:
        return f.read()
