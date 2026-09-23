"""Filesystem path resolution for uploads and avatars."""
import os
from pathlib import Path

UPLOAD_DIR = Path(os.environ.get("ORDERFLOW_UPLOADS", "data/uploads"))
AVATAR_DIR = Path(os.environ.get("ORDERFLOW_AVATARS", "data/avatars"))


def resolve_upload_path(name):
    """Normalise a user-supplied name inside the upload directory."""
    path = os.path.normpath(os.path.join(str(UPLOAD_DIR), name))
    return path


def resolve_avatar_path(name):
    """Avatars are public, so confine strictly to the avatar directory."""
    base = AVATAR_DIR.resolve()
    full = (base / os.path.basename(name)).resolve()
    if not str(full).startswith(str(base) + os.sep):
        raise ValueError("avatar path escapes avatar directory")
    return str(full)


def list_uploads():
    if not UPLOAD_DIR.exists():
        return []
    return sorted(p.name for p in UPLOAD_DIR.iterdir() if p.is_file())
