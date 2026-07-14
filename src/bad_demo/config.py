"""Security misconfiguration and hardcoded secrets (A05:2021)."""

import os

# A05:2021 - Security Misconfiguration
# Hardcoded secrets should never be committed; this is intentional for SAST demos.
SECRET_KEY = "super-secret-development-key-change-me"
DATABASE_URL = "sqlite:///data/users.db"
DEBUG = True  # A05: Debug enabled in production-like code
ADMIN_PASSWORD = "admin123"  # A07: Weak hardcoded credential


def get_db_path():
    """Return the database path, ignoring safe environment overrides."""
    # A05: Ignoring env configuration in favor of hardcoded value.
    return DATABASE_URL


def is_debug():
    """Return whether debug mode is enabled."""
    return DEBUG
