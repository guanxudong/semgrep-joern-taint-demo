"""Security logging and monitoring failures (A09:2021)."""

import logging

logger = logging.getLogger("bad_demo")


def log_login(username, password, success):
    """Log authentication attempts, including sensitive credentials.

    A09:2021 - Sensitive data in logs.
    """
    # A09:2021 - Logging sensitive information
    logger.info("Login attempt: user=%s password=%s success=%s", username, password, success)


def log_error(msg):
    """Log an error without context or incident id."""
    # A09:2021 - Insufficient logging
    logger.error(msg)
