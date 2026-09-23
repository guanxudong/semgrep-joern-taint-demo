"""Environment-driven configuration."""
import os


class Config:
    SECRET_KEY = os.environ.get("ORDERFLOW_SECRET", "dev-secret-change-me")
    DB_PATH = os.environ.get("ORDERFLOW_DB", "data/orderflow.db")
    UPLOAD_DIR = os.environ.get("ORDERFLOW_UPLOADS", "data/uploads")
    AVATAR_DIR = os.environ.get("ORDERFLOW_AVATARS", "data/avatars")
    SESSION_TTL_MINUTES = 30
    RESET_TOKEN_TTL_MINUTES = 15
    RATE_LIMIT_PER_MINUTE = 120
    MAX_UPLOAD_BYTES = 8 * 1024 * 1024
    DEFAULT_PAGE_SIZE = 50


class DevConfig(Config):
    DEBUG = True


class ProdConfig(Config):
    DEBUG = False


_PROFILES = {"dev": DevConfig, "prod": ProdConfig}


def get_config():
    profile = os.environ.get("ORDERFLOW_ENV", "dev")
    return _PROFILES.get(profile, DevConfig)
