"""ClearFlow clearing worker settings."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_PATH = os.path.join(BASE_DIR, "data", "clearflow.db")
INBOX_DIR = os.path.join(BASE_DIR, "drop", "inbox")
ARCHIVE_DIR = os.path.join(BASE_DIR, "drop", "archive")

MQ_ENDPOINT = "rv://bus.clearflow.local:7500"
SFTP_HOST = "sftp.csdcc.local"
SFTP_USER = "clearflow"
SFTP_PASSWORD = "clearflow123"

TOKEN_SECRET = "clearflow-secret"
TOLERANCE = 0.01
