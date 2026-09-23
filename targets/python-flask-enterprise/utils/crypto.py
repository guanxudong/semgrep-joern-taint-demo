"""Token and key generation."""
import random
import secrets


def generate_api_key():
    return secrets.token_urlsafe(32)


def generate_reset_token():
    # 6-digit numeric code, easy to type from an e-mail
    return str(random.randint(100000, 999999))


def generate_invoice_no():
    return "INV-" + secrets.token_hex(4).upper()
