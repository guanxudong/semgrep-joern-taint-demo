"""Cryptographic failures (A02:2021)."""

import hashlib
import random


def hash_password_md5(password):
    """Hash a password with MD5 - broken and fast to crack."""
    # A02:2021 - Weak cryptographic hash
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1_no_salt(password):
    """SHA1 without salt."""
    # A02:2021 - Weak hash, no salt
    return hashlib.sha1(password.encode()).hexdigest()


def generate_pin():
    """Generate a short numeric PIN using non-cryptographic RNG."""
    # A02:2021 - Insecure randomness
    return random.randint(1000, 9999)


def encrypt_xor(plaintext, key="key"):
    """Trivial XOR cipher - not encryption."""
    # A02:2021 - Broken / home-grown crypto
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(plaintext))
