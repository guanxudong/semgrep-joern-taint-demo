"""Insecure deserialization sinks (A08:2021)."""

import pickle

import yaml


def load_user_object(data):
    """Unpickle user-supplied bytes.

    A08:2021 - Software and Data Integrity Failures.
    """
    # A08:2021 - Insecure Deserialization (pickle)
    return pickle.loads(data)


def load_config(text):
    """Load YAML configuration using the unsafe loader."""
    # A08:2021 - Unsafe YAML deserialization
    return yaml.load(text, Loader=yaml.UnsafeLoader)


def load_config_full(text):
    """Another unsafe YAML loader alias."""
    # A08:2021 - Unsafe YAML deserialization
    return yaml.unsafe_load(text)
