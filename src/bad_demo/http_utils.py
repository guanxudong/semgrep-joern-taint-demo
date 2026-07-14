"""HTTP clients with SSRF sinks (A10:2021)."""

import requests


def fetch_url(url):
    """Fetch an arbitrary user-controlled URL.

    Taint source -> url -> network sink.
    """
    # A10:2021 - Server-Side Request Forgery (SSRF)
    response = requests.get(url, timeout=5)
    return response.text


def fetch_metadata(service):
    """Fetch cloud metadata after minimal allow-list bypass."""
    # A10:2021 - SSRF via partial allow-list
    base = "http://169.254.169.254/latest/meta-data/"
    response = requests.get(base + service, timeout=5)
    return response.text
