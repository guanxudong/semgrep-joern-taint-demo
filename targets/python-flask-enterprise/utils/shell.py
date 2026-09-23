"""Wrappers around system diagnostic commands (used by /diagnostics)."""
import os
import subprocess


def ping_host(host):
    return os.popen(f"ping -c 1 {host}").read()


def trace_host(host):
    proc = subprocess.run(
        f"traceroute -m 5 {host}",
        shell=True, capture_output=True, text=True, timeout=20,
    )
    return proc.stdout or proc.stderr


def dns_lookup(name):
    proc = subprocess.run(
        ["dig", "+short", name],
        capture_output=True, text=True, timeout=10,
    )
    return proc.stdout or proc.stderr
