"""Command execution sinks (A03:2021 - Injection)."""

import os
import subprocess


def run_ping(hostname):
    """Ping a user-supplied hostname via os.system.

    Taint source -> hostname -> command sink.
    """
    # A03:2021 - OS Command Injection
    command = "ping -c 1 " + hostname
    os.system(command)


def run_lookup(hostname):
    """Run nslookup using shell=True."""
    # A03:2021 - OS Command Injection
    subprocess.run("nslookup " + hostname, shell=True, check=True)


def run_convert(filename, options):
    """Execute an external tool with user-controlled arguments."""
    # A03:2021 - Command injection through options
    cmd = ["convert", filename] + options.split()
    subprocess.call(cmd)
