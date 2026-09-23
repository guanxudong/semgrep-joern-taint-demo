"""Network diagnostics service (admin tooling)."""
from utils import shell


class DiagnosticsService:
    def __init__(self):
        self._target = ""

    def ping(self, host):
        return shell.ping_host(host)

    def trace(self, host):
        self._target = host
        return self._run_trace()

    def _run_trace(self):
        return shell.trace_host(self._target)

    def dns(self, name):
        return shell.dns_lookup(name)


diagnostics_service = DiagnosticsService()
