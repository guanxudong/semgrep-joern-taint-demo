"""Diagnostic command helpers; taint stored in a field between calls."""
import os


class ToolService:
    def __init__(self):
        self._target = ""

    def stage_target(self, host):
        self._target = host

    def run_staged_diag(self):
        cmd = "ping -c 1 " + self._target
        return os.system(cmd)


tool_service = ToolService()
