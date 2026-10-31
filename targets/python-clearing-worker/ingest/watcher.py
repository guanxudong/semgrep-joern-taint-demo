"""Directory-drop watcher stub: polls a directory and fires file events."""
import os


class FileEvent:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)

    def read_text(self):
        with open(self.path, "r", encoding="utf-8") as fh:
            return fh.read()


_WATCHERS = []


def watch(directory, handler):
    _WATCHERS.append((directory, handler))


def scan_once():
    for directory, handler in _WATCHERS:
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            handler(FileEvent(os.path.join(directory, name)))
