"""Report snapshot cache (pickle-based)."""
import pickle
from pathlib import Path

CACHE_DIR = Path("data/cache")


class CacheService:
    def snapshot(self, name, payload):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = CACHE_DIR / f"{name}.pkl"
        path.write_bytes(pickle.dumps(payload))
        return str(path)

    def restore(self, raw):
        return pickle.loads(raw)


cache_service = CacheService()
