"""Central configuration — one place for every setting. Safe defaults; no
hardcoded user paths. Override via a .env-style environment if desired."""
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent.parent


def _path(env_key, default):
    raw = os.getenv(env_key)
    return Path(raw).resolve() if raw else default


class Settings:
    HOST = os.getenv("RODE_HOST", "127.0.0.1")
    PORT = int(os.getenv("RODE_PORT", "8000"))
    DATA_DIR = _path("RODE_DATA_DIR", ROOT / "data")
    WORKSPACE_DIR = _path("RODE_WORKSPACE_DIR", ROOT / "workspace")
    WORDLISTS_DIR = _path("RODE_WORDLISTS_DIR", ROOT / "wordlists")
    DATABASE_URL = os.getenv("RODE_DATABASE_URL", "")
    MAX_OUTPUT_CHARS = int(os.getenv("RODE_MAX_OUTPUT_CHARS", "500000"))
    TOOL_TIMEOUT_SEC = int(os.getenv("RODE_TOOL_TIMEOUT_SEC", "900"))
    CONFIRM_FROM_NOISE = os.getenv("RODE_CONFIRM_FROM_NOISE", "loud")

    def __init__(self):
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
        self.WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
        if not self.DATABASE_URL:
            db = (self.DATA_DIR / "rode.db").as_posix()
            self.DATABASE_URL = f"sqlite:///{db}"


settings = Settings()
