"""Tiny logging helper — writes to data/logs and the console."""
import logging
from .config import settings

_configured = False


def get_logger(name: str) -> logging.Logger:
    global _configured
    if not _configured:
        log_dir = settings.DATA_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(log_dir / "rode.log", encoding="utf-8"),
            ],
        )
        _configured = True
    return logging.getLogger(f"rode.{name}")
