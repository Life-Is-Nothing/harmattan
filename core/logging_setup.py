"""Structured logging for HARMATTAN."""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from core.config import DATA_DIR, ensure_dirs


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    ensure_dirs()
    logger = logging.getLogger("harmattan")
    if logger.handlers:
        return logger

    logger.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    log_path = Path(DATA_DIR) / "harmattan.log"
    try:
        fh = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        pass

    # Quiet noisy libs
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logger


def get_logger(name: str = "harmattan") -> logging.Logger:
    return logging.getLogger(name)
