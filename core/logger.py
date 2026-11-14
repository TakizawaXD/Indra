"""
GOJO INFINITY SECURITY ∞ — LOGGING SUBSYSTEM
Provides high-performance, colorized, and thread-safe structured logging.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from core.config import settings

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

class GojoColorFormatter(logging.Formatter):
    # ANSI Colors
    CYAN = "\033[36m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: BLUE,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: PURPLE + BOLD,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        msg = super().format(record)
        return f"{color}{msg}{self.RESET}"

def setup_logger(name: str = "gojo") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

    # Avoid duplicate handlers if already configured
    if logger.handlers:
        return logger

    # Console Handler (UTF-8 so Windows cp1252 consoles do not crash on "∞")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    console_handler.setFormatter(GojoColorFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(console_handler)

    # File Handler (Rotating: 10MB x 5 backups)
    log_file = settings.LOGS_DIR / "gojo_infinity.log"
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(file_handler)

    # Do not propagate to root logger
    logger.propagate = False
    return logger

def set_console_level(level: int) -> None:
    """Changes only the on-screen verbosity; the log file keeps every record."""
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, RotatingFileHandler):
            handler.setLevel(level)


# Primary Default Logger
logger = setup_logger("six_eyes")
