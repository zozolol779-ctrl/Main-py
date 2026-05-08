import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler

# Ensure logs directory exists
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "red_king.log")

def get_logger(name: str):
    """
    Returns a configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if get_logger is called multiple times
    if logger.hasHandlers():
        return logger

    # 1. Console Handler (Rich)
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_time=True,
        show_path=False
    )
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_format)

    # 2. File Handler (Rotating)
    # 10MB max size, keep 5 backups
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_format)

    # Add Handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

# Create centralized logger for the core app
logger = get_logger("RED_KING_CORE")
