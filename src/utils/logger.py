"""
Logging setup for SCAMLENS AI
Logs to console and to logs/scamlens.log file.
"""

import logging
import sys
from src.config import LOGS_DIR


def get_logger(name: str = "SCAMLENS") -> logging.Logger:
    """Configures and returns a structured logger instance."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # File Handler
        log_file = LOGS_DIR / "scamlens.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
