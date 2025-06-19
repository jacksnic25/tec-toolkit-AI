import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(name: str, log_file: Optional[str] = None) -> logging.Logger:
    """Configure structured logging"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Formatting
    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # File handler (if specified)
    if log_file:
        Path(log_file).parent.mkdir(exist_ok=True)
        file = logging.FileHandler(log_file)
        file.setFormatter(fmt)
        logger.addHandler(file)

    return logger
