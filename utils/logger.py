import logging
import os

os.makedirs("logs", exist_ok=True)

def setup_logger(name, log_file="logs/scanner.log", level=logging.INFO):
    """Setup and return a logger instance."""
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger
