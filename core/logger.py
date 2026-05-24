import logging
import os
import sys
from logging.handlers import RotatingFileHandler

if getattr(sys, 'frozen', False):
    _BASE_DIR = os.path.dirname(sys.executable)
else:
    _BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = "app.log"
LOG_PATH = os.path.join(_BASE_DIR, LOG_FILE)


def setup_logging():
    log_dir = os.path.dirname(LOG_PATH)
    os.makedirs(log_dir, exist_ok=True)

    handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s [%(threadName)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)

    return LOG_PATH
