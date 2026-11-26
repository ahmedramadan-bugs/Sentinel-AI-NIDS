"""
logger.py
---------------------------------------
Sentinel-AI Logger
"""

import logging
from pathlib import Path

try:  # package import used by the integrated service
    from .config import LoggerConfig, LOG_DIR, LOG_FILE
except ImportError:  # direct legacy execution from response_engine/
    from config import LoggerConfig, LOG_DIR, LOG_FILE


class EngineLogger:

    def __init__(self):

        self.logger = logging.getLogger(LoggerConfig.LOGGER_NAME)

        if self.logger.handlers:
            return

        self.logger.setLevel(LoggerConfig.LEVEL)

        formatter = logging.Formatter(
            LoggerConfig.FORMAT,
            LoggerConfig.DATE_FORMAT
        )

        if LoggerConfig.CONSOLE_LOGGING:

            console_handler = logging.StreamHandler()

            console_handler.setFormatter(formatter)

            self.logger.addHandler(console_handler)

        if LoggerConfig.FILE_LOGGING:

            Path(LOG_DIR).mkdir(exist_ok=True)

            file_handler = logging.FileHandler(
                LOG_FILE,
                encoding="utf-8"
            )

            file_handler.setFormatter(formatter)

            self.logger.addHandler(file_handler)

    # -----------------------------------

    def info(self, message):

        self.logger.info(message)

    def warning(self, message):

        self.logger.warning(message)

    def error(self, message):

        self.logger.error(message)

    def critical(self, message):

        self.logger.critical(message)

    def debug(self, message):

        self.logger.debug(message)

    # -----------------------------------

    def block(self, ip):

        self.info(f"[BLOCK] {ip}")

    def unblock(self, ip):

        self.info(f"[UNBLOCK] {ip}")

    def temp_block(self, ip, timeout):

        self.info(
            f"[TEMP BLOCK] {ip} ({timeout}s)"
        )

    def auto_unblock(self, ip):

        self.info(
            f"[AUTO UNBLOCK] {ip}"
        )

    def whitelist(self, ip):

        self.warning(
            f"[WHITELIST] {ip}"
        )

    def connection(self, host):

        self.info(
            f"[CONNECT] {host}"
        )

    def disconnect(self):

        self.info("[DISCONNECT]")

    def exception(self, ex):

        self.error(str(ex))
