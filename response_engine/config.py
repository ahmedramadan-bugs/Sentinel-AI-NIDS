"""
config.py
---------------------------------------
Sentinel-AI Configuration
Version : 1.0

هذا الملف هو المكان الوحيد الذي يتم فيه تعديل
الإعدادات الخاصة بالمشروع.
"""

import os
from pathlib import Path
from dataclasses import dataclass


# ==========================================================
# Project Paths
# ==========================================================

# Keep legacy locations by default, while allowing test/deployment instances to
# isolate their action history from the source tree.
PROJECT_ROOT = Path(os.getenv("NIDS_RESPONSE_DATA_DIR", Path(__file__).resolve().parent))

DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = PROJECT_ROOT / "logs"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

WHITELIST_FILE = DATA_DIR / "whitelist.json"
ACTION_HISTORY_FILE = DATA_DIR / "history.json"
TEMP_BLOCKS_FILE = DATA_DIR / "temp_blocks.json"
LOG_FILE = LOG_DIR / "response_engine.log"


# ==========================================================
# Cisco Configuration
# ==========================================================

@dataclass(frozen=True)
class CiscoConfig:

    DEVICE_TYPE: str = "cisco_ios"

    HOST: str = os.getenv("NIDS_CISCO_HOST", "")

    USERNAME: str = os.getenv("NIDS_CISCO_USERNAME", "")

    PASSWORD: str = os.getenv("NIDS_CISCO_PASSWORD", "")

    SECRET: str = os.getenv("NIDS_CISCO_SECRET", "")

    ACL_NAME: str = os.getenv("NIDS_CISCO_ACL_NAME", "IDS-BLOCK")

    CONNECTION_TIMEOUT: int = 10

    READ_TIMEOUT: int = 20

    FAST_CLI: bool = False


# ==========================================================
# Response Engine Configuration
# ==========================================================

@dataclass(frozen=True)
class EngineConfig:

    # Default temporary block duration
    DEFAULT_TEMP_BLOCK: int = 300

    # Verify every action after execution
    VERIFY_AFTER_ACTION: bool = True

    # Enable log file
    ENABLE_LOGGING: bool = True

    # Save history.json
    ENABLE_ACTION_HISTORY: bool = True

    AUTO_SAVE_HISTORY: bool = True

    # Threading
    THREAD_SAFE: bool = True

    MAX_WORKERS: int = 4

    QUEUE_SIZE: int = 1000

    # Cisco
    AUTO_CREATE_ACL: bool = True

    VERIFY_CONNECTION_ON_STARTUP: bool = False

    # Debug
    # Safety default: no device configuration is attempted unless explicitly
    # enabled in an approved environment via NIDS_RESPONSE_DRY_RUN=false.
    DRY_RUN: bool = os.getenv("NIDS_RESPONSE_DRY_RUN", "true").strip().lower() in {
        "1", "true", "yes", "on"
    }

    # Limits
    MAX_HISTORY_SIZE: int = 10000


# ==========================================================
# Logger
# ==========================================================

@dataclass(frozen=True)
class LoggerConfig:

    LOGGER_NAME: str = "Sentinel-AI"

    LEVEL: str = "INFO"

    FORMAT: str = (
        "%(asctime)s | "
        "%(levelname)-8s | "
        "%(message)s"
    )

    DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

    FILE_LOGGING: bool = True

    CONSOLE_LOGGING: bool = True


# ==========================================================
# Messages
# ==========================================================

class Messages:

    BLOCK_SUCCESS = "IP blocked successfully."

    TEMP_BLOCK_SUCCESS = "Temporary block created."

    UNBLOCK_SUCCESS = "IP unblocked successfully."

    ALREADY_BLOCKED = "IP already blocked."

    NOT_BLOCKED = "IP is not blocked."

    WHITELISTED = "IP exists in whitelist."

    INVALID_IP = "Invalid IP address."

    CONNECTION_FAILED = "Cisco connection failed."

    VERIFICATION_FAILED = "Verification failed."

    UNKNOWN_ERROR = "Unexpected error occurred."


# ==========================================================
# Event Names
# ==========================================================

class Events:

    BLOCK = "block"

    TEMP_BLOCK = "temporary_block"

    UNBLOCK = "unblock"

    AUTO_UNBLOCK = "auto_unblock"


# ==========================================================
# Default Response Template
# ==========================================================

DEFAULT_RESPONSE = {

    "success": False,

    "action": None,

    "ip": None,

    "message": "",

    "verified": False,

    "timestamp": None,

    "details": {}
}


def configure_runtime(*, dry_run: bool = True, data_dir: Path | None = None) -> None:
    """Set safe runtime options before constructing a ResponseEngine.

    This keeps the legacy response module usable from its original directory
    while allowing the integrated pipeline to enforce dry-run policy.
    """
    EngineConfig.DRY_RUN = bool(dry_run)
    if data_dir is not None:
        global DATA_DIR, WHITELIST_FILE, ACTION_HISTORY_FILE, TEMP_BLOCKS_FILE
        DATA_DIR = Path(data_dir)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        WHITELIST_FILE = DATA_DIR / "whitelist.json"
        ACTION_HISTORY_FILE = DATA_DIR / "history.json"
        TEMP_BLOCKS_FILE = DATA_DIR / "temp_blocks.json"
