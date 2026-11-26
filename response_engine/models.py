"""
models.py
---------------------------------------
Sentinel-AI Models

Contains all data models used by
Response Engine.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict


# ==========================================================
# Generic Action Result
# ==========================================================

@dataclass
class ActionResult:

    success: bool

    action: str

    ip: str

    message: str = ""

    verified: bool = False

    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    details: Dict = field(default_factory=dict)

    def to_dict(self):

        return asdict(self)


# ==========================================================
# Blocked IP
# ==========================================================

@dataclass
class BlockedIP:

    ip: str

    block_type: str

    created_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    timeout: Optional[int] = None

    expires_at: Optional[str] = None

    expires_epoch: Optional[float] = None

    active: bool = True

    reason: str = ""

    source: str = "ResponseEngine"

    def to_dict(self):

        return asdict(self)


# ==========================================================
# Statistics
# ==========================================================

@dataclass
class EngineStats:

    total_blocks: int = 0

    permanent_blocks: int = 0

    temporary_blocks: int = 0

    active_blocks: int = 0

    whitelist_size: int = 0

    total_actions: int = 0

    total_errors: int = 0

    uptime_seconds: int = 0

    def to_dict(self):

        return asdict(self)


# ==========================================================
# History Event
# ==========================================================

@dataclass
class HistoryEvent:

    action: str

    ip: str

    success: bool

    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    details: Dict = field(default_factory=dict)

    def to_dict(self):

        return asdict(self)


# ==========================================================
# Active Block List
# ==========================================================

@dataclass
class ActiveBlockList:

    blocks: List[BlockedIP] = field(default_factory=list)

    def add(self, block: BlockedIP):

        self.blocks.append(block)

    def remove(self, ip):

        self.blocks = [

            block

            for block in self.blocks

            if block.ip != ip

        ]

    def exists(self, ip):

        return any(

            block.ip == ip

            for block in self.blocks

        )

    def get(self, ip):

        for block in self.blocks:

            if block.ip == ip:

                return block

        return None

    def count(self):

        return len(self.blocks)

    def clear(self):

        self.blocks.clear()

    def to_dict(self):

        return [

            block.to_dict()

            for block in self.blocks

        ]
