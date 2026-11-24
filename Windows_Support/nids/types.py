"""Small typed contracts shared by the NIDS components."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass(frozen=True)
class Detection:
    attack_type: str
    severity: str
    confidence: float
    engine: str
    mode: str
    signature: Optional[str] = None
    rule_id: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MLDecision:
    label: str
    confidence: float
    latency_ms: float


def stronger_severity(first: str, second: str) -> str:
    return first if SEVERITY_RANK.get(first, 0) >= SEVERITY_RANK.get(second, 0) else second


def serialise(value: Any) -> Any:
    """Convert a dataclass or nested value to JSON-compatible data."""
    if hasattr(value, "__dataclass_fields__"):
        return {key: serialise(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): serialise(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialise(item) for item in value]
    return value
