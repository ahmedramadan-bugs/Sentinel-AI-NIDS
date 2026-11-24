"""Integrated, fail-safe network intrusion detection service."""

from .config import Settings
from .pipeline import NIDSPipeline

__all__ = ["NIDSPipeline", "Settings"]
