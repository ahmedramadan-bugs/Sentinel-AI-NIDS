"""Central configuration for the demonstrable NIDS deployment.

All values may be overridden through ``NIDS_*`` environment variables.  The
safe defaults keep the dashboard local and make network enforcement a dry run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
XGBOOST_MODEL = ROOT / "AI" / "models" / "xgboost_nids_model.pkl"
XGBOOST_ARTIFACTS = ROOT / "AI" / "models" / "xgboost_nids_artifacts"


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Runtime configuration.  Paths are deliberately relative to this repo."""

    root: Path = ROOT
    eve_log_path: Path = field(
        default_factory=lambda: Path(os.getenv("NIDS_EVE_LOG", ROOT / "runtime" / "eve.json"))
    )
    database_path: Path = field(
        default_factory=lambda: Path(os.getenv("NIDS_DATABASE", ROOT / "runtime" / "nids.db"))
    )
    model_path: Path = field(
        default_factory=lambda: Path(os.getenv(
            "NIDS_MODEL_PATH",
            XGBOOST_MODEL if XGBOOST_MODEL.is_file() else ROOT / "AI" / "models" / "ensemble_nids_model.pkl",
        ))
    )
    scaler_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("NIDS_SCALER_PATH", (XGBOOST_ARTIFACTS / "scaler.pkl") if XGBOOST_MODEL.is_file()
                      else ROOT / "AI" / "processed_data" / "scaler.pkl")
        )
    )
    label_encoder_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("NIDS_LABEL_ENCODER_PATH", (XGBOOST_ARTIFACTS / "label_encoder.pkl") if XGBOOST_MODEL.is_file()
                      else ROOT / "AI" / "processed_data" / "label_encoder.pkl")
        )
    )
    feature_schema_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("NIDS_FEATURE_SCHEMA", (XGBOOST_ARTIFACTS / "features.pkl") if XGBOOST_MODEL.is_file()
                      else ROOT / "AI" / "processed_data" / "features.pkl")
        )
    )
    imputer_path: Path = field(
        default_factory=lambda: Path(os.getenv("NIDS_IMPUTER_PATH", (XGBOOST_ARTIFACTS / "imputer.pkl") if XGBOOST_MODEL.is_file()
                                         else ROOT / "AI" / "processed_data" / "imputer.pkl"))
    )
    ml_confidence_threshold: float = field(
        default_factory=lambda: float(os.getenv("NIDS_ML_CONFIDENCE_THRESHOLD", "0.70"))
    )
    ml_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("NIDS_ML_TIMEOUT_SECONDS", "2.0"))
    )
    response_dry_run: bool = field(default_factory=lambda: _bool("NIDS_RESPONSE_DRY_RUN", True))
    temp_block_seconds: int = field(default_factory=lambda: int(os.getenv("NIDS_TEMP_BLOCK_SECONDS", "300")))
    dashboard_host: str = field(default_factory=lambda: os.getenv("NIDS_DASHBOARD_HOST", "127.0.0.1"))
    dashboard_port: int = field(default_factory=lambda: int(os.getenv("NIDS_DASHBOARD_PORT", "8080")))
    poll_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("NIDS_POLL_INTERVAL_SECONDS", "1.0"))
    )
    dedup_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("NIDS_DEDUP_WINDOW_SECONDS", "60"))
    )

    def ensure_runtime_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.eve_log_path.parent.mkdir(parents=True, exist_ok=True)
