"""Guarded ML inference with explicit health state.

The saved estimator is loaded only once and every prediction is validated.  A
load or prediction failure changes state but never raises into the collector:
the deterministic layer remains available to the pipeline.
"""

from __future__ import annotations

import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from collectors.feature_alignment import FEATURE_COLUMNS, build_feature_vector

from .config import Settings
from .types import MLDecision


class ModelDetector:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.model: Any = None
        self.scaler: Any = None
        self.imputer: Any = None
        self.encoder: Any = None
        self.status = "UNAVAILABLE"
        self.error_count = 0
        self.last_error: Optional[str] = None
        self.last_prediction_at: Optional[str] = None
        self.last_latency_ms: Optional[float] = None
        self.model_version: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.status == "HEALTHY" and self.model is not None

    def load(self) -> bool:
        """Load and validate artifacts without trusting their metadata blindly."""
        try:
            import joblib

            for path in (
                self.settings.model_path,
                self.settings.scaler_path,
                self.settings.label_encoder_path,
                self.settings.feature_schema_path,
            ):
                if not Path(path).is_file():
                    raise FileNotFoundError(f"required ML artifact is missing: {path}")

            schema = list(joblib.load(self.settings.feature_schema_path))
            if schema != list(FEATURE_COLUMNS):
                raise ValueError("saved feature schema differs from the live feature schema")

            scaler = joblib.load(self.settings.scaler_path)
            model = joblib.load(self.settings.model_path)
            encoder = joblib.load(self.settings.label_encoder_path)
            expected = getattr(model, "n_features_in_", len(FEATURE_COLUMNS))
            if expected != len(FEATURE_COLUMNS):
                raise ValueError(f"model expects {expected} features, not {len(FEATURE_COLUMNS)}")
            if not hasattr(model, "predict_proba") or not hasattr(encoder, "inverse_transform"):
                raise TypeError("model artifacts do not support probability inference and label decoding")

            # The legacy bundle has no imputer.  A model retrained with
            # AI/train_model.py gets its train-only imputer applied here.
            imputer = joblib.load(self.settings.imputer_path) if Path(self.settings.imputer_path).is_file() else None
            self.scaler, self.imputer, self.model, self.encoder = scaler, imputer, model, encoder
            self.status = "HEALTHY"
            self.last_error = None
            self.model_version = f"{Path(self.settings.model_path).name}:{Path(self.settings.model_path).stat().st_mtime_ns}"
            return True
        except Exception as exc:  # the fallback path must cover artifact failures
            self.model = self.scaler = self.imputer = self.encoder = None
            self.status = "UNAVAILABLE"
            self.error_count += 1
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False

    def classify(self, flow_features: dict[str, Any]) -> Optional[MLDecision]:
        if not self.available:
            return None
        started = time.perf_counter()
        try:
            vector = build_feature_vector(flow_features, self.scaler, self.imputer)
            probabilities = self.model.predict_proba(vector)[0]
            values = [float(item) for item in probabilities]
            if not values or any(not math.isfinite(item) or item < 0 for item in values):
                raise ValueError("model returned invalid probabilities")
            index = max(range(len(values)), key=values.__getitem__)
            confidence = values[index]
            if not 0.0 <= confidence <= 1.0:
                raise ValueError("model confidence is outside [0, 1]")
            label = str(self.encoder.inverse_transform([index])[0])
            latency_ms = (time.perf_counter() - started) * 1000
            if latency_ms > self.settings.ml_timeout_seconds * 1000:
                raise TimeoutError(f"prediction exceeded {self.settings.ml_timeout_seconds}s")
            self.last_prediction_at = datetime.now(timezone.utc).isoformat()
            self.last_latency_ms = round(latency_ms, 3)
            self.status = "HEALTHY"
            return MLDecision(label=label, confidence=confidence, latency_ms=latency_ms)
        except Exception as exc:
            self.status = "ERROR"
            self.error_count += 1
            self.last_error = f"{type(exc).__name__}: {exc}"
            return None

    def health(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "model_loaded": self.model is not None,
            "feature_count": len(FEATURE_COLUMNS),
            "model_version": self.model_version,
            "last_prediction_at": self.last_prediction_at,
            "last_prediction_latency_ms": self.last_latency_ms,
            "error_count": self.error_count,
            "last_error": self.last_error,
        }
