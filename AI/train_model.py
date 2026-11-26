"""Reproducible XGBoost training command for the live Suricata feature schema.

This is intentionally separate from the historical numbered notebooks/scripts.
It is only needed when model validation proves the bundled artifact unsuitable.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

# Make this command runnable as ``python AI/train_model.py`` from any working
# directory without relying on an implicit PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collectors.feature_alignment import FEATURE_COLUMNS, select_training_columns


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "AI" / "MachineLearningCSV" / "MachineLearningCVE"
MODEL_DIR = ROOT / "AI" / "models"
ARTIFACT_DIR = MODEL_DIR / "xgboost_nids_artifacts"

LABEL_MAP = {
    "BENIGN": "Normal",
    "PortScan": "Suspicious Port",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Infiltration": "Data Exfiltration",
}


def load_data(max_rows_per_class: int, chunk_size: int, random_state: int) -> pd.DataFrame:
    """Uniformly retain a bounded, reproducible sample for each target class.

    Every CSV is streamed, so the command neither silently trains on just the
    first few rows nor needs to hold the full CICIDS corpus in memory.
    """
    rng = np.random.default_rng(random_state)
    reservoirs: dict[str, pd.DataFrame] = {}
    for csv_file in sorted(DATA_DIR.glob("*.csv")):
        header = pd.read_csv(csv_file, nrows=0)
        available = {column.strip(): column for column in header.columns}
        required = [available[column] for column in [*FEATURE_COLUMNS, "Label"]]
        for chunk in pd.read_csv(csv_file, usecols=required, chunksize=chunk_size, low_memory=False):
            chunk.columns = chunk.columns.str.strip()
            chunk["Label"] = chunk["Label"].astype(str).str.strip()
            chunk["MappedLabel"] = chunk["Label"].map(LABEL_MAP)
            chunk = chunk[chunk["MappedLabel"].notna()].copy()
            for label, subset in chunk.groupby("MappedLabel", sort=False):
                subset["_sample_key"] = rng.random(len(subset))
                combined = pd.concat([reservoirs.get(label, subset.iloc[0:0]), subset], ignore_index=True)
                reservoirs[label] = combined.nsmallest(max_rows_per_class, "_sample_key")
    if not reservoirs:
        raise FileNotFoundError(f"No CICIDS CSV files found in {DATA_DIR}")
    return pd.concat(reservoirs.values(), ignore_index=True).drop(columns="_sample_key")


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--max-rows-per-class", type=int, default=75_000,
                     help="bounded uniform reservoir size for each target class")
    cli.add_argument("--chunk-size", type=int, default=100_000)
    cli.add_argument("--random-state", type=int, default=42)
    args = cli.parse_args()
    df = load_data(args.max_rows_per_class, args.chunk_size, args.random_state)
    raw_features = select_training_columns(df).replace([np.inf, -np.inf], np.nan)
    labels = df["MappedLabel"]
    x_train, x_holdout, y_train, y_holdout = train_test_split(
        raw_features, labels, test_size=0.20, random_state=args.random_state, stratify=labels
    )
    x_validation, x_test, y_validation, y_test = train_test_split(
        x_holdout, y_holdout, test_size=0.50, random_state=args.random_state, stratify=y_holdout
    )
    encoder = LabelEncoder().fit(y_train)
    y_train_encoded = encoder.transform(y_train)
    y_validation_encoded = encoder.transform(y_validation)
    y_test_encoded = encoder.transform(y_test)
    imputer = SimpleImputer(strategy="median").fit(x_train.values)
    scaler = StandardScaler().fit(np.log1p(np.clip(imputer.transform(x_train.values), 0, None)))

    def transform(frame):
        values = frame.values if hasattr(frame, "values") else frame
        return scaler.transform(np.log1p(np.clip(imputer.transform(values), 0, None)))

    train_values, validation_values, test_values = map(transform, (x_train, x_validation, x_test))
    counts = np.bincount(y_train_encoded)
    weights = np.asarray([len(y_train_encoded) / (len(counts) * counts[item]) for item in y_train_encoded])
    model = XGBClassifier(
        objective="multi:softprob", num_class=len(encoder.classes_), n_estimators=400,
        learning_rate=0.05, max_depth=8, subsample=0.85, colsample_bytree=0.85,
        eval_metric="mlogloss", early_stopping_rounds=30, random_state=args.random_state, n_jobs=-1,
    )
    model.fit(train_values, y_train_encoded, sample_weight=weights, eval_set=[(validation_values, y_validation_encoded)], verbose=False)
    predictions = model.predict(test_values)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_DIR / "xgboost_nids_model.pkl")
    joblib.dump(scaler, ARTIFACT_DIR / "scaler.pkl")
    joblib.dump(imputer, ARTIFACT_DIR / "imputer.pkl")
    joblib.dump(encoder, ARTIFACT_DIR / "label_encoder.pkl")
    joblib.dump(FEATURE_COLUMNS, ARTIFACT_DIR / "features.pkl")
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model": "XGBClassifier",
        "feature_schema": FEATURE_COLUMNS,
        "classes": encoder.classes_.tolist(),
        "test_macro_f1": float(f1_score(y_test_encoded, predictions, average="macro")),
        "classification_report": classification_report(y_test_encoded, predictions, target_names=encoder.classes_, output_dict=True),
        "confusion_matrix": confusion_matrix(y_test_encoded, predictions).tolist(),
        "rows": {"train": len(x_train), "validation": len(x_validation), "test": len(x_test)},
    }
    (ARTIFACT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({"test_macro_f1": metrics["test_macro_f1"], "rows": metrics["rows"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
