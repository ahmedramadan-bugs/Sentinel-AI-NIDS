"""
feature_alignment.py
---------------------------------------
Single source of truth for the feature set used by AI-NIDS.

WHY THIS FILE EXISTS
The training pipeline (train_model.py) and the live detection
pipeline (nids/ml.py) must build the EXACT same feature vector
- same columns, same order, same scaling - or the trained model's reported
accuracy means nothing once it sees real Suricata traffic. This is the
train/serving skew problem documented in Chapter 2 (Section 2.5.3).

This module is imported by BOTH sides, so there is only one place that
defines what a "feature vector" is.

The feature list below is deliberately restricted to columns that
SuricataParser.to_features() can actually produce from a live flow event.
There is no point training on CICIDS2017 columns (e.g. Flow IAT Std,
Fwd PSH Flags, Subflow Fwd Bytes...) that Suricata's eve.json flow event
does not give us at inference time - the model would learn to rely on
information we can never supply live.
"""

from __future__ import annotations

# These names match the *keys* returned by SuricataFlow.to_features()
# in suricata_parser.py. 'Source IP' and 'Destination IP' are excluded on
# purpose: they are identifiers used for the whitelist check and for the
# block command, not numeric signal for the classifier.
FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Down/Up Ratio",
    "Average Packet Size",
]


def select_training_columns(df):
    """
    Called from 01_feature_engineering.py on the raw CICIDS2017 dataframe.

    Instead of letting VarianceThreshold / correlation filtering pick an
    unpredictable subset of the ~78 CICIDS columns, we intersect the
    dataset against FEATURE_COLUMNS - the fixed list above. Any column
    Suricata cannot reproduce live is dropped before training ever sees it.

    Raises a clear error instead of silently training on the wrong columns
    if the CSV's header does not match what we expect (dataset re-uploads
    sometimes rename or drop columns).
    """

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]

    if missing:
        raise ValueError(
            "The following expected columns are not present in the "
            "CICIDS2017 CSV header: "
            + ", ".join(missing)
            + ". Run print(df.columns.tolist()) on the raw dataframe and "
              "update FEATURE_COLUMNS in feature_alignment.py to match "
              "the exact column names in your copy of the dataset "
              "(leading/trailing spaces are already stripped by "
              "df.columns.str.strip() before this function is called)."
        )

    return df[FEATURE_COLUMNS].copy()


def build_feature_vector(flow_features: dict, scaler, imputer=None) -> np.ndarray:
    """
    Called from detection_service.py on a single live flow.

    flow_features: the dict returned by SuricataFlow.to_features().
    scaler: the StandardScaler loaded from scaler.pkl (fitted during
            training in 01_feature_engineering.py).

    Applies the SAME transform used at training time, in the SAME order:
    select the fixed columns -> clip negatives -> log1p -> StandardScaler.
    Returns a (1, n_features) array ready for model.predict_proba().
    """

    # Keep importing this schema module lightweight.  This allows the
    # deterministic fallback and its tests to run even when optional ML
    # dependencies are not installed yet.
    import numpy as np

    row = [flow_features.get(col, 0) for col in FEATURE_COLUMNS]

    arr = np.array(row, dtype=np.float64).reshape(1, -1)

    # Flow Bytes/s and Flow Packets/s can be +inf if duration rounded to 0;
    # replace with 0 rather than letting log1p/scaler choke on inf.
    arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

    # Newer reproducible models save a train-only median imputer.  Historical
    # artifacts did not; keeping this optional preserves their valid serving
    # contract because live flow fields are always populated with numeric 0s.
    if imputer is not None:
        arr = imputer.transform(arr)

    arr = np.log1p(np.clip(arr, 0, None))

    return scaler.transform(arr)
