"""utils/data_fusion.py — BATADAL + UNSW-NB15 cyber-physical data fusion."""
from __future__ import annotations
import numpy as np
import pandas as pd
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

HYBRID_VALIDATION_STATEMENT = (
    "Due to restricted access to real-world ICS datasets, we adopt a hybrid "
    "validation strategy combining benchmark datasets with controlled simulation."
)

BATADAL_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "BATADAL_dataset03.csv")


def _synthetic_unsw_nb15(n: int, seed: int = 0) -> np.ndarray:
    """
    Synthetic UNSW-NB15-compatible network feature vector.
    Columns: [dur, proto, sbytes, dbytes, spkts, dpkts, sttl, dttl,
               sload, dload, smean, dmean, label]
    """
    rng = np.random.default_rng(seed)
    dur    = rng.exponential(0.5, n)
    sbytes = rng.integers(40, 65535, n).astype(float)
    dbytes = rng.integers(0, 65535, n).astype(float)
    spkts  = rng.integers(1, 200, n).astype(float)
    dpkts  = rng.integers(0, 200, n).astype(float)
    sttl   = rng.choice([64, 128, 255], n).astype(float)
    dttl   = rng.choice([64, 128, 255], n).astype(float)
    sload  = sbytes / (dur + 1e-6)
    dload  = dbytes / (dur + 1e-6)
    smean  = sbytes / (spkts + 1e-6)
    dmean  = dbytes / (dpkts + 1e-6)
    label  = np.zeros(n)

    arr = np.column_stack([dur, sbytes, dbytes, spkts, dpkts,
                           sttl, dttl, sload, dload, smean, dmean, label])
    return arr


def _synthetic_batadal(n: int, seed: int = 1) -> pd.DataFrame:
    """Synthetic BATADAL-compatible sensor/actuator time series."""
    rng = np.random.default_rng(seed)
    t = np.arange(n)
    df = pd.DataFrame({
        "DATETIME": pd.date_range("2016-01-01", periods=n, freq="h"),
        "L_T1": 1.5 + 0.3 * np.sin(2 * np.pi * t / 24) + rng.normal(0, 0.04, n),
        "F_PU1": 120 + 15 * np.sin(2 * np.pi * t / 12) + rng.normal(0, 5, n),
        "P_J280": 50 + 8 * np.cos(2 * np.pi * t / 24) + rng.normal(0, 2, n),
        "ATT_FLAG": np.zeros(n, dtype=int),
    })
    return df


def _normalize_cols(arr: np.ndarray) -> np.ndarray:
    mn = arr.min(axis=0)
    mx = arr.max(axis=0)
    rng = mx - mn
    rng[rng < 1e-9] = 1.0
    return (arr - mn) / rng


def load_batadal(n: int = 500) -> pd.DataFrame:
    """Load BATADAL or fall back to synthetic."""
    if os.path.exists(BATADAL_PATH):
        try:
            df = pd.read_csv(BATADAL_PATH, nrows=n)
            df.columns = [c.strip() for c in df.columns]
            return df
        except Exception:
            pass
    return _synthetic_batadal(n)


def load_unsw_nb15(n: int = 500) -> np.ndarray:
    """Return synthetic UNSW-NB15 feature array (n × 12)."""
    return _synthetic_unsw_nb15(n)


def fuse_datasets(n: int = 500) -> pd.DataFrame:
    """
    Fuse BATADAL (physical) + UNSW-NB15 (network) into unified dataset.
    Returns DataFrame with columns:
      tick, cyber_score, physical_score, label
    All numeric, timestamps aligned.
    """
    bat = load_batadal(n)
    net = load_unsw_nb15(n)

    # Physical signal: normalize sensor columns from BATADAL
    phys_cols = [c for c in bat.columns
                 if c not in ("DATETIME", "ATT_FLAG") and bat[c].dtype != object]
    if phys_cols:
        phys_raw = bat[phys_cols].fillna(0).values.astype(float)
    else:
        phys_raw = _synthetic_batadal(n)[["L_T1", "F_PU1", "P_J280"]].values

    phys_norm = _normalize_cols(phys_raw)
    # Aggregate physical into single anomaly score (deviation from median)
    phys_median = np.median(phys_norm, axis=0)
    phys_score = np.mean(np.abs(phys_norm - phys_median), axis=1)
    phys_score = np.clip(phys_score / (phys_score.max() + 1e-9), 0, 1)

    # Cyber signal: normalize UNSW-NB15 features (exclude label col)
    net_norm = _normalize_cols(net[:n, :-1])
    cyber_score = np.mean(net_norm[:, :5], axis=1)   # traffic volume features
    cyber_score = np.clip(cyber_score, 0, 1)

    # Label: use ATT_FLAG if available
    if "ATT_FLAG" in bat.columns:
        label = bat["ATT_FLAG"].values[:n].astype(int)
    else:
        label = np.zeros(n, dtype=int)

    df = pd.DataFrame({
        "tick": np.arange(n),
        "cyber_score": cyber_score,
        "physical_score": phys_score,
        "label": label,
    })
    return df
