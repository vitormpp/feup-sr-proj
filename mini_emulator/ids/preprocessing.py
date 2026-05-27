"""
preprocessing.py
================
Stage 3: turn the labelled flow table into a clean numeric feature matrix.

Responsibilities
----------------
1. Engineer a handful of ratio/rate features that are invariant to topology and
   wall-clock time (everything here is a ratio of two flow quantities or a rate
   over the flow's own duration delta).
2. Select only the model features (``BASE_FEATURES`` + ``ENGINEERED_FEATURES``)
   that are actually present -- guaranteeing no IP/MAC/port/timestamp leaks in,
   because those live in ``IDENTITY_COLUMNS`` and are never selected.
3. Clean: replace inf/NaN, cast to float32.
4. Return ``X`` (DataFrame), ``y`` (np.ndarray) and the feature-name list.

Scaling is left to the model stages: classifiers wrap a ``StandardScaler`` in a
Pipeline so it is re-fit inside every CV fold (no leakage), and the outlier
detectors fit their scaler on normal-only data.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from . import config

log = logging.getLogger("ids.prep")

_EPS = 1e-9


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add the ``ENGINEERED_FEATURES`` columns (safe if some inputs are absent)."""
    df = df.copy()

    def col(name):  # tolerant column getter
        return df[name].astype(float) if name in df.columns else pd.Series(0.0, index=df.index)

    bi_bytes = col("bidirectional_bytes")
    bi_pkts = col("bidirectional_packets")
    s2d_bytes = col("src2dst_bytes")
    s2d_pkts = col("src2dst_packets")
    d2s_bytes = col("dst2src_bytes")
    bi_dur = col("bidirectional_duration_ms")

    df["bytes_per_packet"] = bi_bytes / (bi_pkts + _EPS)
    df["src2dst_bytes_ratio"] = s2d_bytes / (bi_bytes + _EPS)
    df["src2dst_packets_ratio"] = s2d_pkts / (bi_pkts + _EPS)
    df["download_upload_ratio"] = d2s_bytes / (s2d_bytes + _EPS)
    df["bytes_per_ms"] = bi_bytes / (bi_dur + _EPS)
    df["packets_per_ms"] = bi_pkts / (bi_dur + _EPS)

    df["syn_ratio"] = col("bidirectional_syn_packets") / (bi_pkts + _EPS)
    df["rst_ratio"] = col("bidirectional_rst_packets") / (bi_pkts + _EPS)
    df["fin_ratio"] = col("bidirectional_fin_packets") / (bi_pkts + _EPS)
    df["ack_ratio"] = col("bidirectional_ack_packets") / (bi_pkts + _EPS)
    df["mean_ps_ratio"] = col("src2dst_mean_ps") / (col("dst2src_mean_ps") + _EPS)
    return df


def build_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, np.ndarray, list[str]]:
    """Return (X, y, feature_names) ready for the models."""
    df = engineer_features(df)

    wanted = config.BASE_FEATURES + config.ENGINEERED_FEATURES
    available = [c for c in wanted if c in df.columns]
    missing = [c for c in wanted if c not in df.columns]
    if missing:
        log.info("%d declared features absent in this capture (skipped): %s",
                 len(missing), missing)

    # Hard guard against rule #2: no identity column may ever enter X.
    leaked = [c for c in available if c in config.IDENTITY_COLUMNS]
    if leaked:
        raise RuntimeError(f"Identity columns leaked into features: {leaked}")

    X = df[available].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0.0, inplace=True)
    X = X.astype(np.float32)

    if config.LABEL_COLUMN not in df.columns:
        raise RuntimeError("Label column missing -- run labeling.add_labels first.")
    y = df[config.LABEL_COLUMN].to_numpy(dtype=int)

    log.info("Feature matrix: %d flows x %d features", X.shape[0], X.shape[1])
    return X, y, available
