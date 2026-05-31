"""
preprocessing.py
================
Stage 3: turn the labelled flow/packet table into a clean numeric feature matrix.

Responsibilities
----------------
1. Engineer a handful of ratio/rate features that are invariant to topology and
   wall-clock time. For the packet-based variant every engineered column uses
   only past-or-present quantities -- nothing about the rest of the flow.
2. Select only the model features (``BASE_FEATURES`` + ``ENGINEERED_FEATURES``)
   that are actually present.
3. Clean: replace inf/NaN, clip away the residual numerical blow-ups left over
   by ratios with tiny denominators, cast to float32.
4. Return ``X`` (DataFrame), ``y`` (np.ndarray), the feature-name list and --
   optionally -- a ``groups`` array (the flow-instance id of each row) so the
   classifier CV can use ``GroupKFold`` to avoid leakage across train/test.

This module supports two data shapes:
  * Flow-based (NFStream output -- ``bidirectional_*`` columns).
  * Packet-based (feature_extraction_packets output -- ``flow_pkt_index``,
    ``run_mean_ps``, ...).
Shape is auto-detected by column presence; pass a ``cfg`` module to pick which
BASE/ENGINEERED/IDENTITY lists to honour.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from . import config as _default_config

log = logging.getLogger("ids.prep")

_EPS = 1e-9
# Hard clip applied after engineering. Ratios with tiny denominators (e.g.
# `iat / run_mean_iat` on the second packet) can produce values up to 1/EPS
# = 1e9, which would dominate any StandardScaler and skew linear models.
_CLIP = 1.0e6


def _col(df: pd.DataFrame, name: str) -> pd.Series:
    """Tolerant column getter: returns the column as float, or zeros if absent."""
    if name in df.columns:
        return df[name].astype(float)
    return pd.Series(0.0, index=df.index)


def _engineer_flow(df: pd.DataFrame) -> pd.DataFrame:
    """Engineered ratio/rate columns for NFStream per-flow tables (unchanged)."""
    bi_bytes = _col(df, "bidirectional_bytes")
    bi_pkts = _col(df, "bidirectional_packets")
    s2d_bytes = _col(df, "src2dst_bytes")
    s2d_pkts = _col(df, "src2dst_packets")
    d2s_bytes = _col(df, "dst2src_bytes")
    bi_dur = _col(df, "bidirectional_duration_ms")

    df["bytes_per_packet"] = bi_bytes / (bi_pkts + _EPS)
    df["src2dst_bytes_ratio"] = s2d_bytes / (bi_bytes + _EPS)
    df["src2dst_packets_ratio"] = s2d_pkts / (bi_pkts + _EPS)
    df["download_upload_ratio"] = d2s_bytes / (s2d_bytes + _EPS)
    df["bytes_per_ms"] = bi_bytes / (bi_dur + _EPS)
    df["packets_per_ms"] = bi_pkts / (bi_dur + _EPS)

    df["syn_ratio"] = _col(df, "bidirectional_syn_packets") / (bi_pkts + _EPS)
    df["rst_ratio"] = _col(df, "bidirectional_rst_packets") / (bi_pkts + _EPS)
    df["fin_ratio"] = _col(df, "bidirectional_fin_packets") / (bi_pkts + _EPS)
    df["ack_ratio"] = _col(df, "bidirectional_ack_packets") / (bi_pkts + _EPS)
    df["mean_ps_ratio"] = _col(df, "src2dst_mean_ps") / (_col(df, "dst2src_mean_ps") + _EPS)
    return df


def _safe_div(num: pd.Series, denom: pd.Series) -> pd.Series:
    """Element-wise division that returns 0 when the denominator is 0.

    Avoids the `num / (denom + EPS) ~= num / EPS` blow-up that produces 1e9-
    scale outliers on first-packet ratios.
    """
    out = pd.Series(0.0, index=num.index)
    mask = denom != 0
    out[mask] = num[mask] / denom[mask]
    return out


def _engineer_packets(df: pd.DataFrame) -> pd.DataFrame:
    """Engineered features for the per-packet table -- past-only inputs."""
    pkt_len = _col(df, "pkt_len")
    run_mean_ps = _col(df, "run_mean_ps")
    iat = _col(df, "iat_from_prev_ms")
    run_mean_iat = _col(df, "run_mean_iat_ms")
    fwd_bytes_so_far = _col(df, "fwd_bytes_so_far")
    rev_bytes_so_far = _col(df, "rev_bytes_so_far")

    df["pkt_size_vs_run_mean"] = _safe_div(pkt_len, run_mean_ps)
    df["iat_vs_run_mean"] = _safe_div(iat, run_mean_iat)

    # Signed asymmetry in [-1, 1]: +1 = all forward bytes so far, -1 = all
    # reverse. Well-defined except when both directions have zero bytes --
    # impossible after the first packet, but _safe_div handles it anyway.
    df["run_byte_asymmetry"] = _safe_div(
        fwd_bytes_so_far - rev_bytes_so_far,
        fwd_bytes_so_far + rev_bytes_so_far,
    )
    return df


def _is_packet_table(df: pd.DataFrame) -> bool:
    """True for per-packet rows, False for NFStream per-flow rows."""
    return "flow_pkt_index" in df.columns or "run_mean_ps" in df.columns


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add engineered columns appropriate to the input table's shape."""
    df = df.copy()
    if _is_packet_table(df):
        return _engineer_packets(df)
    return _engineer_flow(df)


def build_matrix(df: pd.DataFrame, cfg=None, return_groups: bool = False):
    """Return ``(X, y, feature_names)`` or ``(X, y, feature_names, groups)``.

    ``cfg`` selects the BASE/ENGINEERED/IDENTITY lists; defaults to the
    flow-based ``ids.config``.

    ``return_groups=True`` additionally returns the per-row flow-instance id
    (from ``cfg.GROUP_COLUMN``) for use as the ``groups`` arg of
    ``sklearn.model_selection.GroupKFold`` / ``GroupShuffleSplit``. Falls back
    to a unique-per-row group array if the column isn't present (degrades CV
    to plain KFold, which is the right behaviour for one-row-per-flow data).
    """
    if cfg is None:
        cfg = _default_config

    df = engineer_features(df)

    wanted = cfg.BASE_FEATURES + cfg.ENGINEERED_FEATURES
    available = [c for c in wanted if c in df.columns]
    missing = [c for c in wanted if c not in df.columns]
    if missing:
        log.info("%d declared features absent in this capture (skipped): %s",
                 len(missing), missing)

    # Hard guard against rule #2: no identity column may ever enter X.
    leaked = [c for c in available if c in cfg.IDENTITY_COLUMNS]
    if leaked:
        raise RuntimeError(f"Identity columns leaked into features: {leaked}")

    X = df[available].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0.0, inplace=True)
    # Clip residual blow-ups so StandardScaler isn't dominated by one outlier.
    X = X.clip(lower=-_CLIP, upper=_CLIP)
    X = X.astype(np.float32)

    if cfg.LABEL_COLUMN not in df.columns:
        raise RuntimeError("Label column missing -- run labeling.add_labels first.")
    y = df[cfg.LABEL_COLUMN].to_numpy(dtype=int)

    log.info("Feature matrix: %d rows x %d features", X.shape[0], X.shape[1])

    if not return_groups:
        return X, y, available

    group_col = getattr(cfg, "GROUP_COLUMN", None)
    if group_col and group_col in df.columns:
        groups = df[group_col].astype(str).to_numpy()
    else:
        # Each row is its own group; GroupKFold degrades to KFold cleanly.
        groups = np.arange(len(df))
    return X, y, available, groups
