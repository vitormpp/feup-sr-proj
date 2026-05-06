#!/usr/bin/env python3
"""
train_outlier_model.py
======================
Reads a .pcap file, extracts per-flow features with NFStream, and trains an
Isolation Forest anomaly-detection model that treats all observed traffic as
"normal".

Outputs
-------
  model.pkl   — trained IsolationForest  (joblib)
  scaler.pkl  — StandardScaler fitted on the training flows (joblib)
  features.csv — (optional) extracted feature table for inspection

Usage
-----
  python3 train_outlier_model.py --pcap capture.pcap --model-out model.pkl
"""

import argparse
import sys
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

# --------------------------------------------------------------------------- #
#  Logging
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("train_outlier_model")

# --------------------------------------------------------------------------- #
#  Feature columns produced by NFStream that we use for the model.
#  Only numeric / ordinal columns are kept.  Columns absent from a particular
#  pcap are silently dropped before training.
# --------------------------------------------------------------------------- #
CANDIDATE_FEATURES = [
    # Flow volume
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    # Duration / timing
    "bidirectional_duration_ms",
    "src2dst_duration_ms",
    "dst2src_duration_ms",
    # Inter-arrival times
    "bidirectional_mean_ps",          # mean packet size
    "bidirectional_stddev_ps",
    "src2dst_mean_ps",
    "src2dst_stddev_ps",
    "dst2src_mean_ps",
    "dst2src_stddev_ps",
    # Packet-size min/max
    "bidirectional_min_ps",
    "bidirectional_max_ps",
    "src2dst_min_ps",
    "src2dst_max_ps",
    "dst2src_min_ps",
    "dst2src_max_ps",
    # Byte ratios
    "src2dst_bytes_ratio",            # computed below if absent
    # Protocol (numeric)
    "protocol",
    # TCP flags (if present)
    "bidirectional_syn_packets",
    "bidirectional_fin_packets",
    "bidirectional_rst_packets",
    "bidirectional_psh_packets",
    "bidirectional_ack_packets",
    "bidirectional_urg_packets",
    # NFStream statistical plug-ins (present when statistical=True)
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_min_piat_ms",
    "bidirectional_max_piat_ms",
    "src2dst_mean_piat_ms",
    "src2dst_stddev_piat_ms",
    "src2dst_min_piat_ms",
    "src2dst_max_piat_ms",
    "dst2src_mean_piat_ms",
    "dst2src_stddev_piat_ms",
    "dst2src_min_piat_ms",
    "dst2src_max_piat_ms",
]


# --------------------------------------------------------------------------- #
#  Helper: derive extra ratio features
# --------------------------------------------------------------------------- #
def _add_ratio_features(df: pd.DataFrame) -> pd.DataFrame:
    total = df.get("bidirectional_bytes", pd.Series(dtype=float))
    s2d   = df.get("src2dst_bytes",       pd.Series(dtype=float))
    if total is not None and s2d is not None:
        df["src2dst_bytes_ratio"] = np.where(total > 0, s2d / total, 0.5)
    return df


# --------------------------------------------------------------------------- #
#  Step 1 — NFStream feature extraction
# --------------------------------------------------------------------------- #
def extract_features(pcap_path: str) -> pd.DataFrame:
    try:
        from nfstream import NFStreamer
    except ImportError:
        log.error("nfstream is not installed.  Run:  pip install nfstream")
        sys.exit(1)

    log.info("Opening pcap: %s", pcap_path)
    streamer = NFStreamer(
        source=pcap_path,
        statistical_analysis=True,   # enables PIAT stats, etc.
        splt_analysis=0,             # disable sequence-payload — not needed here
        n_dissections=20,
        accounting_mode=1,           # IP-level bytes
    )

    df = streamer.to_pandas()

    if df.empty:
        log.error("NFStream produced 0 flows from %s — pcap may be empty or corrupt.", pcap_path)
        sys.exit(1)

    #df = pd.DataFrame(rows)
    log.info("Raw flow count: %d   columns: %d", len(df), len(df.columns))
    return df


# --------------------------------------------------------------------------- #
#  Step 2 — Feature selection + cleaning
# --------------------------------------------------------------------------- #
def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    df = _add_ratio_features(df)

    # Keep only columns that exist in this capture
    available = [c for c in CANDIDATE_FEATURES if c in df.columns]
    missing   = [c for c in CANDIDATE_FEATURES if c not in df.columns]
    if missing:
        log.debug("Columns not present in this pcap (skipped): %s", missing)

    log.info("Using %d feature columns: %s", len(available), available)
    X = df[available].copy()

    # Replace inf / NaN with 0
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Cast everything to float32
    X = X.astype(np.float32)

    # Drop any rows that are still all-zero (degenerate flows)
    mask = X.abs().sum(axis=1) > 0
    dropped = (~mask).sum()
    if dropped:
        log.warning("Dropping %d all-zero flows.", dropped)
    X = X[mask].reset_index(drop=True)

    if len(X) == 0:
        log.error("No usable flows after cleaning.")
        sys.exit(1)

    log.info("Feature matrix shape after cleaning: %s", X.shape)
    return X


# --------------------------------------------------------------------------- #
#  Step 3 — Train Isolation Forest
# --------------------------------------------------------------------------- #
def train_model(X: np.ndarray, contamination: float = 0.01):
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    log.info("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    log.info("Training IsolationForest  (n_estimators=200, contamination=%.3f)...", contamination)
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=contamination,   # expected fraction of anomalies in training set
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )
    model.fit(X_scaled)

    # Self-evaluate: fraction the model itself marks as anomalous
    preds  = model.predict(X_scaled)
    n_anom = (preds == -1).sum()
    log.info("Self-evaluation: %d / %d flows flagged as anomalous (%.1f%%)",
             n_anom, len(preds), 100 * n_anom / len(preds))

    return model, scaler


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        description="Extract NFStream features from a pcap and train an "
                    "Isolation Forest outlier detector."
    )
    p.add_argument("--pcap",         required=True,                   help="Input .pcap file")
    p.add_argument("--model-out",    default="model.pkl",             help="Where to save the trained model")
    p.add_argument("--scaler-out",   default="scaler.pkl",            help="Where to save the fitted scaler")
    p.add_argument("--features-csv", default="",                      help="(Optional) save feature table to CSV")
    p.add_argument("--contamination",type=float, default=0.01,        help="IsolationForest contamination param (default 0.01)")
    p.add_argument("--verbose",      action="store_true",             help="Verbose debug logging")
    return p.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate input
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        log.error("pcap file not found: %s", pcap_path)
        sys.exit(1)

    # ---- 1. Extract flows ------------------------------------------------- #
    df_raw = extract_features(str(pcap_path))

    # ---- 2. Prepare features ---------------------------------------------- #
    X_df = prepare_features(df_raw)

    # Optionally persist feature table
    if args.features_csv:
        X_df.to_csv(args.features_csv, index=False)
        log.info("Feature table saved -> %s", args.features_csv)

    # ---- 3. Train --------------------------------------------------------- #
    model, scaler = train_model(X_df.values, contamination=args.contamination)

    # ---- 4. Save ---------------------------------------------------------- #
    model_path  = Path(args.model_out)
    scaler_path = Path(args.scaler_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    scaler_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model,  model_path,  compress=3)
    joblib.dump(scaler, scaler_path, compress=3)

    log.info("Model  saved -> %s", model_path)
    log.info("Scaler saved -> %s", scaler_path)

    # ---- 5. Print a usage snippet ----------------------------------------- #
    print()
    print("=" * 60)
    print("  Training complete!")
    print(f"  Flows used for training : {len(X_df):,}")
    print(f"  Feature count           : {X_df.shape[1]}")
    print(f"  Model                   : {model_path}")
    print(f"  Scaler                  : {scaler_path}")
    print("=" * 60)
    print()
    print("  Inference snippet:")
    print("  ──────────────────")
    print("    import joblib, numpy as np")
    print(f"    model  = joblib.load('{model_path}')")
    print(f"    scaler = joblib.load('{scaler_path}')")
    print("    # X_new: 2-D numpy array with the same feature columns")
    print("    scores = model.score_samples(scaler.transform(X_new))")
    print("    # score < threshold  =>  anomaly")
    print("    # A common threshold: np.percentile(training_scores, 5)")
    print()


if __name__ == "__main__":
    main()