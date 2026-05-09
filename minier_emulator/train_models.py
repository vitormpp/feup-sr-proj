#!/usr/bin/env python3
"""
pcap_classifier.py
------------------
Accepts two folders of pcap files (normal vs malicious), extracts flow
features with nfstream, trains a Random Forest classifier AND an Isolation
Forest outlier detector, validates both on a held-out mixed dataset, and
saves the models.

Usage:
    python pcap_classifier.py --normal ./pcaps/normal/ --malicious ./pcaps/malicious/

    Each folder may contain any number of .pcap / .pcapng files.
    All files in a folder are treated as belonging to the same class.

Dependencies:
    pip install nfstream scikit-learn pandas joblib
"""

import argparse
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from nfstream import NFStreamer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}

# ---------------------------------------------------------------------------
# Feature columns produced by nfstream (statistical_analysis=True).
# All names match the actual to_pandas() output columns.
# Any column absent from a particular file is silently skipped.
# ---------------------------------------------------------------------------
FEATURE_COLS = [
    # Durations
    "bidirectional_duration_ms",
    "src2dst_duration_ms",
    "dst2src_duration_ms",
    # Packet / byte counts
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "dst2src_packets",
    "src2dst_bytes",
    "dst2src_bytes",
    # Packet-size statistics
    "bidirectional_min_ps",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",
    "src2dst_min_ps",
    "src2dst_mean_ps",
    "src2dst_stddev_ps",
    "src2dst_max_ps",
    "dst2src_min_ps",
    "dst2src_mean_ps",
    "dst2src_stddev_ps",
    "dst2src_max_ps",
    # Inter-arrival time statistics
    "bidirectional_min_piat_ms",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_max_piat_ms",
    "src2dst_min_piat_ms",
    "src2dst_mean_piat_ms",
    "src2dst_stddev_piat_ms",
    "src2dst_max_piat_ms",
    "dst2src_min_piat_ms",
    "dst2src_mean_piat_ms",
    "dst2src_stddev_piat_ms",
    "dst2src_max_piat_ms",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_pcaps(folder: Path):
    """Return all pcap-like files directly inside *folder* (non-recursive)."""
    files = [f for f in sorted(folder.iterdir())
             if f.is_file() and f.suffix.lower() in PCAP_SUFFIXES]
    return files


def extract_one(pcap_path: Path, label: str) -> pd.DataFrame:
    """Extract flows from a single pcap file and return a labelled DataFrame."""
    streamer = NFStreamer(
        source=str(pcap_path),
        statistical_analysis=True,
        splt_analysis=0,
        n_dissections=0,
    )
    df = streamer.to_pandas()

    if df is None or df.empty:
        print(f"    WARNING: no flows in {pcap_path.name}")
        return pd.DataFrame()

    available = [c for c in FEATURE_COLS if c in df.columns]
    df = df[available].copy()
    df["label"] = label
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    print(f"    {pcap_path.name}: {len(df)} flows")
    return df


def extract_folder(folder: Path, label: str) -> pd.DataFrame:
    """Extract and concatenate flows from all pcaps in *folder*."""
    pcaps = find_pcaps(folder)
    if not pcaps:
        sys.exit(f"ERROR: no pcap files found in {folder}")

    print(f"  [{label}] {len(pcaps)} file(s) in {folder}")
    frames = [extract_one(p, label) for p in pcaps]
    frames = [f for f in frames if not f.empty]

    if not frames:
        sys.exit(f"ERROR: all pcap files in {folder} produced zero flows.")

    combined = pd.concat(frames, ignore_index=True)
    print(f"  [{label}] total flows: {len(combined)}")
    return combined


def print_confusion(y_true, y_pred, title: str):
    labels = sorted(set(y_true) | set(y_pred))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    print(f"\n  Confusion matrix -- {title}")
    header = "        " + "  ".join(f"{l:>12}" for l in labels)
    print(header)
    for row_label, row in zip(labels, cm):
        print(f"  {row_label:>8}  " + "  ".join(f"{v:>12}" for v in row))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Train RF classifier + Isolation Forest on folders of pcap files."
    )
    parser.add_argument("--normal",     required=True,
                        help="Folder containing normal-traffic pcap files")
    parser.add_argument("--malicious",  required=True,
                        help="Folder containing malicious-traffic pcap files")
    parser.add_argument("--test-ratio", type=float, default=0.3,
                        help="Fraction of each class reserved for validation (default 0.3)")
    parser.add_argument("--out-dir",    default=".",
                        help="Directory where models are saved (default: current dir)")
    args = parser.parse_args()

    normal_dir    = Path(args.normal)
    malicious_dir = Path(args.malicious)
    out_dir       = Path(args.out_dir)

    for d in (normal_dir, malicious_dir):
        if not d.is_dir():
            sys.exit(f"ERROR: {d} is not a directory.")
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Feature extraction
    # ------------------------------------------------------------------
    print("\n[1/4] Extracting features ...")
    df_normal    = extract_folder(normal_dir,    label="normal")
    df_malicious = extract_folder(malicious_dir, label="malicious")

    # Align to the common feature set present in both
    common_features = [
        c for c in df_normal.columns
        if c in df_malicious.columns and c != "label"
    ]
    df_normal    = df_normal[common_features + ["label"]]
    df_malicious = df_malicious[common_features + ["label"]]
    print(f"\n  Using {len(common_features)} features: {common_features}")

    # ------------------------------------------------------------------
    # 2. Train / test split (per class, then merged)
    # ------------------------------------------------------------------
    print(f"\n[2/4] Splitting data (test ratio = {args.test_ratio}) ...")

    def split(df):
        return train_test_split(df, test_size=args.test_ratio,
                                random_state=42, shuffle=True)

    train_normal,    test_normal    = split(df_normal)
    train_malicious, test_malicious = split(df_malicious)

    # Combined shuffled training set (for Random Forest)
    train_all = (pd.concat([train_normal, train_malicious], ignore_index=True)
                   .sample(frac=1, random_state=42)
                   .reset_index(drop=True))
    X_train = train_all[common_features].values
    y_train = train_all["label"].values

    # Mixed shuffled validation set
    test_all = (pd.concat([test_normal, test_malicious], ignore_index=True)
                  .sample(frac=1, random_state=99)
                  .reset_index(drop=True))
    X_test = test_all[common_features].values
    y_test = test_all["label"].values

    print(f"  Training   : {len(X_train):>8} flows  "
          f"(normal={len(train_normal)}, malicious={len(train_malicious)})")
    print(f"  Validation : {len(X_test):>8} flows  "
          f"(normal={len(test_normal)}, malicious={len(test_malicious)})")

    # Fit scaler on the combined training set
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # ------------------------------------------------------------------
    # 3a. Random Forest — trained on labelled mixed data
    # ------------------------------------------------------------------
    print("\n[3/4] Training models ...")
    print("  -> Random Forest classifier (mixed labelled data) ...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)

    rf_preds = rf.predict(X_test_scaled)
    print("\n  -- Random Forest (supervised classification) --")
    print(classification_report(y_test, rf_preds))
    print_confusion(y_test, rf_preds, "Random Forest")

    # ------------------------------------------------------------------
    # 3b. Isolation Forest — trained on NORMAL flows only
    # ------------------------------------------------------------------
    print("\n  -> Isolation Forest (normal flows only) ...")
    X_train_normal_scaled = scaler.transform(train_normal[common_features].values)
    print(f"     Training on {len(X_train_normal_scaled)} normal flows.")

    iso = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    iso.fit(X_train_normal_scaled)

    # +1 = inlier (normal), -1 = outlier (malicious)
    iso_preds = np.where(iso.predict(X_test_scaled) == 1, "normal", "malicious")

    print("\n  -- Isolation Forest (unsupervised outlier detection) --")
    print(classification_report(y_test, iso_preds))
    print_confusion(y_test, iso_preds, "Isolation Forest")

    # ------------------------------------------------------------------
    # 4. Save everything
    # ------------------------------------------------------------------
    print("\n[4/4] Saving models ...")
    artifacts = {
        "random_forest.joblib":    rf,
        "isolation_forest.joblib": iso,
        "scaler.joblib":           scaler,
        "feature_names.joblib":    common_features,
    }
    for filename, obj in artifacts.items():
        fpath = out_dir / filename
        joblib.dump(obj, fpath)
        print(f"  Saved: {fpath}")

    print("\nDone.")
    print("\nTo reload and reuse:")
    print("  import joblib, numpy as np")
    print("  rf       = joblib.load('random_forest.joblib')")
    print("  iso      = joblib.load('isolation_forest.joblib')")
    print("  scaler   = joblib.load('scaler.joblib')")
    print("  features = joblib.load('feature_names.joblib')")
    print("  X = scaler.transform(df[features])")
    print("  rf_preds  = rf.predict(X)")
    print("  iso_preds = np.where(iso.predict(X) == 1, 'normal', 'malicious')")


if __name__ == "__main__":
    main()