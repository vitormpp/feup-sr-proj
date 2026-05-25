"""
Malicious Traffic Detection using NFStream + scikit-learn
==========================================================
- Reads all .pcap files from a folder
- Labels flows as malicious if they originate from a specified MAC address
  or from a source IP not present in the KNOWN_IPS whitelist
- Trains a supervised classifier (Random Forest) on all labeled data
- Trains an unsupervised outlier detector (Isolation Forest) on normal flows only
- Evaluates and reports both models

Usage:
    python detect_malicious.py --pcap-dir ./pcaps --malicious-mac "aa:bb:cc:dd:ee:ff"

Requirements:
    pip install nfstream scikit-learn pandas numpy
"""

import argparse
import os
import sys
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

warnings.filterwarnings("ignore")

# ── NFStream ──────────────────────────────────────────────────────────────────
try:
    from nfstream import NFStreamer
except ImportError:
    sys.exit("nfstream is not installed. Run: pip install nfstream")

# ── scikit-learn ──────────────────────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

# ─────────────────────────────────────────────────────────────────────────────
# NFStream numeric features available for every flow
# (string / IP / port columns are dropped before training)
# ─────────────────────────────────────────────────────────────────────────────
NUMERIC_FEATURES = [
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_duration_ms",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_duration_ms",
    "dst2src_packets",
    "dst2src_bytes",
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
    "bidirectional_syn_packets",
    "bidirectional_cwr_packets",
    "bidirectional_ece_packets",
    "bidirectional_urg_packets",
    "bidirectional_ack_packets",
    "bidirectional_psh_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
    "src2dst_syn_packets",
    "src2dst_cwr_packets",
    "src2dst_ece_packets",
    "src2dst_urg_packets",
    "src2dst_ack_packets",
    "src2dst_psh_packets",
    "src2dst_rst_packets",
    "src2dst_fin_packets",
    "dst2src_syn_packets",
    "dst2src_cwr_packets",
    "dst2src_ece_packets",
    "dst2src_urg_packets",
    "dst2src_ack_packets",
    "dst2src_psh_packets",
    "dst2src_rst_packets",
    "dst2src_fin_packets",
]


# ─────────────────────────────────────────────────────────────────────────────
# Whitelist of known-good source IPs.
# Any flow whose source IP is NOT in this set will be labelled malicious,
# in addition to flows from the malicious MAC address.
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_IPS: set[str] = {
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.5",
    "172.16.0.1",
    "172.16.0.2",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def normalise_mac(mac: str) -> str:
    """Lowercase and normalise MAC to colon-separated format."""
    return mac.strip().lower().replace("-", ":").replace(".", ":")


def extract_flows(pcap_path: str, malicious_mac: str,
                  known_ips: set[str]) -> pd.DataFrame:
    """
    Stream a pcap through NFStream and return a DataFrame with a 'label' column.
    A flow is labelled 1 (malicious) if ANY of the following is true:
      - its source MAC matches malicious_mac
      - its source IP is not present in known_ips
    Otherwise it is labelled 0 (normal).
    """
    streamer = NFStreamer(
        source=pcap_path,
        statistical_analysis=True,   # enables all the ps/piat stats
        decode_tunnels=True,
        accounting_mode=0,           # raw bytes
    )

    rows = []
    for flow in streamer:
        row = flow.__dict__.copy() if hasattr(flow, "__dict__") else {}
        if not row:
            # Fallback: convert to dict via _fields (namedtuple-style)
            row = {k: getattr(flow, k, None) for k in flow._fields} if hasattr(flow, "_fields") else {}
        rows.append(row)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    # ── Condition 1: source MAC matches the malicious MAC ──
    src_mac_col = next((c for c in df.columns if "src_mac" in c.lower()), None)
    if src_mac_col is None:
        print(f"  [!] No MAC column found in {pcap_path}. MAC rule will not be applied.")
        bad_mac = pd.Series(False, index=df.index)
    else:
        bad_mac = (
            df[src_mac_col]
            .fillna("")
            .str.lower()
            .str.strip()
            .eq(malicious_mac)
        )

    # ── Condition 2: source IP is not in the known-IPs whitelist ──
    src_ip_col = next((c for c in df.columns if c.lower() in ("src_ip", "src_ip6")), None)
    if src_ip_col is None:
        print(f"  [!] No source-IP column found in {pcap_path}. IP rule will not be applied.")
        unknown_ip = pd.Series(False, index=df.index)
    else:
        unknown_ip = ~df[src_ip_col].fillna("").isin(known_ips)

    # ── Label: malicious if either condition is true ──
    df["label"] = (bad_mac | unknown_ip).astype(int)

    return df


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Keep only numeric feature columns that are present in the DataFrame."""
    available = [c for c in NUMERIC_FEATURES if c in df.columns]
    missing   = [c for c in NUMERIC_FEATURES if c not in df.columns]
    if missing:
        print(f"  [~] {len(missing)} feature(s) not found and will be skipped "
              f"(e.g. {missing[:3]}{'...' if len(missing)>3 else ''})")
    X = df[available].copy()
    # Replace inf / NaN with 0
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    return X


# ─────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────────────────────────────────────

def main(pcap_dir: str, malicious_mac: str, test_size: float = 0.25,
         n_estimators: int = 200, contamination: float = "auto",
         random_state: int = 42):

    malicious_mac = normalise_mac(malicious_mac)
    pcap_files = sorted(Path(pcap_dir).glob("*.pcap")) + \
                 sorted(Path(pcap_dir).glob("*.pcapng"))

    if not pcap_files:
        sys.exit(f"No .pcap / .pcapng files found in '{pcap_dir}'")

    print(f"\n{'='*60}")
    print(f"  Found {len(pcap_files)} pcap file(s) in '{pcap_dir}'")
    print(f"  Malicious MAC  : {malicious_mac}")
    print(f"  Known IPs      : {len(KNOWN_IPS)} address(es) whitelisted")
    print(f"{'='*60}\n")

    # ── 1. Feature extraction ──────────────────────────────────────────────
    all_frames = []
    for pcap in pcap_files:
        print(f"  Streaming: {pcap.name}")
        df = extract_flows(str(pcap), malicious_mac, KNOWN_IPS)
        if df.empty:
            print(f"    → No flows extracted, skipping.")
            continue
        n_mal = int(df["label"].sum())
        print(f"    → {len(df)} flows  |  {n_mal} malicious  |  {len(df)-n_mal} normal")
        all_frames.append(df)

    if not all_frames:
        sys.exit("No flows were extracted from any pcap file. Aborting.")

    data = pd.concat(all_frames, ignore_index=True)
    print(f"\nTotal flows : {len(data)}")
    print(f"  Malicious : {int(data['label'].sum())}")
    print(f"  Normal    : {int((data['label']==0).sum())}\n")

    X = build_feature_matrix(data)
    y = data["label"].values

    if X.empty:
        sys.exit("Feature matrix is empty — no numeric features available.")

    if y.sum() == 0:
        print("[!] No malicious flows detected. Check --malicious-mac value.")
    if (y == 0).sum() == 0:
        sys.exit("No normal flows found. Cannot train outlier detector.")

    # ── 2. Train / test split ───────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y if y.sum() > 1 else None
    )
    print(f"Train size : {len(X_train)}   Test size : {len(X_test)}\n")

    # ─────────────────────────────────────────────────────────────────────
    # MODEL A: Supervised Classifier (Random Forest)
    # ─────────────────────────────────────────────────────────────────────
    print("─" * 60)
    print("MODEL A — Supervised Classifier (Random Forest)")
    print("─" * 60)

    clf_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    RandomForestClassifier(
            n_estimators=n_estimators,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        )),
    ])

    clf_pipeline.fit(X_train, y_train)
    y_pred_clf = clf_pipeline.predict(X_test)

    print(classification_report(y_test, y_pred_clf,
                                 target_names=["Normal", "Malicious"],
                                 zero_division=0))

    cm = confusion_matrix(y_test, y_pred_clf)
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(f"  [TN={cm[0,0]}  FP={cm[0,1]}]")
    print(f"  [FN={cm[1,0]}  TP={cm[1,1]}]")

    if y_test.sum() > 0 and (y_test == 0).sum() > 0:
        y_prob = clf_pipeline.predict_proba(X_test)[:, 1]
        print(f"\nROC-AUC (classifier) : {roc_auc_score(y_test, y_prob):.4f}")

    # ─────────────────────────────────────────────────────────────────────
    # MODEL B: Outlier / Anomaly Detector (Isolation Forest)
    # Trained on NORMAL flows ONLY
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("MODEL B — Outlier Detector (Isolation Forest)")
    print("  Trained on normal flows only")
    print("─" * 60)

    scaler_if = StandardScaler()
    X_train_normal = X_train[y_train == 0]
    print(f"  Normal training samples : {len(X_train_normal)}")

    X_train_normal_scaled = scaler_if.fit_transform(X_train_normal)
    X_test_scaled         = scaler_if.transform(X_test)

    iso_forest = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,   # "auto" or a float 0<x<0.5
        random_state=random_state,
        n_jobs=-1,
    )
    iso_forest.fit(X_train_normal_scaled)

    # IsolationForest: -1 = outlier (malicious), 1 = inlier (normal)
    raw_pred   = iso_forest.predict(X_test_scaled)
    y_pred_if  = np.where(raw_pred == -1, 1, 0)   # convert to 0/1

    print(classification_report(y_test, y_pred_if,
                                 target_names=["Normal", "Malicious"],
                                 zero_division=0))

    cm_if = confusion_matrix(y_test, y_pred_if)
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(f"  [TN={cm_if[0,0]}  FP={cm_if[0,1]}]")
    print(f"  [FN={cm_if[1,0]}  TP={cm_if[1,1]}]")

    # Outlier scores as an anomaly probability proxy
    scores = -iso_forest.score_samples(X_test_scaled)   # higher = more anomalous
    if y_test.sum() > 0 and (y_test == 0).sum() > 0:
        print(f"\nROC-AUC (outlier score) : {roc_auc_score(y_test, scores):.4f}")

    # ── 3. Feature importances (from classifier) ───────────────────────────
    print("\n" + "─" * 60)
    print("Top-10 most important features (Random Forest)")
    print("─" * 60)
    rf_model    = clf_pipeline.named_steps["clf"]
    importances = rf_model.feature_importances_
    feat_names  = X.columns.tolist()
    top10_idx   = np.argsort(importances)[::-1][:10]
    for rank, idx in enumerate(top10_idx, 1):
        print(f"  {rank:2d}. {feat_names[idx]:<40s}  {importances[idx]:.4f}")

    print("\nDone.\n")
    return clf_pipeline, (scaler_if, iso_forest)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detect malicious flows in pcap files using NFStream + scikit-learn"
    )
    parser.add_argument(
        "--pcap-dir",
        required=True,
        help="Directory containing .pcap / .pcapng files",
    )
    parser.add_argument(
        "--malicious-mac",
        required=True,
        help="Source MAC address to label as malicious (e.g. 'aa:bb:cc:dd:ee:ff')",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.25,
        help="Fraction of data for the test split (default: 0.25)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=200,
        help="Number of trees in both forest models (default: 200)",
    )
    parser.add_argument(
        "--contamination",
        default="auto",
        help="Expected outlier fraction for IsolationForest (default: 'auto'). "
             "Pass a float like 0.05 if you know the approximate ratio.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
    )

    args = parser.parse_args()

    contamination = args.contamination
    if contamination != "auto":
        contamination = float(contamination)

    main(
        pcap_dir       = args.pcap_dir,
        malicious_mac  = args.malicious_mac,
        test_size      = args.test_size,
        n_estimators   = args.n_estimators,
        contamination  = contamination,
        random_state   = args.random_state,
    )