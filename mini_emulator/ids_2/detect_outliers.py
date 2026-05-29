"""
outlier.py
==========
Train and evaluate outlier detection algorithms on features extracted from
a PCAP file.

Usage
-----
    python outlier.py capture.pcap
    python outlier.py capture.pcap --algos iforest lof
    python outlier.py capture.pcap --known 10.0.0.1 10.0.0.2 --window 2.0

Algorithms
----------
    iforest   Isolation Forest          – unsupervised, train on normal only
    ocsvm     One-Class SVM             – unsupervised, train on normal only
    lof       Local Outlier Factor      – unsupervised, train on normal only
    envelope  Elliptic Envelope         – unsupervised, train on normal only

All algorithms are trained on normal (label=0) samples only and evaluated on
the full test set, which is the standard protocol for anomaly detection: the
model learns what "normal" looks like and flags deviations as outliers.

sklearn outlier detectors predict +1 for inliers and -1 for outliers.
These are mapped to label=0 (normal) and label=1 (malicious) for reporting.
"""

import argparse
import sys

import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from ids_2.feature_extraction import extract_features

# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------

_DETECTORS = {
    "iforest":  IsolationForest(contamination="auto", random_state=42,
                                n_jobs=-1),
    "ocsvm":    OneClassSVM(kernel="rbf", nu=0.1),
    "lof":      LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1),
    "envelope": EllipticEnvelope(contamination=0.1, random_state=42),
}

DEFAULT_ALGOS = ["iforest", "lof"]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate outlier detectors on packets from a PCAP file.")
    parser.add_argument("pcap", help="Path to .pcap / .pcapng file")
    parser.add_argument(
        "--algos", nargs="+", default=DEFAULT_ALGOS,
        choices=_DETECTORS.keys(), metavar="ALGO",
        help=f"Algorithms to run (default: {DEFAULT_ALGOS}). "
             f"Choices: {list(_DETECTORS)}")
    parser.add_argument(
        "--test-size", type=float, default=0.2,
        help="Fraction of data held out for testing (default: 0.2)")
    parser.add_argument(
        "--known", nargs="*", default=None, metavar="IP",
        help="Whitelist of known IP addresses")
    parser.add_argument(
        "--window", type=float, default=1.0,
        help="Rolling-feature look-back window in seconds (default: 1.0)")
    args = parser.parse_args()

    # ---- extract features --------------------------------------------------
    print(f"Loading {args.pcap} …")
    try:
        df = extract_features(args.pcap,
                              known_addresses=args.known,
                              window_seconds=args.window)
    except Exception as exc:
        sys.exit(f"Feature extraction failed: {exc}")

    X = df.drop(columns=["label"]).values.astype(np.float32)
    y = df["label"].values

    n_pos = y.sum()
    print(f"  {len(y)} packets  |  {n_pos} malicious ({100*n_pos/len(y):.1f}%)  "
          f"|  {len(y)-n_pos} normal\n")

    if n_pos == 0:
        sys.exit("No malicious samples — nothing to detect.")
    if n_pos == len(y):
        sys.exit("No normal samples — cannot train an outlier detector.")

    # Stratified split so both sets contain normal and malicious packets.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y)

    # All detectors here are trained on normal samples only.
    X_train_normal = X_train[y_train == 0]

    # Scale once; fit on normal training samples only to avoid leaking
    # outlier statistics into the scaler.
    scaler = StandardScaler()
    X_train_normal_s = scaler.fit_transform(X_train_normal)
    X_test_s         = scaler.transform(X_test)

    # ---- run each algorithm ------------------------------------------------
    for name in args.algos:
        det = _DETECTORS[name]
        det.fit(X_train_normal_s)

        # sklearn outlier detectors: +1 = inlier, -1 = outlier.
        # Map to 0 = normal, 1 = malicious to match our labels.
        raw_pred = det.predict(X_test_s)
        y_pred   = (raw_pred == -1).astype(int)

        # decision_function returns higher scores for inliers; negate so that
        # higher score = more anomalous, matching the convention for AUC.
        y_score = -det.decision_function(X_test_s)

        auc = roc_auc_score(y_test, y_score)
        print(f"=== {name.upper()} ===")
        print(classification_report(y_test, y_pred,
                                    target_names=["normal", "malicious"],
                                    digits=3))
        print(f"  ROC-AUC: {auc:.4f}\n")


if __name__ == "__main__":
    main()