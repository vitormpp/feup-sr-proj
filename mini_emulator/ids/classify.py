"""
classify.py
===========
Train and evaluate classifiers on features extracted from a PCAP file.

Usage
-----
    python classify.py capture.pcap
    python classify.py capture.pcap --algos rf lr
    python classify.py capture.pcap --algos rf svm dt --test-size 0.3
    python classify.py capture.pcap --known 10.0.0.1 10.0.0.2 --window 2.0

Algorithms
----------
    rf   Random Forest
    lr   Logistic Regression
    svm  Support Vector Machine (RBF kernel)
    dt   Decision Tree
    knn  k-Nearest Neighbours

All algorithms that accept class_weight use class_weight='balanced'.
Random Forest uses its built-in balanced class weighting.
"""

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from ids.feature_extraction import extract_features

# ---------------------------------------------------------------------------
# Algorithm registry
# ---------------------------------------------------------------------------

# Algorithms that need feature scaling before fitting.
_NEEDS_SCALING = {"lr", "svm", "knn"}

_CLASSIFIERS = {
    "rf":  RandomForestClassifier( n_estimators=60, max_depth=12, min_samples_leaf=10, class_weight="balanced", random_state=42, n_jobs=-1,),
    "lr":  LogisticRegression(max_iter=1000, class_weight="balanced",
                              random_state=42),
    "svm": SVC(kernel="rbf", class_weight="balanced", random_state=42,
               probability=True),
    "dt":  DecisionTreeClassifier(class_weight="balanced", random_state=42),
    "knn": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
}


DEFAULT_ALGOS = ["rf", "lr", "dt", "knn"]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Classify packets in a PCAP file using ML algorithms.")
    parser.add_argument("pcap", help="Path to .pcap / .pcapng file")
    parser.add_argument(
        "--algos", nargs="+", default=DEFAULT_ALGOS,
        choices=_CLASSIFIERS.keys(), metavar="ALGO",
        help=f"Algorithms to run (default: {DEFAULT_ALGOS}). "
             f"Choices: {list(_CLASSIFIERS)}")
    parser.add_argument(
        "--test-size", type=float, default=0.2,
        help="Fraction of data held out for testing (default: 0.2)")
    parser.add_argument(
        "--known", nargs="*", default=None, metavar="IP",
        help="Whitelist of known IP addresses; unrecognised IPs are dropped")
    parser.add_argument(
        "--window", type=float, default=1.0,
        help="Rolling-feature look-back window in seconds (default: 1.0)")
    parser.add_argument(
        "--model-dir", type=Path, default=None, metavar="DIR",
        help="If set, save fitted models and scalers to this directory")
    args = parser.parse_args()

    # ---- extract features --------------------------------------------------
    print(f"Loading {args.pcap} …")
    try:
        df = extract_features(args.pcap,
                              known_addresses=args.known,
                              window_seconds=args.window)
    except Exception as exc:
        sys.exit(f"Feature extraction failed: {exc}")

    df.to_csv("features.csv", index=False)
    print("  Features saved to features.csv")

    X = df.drop(columns=["label"]).values.astype(np.float32)
    y = df["label"].values

    n_pos = y.sum()
    print(f"  {len(y)} packets  |  {n_pos} malicious ({100*n_pos/len(y):.1f}%)  "
          f"|  {len(y)-n_pos} normal\n")

    if n_pos == 0 or n_pos == len(y):
        sys.exit("Only one class present — cannot train a classifier.")

    # Stratify so both train and test sets preserve the class ratio.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y)

    # ---- run each algorithm ------------------------------------------------
    for name in args.algos:
        clf = _CLASSIFIERS[name]

        if name in _NEEDS_SCALING:
            scaler  = StandardScaler()
            X_tr    = scaler.fit_transform(X_train)
            X_te    = scaler.transform(X_test)
        else:
            scaler  = None
            X_tr, X_te = X_train, X_test

        clf.fit(X_tr, y_train)
        y_pred = clf.predict(X_te)
        y_prob = clf.predict_proba(X_te)[:, 1]

        auc = roc_auc_score(y_test, y_prob)
        print(f"=== {name.upper()} ===")
        print(classification_report(y_test, y_pred,
                                    target_names=["normal", "malicious"],
                                    digits=3))
        print(f"  ROC-AUC: {auc:.4f}\n")

        if args.model_dir is not None:
            args.model_dir.mkdir(parents=True, exist_ok=True)
            joblib.dump(clf, args.model_dir / f"{name}.joblib")
            if scaler is not None:
                joblib.dump(scaler, args.model_dir / f"{name}_scaler.joblib")
            print(f"  Saved {name}.joblib to {args.model_dir}\n")


if __name__ == "__main__":
    main()