"""
evaluate.py
===========
Load a features CSV and one or more saved models (produced by classify.py or
outlier.py) and print precision, recall, F1, ROC-AUC, and a full
classification report for each.

Usage
-----
    python evaluate.py features.csv --model-dir models/
    python evaluate.py features.csv --models models/rf.joblib models/lof.joblib
    python evaluate.py features.csv --model-dir models/ --no-downsample
    python evaluate.py features.csv --model-dir models/ --test-size 1.0

Notes
-----
* By default the same majority-class downsampling used in classify.py and
  outlier.py is applied before evaluation so metrics are comparable.
  Pass --no-downsample to evaluate on the full CSV instead.

* Classifiers (those with predict_proba) are detected automatically.
  Outlier detectors (those with decision_function but no predict_proba)
  have their raw scores negated so that higher = more anomalous, matching
  the AUC convention used in outlier.py.

* Scalers are loaded automatically if a file named <model>_scaler.joblib
  exists alongside the model file.

* --test-size controls what fraction of the (possibly downsampled) data is
  used for evaluation. Default 1.0 means the entire CSV is scored, which is
  fine for post-hoc inspection. Set to 0.2 to replicate the held-out test
  split used during training.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_models(model_paths: list[Path]) -> list[tuple[str, object, object | None]]:
    """
    Load each model file and, if present, its companion scaler.

    Returns a list of (name, model, scaler_or_None) triples.
    """
    loaded = []
    for path in model_paths:
        if not path.exists():
            print(f"  [WARN] model file not found, skipping: {path}")
            continue

        model = joblib.load(path)

        # Companion scaler: <stem>_scaler.joblib in the same directory.
        scaler_path = path.with_name(path.stem + "_scaler.joblib")
        scaler = joblib.load(scaler_path) if scaler_path.exists() else None

        name = path.stem
        loaded.append((name, model, scaler))
        scaler_note = f" (+ scaler)" if scaler is not None else ""
        print(f"  loaded: {path}{scaler_note}")

    return loaded


def _collect_model_paths(args: argparse.Namespace) -> list[Path]:
    """Gather .joblib paths from --models and/or --model-dir, excluding scalers."""
    paths: list[Path] = []

    if args.models:
        paths.extend(Path(p) for p in args.models)

    if args.model_dir:
        dir_path = Path(args.model_dir)
        if not dir_path.is_dir():
            sys.exit(f"[ERROR] --model-dir is not a directory: {dir_path}")
        for p in sorted(dir_path.glob("*.joblib")):
            if not p.stem.endswith("_scaler"):
                paths.append(p)

    if not paths:
        sys.exit("[ERROR] No models found. Use --models or --model-dir.")

    # Deduplicate while preserving order.
    seen: set[Path] = set()
    unique: list[Path] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def _predict(name: str, model, scaler, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Return (y_pred, y_score) for any sklearn classifier or outlier detector.

    Classifiers  : predict() + predict_proba()[:, 1]
    Detectors    : predict() mapped from {+1,-1} → {0,1}, score = -decision_function()
    """
    X_in = scaler.transform(X) if scaler is not None else X

    if hasattr(model, "predict_proba"):
        # Supervised classifier
        y_pred  = model.predict(X_in)
        y_score = model.predict_proba(X_in)[:, 1]
    elif hasattr(model, "decision_function"):
        # Outlier detector
        raw     = model.predict(X_in)
        y_pred  = (raw == -1).astype(int)
        y_score = -model.decision_function(X_in)
    else:
        sys.exit(f"[ERROR] Model '{name}' has neither predict_proba nor "
                 "decision_function — cannot score.")

    return y_pred, y_score


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate saved models against a features CSV.")
    parser.add_argument(
        "csv",
        help="Path to features CSV file (produced by pcap_to_csv.py).")
    parser.add_argument(
        "--models", nargs="+", metavar="PATH",
        help="One or more .joblib model files to evaluate.")
    parser.add_argument(
        "--model-dir", metavar="DIR",
        help="Directory of .joblib files; all non-scaler models are evaluated.")
    parser.add_argument(
        "--no-downsample", action="store_true",
        help="Skip majority-class downsampling; evaluate on the full CSV.")
    parser.add_argument(
        "--test-size", type=float, default=1.0, metavar="FRAC",
        help=(
            "Fraction of (possibly downsampled) data to evaluate on. "
            "Default 1.0 = full dataset. Use 0.2 to replicate the "
            "held-out split from training."))
    args = parser.parse_args()

    if not args.models and not args.model_dir:
        parser.error("Provide at least one of --models or --model-dir.")

    # ---- load CSV ----------------------------------------------------------
    print(f"\n[1/3] Loading {args.csv} …")
    try:
        df = pd.read_csv(args.csv)
    except Exception as exc:
        sys.exit(f"[ERROR] Failed to load CSV: {exc}")

    if "label" not in df.columns:
        sys.exit("[ERROR] CSV must contain a 'label' column.")

    # ---- optional downsampling ---------------------------------------------
    if not args.no_downsample:
        counts         = df["label"].value_counts()
        minority_n     = counts.min()
        majority_label = counts.idxmax()

        df_majority = df[df["label"] == majority_label].sample(
            n=minority_n, random_state=42)
        df_minority = df[df["label"] != majority_label]
        df = pd.concat([df_majority, df_minority]).sample(
            frac=1, random_state=42).reset_index(drop=True)

        print(f"  Downsampled majority class (label={majority_label}) to "
              f"{minority_n} samples — {len(df)} total rows.")
    else:
        print("  Downsampling skipped (--no-downsample).")

    X_all = df.drop(columns=["label"]).values.astype(np.float32)
    y_all = df["label"].values

    n_pos   = int(y_all.sum())
    n_total = len(y_all)
    print(f"  {n_total:,} rows  |  {n_pos:,} malicious ({100*n_pos/n_total:.1f}%)  "
          f"|  {n_total-n_pos:,} normal")

    if n_pos == 0 or n_pos == n_total:
        sys.exit("[ERROR] Only one class present — cannot compute metrics.")

    # ---- optional train/test split -----------------------------------------
    if args.test_size < 1.0:
        _, X_eval, _, y_eval = train_test_split(
            X_all, y_all,
            test_size=args.test_size, random_state=42, stratify=y_all)
        print(f"  Using held-out {args.test_size*100:.0f}% split "
              f"({len(y_eval):,} rows) for evaluation.")
    else:
        X_eval, y_eval = X_all, y_all
        print("  Evaluating on full dataset (--test-size 1.0).")

    # ---- load models -------------------------------------------------------
    print(f"\n[2/3] Loading models …")
    model_paths = _collect_model_paths(args)
    models      = _load_models(model_paths)

    if not models:
        sys.exit("[ERROR] No models could be loaded.")

    # ---- evaluate ----------------------------------------------------------
    print(f"\n[3/3] Evaluating {len(models)} model(s) …\n")
    print("=" * 60)

    for name, model, scaler in models:
        y_pred, y_score = _predict(name, model, scaler, X_eval)

        precision = precision_score(y_eval, y_pred, zero_division=0)
        recall    = recall_score(y_eval, y_pred, zero_division=0)
        f1        = f1_score(y_eval, y_pred, zero_division=0)
        auc       = roc_auc_score(y_eval, y_score)

        print(f"\n  MODEL : {name.upper()}")
        print(f"  {'Precision':<12} {precision:.4f}")
        print(f"  {'Recall':<12} {recall:.4f}")
        print(f"  {'F1':<12} {f1:.4f}")
        print(f"  {'ROC-AUC':<12} {auc:.4f}")
        print()
        print(classification_report(
            y_eval, y_pred,
            target_names=["normal", "malicious"],
            digits=3))
        print("=" * 60)


if __name__ == "__main__":
    main()