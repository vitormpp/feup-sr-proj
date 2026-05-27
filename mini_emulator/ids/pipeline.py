"""
pipeline.py
===========
Orchestrator / CLI tying the stages together:

    pcap --NFStream--> raw flows --label--> matrix
        |                                     |
        |                          +----------+-----------+
        |                          |                      |
        |                outlier detectors        CV classifiers
        |               (fit on normal only)   (StratifiedKFold)
        |                          |                      |
        +-----------------> evaluation + visualisation gallery

Run (inside the SEED Ubuntu VM, where NFStream/libpcap live)::

    python -m ids.pipeline \\
        --pcap captures_full/capture_20260527_085807/merged.pcap \\
        --outdir ids_out

The NFStream pass is cached to ``<outdir>/flows_raw.csv``; re-runs skip it.
To iterate on the ML/plots only (no NFStream needed) point ``--features-csv``
at an existing cache, or re-run with the cache already present.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

from . import (
    classification,
    config,
    evaluation,
    feature_extraction,
    labeling,
    outlier_models,
    preprocessing,
    visualization,
)

log = logging.getLogger("ids")


def run(pcap: str | None, outdir: str, features_csv: str | None,
        force_extract: bool, test_size: float, n_splits: int,
        contamination: float, no_plots: bool) -> None:
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)
    cache = Path(features_csv) if features_csv else outdir_p / "flows_raw.csv"

    # --- 1. extract (or load cache) -------------------------------------- #
    raw = feature_extraction.load_or_extract(pcap, cache, force=force_extract)

    # --- 2. label -------------------------------------------------------- #
    labeled = labeling.add_labels(raw)
    labeled.to_csv(outdir_p / "flows_labeled.csv", index=False)

    # --- 3. feature matrix (identity/time columns dropped here) ---------- #
    X, y, feat_names = preprocessing.build_matrix(labeled)
    X.assign(label=y).to_csv(outdir_p / "features.csv", index=False)

    if len(np.unique(y)) < 2:
        log.error("Only one class present -- cannot train/evaluate. Abort.")
        sys.exit(1)

    # --- 4. shared stratified train/test split --------------------------- #
    Xtr, Xte, ytr, yte = train_test_split(
        X.values, y, test_size=test_size, stratify=y,
        random_state=config.RANDOM_STATE)

    # --- 5a. outlier detection (fit on NORMAL training flows only) ------- #
    Xtr_normal = Xtr[ytr == 0]
    if len(Xtr_normal) < 10:
        log.warning("Very few normal training flows (%d).", len(Xtr_normal))
    outlier_results = outlier_models.train_outlier_models(
        Xtr_normal, Xte, yte, contamination=contamination)

    # --- 5b. supervised classification with cross-validation ------------- #
    clf_results = classification.cross_validate_classifiers(
        X.values, y, n_splits=n_splits)
    cv_table = classification.cv_summary_table(clf_results)
    cv_table.to_csv(outdir_p / "cv_scores.csv")

    # --- 6. evaluation --------------------------------------------------- #
    table = evaluation.evaluate_all(clf_results, outlier_results)
    evaluation.print_report(table)
    table.to_csv(outdir_p / "model_comparison.csv")

    print("Cross-validation summary (mean +/- std):")
    with __import__("pandas").option_context("display.width", 140,
                                              "display.max_columns", 30):
        print(cv_table.round(3).to_string())
    print()

    # --- 7. visualisation ------------------------------------------------ #
    if not no_plots:
        log.info("Rendering visualisations -> %s", outdir_p)
        # anomaly score per *full-set* row for the PCA colour map
        iso = outlier_results.get("IsolationForest")
        pca_scores = None
        if iso is not None:
            est, scaler = iso["estimator"], iso["scaler"]
            pca_scores = -est.score_samples(scaler.transform(X.values))
        paths = visualization.generate_all(
            labeled, X, y, clf_results, outlier_results, table,
            outdir_p / "figures", pca_anomaly_scores=pca_scores)
        log.info("Wrote %d figures to %s", len(paths), outdir_p / "figures")

    best = table[table["family"] == "classifier"]["f1"].idxmax()
    best_o = table[table["family"] == "outlier"]["f1"].idxmax()
    print(f"Artifacts written to: {outdir_p.resolve()}")
    print(f"  best classifier (F1): {best}")
    print(f"  best outlier detector (F1): {best_o}")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="NFStream + scikit-learn intrusion-detection pipeline.")
    p.add_argument("--pcap", help="input pcap (omitted if a feature cache exists)")
    p.add_argument("--outdir", default="ids_out", help="output directory")
    p.add_argument("--features-csv",
                   help="path to a cached raw-flow CSV (skips NFStream)")
    p.add_argument("--force-extract", action="store_true",
                   help="re-run NFStream even if a cache exists")
    p.add_argument("--test-size", type=float, default=0.3,
                   help="held-out fraction for outlier-detector evaluation")
    p.add_argument("--cv-splits", type=int, default=5,
                   help="StratifiedKFold splits for classification")
    p.add_argument("--contamination", type=float, default=0.05,
                   help="expected outlier fraction for the detectors")
    p.add_argument("--no-plots", action="store_true", help="skip figures")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S")
    run(pcap=args.pcap, outdir=args.outdir, features_csv=args.features_csv,
        force_extract=args.force_extract, test_size=args.test_size,
        n_splits=args.cv_splits, contamination=args.contamination,
        no_plots=args.no_plots)


if __name__ == "__main__":
    main()
