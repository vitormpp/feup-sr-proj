"""
pipeline_alt.py
===============
Orchestrator for the **per-packet, online, behaviour-labelled** IDS variant.

    pcap --pkt-extractor--> per-packet rows --behaviour-labels--> matrix
        |                                                            |
        |                          +---------------------------------+
        |                          |                                 |
        |               outlier detectors                   (Stratified)GroupKFold
        |              (fit on normal only,                  classifier CV
        |               flow-grouped split via               grouped by flow
        |               GroupShuffleSplit, retried           instance
        |               if test split has zero               + per-attack-type
        |               malicious packets)                   breakdown
        |                          |                                 |
        +-----------------> evaluation + visualisation gallery

Online rule (CRITICAL)
----------------------
The extractor and ``config_alt`` ship NO completed-flow summary features.
Every value the model sees is computable from packets at-or-before the
current timestamp -- so the metrics here describe what a real-time IDS could
plausibly achieve.

Behaviour-based labels (CRITICAL)
---------------------------------
Labels come from packet-pattern signatures of actual attacks (SYN-flood
burst, ARP binding conflict, BGP UPDATE cluster), not from endpoint identity.
A model trained on identity labels learns "is this the rogue?" -- which the
extractor deliberately strips. Now it has a chance to learn what attacks
actually look like.

Group-based CV (CRITICAL)
-------------------------
``_flow_key`` is passed as ``groups`` so train and test never share a flow
instance. Without this the classifiers memorise flow fingerprints and the
metrics become meaningless.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from . import (
    classification,
    config_alt as config,
    evaluation,
    feature_extraction_packets as feature_extraction,
    labeling_alt as labeling,
    outlier_models,
    preprocessing,
    visualization,
)

log = logging.getLogger("ids")

# Detectors that don't suit per-packet rows. EllipticEnvelope assumes Gaussian
# inputs but the per-packet matrix is full of boolean one-hots and zero-
# inflated counts; OneClassSVM is O(n^2) at fit/predict.
_OUTLIER_SKIP = {"EllipticEnvelope", "OneClassSVM"}


def _grouped_split_with_malicious(values, y, groups, test_size: float,
                                  random_state: int, n_attempts: int = 10):
    """GroupShuffleSplit that retries until the test side has malicious rows.

    GroupShuffleSplit is not stratified, so with few malicious flow instances
    a single random split can put all of them in train. We retry with
    different seeds until the test split contains malicious rows, or give up
    after ``n_attempts`` and return the last split with a loud warning.
    """
    for attempt in range(n_attempts):
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size,
                                random_state=random_state + attempt)
        tr_idx, te_idx = next(gss.split(values, y, groups=groups))
        if y[te_idx].sum() > 0:
            return tr_idx, te_idx
    log.warning("Grouped split could not put any malicious rows in test after "
                "%d attempts -- outlier metrics will be undefined.", n_attempts)
    return tr_idx, te_idx


def run(pcap: str | None, outdir: str, features_csv: str | None,
        force_extract: bool, test_size: float, n_splits: int,
        contamination: float, no_plots: bool,
        idle_timeout_ms: int, max_rows_per_flow: int,
        attack_windows_csv: str | None) -> None:
    outdir_p = Path(outdir)
    outdir_p.mkdir(parents=True, exist_ok=True)
    cache = Path(features_csv) if features_csv else outdir_p / "packets_raw.csv"

    # --- 1. extract (or load cache) -------------------------------------- #
    raw = feature_extraction.load_or_extract(
        pcap, cache, force=force_extract,
        idle_timeout_ms=idle_timeout_ms,
        max_rows_per_flow=max_rows_per_flow,
        rng_seed=config.RANDOM_STATE,
    )

    # --- 2. behaviour-based label --------------------------------------- #
    labeled = labeling.add_labels(raw, attack_windows_csv=attack_windows_csv)
    labeled.to_csv(outdir_p / "packets_labeled.csv", index=False)

    if labeled.empty:
        log.error("No packets to train on. Abort.")
        sys.exit(1)

    # --- 3. feature matrix (identity/time columns dropped here) ---------- #
    X, y, feat_names, groups = preprocessing.build_matrix(
        labeled, cfg=config, return_groups=True)
    X.assign(label=y).to_csv(outdir_p / "features.csv", index=False)

    if len(np.unique(y)) < 2:
        log.error("Only one class present after labelling -- cannot evaluate. "
                  "Try lowering SYN_PER_WINDOW / BGP_BURST_COUNT in "
                  "labeling_alt.py, or supply attack_windows.csv.")
        sys.exit(1)

    # The per-attack labels we keep for the per-attack breakdown report.
    attack_types = labeled["_attack_type"].to_numpy()

    # --- 4. flow-grouped train/test split (with retry) ------------------- #
    tr_idx, te_idx = _grouped_split_with_malicious(
        X.values, y, groups, test_size=test_size,
        random_state=config.RANDOM_STATE)
    Xtr, Xte = X.values[tr_idx], X.values[te_idx]
    ytr, yte = y[tr_idx], y[te_idx]
    log.info("Group split: %d train rows (%d malicious) / %d test rows (%d malicious).",
             len(tr_idx), int(ytr.sum()), len(te_idx), int(yte.sum()))

    # --- 5a. outlier detection ------------------------------------------ #
    Xtr_normal = Xtr[ytr == 0]
    if len(Xtr_normal) < 10:
        log.warning("Very few normal training rows (%d).", len(Xtr_normal))
    outlier_results = outlier_models.train_outlier_models(
        Xtr_normal, Xte, yte, contamination=contamination,
        skip_models=_OUTLIER_SKIP)

    # --- 5b. supervised classification ---------------------------------- #
    clf_results = classification.cross_validate_classifiers(
        X.values, y, n_splits=n_splits, groups=groups, profile="packet")
    cv_table = classification.cv_summary_table(clf_results)
    cv_table.to_csv(outdir_p / "cv_scores.csv")

    # --- 6. evaluation --------------------------------------------------- #
    table = evaluation.evaluate_all(clf_results, outlier_results)
    evaluation.print_report(table)
    table.to_csv(outdir_p / "model_comparison.csv")

    # Per-attack-type breakdown. For the supervised classifiers this uses
    # out-of-fold predictions over the FULL dataset (so attack_types aligns
    # directly). For the outlier detectors only the test split is predicted,
    # so the breakdown there uses the test-row attack_types. Share the
    # column set across both calls so concat doesn't pad with NaN.
    test_attack_types = attack_types[te_idx]
    distinct_types = sorted(
        t for t in set(attack_types) | set(test_attack_types) if t != "benign"
    )
    clf_breakdown = evaluation.per_attack_breakdown(
        clf_results, attack_types=attack_types,
        distinct_types=distinct_types)
    out_breakdown = evaluation.per_attack_breakdown(
        outlier_results, attack_types=test_attack_types,
        distinct_types=distinct_types)
    full_breakdown = pd.concat([clf_breakdown, out_breakdown])
    evaluation.print_attack_breakdown(full_breakdown)
    full_breakdown.to_csv(outdir_p / "per_attack_breakdown.csv")

    print("Cross-validation summary (mean +/- std):")
    with pd.option_context("display.width", 140, "display.max_columns", 30):
        print(cv_table.round(3).to_string())
    print()

    # --- 7. visualisation ------------------------------------------------ #
    if not no_plots:
        log.info("Rendering visualisations -> %s", outdir_p)
        iso = outlier_results.get("IsolationForest")
        pca_scores = None
        if iso is not None:
            est, scaler = iso["estimator"], iso["scaler"]
            pca_scores = -est.score_samples(scaler.transform(X.values))
        paths = visualization.generate_all(
            labeled, X, y, clf_results, outlier_results, table,
            outdir_p / "figures", pca_anomaly_scores=pca_scores)
        log.info("Wrote %d figures to %s", len(paths), outdir_p / "figures")

    if not table[table["family"] == "classifier"].empty:
        best = table[table["family"] == "classifier"]["f1"].idxmax()
        print(f"  best classifier (F1): {best}")
    if not table[table["family"] == "outlier"].empty:
        best_o = table[table["family"] == "outlier"]["f1"].idxmax()
        print(f"  best outlier detector (F1): {best_o}")
    print(f"Artifacts written to: {outdir_p.resolve()}")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Per-packet, behaviour-labelled IDS pipeline.")
    p.add_argument("--pcap", help="input pcap (omitted if a feature cache exists)")
    p.add_argument("--outdir", default="ids_out", help="output directory")
    p.add_argument("--features-csv",
                   help="path to a cached per-packet CSV (skips extraction)")
    p.add_argument("--force-extract", action="store_true",
                   help="re-run the packet extractor even if a cache exists")
    p.add_argument("--test-size", type=float, default=0.3,
                   help="held-out fraction (flow-grouped) for outlier eval")
    p.add_argument("--cv-splits", type=int, default=5,
                   help="GroupKFold splits for classification")
    p.add_argument("--contamination", type=float, default=0.05,
                   help="expected outlier fraction for the detectors")
    p.add_argument("--idle-timeout-ms", type=int,
                   default=feature_extraction.FLOW_IDLE_TIMEOUT_MS,
                   help="flow idle-timeout (ms); past this a new flow instance starts")
    p.add_argument("--max-rows-per-flow", type=int,
                   default=feature_extraction.MAX_ROWS_PER_FLOW,
                   help="reservoir size per flow instance (unbiased sampling cap)")
    p.add_argument("--attack-windows",
                   help="optional CSV with ground-truth attack windows "
                        "(columns: start_ts,end_ts,attack_type,src_ip,dst_ip)")
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
        no_plots=args.no_plots,
        idle_timeout_ms=args.idle_timeout_ms,
        max_rows_per_flow=args.max_rows_per_flow,
        attack_windows_csv=args.attack_windows)


if __name__ == "__main__":
    main()
