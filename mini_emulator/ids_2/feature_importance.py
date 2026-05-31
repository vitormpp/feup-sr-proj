"""
feature_importance.py
=====================

Load a saved classifier/anomaly detector and report which features
contribute most to its predictions.

Usage
-----
    python -m ids_2.feature_importance models/rf.joblib features.csv
    python -m ids_2.feature_importance models/lr.joblib features.csv --top 20
    python -m ids_2.feature_importance outlier_detection_models/iforest.joblib features.csv

Methods used per model type
---------------------------
    RandomForest / DecisionTree
        -> model.feature_importances_

    LogisticRegression / Linear models
        -> abs(model.coef_[0])

    IsolationForest
        -> permutation importance based on anomaly score changes

    SVC (RBF), KNN, others
        -> sklearn permutation_importance()
"""

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.inspection import permutation_importance


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_SAMPLES_FOR_IMPORTANCE = 5000
IFOREST_REPEATS = 5
PERMUTATION_REPEATS = 5


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_features(path: str) -> tuple[np.ndarray, list[str], np.ndarray | None]:
    p = Path(path)

    if p.suffix == ".joblib":
        df = joblib.load(p)
    else:
        df = pd.read_csv(p)

    y = df["label"].values if "label" in df.columns else None

    df = df.drop(columns=["label"], errors="ignore")

    return (
        df.values.astype(np.float32),
        list(df.columns),
        y,
    )


# ---------------------------------------------------------------------------
# Isolation Forest importance
# ---------------------------------------------------------------------------

def isolation_forest_importance(
    model: IsolationForest,
    X: np.ndarray,
    feature_names: list[str],
    n_repeats: int = IFOREST_REPEATS,
) -> pd.Series:
    """
    Feature importance for IsolationForest.

    Measures how much the anomaly scores change when a feature
    is randomly permuted.
    """

    rng = np.random.default_rng(42)

    baseline_scores = model.score_samples(X)

    importances = np.zeros(X.shape[1], dtype=np.float64)

    print(
        f"  Running IsolationForest permutation importance "
        f"({X.shape[1]} features × {n_repeats} repeats)..."
    )

    for feature_idx in range(X.shape[1]):
        feature_importance = []

        for _ in range(n_repeats):
            X_perm = X.copy()

            shuffled = X_perm[:, feature_idx].copy()
            rng.shuffle(shuffled)
            X_perm[:, feature_idx] = shuffled

            perm_scores = model.score_samples(X_perm)

            change = np.mean(
                np.abs(baseline_scores - perm_scores)
            )

            feature_importance.append(change)

        importances[feature_idx] = np.mean(feature_importance)

    return pd.Series(importances, index=feature_names)


# ---------------------------------------------------------------------------
# Generic importance dispatcher
# ---------------------------------------------------------------------------

def get_importances(
    model,
    X: np.ndarray,
    y: np.ndarray | None,
    feature_names: list[str],
) -> pd.Series:

    mtype = type(model).__name__

    # --------------------------------------------------
    # Tree models
    # --------------------------------------------------

    if hasattr(model, "feature_importances_"):
        scores = model.feature_importances_

    # --------------------------------------------------
    # Linear models
    # --------------------------------------------------

    elif hasattr(model, "coef_"):
        coef = model.coef_

        if coef.ndim == 1:
            scores = np.abs(coef)
        else:
            scores = np.mean(np.abs(coef), axis=0)

    # --------------------------------------------------
    # Isolation Forest
    # --------------------------------------------------

    elif isinstance(model, IsolationForest):
        return isolation_forest_importance(
            model,
            X,
            feature_names,
        )

    # --------------------------------------------------
    # Generic permutation importance
    # --------------------------------------------------

    else:

        if y is None:
            sys.exit(
                f"{mtype} has no built-in feature importance and "
                f"permutation importance requires labels."
            )

        if not hasattr(model, "score"):
            sys.exit(
                f"{mtype} does not provide feature importances and "
                f"does not implement score()."
            )

        print(
            f"  {mtype} has no built-in importances — "
            f"running permutation importance..."
        )

        result = permutation_importance(
            model,
            X,
            y,
            n_repeats=PERMUTATION_REPEATS,
            random_state=42,
            n_jobs=-1,
        )

        scores = result.importances_mean

    return pd.Series(scores, index=feature_names)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:

    parser = argparse.ArgumentParser(
        description="Report feature importances for a saved sklearn model."
    )

    parser.add_argument(
        "model",
        help="Path to saved .joblib model",
    )

    parser.add_argument(
        "features",
        help="Feature CSV or DataFrame joblib",
    )

    parser.add_argument(
        "--scaler",
        default=None,
        help="Optional scaler used during training",
    )

    parser.add_argument(
        "--top",
        type=int,
        default=15,
        help="Number of top features to display",
    )

    parser.add_argument(
        "--max-samples",
        type=int,
        default=MAX_SAMPLES_FOR_IMPORTANCE,
        help=(
            "Maximum samples used when computing "
            "permutation-based importances"
        ),
    )

    args = parser.parse_args()

    model = joblib.load(args.model)

    print(f"Loaded {type(model).__name__} from {args.model}")

    X, feature_names, y = load_features(args.features)

    print(f"Loaded {X.shape[0]} samples, {X.shape[1]} features")

    # --------------------------------------------------
    # Scaling
    # --------------------------------------------------

    if args.scaler:
        scaler = joblib.load(args.scaler)
        X = scaler.transform(X)
        print(f"Applied scaler from {args.scaler}")

    # --------------------------------------------------
    # Subsample large datasets
    # --------------------------------------------------

    if len(X) > args.max_samples:

        rng = np.random.default_rng(42)

        idx = rng.choice(
            len(X),
            size=args.max_samples,
            replace=False,
        )

        X = X[idx]

        if y is not None:
            y = y[idx]

        print(
            f"Using random subset of {len(X)} samples "
            f"for importance calculation"
        )

    # --------------------------------------------------
    # Compute importances
    # --------------------------------------------------

    importances = get_importances(
        model,
        X,
        y,
        feature_names,
    )

    importances = importances.sort_values(ascending=False)

    # --------------------------------------------------
    # Display
    # --------------------------------------------------

    top_n = min(args.top, len(importances))

    print(
        f"\nTop {top_n} features "
        f"({type(model).__name__}):"
    )

    print("-" * 70)

    max_score = importances.iloc[0]

    for rank, (feat, score) in enumerate(
        importances.head(top_n).items(),
        start=1,
    ):
        bar_len = 0

        if max_score > 0:
            bar_len = int((score / max_score) * 30)

        bar = "█" * bar_len

        print(
            f"{rank:>3}. "
            f"{feat:<35} "
            f"{score:>10.6f}  "
            f"{bar}"
        )

    # --------------------------------------------------
    # Save CSV
    # --------------------------------------------------

    out_path = Path(args.model).with_suffix(
        ".feature_importances.csv"
    )

    importances.rename(
        "importance"
    ).to_csv(
        out_path,
        header=True,
    )

    print(f"\nFull ranking saved to {out_path}")


if __name__ == "__main__":
    main()