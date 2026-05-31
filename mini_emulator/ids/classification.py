"""
classification.py
=================
Stage 4b: supervised classification with cross-validation (task note #2).

Each classifier is wrapped in a ``Pipeline([StandardScaler, clf])`` so the
scaler is re-fit inside every CV fold -- no information leaks from validation
folds into training.  We use ``StratifiedKFold`` because the malicious class is
the minority, and gather per-fold scores plus an out-of-fold
``cross_val_predict`` so the confusion matrix / ROC curve are built from
predictions the model never trained on.

Models compared
---------------
  * RandomForest
  * HistGradientBoosting
  * LogisticRegression
  * KNeighbors
  * DecisionTree   (a simple, interpretable baseline)

Returns, per model, the CV metric table, out-of-fold predictions/probabilities
and a final estimator fit on all data (handy for feature importance / reuse).
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_predict,
    cross_validate,
)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

try:
    # sklearn >= 1.0 ships StratifiedGroupKFold; fall back to GroupKFold if not.
    from sklearn.model_selection import StratifiedGroupKFold
except ImportError:  # pragma: no cover
    StratifiedGroupKFold = None  # type: ignore[assignment]
from sklearn.model_selection import GroupKFold

from . import config

log = logging.getLogger("ids.classify")

_SCORING = {
    "accuracy": "accuracy",
    "precision": "precision",
    "recall": "recall",
    "f1": "f1",
    "roc_auc": "roc_auc",
    "average_precision": "average_precision",   # PR-AUC, robust to imbalance
}


def _build_classifiers(profile: str = "flow") -> dict:
    """Build the classifier zoo for a given workload profile.

    ``profile="flow"`` keeps the original NFStream-style zoo (KNN + LogReg
    work fine on a few thousand flows).

    ``profile="packet"`` swaps out the choices that don't survive at packet
    scale: KNN gets dropped (O(n^2) at predict), LogReg's L-BFGS solver
    gets replaced by SGD with log-loss (linear in n).
    """
    rs = config.RANDOM_STATE
    if profile == "packet":
        return {
            "RandomForest": RandomForestClassifier(
                n_estimators=200, class_weight="balanced",
                random_state=rs, n_jobs=-1),
            "HistGradientBoosting": HistGradientBoostingClassifier(
                random_state=rs),
            "SGDLogReg": SGDClassifier(
                loss="log_loss", class_weight="balanced",
                max_iter=20, tol=1e-3, random_state=rs, n_jobs=-1),
            "DecisionTree": DecisionTreeClassifier(
                class_weight="balanced", random_state=rs),
        }
    return {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=rs, n_jobs=-1),
        "HistGradientBoosting": HistGradientBoostingClassifier(random_state=rs),
        "LogisticRegression": LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=rs),
        "KNeighbors": KNeighborsClassifier(n_neighbors=15, n_jobs=-1),
        "DecisionTree": DecisionTreeClassifier(
            class_weight="balanced", random_state=rs),
    }


def _pipeline(estimator) -> Pipeline:
    return Pipeline([("scaler", StandardScaler()), ("clf", estimator)])


def _make_cv(y: np.ndarray, groups: np.ndarray | None, n_splits: int):
    """Pick the right CV splitter and the actual usable n_splits.

    When ``groups`` is given (per-packet data), we need GroupKFold so that all
    packets of the same flow instance stay in the same fold -- otherwise a
    classifier just memorises flow fingerprints and reports impossible F1.
    Prefer StratifiedGroupKFold if available to preserve class balance per
    fold; fall back to plain GroupKFold otherwise.
    """
    minority = int(min(np.bincount(y))) if len(np.unique(y)) > 1 else 0
    if minority < 2:
        raise SystemExit(
            f"Need >=2 samples of each class for CV; minority class has {minority}.")
    n_splits = max(2, min(n_splits, minority))

    if groups is None:
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True,
                             random_state=config.RANDOM_STATE)
        log.info("Stratified %d-fold CV on %d rows (%d malicious).",
                 n_splits, len(y), int(y.sum()))
        return cv, n_splits

    # Number of distinct groups bounds the achievable split count too.
    n_groups = int(len(set(groups)))
    n_splits = max(2, min(n_splits, n_groups))
    if StratifiedGroupKFold is not None:
        cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True,
                                  random_state=config.RANDOM_STATE)
    else:
        cv = GroupKFold(n_splits=n_splits)
    log.info("Group %d-fold CV on %d rows / %d flow groups (%d malicious).",
             n_splits, len(y), n_groups, int(y.sum()))
    return cv, n_splits


def cross_validate_classifiers(X, y, n_splits: int = 5,
                               groups: np.ndarray | None = None,
                               profile: str = "flow") -> dict:
    """Run K-fold CV for every classifier.

    Pass ``groups`` (one id per row, e.g. the flow-instance id) to switch from
    plain StratifiedKFold to (Stratified)GroupKFold. With per-packet data the
    latter is mandatory to avoid leakage; classifier metrics computed without
    it on packet rows are not believable.

    ``profile`` selects the classifier zoo -- "packet" drops KNN and swaps
    LogReg for SGD so packet-scale CV finishes in minutes rather than hours.
    """
    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=int)
    if groups is not None:
        groups = np.asarray(groups)

    cv, _ = _make_cv(y, groups, n_splits)

    results: dict[str, dict] = {}
    for name, est in _build_classifiers(profile=profile).items():
        log.info("  cross-validating %s ...", name)
        pipe = _pipeline(est)
        cv_scores = cross_validate(pipe, X, y, cv=cv, scoring=_SCORING,
                                   n_jobs=-1, return_train_score=False,
                                   groups=groups)
        # out-of-fold predictions for an honest confusion matrix / curves
        y_oof = cross_val_predict(pipe, X, y, cv=cv, n_jobs=-1,
                                  groups=groups)
        try:
            proba = cross_val_predict(pipe, X, y, cv=cv,
                                      method="predict_proba",
                                      n_jobs=-1, groups=groups)[:, 1]
        except Exception:  # estimator without predict_proba
            proba = None

        final = _pipeline(est).fit(X, y)
        results[name] = {
            "cv_scores": {k: cv_scores[f"test_{k}"] for k in _SCORING},
            "y_true": y,
            "y_pred": y_oof,
            "scores": proba,
            "estimator": final,
            "family": "classifier",
        }
        f1 = cv_scores["test_f1"]
        log.info("    f1 = %.3f +/- %.3f", f1.mean(), f1.std())
    return results


def cv_summary_table(results: dict) -> pd.DataFrame:
    """Tidy mean +/- std table across models for quick comparison / printing."""
    rows = []
    for name, r in results.items():
        row = {"model": name}
        for metric, arr in r["cv_scores"].items():
            row[f"{metric}_mean"] = float(np.mean(arr))
            row[f"{metric}_std"] = float(np.std(arr))
        rows.append(row)
    return pd.DataFrame(rows).set_index("model")
