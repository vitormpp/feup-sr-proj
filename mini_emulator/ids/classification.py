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
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_validate
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

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


def _build_classifiers():
    rs = config.RANDOM_STATE
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


def cross_validate_classifiers(X, y, n_splits: int = 5) -> dict:
    """Run stratified K-fold CV for every classifier.

    Returns ``{name: {...}}`` with CV score arrays, mean/std, out-of-fold
    predictions + probabilities, and a final model fit on all data.
    """
    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=int)

    minority = int(min(np.bincount(y))) if len(np.unique(y)) > 1 else 0
    if minority < 2:
        raise SystemExit(
            f"Need >=2 samples of each class for CV; minority class has {minority}.")
    n_splits = max(2, min(n_splits, minority))
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True,
                         random_state=config.RANDOM_STATE)
    log.info("Stratified %d-fold CV on %d flows (%d malicious).",
             n_splits, len(y), int(y.sum()))

    results: dict[str, dict] = {}
    for name, est in _build_classifiers().items():
        log.info("  cross-validating %s ...", name)
        pipe = _pipeline(est)
        cv_scores = cross_validate(pipe, X, y, cv=cv, scoring=_SCORING,
                                   n_jobs=-1, return_train_score=False)
        # out-of-fold predictions for an honest confusion matrix / curves
        y_oof = cross_val_predict(pipe, X, y, cv=cv, n_jobs=-1)
        try:
            proba = cross_val_predict(pipe, X, y, cv=cv, method="predict_proba",
                                      n_jobs=-1)[:, 1]
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
