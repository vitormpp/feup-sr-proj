"""
outlier_models.py
=================
Stage 4a: unsupervised / semi-supervised anomaly detection.

Per the task note, every outlier detector is trained on **normal flows only** --
it learns the shape of legitimate traffic and flags whatever falls outside.
The malicious flows are kept aside and only revealed at evaluation time.

Protocol
--------
``train_outlier_models(X_train_normal, X_test, y_test)``:
  * scaler is fit on the normal training data only,
  * each detector is fit on the scaled normal data,
  * we score the test set (mixture of normal + malicious) and report.

Models compared
----------------
  * IsolationForest      -- random-split isolation depth
  * LocalOutlierFactor   -- local density (novelty mode)
  * OneClassSVM          -- RBF boundary around normal data
  * EllipticEnvelope     -- robust Gaussian assumption

Each returns a dict with the fitted estimator, the binary prediction on the
test set (1 = malicious) and a continuous anomaly score (higher = more
anomalous) suitable for ROC / PR curves.
"""

from __future__ import annotations

import logging

import numpy as np
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from . import config

log = logging.getLogger("ids.outlier")


def _build_detectors(contamination: float):
    """Return name -> (estimator, uses_decision_function) detector zoo."""
    return {
        "IsolationForest": IsolationForest(
            n_estimators=200, contamination=contamination,
            random_state=config.RANDOM_STATE, n_jobs=-1,
        ),
        "LocalOutlierFactor": LocalOutlierFactor(
            n_neighbors=20, novelty=True, contamination=contamination,
        ),
        "OneClassSVM": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
        "EllipticEnvelope": EllipticEnvelope(
            contamination=contamination, support_fraction=None,
            random_state=config.RANDOM_STATE,
        ),
    }


def _anomaly_score(est, X):
    """Continuous score where *higher = more anomalous*.

    sklearn's ``score_samples``/``decision_function`` return higher = more
    normal, so we negate.
    """
    if hasattr(est, "score_samples"):
        return -est.score_samples(X)
    return -est.decision_function(X)


def train_outlier_models(X_train_normal: np.ndarray,
                          X_test: np.ndarray,
                          y_test: np.ndarray,
                          contamination: float = 0.05) -> dict:
    """Fit every detector on normal-only data; score the held-out test set."""
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_train_normal)
    X_te = scaler.transform(X_test)

    log.info("Outlier detectors: trained on %d normal flows, tested on %d "
             "(%d malicious).", len(X_tr), len(X_te), int(y_test.sum()))

    results: dict[str, dict] = {}
    for name, est in _build_detectors(contamination).items():
        log.info("  fitting %s ...", name)
        try:
            est.fit(X_tr)
        except Exception as e:
            log.error("  failed to fit %s: %s", name, e)
            continue
        raw = est.predict(X_te)                 # -1 outlier / +1 inlier
        y_pred = np.where(raw == -1, 1, 0)      # -> 1 malicious / 0 normal
        scores = _anomaly_score(est, X_te)
        results[name] = {
            "estimator": est,
            "scaler": scaler,
            "y_true": y_test,
            "y_pred": y_pred,
            "scores": scores,
            "family": "outlier",
        }
    return results
