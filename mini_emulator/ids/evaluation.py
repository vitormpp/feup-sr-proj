"""
evaluation.py
=============
Stage 5: compute a uniform metric record for every model, regardless of family.

Both outlier detectors and classifiers expose the same shape after their
training stage::

    result = {"y_true": ..., "y_pred": ..., "scores": ..., "family": ...}

so this module can score them all identically and return a tidy comparison
table.  For imbalanced intrusion data the headline metrics are recall on the
malicious class, F1, ROC-AUC and PR-AUC (average precision).
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

log = logging.getLogger("ids.eval")


def evaluate_one(name: str, result: dict) -> dict:
    """Return a flat metric dict for a single model result."""
    y_true = np.asarray(result["y_true"], dtype=int)
    y_pred = np.asarray(result["y_pred"], dtype=int)
    scores = result.get("scores")

    both_classes = len(np.unique(y_true)) > 1
    rec = {
        "model": name,
        "family": result.get("family", "?"),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }
    if scores is not None and both_classes:
        rec["roc_auc"] = roc_auc_score(y_true, scores)
        rec["pr_auc"] = average_precision_score(y_true, scores)
    else:
        rec["roc_auc"] = np.nan
        rec["pr_auc"] = np.nan

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    rec.update(tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))
    rec["false_positive_rate"] = fp / (fp + tn) if (fp + tn) else 0.0
    return rec


def evaluate_all(*result_groups: dict) -> pd.DataFrame:
    """Merge any number of result dicts into one sorted comparison table."""
    rows = []
    for group in result_groups:
        for name, result in group.items():
            rows.append(evaluate_one(name, result))
    df = pd.DataFrame(rows).set_index("model")
    return df.sort_values(["family", "f1"], ascending=[True, False])


def per_attack_breakdown(*result_groups: dict,
                          attack_types: np.ndarray | pd.Series,
                          distinct_types: list[str] | None = None) -> pd.DataFrame:
    """Per-attack-type recall + benign FPR, per model.

    ``attack_types`` is a per-row string array (e.g. from
    ``labeling_alt._attack_type``) aligned with each result's ``y_true``.
    For each non-benign attack class we report:

      * count    -- ground-truth packets of that class
      * recall   -- fraction of those packets the model flagged as malicious

    A single ``benign_fpr`` row reports the false-positive rate on packets
    whose ground-truth attack_type is "benign".

    ``distinct_types`` pins the column set; pass a shared list when calling
    this twice (e.g. once per model family) so both tables have the same
    columns and ``pd.concat`` doesn't pad with NaN.

    This is the metric that actually matters: "F1 = 0.87" doesn't tell you
    whether the model catches the SYN flood; this table does.
    """
    attack_types = pd.Series(attack_types).reset_index(drop=True).astype(str)
    benign_mask = (attack_types == "benign").to_numpy()
    benign_n = int(benign_mask.sum())
    if distinct_types is None:
        distinct = sorted(t for t in attack_types.unique() if t != "benign")
    else:
        distinct = [t for t in distinct_types if t != "benign"]

    rows = []
    for group in result_groups:
        for name, result in group.items():
            y_pred = np.asarray(result["y_pred"], dtype=int)
            row: dict[str, object] = {
                "model": name,
                "family": result.get("family", "?"),
            }
            for atk in distinct:
                m = (attack_types == atk).to_numpy()
                cnt = int(m.sum())
                if cnt == 0:
                    row[f"{atk}_recall"] = float("nan")
                    row[f"{atk}_n"] = 0
                    continue
                row[f"{atk}_recall"] = float(y_pred[m].sum()) / cnt
                row[f"{atk}_n"] = cnt
            row["benign_fpr"] = (
                float(y_pred[benign_mask].sum()) / benign_n if benign_n else float("nan")
            )
            row["benign_n"] = benign_n
            rows.append(row)
    return pd.DataFrame(rows).set_index("model")


def print_attack_breakdown(breakdown: pd.DataFrame) -> None:
    """Pretty-print the per-attack table -- the headline diagnostic."""
    with pd.option_context("display.float_format", lambda v: f"{v:.3f}",
                           "display.width", 140, "display.max_columns", 30):
        print("\n" + "=" * 78)
        print("  PER-ATTACK BREAKDOWN  (recall on each attack class; FPR on benign)")
        print("=" * 78)
        print(breakdown.to_string())
        print("=" * 78 + "\n")


def print_report(table: pd.DataFrame) -> None:
    cols = ["family", "precision", "recall", "f1", "roc_auc", "pr_auc",
            "tp", "fp", "fn", "tn"]
    with pd.option_context("display.float_format", lambda v: f"{v:.3f}",
                           "display.width", 120):
        print("\n" + "=" * 78)
        print("  MODEL COMPARISON  (malicious = positive class)")
        print("=" * 78)
        print(table[cols].to_string())
        print("=" * 78 + "\n")
