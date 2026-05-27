"""
visualization.py
================
Stage 6: evaluation + exploratory visualisations (task requirement #4).

All figures are written as PNGs to an output directory using the headless Agg
backend, so this runs fine over SSH on the SEED VM.

The gallery:
  1. dataset_overview      - class balance + why each flow was labelled
  2. feature_separation    - ridge-style normal-vs-malicious distributions for
                             the most discriminative features
  3. correlation_heatmap   - feature correlation structure
  4. pca_embedding         - 2-D PCA scatter, true label vs an IsolationForest's
                             anomaly score (side by side)
  5. model_comparison      - grouped bars across F1 / recall / ROC-AUC / PR-AUC
  6. roc_pr_curves         - overlaid ROC + Precision-Recall curves
  7. confusion_matrices    - small-multiple confusion heatmaps for every model
  8. anomaly_scores        - outlier-score distributions, normal vs malicious
  9. cv_stability          - per-fold F1 box/strip plot for the classifiers
 10. metric_radar          - radar/spider chart comparing models on 5 axes
"""

from __future__ import annotations

import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
)
from sklearn.preprocessing import StandardScaler

from . import config

log = logging.getLogger("ids.viz")

plt.rcParams.update({
    "figure.dpi": 120,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "font.size": 10,
})

_NORMAL_C = "#2a9d8f"
_MAL_C = "#e76f51"


def _save(fig, outdir: Path, name: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / name
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    log.info("  wrote %s", path)
    return path


# --------------------------------------------------------------------------- #
# 1. dataset overview
# --------------------------------------------------------------------------- #
def dataset_overview(df: pd.DataFrame, outdir: Path) -> Path:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))

    counts = df[config.LABEL_COLUMN].value_counts().reindex([0, 1]).fillna(0)
    ax1.bar(["normal", "malicious"], counts.values,
            color=[_NORMAL_C, _MAL_C])
    for i, v in enumerate(counts.values):
        ax1.text(i, v, f"{int(v):,}", ha="center", va="bottom", fontweight="bold")
    ax1.set_title("Flow class balance")
    ax1.set_ylabel("flows")

    if "_label_reason" in df.columns:
        reason = df["_label_reason"].value_counts()
        colors = {"normal": _NORMAL_C, "rogue_node": _MAL_C, "foreign_ip": "#f4a261"}
        ax2.pie(reason.values, labels=reason.index, autopct="%1.1f%%",
                colors=[colors.get(r, "#888") for r in reason.index],
                wedgeprops=dict(width=0.45, edgecolor="w"))
        ax2.set_title("Why each flow was labelled")
    else:
        ax2.axis("off")
    fig.suptitle("Dataset overview", fontweight="bold")
    return _save(fig, outdir, "01_dataset_overview.png")


# --------------------------------------------------------------------------- #
# 2. feature separation (ridge-style)
# --------------------------------------------------------------------------- #
def feature_separation(X: pd.DataFrame, y: np.ndarray, outdir: Path,
                       top_k: int = 8) -> Path:
    # rank features by standardised mean difference between the two classes
    mu0, mu1 = X[y == 0].mean(), X[y == 1].mean()
    sd = X.std().replace(0, np.nan)
    smd = ((mu1 - mu0).abs() / sd).fillna(0).sort_values(ascending=False)
    feats = smd.head(top_k).index.tolist()

    fig, axes = plt.subplots(len(feats), 1, figsize=(8, 1.05 * len(feats)),
                             sharex=False)
    if len(feats) == 1:
        axes = [axes]
    for ax, f in zip(axes, feats):
        for cls, color, lab in [(0, _NORMAL_C, "normal"), (1, _MAL_C, "malicious")]:
            vals = X.loc[y == cls, f].astype(float)
            if vals.nunique() < 2:
                continue
            lo, hi = np.percentile(vals, [1, 99])
            vals = vals.clip(lo, hi)
            ax.hist(vals, bins=40, density=True, alpha=0.55, color=color,
                    label=lab)
        ax.set_ylabel(f, rotation=0, ha="right", va="center", fontsize=8)
        ax.set_yticks([])
    axes[0].legend(loc="upper right", fontsize=8)
    fig.suptitle("Most discriminative features: normal vs malicious",
                 fontweight="bold")
    return _save(fig, outdir, "02_feature_separation.png")


# --------------------------------------------------------------------------- #
# 3. correlation heatmap
# --------------------------------------------------------------------------- #
def correlation_heatmap(X: pd.DataFrame, outdir: Path) -> Path:
    corr = X.corr().fillna(0).values
    n = corr.shape[0]
    fig, ax = plt.subplots(figsize=(0.32 * n + 3, 0.32 * n + 3))
    im = ax.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(n)); ax.set_yticks(range(n))
    ax.set_xticklabels(X.columns, rotation=90, fontsize=6)
    ax.set_yticklabels(X.columns, fontsize=6)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Pearson r")
    ax.set_title("Feature correlation", fontweight="bold")
    return _save(fig, outdir, "03_correlation_heatmap.png")


# --------------------------------------------------------------------------- #
# 4. PCA embedding: ground truth vs anomaly score
# --------------------------------------------------------------------------- #
def pca_embedding(X: pd.DataFrame, y: np.ndarray, outdir: Path,
                  anomaly_scores: np.ndarray | None = None) -> Path:
    Xs = StandardScaler().fit_transform(X)
    coords = PCA(n_components=2, random_state=config.RANDOM_STATE).fit_transform(Xs)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    a = axes[0]
    for cls, color, lab in [(0, _NORMAL_C, "normal"), (1, _MAL_C, "malicious")]:
        m = y == cls
        a.scatter(coords[m, 0], coords[m, 1], s=8, alpha=0.5, c=color, label=lab)
    a.legend(); a.set_title("PCA - ground truth")
    a.set_xlabel("PC1"); a.set_ylabel("PC2")

    b = axes[1]
    if anomaly_scores is not None:
        sc = b.scatter(coords[:, 0], coords[:, 1], s=8, alpha=0.6,
                       c=anomaly_scores, cmap="magma")
        fig.colorbar(sc, ax=b, label="anomaly score (higher = more anomalous)")
        b.set_title("PCA - IsolationForest anomaly score")
    else:
        b.axis("off")
    b.set_xlabel("PC1"); b.set_ylabel("PC2")
    fig.suptitle("Flows projected to 2-D", fontweight="bold")
    return _save(fig, outdir, "04_pca_embedding.png")


# --------------------------------------------------------------------------- #
# 5. model comparison bars
# --------------------------------------------------------------------------- #
def model_comparison(table: pd.DataFrame, outdir: Path) -> Path:
    metrics = ["recall", "precision", "f1", "roc_auc", "pr_auc"]
    metrics = [m for m in metrics if m in table.columns]
    models = table.index.tolist()
    x = np.arange(len(models))
    w = 0.8 / len(metrics)

    fig, ax = plt.subplots(figsize=(1.6 * len(models) + 3, 5))
    for i, m in enumerate(metrics):
        ax.bar(x + i * w, table[m].fillna(0).values, w, label=m)
    ax.set_xticks(x + 0.4 - w / 2)
    ax.set_xticklabels(models, rotation=20, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("score")
    ax.legend(ncol=len(metrics), fontsize=8, loc="lower center",
              bbox_to_anchor=(0.5, 1.01))
    ax.set_title("Model comparison", fontweight="bold", pad=28)
    return _save(fig, outdir, "05_model_comparison.png")


# --------------------------------------------------------------------------- #
# 6. ROC + PR curves
# --------------------------------------------------------------------------- #
def roc_pr_curves(results: dict, outdir: Path) -> Path:
    fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(12, 5))
    for name, r in results.items():
        sc = r.get("scores")
        if sc is None or len(np.unique(r["y_true"])) < 2:
            continue
        fpr, tpr, _ = roc_curve(r["y_true"], sc)
        ax_roc.plot(fpr, tpr, label=name, lw=1.8)
        prec, rec, _ = precision_recall_curve(r["y_true"], sc)
        ax_pr.plot(rec, prec, label=name, lw=1.8)
    ax_roc.plot([0, 1], [0, 1], "k--", lw=0.8, alpha=0.5)
    ax_roc.set_xlabel("false positive rate"); ax_roc.set_ylabel("true positive rate")
    ax_roc.set_title("ROC curves"); ax_roc.legend(fontsize=8)
    ax_pr.set_xlabel("recall"); ax_pr.set_ylabel("precision")
    ax_pr.set_title("Precision-Recall curves"); ax_pr.legend(fontsize=8)
    fig.suptitle("Discrimination curves (score-based models)", fontweight="bold")
    return _save(fig, outdir, "06_roc_pr_curves.png")


# --------------------------------------------------------------------------- #
# 7. confusion-matrix small multiples
# --------------------------------------------------------------------------- #
def confusion_matrices(results: dict, outdir: Path) -> Path:
    names = list(results.keys())
    ncol = min(4, len(names))
    nrow = int(np.ceil(len(names) / ncol))
    fig, axes = plt.subplots(nrow, ncol, figsize=(3 * ncol, 3 * nrow))
    axes = np.atleast_1d(axes).ravel()
    for ax, name in zip(axes, names):
        r = results[name]
        cm = confusion_matrix(r["y_true"], r["y_pred"], labels=[0, 1])
        im = ax.imshow(cm, cmap="Blues")
        ax.set_title(name, fontsize=9)
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(["norm", "mal"], fontsize=8)
        ax.set_yticklabels(["norm", "mal"], fontsize=8)
        ax.set_xlabel("predicted", fontsize=8); ax.set_ylabel("actual", fontsize=8)
        thr = cm.max() / 2 if cm.max() else 0
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                        color="white" if cm[i, j] > thr else "black",
                        fontsize=9, fontweight="bold")
    for ax in axes[len(names):]:
        ax.axis("off")
    fig.suptitle("Confusion matrices", fontweight="bold")
    return _save(fig, outdir, "07_confusion_matrices.png")


# --------------------------------------------------------------------------- #
# 8. anomaly score distributions (outlier detectors)
# --------------------------------------------------------------------------- #
def anomaly_score_distributions(outlier_results: dict, outdir: Path) -> Path:
    names = list(outlier_results.keys())
    ncol = min(2, len(names))
    nrow = int(np.ceil(len(names) / ncol))
    fig, axes = plt.subplots(nrow, ncol, figsize=(6 * ncol, 3.4 * nrow))
    axes = np.atleast_1d(axes).ravel()
    for ax, name in zip(axes, names):
        r = outlier_results[name]
        sc, y = np.asarray(r["scores"]), np.asarray(r["y_true"])
        lo, hi = np.percentile(sc, [1, 99])
        bins = np.linspace(lo, hi, 50)
        ax.hist(sc[y == 0].clip(lo, hi), bins=bins, density=True, alpha=0.6,
                color=_NORMAL_C, label="normal")
        ax.hist(sc[y == 1].clip(lo, hi), bins=bins, density=True, alpha=0.6,
                color=_MAL_C, label="malicious")
        ax.set_title(name, fontsize=10)
        ax.set_xlabel("anomaly score"); ax.set_yticks([])
        ax.legend(fontsize=8)
    for ax in axes[len(names):]:
        ax.axis("off")
    fig.suptitle("Outlier scores: normal vs malicious", fontweight="bold")
    return _save(fig, outdir, "08_anomaly_scores.png")


# --------------------------------------------------------------------------- #
# 9. CV stability (per-fold F1)
# --------------------------------------------------------------------------- #
def cv_stability(clf_results: dict, outdir: Path) -> Path:
    names, data = [], []
    for name, r in clf_results.items():
        if "cv_scores" in r and "f1" in r["cv_scores"]:
            names.append(name)
            data.append(r["cv_scores"]["f1"])
    if not data:
        return outdir / "09_cv_stability.png"
    fig, ax = plt.subplots(figsize=(1.4 * len(names) + 3, 5))
    bp = ax.boxplot(data, labels=names, patch_artist=True, widths=0.5)
    for patch in bp["boxes"]:
        patch.set_facecolor("#8ecae6"); patch.set_alpha(0.7)
    for i, d in enumerate(data, 1):
        ax.scatter(np.full(len(d), i) + np.random.uniform(-0.08, 0.08, len(d)),
                   d, color="#023047", s=18, zorder=3)
    ax.set_ylabel("F1 (per fold)")
    ax.set_title("Cross-validation stability across folds", fontweight="bold")
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
    return _save(fig, outdir, "09_cv_stability.png")


# --------------------------------------------------------------------------- #
# 10. metric radar / spider chart
# --------------------------------------------------------------------------- #
def metric_radar(table: pd.DataFrame, outdir: Path) -> Path:
    metrics = [m for m in ["recall", "precision", "f1", "roc_auc", "pr_auc"]
               if m in table.columns]
    angles = np.linspace(0, 2 * np.pi, len(metrics), endpoint=False).tolist()
    angles += angles[:1]
    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    cmap = plt.get_cmap("tab10")
    for i, (name, row) in enumerate(table.iterrows()):
        vals = [float(row[m]) if not pd.isna(row[m]) else 0.0 for m in metrics]
        vals += vals[:1]
        ax.plot(angles, vals, lw=1.8, label=name, color=cmap(i % 10))
        ax.fill(angles, vals, alpha=0.07, color=cmap(i % 10))
    ax.set_xticks(angles[:-1]); ax.set_xticklabels(metrics)
    ax.set_ylim(0, 1)
    ax.set_title("Model profiles", fontweight="bold", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=8)
    return _save(fig, outdir, "10_metric_radar.png")


# --------------------------------------------------------------------------- #
# orchestrating helper
# --------------------------------------------------------------------------- #
def generate_all(df_labeled: pd.DataFrame, X: pd.DataFrame, y: np.ndarray,
                 clf_results: dict, outlier_results: dict,
                 comparison_table: pd.DataFrame, outdir: str | Path,
                 pca_anomaly_scores: np.ndarray | None = None) -> list[Path]:
    """Produce the whole gallery; returns the list of written paths.

    ``pca_anomaly_scores`` should be an anomaly score per row of ``X`` (full
    set) for the PCA colour map; if its length doesn't match it is ignored.
    """
    outdir = Path(outdir)
    all_results = {**clf_results, **outlier_results}
    full_scores = (pca_anomaly_scores
                   if (pca_anomaly_scores is not None
                       and len(pca_anomaly_scores) == len(X)) else None)

    paths = [
        dataset_overview(df_labeled, outdir),
        feature_separation(X, y, outdir),
        correlation_heatmap(X, outdir),
        pca_embedding(X, y, outdir, anomaly_scores=full_scores),
        model_comparison(comparison_table, outdir),
        roc_pr_curves(all_results, outdir),
        confusion_matrices(all_results, outdir),
        cv_stability(clf_results, outdir),
        metric_radar(comparison_table, outdir),
    ]
    if outlier_results:
        paths.append(anomaly_score_distributions(outlier_results, outdir))
    return paths
