"""
evaluate_compare.py
===================
Load features CSVs and two folders of saved models, evaluate each model,
and produce a comprehensive suite of comparison plots.

Usage
-----
    python evaluate_compare.py features.csv \\
        --folder-a models/run_a/ --folder-b models/run_b/ \\
        --label-a "Experiment A" --label-b "Experiment B" \\
        --output-dir results/

    python evaluate_compare.py features.csv \\
        --folder-a models/baseline/ --folder-b models/tuned/ \\
        --no-downsample --test-size 0.2

Notes
-----
* Accepts one CSV that is shared across both folders, OR two separate CSVs
  via --csv-a / --csv-b (useful when the feature sets differ between runs).

* The same majority-class downsampling logic from the original evaluate.py
  is applied by default.  Pass --no-downsample to skip it.

* All plots are saved to --output-dir (default: eval_output/).
  A summary table is also written as a CSV.

* Plots produced:
    1.  bar_metrics              – Precision / Recall / F1 / ROC-AUC bars per model
    2.  roc_curves               – ROC curves, coloured by folder
    3.  pr_curves                – Precision-Recall curves, coloured by folder
    4.  confusion_matrices       – Grid of confusion matrices (normalised)
    5.  radar_chart              – Spider / radar chart of all four metrics per model
    6.  score_distributions      – KDE of decision scores split by true label
    7.  calibration_curves       – Reliability / calibration diagram (classifiers only)
    8.  metric_deltas            – Δ(folder_b − folder_a) bar chart for matched models
    9.  heatmap_metrics          – Heatmap of metrics × models, annotated
    10. scatter_f1_vs_auc        – Scatter F1 vs ROC-AUC, coloured by folder
    11. violin_scores            – Violin of decision scores split by folder & class
    12. rank_plot                – Model ranking per metric (parallel-coordinates style)
    -- Feature Importance --
    13. feature_importance       – Built-in importances or |coef| per model
    14. feature_importance_heatmap – Heatmap of importance scores across all models
    15. permutation_importance   – Model-agnostic permutation importance per model
    16. top_features_pairplot    – Pairplot of top-N features coloured by true class
    17. shap_summary             – SHAP beeswarm / bar (tree models; skipped if unavailable)
    -- Additional Diagnostics --
    18. threshold_sweep          – F1 / Precision / Recall vs decision threshold
    19. lift_curve               – Cumulative lift and gain curves
    20. learning_curve           – Train vs CV score as training size grows
    21. error_analysis           – FP-rate / FN-rate breakdown stacked bar per model
"""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path
from typing import Optional

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.gridspec import GridSpec
from sklearn.calibration import calibration_curve
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    auc,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import learning_curve, train_test_split

warnings.filterwarnings("ignore")

# ── Aesthetic constants ────────────────────────────────────────────────────────

PALETTE_A = "#3A86FF"   # folder A: electric blue
PALETTE_B = "#FF6B6B"   # folder B: coral red
GOOD      = "#0A9D8C"   # accent: teal (darker for white bg)
WARN      = "#E07B00"   # accent: amber (darker for white bg)
BG        = "#FFFFFF"   # white background
SURFACE   = "#F5F6FA"   # card surface
GRID      = "#DCDDE8"   # subtle grid
TEXT      = "#1A1A2E"   # primary text (dark)
SUBTEXT   = "#5C5C7A"   # secondary text

METRICS = ["Precision", "Recall", "F1", "ROC-AUC"]

# ── Matplotlib global style ────────────────────────────────────────────────────

def _set_style() -> None:
    plt.rcParams.update({
        "figure.facecolor":    BG,
        "axes.facecolor":      SURFACE,
        "axes.edgecolor":      GRID,
        "axes.labelcolor":     TEXT,
        "axes.titlecolor":     TEXT,
        "axes.spines.top":     False,
        "axes.spines.right":   False,
        "axes.grid":           True,
        "grid.color":          GRID,
        "grid.linewidth":      0.6,
        "grid.linestyle":      "--",
        "xtick.color":         SUBTEXT,
        "ytick.color":         SUBTEXT,
        "text.color":          TEXT,
        "legend.facecolor":    BG,
        "legend.edgecolor":    GRID,
        "legend.labelcolor":   TEXT,
        "figure.titlesize":    16,
        "axes.titlesize":      12,
        "axes.labelsize":      10,
        "font.family":         "DejaVu Sans",
        "savefig.facecolor":   BG,
        "savefig.dpi":         150,
        "savefig.bbox":        "tight",
    })

# ── Data loading ───────────────────────────────────────────────────────────────

def _load_csv(path: str, downsample: bool, seed: int = 42) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    df = pd.read_csv(path)
    if "label" not in df.columns:
        sys.exit(f"[ERROR] CSV must contain a 'label' column: {path}")

    if downsample:
        counts         = df["label"].value_counts()
        minority_n     = counts.min()
        majority_label = counts.idxmax()
        df_majority    = df[df["label"] == majority_label].sample(n=minority_n, random_state=seed)
        df_minority    = df[df["label"] != majority_label]
        df = pd.concat([df_majority, df_minority]).sample(frac=1, random_state=seed).reset_index(drop=True)
        print(f"  Downsampled to {len(df):,} rows ({minority_n:,} per class).")
    else:
        print(f"  Loaded {len(df):,} rows (no downsampling).")

    X = df.drop(columns=["label"]).values.astype(np.float32)
    y = df["label"].values
    return X, y, df


def _split(X, y, test_size: float, seed: int = 42):
    if test_size < 1.0:
        _, X_e, _, y_e = train_test_split(X, y, test_size=test_size, random_state=seed, stratify=y)
        return X_e, y_e
    return X, y


# ── Model loading ──────────────────────────────────────────────────────────────

def _load_folder(folder: Path) -> list[tuple[str, object, Optional[object]]]:
    results = []
    if not folder.is_dir():
        sys.exit(f"[ERROR] Not a directory: {folder}")
    for p in sorted(folder.glob("*.joblib")):
        if p.stem.endswith("_scaler"):
            continue
        model  = joblib.load(p)
        scaler_path = p.with_name(p.stem + "_scaler.joblib")
        scaler = joblib.load(scaler_path) if scaler_path.exists() else None
        results.append((p.stem, model, scaler))
        print(f"  loaded: {p}" + (" (+ scaler)" if scaler else ""))
    return results


# ── Scoring ────────────────────────────────────────────────────────────────────

def _predict(name: str, model, scaler, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    X_in = scaler.transform(X) if scaler is not None else X
    if hasattr(model, "predict_proba"):
        y_pred  = model.predict(X_in)
        y_score = model.predict_proba(X_in)[:, 1]
    elif hasattr(model, "decision_function"):
        raw     = model.predict(X_in)
        y_pred  = (raw == -1).astype(int)
        y_score = -model.decision_function(X_in)
    else:
        sys.exit(f"[ERROR] '{name}' has neither predict_proba nor decision_function.")
    return y_pred, y_score


def _evaluate_all(
    models: list[tuple[str, object, Optional[object]]],
    X: np.ndarray,
    y: np.ndarray,
    folder_label: str,
) -> list[dict]:
    records = []
    for name, model, scaler in models:
        y_pred, y_score = _predict(name, model, scaler, X)
        records.append({
            "folder":    folder_label,
            "model":     name,
            "Precision": precision_score(y, y_pred, zero_division=0),
            "Recall":    recall_score(y, y_pred, zero_division=0),
            "F1":        f1_score(y, y_pred, zero_division=0),
            "ROC-AUC":   roc_auc_score(y, y_score),
            "AP":        average_precision_score(y, y_score),
            "y_pred":    y_pred,
            "y_score":   y_score,
            "y_true":    y,
            # store raw model/scaler/X for importance plots
            "_model":    model,
            "_scaler":   scaler,
            "_X":        X,
        })
        print(f"  {folder_label} / {name:30s}  "
              f"F1={records[-1]['F1']:.3f}  AUC={records[-1]['ROC-AUC']:.3f}")
    return records


# ── Plot helpers ───────────────────────────────────────────────────────────────

def _folder_color(folder: str, label_a: str, label_b: str) -> str:
    return PALETTE_A if folder == label_a else PALETTE_B


def _save(fig: plt.Figure, out_dir: Path, name: str) -> None:
    p = out_dir / f"{name}.png"
    fig.savefig(p)
    plt.close(fig)
    print(f"  saved → {p}")


def _feature_names(X: np.ndarray, df: Optional[pd.DataFrame] = None) -> list[str]:
    """Return feature names from DataFrame columns or generic F0…Fn."""
    if df is not None and "label" in df.columns:
        cols = [c for c in df.columns if c != "label"]
        if len(cols) == X.shape[1]:
            return cols
    return [f"F{i}" for i in range(X.shape[1])]


def _get_importances(name: str, model, scaler, X: np.ndarray) -> Optional[np.ndarray]:
    """
    Return a 1-D importance array (length = n_features) or None if unavailable.
    Priority: feature_importances_ → |coef_| → None
    """
    if hasattr(model, "feature_importances_"):
        return np.array(model.feature_importances_)
    if hasattr(model, "coef_"):
        coef = np.array(model.coef_)
        if coef.ndim == 2:
            coef = coef[0]
        return np.abs(coef)
    return None


# ── Original plots (1–12) ──────────────────────────────────────────────────────

def plot_bar_metrics(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """Grouped bar chart: each metric per model, coloured by folder."""
    df = pd.DataFrame([{k: v for k, v in r.items() if k not in ("y_pred","y_score","y_true","_model","_scaler","_X")}
                       for r in records])
    models   = df["model"].unique().tolist()
    n_models = len(models)
    n_metrics = len(METRICS)

    fig, axes = plt.subplots(1, n_metrics, figsize=(4 * n_metrics, max(4, n_models * 0.6 + 2)))
    fig.suptitle("Per-Model Metrics by Folder", fontweight="bold", y=1.01)

    for ax, metric in zip(axes, METRICS):
        for i, folder in enumerate([label_a, label_b]):
            sub = df[df["folder"] == folder].set_index("model").reindex(models)
            vals = sub[metric].fillna(0).values
            ys   = np.arange(n_models) + i * 0.35 - 0.175
            color = PALETTE_A if folder == label_a else PALETTE_B
            bars = ax.barh(ys, vals, height=0.3, color=color, alpha=0.85, label=folder)
            for bar, v in zip(bars, vals):
                ax.text(min(v + 0.01, 0.97), bar.get_y() + bar.get_height() / 2,
                        f"{v:.3f}", va="center", ha="left", fontsize=7, color=TEXT)

        ax.set_yticks(np.arange(n_models))
        ax.set_yticklabels(models, fontsize=8)
        ax.set_xlim(0, 1.05)
        ax.set_title(metric, fontweight="bold")
        ax.set_xlabel("Score")
        if ax is axes[0]:
            ax.legend(loc="lower right", fontsize=8)

    fig.tight_layout()
    _save(fig, out, "01_bar_metrics")


def plot_roc_curves(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """ROC curves for every model, coloured by folder."""
    fig, ax = plt.subplots(figsize=(8, 6))
    fig.suptitle("ROC Curves — All Models", fontweight="bold")

    for r in records:
        color   = _folder_color(r["folder"], label_a, label_b)
        fpr, tpr, _ = roc_curve(r["y_true"], r["y_score"])
        lw = 1.8 if r["folder"] == label_a else 1.2
        ax.plot(fpr, tpr, color=color, lw=lw, alpha=0.75,
                label=f"{r['folder']} / {r['model']} (AUC={r['ROC-AUC']:.3f})")

    ax.plot([0,1],[0,1], "--", color=SUBTEXT, lw=1, label="Random")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.05)
    ax.legend(fontsize=7, loc="lower right")
    fig.tight_layout()
    _save(fig, out, "02_roc_curves")


def plot_pr_curves(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """Precision-Recall curves."""
    fig, ax = plt.subplots(figsize=(8, 6))
    fig.suptitle("Precision–Recall Curves — All Models", fontweight="bold")

    for r in records:
        color = _folder_color(r["folder"], label_a, label_b)
        prec, rec, _ = precision_recall_curve(r["y_true"], r["y_score"])
        ap = r["AP"]
        lw = 1.8 if r["folder"] == label_a else 1.2
        ax.plot(rec, prec, color=color, lw=lw, alpha=0.75,
                label=f"{r['folder']} / {r['model']} (AP={ap:.3f})")

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.05)
    ax.legend(fontsize=7, loc="upper right")
    fig.tight_layout()
    _save(fig, out, "03_pr_curves")


def plot_confusion_matrices(records: list[dict], out: Path) -> None:
    """Grid of normalised confusion matrices."""
    n   = len(records)
    ncols = min(4, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 3.2, nrows * 3.0))
    fig.suptitle("Normalised Confusion Matrices", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    for ax, r in zip(axes, records):
        cm = confusion_matrix(r["y_true"], r["y_pred"], normalize="true")
        sns.heatmap(cm, annot=True, fmt=".2f", ax=ax, cmap="Blues",
                    linewidths=0.5, linecolor=GRID,
                    xticklabels=["Normal","Malicious"],
                    yticklabels=["Normal","Malicious"],
                    cbar=False, annot_kws={"size": 9})
        ax.set_title(f"{r['folder']}\n{r['model']}", fontsize=8)
        ax.set_xlabel("Predicted", fontsize=7)
        ax.set_ylabel("Actual", fontsize=7)
        ax.tick_params(labelsize=7)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "04_confusion_matrices")


def plot_radar(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """Radar / spider chart — one polygon per model."""
    categories = METRICS
    n_cat      = len(categories)
    angles     = np.linspace(0, 2 * np.pi, n_cat, endpoint=False).tolist()
    angles    += angles[:1]

    n   = len(records)
    ncols = min(4, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols,
                             subplot_kw={"projection": "polar"},
                             figsize=(ncols * 3.5, nrows * 3.5))
    fig.suptitle("Radar Charts — Per-Model Metric Profile", fontweight="bold", y=1.02)
    axes = np.array(axes).flatten()

    for ax, r in zip(axes, records):
        vals  = [r[m] for m in categories] + [r[categories[0]]]
        color = _folder_color(r["folder"], label_a, label_b)
        ax.plot(angles, vals, color=color, lw=2)
        ax.fill(angles, vals, color=color, alpha=0.25)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, fontsize=8, color=TEXT)
        ax.set_ylim(0, 1)
        ax.set_yticks([0.25, 0.5, 0.75, 1.0])
        ax.set_yticklabels(["", ".5", ".75", "1"], fontsize=6, color=SUBTEXT)
        ax.grid(color=GRID, linewidth=0.5)
        ax.set_facecolor(SURFACE)
        ax.set_title(f"{r['folder']}\n{r['model']}", fontsize=7, pad=12)
        for label in ax.get_xticklabels():
            label.set_backgroundcolor(SURFACE)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "05_radar_charts")


def plot_score_distributions(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """KDE of decision scores split by true class, one subplot per model."""
    n     = len(records)
    ncols = min(3, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 4, nrows * 3))
    fig.suptitle("Decision Score Distributions (by True Label)", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    for ax, r in zip(axes, records):
        scores = r["y_score"]
        y      = r["y_true"]
        alpha  = 0.65
        for cls, lbl, col in [(0, "Normal", GOOD), (1, "Malicious", WARN)]:
            mask = y == cls
            if mask.sum() > 1:
                sns.kdeplot(scores[mask], ax=ax, fill=True, color=col,
                            alpha=alpha, label=lbl, linewidth=1.5, bw_adjust=0.8)
        ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
        ax.set_xlabel("Score", fontsize=7)
        ax.set_ylabel("Density", fontsize=7)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=7)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "06_score_distributions")


def plot_calibration(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """Reliability diagram — classifiers only (have predict_proba)."""
    classifier_records = [r for r in records
                          if (r["y_score"].min() >= 0) and (r["y_score"].max() <= 1)]
    if not classifier_records:
        print("  [skip] calibration plot — no classifiers with probability output.")
        return

    n     = len(classifier_records)
    ncols = min(3, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 4, nrows * 3.5))
    fig.suptitle("Calibration (Reliability) Curves — Classifiers Only", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    for ax, r in zip(axes, classifier_records):
        color = _folder_color(r["folder"], label_a, label_b)
        try:
            frac_pos, mean_pred = calibration_curve(r["y_true"], r["y_score"], n_bins=10)
            ax.plot(mean_pred, frac_pos, "s-", color=color, lw=1.8, markersize=5, label="Model")
        except Exception:
            ax.text(0.5, 0.5, "insufficient\ndata", ha="center", va="center",
                    color=SUBTEXT, transform=ax.transAxes)
        ax.plot([0,1],[0,1], "--", color=SUBTEXT, lw=1, label="Perfect")
        ax.set_xlim(-0.02, 1.02)
        ax.set_ylim(-0.02, 1.10)
        ax.set_xlabel("Mean Predicted Probability", fontsize=7)
        ax.set_ylabel("Fraction of Positives", fontsize=7)
        ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
        ax.legend(fontsize=7)
        ax.tick_params(labelsize=7)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "07_calibration_curves")


def plot_metric_deltas(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """
    Δ(B − A) for every metric, for models that appear in BOTH folders.
    Positive = B is better, negative = A is better.
    """
    df = pd.DataFrame([{k: v for k, v in r.items() if k not in ("y_pred","y_score","y_true","_model","_scaler","_X")}
                       for r in records])
    a_df = df[df["folder"] == label_a].set_index("model")
    b_df = df[df["folder"] == label_b].set_index("model")
    shared = a_df.index.intersection(b_df.index).tolist()

    if not shared:
        print("  [skip] delta plot — no model names shared between the two folders.")
        return

    n       = len(shared)
    n_m     = len(METRICS)
    fig, axes = plt.subplots(1, n_m, figsize=(n_m * 3.5, max(4, n * 0.6 + 2)))
    fig.suptitle(f"Δ Metrics  ({label_b} − {label_a})  for Matched Models",
                 fontweight="bold", y=1.01)

    for ax, metric in zip(axes, METRICS):
        deltas = b_df.loc[shared, metric].values - a_df.loc[shared, metric].values
        colors = [PALETTE_B if d >= 0 else PALETTE_A for d in deltas]
        bars   = ax.barh(np.arange(n), deltas, color=colors, alpha=0.85, height=0.5)
        for bar, d in zip(bars, deltas):
            x = d + (0.005 if d >= 0 else -0.005)
            ax.text(x, bar.get_y() + bar.get_height() / 2,
                    f"{d:+.3f}", va="center",
                    ha="left" if d >= 0 else "right", fontsize=7, color=TEXT)
        ax.axvline(0, color=SUBTEXT, lw=1)
        ax.set_yticks(np.arange(n))
        ax.set_yticklabels(shared, fontsize=8)
        ax.set_title(metric, fontweight="bold")
        ax.set_xlabel(f"Δ {metric}")
    fig.tight_layout()
    _save(fig, out, "08_metric_deltas")


def plot_heatmap(records: list[dict], out: Path) -> None:
    """Heatmap of metrics × (folder/model), annotated with values."""
    rows = []
    for r in records:
        rows.append({
            "Model": f"{r['folder']}\n{r['model']}",
            **{m: r[m] for m in METRICS},
        })
    df  = pd.DataFrame(rows).set_index("Model")
    fig, ax = plt.subplots(figsize=(len(METRICS) * 1.8, max(4, len(rows) * 0.7 + 1.5)))
    fig.suptitle("Metric Heatmap — All Models", fontweight="bold")

    sns.heatmap(df, annot=True, fmt=".3f", ax=ax,
                cmap=sns.color_palette("YlGnBu", as_cmap=True),
                linewidths=0.5, linecolor=GRID,
                cbar_kws={"shrink": 0.6},
                vmin=0, vmax=1, annot_kws={"size": 9})
    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.tick_params(axis="y", labelsize=8)
    ax.tick_params(axis="x", labelsize=9)
    fig.tight_layout()
    _save(fig, out, "09_heatmap_metrics")


def plot_scatter_f1_auc(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """Scatter F1 vs ROC-AUC, each model labelled, coloured by folder."""
    fig, ax = plt.subplots(figsize=(8, 6))
    fig.suptitle("F1 vs ROC-AUC — Model Landscape", fontweight="bold")

    for folder, color, marker in [(label_a, PALETTE_A, "o"), (label_b, PALETTE_B, "s")]:
        sub = [r for r in records if r["folder"] == folder]
        xs  = [r["ROC-AUC"] for r in sub]
        ys  = [r["F1"]       for r in sub]
        ax.scatter(xs, ys, color=color, marker=marker, s=120, zorder=3,
                   alpha=0.85, label=folder, edgecolors=BG, linewidths=0.8)
        for r, x, y in zip(sub, xs, ys):
            ax.annotate(r["model"], (x, y),
                        textcoords="offset points", xytext=(6, 4),
                        fontsize=7, color=SUBTEXT)

    ax.set_xlabel("ROC-AUC")
    ax.set_ylabel("F1 Score")
    ax.set_xlim(0, 1.05)
    ax.set_ylim(0, 1.05)
    ax.axhline(0.5, color=GRID, lw=0.8, ls="--")
    ax.axvline(0.5, color=GRID, lw=0.8, ls="--")
    ax.legend(fontsize=9)
    fig.tight_layout()
    _save(fig, out, "10_scatter_f1_vs_auc")


def plot_violin_scores(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """Violin plots of decision scores, split by folder and true class."""
    rows = []
    for r in records:
        for score, label in zip(r["y_score"], r["y_true"]):
            rows.append({
                "score":  float(score),
                "class":  "Malicious" if label == 1 else "Normal",
                "folder": r["folder"],
                "model":  r["model"],
            })
    df   = pd.DataFrame(rows)
    n    = df["model"].nunique()
    ncols = min(3, n)
    nrows = int(np.ceil(n / ncols))

    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 4, nrows * 3.5))
    fig.suptitle("Decision Score Violins — by Folder & True Class", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    model_list = df["model"].unique().tolist()
    for ax, model in zip(axes, model_list):
        sub = df[df["model"] == model]
        pal = {label_a: PALETTE_A, label_b: PALETTE_B}
        try:
            sns.violinplot(data=sub, x="class", y="score", hue="folder",
                           palette=pal, ax=ax, split=False,
                           inner="quartile", linewidth=0.8, alpha=0.75)
        except Exception:
            sns.boxplot(data=sub, x="class", y="score", hue="folder",
                        palette=pal, ax=ax)
        ax.set_title(model, fontsize=8)
        ax.set_xlabel("")
        ax.set_ylabel("Score", fontsize=7)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=7, title="Folder", title_fontsize=7)

    for ax in axes[len(model_list):]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "11_violin_scores")


def plot_rank_parallel(records: list[dict], label_a: str, label_b: str, out: Path) -> None:
    """
    Parallel-coordinates rank plot.
    Each model is a line; y-axis = rank (1 = best) per metric.
    Separate sub-panels per folder keep it readable.
    """
    df = pd.DataFrame([{k: v for k, v in r.items() if k not in ("y_pred","y_score","y_true","_model","_scaler","_X")}
                       for r in records])

    fig, axes = plt.subplots(1, 2, figsize=(14, max(5, len(df) * 0.5 + 2)))
    fig.suptitle("Model Ranking per Metric (1 = best)", fontweight="bold")

    for ax, (folder, color) in zip(axes, [(label_a, PALETTE_A), (label_b, PALETTE_B)]):
        sub = df[df["folder"] == folder].copy()
        if sub.empty:
            ax.set_visible(False)
            continue
        ranked = sub[METRICS].rank(ascending=False, method="min").astype(int)
        ranked["model"] = sub["model"].values
        n_models = len(ranked)

        xs = np.arange(len(METRICS))
        cmap = plt.cm.get_cmap("Set2", n_models)
        for i, (_, row) in enumerate(ranked.iterrows()):
            ys = [row[m] for m in METRICS]
            c  = cmap(i)
            ax.plot(xs, ys, "o-", color=c, lw=1.8, markersize=6,
                    label=row["model"], alpha=0.85)
            ax.annotate(row["model"], (xs[-1], ys[-1]),
                        textcoords="offset points", xytext=(6, 0),
                        fontsize=7, color=c, va="center")

        ax.set_xticks(xs)
        ax.set_xticklabels(METRICS, fontsize=9)
        ax.invert_yaxis()
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.set_ylabel("Rank")
        ax.set_title(folder, fontweight="bold", color=color)
        ax.legend(fontsize=7, loc="upper left")

    fig.tight_layout()
    _save(fig, out, "12_rank_parallel")


# ── Feature Importance plots (13–17) ──────────────────────────────────────────

def plot_feature_importance(
    records: list[dict],
    feat_names: list[str],
    label_a: str,
    label_b: str,
    out: Path,
    top_n: int = 20,
) -> None:
    """
    Bar chart of built-in feature importances (tree-based) or |coef_| (linear).
    One subplot per model; models without either attribute are skipped.
    """
    eligible = []
    for r in records:
        imp = _get_importances(r["model"], r["_model"], r["_scaler"], r["_X"])
        if imp is not None:
            eligible.append((r, imp))

    if not eligible:
        print("  [skip] feature_importance — no models with feature_importances_ or coef_.")
        return

    n     = len(eligible)
    ncols = min(3, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 5, nrows * max(4, top_n * 0.28 + 1.5)))
    fig.suptitle(f"Feature Importance — Top {top_n} Features", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    for ax, (r, imp) in zip(axes, eligible):
        n_feats = min(top_n, len(imp))
        idx     = np.argsort(imp)[-n_feats:]
        vals    = imp[idx]
        names   = [feat_names[i] if i < len(feat_names) else f"F{i}" for i in idx]
        color   = _folder_color(r["folder"], label_a, label_b)
        bars    = ax.barh(np.arange(n_feats), vals, color=color, alpha=0.85, height=0.7)
        ax.set_yticks(np.arange(n_feats))
        ax.set_yticklabels(names, fontsize=7)
        ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
        ax.set_xlabel("Importance", fontsize=7)
        ax.tick_params(labelsize=7)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "13_feature_importance")


def plot_feature_importance_heatmap(
    records: list[dict],
    feat_names: list[str],
    out: Path,
    top_n: int = 25,
) -> None:
    """
    Heatmap of normalised importance scores: features (rows) × models (cols).
    Only models that expose importances are included.
    """
    imp_dict: dict[str, np.ndarray] = {}
    for r in records:
        imp = _get_importances(r["model"], r["_model"], r["_scaler"], r["_X"])
        if imp is not None:
            key = f"{r['folder']}\n{r['model']}"
            # Normalise to [0, 1]
            denom = imp.max() if imp.max() > 0 else 1.0
            imp_dict[key] = imp / denom

    if not imp_dict:
        print("  [skip] feature_importance_heatmap — no eligible models.")
        return

    # Select top_n features by mean importance across models
    all_imps = np.stack(list(imp_dict.values()), axis=1)  # (n_features, n_models)
    mean_imp = all_imps.mean(axis=1)
    top_idx  = np.argsort(mean_imp)[-top_n:][::-1]
    top_names = [feat_names[i] if i < len(feat_names) else f"F{i}" for i in top_idx]

    df = pd.DataFrame(
        {col: vals[top_idx] for col, vals in imp_dict.items()},
        index=top_names,
    )

    fig, ax = plt.subplots(figsize=(max(5, len(imp_dict) * 1.6), max(6, top_n * 0.4 + 2)))
    fig.suptitle(f"Feature Importance Heatmap — Top {top_n} Features (Normalised)", fontweight="bold")
    sns.heatmap(
        df, annot=(top_n <= 20), fmt=".2f", ax=ax,
        cmap="rocket_r",
        linewidths=0.3, linecolor=GRID,
        cbar_kws={"shrink": 0.6, "label": "Normalised Importance"},
        annot_kws={"size": 7},
    )
    ax.set_xlabel("Model", fontsize=9)
    ax.set_ylabel("Feature", fontsize=9)
    ax.tick_params(axis="y", labelsize=7)
    ax.tick_params(axis="x", labelsize=7, rotation=30)
    fig.tight_layout()
    _save(fig, out, "14_feature_importance_heatmap")


def plot_permutation_importance(
    records: list[dict],
    feat_names: list[str],
    label_a: str,
    label_b: str,
    out: Path,
    top_n: int = 20,
    n_repeats: int = 10,
    seed: int = 42,
) -> None:
    """
    Model-agnostic permutation importance with error bars (std across repeats).
    Subsample to ≤2000 rows for speed.
    """
    n     = len(records)
    ncols = min(3, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 5, nrows * max(4, top_n * 0.28 + 1.5)))
    fig.suptitle(f"Permutation Feature Importance — Top {top_n}", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    for ax, r in zip(axes, records):
        model  = r["_model"]
        scaler = r["_scaler"]
        X_raw  = r["_X"]
        y      = r["y_true"]

        X_in = scaler.transform(X_raw) if scaler is not None else X_raw

        # Subsample for speed
        max_rows = 2000
        if len(y) > max_rows:
            rng = np.random.default_rng(seed)
            idx = rng.choice(len(y), max_rows, replace=False)
            X_in, y_sub = X_in[idx], y[idx]
        else:
            y_sub = y

        try:
            result = permutation_importance(
                model, X_in, y_sub,
                n_repeats=n_repeats,
                random_state=seed,
                scoring="roc_auc",
            )
            imp_mean = result.importances_mean
            imp_std  = result.importances_std
        except Exception as exc:
            ax.text(0.5, 0.5, f"Error:\n{exc}", ha="center", va="center",
                    color=SUBTEXT, transform=ax.transAxes, fontsize=7, wrap=True)
            ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
            continue

        n_feats = min(top_n, len(imp_mean))
        idx_top = np.argsort(imp_mean)[-n_feats:]
        vals    = imp_mean[idx_top]
        errs    = imp_std[idx_top]
        names   = [feat_names[i] if i < len(feat_names) else f"F{i}" for i in idx_top]
        color   = _folder_color(r["folder"], label_a, label_b)

        ax.barh(np.arange(n_feats), vals, xerr=errs,
                color=color, alpha=0.80, height=0.7,
                error_kw={"ecolor": SUBTEXT, "capsize": 3, "elinewidth": 1})
        ax.set_yticks(np.arange(n_feats))
        ax.set_yticklabels(names, fontsize=7)
        ax.axvline(0, color=SUBTEXT, lw=0.8, ls="--")
        ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
        ax.set_xlabel("Mean decrease in ROC-AUC", fontsize=7)
        ax.tick_params(labelsize=7)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "15_permutation_importance")


def plot_top_features_pairplot(
    records: list[dict],
    df_full: pd.DataFrame,
    feat_names: list[str],
    out: Path,
    top_n: int = 4,
) -> None:
    """
    Pairplot of the top-N features (by mean built-in importance across all eligible
    models), coloured by true class.  Uses the first record's X / y as reference.
    """
    imp_arrays = []
    for r in records:
        imp = _get_importances(r["model"], r["_model"], r["_scaler"], r["_X"])
        if imp is not None:
            imp_arrays.append(imp / (imp.max() or 1))

    if not imp_arrays:
        # Fall back to first top_n features
        top_idx = list(range(min(top_n, len(feat_names))))
    else:
        mean_imp = np.stack(imp_arrays).mean(axis=0)
        top_idx  = np.argsort(mean_imp)[-top_n:][::-1].tolist()

    r0 = records[0]
    X  = r0["_X"]
    y  = r0["y_true"]

    top_feat_names = [feat_names[i] if i < len(feat_names) else f"F{i}" for i in top_idx]
    plot_df = pd.DataFrame(X[:, top_idx], columns=top_feat_names)
    plot_df["Class"] = ["Malicious" if v == 1 else "Normal" for v in y]

    pal = {"Normal": GOOD, "Malicious": WARN}
    try:
        g = sns.pairplot(
            plot_df,
            hue="Class",
            palette=pal,
            diag_kind="kde",
            plot_kws={"alpha": 0.35, "s": 12, "edgecolor": "none"},
            diag_kws={"fill": True, "alpha": 0.5},
        )
        g.figure.suptitle(f"Pairplot — Top {top_n} Features by Mean Importance",
                          fontweight="bold", y=1.02)
        g.figure.set_facecolor(BG)
        for ax in g.axes.flatten():
            if ax:
                ax.set_facecolor(SURFACE)
                ax.tick_params(labelsize=6)
        _save(g.figure, out, "16_top_features_pairplot")
    except Exception as exc:
        print(f"  [skip] pairplot — {exc}")
        plt.close("all")


def plot_shap_summary(
    records: list[dict],
    feat_names: list[str],
    label_a: str,
    label_b: str,
    out: Path,
    max_display: int = 20,
) -> None:
    """
    SHAP summary (beeswarm) for tree-based models.
    Gracefully skipped if shap is not installed or model is unsupported.
    """
    try:
        import shap
    except ImportError:
        print("  [skip] SHAP plots — install 'shap' to enable (pip install shap).")
        return

    eligible = []
    for r in records:
        m = r["_model"]
        if hasattr(m, "feature_importances_"):
            eligible.append(r)

    if not eligible:
        print("  [skip] SHAP — no tree-based models found.")
        return

    n     = len(eligible)
    ncols = min(2, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols,
                             figsize=(ncols * 6, nrows * max(4, max_display * 0.3 + 1.5)))
    fig.suptitle(f"SHAP Summary — Top {max_display} Features", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    for ax, r in zip(axes, eligible):
        model  = r["_model"]
        scaler = r["_scaler"]
        X_raw  = r["_X"]
        X_in   = scaler.transform(X_raw) if scaler is not None else X_raw

        # Subsample for speed
        max_rows = 500
        if X_in.shape[0] > max_rows:
            rng = np.random.default_rng(42)
            idx = rng.choice(X_in.shape[0], max_rows, replace=False)
            X_in = X_in[idx]

        try:
            explainer   = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_in)
            # For binary classifiers shap_values may be a list [class0, class1]
            if isinstance(shap_values, list) and len(shap_values) == 2:
                sv = shap_values[1]
            else:
                sv = shap_values

            # Use matplotlib summary_plot into existing axes
            plt.sca(ax)
            shap.summary_plot(
                sv,
                X_in,
                feature_names=feat_names[:X_in.shape[1]],
                max_display=max_display,
                show=False,
                plot_size=None,
                color_bar=True,
            )
            ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
            ax.tick_params(labelsize=7)
        except Exception as exc:
            ax.text(0.5, 0.5, f"SHAP error:\n{exc}", ha="center", va="center",
                    color=SUBTEXT, transform=ax.transAxes, fontsize=7, wrap=True)
            ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "17_shap_summary")


# ── Additional diagnostic plots (18–21) ───────────────────────────────────────

def plot_threshold_sweep(
    records: list[dict],
    label_a: str,
    label_b: str,
    out: Path,
) -> None:
    """
    F1, Precision, and Recall as a function of decision threshold [0, 1].
    One subplot per model.  Models with scores outside [0,1] have their
    scores min-max normalised for the purpose of this plot.
    """
    n     = len(records)
    ncols = min(3, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 4.5, nrows * 3.2))
    fig.suptitle("Threshold Sweep — Precision / Recall / F1 vs Threshold",
                 fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    thresholds = np.linspace(0, 1, 200)

    for ax, r in zip(axes, records):
        scores = r["y_score"].copy()
        y      = r["y_true"]
        # Normalise to [0,1] if needed
        s_min, s_max = scores.min(), scores.max()
        if s_min < 0 or s_max > 1:
            scores = (scores - s_min) / (s_max - s_min + 1e-12)

        precs, recs, f1s = [], [], []
        for t in thresholds:
            y_pred = (scores >= t).astype(int)
            precs.append(precision_score(y, y_pred, zero_division=0))
            recs.append(recall_score(y, y_pred, zero_division=0))
            f1s.append(f1_score(y, y_pred, zero_division=0))

        ax.plot(thresholds, precs, color=GOOD,      lw=1.8, label="Precision")
        ax.plot(thresholds, recs,  color=WARN,      lw=1.8, label="Recall")
        ax.plot(thresholds, f1s,   color=PALETTE_A, lw=2.2, label="F1", ls="--")

        # Mark the threshold that maximises F1
        best_t = thresholds[np.argmax(f1s)]
        ax.axvline(best_t, color=SUBTEXT, lw=0.9, ls=":", alpha=0.8)
        ax.text(best_t + 0.01, 0.05, f"t*={best_t:.2f}", fontsize=6, color=SUBTEXT)

        ax.set_xlim(0, 1)
        ax.set_ylim(-0.02, 1.05)
        ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
        ax.set_xlabel("Threshold", fontsize=7)
        ax.set_ylabel("Score", fontsize=7)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=7)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "18_threshold_sweep")


def plot_lift_curve(
    records: list[dict],
    label_a: str,
    label_b: str,
    out: Path,
) -> None:
    """
    Cumulative lift and cumulative gain (Lorenz-style) curves.
    Both panels on one figure; models coloured by folder.
    """
    fig, (ax_lift, ax_gain) = plt.subplots(1, 2, figsize=(13, 6))
    fig.suptitle("Lift & Gain Curves — All Models", fontweight="bold")

    for r in records:
        color = _folder_color(r["folder"], label_a, label_b)
        y     = r["y_true"]
        score = r["y_score"]
        lw    = 1.8 if r["folder"] == label_a else 1.2

        sort_idx    = np.argsort(score)[::-1]
        y_sorted    = y[sort_idx]
        n_total     = len(y)
        n_pos       = y.sum()
        cumpos      = np.cumsum(y_sorted)
        frac_samp   = np.arange(1, n_total + 1) / n_total
        gain        = cumpos / n_pos
        lift        = gain / frac_samp

        label = f"{r['folder']} / {r['model']}"
        ax_gain.plot(frac_samp, gain,  color=color, lw=lw, alpha=0.75, label=label)
        ax_lift.plot(frac_samp, lift,  color=color, lw=lw, alpha=0.75, label=label)

    # Reference lines
    ax_gain.plot([0, 1], [0, 1], "--", color=SUBTEXT, lw=1, label="Random")
    ax_lift.axhline(1.0,  color=SUBTEXT, lw=1, ls="--", label="Random (lift=1)")

    ax_gain.set_xlabel("Fraction of Samples")
    ax_gain.set_ylabel("Fraction of Positives Captured")
    ax_gain.set_title("Cumulative Gain", fontweight="bold")
    ax_gain.set_xlim(0, 1.01)
    ax_gain.set_ylim(0, 1.05)
    ax_gain.legend(fontsize=7)

    ax_lift.set_xlabel("Fraction of Samples")
    ax_lift.set_ylabel("Lift")
    ax_lift.set_title("Cumulative Lift", fontweight="bold")
    ax_lift.set_xlim(0, 1.01)
    ax_lift.legend(fontsize=7)

    fig.tight_layout()
    _save(fig, out, "19_lift_curve")


def plot_learning_curve(
    records: list[dict],
    label_a: str,
    label_b: str,
    out: Path,
    cv: int = 5,
    seed: int = 42,
) -> None:
    """
    Training vs cross-validation score as training set size grows.
    Computed for each model using its folder-A data (or folder-B if A is empty).
    Subsampled to ≤3000 rows for tractability.
    """
    n     = len(records)
    ncols = min(3, n)
    nrows = int(np.ceil(n / ncols))
    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 4.5, nrows * 3.5))
    fig.suptitle("Learning Curves — Train vs CV Score", fontweight="bold", y=1.01)
    axes = np.array(axes).flatten()

    for ax, r in zip(axes, records):
        model  = r["_model"]
        scaler = r["_scaler"]
        X_raw  = r["_X"]
        y      = r["y_true"]
        X_in   = scaler.transform(X_raw) if scaler is not None else X_raw

        # Subsample
        max_rows = 3000
        if len(y) > max_rows:
            rng = np.random.default_rng(seed)
            idx = rng.choice(len(y), max_rows, replace=False)
            X_in, y = X_in[idx], y[idx]

        color = _folder_color(r["folder"], label_a, label_b)

        try:
            train_sizes, train_scores, val_scores = learning_curve(
                model, X_in, y,
                cv=cv,
                scoring="roc_auc",
                train_sizes=np.linspace(0.1, 1.0, 8),
                random_state=seed,
                n_jobs=-1,
            )
            tr_mean = train_scores.mean(axis=1)
            tr_std  = train_scores.std(axis=1)
            va_mean = val_scores.mean(axis=1)
            va_std  = val_scores.std(axis=1)

            ax.plot(train_sizes, tr_mean, "o-", color=color, lw=2, label="Train")
            ax.fill_between(train_sizes, tr_mean - tr_std, tr_mean + tr_std,
                            color=color, alpha=0.15)
            ax.plot(train_sizes, va_mean, "s--", color=WARN, lw=2, label="CV val")
            ax.fill_between(train_sizes, va_mean - va_std, va_mean + va_std,
                            color=WARN, alpha=0.15)
        except Exception as exc:
            ax.text(0.5, 0.5, f"Error:\n{exc}", ha="center", va="center",
                    color=SUBTEXT, transform=ax.transAxes, fontsize=7, wrap=True)

        ax.set_ylim(0, 1.05)
        ax.set_xlabel("Training examples", fontsize=7)
        ax.set_ylabel("ROC-AUC", fontsize=7)
        ax.set_title(f"{r['folder']} / {r['model']}", fontsize=8)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=7)

    for ax in axes[n:]:
        ax.set_visible(False)

    fig.tight_layout()
    _save(fig, out, "20_learning_curve")


def plot_error_analysis(
    records: list[dict],
    label_a: str,
    label_b: str,
    out: Path,
) -> None:
    """
    Stacked bar chart showing per-model breakdown of:
      True Positives / True Negatives / False Positives / False Negatives
    as a fraction of total samples, coloured by error type.
    """
    TP_C = "#2EC4B6"  # teal
    TN_C = "#3A86FF"  # blue
    FP_C = "#FFBF00"  # amber
    FN_C = "#FF6B6B"  # coral

    rows = []
    for r in records:
        y, yp = r["y_true"], r["y_pred"]
        n  = len(y)
        tp = ((y == 1) & (yp == 1)).sum() / n
        tn = ((y == 0) & (yp == 0)).sum() / n
        fp = ((y == 0) & (yp == 1)).sum() / n
        fn = ((y == 1) & (yp == 0)).sum() / n
        rows.append({"label": f"{r['folder']}\n{r['model']}",
                     "TP": tp, "TN": tn, "FP": fp, "FN": fn})

    df  = pd.DataFrame(rows)
    n   = len(df)
    fig, ax = plt.subplots(figsize=(max(8, n * 1.0 + 2), 5))
    fig.suptitle("Error Analysis — Prediction Breakdown per Model", fontweight="bold")

    x       = np.arange(n)
    bottoms = np.zeros(n)
    for col, color, label in [
        ("TP", TP_C, "True Positive"),
        ("TN", TN_C, "True Negative"),
        ("FP", FP_C, "False Positive"),
        ("FN", FN_C, "False Negative"),
    ]:
        vals = df[col].values
        bars = ax.bar(x, vals, bottom=bottoms, color=color, alpha=0.85, label=label, width=0.6)
        for bar, v, b in zip(bars, vals, bottoms):
            if v > 0.04:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        b + v / 2,
                        f"{v:.2f}",
                        ha="center", va="center", fontsize=7, color="#FFFFFF", fontweight="bold")
        bottoms += vals

    ax.set_xticks(x)
    ax.set_xticklabels(df["label"], fontsize=7)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Fraction of Total Samples", fontsize=9)
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    _save(fig, out, "21_error_analysis")


# ── Summary CSV ────────────────────────────────────────────────────────────────

def save_summary_csv(records: list[dict], out: Path) -> None:
    rows = [{k: v for k, v in r.items()
             if k not in ("y_pred","y_score","y_true","_model","_scaler","_X")}
            for r in records]
    df = pd.DataFrame(rows)
    p  = out / "summary_metrics.csv"
    df.to_csv(p, index=False, float_format="%.4f")
    print(f"  saved → {p}")


def print_text_summary(records: list[dict]) -> None:
    print("\n" + "=" * 70)
    print(f"{'FOLDER':<22} {'MODEL':<28} {'Prec':>6} {'Rec':>6} {'F1':>6} {'AUC':>6}")
    print("-" * 70)
    for r in sorted(records, key=lambda x: (-x["ROC-AUC"], x["folder"])):
        print(f"{r['folder']:<22} {r['model']:<28} "
              f"{r['Precision']:>6.3f} {r['Recall']:>6.3f} "
              f"{r['F1']:>6.3f} {r['ROC-AUC']:>6.3f}")
    print("=" * 70)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate & compare two folders of models with comprehensive visualisations.")
    parser.add_argument("csv", nargs="?",
        help="Shared features CSV (required unless --csv-a and --csv-b are used).")
    parser.add_argument("--csv-a", metavar="PATH",
        help="CSV for folder A (overrides positional csv for folder A).")
    parser.add_argument("--csv-b", metavar="PATH",
        help="CSV for folder B (overrides positional csv for folder B).")
    parser.add_argument("--folder-a", required=True, metavar="DIR",
        help="Directory of .joblib models — group A.")
    parser.add_argument("--folder-b", required=True, metavar="DIR",
        help="Directory of .joblib models — group B.")
    parser.add_argument("--label-a", default="Folder A", metavar="STR",
        help="Display name for folder A (default: 'Folder A').")
    parser.add_argument("--label-b", default="Folder B", metavar="STR",
        help="Display name for folder B (default: 'Folder B').")
    parser.add_argument("--no-downsample", action="store_true",
        help="Skip majority-class downsampling.")
    parser.add_argument("--test-size", type=float, default=1.0, metavar="FRAC",
        help="Fraction for held-out evaluation split. Default 1.0 = full dataset.")
    parser.add_argument("--output-dir", default="eval_output", metavar="DIR",
        help="Directory to save all plots and summary CSV (default: eval_output/).")
    parser.add_argument("--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42).")
    parser.add_argument("--top-features", type=int, default=20, metavar="N",
        help="Number of top features to show in importance plots (default: 20).")
    parser.add_argument("--pairplot-features", type=int, default=4, metavar="N",
        help="Number of top features for the pairplot (default: 4).")
    parser.add_argument("--perm-repeats", type=int, default=10, metavar="N",
        help="Repeats for permutation importance (default: 10).")
    parser.add_argument("--no-permutation", action="store_true",
        help="Skip permutation importance (can be slow on large models).")
    parser.add_argument("--no-learning-curve", action="store_true",
        help="Skip learning-curve plots (can be slow).")
    args = parser.parse_args()

    # Resolve CSVs
    csv_a = args.csv_a or args.csv
    csv_b = args.csv_b or args.csv
    if not csv_a or not csv_b:
        parser.error("Provide either a shared CSV (positional) or both --csv-a and --csv-b.")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    _set_style()

    # ── Load data ──────────────────────────────────────────────────────────────
    print(f"\n[1/4] Loading data …")
    print(f"  CSV A: {csv_a}")
    X_a, y_a, df_a = _load_csv(csv_a, not args.no_downsample, args.seed)
    X_a, y_a       = _split(X_a, y_a, args.test_size, args.seed)
    feat_names_a   = _feature_names(X_a, df_a)

    if csv_b != csv_a:
        print(f"  CSV B: {csv_b}")
        X_b, y_b, df_b = _load_csv(csv_b, not args.no_downsample, args.seed)
        X_b, y_b       = _split(X_b, y_b, args.test_size, args.seed)
        feat_names_b   = _feature_names(X_b, df_b)
    else:
        X_b, y_b       = X_a, y_a
        df_b           = df_a
        feat_names_b   = feat_names_a

    # Use folder-A feature names for shared importance plots; fall back to generic
    feat_names = feat_names_a

    # ── Load models ────────────────────────────────────────────────────────────
    print(f"\n[2/4] Loading models …")
    models_a = _load_folder(Path(args.folder_a))
    models_b = _load_folder(Path(args.folder_b))

    if not models_a and not models_b:
        sys.exit("[ERROR] No models found in either folder.")

    # ── Evaluate ───────────────────────────────────────────────────────────────
    print(f"\n[3/4] Evaluating …")
    records = []
    if models_a:
        records += _evaluate_all(models_a, X_a, y_a, args.label_a)
    if models_b:
        records += _evaluate_all(models_b, X_b, y_b, args.label_b)

    print_text_summary(records)

    # ── Plots ──────────────────────────────────────────────────────────────────
    print(f"\n[4/4] Generating plots → {out_dir}/")

    # --- original 12 ---
    plot_bar_metrics(records, args.label_a, args.label_b, out_dir)
    plot_roc_curves(records, args.label_a, args.label_b, out_dir)
    plot_pr_curves(records, args.label_a, args.label_b, out_dir)
    plot_confusion_matrices(records, out_dir)
    plot_radar(records, args.label_a, args.label_b, out_dir)
    plot_score_distributions(records, args.label_a, args.label_b, out_dir)
    plot_calibration(records, args.label_a, args.label_b, out_dir)
    plot_metric_deltas(records, args.label_a, args.label_b, out_dir)
    plot_heatmap(records, out_dir)
    plot_scatter_f1_auc(records, args.label_a, args.label_b, out_dir)
    plot_violin_scores(records, args.label_a, args.label_b, out_dir)
    plot_rank_parallel(records, args.label_a, args.label_b, out_dir)

    # --- feature importance (13–17) ---
    plot_feature_importance(records, feat_names, args.label_a, args.label_b, out_dir,
                            top_n=args.top_features)
    plot_feature_importance_heatmap(records, feat_names, out_dir,
                                    top_n=args.top_features)
    if not args.no_permutation:
        plot_permutation_importance(records, feat_names, args.label_a, args.label_b, out_dir,
                                    top_n=args.top_features,
                                    n_repeats=args.perm_repeats,
                                    seed=args.seed)
    else:
        print("  [skip] permutation importance (--no-permutation).")

    plot_top_features_pairplot(records, df_a, feat_names, out_dir,
                               top_n=args.pairplot_features)
    plot_shap_summary(records, feat_names, args.label_a, args.label_b, out_dir,
                      max_display=args.top_features)

    # --- additional diagnostics (18–21) ---
    plot_threshold_sweep(records, args.label_a, args.label_b, out_dir)
    plot_lift_curve(records, args.label_a, args.label_b, out_dir)
    if not args.no_learning_curve:
        plot_learning_curve(records, args.label_a, args.label_b, out_dir,
                            seed=args.seed)
    else:
        print("  [skip] learning curves (--no-learning-curve).")
    plot_error_analysis(records, args.label_a, args.label_b, out_dir)

    save_summary_csv(records, out_dir)

    n_plots = 21 - (1 if args.no_permutation else 0) - (1 if args.no_learning_curve else 0)
    print(f"\n✓  Done.  {len(records)} models evaluated, "
          f"up to {n_plots} plots + 1 CSV written to {out_dir}/")


if __name__ == "__main__":
    main()