"""
visualize_models.py
===================
Re-train and visually compare all classifiers and outlier detectors from a
features CSV file (produced by pcap_to_csv.py), saving individual matplotlib
PNG plots to an output directory.

Usage
-----
    python visualize_models.py features.csv
    python visualize_models.py features.csv --algos rf lr svm --outliers iforest lof
    python visualize_models.py features.csv --test-size 0.3
    python visualize_models.py features.csv --out-dir my_plots/

Output
------
    PNGs written to --out-dir (default: model_plots/):
      confusion_<name>.png      – per-model confusion matrix
      roc_classifiers.png       – ROC curves for all classifiers
      pr_classifiers.png        – PR curves for all classifiers
      roc_detectors.png         – ROC curves for all detectors
      pr_detectors.png          – PR curves for all detectors
      metrics_classifiers.png   – bar chart of F1/Prec/Rec/AUC (classifiers)
      metrics_detectors.png     – bar chart of F1/Prec/Rec/AUC (detectors)
      metrics_all.png           – bar chart of all models together
      radar_all.png             – spider/radar overview
      feature_importance_<name>.png
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, average_precision_score,
    confusion_matrix, f1_score, precision_score, recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier, LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier
from sklearn.covariance import EllipticEnvelope

# ── palette ───────────────────────────────────────────────────────────────────
PALETTE = [
    "#E63946", "#F4A261", "#2A9D8F", "#457B9D",
    "#A8DADC", "#E9C46A", "#264653", "#F77F00",
]
BG      = "#0D1117"
SURFACE = "#161B22"
BORDER  = "#30363D"
TEXT    = "#E6EDF3"
MUTED   = "#8B949E"
ACCENT  = "#E63946"
GREEN   = "#3FB950"

_CM_COLORS = ["#1E3A2F", "#2A9D8F", "#E9C46A", "#E63946"]
CM_CMAP = LinearSegmentedColormap.from_list("cm_cmap", _CM_COLORS)

plt.rcParams.update({
    "figure.facecolor":  BG,
    "axes.facecolor":    SURFACE,
    "axes.edgecolor":    BORDER,
    "axes.labelcolor":   TEXT,
    "axes.titlecolor":   TEXT,
    "xtick.color":       MUTED,
    "ytick.color":       MUTED,
    "text.color":        TEXT,
    "grid.color":        BORDER,
    "grid.linestyle":    "--",
    "grid.alpha":        0.5,
    "font.family":       "monospace",
    "legend.facecolor":  SURFACE,
    "legend.edgecolor":  BORDER,
})

# ── model registries ──────────────────────────────────────────────────────────
CLASSIFIERS = {
    "rf":  RandomForestClassifier(n_estimators=60, max_depth=12,
                                   min_samples_leaf=10,
                                   class_weight="balanced",
                                   random_state=42, n_jobs=-1),
    "lr":  LogisticRegression(max_iter=1000, class_weight="balanced",
                               random_state=42),
    "svm": SVC(kernel="rbf", class_weight="balanced", random_state=42,
               probability=True),
    "dt":  DecisionTreeClassifier(class_weight="balanced", random_state=42),
    "knn": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
}
CLF_NEEDS_SCALE = {"lr", "svm", "knn"}
_DEFAULT_ALGOS = [k for k in CLASSIFIERS if k != "knn" and k != "svm"]

DETECTORS = {
    "iforest":  IsolationForest(contamination="auto", random_state=42, n_jobs=-1),
    "ocsvm":    OneClassSVM(kernel="rbf", nu=0.1),
    "lof":      LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1),
    "envelope": EllipticEnvelope(contamination=0.1, random_state=42),
}

# ── save helper ───────────────────────────────────────────────────────────────

def _save(fig: plt.Figure, out_dir: Path, name: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=130,
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  saved → {path}")


# ── plotting functions ────────────────────────────────────────────────────────

def plot_confusion_matrix(y_true, y_pred, title: str, color: str) -> plt.Figure:
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(4, 3.5))
    ax.imshow(cm, cmap=CM_CMAP, aspect="auto")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Malicious"], color=TEXT)
    ax.set_yticklabels(["Normal", "Malicious"], color=TEXT)
    ax.set_xlabel("Predicted", color=MUTED, fontsize=9)
    ax.set_ylabel("Actual",    color=MUTED, fontsize=9)
    ax.set_title(title, color=color, fontsize=11, pad=10)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i,j]:,}", ha="center", va="center",
                    color=TEXT, fontsize=14, fontweight="bold")
    fig.tight_layout()
    return fig


def plot_roc_curves(results: list[dict], title: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot([0, 1], [0, 1], "--", color=MUTED, linewidth=1)
    for i, r in enumerate(results):
        fpr, tpr, _ = roc_curve(r["y_test"], r["y_score"])
        ax.plot(fpr, tpr, color=PALETTE[i % len(PALETTE)], linewidth=2,
                label=f"{r['name'].upper()}  (AUC={r['auc']:.3f})")
    ax.set_xlabel("False Positive Rate", fontsize=9)
    ax.set_ylabel("True Positive Rate",  fontsize=9)
    ax.set_title(title, fontsize=12, color=TEXT)
    ax.legend(fontsize=8, loc="lower right")
    ax.grid(True)
    fig.tight_layout()
    return fig


def plot_pr_curves(results: list[dict], title: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(7, 5))
    for i, r in enumerate(results):
        prec, rec, _ = precision_recall_curve(r["y_test"], r["y_score"])
        ap = average_precision_score(r["y_test"], r["y_score"])
        ax.plot(rec, prec, color=PALETTE[i % len(PALETTE)], linewidth=2,
                label=f"{r['name'].upper()}  (AP={ap:.3f})")
    ax.set_xlabel("Recall",    fontsize=9)
    ax.set_ylabel("Precision", fontsize=9)
    ax.set_title(title, fontsize=12, color=TEXT)
    ax.legend(fontsize=8, loc="upper right")
    ax.grid(True)
    fig.tight_layout()
    return fig


def plot_metric_bars(results: list[dict], title: str) -> plt.Figure:
    metrics  = ["f1", "precision", "recall", "auc"]
    m_labels = ["F1", "Precision", "Recall", "ROC-AUC"]
    names    = [r["name"].upper() for r in results]
    x        = np.arange(len(names))
    width    = 0.18
    fig, ax  = plt.subplots(figsize=(max(8, len(names) * 1.4), 5))
    for mi, (m, ml) in enumerate(zip(metrics, m_labels)):
        vals = [r[m] for r in results]
        bars = ax.bar(x + mi * width, vals, width,
                      label=ml, color=PALETTE[mi], alpha=0.88, zorder=3)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.005, f"{v:.2f}",
                    ha="center", va="bottom", fontsize=7, color=TEXT)
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(names, fontsize=10)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score", fontsize=9)
    ax.set_title(title, fontsize=12, color=TEXT)
    ax.legend(fontsize=9)
    ax.grid(True, axis="y", zorder=0)
    fig.tight_layout()
    return fig


def plot_feature_importance(clf, feature_names: list[str],
                             title: str, color: str) -> plt.Figure:
    importances = clf.feature_importances_
    idx = np.argsort(importances)[::-1][:20]
    fig, ax = plt.subplots(figsize=(8, max(3, len(idx) * 0.35)))
    ax.barh([feature_names[i] for i in idx[::-1]],
            importances[idx[::-1]], color=color, alpha=0.85)
    ax.set_xlabel("Importance", fontsize=9)
    ax.set_title(title, fontsize=11, color=color)
    ax.grid(True, axis="x")
    fig.tight_layout()
    return fig


def plot_summary_radar(results: list[dict]) -> plt.Figure:
    metrics = ["f1", "precision", "recall", "auc"]
    labels  = ["F1", "Prec", "Rec", "AUC"]
    N       = len(labels)
    angles  = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig = plt.figure(figsize=(min(3 * len(results), 18), 3.5))
    for i, r in enumerate(results):
        ax = fig.add_subplot(1, len(results), i + 1, polar=True)
        vals = [r[m] for m in metrics] + [r[metrics[0]]]
        c = PALETTE[i % len(PALETTE)]
        ax.plot(angles, vals, color=c, linewidth=2)
        ax.fill(angles, vals, color=c, alpha=0.25)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, color=TEXT, fontsize=8)
        ax.set_yticklabels([])
        ax.set_ylim(0, 1)
        ax.set_facecolor(SURFACE)
        ax.spines["polar"].set_color(BORDER)
        ax.grid(color=BORDER)
        ax.set_title(r["name"].upper(), color=c, fontsize=10, pad=10)
    fig.tight_layout()
    return fig


def plot_summary_table(all_results: list[dict]) -> plt.Figure:
    """Render the ranking table as a matplotlib figure."""
    metrics = ["auc", "f1", "precision", "recall"]
    col_labels = ["Model", "Type", "ROC-AUC", "F1", "Precision", "Recall"]
    sorted_results = sorted(all_results, key=lambda x: x["auc"], reverse=True)
    best  = {m: max(r[m] for r in all_results) for m in metrics}
    worst = {m: min(r[m] for r in all_results) for m in metrics}

    rows = []
    cell_colors = []
    for r in sorted_results:
        row = [r["name"].upper(), r.get("kind", "clf")]
        row_colors = [SURFACE, SURFACE]
        for m in metrics:
            v = r[m]
            row.append(f"{v:.4f}")
            if v == best[m]:
                row_colors.append("#1A3A20")
            elif v == worst[m]:
                row_colors.append("#3A1A1A")
            else:
                row_colors.append(SURFACE)
        rows.append(row)
        cell_colors.append(row_colors)

    fig, ax = plt.subplots(figsize=(10, max(2, len(rows) * 0.5 + 1)))
    ax.axis("off")
    tbl = ax.table(
        cellText=rows,
        colLabels=col_labels,
        cellLoc="center",
        loc="center",
        cellColours=cell_colors,
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.scale(1, 1.5)
    for (row, col), cell in tbl.get_celld().items():
        cell.set_edgecolor(BORDER)
        if row == 0:
            cell.set_facecolor(BORDER)
            cell.set_text_props(color=MUTED, fontweight="bold")
        else:
            cell.set_text_props(color=TEXT)
    ax.set_title("Summary Ranking (sorted by ROC-AUC)",
                 fontsize=11, color=TEXT, pad=12)
    fig.tight_layout()
    return fig


# ── feature sanitisation ──────────────────────────────────────────────────────

def sanitise_features(X: np.ndarray, feature_names: list[str]) -> np.ndarray:
    X = X.copy()
    _F32_MAX = np.finfo(np.float32).max

    n_nan  = int(np.isnan(X).sum())
    n_pinf = int(np.isposinf(X).sum())
    n_ninf = int(np.isneginf(X).sum())

    if n_nan == 0 and n_pinf == 0 and n_ninf == 0:
        return X

    print(f"  WARNING: feature matrix contains {n_nan} NaN, "
          f"{n_pinf} +inf, {n_ninf} -inf values — sanitising …")

    for j, col in enumerate(feature_names):
        col_data = X[:, j]
        if not (~np.isfinite(col_data)).any():
            continue
        finite_vals = col_data[np.isfinite(col_data)]
        col_max = float(finite_vals.max()) if len(finite_vals) else 0.0
        col_min = float(finite_vals.min()) if len(finite_vals) else 0.0
        n_bad = int((~np.isfinite(col_data)).sum())
        print(f"    {col}: {n_bad} non-finite value(s) "
              f"(replacing +inf→{col_max:.4g}, -inf→{col_min:.4g}, NaN→0)")
        col_data = col_data.copy()
        col_data[np.isposinf(col_data)] = col_max
        col_data[np.isneginf(col_data)] = col_min
        col_data[np.isnan(col_data)]    = 0.0
        X[:, j] = col_data

    X = np.clip(X, -_F32_MAX, _F32_MAX)
    return X.astype(np.float32)


# ── training / evaluation ─────────────────────────────────────────────────────

def run_classifiers(X_train, X_test, y_train, y_test,
                    chosen: list[str], feature_names: list[str]) -> tuple:
    results   = []
    fi_clfs   = {}

    for name in chosen:
        clf = CLASSIFIERS[name]
        if name in CLF_NEEDS_SCALE:
            scaler = StandardScaler()
            Xtr = scaler.fit_transform(X_train)
            Xte = scaler.transform(X_test)
        else:
            Xtr, Xte = X_train, X_test

        clf.fit(Xtr, y_train)
        y_pred  = clf.predict(Xte)
        y_score = clf.predict_proba(Xte)[:, 1]

        results.append({
            "name":      name,
            "y_test":    y_test,
            "y_pred":    y_pred,
            "y_score":   y_score,
            "auc":       roc_auc_score(y_test, y_score),
            "f1":        f1_score(y_test, y_pred, zero_division=0),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall":    recall_score(y_test, y_pred, zero_division=0),
            "report":    classification_report(
                             y_test, y_pred,
                             target_names=["normal", "malicious"], digits=3),
        })

        if hasattr(clf, "feature_importances_"):
            fi_clfs[name] = (clf, PALETTE[len(results) - 1 % len(PALETTE)])

    return results, fi_clfs


def run_detectors(X_train, X_test, y_train, y_test,
                  chosen: list[str]) -> list[dict]:
    results = []
    X_train_normal = X_train[y_train == 0]
    scaler = StandardScaler()
    Xtrn = scaler.fit_transform(X_train_normal)
    Xte  = scaler.transform(X_test)

    for name in chosen:
        det = DETECTORS[name]
        det.fit(Xtrn)
        raw     = det.predict(Xte)
        y_pred  = (raw == -1).astype(int)
        y_score = -det.decision_function(Xte)

        results.append({
            "name":      name,
            "y_test":    y_test,
            "y_pred":    y_pred,
            "y_score":   y_score,
            "auc":       roc_auc_score(y_test, y_score),
            "f1":        f1_score(y_test, y_pred, zero_division=0),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall":    recall_score(y_test, y_pred, zero_division=0),
            "report":    classification_report(
                             y_test, y_pred,
                             target_names=["normal", "malicious"], digits=3),
        })

    return results


# ── save all plots ────────────────────────────────────────────────────────────

def save_all_plots(clf_results, det_results, fi_clfs,
                   feature_names, out_dir: Path) -> None:

    all_results = (
        [{**r, "kind": "classifier"} for r in clf_results] +
        [{**r, "kind": "detector"}   for r in det_results]
    )

    print("\n[Confusion matrices]")
    for i, r in enumerate(all_results):
        color = PALETTE[i % len(PALETTE)]
        fig   = plot_confusion_matrix(r["y_test"], r["y_pred"],
                                      r["name"].upper(), color)
        _save(fig, out_dir, f"confusion_{r['name']}")

    print("\n[Classification reports]")
    for r in all_results:
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / f"report_{r['name']}.txt"
        report_path.write_text(r["report"])
        print(f"  saved → {report_path}")

    if clf_results:
        print("\n[Classifier curves]")
        _save(plot_roc_curves(clf_results, "Classifiers – ROC Curves"),
              out_dir, "roc_classifiers")
        _save(plot_pr_curves(clf_results, "Classifiers – Precision-Recall Curves"),
              out_dir, "pr_classifiers")

    if det_results:
        print("\n[Detector curves]")
        _save(plot_roc_curves(det_results, "Detectors – ROC Curves"),
              out_dir, "roc_detectors")
        _save(plot_pr_curves(det_results, "Detectors – Precision-Recall Curves"),
              out_dir, "pr_detectors")

    print("\n[Metric bar charts]")
    if clf_results:
        _save(plot_metric_bars(clf_results, "Classifiers – Metric Comparison"),
              out_dir, "metrics_classifiers")
    if det_results:
        _save(plot_metric_bars(det_results, "Detectors – Metric Comparison"),
              out_dir, "metrics_detectors")
    if len(all_results) > 1:
        _save(plot_metric_bars(all_results, "All Models – Metric Comparison"),
              out_dir, "metrics_all")

    if len(all_results) > 1:
        print("\n[Radar overview]")
        _save(plot_summary_radar(all_results), out_dir, "radar_all")

    print("\n[Summary table]")
    _save(plot_summary_table(all_results), out_dir, "summary_table")

    if fi_clfs:
        print("\n[Feature importances]")
        for name, (clf, color) in fi_clfs.items():
            fig = plot_feature_importance(
                clf, feature_names,
                f"{name.upper()} – Feature Importances", color)
            _save(fig, out_dir, f"feature_importance_{name}")


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Visualise and compare IDS models; save plots as PNGs.")
    parser.add_argument("csv", help="Path to features CSV file (produced by pcap_to_csv.py)")
    parser.add_argument(
        "--algos", nargs="*",
        default=_DEFAULT_ALGOS, choices=list(CLASSIFIERS), metavar="ALGO",
        help=f"Supervised classifiers (default: all except knn). "
             f"Choices: {list(CLASSIFIERS)}")
    parser.add_argument(
        "--outliers", nargs="*",
        default=list(DETECTORS), choices=list(DETECTORS), metavar="DET",
        help=f"Outlier detectors (default: all). Choices: {list(DETECTORS)}")
    parser.add_argument("--no-classifiers", action="store_true")
    parser.add_argument("--no-outliers",    action="store_true")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Test fraction (default: 0.2)")
    parser.add_argument("--out-dir", type=Path, default=Path("model_plots"),
                        help="Directory to write PNG plots (default: model_plots/)")
    args = parser.parse_args()

    print(f"[1/4] Loading features from {args.csv} …")
    try:
        df = pd.read_csv(args.csv)
    except Exception as exc:
        sys.exit(f"Failed to load CSV: {exc}")

    if "label" not in df.columns:
        sys.exit("CSV must contain a 'label' column.")

    # ---- downsample majority class -----------------------------------------
    counts         = df["label"].value_counts()
    minority_n     = counts.min()
    majority_label = counts.idxmax()
    minority_label = counts.idxmin()

    df_majority = df[df["label"] == majority_label].sample(
        n=minority_n, random_state=42)
    df_minority = df[df["label"] == minority_label]
    df = pd.concat([df_majority, df_minority]).sample(
        frac=1, random_state=42).reset_index(drop=True)

    print(f"     Downsampled majority class (label={majority_label}) to "
          f"{minority_n} samples — dataset now balanced at "
          f"{len(df)} total rows.")

    feature_names = [c for c in df.columns if c != "label"]
    X = df[feature_names].values.astype(np.float32)
    y = df["label"].values

    n_pos   = int(y.sum())
    n_total = len(y)
    print(f"     {n_total:,} packets  |  {n_pos:,} malicious ({100*n_pos/n_total:.1f}%)")

    if n_pos == 0 or n_pos == n_total:
        sys.exit("Only one class present — cannot evaluate.")

    X = sanitise_features(X, feature_names)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y)

    clf_results, fi_clfs = [], {}
    if not args.no_classifiers and args.algos:
        print(f"[2/4] Training classifiers: {args.algos} …")
        clf_results, fi_clfs = run_classifiers(
            X_train, X_test, y_train, y_test, args.algos, feature_names)
    else:
        print("[2/4] Skipping classifiers.")

    det_results = []
    if not args.no_outliers and args.outliers:
        print(f"[3/4] Training outlier detectors: {args.outliers} …")
        det_results = run_detectors(
            X_train, X_test, y_train, y_test, args.outliers)
    else:
        print("[3/4] Skipping outlier detectors.")

    if not clf_results and not det_results:
        sys.exit("No models to evaluate.")

    print(f"[4/4] Saving plots to {args.out_dir}/ …")
    save_all_plots(clf_results, det_results, fi_clfs, feature_names, args.out_dir)
    print(f"\n✓  All plots saved to {args.out_dir.resolve()}/")


if __name__ == "__main__":
    main()