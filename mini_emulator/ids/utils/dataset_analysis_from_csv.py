"""
inspect_csv.py
==============
Print statistics and save matplotlib PNG plots for a features CSV file
(produced by pcap_to_csv.py).

Usage
-----
    python inspect_csv.py features.csv
    python inspect_csv.py features.csv --out-dir my_plots/
    python inspect_csv.py features.csv --no-plots   # print only, no images

Output
------
  Plots are written to --out-dir (default: csv_plots/).
  Each chart is saved as an individual PNG, named descriptively, e.g.:
    feat_class_balance.png
    feat_corr_heatmap.png
    feat_corr_with_label.png
    feat_violin_1.png
    feat_onehot_coverage.png
    feat_temporal_scatter.png
    feat_discriminating_features.png
"""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Shared style
# ---------------------------------------------------------------------------
PALETTE = ["#E63946", "#F4A261", "#2A9D8F", "#457B9D",
           "#A8DADC", "#E9C46A", "#264653", "#F77F00"]
BG      = "#0D1117"
SURFACE = "#161B22"
BORDER  = "#30363D"
TEXT    = "#E6EDF3"
MUTED   = "#8B949E"
ACCENT  = "#E63946"
GREEN   = "#3FB950"

plt.rcParams.update({
    "figure.facecolor": BG,   "axes.facecolor":  SURFACE,
    "axes.edgecolor":   BORDER, "axes.labelcolor": TEXT,
    "axes.titlecolor":  TEXT,   "xtick.color":     MUTED,
    "ytick.color":      MUTED,  "text.color":      TEXT,
    "grid.color":       BORDER, "grid.linestyle":  "--",
    "grid.alpha":       0.5,    "font.family":     "monospace",
    "legend.facecolor": SURFACE,"legend.edgecolor": BORDER,
})

# ---------------------------------------------------------------------------
# Shared save helper
# ---------------------------------------------------------------------------

def _save(fig: plt.Figure, out_dir: Path, name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=130,
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  saved → {path}")
    return path


def _hbar(counts: dict, title: str, color: str = PALETTE[2],
          max_items: int = 15) -> plt.Figure | None:
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:max_items]
    if not items:
        return None
    labels = [str(k) for k, _ in items]
    vals   = [v for _, v in items]
    fig, ax = plt.subplots(figsize=(8, max(2.5, len(labels) * 0.38)))
    ax.barh(labels[::-1], vals[::-1], color=color, alpha=0.85)
    ax.set_xlabel("Count", fontsize=9)
    ax.set_title(title, fontsize=11, color=TEXT)
    ax.grid(True, axis="x")
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Feature DataFrame analysis
# ---------------------------------------------------------------------------

class FeatureStats:
    """Derived from the post-extraction DataFrame."""

    def __init__(self, df: pd.DataFrame):
        self.df = df
        self.feature_cols = [c for c in df.columns if c != "label"]
        self.y = df["label"].values
        self.X = df[self.feature_cols]

    def print_summary(self):
        df  = self.df
        n   = len(df)
        n_mal = int(self.y.sum())
        n_nor = n - n_mal

        print("=" * 60)
        print("  FEATURE SUMMARY")
        print("=" * 60)
        print(f"  Rows             : {n:,}")
        print(f"  Feature columns  : {len(self.feature_cols)}")
        print(f"  Label – normal   : {n_nor:,}  ({100*n_nor/n:.1f}%)")
        print(f"  Label – malicious: {n_mal:,}  ({100*n_mal/n:.1f}%)")
        print()

        num_cols = self.X.select_dtypes(include=np.number).columns.tolist()
        print(f"  Numeric features ({len(num_cols)}):")
        print(f"  {'Feature':<30} {'mean':>9} {'std':>9} "
              f"{'min':>9} {'p50':>9} {'max':>9} {'zeros%':>7}")
        print("  " + "-"*78)
        for col in num_cols:
            v   = df[col].values.astype(float)
            pct = 100 * (v == 0).mean()
            print(f"  {col:<30} {v.mean():>9.3f} {v.std():>9.3f} "
                  f"{v.min():>9.3f} {np.percentile(v,50):>9.3f} "
                  f"{v.max():>9.3f} {pct:>6.1f}%")
        print()

        bool_cols = [c for c in self.feature_cols if c not in num_cols]
        if bool_cols:
            print(f"  One-hot / binary features ({len(bool_cols)}):")
            for col in sorted(bool_cols):
                v   = df[col].values.astype(float)
                pct = 100 * v.mean()
                print(f"    {col:<45}  active in {pct:5.1f}% of packets")
            print()

        # print correlation with label
        print("  Correlation with label (Pearson, numeric features):")
        print(f"  {'Feature':<35} {'corr':>8}")
        print("  " + "-"*45)
        try:
            corr_with_label = (
                df[num_cols + ["label"]]
                .corr()["label"]
                .drop("label")
                .sort_values(key=abs, ascending=False)
            )
            for col, val in corr_with_label.items():
                print(f"  {col:<35} {val:>8.4f}")
        except Exception as exc:
            print(f"  (could not compute: {exc})")
        print()

    def save_plots(self, out_dir: Path):
        print("\n[Feature DataFrame plots]")
        df       = self.df
        y        = self.y
        num_cols = self.X.select_dtypes(include=np.number).columns.tolist()
        bool_cols = [c for c in self.feature_cols if c not in num_cols]

        # ---- class balance bar -------------------------------------------
        n_nor = int((y == 0).sum())
        n_mal = int((y == 1).sum())
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.bar(["Normal", "Malicious"], [n_nor, n_mal],
               color=[GREEN, ACCENT], alpha=0.85, width=0.5)
        for i, v in enumerate([n_nor, n_mal]):
            ax.text(i, v + max(n_nor, n_mal) * 0.01, f"{v:,}",
                    ha="center", va="bottom", color=TEXT, fontsize=9)
        ax.set_ylabel("Packets", fontsize=9)
        ax.set_title("Class Balance", fontsize=11, color=TEXT)
        ax.grid(True, axis="y")
        fig.tight_layout()
        _save(fig, out_dir, "feat_class_balance")

        # ---- label pie ---------------------------------------------------
        fig, ax = plt.subplots(figsize=(4.5, 4))
        ax.pie(
            [n_nor, n_mal],
            labels=["Normal", "Malicious"],
            colors=[GREEN, ACCENT],
            autopct="%1.1f%%", startangle=90,
            textprops={"color": TEXT, "fontsize": 10},
            wedgeprops={"edgecolor": BG, "linewidth": 1.5},
        )
        ax.set_title("Label Distribution", fontsize=11, color=TEXT)
        _save(fig, out_dir, "feat_label_pie")

        # ---- numeric feature distributions by label (violin, chunked) ---
        if num_cols:
            chunk_size = 6
            chunks = [num_cols[i:i+chunk_size]
                      for i in range(0, len(num_cols), chunk_size)]
            for ci, chunk in enumerate(chunks):
                try:
                    fig, axes = plt.subplots(
                        1, len(chunk),
                        figsize=(max(7, len(chunk) * 2.2), 4))
                    if len(chunk) == 1:
                        axes = [axes]
                    for ax, col in zip(axes, chunk):
                        data_nor = df.loc[y==0, col].values.astype(float)
                        data_mal = df.loc[y==1, col].values.astype(float)
                        p99 = np.percentile(
                            np.concatenate([data_nor, data_mal]), 99)
                        data_nor = data_nor[data_nor <= p99]
                        data_mal = data_mal[data_mal <= p99]
                        groups = [(d, c) for d, c in
                                  zip([data_nor, data_mal], [GREEN, ACCENT])
                                  if len(d)]
                        if groups:
                            vp = ax.violinplot(
                                [g[0] for g in groups],
                                positions=list(range(len(groups))),
                                showmedians=True, showextrema=False)
                            for body, (_, color) in zip(vp["bodies"], groups):
                                body.set_facecolor(color)
                                body.set_alpha(0.7)
                            vp["cmedians"].set_color(TEXT)
                        labels_used = [lbl for lbl, d in
                                       zip(["nor", "mal"], [data_nor, data_mal])
                                       if len(d)]
                        ax.set_xticks(range(len(labels_used)))
                        ax.set_xticklabels(labels_used, fontsize=8)
                        short = col if len(col) <= 18 else col[:16] + "…"
                        ax.set_title(short, fontsize=8, color=MUTED)
                        ax.grid(True, axis="y")
                    fig.suptitle(
                        f"Numeric Feature Distributions by Label (part {ci+1})",
                        fontsize=10, color=TEXT, y=1.02)
                    fig.tight_layout()
                    _save(fig, out_dir, f"feat_violin_{ci+1}")
                except Exception as exc:
                    print(f"  [warn] violin chunk {ci+1} skipped: {exc}")
                    plt.close("all")

        # ---- one-hot coverage bar ----------------------------------------
        if bool_cols:
            try:
                coverage = dict(sorted(
                    {c: float(df[c].mean()) for c in bool_cols}.items(),
                    key=lambda x: x[1], reverse=True))
                keys  = list(coverage.keys())
                vals  = [coverage[k] * 100 for k in keys]
                colors = [ACCENT if "proto_" in k or "service_" in k
                          else PALETTE[2] for k in keys]
                fig, ax = plt.subplots(figsize=(9, max(3, len(coverage) * 0.32)))
                ax.barh(keys[::-1], vals[::-1], color=colors[::-1], alpha=0.85)
                ax.set_xlabel("% of packets with feature active", fontsize=9)
                ax.set_title("One-Hot Feature Coverage", fontsize=11, color=TEXT)
                ax.grid(True, axis="x")
                fig.tight_layout()
                _save(fig, out_dir, "feat_onehot_coverage")
            except Exception as exc:
                print(f"  [warn] one-hot coverage plot skipped: {exc}")
                plt.close("all")

        # ---- correlation heatmap (feature × feature) ---------------------
        if len(num_cols) >= 2:
            try:
                corr = df[num_cols].corr()
                # drop columns/rows that are all-NaN (constant features)
                corr = corr.dropna(axis=0, how="all").dropna(axis=1, how="all")
                if corr.shape[0] >= 2:
                    fig, ax = plt.subplots(
                        figsize=(max(6, corr.shape[1]*0.6),
                                 max(5, corr.shape[0]*0.55)))
                    im = ax.imshow(corr.values, cmap="RdBu_r", vmin=-1, vmax=1,
                                   aspect="auto")
                    ax.set_xticks(range(corr.shape[1]))
                    ax.set_yticks(range(corr.shape[0]))
                    ax.set_xticklabels(corr.columns, rotation=45,
                                       ha="right", fontsize=7)
                    ax.set_yticklabels(corr.index, fontsize=7)
                    ax.set_title("Numeric Feature Correlation Matrix",
                                 fontsize=11, color=TEXT)
                    plt.colorbar(im, ax=ax, fraction=0.03, pad=0.04)
                    fig.tight_layout()
                    _save(fig, out_dir, "feat_corr_heatmap")
            except Exception as exc:
                print(f"  [warn] feature correlation heatmap skipped: {exc}")
                plt.close("all")

        # ---- correlation with label (horizontal bar) ---------------------
        if len(num_cols) >= 1:
            try:
                corr_label = (
                    df[num_cols + ["label"]]
                    .corr()["label"]
                    .drop("label")
                    .dropna()
                    .sort_values()
                )
                if len(corr_label):
                    colors = [ACCENT if v > 0 else GREEN
                              for v in corr_label.values]
                    fig, ax = plt.subplots(
                        figsize=(8, max(3, len(corr_label) * 0.32)))
                    ax.barh(corr_label.index, corr_label.values,
                            color=colors, alpha=0.85)
                    ax.axvline(0, color=TEXT, linewidth=0.8, linestyle="--")
                    ax.set_xlabel("Pearson correlation with label", fontsize=9)
                    ax.set_title("Feature Correlation with Label\n"
                                 "(red = positively correlated with malicious)",
                                 fontsize=10, color=TEXT)
                    ax.grid(True, axis="x")
                    fig.tight_layout()
                    _save(fig, out_dir, "feat_corr_with_label")
            except Exception as exc:
                print(f"  [warn] correlation-with-label plot skipped: {exc}")
                plt.close("all")

        # ---- rolling temporal scatter ------------------------------------
        temporal_cols = [c for c in num_cols if c.startswith("rolling_")
                         or c == "inter_arrival_time"]
        if temporal_cols:
            try:
                idx = np.arange(len(df))
                fig, axes = plt.subplots(
                    len(temporal_cols), 1,
                    figsize=(10, 2.8 * len(temporal_cols)),
                    sharex=True)
                if len(temporal_cols) == 1:
                    axes = [axes]
                for ax, col in zip(axes, temporal_cols):
                    for lbl, color, name in [(0, GREEN, "normal"),
                                             (1, ACCENT, "malicious")]:
                        mask = y == lbl
                        if mask.any():
                            ax.scatter(idx[mask], df[col].values[mask],
                                       color=color, s=1.5, alpha=0.4,
                                       label=name)
                    ax.set_ylabel(col, fontsize=8, color=MUTED)
                    ax.grid(True)
                    if ax is axes[0]:
                        ax.legend(fontsize=7, markerscale=4)
                axes[-1].set_xlabel("Packet index", fontsize=9)
                fig.suptitle("Rolling Temporal Features by Label",
                             fontsize=11, color=TEXT, y=1.001)
                fig.tight_layout()
                _save(fig, out_dir, "feat_temporal_scatter")
            except Exception as exc:
                print(f"  [warn] temporal scatter skipped: {exc}")
                plt.close("all")

        # ---- top 15 most discriminating features -------------------------
        if len(num_cols) >= 2:
            try:
                means_nor = df.loc[y==0, num_cols].mean()
                means_mal = df.loc[y==1, num_cols].mean()
                diff = (means_mal - means_nor).abs().dropna().sort_values(
                    ascending=False)
                top15 = diff.head(15).index.tolist()
                if len(top15) >= 2:
                    nor_v = means_nor[top15].values.astype(float)
                    mal_v = means_mal[top15].values.astype(float)
                    combined = np.stack([nor_v, mal_v])
                    rng = combined.max(axis=0) - combined.min(axis=0)
                    rng[rng == 0] = 1
                    nor_n = (nor_v - combined.min(axis=0)) / rng
                    mal_n = (mal_v - combined.min(axis=0)) / rng

                    x = np.arange(len(top15))
                    w = 0.35
                    fig, ax = plt.subplots(figsize=(max(8, len(top15)*0.8), 4.5))
                    ax.bar(x - w/2, nor_n, w, label="normal",
                           color=GREEN,  alpha=0.8)
                    ax.bar(x + w/2, mal_n, w, label="malicious",
                           color=ACCENT, alpha=0.8)
                    ax.set_xticks(x)
                    ax.set_xticklabels(
                        [c if len(c)<=14 else c[:13]+"…" for c in top15],
                        rotation=40, ha="right", fontsize=8)
                    ax.set_ylabel("Normalised mean", fontsize=9)
                    ax.set_title(
                        "Top 15 Most Discriminating Numeric Features\n"
                        "(values normalised per feature)",
                        fontsize=10, color=TEXT)
                    ax.legend(fontsize=9)
                    ax.grid(True, axis="y")
                    fig.tight_layout()
                    _save(fig, out_dir, "feat_discriminating_features")
            except Exception as exc:
                print(f"  [warn] discriminating features plot skipped: {exc}")
                plt.close("all")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect a features CSV: print stats and save PNG plots.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("csv", help="Path to features CSV file (produced by pcap_to_csv.py)")
    parser.add_argument("--out-dir", type=Path, default=Path("csv_plots"),
                        help="Directory to write PNG plots (default: csv_plots/)")
    parser.add_argument("--no-plots", action="store_true",
                        help="Print stats only; skip all plot generation")
    args = parser.parse_args()

    print(f"Loading {args.csv} …")
    try:
        df = pd.read_csv(args.csv)
    except Exception as exc:
        sys.exit(f"Could not read CSV: {exc}")

    if "label" not in df.columns:
        sys.exit("CSV must contain a 'label' column.")

    print(f"  {len(df):,} rows, {len(df.columns)} columns loaded.\n")

    feat = FeatureStats(df)
    feat.print_summary()

    if args.no_plots:
        print("--no-plots set; done.")
        return

    print(f"\nSaving plots to {args.out_dir}/ …")
    feat.save_plots(args.out_dir)
    print(f"\n✓  All plots saved to {args.out_dir.resolve()}/")


if __name__ == "__main__":
    main()