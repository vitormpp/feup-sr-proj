"""
inspect_pcap.py
===============
Print statistics and save matplotlib PNG plots for a PCAP file, covering both
the raw capture and the post-feature-extraction view.

Usage
-----
    python inspect_pcap.py capture.pcap
    python inspect_pcap.py capture.pcap --malicious-ip 10.0.0.99
    python inspect_pcap.py capture.pcap --malicious-mac 00:11:22:33:44:55
    python inspect_pcap.py capture.pcap --known 10.0.0.1 10.0.0.2
    python inspect_pcap.py capture.pcap --window 2.0 --out-dir my_plots/
    python inspect_pcap.py capture.pcap --no-plots   # print only, no images

Output
------
  Plots are written to --out-dir (default: pcap_plots/).
  Each chart is saved as an individual PNG, named descriptively, e.g.:
    raw_label_pie.png
    raw_l4_proto.png
    raw_packet_size_dist.png
    feat_class_balance.png
    feat_corr_heatmap.png
    ... etc.
"""

from __future__ import annotations

import argparse
import sys
import warnings
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scapy.all import rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP

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

_PROTO_MAP: dict[int, str] = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
    58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

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
# Section 1 – Raw capture analysis
# ---------------------------------------------------------------------------

class RawStats:
    """Everything derived directly from scapy packets, before feature extraction."""

    def __init__(self, packets, malicious_ip: str, malicious_mac: str,
                 known_ips: frozenset | None):
        self.packets       = packets
        self.malicious_ip  = malicious_ip
        self.malicious_mac = malicious_mac.lower()
        self.known_ips     = known_ips
        self._analyse()

    def _analyse(self):
        pkts = self.packets
        n    = len(pkts)

        timestamps = [float(p.time) for p in pkts]
        self.n_packets   = n
        self.duration_s  = (max(timestamps) - min(timestamps)) if n > 1 else 0.0
        self.t_start     = min(timestamps)
        self.t_end       = max(timestamps)
        self.total_bytes = sum(len(p) for p in pkts)

        l3_proto  = Counter()
        l4_proto  = Counter()
        src_ips   = Counter()
        dst_ips   = Counter()
        src_bytes = Counter()
        dst_bytes = Counter()
        flows     = Counter()
        pkt_sizes = []
        iats      = []
        tcp_flags = Counter()
        labels    = []

        prev_ts = None
        for p in pkts:
            ts = float(p.time)
            if prev_ts is not None:
                iats.append(ts - prev_ts)
            prev_ts = ts

            size = len(p)
            pkt_sizes.append(size)

            src_ip = dst_ip = None
            if p.haslayer(IP):
                src_ip, dst_ip = p[IP].src, p[IP].dst
                proto_num = p[IP].proto
                l3_proto["IPv4"] += 1
            elif p.haslayer(IPv6):
                src_ip, dst_ip = p[IPv6].src, p[IPv6].dst
                proto_num = p[IPv6].nh
                l3_proto["IPv6"] += 1
            else:
                proto_num = 0
                l3_proto["Other"] += 1

            l4_name = _PROTO_MAP.get(proto_num, f"proto_{proto_num}")
            l4_proto[l4_name] += 1

            if src_ip:
                src_ips[src_ip]   += 1
                dst_ips[dst_ip]   += 1
                src_bytes[src_ip] += size
                dst_bytes[dst_ip] += size

            sport = dport = None
            if p.haslayer(TCP):
                sport, dport = p[TCP].sport, p[TCP].dport
                f = p[TCP].flags
                for bit, name in [(0x01,"FIN"),(0x02,"SYN"),(0x04,"RST"),
                                   (0x08,"PSH"),(0x10,"ACK"),(0x20,"URG")]:
                    if f & bit:
                        tcp_flags[name] += 1
            elif p.haslayer(UDP):
                sport, dport = p[UDP].sport, p[UDP].dport

            if src_ip and dst_ip:
                sp = f":{sport}" if sport else ""
                dp = f":{dport}" if dport else ""
                flows[f"{src_ip}{sp} → {dst_ip}{dp}"] += 1

            src_mac = p[Ether].src if p.haslayer(Ether) else None
            dst_mac = p[Ether].dst if p.haslayer(Ether) else None
            is_mal  = (
                self.malicious_ip  in (src_ip,  dst_ip)  or
                self.malicious_mac in (src_mac, dst_mac)
            )
            if not is_mal and self.known_ips is not None:
                if src_ip not in self.known_ips or dst_ip not in self.known_ips:
                    is_mal = True
            labels.append(int(is_mal))

        self.l3_proto  = l3_proto
        self.l4_proto  = l4_proto
        self.src_ips   = src_ips
        self.dst_ips   = dst_ips
        self.src_bytes = src_bytes
        self.dst_bytes = dst_bytes
        self.flows     = flows
        self.pkt_sizes = np.array(pkt_sizes)
        self.iats      = np.array(iats)
        self.tcp_flags = tcp_flags
        self.labels    = np.array(labels)

    def print_summary(self):
        n_mal = int(self.labels.sum())
        n_nor = self.n_packets - n_mal
        print("=" * 60)
        print("  RAW CAPTURE SUMMARY")
        print("=" * 60)
        print(f"  Packets          : {self.n_packets:,}")
        print(f"  Duration         : {self.duration_s:.3f} s")
        print(f"  Total bytes      : {self.total_bytes:,}  "
              f"({self.total_bytes/1024/1024:.2f} MB)")
        print(f"  Avg packet size  : {self.pkt_sizes.mean():.1f} bytes")
        if self.duration_s > 0:
            print(f"  Avg packet rate  : {self.n_packets/self.duration_s:.1f} pkt/s")
        print(f"  Label – normal   : {n_nor:,}  ({100*n_nor/self.n_packets:.1f}%)")
        print(f"  Label – malicious: {n_mal:,}  ({100*n_mal/self.n_packets:.1f}%)")
        print()

        print("  L3 protocol mix:")
        for k, v in self.l3_proto.most_common():
            print(f"    {k:<12} {v:>8,}  ({100*v/self.n_packets:.1f}%)")
        print()

        print("  L4 protocol mix:")
        for k, v in self.l4_proto.most_common(10):
            print(f"    {k:<12} {v:>8,}  ({100*v/self.n_packets:.1f}%)")
        print()

        print("  Top 10 source IPs (by packet count):")
        for ip, cnt in self.src_ips.most_common(10):
            tag = " ← MALICIOUS" if ip == self.malicious_ip else ""
            print(f"    {ip:<20} {cnt:>8,}{tag}")
        print()

        print("  Top 10 source IPs (by bytes sent):")
        for ip, b in sorted(self.src_bytes.items(), key=lambda x: -x[1])[:10]:
            tag = " ← MALICIOUS" if ip == self.malicious_ip else ""
            print(f"    {ip:<20} {b:>12,} bytes{tag}")
        print()

        print("  TCP flag distribution:")
        total_tcp = self.l4_proto.get("TCP", 1)
        for flag, cnt in self.tcp_flags.most_common():
            print(f"    {flag:<6} {cnt:>8,}  ({100*cnt/total_tcp:.1f}% of TCP)")
        print()

        print("  Packet-size statistics (bytes):")
        ps = self.pkt_sizes
        for label, name in [(None,"all"), (0,"normal"), (1,"malicious")]:
            subset = ps if label is None else ps[self.labels == label]
            if len(subset) == 0:
                continue
            print(f"    {name:<10}  min={subset.min():<6}  "
                  f"mean={subset.mean():<8.1f}  "
                  f"p50={int(np.percentile(subset,50)):<6}  "
                  f"p95={int(np.percentile(subset,95)):<6}  "
                  f"max={subset.max()}")
        print()

        if len(self.iats):
            print("  Inter-arrival time statistics (s):")
            ia = self.iats
            print(f"    min={ia.min():.6f}  mean={ia.mean():.6f}  "
                  f"p50={np.percentile(ia,50):.6f}  "
                  f"p95={np.percentile(ia,95):.6f}  "
                  f"max={ia.max():.6f}")
        print()

    def save_plots(self, out_dir: Path):
        print("\n[Raw capture plots]")

        # label pie
        n_mal = int(self.labels.sum())
        n_nor = self.n_packets - n_mal
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
        _save(fig, out_dir, "raw_label_pie")

        # L4 / L3 protocol bars
        for counts, title, suffix, color in [
            (self.l4_proto, "L4 Protocol Distribution", "raw_l4_proto", PALETTE[2]),
            (self.l3_proto, "L3 Protocol Distribution", "raw_l3_proto", PALETTE[3]),
        ]:
            fig = _hbar(dict(counts), title, color=color)
            if fig:
                _save(fig, out_dir, suffix)

        # top source IPs – packets
        fig = _hbar(dict(self.src_ips.most_common(15)),
                    "Top Source IPs (packet count)", color=PALETTE[1])
        if fig:
            _save(fig, out_dir, "raw_top_src_pkts")

        # top source IPs – bytes
        fig = _hbar(
            {k: v for k, v in sorted(self.src_bytes.items(),
                                     key=lambda x: -x[1])[:15]},
            "Top Source IPs (bytes sent)", color=PALETTE[4])
        if fig:
            _save(fig, out_dir, "raw_top_src_bytes")

        # top flows
        fig = _hbar(dict(self.flows.most_common(15)),
                    "Top 15 Flows (packet count)", color=PALETTE[6])
        if fig:
            _save(fig, out_dir, "raw_top_flows")

        # TCP flags
        if self.tcp_flags:
            fig = _hbar(dict(self.tcp_flags), "TCP Flag Counts", color=PALETTE[5])
            if fig:
                _save(fig, out_dir, "raw_tcp_flags")

        # packet size distribution by label
        fig, ax = plt.subplots(figsize=(7, 4))
        bins = np.linspace(0, min(self.pkt_sizes.max(), 1600), 50)
        for lbl, color, name in [(0, GREEN, "normal"), (1, ACCENT, "malicious")]:
            subset = self.pkt_sizes[self.labels == lbl]
            if len(subset):
                ax.hist(subset, bins=bins, color=color, alpha=0.65,
                        label=f"{name} (n={len(subset):,})", density=True)
        ax.set_xlabel("Packet size (bytes)", fontsize=9)
        ax.set_ylabel("Density", fontsize=9)
        ax.set_title("Packet Size Distribution", fontsize=11, color=TEXT)
        ax.legend(fontsize=8)
        ax.grid(True)
        fig.tight_layout()
        _save(fig, out_dir, "raw_packet_size_dist")

        # inter-arrival time distribution (log scale)
        if len(self.iats) > 1:
            pos_ia = self.iats[self.iats > 0]
            if len(pos_ia):
                fig, ax = plt.subplots(figsize=(7, 4))
                ax.hist(np.log10(pos_ia + 1e-9), bins=60,
                        color=PALETTE[2], alpha=0.85, density=True)
                ax.set_xlabel("log₁₀(inter-arrival time / s)", fontsize=9)
                ax.set_ylabel("Density", fontsize=9)
                ax.set_title("Inter-Arrival Time Distribution (log scale)",
                             fontsize=11, color=TEXT)
                ax.grid(True)
                fig.tight_layout()
                _save(fig, out_dir, "raw_iat_dist")

        # packet rate over time (1-second buckets)
        if self.duration_s > 1:
            fig, ax = plt.subplots(figsize=(9, 3.5))
            ts_all = np.array([float(p.time) for p in self.packets])
            t0     = ts_all.min()
            bins   = np.arange(0, self.duration_s + 1, 1.0)
            all_counts, edges = np.histogram(ts_all - t0, bins=bins)
            mal_counts, _     = np.histogram(ts_all[self.labels == 1] - t0, bins=bins)
            mid = (edges[:-1] + edges[1:]) / 2
            ax.fill_between(mid, all_counts, color=PALETTE[3], alpha=0.5, label="all")
            ax.fill_between(mid, mal_counts, color=ACCENT,     alpha=0.7, label="malicious")
            ax.set_xlabel("Time (s from capture start)", fontsize=9)
            ax.set_ylabel("Packets / s", fontsize=9)
            ax.set_title("Packet Rate Over Time", fontsize=11, color=TEXT)
            ax.legend(fontsize=8)
            ax.grid(True)
            fig.tight_layout()
            _save(fig, out_dir, "raw_pkt_rate_timeline")


# ---------------------------------------------------------------------------
# Section 2 – Post-extraction feature DataFrame analysis
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
        print("  POST-EXTRACTION FEATURE SUMMARY")
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

    def save_plots(self, out_dir: Path):
        print("\n[Feature DataFrame plots]")
        df       = self.df
        y        = self.y
        num_cols = self.X.select_dtypes(include=np.number).columns.tolist()
        bool_cols = [c for c in self.feature_cols if c not in num_cols]

        # class balance bar
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

        # numeric feature distributions by label (violin, chunked)
        if num_cols:
            chunk_size = 6
            chunks = [num_cols[i:i+chunk_size]
                      for i in range(0, len(num_cols), chunk_size)]
            for ci, chunk in enumerate(chunks):
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

        # one-hot coverage bar
        if bool_cols:
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

        # correlation heatmap
        if len(num_cols) >= 2:
            corr = df[num_cols].corr()
            fig, ax = plt.subplots(
                figsize=(max(6, len(num_cols)*0.6),
                         max(5, len(num_cols)*0.55)))
            im = ax.imshow(corr.values, cmap="RdBu_r", vmin=-1, vmax=1,
                           aspect="auto")
            ax.set_xticks(range(len(num_cols)))
            ax.set_yticks(range(len(num_cols)))
            ax.set_xticklabels(num_cols, rotation=45, ha="right", fontsize=7)
            ax.set_yticklabels(num_cols, fontsize=7)
            ax.set_title("Numeric Feature Correlation Matrix",
                         fontsize=11, color=TEXT)
            plt.colorbar(im, ax=ax, fraction=0.03, pad=0.04)
            fig.tight_layout()
            _save(fig, out_dir, "feat_corr_heatmap")

        # rolling temporal scatter
        temporal_cols = [c for c in num_cols if c.startswith("rolling_")
                         or c == "inter_arrival_time"]
        if temporal_cols and "rolling_pkt_rate" in df.columns:
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
                                   color=color, s=1.5, alpha=0.4, label=name)
                ax.set_ylabel(col, fontsize=8, color=MUTED)
                ax.grid(True)
                if ax is axes[0]:
                    ax.legend(fontsize=7, markerscale=4)
            axes[-1].set_xlabel("Packet index", fontsize=9)
            fig.suptitle("Rolling Temporal Features by Label",
                         fontsize=11, color=TEXT, y=1.001)
            fig.tight_layout()
            _save(fig, out_dir, "feat_temporal_scatter")

        # top 15 most discriminating features (normalised grouped bar)
        if len(num_cols) >= 2:
            means_nor = df.loc[y==0, num_cols].mean()
            means_mal = df.loc[y==1, num_cols].mean()
            diff = (means_mal - means_nor).abs().sort_values(ascending=False)
            top15 = diff.head(15).index.tolist()

            nor_v = means_nor[top15].values
            mal_v = means_mal[top15].values
            combined = np.stack([nor_v, mal_v])
            rng = combined.max(axis=0) - combined.min(axis=0)
            rng[rng == 0] = 1
            nor_n = (nor_v - combined.min(axis=0)) / rng
            mal_n = (mal_v - combined.min(axis=0)) / rng

            x = np.arange(len(top15))
            w = 0.35
            fig, ax = plt.subplots(figsize=(max(8, len(top15)*0.8), 4.5))
            ax.bar(x - w/2, nor_n, w, label="normal",    color=GREEN,  alpha=0.8)
            ax.bar(x + w/2, mal_n, w, label="malicious",  color=ACCENT, alpha=0.8)
            ax.set_xticks(x)
            ax.set_xticklabels(
                [c if len(c)<=14 else c[:13]+"…" for c in top15],
                rotation=40, ha="right", fontsize=8)
            ax.set_ylabel("Normalised mean", fontsize=9)
            ax.set_title("Top 15 Most Discriminating Numeric Features\n"
                         "(values normalised per feature)", fontsize=10, color=TEXT)
            ax.legend(fontsize=9)
            ax.grid(True, axis="y")
            fig.tight_layout()
            _save(fig, out_dir, "feat_discriminating_features")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect a PCAP: print stats and save matplotlib PNG plots.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("pcap", help="Path to .pcap / .pcapng file")
    parser.add_argument("--malicious-ip",  default=None, metavar="IP")
    parser.add_argument("--malicious-mac", default=None, metavar="MAC")
    parser.add_argument("--known", nargs="*", default=None, metavar="IP",
                        help="Known-good IP whitelist")
    parser.add_argument("--window", type=float, default=1.0,
                        help="Rolling-feature window in seconds (default: 1.0)")
    parser.add_argument("--out-dir", type=Path, default=Path("pcap_plots"),
                        help="Directory to write PNG plots (default: pcap_plots/)")
    parser.add_argument("--no-plots", action="store_true",
                        help="Print stats only; skip all plot generation")
    args = parser.parse_args()

    import ids.feature_extraction as fe_mod
    mal_ip  = args.malicious_ip  or fe_mod.MALICIOUS_IP
    mal_mac = args.malicious_mac or fe_mod.MALICIOUS_MAC

    print(f"Loading {args.pcap} …")
    try:
        packets = rdpcap(args.pcap)
    except Exception as exc:
        sys.exit(f"Could not read PCAP: {exc}")
    print(f"  {len(packets):,} packets loaded.\n")

    known_ips = frozenset(args.known) if args.known else None

    # raw analysis
    print("[1/3] Analysing raw capture …")
    raw = RawStats(packets, mal_ip, mal_mac, known_ips)
    raw.print_summary()

    # feature extraction
    print("[2/3] Running feature extraction …")
    try:
        fe_mod.MALICIOUS_IP  = mal_ip
        fe_mod.MALICIOUS_MAC = mal_mac.lower()
        df = fe_mod.extract_features(
            args.pcap,
            known_addresses=args.known,
            window_seconds=args.window,
        )
    except Exception as exc:
        sys.exit(f"Feature extraction failed: {exc}")
    finally:
        import importlib; importlib.reload(fe_mod)

    feat = FeatureStats(df)
    feat.print_summary()

    if args.no_plots:
        print("--no-plots set; done.")
        return

    # save all plots
    print(f"\n[3/3] Saving plots to {args.out_dir}/ …")
    raw.save_plots(args.out_dir)
    feat.save_plots(args.out_dir)
    print(f"\n✓  All plots saved to {args.out_dir.resolve()}/")


if __name__ == "__main__":
    main()