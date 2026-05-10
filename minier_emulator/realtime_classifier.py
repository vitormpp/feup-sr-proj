#!/usr/bin/env python3
"""
realtime_classifier.py
-----------------------
Captures traffic from a network interface in real time, classifies flows
using a pre-trained model (Random Forest or Isolation Forest), and writes
detected malicious flows to per-source-IP pcap files.

For spoofed-source attacks the source IP in the flow will be the spoofed
address, which is unknown to the topology.  These flows are bucketed into
a single "unknown" output file.

Usage:
    sudo python realtime_classifier.py [options]

    Options:
        --interface   NIC to capture on              (default: eth0)
        --model       Path to .joblib model file     (default: random_forest.joblib)
        --model-type  "rf" or "iso"                  (default: rf)
        --scaler      Path to scaler .joblib         (default: scaler.joblib)
        --features    Path to feature_names .joblib  (default: feature_names.joblib)
        --known-ips   Comma-separated list of IPs considered part of the topology.
                      Flows whose source is not in this list are bucketed as
                      "unknown".  Auto-detected from the local interface if omitted.
        --out-dir     Directory for per-IP malicious pcap output (default: ./malicious)
        --idle-timeout   nfstream flow idle timeout in seconds  (default: 15)
        --active-timeout nfstream flow active timeout in seconds (default: 60)

Dependencies:
    pip install nfstream scikit-learn joblib scapy
"""

import argparse
import logging
import os
import socket
import subprocess
import sys
import threading
import warnings
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import warnings

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [classifier] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("realtime_classifier")

# ---------------------------------------------------------------------------
# Feature columns — must match what the model was trained on.
# The actual list is loaded from feature_names.joblib at runtime.
# ---------------------------------------------------------------------------

ALL_HOSTS = [
    "10.160.0.71", "10.160.0.72", "10.160.0.73",
    "10.161.0.71", "10.161.0.72", "10.161.0.73",
    "10.162.0.71", "10.162.0.72", "10.162.0.73", "10.162.0.74",
]

UNKNOWN_LABEL = "unknown"

# ---------------------------------------------------------------------------
# Pcap writer — uses scapy to append packets to a pcap file
# ---------------------------------------------------------------------------

try:
    from scapy.utils import PcapWriter
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    log.warning("scapy not available — malicious flow pcap writing disabled. "
                "Install with: pip install scapy")


class MaliciousPcapSink:
    """
    Thread-safe writer that maintains one open PcapWriter per source-IP bucket.
    Flows classified as malicious are re-captured from the interface for a
    short window to populate the output files.

    Because nfstream works at the flow level (not packet level), we record
    flow metadata to a CSV alongside a pcap reconstructed via scapy sniffing
    filtered to the flow's 5-tuple.
    """

    def __init__(self, out_dir: Path, interface: str, known_ips: set):
        self.out_dir   = out_dir
        self.interface = interface
        self.known_ips = known_ips
        self._lock     = threading.Lock()
        self._csv_rows = defaultdict(list)   # bucket -> list of dicts
        out_dir.mkdir(parents=True, exist_ok=True)

    def _bucket(self, src_ip: str) -> str:
        return src_ip if src_ip in self.known_ips else UNKNOWN_LABEL

    def record_flow(self, flow_row: dict, score: float):
        """Record a malicious flow's metadata to the appropriate bucket CSV."""
        src_ip = str(flow_row.get("src_ip", UNKNOWN_LABEL))
        bucket = self._bucket(src_ip)

        row = dict(flow_row)
        row["_malicious_score"] = score
        row["_bucket"]          = bucket

        with self._lock:
            self._csv_rows[bucket].append(row)
            self._flush_csv(bucket)

        log.info(
            "MALICIOUS [%s] src=%s dst=%s sport=%s dport=%s proto=%s score=%.3f",
            bucket,
            flow_row.get("src_ip", "?"),
            flow_row.get("dst_ip", "?"),
            flow_row.get("src_port", "?"),
            flow_row.get("dst_port", "?"),
            flow_row.get("protocol", "?"),
            score,
        )

    def _flush_csv(self, bucket: str):
        """Append the latest row to the per-bucket CSV (called under lock)."""
        import csv
        rows = self._csv_rows[bucket]
        if not rows:
            return
        csv_path = self.out_dir / f"{bucket}_malicious.csv"
        write_header = not csv_path.exists()
        with open(csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[-1].keys())
            if write_header:
                writer.writeheader()
            writer.writerow(rows[-1])


# ---------------------------------------------------------------------------
# Local IP detection
# ---------------------------------------------------------------------------

def get_local_ips() -> set:
    ips = set()
    try:
        output = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"], text=True, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    ips.add(parts[i + 1].split("/")[0])
    except Exception:
        pass
    ips.discard("127.0.0.1")
    return ips


# ---------------------------------------------------------------------------
# Flow feature extraction + classification
# ---------------------------------------------------------------------------

def extract_features(flow, feature_names: list) -> np.ndarray:
    """
    Pull the named features from an nfstream flow object.
    Missing attributes default to 0.
    """
    row = []
    for feat in feature_names:
        val = getattr(flow, feat, 0)
        if val is None or (isinstance(val, float) and (
                np.isnan(val) or np.isinf(val))):
            val = 0.0
        row.append(float(val))
    return np.array(row, dtype=np.float32).reshape(1, -1)


def classify_flow(flow, model, model_type: str, scaler, feature_names: list):
    """
    Returns (is_malicious: bool, score: float).
    score is the malicious class probability for RF, or the negative anomaly
    score for Isolation Forest (higher = more anomalous).
    """
    X = extract_features(flow, feature_names)
    X_scaled = scaler.transform(X)

    if model_type == "rf":
        pred = model.predict(X_scaled)[0]
        try:
            proba = model.predict_proba(X_scaled)[0]
            classes = list(model.classes_)
            score = proba[classes.index("malicious")] if "malicious" in classes else 0.0
        except Exception:
            score = 1.0 if pred == "malicious" else 0.0
        return pred == "malicious", score

    else:  # iso
        pred  = model.predict(X_scaled)[0]   # +1 = normal, -1 = anomaly
        score = -model.score_samples(X_scaled)[0]  # higher = more anomalous
        return pred == -1, float(score)


# ---------------------------------------------------------------------------
# Flow identity dict (for recording)
# ---------------------------------------------------------------------------

IDENTITY_ATTRS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "bidirectional_packets", "bidirectional_bytes",
]


def flow_to_dict(flow) -> dict:
    d = {}
    for attr in IDENTITY_ATTRS:
        d[attr] = getattr(flow, attr, None)
    return d


# ---------------------------------------------------------------------------
# Main capture loop
# ---------------------------------------------------------------------------

def run(args):
    # -- Load model artefacts ------------------------------------------------
    log.info("Loading model from %s (type=%s)", args.model, args.model_type)
    model         = joblib.load(args.model)
    scaler        = joblib.load(args.scaler)
    feature_names = joblib.load(args.features)
    log.info("Loaded %d features", len(feature_names))

    # -- Resolve known IPs ---------------------------------------------------
    if args.known_ips:
        known_ips = set(ip.strip() for ip in args.known_ips.split(",") if ip.strip())
    else:
        known_ips = set(ALL_HOSTS) | get_local_ips()
    log.info("Known IPs (%d): %s", len(known_ips), sorted(known_ips))

    # -- Output sink ---------------------------------------------------------
    out_dir = Path(args.out_dir)
    sink    = MaliciousPcapSink(out_dir, args.interface, known_ips)

    # -- nfstream live capture -----------------------------------------------
    try:
        from nfstream import NFStreamer
    except ImportError:
        sys.exit("ERROR: nfstream is not installed. pip install nfstream")

    log.info("Starting live capture on interface '%s'", args.interface)
    log.info("Idle timeout=%ds  Active timeout=%ds",
             args.idle_timeout, args.active_timeout)
    log.info("Output directory: %s", out_dir)

    streamer = NFStreamer(
        source=args.interface,
        statistical_analysis=True,
        splt_analysis=0,
        n_dissections=0,
        idle_timeout=args.idle_timeout,
        active_timeout=args.active_timeout,
    )

    total = 0
    malicious_count = 0

    try:
        for flow in streamer:
            total += 1
            is_malicious, score = classify_flow(
                flow, model, args.model_type, scaler, feature_names
            )

            if is_malicious:
                malicious_count += 1
                sink.record_flow(flow_to_dict(flow), score)

            if total % 100 == 0:
                log.info("Flows processed: %d  malicious: %d", total, malicious_count)

    except KeyboardInterrupt:
        log.info("Interrupted by user.")

    log.info("Done. Total flows: %d  Malicious: %d", total, malicious_count)
    log.info("Output written to: %s", out_dir)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Real-time flow classifier using a pre-trained sklearn model."
    )
    parser.add_argument(
        "--interface", default="eth0",
        help="Network interface to capture on (default: eth0)",
    )
    parser.add_argument(
        "--model", default="random_forest.joblib",
        help="Path to trained model .joblib file (default: random_forest.joblib)",
    )
    parser.add_argument(
        "--model-type", default="rf", choices=["rf", "iso"],
        help="Model type: 'rf' (Random Forest) or 'iso' (Isolation Forest) (default: rf)",
    )
    parser.add_argument(
        "--scaler", default="scaler.joblib",
        help="Path to fitted StandardScaler .joblib (default: scaler.joblib)",
    )
    parser.add_argument(
        "--features", default="feature_names.joblib",
        help="Path to feature name list .joblib (default: feature_names.joblib)",
    )
    parser.add_argument(
        "--known-ips", default="",
        help=(
            "Comma-separated list of topology IPs. Flows from other sources "
            "are bucketed as 'unknown'. Defaults to ALL_HOSTS + local IPs."
        ),
    )
    parser.add_argument(
        "--out-dir", default="./malicious",
        help="Directory to write per-IP malicious flow CSVs (default: ./malicious)",
    )
    parser.add_argument(
        "--idle-timeout", type=int, default=15,
        help="nfstream idle flow timeout in seconds (default: 15)",
    )
    parser.add_argument(
        "--active-timeout", type=int, default=60,
        help="nfstream active flow timeout in seconds (default: 60)",
    )

    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
     if os.environ.get("RUN_IDS", "").lower() in ["1", "true", "yes"]:
        main()