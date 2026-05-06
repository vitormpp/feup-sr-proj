#!/usr/bin/env python3
"""
detect_realtime.py
==================
Loads a trained IsolationForest + StandardScaler (produced by train_outlier_model.py)
and runs live anomaly detection on a network interface (or a pcap file for replay).

Flagged flows are written to a rotating log file AND printed to stdout.

Usage
-----
  # Live capture on eth0
  sudo python3 detect_realtime.py --iface eth0 --model model.pkl --scaler scaler.pkl

  # Replay a pcap (useful for testing without root)
  python3 detect_realtime.py --pcap test.pcap --model model.pkl --scaler scaler.pkl

  # Tune the anomaly threshold (lower = more sensitive; default: auto from contamination)
  sudo python3 detect_realtime.py --iface eth0 --model model.pkl --scaler scaler.pkl \\
      --threshold -0.12 --log-dir /var/log/netanomaly
"""

import argparse
import logging
import logging.handlers
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
#  These must exactly mirror what train_outlier_model.py used.
# --------------------------------------------------------------------------- #
CANDIDATE_FEATURES = [
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    "bidirectional_duration_ms",
    "src2dst_duration_ms",
    "dst2src_duration_ms",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "src2dst_mean_ps",
    "src2dst_stddev_ps",
    "dst2src_mean_ps",
    "dst2src_stddev_ps",
    "bidirectional_min_ps",
    "bidirectional_max_ps",
    "src2dst_min_ps",
    "src2dst_max_ps",
    "dst2src_min_ps",
    "dst2src_max_ps",
    "src2dst_bytes_ratio",
    "protocol",
    "bidirectional_syn_packets",
    "bidirectional_fin_packets",
    "bidirectional_rst_packets",
    "bidirectional_psh_packets",
    "bidirectional_ack_packets",
    "bidirectional_urg_packets",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_min_piat_ms",
    "bidirectional_max_piat_ms",
    "src2dst_mean_piat_ms",
    "src2dst_stddev_piat_ms",
    "src2dst_min_piat_ms",
    "src2dst_max_piat_ms",
    "dst2src_mean_piat_ms",
    "dst2src_stddev_piat_ms",
    "dst2src_min_piat_ms",
    "dst2src_max_piat_ms",
]

# Protocol number → name (IANA)
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

# How often (in flows) to print a heartbeat to stdout
HEARTBEAT_EVERY = 500

# --------------------------------------------------------------------------- #
#  Logging setup
# --------------------------------------------------------------------------- #

def _setup_logging(log_dir: str, verbose: bool) -> logging.Logger:
    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(parents=True, exist_ok=True)

    log = logging.getLogger("netanomaly")
    log.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    log.addHandler(ch)

    # Rotating file handler — one per day, keep 30 days
    fh = logging.handlers.TimedRotatingFileHandler(
        filename=log_dir_path / "anomalies.log",
        when="midnight",
        backupCount=30,
        utc=True,
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s\t%(levelname)s\t%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    ))
    log.addHandler(fh)

    return log


# --------------------------------------------------------------------------- #
#  Feature engineering (mirrors train_outlier_model.py)
# --------------------------------------------------------------------------- #

def _flow_to_feature_row(flow) -> dict:
    """Convert a single NFStream flow object (or dict-like) into a flat dict."""
    # NFStream flows expose attributes; handle both object and namedtuple styles
    def g(attr, default=0):
        try:
            v = getattr(flow, attr)
            return v if v is not None else default
        except AttributeError:
            return default

    total_bytes = g("bidirectional_bytes")
    s2d_bytes   = g("src2dst_bytes")
    ratio       = (s2d_bytes / total_bytes) if total_bytes > 0 else 0.5

    row = {feat: g(feat) for feat in CANDIDATE_FEATURES if feat != "src2dst_bytes_ratio"}
    row["src2dst_bytes_ratio"] = ratio
    return row


def _vectorize(row: dict, feature_cols: list[str]) -> np.ndarray:
    """Turn a feature dict into a float32 row vector aligned to feature_cols."""
    vec = np.array([row.get(col, 0.0) for col in feature_cols], dtype=np.float32)
    vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)
    return vec.reshape(1, -1)


# --------------------------------------------------------------------------- #
#  Flow formatting helper
# --------------------------------------------------------------------------- #

def _flow_summary(flow, score: float, threshold: float) -> str:
    """Return a human-readable one-liner describing the flagged flow."""
    def g(attr, default="?"):
        try:
            v = getattr(flow, attr)
            return v if v is not None else default
        except AttributeError:
            return default

    proto_num  = g("protocol", 0)
    proto_name = _PROTO_NAMES.get(proto_num, f"proto/{proto_num}")
    src_ip     = g("src_ip")
    src_port   = g("src_port", "")
    dst_ip     = g("dst_ip")
    dst_port   = g("dst_port", "")
    app        = g("application_name", "")
    pkts       = g("bidirectional_packets", 0)
    byts       = g("bidirectional_bytes", 0)
    dur_ms     = g("bidirectional_duration_ms", 0)

    src = f"{src_ip}:{src_port}" if src_port != "" else str(src_ip)
    dst = f"{dst_ip}:{dst_port}" if dst_port != "" else str(dst_ip)
    app_tag = f" [{app}]" if app and app not in ("", "Unknown") else ""

    return (
        f"{proto_name}{app_tag}  {src} -> {dst}  "
        f"pkts={pkts}  bytes={byts}  dur={dur_ms}ms  "
        f"score={score:.4f}  threshold={threshold:.4f}"
    )


# --------------------------------------------------------------------------- #
#  Core detection loop
# --------------------------------------------------------------------------- #

def run_detection(
    source: str,
    model,
    scaler,
    feature_cols: list[str],
    threshold: float,
    log: logging.Logger,
    pcap_mode: bool,
):
    try:
        from nfstream import NFStreamer
    except ImportError:
        log.error("nfstream is not installed.  Run:  pip install nfstream")
        sys.exit(1)

    log.info("Starting NFStreamer on source: %s  (pcap_mode=%s)", source, pcap_mode)
    log.info("Anomaly threshold: %.4f  (score below this → flagged)", threshold)
    log.info("Active feature columns (%d): %s", len(feature_cols), feature_cols)

    streamer_kwargs = dict(
        source=source,
        statistical_analysis=True,
        splt_analysis=0,
        n_dissections=20,
        accounting_mode=1,
    )

    # For live capture, idle/active timeouts control when a flow is emitted
    if not pcap_mode:
        streamer_kwargs["idle_timeout"]   = 15   # seconds of inactivity → export
        streamer_kwargs["active_timeout"] = 120  # max seconds before forced export

    streamer = NFStreamer(**streamer_kwargs)

    total_flows   = 0
    flagged_flows = 0
    start_time    = time.monotonic()

    # Graceful Ctrl-C
    _stop = [False]
    def _sigint(sig, frame):
        _stop[0] = True
    signal.signal(signal.SIGINT, _sigint)

    try:
        for flow in streamer:
            if _stop[0]:
                break

            total_flows += 1

            # --- Build feature vector ---
            row = _flow_to_feature_row(flow)
            X   = _vectorize(row, feature_cols)

            # --- Score ---
            X_scaled = scaler.transform(X)
            score    = float(model.score_samples(X_scaled)[0])

            # --- Flag? ---
            if score < threshold:
                flagged_flows += 1
                summary = _flow_summary(flow, score, threshold)
                log.warning("ANOMALY #%d  %s", flagged_flows, summary)

            # --- Heartbeat ---
            if total_flows % HEARTBEAT_EVERY == 0:
                elapsed = time.monotonic() - start_time
                fps     = total_flows / elapsed if elapsed > 0 else 0
                log.info(
                    "Heartbeat: flows_seen=%d  flagged=%d  elapsed=%.0fs  rate=%.1f flows/s",
                    total_flows, flagged_flows, elapsed, fps,
                )

    except Exception as exc:
        log.error("Unexpected error during capture: %s", exc, exc_info=True)
    finally:
        elapsed = time.monotonic() - start_time
        log.info(
            "Detection finished.  total_flows=%d  flagged=%d  elapsed=%.1fs",
            total_flows, flagged_flows, elapsed,
        )


# --------------------------------------------------------------------------- #
#  Threshold: auto-derive from model if not supplied
# --------------------------------------------------------------------------- #

def _auto_threshold(model) -> float:
    """
    Use the model's internal offset (calibrated during fit) as a default.
    IsolationForest stores `offset_` which is the decision boundary such that
    score_samples(...) < offset_  ⟺  predict(...) == -1.
    This replicates the contamination-aware threshold used at training time.
    """
    return float(model.offset_)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def parse_args():
    p = argparse.ArgumentParser(
        description="Real-time network anomaly detection with IsolationForest + NFStream."
    )
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--iface", metavar="INTERFACE",
                        help="Network interface for live capture (e.g. eth0). Requires root.")
    source.add_argument("--pcap",  metavar="FILE",
                        help="Replay a .pcap file instead of live capture.")

    p.add_argument("--model",     required=True, help="Path to model.pkl (from train_outlier_model.py)")
    p.add_argument("--scaler",    required=True, help="Path to scaler.pkl (from train_outlier_model.py)")
    p.add_argument("--threshold", type=float, default=None,
                   help="Anomaly score threshold.  Flows with score_samples() < threshold are flagged. "
                        "Default: model.offset_ (matches training contamination).")
    p.add_argument("--log-dir",   default="logs",
                   help="Directory for rotating anomaly log files (default: ./logs)")
    p.add_argument("--verbose",   action="store_true",
                   help="Enable DEBUG logging.")
    return p.parse_args()


def main():
    args = parse_args()
    log  = _setup_logging(args.log_dir, args.verbose)

    # ---- Load artifacts --------------------------------------------------- #
    model_path  = Path(args.model)
    scaler_path = Path(args.scaler)

    for p in (model_path, scaler_path):
        if not p.exists():
            log.error("File not found: %s", p)
            sys.exit(1)

    log.info("Loading model  : %s", model_path)
    model = joblib.load(model_path)

    log.info("Loading scaler : %s", scaler_path)
    scaler = joblib.load(scaler_path)

    # ---- Determine which feature columns the scaler was fitted on --------- #
    # StandardScaler stores n_features_in_; we reconstruct the column list by
    # matching against CANDIDATE_FEATURES in order (same logic as training).
    n_features = scaler.n_features_in_
    feature_cols = CANDIDATE_FEATURES[:n_features]  # safe fallback

    # Better: if the scaler has feature_names_in_ (scikit-learn >= 1.0 + pandas)
    if hasattr(scaler, "feature_names_in_") and scaler.feature_names_in_ is not None:
        feature_cols = list(scaler.feature_names_in_)
        log.info("Feature columns restored from scaler.feature_names_in_")
    else:
        log.warning(
            "scaler.feature_names_in_ not available; assuming first %d CANDIDATE_FEATURES. "
            "Re-train with a newer scikit-learn if this causes issues.",
            n_features,
        )

    # ---- Threshold -------------------------------------------------------- #
    threshold = args.threshold if args.threshold is not None else _auto_threshold(model)
    log.info("Anomaly threshold: %.4f", threshold)

    # ---- Run -------------------------------------------------------------- #
    pcap_mode = args.pcap is not None
    source    = args.pcap if pcap_mode else args.iface

    run_detection(
        source=source,
        model=model,
        scaler=scaler,
        feature_cols=feature_cols,
        threshold=threshold,
        log=log,
        pcap_mode=pcap_mode,
    )


if __name__ == "__main__":
    main()