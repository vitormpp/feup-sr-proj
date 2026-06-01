"""
real_time/main.py
=================
Real-time, per-packet intrusion detection that reuses the *exact* feature
pipeline from ``ids.feature_extraction`` — no re-implementation.

Usage
-----
    sudo python ids/real_time/main.py <interface> [<model.joblib>] [<scaler.joblib>]

    <model.joblib>   – any model saved by classify.py or detect_outliers.py.
                       Defaults to the trained Random Forest (out_cls/rf.joblib).
    <scaler.joblib>  – optional; required for lr / svm / knn / ocsvm / lof models
                       (Random Forest needs none).

Only packets the model classifies as malicious (label=1) are printed.

Design notes
------------
* Feature extraction is delegated to
  ``ids.feature_extraction.extract_features_from_packets``, so the live feature
  schema is guaranteed identical to what the models were trained on.  When the
  vocabularies or temporal features in feature_extraction.py change, this
  sniffer follows automatically.
* ``extract_features_from_packets`` is batch/causal: rolling temporal features
  and TCP seq/ack deltas need the recent past of each flow.  To get them right
  for the current packet without re-reading the whole capture, we keep a small
  sliding buffer of the most recent packets (BUFFER_SECONDS) and re-extract over
  it on every packet, taking the LAST row (the current packet, since live
  capture timestamps are monotonic) as the feature vector to classify.
* The model — not the labelling rule in feature_extraction — decides the
  verdict, so we extract with ``with_label=False``.
"""

from __future__ import annotations

import os
import sys
import warnings
from collections import deque
from typing import Deque

import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff

# ---------------------------------------------------------------------------
# Make `ids` importable regardless of the current working directory.
# main.py lives at <mini_emulator>/ids/real_time/main.py, so two dirnames up
# from here is <mini_emulator>, the package root that holds `ids/`.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from ids.feature_extraction import extract_features_from_packets  # noqa: E402

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WINDOW_SECONDS: float = 1.0   # rolling look-back window (matches training default)

# How much packet history to retain in the sliding buffer.  Must comfortably
# exceed WINDOW_SECONDS so the current packet's rolling features see their full
# look-back window; extra slack improves TCP seq/ack-delta continuity.
BUFFER_SECONDS: float = max(WINDOW_SECONDS * 5.0, 5.0)

# Default model: the trained Random Forest classifier (needs no scaler).
DEFAULT_MODEL: str = os.path.join(_PKG_ROOT, "out_cls", "rf.joblib")

# Optional whitelist of known-good IPs.  Left as None (no whitelist) because the
# trained model, not the labelling heuristic, makes the malicious/normal call.
KNOWN_ADDRESSES: list[str] | None = None

# ---------------------------------------------------------------------------
# Model / scaler — loaded once at startup
# ---------------------------------------------------------------------------

_MODEL = None    # sklearn estimator with predict()
_SCALER = None   # StandardScaler or None

# Sliding buffer of recent scapy packets (oldest first).
_BUFFER: Deque = deque()

# Running packet counters.
_COUNT_TOTAL = 0
_COUNT_MALICIOUS = 0


def _load_model(model_path: str, scaler_path: str | None) -> None:
    global _MODEL, _SCALER
    _MODEL = joblib.load(model_path)
    if scaler_path is not None:
        _SCALER = joblib.load(scaler_path)
    print(f"[*] Model loaded from  {model_path!r}", flush=True)
    if _SCALER is not None:
        print(f"[*] Scaler loaded from {scaler_path!r}", flush=True)


def _predict(features: pd.Series) -> int:
    """
    Return 1 (malicious) or 0 (normal) for a single feature row.

    sklearn outlier detectors (IsolationForest, OneClassSVM, LOF,
    EllipticEnvelope) return +1 (inlier) / -1 (outlier); we map -1 → 1.
    Supervised classifiers return 0 / 1 directly.  Feeding the row in the
    DataFrame's native column order keeps it aligned with training.
    """
    X = features.to_numpy(dtype=np.float32).reshape(1, -1)

    if _SCALER is not None:
        X = _SCALER.transform(X)

    raw = _MODEL.predict(X)[0]
    if raw == -1:           # outlier detector: -1 = anomalous = malicious
        return 1
    return int(raw)


def process_packet(pkt) -> None:
    global _COUNT_TOTAL, _COUNT_MALICIOUS

    _BUFFER.append(pkt)

    # Evict packets older than BUFFER_SECONDS relative to the newest one.
    now = float(pkt.time)
    while _BUFFER and (now - float(_BUFFER[0].time)) > BUFFER_SECONDS:
        _BUFFER.popleft()

    # Re-run the real feature extractor over the buffer.  The current packet is
    # the most recent timestamp, so after the pipeline's internal sort it is the
    # last row.
    df = extract_features_from_packets(
        list(_BUFFER),
        known_addresses=KNOWN_ADDRESSES,
        window_seconds=WINDOW_SECONDS,
        with_label=False,
    )
    if df.empty:
        return

    features = df.iloc[-1]
    label = _predict(features)

    _COUNT_TOTAL += 1
    if label == 1:
        _COUNT_MALICIOUS += 1
        normal = _COUNT_TOTAL - _COUNT_MALICIOUS
        print(f"total={_COUNT_TOTAL}  normal={normal}  malicious={_COUNT_MALICIOUS}", flush=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) not in (2, 3, 4):
        print(
            f"Usage: sudo python {sys.argv[0]} <interface> [<model.joblib>] "
            f"[<scaler.joblib>]",
            file=sys.stderr,
        )
        sys.exit(1)

    iface = sys.argv[1]
    model_path = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_MODEL
    scaler_path = sys.argv[3] if len(sys.argv) == 4 else None

    _load_model(model_path, scaler_path)

    print(
        f"[*] Sniffing on {iface!r}  —  printing malicious packets only  "
        f"(Ctrl-C to stop)\n",
        flush=True,
    )
    sniff(iface=iface, prn=process_packet, store=False)
