"""
feature_extraction.py
======================
Stage 1 of the pipeline: turn a raw ``.pcap`` into a per-flow feature table
using NFStream.

The extractor keeps *both* the statistical features (what the models will see)
and the identity columns (src/dst IP + MAC, ports, timestamps).  The identity
columns are needed downstream by ``labeling.py`` to build the ground truth and
are dropped before any model is fitted -- see ``preprocessing.py``.

The result is cached to CSV so the expensive NFStream pass runs once; every
later stage (labeling, training, evaluation, plotting) can re-load the CSV and
runs anywhere, even without NFStream/libpcap installed.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from . import config

log = logging.getLogger("ids.features")


def extract_flows(pcap_path: str | Path) -> pd.DataFrame:
    """Run NFStream over ``pcap_path`` and return one row per bidirectional flow.

    ``statistical_analysis=True`` enables the packet-size / inter-arrival /
    TCP-flag statistics listed in ``config.BASE_FEATURES``.
    """
    try:
        from nfstream import NFStreamer
    except ImportError as exc:  # pragma: no cover - depends on host
        raise SystemExit(
            "nfstream is not installed. Run `pip install -r requirements.txt` "
            "inside the SEED Ubuntu VM (nfstream needs libpcap)."
        ) from exc

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    log.info("NFStream: opening %s (%.1f MB)",
             pcap_path, pcap_path.stat().st_size / 1e6)

    streamer = NFStreamer(
        source=str(pcap_path),
        statistical_analysis=True,   # packet-size / piat / flag stats
        splt_analysis=0,             # don't keep per-packet sequence payloads
        n_dissections=20,            # let nDPI label the L7 protocol
        accounting_mode=1,           # IP-layer byte accounting
    )

    df = streamer.to_pandas()
    if df.empty:
        raise SystemExit(f"NFStream produced 0 flows from {pcap_path}")

    log.info("NFStream: %d flows, %d raw columns", len(df), df.shape[1])
    return df


def load_or_extract(pcap_path: str | Path | None,
                    cache_csv: str | Path,
                    force: bool = False) -> pd.DataFrame:
    """Return the raw flow table, using the CSV cache when available.

    * If ``cache_csv`` exists and ``force`` is False -> load it (no NFStream).
    * Otherwise run NFStream on ``pcap_path`` and write the cache.
    """
    cache_csv = Path(cache_csv)
    if cache_csv.exists() and not force:
        log.info("Loading cached flow table: %s", cache_csv)
        return pd.read_csv(cache_csv, low_memory=False)

    if pcap_path is None:
        raise SystemExit(
            f"No cached features at {cache_csv} and no --pcap given. "
            "Provide a pcap to extract from."
        )

    df = extract_flows(pcap_path)
    cache_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(cache_csv, index=False)
    log.info("Cached raw flow table -> %s", cache_csv)
    return df
