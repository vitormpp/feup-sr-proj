"""
labeling.py
===========
Stage 2: attach the ground-truth label to every flow.

Rule (task requirement #3)
--------------------------
A flow is **malicious** (label 1) if either endpoint is the rogue node OR an
address that does not belong to the emulated topology:

  * source OR destination IP/MAC is the new_eth_node
    (10.162.0.74 / 02:42:0a:a2:00:4a)            -> "both directions" per user choice
  * source OR destination is a *unicast* IP absent from ``KNOWN_IPS``

Special/infrastructure addresses (broadcast, multicast, link-local, DHCP
0.0.0.0, loopback) are not treated as intruders just for being outside the
whitelist -- they are normal control-plane noise.

Everything else is **normal** (label 0).

These identity columns are used *only* here.  ``preprocessing.py`` drops them so
the models never see an IP/MAC/port.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd

from . import config

log = logging.getLogger("ids.label")


def _norm_mac(series: pd.Series) -> pd.Series:
    return (series.fillna("").astype(str).str.lower()
            .str.strip().str.replace("-", ":", regex=False))


def _is_special(ip_series: pd.Series) -> pd.Series:
    """True for addresses that are infrastructure noise, not intruders."""
    ip = ip_series.fillna("").astype(str)
    mask = pd.Series(False, index=ip.index)
    for prefix in config.BENIGN_SPECIAL_PREFIXES:
        mask |= ip.str.startswith(prefix)
    mask |= (ip == "")          # non-IP (pure L2) flows -> treat as normal noise
    return mask


def _unknown_unicast(ip_series: pd.Series) -> pd.Series:
    """True when the address is a real unicast IP not in the whitelist."""
    ip = ip_series.fillna("").astype(str)
    known = ip.isin(config.KNOWN_IPS)
    return (~known) & (~_is_special(ip))


def add_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Return ``df`` with a 1/0 ``label`` column added (and a few audit columns)."""
    df = df.copy()
    n = len(df)
    src_ip = df.get("src_ip", pd.Series([""] * n, index=df.index))
    dst_ip = df.get("dst_ip", pd.Series([""] * n, index=df.index))
    src_mac = _norm_mac(df.get("src_mac", pd.Series([""] * n, index=df.index)))
    dst_mac = _norm_mac(df.get("dst_mac", pd.Series([""] * n, index=df.index)))

    mal_macs = {m.lower() for m in config.MALICIOUS_MACS}

    # --- the rogue node, matched on either IP or MAC, in either direction ---
    rogue = (
        src_ip.isin(config.MALICIOUS_IPS) | dst_ip.isin(config.MALICIOUS_IPS)
        | src_mac.isin(mal_macs) | dst_mac.isin(mal_macs)
    )

    # --- any other off-topology unicast address, in either direction ---
    foreign = _unknown_unicast(src_ip) | _unknown_unicast(dst_ip)

    df[config.LABEL_COLUMN] = (rogue | foreign).astype(int)

    # audit columns (handy for plots / sanity checks; dropped before training)
    df["_label_reason"] = np.select(
        [rogue, foreign],
        ["rogue_node", "foreign_ip"],
        default="normal",
    )

    n_mal = int(df[config.LABEL_COLUMN].sum())
    log.info("Labelled %d flows: %d malicious (%.1f%%) / %d normal",
             n, n_mal, 100 * n_mal / max(n, 1), n - n_mal)
    if n_mal == 0:
        log.warning("No malicious flows found -- check the whitelist / capture.")
    if n_mal == n:
        log.warning("All flows malicious -- outlier detector will have no normal data.")
    return df
