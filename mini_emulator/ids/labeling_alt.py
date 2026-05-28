"""
labeling_alt.py
===============
Per-packet, **behaviour-based** ground-truth labelling for the packet IDS.

Rationale
---------
The flow-based ``labeling.py`` marks a packet as malicious iff one of its
endpoints is the rogue node (by IP or MAC) or any unicast IP not in the
whitelist. That's an *identity* label: it tells you "who" sent the packet,
not "what attack the packet is part of". A model trained on identity labels
ends up learning the rogue's normal heartbeats are malicious -- contradictory
signal that caps real-world generalisation.

This module replaces that rule with packet-pattern signatures of the actual
attacks the SEED emulator runs:

  * **SYN flood**  -- bursts of pure-SYN TCP packets from one source
                      across many destinations within a short window.
  * **ARP spoof**  -- ARP packets that introduce a new (IP -> MAC) binding
                      that contradicts the previously-observed binding,
                      plus gratuitous replies (unsolicited).
  * **BGP hijack** -- BGP (TCP/179) packets larger than a keepalive
                      arriving in temporal clusters atypical of a steady
                      session.

Each labelled packet additionally gets an ``_attack_type`` column so the
evaluation stage can report *per-attack* recall and false-positive rate
instead of a single binary F1 that hides which attacks the model misses.

Optional ground truth windows
-----------------------------
Hard-to-fingerprint attacks (or anything you have a precise timeline for)
can override the heuristics via an ``attack_windows.csv`` with columns:

    start_ts, end_ts, attack_type, src_ip, dst_ip

All four selectors are optional (empty = wildcard). Packets whose timestamp
falls in [start_ts, end_ts] and whose endpoints match the (possibly wildcard)
src_ip / dst_ip are tagged with ``attack_type`` and marked malicious. This
lets your attack scripts emit ground truth directly.

Outputs
-------
``add_labels(df)`` adds:
  * ``label``           1 if any heuristic / window fires, else 0
  * ``_attack_type``    one of ``benign``, ``syn_flood``, ``arp_spoof``,
                        ``bgp_hijack``, ``window:<name>``
  * ``_label_reason``   short human-readable string used for plots / audits
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from . import config_alt as config

log = logging.getLogger("ids.label_alt")

# --------------------------------------------------------------------------- #
#  Heuristic thresholds. Tunable but defaults match the SEED attack scripts:
#  * synflood runs 0.015 s bursts to many ports/IPs -- in 2 s bins we expect
#    one source to fire dozens of SYNs across 5+ destinations.
#  * arp_spoof issues gratuitous replies regularly; binding conflicts catch
#    them on the first replay.
#  * BGP keepalives are ~73 B; UPDATEs are larger -- flag >100 B BGP packets
#    that aren't a single isolated event.
# --------------------------------------------------------------------------- #
# Two SYN-flood patterns are detected, with thresholds tuned to the SEED
# scenario (synflood bursts of ~15 ms against a randomly-chosen target):
#   * single-target burst: many SYNs from one src to one (dst_ip, dst_port)
#     within a tight window -- the SEED synflood signature.
#   * multi-target scan:   many SYNs from one src across many destinations
#     in a wider window -- typical port scan / spread flood.
SYN_BURST_WINDOW_S = 0.5
SYN_BURST_COUNT = 20

SYN_SCAN_WINDOW_S = 2.0
SYN_SCAN_COUNT = 30
SYN_SCAN_DISTINCT_DESTS = 4

BGP_KEEPALIVE_SIZE = 100   # bytes, total frame size; > this looks like UPDATE
# Session-establishment grace period: BGP OPEN + initial UPDATEs are
# legitimate at the very start of a capture. We only treat oversized BGP
# packets as suspicious after this many seconds of settled session.
BGP_SETTLE_GRACE_S = 60.0

LABEL_BENIGN = "benign"
LABEL_SYN_FLOOD = "syn_flood"
LABEL_ARP_SPOOF = "arp_spoof"
LABEL_BGP_HIJACK = "bgp_hijack"


# --------------------------------------------------------------------------- #
#  SYN flood: per-source sliding-window count of pure SYNs
# --------------------------------------------------------------------------- #
def _label_syn_floods(df: pd.DataFrame, type_col: pd.Series,
                       reason_col: pd.Series) -> int:
    """Tag pure-SYN packets that belong to a flood.

    A pure SYN is ``tcp_syn==1, tcp_ack==0``. Two patterns fire:

      1. Single-target burst -- one src emits >= ``SYN_BURST_COUNT`` pure
         SYNs to one (dst_ip, dst_port) within ``SYN_BURST_WINDOW_S`` s.
         This is the SEED synflood signature: ~15 ms bursts against a
         random target.
      2. Multi-target scan -- one src emits >= ``SYN_SCAN_COUNT`` pure
         SYNs across >= ``SYN_SCAN_DISTINCT_DESTS`` distinct destinations
         in ``SYN_SCAN_WINDOW_S`` s. Catches port-scan / spread floods.

    Both patterns mark only the SYNs in the offending bin -- legitimate
    SYNs in the same window from other sources stay benign.
    """
    if "proto_tcp" not in df.columns or "tcp_syn" not in df.columns:
        return 0

    syn_mask = (
        (df["proto_tcp"] == 1)
        & (df["tcp_syn"] == 1)
        & (df["tcp_ack"] == 0)
    )
    if not syn_mask.any():
        return 0

    syns = df.loc[syn_mask, ["ts", "src_ip", "dst_ip", "dst_port"]].copy()
    n_flagged = 0

    # ---- Pattern 1: single-target burst ----------------------------------
    burst_bin = (syns["ts"] / SYN_BURST_WINDOW_S).astype("int64")
    burst_grp = syns.groupby([syns["src_ip"], syns["dst_ip"],
                              syns["dst_port"], burst_bin])
    burst_counts = burst_grp.size()
    hot_burst = burst_counts[burst_counts >= SYN_BURST_COUNT].index
    if len(hot_burst):
        hot_set = set(hot_burst)
        keys = list(zip(syns["src_ip"], syns["dst_ip"],
                        syns["dst_port"], burst_bin))
        burst_mask = pd.Series([k in hot_set for k in keys],
                                index=syns.index)
        target_idx = syns.index[burst_mask]
        type_col.loc[target_idx] = LABEL_SYN_FLOOD
        reason_col.loc[target_idx] = "syn_flood_burst"
        n_flagged += int(burst_mask.sum())

    # ---- Pattern 2: multi-target scan ------------------------------------
    scan_bin = (syns["ts"] / SYN_SCAN_WINDOW_S).astype("int64")
    syns["_dst"] = syns["dst_ip"].astype(str) + ":" + syns["dst_port"].astype(str)
    scan_grp = syns.groupby([syns["src_ip"], scan_bin])
    scan_counts = scan_grp.size()
    scan_distinct = scan_grp["_dst"].nunique()
    hot_scan = scan_counts[
        (scan_counts >= SYN_SCAN_COUNT)
        & (scan_distinct >= SYN_SCAN_DISTINCT_DESTS)
    ].index
    if len(hot_scan):
        hot_set2 = set(hot_scan)
        keys2 = list(zip(syns["src_ip"], scan_bin))
        scan_mask = pd.Series([k in hot_set2 for k in keys2],
                               index=syns.index)
        target_idx = syns.index[scan_mask]
        # Only overwrite rows still benign so per-attack reason stays
        # specific to the first pattern that fired.
        new = scan_mask & (type_col.loc[syns.index] == LABEL_BENIGN)
        target_idx = syns.index[new]
        type_col.loc[target_idx] = LABEL_SYN_FLOOD
        reason_col.loc[target_idx] = "syn_flood_scan"
        n_flagged += int(new.sum())

    return n_flagged


# --------------------------------------------------------------------------- #
#  ARP spoofing: binding conflicts and gratuitous replies
# --------------------------------------------------------------------------- #
def _label_arp_spoofs(df: pd.DataFrame, type_col: pd.Series,
                       reason_col: pd.Series) -> int:
    """Flag ARP packets whose (psrc IP -> src MAC) binding conflicts with the
    previously-observed binding for that IP, plus gratuitous replies.

    A gratuitous reply is an ARP op=2 (reply) where psrc == pdst -- the
    attacker announces its (claimed) IP without anyone asking. ARP spoofing
    in the SEED scenario uses both: it sends gratuitous replies claiming to
    be the gateway, which also conflicts with the gateway's real MAC.
    """
    if "proto_arp" not in df.columns:
        return 0
    arp_mask = df["proto_arp"] == 1
    if not arp_mask.any():
        return 0

    arps = df.loc[arp_mask, ["ts", "src_ip", "dst_ip", "src_mac", "arp_op"]].copy()
    arps = arps.sort_values("ts", kind="stable")

    bindings: dict[str, str] = {}
    flagged: list[int] = []
    reasons: dict[int, str] = {}

    for idx, row in arps.iterrows():
        ip = str(row["src_ip"] or "").strip()
        mac = str(row["src_mac"] or "").strip().lower()
        op = int(row["arp_op"] or 0)
        dst_ip = str(row["dst_ip"] or "").strip()

        # Gratuitous reply: op==2 (reply) and psrc==pdst (claiming own IP).
        is_gratuitous = (op == 2 and ip and ip == dst_ip)

        is_conflict = False
        if ip and mac:
            prev = bindings.get(ip)
            if prev is not None and prev != mac:
                is_conflict = True
            bindings[ip] = mac

        if is_conflict or is_gratuitous:
            flagged.append(idx)
            reasons[idx] = (
                "arp_binding_conflict" if is_conflict else "arp_gratuitous_reply"
            )

    if not flagged:
        return 0
    type_col.loc[flagged] = LABEL_ARP_SPOOF
    for idx in flagged:
        reason_col.loc[idx] = reasons[idx]
    return len(flagged)


# --------------------------------------------------------------------------- #
#  BGP hijack: oversized BGP packets in clusters
# --------------------------------------------------------------------------- #
def _label_bgp_anomalies(df: pd.DataFrame, type_col: pd.Series,
                          reason_col: pd.Series) -> int:
    """Heuristic BGP-anomaly tag: oversized BGP packets after session settle.

    Normal BGP keepalives are ~73 B and happen every ~30 s. UPDATE messages
    are bigger. The SEED BGP hijack injects exactly one UPDATE when the
    BIRD config is reloaded (and one WITHDRAW at cleanup) -- a burst-of-N
    detector wouldn't fire on a single UPDATE.

    Approach: flag every BGP packet whose ``pkt_len > BGP_KEEPALIVE_SIZE``
    that arrives after ``BGP_SETTLE_GRACE_S`` seconds of capture (i.e.,
    after legitimate initial OPEN + UPDATE exchanges have completed).
    """
    if "proto_bgp" not in df.columns:
        return 0
    if df.empty:
        return 0
    capture_start = float(df["ts"].iloc[0])
    bgp_mask = (
        (df["proto_bgp"] == 1)
        & (df["pkt_len"] > BGP_KEEPALIVE_SIZE)
        & ((df["ts"] - capture_start) > BGP_SETTLE_GRACE_S)
    )
    if not bgp_mask.any():
        return 0
    target_idx = df.index[bgp_mask]
    type_col.loc[target_idx] = LABEL_BGP_HIJACK
    reason_col.loc[target_idx] = "bgp_update_post_settle"
    return int(bgp_mask.sum())


# --------------------------------------------------------------------------- #
#  Optional ground-truth windows
# --------------------------------------------------------------------------- #
def _apply_attack_windows(df: pd.DataFrame, windows_csv: Path,
                           type_col: pd.Series, reason_col: pd.Series) -> int:
    """Tag packets falling inside user-supplied attack windows.

    CSV schema (header required):
        start_ts, end_ts, attack_type, src_ip, dst_ip
    Empty ``src_ip`` / ``dst_ip`` cells mean wildcard.
    """
    w = pd.read_csv(windows_csv)
    needed = {"start_ts", "end_ts", "attack_type"}
    missing = needed - set(w.columns)
    if missing:
        raise ValueError(f"attack_windows CSV missing columns: {sorted(missing)}")
    if "src_ip" not in w.columns:
        w["src_ip"] = ""
    if "dst_ip" not in w.columns:
        w["dst_ip"] = ""
    w["src_ip"] = w["src_ip"].fillna("").astype(str)
    w["dst_ip"] = w["dst_ip"].fillna("").astype(str)

    n_tagged = 0
    for _, row in w.iterrows():
        t0, t1 = float(row["start_ts"]), float(row["end_ts"])
        attack = str(row["attack_type"]).strip() or "window"
        src = row["src_ip"].strip()
        dst = row["dst_ip"].strip()

        mask = (df["ts"] >= t0) & (df["ts"] <= t1)
        if src:
            mask &= (df["src_ip"].astype(str) == src) | (df["dst_ip"].astype(str) == src)
        if dst:
            mask &= (df["src_ip"].astype(str) == dst) | (df["dst_ip"].astype(str) == dst)

        if mask.any():
            target_idx = df.index[mask]
            type_col.loc[target_idx] = attack
            reason_col.loc[target_idx] = f"window:{attack}"
            n_tagged += int(mask.sum())
    return n_tagged


# --------------------------------------------------------------------------- #
#  Public entry point
# --------------------------------------------------------------------------- #
def add_labels(df: pd.DataFrame,
               attack_windows_csv: str | Path | None = None) -> pd.DataFrame:
    """Return ``df`` with ``label``, ``_attack_type``, ``_label_reason`` added.

    Heuristics fire first (so the per-attack tag is always specific), then
    optional ground-truth windows override on top.
    """
    df = df.copy()
    n = len(df)

    if n == 0:
        df[config.LABEL_COLUMN] = pd.Series([], dtype=int)
        df["_attack_type"] = pd.Series([], dtype=str)
        df["_label_reason"] = pd.Series([], dtype=str)
        return df

    if "ts" not in df.columns:
        raise RuntimeError(
            "labeling_alt requires the absolute timestamp column 'ts'. "
            "Regenerate the packet cache with the current extractor."
        )

    type_col = pd.Series([LABEL_BENIGN] * n, index=df.index, dtype=object)
    reason_col = pd.Series(["normal"] * n, index=df.index, dtype=object)

    n_syn = _label_syn_floods(df, type_col, reason_col)
    n_arp = _label_arp_spoofs(df, type_col, reason_col)
    n_bgp = _label_bgp_anomalies(df, type_col, reason_col)

    n_win = 0
    if attack_windows_csv is not None:
        path = Path(attack_windows_csv)
        if path.exists():
            n_win = _apply_attack_windows(df, path, type_col, reason_col)
        else:
            log.warning("attack_windows_csv not found at %s -- ignoring", path)

    df["_attack_type"] = type_col
    df["_label_reason"] = reason_col
    df[config.LABEL_COLUMN] = (type_col != LABEL_BENIGN).astype(int)

    n_mal = int(df[config.LABEL_COLUMN].sum())
    log.info(
        "Labelled %d packets: %d malicious (%.1f%%) "
        "[syn_flood=%d, arp_spoof=%d, bgp_hijack=%d, window=%d]",
        n, n_mal, 100 * n_mal / max(n, 1),
        n_syn, n_arp, n_bgp, n_win,
    )
    if n_mal == 0:
        log.warning(
            "No malicious packets detected by behaviour heuristics. "
            "If you expect attacks in this capture, lower SYN_PER_WINDOW / "
            "BGP_BURST_COUNT or pass an attack_windows.csv ground truth."
        )
    if n_mal == n:
        log.warning("All packets labelled malicious -- nothing for outlier detectors.")
    return df
