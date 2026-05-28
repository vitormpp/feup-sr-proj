"""
packet_feature_extraction.py
=============================
Stage 1 (per-packet variant): turn a raw ``.pcap`` into a per-packet feature
table using Scapy.

Design goals
------------
* **No identity leakage** -- IP addresses, MAC addresses, ports and absolute
  timestamps are used *only* to build flow-tracking state internally; they
  never appear in the output rows.  This mirrors the ``IDENTITY_COLUMNS`` rule
  enforced in ``config.py`` / ``preprocessing.py``.

* **Three feature layers per row**:
    1. Packet-level fields   -- what this packet looks like in isolation
                               (size, protocol one-hot, TCP flags, TTL,
                               window size, direction within the flow).
    2. Running flow context  -- rolling statistics computed from the start of
                               the flow up to and including this packet
                               (cumulative counts, running mean/stddev of
                               packet size, inter-arrival deltas).
    3. Completed-flow summary -- aggregate statistics over the *entire* flow,
                               attached to every row of that flow in a second
                               pass (gives the model the same view NFStream did,
                               but stored per-packet rather than per-flow).

* **Two-pass approach** (offline / pcap only):
    Pass 1 -- stream packets with Scapy, build flow state, emit per-packet
              rows with packet-level + running features.
    Pass 2 -- for each completed flow, compute summary statistics and join them
              back onto every row belonging to that flow.

  This means every output row has a full view of both the running context *and*
  the completed flow, making it easy to train models that replicate flow-level
  IDS logic at the granularity of individual packets.

* **Result cached to CSV** -- identical caching strategy to the original
  ``feature_extraction.py`` so downstream stages (labeling, preprocessing,
  training) remain unchanged.

Dependencies
------------
  pip install scapy pandas numpy
  (no libpcap wrapper needed beyond what Scapy pulls in)

Usage
-----
  from ids import packet_feature_extraction as pfe

  df = pfe.load_or_extract(pcap_path="capture.pcap",
                           cache_csv="ids_out/packets_raw.csv")
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

log = logging.getLogger("ids.pkt_features")

# --------------------------------------------------------------------------- #
#  Protocol one-hot encoding
# --------------------------------------------------------------------------- #

# Well-known IP protocol numbers -> output column name.
# Any protocol not in this dict sets proto_other=1 and all others 0.
_KNOWN_PROTOS: dict[int, str] = {
    1:   "proto_icmp",
    6:   "proto_tcp",
    17:  "proto_udp",
    47:  "proto_gre",
    50:  "proto_esp",
    58:  "proto_icmpv6",
    89:  "proto_ospf",
    132: "proto_sctp",
}
# All one-hot column names in a stable order (used to ensure consistent columns)
_PROTO_COLUMNS: list[str] = sorted(_KNOWN_PROTOS.values()) + ["proto_other"]


def _protocol_onehot(proto_num: int) -> dict[str, int]:
    """Return a dict with exactly one flag set for the given IP protocol number."""
    row: dict[str, int] = {col: 0 for col in _PROTO_COLUMNS}
    if proto_num in _KNOWN_PROTOS:
        row[_KNOWN_PROTOS[proto_num]] = 1
    else:
        row["proto_other"] = 1
    return row


# --------------------------------------------------------------------------- #
#  Internal flow key / state
# --------------------------------------------------------------------------- #

def _flow_key(pkt) -> tuple | None:
    """Return a canonical (sorted) 5-tuple key or None if not IP/TCP/UDP.

    The key is sorted so that both directions of a conversation share the
    same key -- identical to how NFStream treats bidirectional flows.
    The tuple is used *only* internally for flow tracking; it is never
    written to the output DataFrame.
    """
    from scapy.layers.inet import IP, TCP, UDP

    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    proto = ip.proto

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src = (ip.src, tcp.sport)
        dst = (ip.dst, tcp.dport)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src = (ip.src, udp.sport)
        dst = (ip.dst, udp.dport)
    else:
        # Other IP protocols (ICMP etc.) -- use (ip, 0) as port placeholder
        src = (ip.src, 0)
        dst = (ip.dst, 0)

    # Canonical ordering: smaller (ip, port) pair first
    if src <= dst:
        return (src[0], src[1], dst[0], dst[1], proto)
    else:
        return (dst[0], dst[1], src[0], src[1], proto)


def _direction(pkt, key: tuple) -> int:
    """Return 1 if packet goes src->dst (forward) in the canonical key, 0 if reverse."""
    from scapy.layers.inet import IP, TCP, UDP

    ip = pkt[IP]
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
    else:
        sport = 0

    # key[0] is the canonical forward src IP, key[1] is the forward src port
    return int(ip.src == key[0] and sport == key[1])


# --------------------------------------------------------------------------- #
#  Welford online mean / variance (no sqrt on every packet)
# --------------------------------------------------------------------------- #

class _Welford:
    """Incremental mean and sample-variance (Welford's algorithm)."""

    __slots__ = ("n", "mean", "M2")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, x: float):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.M2 += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        return self.M2 / self.n if self.n > 1 else 0.0

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)


# --------------------------------------------------------------------------- #
#  Flow state accumulator
# --------------------------------------------------------------------------- #

class _FlowState:
    """Mutable per-flow tracking state (never serialised to CSV).

    All counters start at zero. The first packet -- like every subsequent
    packet -- is fully processed by the normal update path in _pass1.
    _FlowState.__init__ only records identity fields, timing anchors, and
    the initial ps_min/ps_max seed (updated immediately on first update).
    """

    __slots__ = (
        # identity (internal only, NOT written to output)
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "src_mac", "dst_mac",
        # timing
        "first_seen_ts", "last_seen_ts", "prev_ts",
        "fwd_prev_ts",   # None until first forward packet arrives
        "rev_prev_ts",   # None until first reverse packet arrives
        # counts
        "pkt_count", "fwd_pkt_count", "rev_pkt_count",
        "byte_count", "fwd_byte_count", "rev_byte_count",
        # TCP flags
        "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
        "fwd_syn", "rev_syn",
        # running stats for packet size
        "ps_wf",        # Welford for bidirectional packet size
        "fwd_ps_wf",    # Welford for forward direction
        "rev_ps_wf",    # Welford for reverse direction
        # running stats for inter-arrival time
        "iat_wf",
        "fwd_iat_wf",
        "rev_iat_wf",
        # min / max packet size
        "ps_min", "ps_max",
    )

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto,
                 src_mac, dst_mac, ts: float, pkt_len: int):
        # Identity (never written to output)
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.protocol  = proto
        self.src_mac   = src_mac
        self.dst_mac   = dst_mac

        # Timing anchors
        self.first_seen_ts = ts
        self.last_seen_ts  = ts
        self.prev_ts       = ts

        # None sentinel: IAT for the first packet in each direction is 0,
        # computed correctly because we gate on "prev_ts is not None".
        self.fwd_prev_ts = None
        self.rev_prev_ts = None

        # All counters start at zero; _pass1 increments them for every packet
        # including the first, so nothing is silently dropped.
        self.pkt_count      = 0
        self.fwd_pkt_count  = 0
        self.rev_pkt_count  = 0
        self.byte_count     = 0
        self.fwd_byte_count = 0
        self.rev_byte_count = 0

        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.fwd_syn   = 0
        self.rev_syn   = 0

        self.ps_wf      = _Welford()
        self.fwd_ps_wf  = _Welford()
        self.rev_ps_wf  = _Welford()
        self.iat_wf     = _Welford()
        self.fwd_iat_wf = _Welford()
        self.rev_iat_wf = _Welford()

        # Seed min/max with the first packet length; they are updated again
        # when _pass1 processes this first packet, which is harmless.
        self.ps_min = float(pkt_len)
        self.ps_max = float(pkt_len)


# --------------------------------------------------------------------------- #
#  Pass 1: stream packets and emit per-packet rows
# --------------------------------------------------------------------------- #

def _extract_tcp_flags(pkt) -> dict[str, int]:
    from scapy.layers.inet import TCP
    if not pkt.haslayer(TCP):
        return dict(tcp_syn=0, tcp_ack=0, tcp_rst=0, tcp_fin=0,
                    tcp_psh=0, tcp_urg=0, tcp_ece=0, tcp_cwr=0)
    f = pkt[TCP].flags
    return dict(
        tcp_syn=int(bool(f & 0x002)),
        tcp_ack=int(bool(f & 0x010)),
        tcp_rst=int(bool(f & 0x004)),
        tcp_fin=int(bool(f & 0x001)),
        tcp_psh=int(bool(f & 0x008)),
        tcp_urg=int(bool(f & 0x020)),
        tcp_ece=int(bool(f & 0x040)),
        tcp_cwr=int(bool(f & 0x080)),
    )


def _pass1(pcap_path: Path) -> tuple[list[dict], dict[tuple, _FlowState]]:
    """
    Stream every packet from the pcap.  For each IP packet:
      - update the flow state
      - emit one row dict containing packet-level + running-context features
      - record the flow key on the row so Pass 2 can join summary stats

    Returns (rows, flow_states) where flow_states is the final state of every
    flow (used in Pass 2 to compute completed-flow summaries).
    """
    try:
        from scapy.utils import PcapReader
        from scapy.layers.inet import IP, TCP, UDP, Ether
    except ImportError as exc:
        raise SystemExit(
            "scapy is not installed.  Run `pip install scapy`."
        ) from exc

    flows: dict[tuple, _FlowState] = {}
    rows: list[dict] = []
    skipped = 0

    log.info("Pass 1: streaming %s ...", pcap_path)

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            key = _flow_key(pkt)
            if key is None:
                skipped += 1
                continue

            ip = pkt[IP]
            ts = float(pkt.time)           # absolute -- only used for deltas
            pkt_len = len(pkt)             # total captured length

            # TCP/UDP specific fields
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                win_size  = tcp.window
                proto_num = 6
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport
                win_size  = 0
                proto_num = 17
            else:
                sport, dport = 0, 0
                win_size  = 0
                proto_num = ip.proto

            src_mac   = pkt[Ether].src if pkt.haslayer(Ether) else ""
            dst_mac   = pkt[Ether].dst if pkt.haslayer(Ether) else ""
            tcp_flags = _extract_tcp_flags(pkt)

            # -------------------------------------------------------------- #
            #  Initialise or retrieve flow state
            # -------------------------------------------------------------- #
            if key not in flows:
                flows[key] = _FlowState(
                    src_ip=ip.src, dst_ip=ip.dst,
                    src_port=sport, dst_port=dport,
                    proto=proto_num,
                    src_mac=src_mac, dst_mac=dst_mac,
                    ts=ts, pkt_len=pkt_len,
                )

            st        = flows[key]
            direction = _direction(pkt, key)   # 1 = forward, 0 = reverse

            # -------------------------------------------------------------- #
            #  Inter-arrival time
            #
            #  Use the None sentinel on fwd_prev_ts / rev_prev_ts so the very
            #  first packet in each direction correctly reports IAT = 0 rather
            #  than measuring against the flow-start timestamp.
            #
            #  Bidirectional IAT: 0 for the absolute first packet of the flow,
            #  otherwise delta from the previous packet of either direction.
            # -------------------------------------------------------------- #
            iat_ms = (ts - st.prev_ts) * 1000.0 if st.pkt_count > 0 else 0.0

            if direction == 1:
                fwd_iat_ms = (
                    (ts - st.fwd_prev_ts) * 1000.0
                    if st.fwd_prev_ts is not None else 0.0
                )
                rev_iat_ms = 0.0
            else:
                fwd_iat_ms = 0.0
                rev_iat_ms = (
                    (ts - st.rev_prev_ts) * 1000.0
                    if st.rev_prev_ts is not None else 0.0
                )

            # -------------------------------------------------------------- #
            #  Update running state (BEFORE emitting the row so the row sees
            #  the state *including* this packet)
            # -------------------------------------------------------------- #
            st.pkt_count  += 1
            st.byte_count += pkt_len
            st.ps_wf.update(pkt_len)
            st.ps_min = min(st.ps_min, pkt_len)
            st.ps_max = max(st.ps_max, pkt_len)
            st.last_seen_ts = ts

            # Gate IAT Welford on pkt_count > 1 (need at least two packets for
            # a meaningful inter-arrival interval).
            if st.pkt_count > 1:
                st.iat_wf.update(iat_ms)

            if direction == 1:
                st.fwd_pkt_count  += 1
                st.fwd_byte_count += pkt_len
                st.fwd_ps_wf.update(pkt_len)
                if st.fwd_pkt_count > 1:
                    st.fwd_iat_wf.update(fwd_iat_ms)
                st.fwd_syn    += tcp_flags["tcp_syn"]
                st.fwd_prev_ts = ts
            else:
                st.rev_pkt_count  += 1
                st.rev_byte_count += pkt_len
                st.rev_ps_wf.update(pkt_len)
                if st.rev_pkt_count > 1:
                    st.rev_iat_wf.update(rev_iat_ms)
                st.rev_syn    += tcp_flags["tcp_syn"]
                st.rev_prev_ts = ts

            st.syn_count += tcp_flags["tcp_syn"]
            st.ack_count += tcp_flags["tcp_ack"]
            st.rst_count += tcp_flags["tcp_rst"]
            st.fin_count += tcp_flags["tcp_fin"]
            st.psh_count += tcp_flags["tcp_psh"]
            st.prev_ts    = ts

            # -------------------------------------------------------------- #
            #  Emit the row
            #  Packet-level features + running context features.
            #  Identity (IP, MAC, port, absolute ts) stored in _identity_*
            #  so labeling.py can use them; they are dropped by
            #  preprocessing.build_matrix just like before.
            # -------------------------------------------------------------- #
            flow_dur_ms = (ts - st.first_seen_ts) * 1000.0

            row: dict[str, Any] = {
                # ----- identity (for labeling only, dropped before training) -----
                "_identity_src_ip":   ip.src,
                "_identity_dst_ip":   ip.dst,
                "_identity_src_mac":  src_mac,
                "_identity_dst_mac":  dst_mac,
                "_identity_src_port": sport,
                "_identity_dst_port": dport,
                # flow key index for Pass 2 join (dropped after join)
                "_flow_key":          str(key),

                # ----- packet-level features (no identity) --------------------
                # Protocol as one-hot boolean columns (proto_tcp, proto_udp, …)
                **_protocol_onehot(proto_num),
                "ip_ttl":             ip.ttl,
                "ip_len":             ip.len if ip.len else pkt_len,
                "pkt_len":            pkt_len,
                "tcp_window_size":    win_size,
                "direction":          direction,          # 1=fwd, 0=rev

                # TCP flags (individual bits)
                **tcp_flags,

                # ----- running context features (no identity) -----------------
                # packet index within flow (0-based)
                "flow_pkt_index":     st.pkt_count - 1,

                # inter-arrival time since previous packet in this flow (ms)
                "iat_from_prev_ms":     iat_ms,
                "fwd_iat_from_prev_ms": fwd_iat_ms,
                "rev_iat_from_prev_ms": rev_iat_ms,

                # running packet/byte totals in flow so far
                "flow_pkts_so_far":   st.pkt_count,
                "flow_bytes_so_far":  st.byte_count,
                "fwd_pkts_so_far":    st.fwd_pkt_count,
                "fwd_bytes_so_far":   st.fwd_byte_count,
                "rev_pkts_so_far":    st.rev_pkt_count,
                "rev_bytes_so_far":   st.rev_byte_count,

                # running packet-size statistics
                "run_mean_ps":        st.ps_wf.mean,
                "run_stddev_ps":      st.ps_wf.stddev,
                "run_min_ps":         st.ps_min,
                "run_max_ps":         st.ps_max,
                "run_fwd_mean_ps":    st.fwd_ps_wf.mean,
                "run_rev_mean_ps":    st.rev_ps_wf.mean,

                # running IAT statistics
                "run_mean_iat_ms":     st.iat_wf.mean,
                "run_stddev_iat_ms":   st.iat_wf.stddev,
                "run_fwd_mean_iat_ms": st.fwd_iat_wf.mean,
                "run_rev_mean_iat_ms": st.rev_iat_wf.mean,

                # running TCP flag tallies in flow so far
                "flow_syn_so_far":      st.syn_count,
                "flow_ack_so_far":      st.ack_count,
                "flow_rst_so_far":      st.rst_count,
                "flow_fin_so_far":      st.fin_count,
                "flow_psh_so_far":      st.psh_count,
                "flow_fwd_syn_so_far":  st.fwd_syn,
                "flow_rev_syn_so_far":  st.rev_syn,

                # running ratios (safe denominator via + eps)
                "run_syn_ratio":      st.syn_count      / (st.pkt_count + 1e-9),
                "run_rst_ratio":      st.rst_count      / (st.pkt_count + 1e-9),
                "run_fwd_ratio":      st.fwd_pkt_count  / (st.pkt_count + 1e-9),
                "run_bytes_per_pkt":  st.byte_count     / (st.pkt_count + 1e-9),

                # elapsed flow duration up to this packet (ms, relative delta)
                "flow_elapsed_ms":    flow_dur_ms,
            }
            rows.append(row)

    log.info("Pass 1 complete: %d packets across %d flows (%d non-IP skipped).",
             len(rows), len(flows), skipped)
    return rows, flows


# --------------------------------------------------------------------------- #
#  Pass 2: attach completed-flow summary statistics to every row
# --------------------------------------------------------------------------- #

def _pass2(rows: list[dict],
           flows: dict[tuple, _FlowState]) -> pd.DataFrame:
    """
    Build one summary-stats record per completed flow, then join it back onto
    every packet row in that flow.

    The summary mirrors the NFStream per-flow view (total packets/bytes,
    final mean/stddev packet size, total IAT mean/stddev, flag ratios, etc.)
    but is now stored *per packet* rather than per flow.

    No IP, MAC, port or timestamp enters the summary -- same identity rule.
    """
    log.info("Pass 2: computing completed-flow summaries for %d flows ...",
             len(flows))

    # Build summary dict keyed by str(flow_key) (same string stored in rows)
    summaries: dict[str, dict] = {}
    for key, st in flows.items():
        total_dur_ms = (st.last_seen_ts - st.first_seen_ts) * 1000.0
        n   = st.pkt_count
        eps = 1e-9

        summaries[str(key)] = {
            # total counts
            "flow_total_pkts":           n,
            "flow_total_bytes":          st.byte_count,
            "flow_fwd_total_pkts":       st.fwd_pkt_count,
            "flow_fwd_total_bytes":      st.fwd_byte_count,
            "flow_rev_total_pkts":       st.rev_pkt_count,
            "flow_rev_total_bytes":      st.rev_byte_count,

            # duration (relative, not absolute)
            "flow_duration_ms":          total_dur_ms,

            # final packet-size distribution
            "flow_mean_ps":              st.ps_wf.mean,
            "flow_stddev_ps":            st.ps_wf.stddev,
            "flow_min_ps":               st.ps_min,
            "flow_max_ps":               st.ps_max,
            "flow_fwd_mean_ps":          st.fwd_ps_wf.mean,
            "flow_rev_mean_ps":          st.rev_ps_wf.mean,

            # final IAT statistics
            "flow_mean_iat_ms":          st.iat_wf.mean,
            "flow_stddev_iat_ms":        st.iat_wf.stddev,
            "flow_fwd_mean_iat_ms":      st.fwd_iat_wf.mean,
            "flow_rev_mean_iat_ms":      st.rev_iat_wf.mean,

            # final TCP flag tallies
            "flow_total_syn":            st.syn_count,
            "flow_total_ack":            st.ack_count,
            "flow_total_rst":            st.rst_count,
            "flow_total_fin":            st.fin_count,
            "flow_total_psh":            st.psh_count,
            "flow_fwd_total_syn":        st.fwd_syn,
            "flow_rev_total_syn":        st.rev_syn,

            # final flow-level ratios
            "flow_syn_ratio":             st.syn_count      / (n + eps),
            "flow_ack_ratio":             st.ack_count      / (n + eps),
            "flow_rst_ratio":             st.rst_count      / (n + eps),
            "flow_fin_ratio":             st.fin_count      / (n + eps),
            "flow_bytes_per_pkt":         st.byte_count     / (n + eps),
            "flow_bytes_per_ms":          st.byte_count     / (total_dur_ms + eps),
            "flow_pkts_per_ms":           n                 / (total_dur_ms + eps),
            "flow_fwd_pkt_ratio":         st.fwd_pkt_count  / (n + eps),
            "flow_fwd_byte_ratio":        st.fwd_byte_count / (st.byte_count + eps),
            "flow_download_upload_ratio": st.rev_byte_count / (st.fwd_byte_count + eps),
            "flow_mean_ps_ratio":         st.fwd_ps_wf.mean / (st.rev_ps_wf.mean + eps),
        }

    # Join onto rows
    df         = pd.DataFrame(rows)
    summary_df = pd.DataFrame.from_dict(summaries, orient="index")
    summary_df.index.name = "_flow_key"
    summary_df = summary_df.reset_index()

    df = df.merge(summary_df, on="_flow_key", how="left")
    df.drop(columns=["_flow_key"], inplace=True)

    log.info("Pass 2 complete: output shape = %s", df.shape)
    return df


# --------------------------------------------------------------------------- #
#  Public API (mirrors feature_extraction.py)
# --------------------------------------------------------------------------- #

def extract_packets(pcap_path: str | Path) -> pd.DataFrame:
    """Run two-pass extraction over ``pcap_path`` and return a per-packet table.

    Output columns fall into three groups:
      * ``_identity_*`` -- IP/MAC/port (for labeling.py, dropped before training)
      * Packet-level features -- protocol one-hot, sizes, TCP flags, TTL,
                                 direction, …
      * Running flow context  -- rolling counts/stats up to this packet
      * Completed-flow summary -- final flow aggregates attached to every row
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    log.info("Packet extractor: opening %s (%.1f MB)",
             pcap_path, pcap_path.stat().st_size / 1e6)

    rows, flows = _pass1(pcap_path)
    df          = _pass2(rows, flows)

    # Rename identity columns to match what labeling.py expects
    # (src_ip, dst_ip, src_mac, dst_mac) so it requires zero changes.
    rename = {
        "_identity_src_ip":   "src_ip",
        "_identity_dst_ip":   "dst_ip",
        "_identity_src_mac":  "src_mac",
        "_identity_dst_mac":  "dst_mac",
        "_identity_src_port": "src_port",
        "_identity_dst_port": "dst_port",
    }
    df.rename(columns=rename, inplace=True)

    # Clean up
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0.0, inplace=True)

    log.info("Extraction done: %d packets, %d columns.", len(df), df.shape[1])
    return df


def load_or_extract(pcap_path: str | Path | None,
                    cache_csv: str | Path,
                    force: bool = False) -> pd.DataFrame:
    """Return the per-packet table, using a CSV cache when available.

    Drop-in replacement for ``feature_extraction.load_or_extract``:
      * If ``cache_csv`` exists and ``force`` is False -> load it (no Scapy).
      * Otherwise run the two-pass extractor on ``pcap_path`` and write cache.
    """
    cache_csv = Path(cache_csv)
    if cache_csv.exists() and not force:
        log.info("Loading cached packet table: %s", cache_csv)
        return pd.read_csv(cache_csv, low_memory=False)

    if pcap_path is None:
        raise SystemExit(
            f"No cached features at {cache_csv} and no --pcap given. "
            "Provide a pcap to extract from."
        )

    df = extract_packets(pcap_path)
    cache_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(cache_csv, index=False)
    log.info("Cached per-packet table -> %s  (%d rows)", cache_csv, len(df))
    return df