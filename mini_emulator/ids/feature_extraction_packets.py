"""
feature_extraction_packets.py
=============================
Per-packet feature extraction for an online IDS.

Online rule (CRITICAL)
----------------------
Every value in a row is computable from packets seen at or before that packet's
timestamp. There is NO second pass over completed flows: a real-time IDS
cannot see the future, so we don't pretend it can. The row layers are:

  1. Packet-level fields   -- size, protocol multi-hot, TCP flag bits, TTL,
                              window, direction (= first-packet direction).
  2. Running flow context  -- counts / running mean / running stddev / running
                              IAT statistics accumulated up to and including
                              this packet.

Identity columns (``_identity_*`` and ``_flow_key``) are kept in the CSV so
``labeling.py`` can derive ground-truth labels, but they are dropped by
``preprocessing.build_matrix`` before any model sees them.

Flow definition
---------------
Bidirectional, keyed by canonically-sorted endpoint pair:
  * IP packets  : (ip, port, ip, port, ip_proto)
  * ARP frames  : (mac, 0, mac, 0, 0x0806)

Flows expire after ``FLOW_IDLE_TIMEOUT_MS`` of no traffic; the next packet
starts a fresh instance with the same base key but an incremented instance id,
so GroupKFold can keep instances disjoint across CV folds.

Per-flow row cap (reservoir sampling)
-------------------------------------
Each flow instance keeps an unbiased reservoir of ``MAX_ROWS_PER_FLOW`` rows
via Vitter's Algorithm R. Once the reservoir is full, a newly arriving packet
replaces a random slot with probability ``k / n``. This keeps a single long
benign flow from drowning the training signal while still letting late-flow
attack stages (e.g. a SYN flood that escalates) get represented.

Streaming
---------
Rows are first buffered per-flow (because the reservoir is per-flow), then
flushed to CSV in chronological order. Memory is O(active flows * reservoir),
not O(packets).
"""

from __future__ import annotations

import csv
import logging
import math
import random
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

log = logging.getLogger("ids.pkt_features")

# --------------------------------------------------------------------------- #
#  Default tunables (overridable per-call via extractor parameters / CLI)
# --------------------------------------------------------------------------- #
FLOW_IDLE_TIMEOUT_MS = 120_000   # 120 s, matches NFStream's default.
MAX_ROWS_PER_FLOW    = 256       # reservoir size per flow instance.
ACTIVE_SWEEP_EVERY   = 100_000   # sweep stale flows every N processed packets.

# --------------------------------------------------------------------------- #
#  Protocol encoding (sparse multi-hot booleans)
#
#  IP-layer protocols are mutually exclusive (proto_tcp/udp/icmp/...).
#  proto_arp fires for L2-only ARP frames -- in that case no IP-proto flag is
#  set, since the packet has no IP layer at all.
#  proto_bgp is an L7 marker that rides *alongside* proto_tcp (BGP runs over
#  TCP/179), so the encoding is multi-hot.
# --------------------------------------------------------------------------- #
_BGP_PORT = 179

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
# Sentinel for ARP in the internal flow key (never written to CSV).
_ARP_PROTO_SENTINEL = 0x0806

_PROTO_COLUMNS: list[str] = sorted(_KNOWN_PROTOS.values()) + [
    "proto_other", "proto_arp", "proto_bgp",
]


def _protocol_flags(proto_num: int | None,
                    is_arp: bool = False,
                    is_bgp: bool = False) -> dict[str, int]:
    row: dict[str, int] = {col: 0 for col in _PROTO_COLUMNS}
    if is_arp:
        row["proto_arp"] = 1
        return row
    if proto_num is not None:
        row[_KNOWN_PROTOS.get(proto_num, "proto_other")] = 1
    if is_bgp:
        row["proto_bgp"] = 1
    return row


# --------------------------------------------------------------------------- #
#  Welford online mean / SAMPLE variance (n-1 denominator)
# --------------------------------------------------------------------------- #
class _Welford:
    __slots__ = ("n", "mean", "M2")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.M2 += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        return self.M2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)


# --------------------------------------------------------------------------- #
#  Flow state (never serialised verbatim)
# --------------------------------------------------------------------------- #
class _FlowState:
    """Per-flow tracking. 'Forward' = the direction of the first observed packet."""

    __slots__ = (
        # initiator endpoints, used to define forward direction (internal only)
        "init_src_ip", "init_src_port", "init_src_mac",
        # timing
        "first_seen_ts", "last_seen_ts",
        "fwd_prev_ts", "rev_prev_ts",
        # counts
        "pkt_count", "fwd_pkt_count", "rev_pkt_count",
        "byte_count", "fwd_byte_count", "rev_byte_count",
        # TCP flag tallies
        "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
        "fwd_syn", "rev_syn",
        # running stats
        "ps_wf", "fwd_ps_wf", "rev_ps_wf",
        "iat_wf", "fwd_iat_wf", "rev_iat_wf",
        "ps_min", "ps_max",
        # how many packets have arrived since this instance started (vs.
        # rows_kept which counts what's currently in the reservoir).
        "packets_seen",
        # per-flow reservoir buffer of finalised row dicts (Vitter Algorithm R)
        "reservoir",
    )

    def __init__(self, init_src_ip: str, init_src_port: int,
                 init_src_mac: str, ts: float) -> None:
        self.init_src_ip = init_src_ip
        self.init_src_port = init_src_port
        self.init_src_mac = init_src_mac
        self.first_seen_ts = ts
        self.last_seen_ts = ts
        self.fwd_prev_ts: float | None = None
        self.rev_prev_ts: float | None = None
        self.pkt_count = 0
        self.fwd_pkt_count = 0
        self.rev_pkt_count = 0
        self.byte_count = 0
        self.fwd_byte_count = 0
        self.rev_byte_count = 0
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.fwd_syn = 0
        self.rev_syn = 0
        self.ps_wf = _Welford()
        self.fwd_ps_wf = _Welford()
        self.rev_ps_wf = _Welford()
        self.iat_wf = _Welford()
        self.fwd_iat_wf = _Welford()
        self.rev_iat_wf = _Welford()
        # ps_min seeded with +inf; coerced to pkt_len in the row dict if no
        # update has happened yet.
        self.ps_min = math.inf
        self.ps_max = 0.0
        self.packets_seen = 0
        self.reservoir: list[dict[str, Any]] = []


# --------------------------------------------------------------------------- #
#  Per-packet helpers
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


def _base_flow_key(pkt) -> tuple | None:
    """Canonically-sorted base key for this packet, or None if unsupported."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether

    if pkt.haslayer(ARP):
        # Prefer the L3 endpoints in the ARP payload (psrc/pdst) as the key
        # base -- they're stable even on captures that lack an Ether header
        # (cooked-mode pcap), and they're what labelling cares about.
        arp = pkt[ARP]
        ipa = arp.psrc or ""
        ipb = arp.pdst or ""
        if ipa or ipb:
            a, b = (ipa, ipb) if ipa <= ipb else (ipb, ipa)
            return (a, 0, b, 0, _ARP_PROTO_SENTINEL)
        # Fallback: use MACs when ARP has no IPs (extremely rare).
        smac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else ""
        dmac = pkt[Ether].dst.lower() if pkt.haslayer(Ether) else ""
        a, b = (smac, dmac) if smac <= dmac else (dmac, smac)
        return (a, 0, b, 0, _ARP_PROTO_SENTINEL)

    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]

    if pkt.haslayer(TCP):
        src = (ip.src, pkt[TCP].sport)
        dst = (ip.dst, pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        src = (ip.src, pkt[UDP].sport)
        dst = (ip.dst, pkt[UDP].dport)
    else:
        src = (ip.src, 0)
        dst = (ip.dst, 0)

    if src <= dst:
        return (src[0], src[1], dst[0], dst[1], ip.proto)
    return (dst[0], dst[1], src[0], src[1], ip.proto)


def _packet_endpoints(pkt):
    """Return all per-packet fields needed to build a row."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether

    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ""
    pkt_len = len(pkt)

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        # ARP op: 1 = request, 2 = reply. Used by labelling to spot gratuitous
        # replies and binding conflicts.
        op = int(arp.op) if arp.op is not None else 0
        return dict(
            src_ip=arp.psrc or "", dst_ip=arp.pdst or "",
            sport=0, dport=0,
            src_mac=src_mac, dst_mac=dst_mac,
            win_size=0, ip_ttl=0, ip_len_val=pkt_len,
            proto_num=None, is_arp=True, is_bgp=False,
            arp_op=op,
        )

    ip = pkt[IP]
    ip_len_val = ip.len if ip.len else pkt_len

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        is_bgp = (tcp.sport == _BGP_PORT or tcp.dport == _BGP_PORT)
        return dict(
            src_ip=ip.src, dst_ip=ip.dst,
            sport=tcp.sport, dport=tcp.dport,
            src_mac=src_mac, dst_mac=dst_mac,
            win_size=tcp.window, ip_ttl=ip.ttl, ip_len_val=ip_len_val,
            proto_num=6, is_arp=False, is_bgp=is_bgp,
            arp_op=0,
        )
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        return dict(
            src_ip=ip.src, dst_ip=ip.dst,
            sport=udp.sport, dport=udp.dport,
            src_mac=src_mac, dst_mac=dst_mac,
            win_size=0, ip_ttl=ip.ttl, ip_len_val=ip_len_val,
            proto_num=17, is_arp=False, is_bgp=False,
            arp_op=0,
        )
    return dict(
        src_ip=ip.src, dst_ip=ip.dst, sport=0, dport=0,
        src_mac=src_mac, dst_mac=dst_mac,
        win_size=0, ip_ttl=ip.ttl, ip_len_val=ip_len_val,
        proto_num=ip.proto, is_arp=False, is_bgp=False,
        arp_op=0,
    )


# --------------------------------------------------------------------------- #
#  Extractor (single pass, streaming, per-flow reservoir)
# --------------------------------------------------------------------------- #
def _extract_rows(pcap_path: Path,
                  idle_timeout_ms: int,
                  max_rows_per_flow: int,
                  rng_seed: int = 0) -> Iterator[dict[str, Any]]:
    """Yield per-packet row dicts. Online: no future leakage."""
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise SystemExit(
            "scapy is not installed.  Run `pip install scapy`."
        ) from exc

    log.info("Streaming %s (idle_timeout=%d ms, reservoir=%d/flow)...",
             pcap_path, idle_timeout_ms, max_rows_per_flow)

    rng = random.Random(rng_seed)
    active: dict[tuple, _FlowState] = {}
    instance_id: dict[tuple, int] = defaultdict(int)
    # When a flow expires it's moved out of `active` into `expired` and its
    # reservoir is flushed in chronological order at the end. Storing the
    # first_seen_ts alongside lets us preserve global ordering.
    expired: list[tuple[float, list[dict[str, Any]]]] = []

    skipped = 0
    processed_since_sweep = 0
    timeout_s = idle_timeout_ms / 1000.0

    def _retire(base_key: tuple) -> None:
        st = active.pop(base_key, None)
        if st is not None and st.reservoir:
            expired.append((st.first_seen_ts, st.reservoir))

    def _sweep_stale(now_ts: float) -> int:
        """Move flows idle for > 2*timeout into the expired bucket. Returns count."""
        cutoff = now_ts - 2 * timeout_s
        stale = [k for k, st in active.items() if st.last_seen_ts < cutoff]
        for k in stale:
            _retire(k)
        return len(stale)

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            base_key = _base_flow_key(pkt)
            if base_key is None:
                skipped += 1
                continue

            ep = _packet_endpoints(pkt)
            ts = float(pkt.time)
            pkt_len = len(pkt)
            tcp_flags = _extract_tcp_flags(pkt)

            # --- Flow expiry / instantiation ----------------------------- #
            st = active.get(base_key)
            # Clock-skew guard: ignore negative deltas (out-of-order packets
            # in merged pcaps) -- they neither trigger expiry nor advance
            # the iat baseline.
            idle_delta = (ts - st.last_seen_ts) if st is not None else 0.0
            if st is None or idle_delta > timeout_s:
                if st is not None:
                    # Same conversation but past timeout: retire the previous
                    # instance's reservoir, increment instance id.
                    _retire(base_key)
                    instance_id[base_key] += 1
                init_mac = ep["src_mac"].lower() if ep["is_arp"] else ""
                st = _FlowState(
                    init_src_ip=ep["src_ip"],
                    init_src_port=ep["sport"],
                    init_src_mac=init_mac,
                    ts=ts,
                )
                active[base_key] = st
            elif idle_delta < 0:
                # Out-of-order in time; pretend it arrived now and continue.
                idle_delta = 0.0

            # --- Direction --------------------------------------------- #
            if ep["is_arp"]:
                src_mac_norm = ep["src_mac"].lower()
                if st.init_src_mac:
                    direction = int(src_mac_norm == st.init_src_mac)
                else:
                    # Cooked-mode pcap: fall back to L3 ARP addresses.
                    direction = int(ep["src_ip"] == st.init_src_ip)
            else:
                direction = int(ep["src_ip"] == st.init_src_ip
                                and ep["sport"] == st.init_src_port)

            # --- Inter-arrival times ----------------------------------- #
            iat_ms = idle_delta * 1000.0 if st.pkt_count > 0 else 0.0
            if direction == 1:
                fwd_iat_ms = (
                    max(0.0, (ts - st.fwd_prev_ts) * 1000.0)
                    if st.fwd_prev_ts is not None else 0.0
                )
                rev_iat_ms = 0.0
            else:
                fwd_iat_ms = 0.0
                rev_iat_ms = (
                    max(0.0, (ts - st.rev_prev_ts) * 1000.0)
                    if st.rev_prev_ts is not None else 0.0
                )

            # --- Update flow state BEFORE building the row -------------- #
            st.pkt_count += 1
            st.byte_count += pkt_len
            st.ps_wf.update(pkt_len)
            st.ps_min = min(st.ps_min, pkt_len)
            st.ps_max = max(st.ps_max, pkt_len)
            if st.pkt_count > 1:
                st.iat_wf.update(iat_ms)

            if direction == 1:
                st.fwd_pkt_count += 1
                st.fwd_byte_count += pkt_len
                st.fwd_ps_wf.update(pkt_len)
                if st.fwd_pkt_count > 1:
                    st.fwd_iat_wf.update(fwd_iat_ms)
                st.fwd_syn += tcp_flags["tcp_syn"]
                st.fwd_prev_ts = ts
            else:
                st.rev_pkt_count += 1
                st.rev_byte_count += pkt_len
                st.rev_ps_wf.update(pkt_len)
                if st.rev_pkt_count > 1:
                    st.rev_iat_wf.update(rev_iat_ms)
                st.rev_syn += tcp_flags["tcp_syn"]
                st.rev_prev_ts = ts

            st.syn_count += tcp_flags["tcp_syn"]
            st.ack_count += tcp_flags["tcp_ack"]
            st.rst_count += tcp_flags["tcp_rst"]
            st.fin_count += tcp_flags["tcp_fin"]
            st.psh_count += tcp_flags["tcp_psh"]
            st.last_seen_ts = ts
            st.packets_seen += 1

            flow_elapsed_ms = (ts - st.first_seen_ts) * 1000.0
            flow_key_str = (
                "|".join(str(x) for x in base_key)
                + f"#{instance_id[base_key]}"
            )

            row = {
                # ----- identity (for labelling; dropped before training) ---- #
                "_identity_ts":       ts,
                "_identity_src_ip":   ep["src_ip"],
                "_identity_dst_ip":   ep["dst_ip"],
                "_identity_src_mac":  ep["src_mac"],
                "_identity_dst_mac":  ep["dst_mac"],
                "_identity_src_port": ep["sport"],
                "_identity_dst_port": ep["dport"],
                "_identity_arp_op":   ep["arp_op"],
                "_flow_key":          flow_key_str,

                # ----- packet-level features ----- #
                **_protocol_flags(ep["proto_num"], is_arp=ep["is_arp"],
                                   is_bgp=ep["is_bgp"]),
                "ip_ttl":             ep["ip_ttl"],
                "ip_len":             ep["ip_len_val"],
                "pkt_len":            pkt_len,
                "tcp_window_size":    ep["win_size"],
                "direction":          direction,
                **tcp_flags,

                # ----- running context (past only) ----- #
                # 0-based packet index within this flow instance.
                "flow_pkt_index":      st.pkt_count - 1,
                "iat_from_prev_ms":     iat_ms,
                "fwd_iat_from_prev_ms": fwd_iat_ms,
                "rev_iat_from_prev_ms": rev_iat_ms,
                # Note: flow_pkts_so_far would be flow_pkt_index + 1 -- omitted
                # as redundant. fwd_pkts + rev_pkts == flow_pkts so we keep
                # only the forward side (and the asymmetry feature derives
                # the rest).
                "fwd_pkts_so_far":      st.fwd_pkt_count,
                "fwd_bytes_so_far":     st.fwd_byte_count,
                "rev_pkts_so_far":      st.rev_pkt_count,
                "rev_bytes_so_far":     st.rev_byte_count,
                "flow_bytes_so_far":    st.byte_count,
                "run_mean_ps":          st.ps_wf.mean,
                "run_stddev_ps":        st.ps_wf.stddev,
                "run_min_ps":           (st.ps_min if math.isfinite(st.ps_min)
                                          else float(pkt_len)),
                "run_max_ps":           st.ps_max,
                "run_fwd_mean_ps":      st.fwd_ps_wf.mean,
                "run_rev_mean_ps":      st.rev_ps_wf.mean,
                "run_mean_iat_ms":      st.iat_wf.mean,
                "run_stddev_iat_ms":    st.iat_wf.stddev,
                "run_fwd_mean_iat_ms":  st.fwd_iat_wf.mean,
                "run_rev_mean_iat_ms":  st.rev_iat_wf.mean,
                "flow_syn_so_far":      st.syn_count,
                "flow_ack_so_far":      st.ack_count,
                "flow_rst_so_far":      st.rst_count,
                "flow_fin_so_far":      st.fin_count,
                "flow_psh_so_far":      st.psh_count,
                "flow_fwd_syn_so_far":  st.fwd_syn,
                "flow_rev_syn_so_far":  st.rev_syn,
                "run_syn_ratio":        st.syn_count     / st.pkt_count,
                "run_rst_ratio":        st.rst_count     / st.pkt_count,
                "run_fwd_ratio":        st.fwd_pkt_count / st.pkt_count,
                "run_bytes_per_pkt":    st.byte_count    / st.pkt_count,
                "flow_elapsed_ms":      flow_elapsed_ms,
            }

            # --- Reservoir sampling (Vitter Algorithm R) ----------------- #
            # Until the reservoir is full, append; afterwards, replace a
            # random slot with probability k/n (n = total packets seen,
            # k = reservoir size). This is unbiased over the whole flow.
            if len(st.reservoir) < max_rows_per_flow:
                st.reservoir.append(row)
            else:
                j = rng.randint(0, st.packets_seen - 1)
                if j < max_rows_per_flow:
                    st.reservoir[j] = row

            # Periodic sweep of stale active flows so memory stays bounded
            # in long captures full of short-lived conversations.
            processed_since_sweep += 1
            if processed_since_sweep >= ACTIVE_SWEEP_EVERY:
                processed_since_sweep = 0
                n_swept = _sweep_stale(ts)
                if n_swept:
                    log.debug("Swept %d stale flows (active=%d).",
                              n_swept, len(active))

    # Flush any still-active flows at EOF.
    for base_key in list(active.keys()):
        _retire(base_key)

    log.info("Done: %d flow instances buffered (%d non-IP/ARP skipped). "
             "Sorting and emitting...",
             len(expired), skipped)

    # Each flow's reservoir is in arrival order but reservoirs across flows
    # are interleaved; flush by sorting per row's _identity_ts so the CSV
    # remains chronological. Memory is O(rows kept), bounded by reservoirs.
    all_rows: list[dict[str, Any]] = []
    for _, reservoir in expired:
        all_rows.extend(reservoir)
    all_rows.sort(key=lambda r: r["_identity_ts"])
    for r in all_rows:
        yield r


# --------------------------------------------------------------------------- #
#  Schema fallback for the empty-pcap edge case
# --------------------------------------------------------------------------- #
_FALLBACK_FIELDS: list[str] = (
    [
        "_identity_ts", "_identity_src_ip", "_identity_dst_ip",
        "_identity_src_mac", "_identity_dst_mac",
        "_identity_src_port", "_identity_dst_port",
        "_identity_arp_op", "_flow_key",
    ]
    + _PROTO_COLUMNS
    + [
        "ip_ttl", "ip_len", "pkt_len", "tcp_window_size", "direction",
        "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin",
        "tcp_psh", "tcp_urg", "tcp_ece", "tcp_cwr",
        "flow_pkt_index",
        "iat_from_prev_ms", "fwd_iat_from_prev_ms", "rev_iat_from_prev_ms",
        "fwd_pkts_so_far", "fwd_bytes_so_far",
        "rev_pkts_so_far", "rev_bytes_so_far",
        "flow_bytes_so_far",
        "run_mean_ps", "run_stddev_ps", "run_min_ps", "run_max_ps",
        "run_fwd_mean_ps", "run_rev_mean_ps",
        "run_mean_iat_ms", "run_stddev_iat_ms",
        "run_fwd_mean_iat_ms", "run_rev_mean_iat_ms",
        "flow_syn_so_far", "flow_ack_so_far", "flow_rst_so_far",
        "flow_fin_so_far", "flow_psh_so_far",
        "flow_fwd_syn_so_far", "flow_rev_syn_so_far",
        "run_syn_ratio", "run_rst_ratio", "run_fwd_ratio", "run_bytes_per_pkt",
        "flow_elapsed_ms",
    ]
)


def _stream_to_csv(pcap_path: Path, csv_path: Path,
                   idle_timeout_ms: int, max_rows_per_flow: int,
                   rng_seed: int = 0) -> int:
    """Single-pass extraction directly to CSV. Returns the row count.

    If the pcap yields zero usable rows, the CSV is still written with a
    header so downstream ``pd.read_csv`` doesn't crash on an empty file.
    """
    writer: csv.DictWriter | None = None
    n = 0
    with open(csv_path, "w", newline="") as f:
        for row in _extract_rows(pcap_path,
                                 idle_timeout_ms=idle_timeout_ms,
                                 max_rows_per_flow=max_rows_per_flow,
                                 rng_seed=rng_seed):
            if writer is None:
                writer = csv.DictWriter(f, fieldnames=list(row.keys()))
                writer.writeheader()
            writer.writerow(row)
            n += 1
        if writer is None:
            log.warning("No rows extracted (pcap has no IP/ARP traffic). "
                        "Writing header-only CSV.")
            csv.DictWriter(f, fieldnames=_FALLBACK_FIELDS).writeheader()
    return n


_RENAME_IDENTITY: dict[str, str] = {
    "_identity_ts":       "ts",
    "_identity_src_ip":   "src_ip",
    "_identity_dst_ip":   "dst_ip",
    "_identity_src_mac":  "src_mac",
    "_identity_dst_mac":  "dst_mac",
    "_identity_src_port": "src_port",
    "_identity_dst_port": "dst_port",
    "_identity_arp_op":   "arp_op",
}


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #
def extract_packets(pcap_path: str | Path,
                    idle_timeout_ms: int = FLOW_IDLE_TIMEOUT_MS,
                    max_rows_per_flow: int = MAX_ROWS_PER_FLOW,
                    rng_seed: int = 0) -> pd.DataFrame:
    """Stream the pcap to a temp CSV, then load and return the DataFrame."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _stream_to_csv(pcap_path, tmp_path,
                       idle_timeout_ms=idle_timeout_ms,
                       max_rows_per_flow=max_rows_per_flow,
                       rng_seed=rng_seed)
        df = pd.read_csv(tmp_path, low_memory=False)
    finally:
        tmp_path.unlink(missing_ok=True)

    df.rename(columns=_RENAME_IDENTITY, inplace=True)
    log.info("Extraction done: %d packets, %d columns.", len(df), df.shape[1])
    return df


def load_or_extract(pcap_path: str | Path | None,
                    cache_csv: str | Path,
                    force: bool = False,
                    idle_timeout_ms: int = FLOW_IDLE_TIMEOUT_MS,
                    max_rows_per_flow: int = MAX_ROWS_PER_FLOW,
                    rng_seed: int = 0) -> pd.DataFrame:
    """Return the per-packet table, streaming to ``cache_csv`` when needed."""
    cache_csv = Path(cache_csv)
    if cache_csv.exists() and not force:
        log.info("Loading cached packet table: %s", cache_csv)
        return pd.read_csv(cache_csv, low_memory=False)

    if pcap_path is None:
        raise SystemExit(
            f"No cached features at {cache_csv} and no --pcap given. "
            "Provide a pcap to extract from."
        )

    pcap_path = Path(pcap_path)
    cache_csv.parent.mkdir(parents=True, exist_ok=True)
    _stream_to_csv(pcap_path, cache_csv,
                   idle_timeout_ms=idle_timeout_ms,
                   max_rows_per_flow=max_rows_per_flow,
                   rng_seed=rng_seed)
    df = pd.read_csv(cache_csv, low_memory=False)
    df.rename(columns=_RENAME_IDENTITY, inplace=True)
    df.to_csv(cache_csv, index=False)
    log.info("Cached per-packet table -> %s  (%d rows)", cache_csv, len(df))
    return df
