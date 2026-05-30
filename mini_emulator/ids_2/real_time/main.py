"""
realtime_features.py
====================
Real-time, per-packet feature extraction that produces EXACTLY the same
features as feature_extraction.extract_features(), minus the label column.

Usage
-----
    sudo python realtime_features.py <interface> <model.joblib> [<scaler.joblib>]

    <model.joblib>   – any model saved by classify.py or outlier.py
    <scaler.joblib>  – optional; required for lr / svm / knn / ocsvm / lof models

Only packets classified as malicious (label=1) are printed.

Design notes
------------
* State that feature_extraction.py accumulates across the whole PCAP
  (prev_seq/ack, per-flow rolling windows) is maintained here in module-level
  dicts that grow as packets arrive.
* One-hot encoding is reproduced by writing the same boolean columns that
  pd.get_dummies would produce.  The full universe of categories is known
  statically (_ALL_PROTOS, _ALL_SERVICES), so no surprises at inference time.
* Rolling temporal features are causal: only past packets in the same flow
  within the look-back window are used — identical to _add_temporal_features.
* `timestamp` and `_flow_key` are dropped before printing, same as in
  extract_features().
* The ICMP sentinel-flow limitation from the original code is preserved:
  all ICMP packets share one flow key regardless of host.
"""

from __future__ import annotations

import sys
import warnings
from collections import defaultdict, deque
from typing import Deque

import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WINDOW_SECONDS: float = 1.0   # rolling look-back window (matches default)

# ---------------------------------------------------------------------------
# Lookup tables — identical to feature_extraction.py
# ---------------------------------------------------------------------------

_PROTO_MAP: dict[int, str] = {
    1:  "ICMP",   2:  "IGMP",  6:   "TCP",   17: "UDP",
    41: "IPv6",   47: "GRE",   50:  "ESP",    51: "AH",
    58: "ICMPv6", 89: "OSPF",  132: "SCTP",
}

_PORT_SERVICES: dict[int, str] = {
    20: "ftp_data",  21: "ftp",        22: "ssh",       23: "telnet",
    25: "smtp",      53: "dns",        67: "dhcp",       68: "dhcp",
    80: "http",     110: "pop3",      123: "ntp",       143: "imap",
    161: "snmp",    162: "snmp_trap", 179: "bgp",       443: "https",
    445: "smb",     514: "syslog",    993: "imaps",     995: "pop3s",
    3306: "mysql",  3389: "rdp",     5432: "postgres",
    5900: "vnc",   6379: "redis",    8080: "http_alt", 8443: "https_alt",
}

# Complete, static category universes — mirrors every value pd.get_dummies
# would ever produce from _PROTO_MAP values + _port_bucket() outputs.
_ALL_PROTOS: list[str] = sorted({
    "ICMP", "IGMP", "TCP", "UDP", "IPv6", "GRE", "ESP", "AH",
    "ICMPv6", "OSPF", "SCTP",
    # catch-all for unknown proto numbers, e.g. "proto_253"
    # — these will simply never be 1 unless that proto appears
})

_ALL_SERVICES: list[str] = sorted({
    "ftp_data", "ftp", "ssh", "telnet", "smtp", "dns", "dhcp",
    "http", "pop3", "ntp", "imap", "snmp", "snmp_trap", "bgp",
    "https", "smb", "syslog", "imaps", "pop3s", "mysql", "rdp",
    "postgres", "vnc", "redis", "http_alt", "https_alt",
    "other_well_known", "registered", "ephemeral", "unknown",
})

# ---------------------------------------------------------------------------
# Per-flow state (mirrors the dicts in _extract_rows and _add_temporal_features)
# ---------------------------------------------------------------------------

# TCP delta tracking
_prev_seq: dict = defaultdict(lambda: None)
_prev_ack: dict = defaultdict(lambda: None)

# Per-flow window: deque of (timestamp, ip_len, syn, rst, dport_service)
_flow_window: dict[tuple, Deque[tuple]] = defaultdict(deque)

# Last packet timestamp per flow (for inter-arrival time)
_flow_last_ts: dict[tuple, float] = {}

# ---------------------------------------------------------------------------
# Model / scaler — loaded once at startup, used in every process_packet call
# ---------------------------------------------------------------------------

_MODEL  = None   # sklearn estimator with predict()
_SCALER = None   # StandardScaler or None

# Column order expected by the model (matches extract_features output minus
# "label"), built lazily from the first assembled row so it is always in sync.
_FEATURE_COLUMNS: list[str] | None = None


def _load_model(model_path: str, scaler_path: str | None) -> None:
    global _MODEL, _SCALER
    _MODEL = joblib.load(model_path)
    if scaler_path is not None:
        _SCALER = joblib.load(scaler_path)
    print(f"[*] Model loaded from  {model_path!r}", flush=True)
    if _SCALER is not None:
        print(f"[*] Scaler loaded from {scaler_path!r}", flush=True)


def _predict(row: dict) -> int:
    """
    Return 1 (malicious) or 0 (normal) for a fully-assembled feature row.

    sklearn outlier detectors (IsolationForest, OneClassSVM, LOF,
    EllipticEnvelope) use predict() returning +1 / -1; we map -1 → 1.
    Supervised classifiers return 0 / 1 directly.
    """
    global _FEATURE_COLUMNS

    # Fix column order on first call
    if _FEATURE_COLUMNS is None:
        _FEATURE_COLUMNS = list(row.keys())

    X = np.array([[row[c] for c in _FEATURE_COLUMNS]], dtype=np.float32)

    if _SCALER is not None:
        X = _SCALER.transform(X)

    raw = _MODEL.predict(X)[0]

    # Outlier detectors: +1 = inlier (normal), -1 = outlier (malicious)
    if raw == -1:
        return 1
    return int(raw)

# ---------------------------------------------------------------------------
# Helpers — exact copies from feature_extraction.py
# ---------------------------------------------------------------------------

def _port_bucket(port: int | None) -> str:
    if port is None:
        return "unknown"
    if port in _PORT_SERVICES:
        return _PORT_SERVICES[port]
    if port < 1024:
        return "other_well_known"
    if port < 49152:
        return "registered"
    return "ephemeral"


def _one_hot_proto(proto: str) -> dict[str, int]:
    """Reproduce pd.get_dummies for the 'proto' column."""
    return {f"proto_{p}": int(p == proto) for p in _ALL_PROTOS}


def _one_hot_service(prefix: str, service: str) -> dict[str, int]:
    """Reproduce pd.get_dummies for sport_service / dport_service columns."""
    return {f"{prefix}_{s}": int(s == service) for s in _ALL_SERVICES}

# ---------------------------------------------------------------------------
# Main per-packet callback
# ---------------------------------------------------------------------------

def process_packet(pkt) -> None:
    """
    Extract features from a single live packet and print the resulting row.
    Replicates _extract_rows → _encode_and_clean → _add_temporal_features
    in a single, stateful pass.
    """

    # ------------------------------------------------------------------
    # 1. IP layer  (mirrors _extract_rows IP section)
    # ------------------------------------------------------------------
    row: dict = {"timestamp": float(pkt.time)}

    if pkt.haslayer(IP):
        ip = pkt[IP]
        row.update(ip_version=4, ttl=ip.ttl, ip_len=ip.len,
                   ip_flags_df=int(bool(ip.flags & 0x2)),
                   ip_flags_mf=int(bool(ip.flags & 0x1)),
                   ip_frag_offset=ip.frag)
        proto_num = ip.proto
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        row.update(ip_version=6, ttl=ip6.hlim,
                   ip_len=ip6.plen + 40,
                   ip_flags_df=0, ip_flags_mf=0, ip_frag_offset=0)
        proto_num = ip6.nh
    else:
        row.update(ip_version=0, ttl=0, ip_len=len(pkt),
                   ip_flags_df=0, ip_flags_mf=0, ip_frag_offset=0)
        proto_num = 0

    proto_str = _PROTO_MAP.get(proto_num, f"proto_{proto_num}")

    # ------------------------------------------------------------------
    # 2. Transport layer  (mirrors _extract_rows transport section)
    #    NaN defaults → filled to 0 by _encode_and_clean; we write 0 directly.
    # ------------------------------------------------------------------
    tcp_seq_delta = tcp_ack_delta = tcp_window = tcp_data_offset = 0
    udp_length    = 0
    icmp_type     = icmp_code = 0
    payload_len   = 0
    flag_fin = flag_syn = flag_rst = flag_psh = 0
    flag_ack = flag_urg = flag_ece = flag_cwr = 0
    sport = dport = None

    if pkt.haslayer(TCP):
        tcp          = pkt[TCP]
        sport, dport = tcp.sport, tcp.dport
        fkey         = (min(sport, dport), max(sport, dport), proto_str)

        ps = _prev_seq[fkey] if _prev_seq[fkey] is not None else tcp.seq
        pa = _prev_ack[fkey] if _prev_ack[fkey] is not None else tcp.ack
        tcp_seq_delta = int(tcp.seq - ps) & 0xFFFF_FFFF
        tcp_ack_delta = int(tcp.ack - pa) & 0xFFFF_FFFF
        _prev_seq[fkey], _prev_ack[fkey] = tcp.seq, tcp.ack

        tcp_window      = tcp.window
        tcp_data_offset = tcp.dataofs
        payload_len     = len(bytes(tcp.payload))

        f = tcp.flags
        flag_fin = int(bool(f & 0x01))
        flag_syn = int(bool(f & 0x02))
        flag_rst = int(bool(f & 0x04))
        flag_psh = int(bool(f & 0x08))
        flag_ack = int(bool(f & 0x10))
        flag_urg = int(bool(f & 0x20))
        flag_ece = int(bool(f & 0x40))
        flag_cwr = int(bool(f & 0x80))

    elif pkt.haslayer(UDP):
        udp          = pkt[UDP]
        sport, dport = udp.sport, udp.dport
        fkey         = (min(sport, dport), max(sport, dport), proto_str)
        udp_length   = udp.len
        payload_len  = len(bytes(udp.payload))

    elif pkt.haslayer(ICMP):
        icmp       = pkt[ICMP]
        fkey       = (None, None, proto_str)   # sentinel: all ICMP grouped
        icmp_type  = icmp.type
        icmp_code  = icmp.code
        payload_len = len(bytes(icmp.payload))

    else:
        fkey        = (None, None, "unknown")
        payload_len = len(pkt)

    sport_service = _port_bucket(sport)
    dport_service = _port_bucket(dport)

    # ------------------------------------------------------------------
    # 3. Temporal features  (mirrors _add_temporal_features, per-flow)
    # ------------------------------------------------------------------
    ts   = float(pkt.time)
    wdq  = _flow_window[fkey]

    # Evict packets outside the look-back window
    while wdq and (ts - wdq[0][0]) > WINDOW_SECONDS:
        wdq.popleft()

    # inter-arrival time
    inter_arrival_time = ts - _flow_last_ts[fkey] if fkey in _flow_last_ts else 0.0
    _flow_last_ts[fkey] = ts

    # Append current packet AFTER computing inter-arrival but BEFORE rates
    # (matches the original: window = indices[left : j+1], inclusive of current)
    wdq.append((ts, row["ip_len"], flag_syn, flag_rst, dport_service))

    win_len = len(wdq)
    elapsed = ts - wdq[0][0] if win_len > 1 else WINDOW_SECONDS

    rolling_pkt_rate      = win_len / elapsed
    rolling_byte_rate     = sum(e[1] for e in wdq) / elapsed
    rolling_unique_dports = len({e[4] for e in wdq})
    rolling_syn_rate      = sum(e[2] for e in wdq) / elapsed
    rolling_rst_rate      = sum(e[3] for e in wdq) / elapsed

    # ------------------------------------------------------------------
    # 4. Assemble final row — same column order as extract_features output
    #    (timestamp and _flow_key are dropped in the original before return)
    # ------------------------------------------------------------------
    row.update(
        ip_version      = row["ip_version"],
        ttl             = row["ttl"],
        ip_len          = row["ip_len"],
        ip_flags_df     = row["ip_flags_df"],
        ip_flags_mf     = row["ip_flags_mf"],
        ip_frag_offset  = row["ip_frag_offset"],
        tcp_seq_delta   = tcp_seq_delta,
        tcp_ack_delta   = tcp_ack_delta,
        tcp_window      = tcp_window,
        tcp_data_offset = tcp_data_offset,
        udp_length      = udp_length,
        icmp_type       = icmp_type,
        icmp_code       = icmp_code,
        payload_len     = payload_len,
        flag_fin        = flag_fin,
        flag_syn        = flag_syn,
        flag_rst        = flag_rst,
        flag_psh        = flag_psh,
        flag_ack        = flag_ack,
        flag_urg        = flag_urg,
        flag_ece        = flag_ece,
        flag_cwr        = flag_cwr,
        inter_arrival_time    = inter_arrival_time,
        rolling_pkt_rate      = rolling_pkt_rate,
        rolling_byte_rate     = rolling_byte_rate,
        rolling_unique_dports = rolling_unique_dports,
        rolling_syn_rate      = rolling_syn_rate,
        rolling_rst_rate      = rolling_rst_rate,
    )

    # One-hot encode proto + service buckets (same as pd.get_dummies)
    row.update(_one_hot_proto(proto_str))
    row.update(_one_hot_service("sport_service", sport_service))
    row.update(_one_hot_service("dport_service", dport_service))

    # Drop timestamp (same as extract_features final drop)
    row.pop("timestamp")

    # ------------------------------------------------------------------
    # 5. Classify — only print if the model says malicious
    # ------------------------------------------------------------------
    if _predict(row) == 1:
        print(pd.Series(row).to_string())
        print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print(
            f"Usage: sudo python {sys.argv[0]} <interface> <model.joblib> [<scaler.joblib>]",
            file=sys.stderr,
        )
        sys.exit(1)

    iface       = sys.argv[1]
    model_path  = sys.argv[2]
    scaler_path = sys.argv[3] if len(sys.argv) == 4 else None

    _load_model(model_path, scaler_path)

    print(f"[*] Sniffing on {iface!r}  —  printing malicious packets only  (Ctrl-C to stop)\n",
          flush=True)
    sniff(iface=iface, prn=process_packet, store=False)