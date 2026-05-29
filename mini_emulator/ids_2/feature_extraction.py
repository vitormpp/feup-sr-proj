"""
pcap_features.py
================
Feature extraction and cleaning for PCAP-based ML pipelines.

Public API
----------
    extract_features(pcap_path, known_addresses=None, window_seconds=1.0)
        -> pd.DataFrame

    MALICIOUS_IP   : str   – IP that marks a packet as malicious (label=1)
    MALICIOUS_MAC  : str   – MAC that marks a packet as malicious (label=1)

Design notes
------------
* Packets to/from the known-malicious host (IP or MAC) are KEPT and receive
  label=1.  All other packets receive label=0.
* Packets whose IP is not in `known_addresses` (when supplied) are labelled
  malicious (label=1) — unrecognised addresses are treated as suspicious.
* No host-identity fields (IP, MAC, absolute TCP seq/ack, IP-ID, checksums)
  ever appear in the output; they are read only for labelling/filtering then
  discarded.
* Categorical fields (protocol, port-service bucket) are one-hot encoded as
  sparse bool columns.
* Rolling temporal features use only past packets within the same flow
  (causal / real-time safe, per-flow).
* ICMP and other portless protocols share a per-protocol sentinel flow key,
  meaning their rolling rates are computed across all hosts using that
  protocol — not per host-pair.  This is a known limitation of the
  IP-free design; see _extract_rows for details.
"""

from __future__ import annotations

import warnings
from collections import defaultdict
from typing import Collection

import numpy as np
import pandas as pd
from scapy.all import rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Known-malicious host – packets touching either address are labelled 1
# ---------------------------------------------------------------------------
MALICIOUS_IP  = "10.162.0.74"
MALICIOUS_MAC = "02:42:0a:a2:00:4a"   # Scapy always normalises MACs to lowercase

# ---------------------------------------------------------------------------
# Helper tables
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

# Fields that are NaN when absent (filled with 0 in _encode_and_clean).
# Declaring them as a constant makes it clear these are intentional absences,
# not forgotten assignments.
_TRANSPORT_DEFAULTS: dict = {
    "tcp_seq_delta": np.nan, "tcp_ack_delta": np.nan,
    "tcp_window":    np.nan, "tcp_data_offset": np.nan,
    "udp_length":    np.nan,
    "icmp_type":     np.nan, "icmp_code": np.nan,
    "payload_len":   0,
    "flag_fin": 0, "flag_syn": 0, "flag_rst": 0, "flag_psh": 0,
    "flag_ack": 0, "flag_urg": 0, "flag_ece": 0, "flag_cwr": 0,
}


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


# ---------------------------------------------------------------------------
# Step 1 – per-packet extraction  (identity fields used only for labelling)
# ---------------------------------------------------------------------------

def _extract_rows(
    packets,
    known_ips: frozenset[str] | None,
) -> list[dict]:
    """
    Iterate packets, assign labels, apply the unknown-address filter, and
    return a list of feature dicts.

    Labelling rules (applied before any identity field is discarded):
        label=1  if src or dst matches MALICIOUS_IP or MALICIOUS_MAC
        label=1  if src or dst IP is not in known_ips (when supplied) —
                 unrecognised addresses are treated as malicious
        label=0  otherwise

    `_flow_key` is stored in each row so that _add_temporal_features can
    group packets by flow.  It is an anonymous (port-only, no IPs) tuple and
    is dropped by extract_features before the DataFrame is returned.

    Limitation: ICMP and other portless protocols use a per-protocol sentinel
    key (None, None, proto_name), grouping all traffic of that protocol into
    one pseudo-flow regardless of host.  This means rolling rate features for
    ICMP reflect all hosts, not per-host-pair activity.  Fixing this would
    require including IP addresses in the key, which violates the no-identity
    design constraint.
    """
    rows: list[dict] = []
    prev_seq: dict = defaultdict(lambda: None)
    prev_ack: dict = defaultdict(lambda: None)

    for pkt in packets:
        # ---- read identity fields (never written to output) ----------------
        src_ip = dst_ip = None
        if pkt.haslayer(IP):
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None

        # ---- assign label --------------------------------------------------
        is_malicious = (
            MALICIOUS_IP  in (src_ip,  dst_ip) or
            MALICIOUS_MAC in (src_mac, dst_mac)
        )

        if not is_malicious and known_ips is not None:
            if src_ip not in known_ips or dst_ip not in known_ips:
                is_malicious = True

        # ---- IP layer features ---------------------------------------------
        row: dict = {"timestamp": float(pkt.time), "label": int(is_malicious)}

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
                       ip_len=ip6.plen + 40,   # +40: fixed IPv6 header bytes
                       ip_flags_df=0, ip_flags_mf=0, ip_frag_offset=0)
            proto_num = ip6.nh
        else:
            row.update(ip_version=0, ttl=np.nan, ip_len=len(pkt),
                       ip_flags_df=0, ip_flags_mf=0, ip_frag_offset=0)
            proto_num = 0

        row["proto"] = _PROTO_MAP.get(proto_num, f"proto_{proto_num}")

        # ---- transport layer features --------------------------------------
        # Start with defaults (NaN for protocol-specific fields, 0 for flags).
        # Each branch below writes only the fields it actually has, keeping
        # the per-branch code minimal.
        row.update(_TRANSPORT_DEFAULTS)
        sport = dport = None

        if pkt.haslayer(TCP):
            tcp          = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            fkey         = (min(sport, dport), max(sport, dport), row["proto"])

            ps = prev_seq[fkey] if prev_seq[fkey] is not None else tcp.seq
            pa = prev_ack[fkey] if prev_ack[fkey] is not None else tcp.ack
            row["tcp_seq_delta"]   = int(tcp.seq - ps) & 0xFFFF_FFFF
            row["tcp_ack_delta"]   = int(tcp.ack - pa) & 0xFFFF_FFFF
            prev_seq[fkey], prev_ack[fkey] = tcp.seq, tcp.ack

            row["tcp_window"]      = tcp.window
            row["tcp_data_offset"] = tcp.dataofs
            row["payload_len"]     = len(bytes(tcp.payload))

            f = tcp.flags
            row["flag_fin"] = int(bool(f & 0x01))
            row["flag_syn"] = int(bool(f & 0x02))
            row["flag_rst"] = int(bool(f & 0x04))
            row["flag_psh"] = int(bool(f & 0x08))
            row["flag_ack"] = int(bool(f & 0x10))
            row["flag_urg"] = int(bool(f & 0x20))
            row["flag_ece"] = int(bool(f & 0x40))
            row["flag_cwr"] = int(bool(f & 0x80))

        elif pkt.haslayer(UDP):
            udp          = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            fkey         = (min(sport, dport), max(sport, dport), row["proto"])
            row["udp_length"]  = udp.len
            row["payload_len"] = len(bytes(udp.payload))

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            fkey = (None, None, row["proto"])   # sentinel: all ICMP grouped
            row["icmp_type"]   = icmp.type
            row["icmp_code"]   = icmp.code
            row["payload_len"] = len(bytes(icmp.payload))

        else:
            fkey               = (None, None, "unknown")
            row["payload_len"] = len(pkt)

        row["sport_service"] = _port_bucket(sport)
        row["dport_service"] = _port_bucket(dport)
        row["_flow_key"]     = fkey
        rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# Step 2 – one-hot encode categoricals + fill protocol-specific NaNs
# ---------------------------------------------------------------------------

_CATEGORICAL_COLS = ("proto", "sport_service", "dport_service")


def _encode_and_clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    One-hot encode categorical columns and fill NaNs with 0 (field absent).
    `label` and `_flow_key` are popped before encoding and restored after.
    """
    label    = df.pop("label")
    flow_key = df.pop("_flow_key")

    df = pd.get_dummies(df, columns=list(_CATEGORICAL_COLS),
                        drop_first=False, dtype=bool)

    num_cols  = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(0)

    bool_cols = df.select_dtypes(include=bool).columns
    df[bool_cols] = df[bool_cols].astype(np.int8)

    df["label"]     = label.values
    df["_flow_key"] = flow_key.values
    return df


# ---------------------------------------------------------------------------
# Step 3 – causal rolling temporal features (per flow)
# ---------------------------------------------------------------------------

def _add_temporal_features(df: pd.DataFrame,
                            window_seconds: float) -> pd.DataFrame:
    """
    Append causal rolling statistics computed per flow.

    Features added
    --------------
    inter_arrival_time    seconds since the previous packet in this flow
    rolling_pkt_rate      packets / second in (t-W, t] for this flow
    rolling_byte_rate     bytes / second in (t-W, t] for this flow
    rolling_unique_dports distinct dport service buckets seen in window
    rolling_syn_rate      SYN packets / second in window for this flow
    rolling_rst_rate      RST packets / second in window for this flow
    """
    df       = df.sort_values("timestamp").reset_index(drop=True)
    label    = df.pop("label")
    flow_key = df.pop("_flow_key")

    ts      = df["timestamp"].values
    ip_len  = df["ip_len"].values
    syn     = df["flag_syn"].values if "flag_syn" in df.columns else np.zeros(len(df))
    rst     = df["flag_rst"].values if "flag_rst" in df.columns else np.zeros(len(df))

    dport_cols = [c for c in df.columns if c.startswith("dport_service_")]
    if dport_cols:
        dport_idx = df[dport_cols].values.argmax(axis=1)
    else:
        warnings.warn(
            "No dport_service_* columns found; rolling_unique_dports will "
            "be 1 for every non-empty window.",
            stacklevel=3,
        )
        dport_idx = np.zeros(len(df), dtype=int)

    n = len(df)
    inter_arr  = np.zeros(n)
    pkt_rate   = np.zeros(n)
    byte_rate  = np.zeros(n)
    uniq_dport = np.zeros(n, dtype=int)
    syn_rate   = np.zeros(n)
    rst_rate   = np.zeros(n)

    # Group row indices by flow key; because df is sorted by timestamp,
    # indices within each group are already in ascending time order.
    flow_groups: dict = defaultdict(list)
    for idx, fk in enumerate(flow_key.values):
        flow_groups[fk].append(idx)

    for idx_list in flow_groups.values():
        indices = np.array(idx_list, dtype=int)
        left    = 0

        for j, i in enumerate(indices):
            inter_arr[i] = ts[i] - ts[indices[j - 1]] if j > 0 else 0.0

            while ts[i] - ts[indices[left]] > window_seconds:
                left += 1

            win     = indices[left : j + 1]
            elapsed = ts[i] - ts[indices[left]] if left < j else window_seconds

            pkt_rate[i]   = len(win) / elapsed
            byte_rate[i]  = ip_len[win].sum() / elapsed
            uniq_dport[i] = len(set(dport_idx[win]))
            syn_rate[i]   = syn[win].sum() / elapsed
            rst_rate[i]   = rst[win].sum() / elapsed

    df["inter_arrival_time"]    = inter_arr
    df["rolling_pkt_rate"]      = pkt_rate
    df["rolling_byte_rate"]     = byte_rate
    df["rolling_unique_dports"] = uniq_dport
    df["rolling_syn_rate"]      = syn_rate
    df["rolling_rst_rate"]      = rst_rate

    df["label"]     = label.values
    df["_flow_key"] = flow_key.values
    return df


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(
    pcap_path: str,
    known_addresses: Collection[str] | None = None,
    window_seconds: float = 1.0,
) -> pd.DataFrame:
    """
    Load a PCAP file and return a cleaned, model-ready feature DataFrame.

    Parameters
    ----------
    pcap_path : str
        Path to a .pcap or .pcapng file.
    known_addresses : collection of str, optional
        Whitelist of IP addresses for normal traffic.  Packets whose source
        or destination is not in this set are labelled malicious (label=1).
        Pass None to disable this check.
    window_seconds : float
        Look-back window for rolling temporal features (default 1 s).

    Returns
    -------
    pd.DataFrame
        One row per retained packet.  The `label` column (last) contains
        1 for malicious packets and 0 for normal ones.  No host-identity
        fields are present.  `timestamp` is dropped before return — it is
        a spurious predictor that overfits to a single capture session and
        fails completely on captures from different times.
    """
    packets = rdpcap(pcap_path)

    known_ips: frozenset[str] | None = (
        frozenset(known_addresses) if known_addresses is not None else None
    )

    rows = _extract_rows(packets, known_ips)
    if not rows:
        raise ValueError(
            "No packets survived filtering.  Check MALICIOUS_IP / "
            "MALICIOUS_MAC constants and your known_addresses whitelist."
        )

    df = pd.DataFrame(rows)
    df = _encode_and_clean(df)
    df = _add_temporal_features(df, window_seconds)
    return df.drop(columns=["timestamp", "_flow_key"])