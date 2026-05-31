"""
feature_extraction.py
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
* Categorical fields (protocol, port-service bucket) are one-hot encoded
  against a FIXED vocabulary defined in _PROTO_VOCAB and _SERVICE_VOCAB.
  Any value not in the vocabulary is mapped to the `other` bucket before
  encoding, so the output schema is always identical regardless of what
  traffic is present in a given capture.  This makes CSV files produced from
  different captures always compatible with the same trained model.
* Rolling temporal features use only past packets within the same flow
  (causal / real-time safe, per-flow).
* ICMP and other portless protocols share a per-protocol sentinel flow key,
  meaning their rolling rates are computed across all hosts using that
  protocol — not per host-pair.  This is a known limitation of the
  IP-free design; see _extract_rows for details.

Fixed output schema
-------------------
The complete set of columns written to the CSV is deterministic.  Adding a
new protocol or port-service to the vocabularies below is the only way to
grow the schema; all existing CSVs and models must be retrained when that
happens.

Numeric columns (always present, NaN-filled to 0 where protocol-absent):
    ip_version, ttl, ip_len, ip_flags_df, ip_flags_mf, ip_frag_offset,
    tcp_seq_delta, tcp_ack_delta, tcp_window, tcp_data_offset,
    udp_length, icmp_type, icmp_code, payload_len,
    flag_fin, flag_syn, flag_rst, flag_psh, flag_ack,
    flag_urg, flag_ece, flag_cwr,
    inter_arrival_time, rolling_pkt_rate, rolling_byte_rate,
    rolling_unique_dports, rolling_syn_rate, rolling_rst_rate

One-hot columns — proto_<name> for each name in _PROTO_VOCAB:
    proto_TCP, proto_UDP, proto_ICMP, proto_ICMPv6, proto_ARP,
    proto_BGP, proto_DNS, proto_IGMP, proto_IPv6, proto_GRE,
    proto_ESP, proto_AH, proto_OSPF, proto_SCTP, proto_other

One-hot columns — sport_service_<name> / dport_service_<name>
for each name in _SERVICE_VOCAB:
    *_unknown, *_ephemeral, *_registered, *_other_well_known,
    *_ftp_data, *_ftp, *_ssh, *_telnet, *_smtp, *_dns, *_dhcp,
    *_http, *_pop3, *_ntp, *_imap, *_snmp, *_snmp_trap, *_bgp,
    *_https, *_smb, *_syslog, *_imaps, *_pop3s,
    *_mysql, *_rdp, *_postgres, *_vnc, *_redis,
    *_http_alt, *_https_alt, *_other

Target column (last):
    label
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
# Fixed vocabularies for one-hot encoding
# ---------------------------------------------------------------------------
# Every value seen in the data is mapped to one of these before encoding.
# Anything not in the vocabulary is mapped to "other".  This guarantees a
# fixed column count regardless of the traffic in a given capture.

# Protocol vocabulary — ARP and BGP are first-class; all others that can
# appear via IP proto numbers or Scapy layer names are included.  Unknown
# proto strings (e.g. "proto_253") fall through to "other".
_PROTO_VOCAB: tuple[str, ...] = (
    "TCP", "UDP", "ICMP", "ICMPv6",
    "ARP",                              # layer-2, not an IP proto number
    "BGP",                              # rides over TCP/179; detected below
    "DNS",                              # rides over UDP/53; detected below
    "IGMP", "IPv6", "GRE", "ESP", "AH", "OSPF", "SCTP",
    "other",
)

# Port-service vocabulary — matches _PORT_SERVICES plus the catch-all buckets
# produced by _port_bucket().
_SERVICE_VOCAB: tuple[str, ...] = (
    "unknown", "ephemeral", "registered", "other_well_known",
    "ftp_data", "ftp", "ssh", "telnet", "smtp", "dns", "dhcp",
    "http", "pop3", "ntp", "imap", "snmp", "snmp_trap", "bgp",
    "https", "smb", "syslog", "imaps", "pop3s",
    "mysql", "rdp", "postgres", "vnc", "redis",
    "http_alt", "https_alt",
    "other",
)

# Pre-compute the full ordered list of one-hot column names so the schema
# is declared in one place and can be imported by other modules if needed.
PROTO_COLUMNS:   tuple[str, ...] = tuple(f"proto_{p}"          for p in _PROTO_VOCAB)
SPORT_COLUMNS:   tuple[str, ...] = tuple(f"sport_service_{s}"  for s in _SERVICE_VOCAB)
DPORT_COLUMNS:   tuple[str, ...] = tuple(f"dport_service_{s}"  for s in _SERVICE_VOCAB)

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

_TRANSPORT_DEFAULTS: dict = {
    "tcp_seq_delta": np.nan, "tcp_ack_delta": np.nan,
    "tcp_window":    np.nan, "tcp_data_offset": np.nan,
    "udp_length":    np.nan,
    "icmp_type":     np.nan, "icmp_code": np.nan,
    "payload_len":   0,
    "flag_fin": 0, "flag_syn": 0, "flag_rst": 0, "flag_psh": 0,
    "flag_ack": 0, "flag_urg": 0, "flag_ece": 0, "flag_cwr": 0,
}

# Pre-built vocab sets for O(1) membership tests
_PROTO_SET:   frozenset[str] = frozenset(_PROTO_VOCAB)
_SERVICE_SET: frozenset[str] = frozenset(_SERVICE_VOCAB)


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
        label=1  if src or dst IP is not in known_ips (when supplied)
        label=0  otherwise

    Protocol detection order
    ------------------------
    Application-layer protocols that ride on top of TCP/UDP are detected
    here by port number and override the transport-layer proto field:
        BGP  → TCP/179
        DNS  → UDP/53
        DHCP → UDP/67 or 68  (remains as "dhcp" in _PORT_SERVICES;
                               proto field stays "UDP")
    ARP is detected via Scapy's ARP layer (no IP layer present).
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
                       ip_len=ip6.plen + 40,
                       ip_flags_df=0, ip_flags_mf=0, ip_frag_offset=0)
            proto_num = ip6.nh
        else:
            row.update(ip_version=0, ttl=np.nan, ip_len=len(pkt),
                       ip_flags_df=0, ip_flags_mf=0, ip_frag_offset=0)
            proto_num = 0

        # Base protocol from IP proto number; may be overridden below.
        proto = _PROTO_MAP.get(proto_num, "other")

        # ARP has no IP layer — detect via Scapy layer.
        from scapy.all import ARP as ScapyARP
        if pkt.haslayer(ScapyARP):
            proto = "ARP"

        # ---- transport layer features --------------------------------------
        row.update(_TRANSPORT_DEFAULTS)
        sport = dport = None

        if pkt.haslayer(TCP):
            tcp          = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            fkey         = (min(sport, dport), max(sport, dport), "TCP")

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

            # Detect application-layer protocols carried over TCP.
            if sport == 179 or dport == 179:
                proto = "BGP"

        elif pkt.haslayer(UDP):
            udp          = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            fkey         = (min(sport, dport), max(sport, dport), "UDP")
            row["udp_length"]  = udp.len
            row["payload_len"] = len(bytes(udp.payload))

            # Detect application-layer protocols carried over UDP.
            if sport == 53 or dport == 53:
                proto = "DNS"

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            fkey = (None, None, "ICMP")
            row["icmp_type"]   = icmp.type
            row["icmp_code"]   = icmp.code
            row["payload_len"] = len(bytes(icmp.payload))

        else:
            fkey               = (None, None, proto)
            row["payload_len"] = len(pkt)

        # Map unknown proto strings to "other" to stay within vocabulary.
        row["proto"]          = proto if proto in _PROTO_SET else "other"
        row["sport_service"]  = _port_bucket(sport)
        row["dport_service"]  = _port_bucket(dport)
        row["_flow_key"]      = fkey
        rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# Step 2 – fixed-schema one-hot encoding + NaN fill
# ---------------------------------------------------------------------------

_CATEGORICAL_COLS = ("proto", "sport_service", "dport_service")


def _encode_and_clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    One-hot encode categorical columns against the fixed vocabularies and
    fill NaNs with 0.  The output always has exactly the same columns,
    regardless of which categories appear in the data.
    """
    label    = df.pop("label")
    flow_key = df.pop("_flow_key")

    # Map any value outside the vocabulary to "other" before encoding.
    df["proto"]         = df["proto"].where(
        df["proto"].isin(_PROTO_SET), other="other")
    df["sport_service"] = df["sport_service"].where(
        df["sport_service"].isin(_SERVICE_SET), other="other")
    df["dport_service"] = df["dport_service"].where(
        df["dport_service"].isin(_SERVICE_SET), other="other")

    # Convert to fixed-vocabulary Categoricals so get_dummies always
    # produces every column even when a category is absent from the data.
    df["proto"] = pd.Categorical(df["proto"], categories=list(_PROTO_VOCAB))
    df["sport_service"] = pd.Categorical(
        df["sport_service"], categories=list(_SERVICE_VOCAB))
    df["dport_service"] = pd.Categorical(
        df["dport_service"], categories=list(_SERVICE_VOCAB))

    df = pd.get_dummies(df, columns=list(_CATEGORICAL_COLS),
                        drop_first=False, dtype=np.int8)

    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].fillna(0)

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
        One row per retained packet.  The output schema is fixed — see the
        module docstring for the complete column list.  The `label` column
        (last) contains 1 for malicious packets and 0 for normal ones.
        No host-identity fields are present.
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