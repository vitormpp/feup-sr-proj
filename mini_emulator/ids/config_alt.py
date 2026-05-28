"""
config_alt.py
=============
Per-packet IDS configuration. Identical topology / labelling rules as the
flow-based variant; the only substantive difference is the feature lists,
which now describe the **online** per-packet output of
``feature_extraction_packets.py``.

Online rule (CRITICAL)
----------------------
Every feature listed here is computable from packets seen at or before the
current packet's timestamp. There are NO completed-flow summaries: a real-time
IDS cannot see the future, so we don't list anything that depends on the
flow's final state (total bytes, final mean IAT, flow duration, ...).
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
#  Ground truth: the legitimate topology
# --------------------------------------------------------------------------- #
KNOWN_IPS: set[str] = {
    # IX103 internet exchange
    "10.103.0.103",
    "10.103.0.160",
    "10.103.0.161",
    "10.103.0.162",
    # AS160
    "10.160.0.71",
    "10.160.0.72",
    "10.160.0.73",
    "10.160.0.254",
    # AS161
    "10.161.0.71",
    "10.161.0.72",
    "10.161.0.73",
    "10.161.0.254",
    # AS162  (10.162.0.74 intentionally absent -> MALICIOUS_IPS)
    "10.162.0.71",
    "10.162.0.72",
    "10.162.0.73",
    "10.162.0.254",
}

MALICIOUS_IPS:  set[str] = {"10.162.0.74"}
MALICIOUS_MACS: set[str] = {"02:42:0a:a2:00:4a"}

BENIGN_SPECIAL_PREFIXES: tuple[str, ...] = (
    "0.0.0.0",
    "255.255.255.255",
    "224.", "225.", "226.", "227.", "228.", "229.", "230.", "231.",
    "232.", "233.", "234.", "235.", "236.", "237.", "238.", "239.",
    "169.254.",
    "127.",
    "ff02:", "ff01:", "ff05:",
    "fe80:",
    "::",
)

# --------------------------------------------------------------------------- #
#  Identity columns -- used only to build labels / group rows for CV, dropped
#  before training. Matches the renamed _identity_* columns output by the
#  extractor, plus the _flow_key string used for GroupKFold.
# --------------------------------------------------------------------------- #
IDENTITY_COLUMNS: list[str] = [
    # Absolute wall-clock timestamp: used by labelling, never a feature.
    "ts",
    "src_ip", "dst_ip",
    "src_mac", "dst_mac",
    "src_port", "dst_port",
    # ARP operation (1=request, 2=reply): used by labelling, never a feature.
    "arp_op",
    # Flow-instance id: kept so pipeline_alt can group on it, never a feature.
    "_flow_key",
    # Labelling audit columns (added by labeling_alt.add_labels): never features.
    "_attack_type", "_label_reason",
    # If a hybrid extractor ever surfaces these, treat them as identity too.
    "application_name", "application_category_name",
    "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
]

LABEL_COLUMN = "label"
LABEL_NAMES  = ["normal", "malicious"]

# Name of the GroupKFold grouping column. Lives in IDENTITY_COLUMNS so it
# never reaches a model, but the pipeline pulls it out to pass as `groups`.
GROUP_COLUMN = "_flow_key"

# --------------------------------------------------------------------------- #
#  BASE_FEATURES -- direct measurements from feature_extraction_packets.
#  Two layers only:
#    1. Packet-level     -- what this packet looks like in isolation
#    2. Running context  -- rolling stats up to and including this packet
#
#  No "completed-flow summary" layer: that would leak the future.
# --------------------------------------------------------------------------- #
BASE_FEATURES: list[str] = [

    # ── 1. Packet-level ────────────────────────────────────────────────── #
    # Sparse multi-hot protocol booleans (see feature_extraction_packets):
    #   * exactly one of proto_tcp/udp/icmp/... fires for an IP packet,
    #   * proto_arp fires alone for L2-only ARP frames,
    #   * proto_bgp fires alongside proto_tcp when TCP/179 is involved.
    "proto_arp",
    "proto_bgp",
    "proto_esp",
    "proto_gre",
    "proto_icmp",
    "proto_icmpv6",
    "proto_ospf",
    "proto_other",
    "proto_sctp",
    "proto_tcp",
    "proto_udp",

    "ip_ttl",
    "ip_len",
    "pkt_len",
    "tcp_window_size",
    "direction",          # 1 = same direction as the flow's first packet

    # TCP flag bits (individual, not a bitmask)
    "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin",
    "tcp_psh", "tcp_urg", "tcp_ece", "tcp_cwr",

    # ── 2. Running context (past only, up to this packet) ──────────────── #
    "flow_pkt_index",       # = fwd_pkts + rev_pkts - 1; total derives from here

    "iat_from_prev_ms",
    "fwd_iat_from_prev_ms",
    "rev_iat_from_prev_ms",

    # Forward and reverse byte/packet running totals. The bidirectional totals
    # are perfectly collinear with these (sum), so they're not listed -- only
    # the byte total is kept because the bytes/packet ratio uses it directly.
    "fwd_pkts_so_far",
    "fwd_bytes_so_far",
    "rev_pkts_so_far",
    "rev_bytes_so_far",
    "flow_bytes_so_far",

    "run_mean_ps",
    "run_stddev_ps",
    "run_min_ps",
    "run_max_ps",
    "run_fwd_mean_ps",
    "run_rev_mean_ps",

    "run_mean_iat_ms",
    "run_stddev_iat_ms",
    "run_fwd_mean_iat_ms",
    "run_rev_mean_iat_ms",

    "flow_syn_so_far",
    "flow_ack_so_far",
    "flow_rst_so_far",
    "flow_fin_so_far",
    "flow_psh_so_far",
    "flow_fwd_syn_so_far",
    "flow_rev_syn_so_far",

    "run_syn_ratio",
    "run_rst_ratio",
    "run_fwd_ratio",
    "run_bytes_per_pkt",

    # Time since the flow started, *relative* to the flow itself.
    "flow_elapsed_ms",
]

# --------------------------------------------------------------------------- #
#  ENGINEERED_FEATURES -- derived columns added by preprocessing.py.
#  Every one is computable from past-only inputs.
# --------------------------------------------------------------------------- #
ENGINEERED_FEATURES: list[str] = [
    # how anomalous this packet's size is vs. the running mean so far
    "pkt_size_vs_run_mean",

    # how anomalous this IAT is vs. the running mean so far
    "iat_vs_run_mean",

    # signed forward/reverse byte asymmetry over packets seen so far,
    # in [-1, 1]: +1 = all forward, -1 = all reverse
    "run_byte_asymmetry",
]

# Reproducibility
RANDOM_STATE = 42
