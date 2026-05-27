"""
config.py
=========
Single source of truth for the intrusion-detection pipeline:

  * the network ground-truth (which IPs / MACs legitimately belong to the
    emulated topology),
  * the definition of the malicious node,
  * which NFStream columns are *identity* columns (used only to build labels
    and then dropped) versus *model features*.

Design rule (task requirement #2)
---------------------------------
No feature handed to a model may encode a fixed identity or wall-clock time:
no IP/MAC/port, no container id, no absolute first/last-seen timestamp.
Those columns live in ``IDENTITY_COLUMNS`` -- they are kept around *only* long
enough to derive the ground-truth label, then removed before training.  What
remains are statistical flow descriptors (counts, byte/packet sizes,
durations expressed as deltas, inter-arrival times, TCP-flag tallies) that stay
meaningful in a different time window or a re-addressed topology.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
#  Ground truth: the legitimate topology
#  (derived from docker-compose.yml container_name / ipv4_address fields)
# --------------------------------------------------------------------------- #
#  AS160 / AS161 / AS162 internal hosts + routers, plus the IX103 fabric.
KNOWN_IPS: set[str] = {
    # IX103 internet exchange
    "10.103.0.103",          # ix103 route server
    "10.103.0.160",          # AS160 router @ IX
    "10.103.0.161",          # AS161 router @ IX
    "10.103.0.162",          # AS162 router @ IX
    # AS160
    "10.160.0.71",           # POW-00 miner / bootnode
    "10.160.0.72",           # host_1
    "10.160.0.73",           # host_2
    "10.160.0.254",          # router0
    # AS161
    "10.161.0.71",           # POW-01 miner
    "10.161.0.72",           # host_1
    "10.161.0.73",           # host_2
    "10.161.0.254",          # router0
    # AS162  (NOTE: 10.162.0.74 is intentionally absent -> see MALICIOUS_IPS)
    "10.162.0.71",           # POW-02 miner
    "10.162.0.72",           # host_1
    "10.162.0.73",           # host_2
    "10.162.0.254",          # router0
}

# --------------------------------------------------------------------------- #
#  The adversary: the rogue "new_eth_node" container.
#  Its MAC follows the SEED scheme 02:42:0a:<as-hex>:00:<host-hex>:
#     0a a2 00 4a  ==  10 .162 .0 .74
# --------------------------------------------------------------------------- #
MALICIOUS_IPS: set[str] = {"10.162.0.74"}
MALICIOUS_MACS: set[str] = {"02:42:0a:a2:00:4a"}

# --------------------------------------------------------------------------- #
#  Address classes that are infrastructure noise rather than evidence of an
#  intruder.  A flow to/from these is NOT labelled malicious just because the
#  address is missing from KNOWN_IPS (ARP-less L2 broadcast, DHCP discover,
#  link-local, multicast, loopback).  Matched by prefix.
# --------------------------------------------------------------------------- #
BENIGN_SPECIAL_PREFIXES: tuple[str, ...] = (
    "0.0.0.0",          # unspecified (DHCP discover)
    "255.255.255.255",  # limited broadcast
    "224.", "225.", "226.", "227.", "228.", "229.", "230.", "231.",
    "232.", "233.", "234.", "235.", "236.", "237.", "238.", "239.",  # IPv4 multicast
    "169.254.",         # link-local
    "127.",             # loopback
    "ff02:", "ff01:", "ff05:",  # IPv6 multicast
    "fe80:",            # IPv6 link-local
    "::",               # IPv6 unspecified / loopback
)

# --------------------------------------------------------------------------- #
#  Identity columns.  NFStream produces these; we use them to build labels and
#  for human-readable inspection, but they are dropped before model fitting.
# --------------------------------------------------------------------------- #
IDENTITY_COLUMNS: list[str] = [
    "id",
    "expiration_id",
    "src_ip", "src_mac", "src_oui", "src_port",
    "dst_ip", "dst_mac", "dst_oui", "dst_port",
    "ip_version", "vlan_id", "tunnel_id",
    # absolute wall-clock timestamps -- excluded from features by rule #2
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms", "src2dst_last_seen_ms",
    "dst2src_first_seen_ms", "dst2src_last_seen_ms",
    # nDPI string fields that can leak identity (SNI may contain an IP, etc.)
    "application_name", "application_category_name",
    "application_is_guessed", "application_confidence",
    "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
]

# The label column name added by labeling.py
LABEL_COLUMN = "label"          # 1 = malicious, 0 = normal
LABEL_NAMES = ["normal", "malicious"]

# --------------------------------------------------------------------------- #
#  Base statistical features taken directly from NFStream.
#  Every entry here is a count, a size, a delta-duration or an inter-arrival
#  statistic -- none of them encode *who* or *when* in absolute terms.
#  Columns absent from a given capture are silently skipped downstream.
# --------------------------------------------------------------------------- #
BASE_FEATURES: list[str] = [
    "protocol",                       # L4 protocol number (6/17/1/...) -- topology-independent
    # ---- volume ----
    "bidirectional_packets", "bidirectional_bytes",
    "src2dst_packets", "src2dst_bytes",
    "dst2src_packets", "dst2src_bytes",
    # ---- duration (relative deltas, not absolute clock) ----
    "bidirectional_duration_ms", "src2dst_duration_ms", "dst2src_duration_ms",
    # ---- packet-size distribution ----
    "bidirectional_min_ps", "bidirectional_mean_ps",
    "bidirectional_stddev_ps", "bidirectional_max_ps",
    "src2dst_min_ps", "src2dst_mean_ps", "src2dst_stddev_ps", "src2dst_max_ps",
    "dst2src_min_ps", "dst2src_mean_ps", "dst2src_stddev_ps", "dst2src_max_ps",
    # ---- inter-arrival times (relative) ----
    "bidirectional_min_piat_ms", "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms", "bidirectional_max_piat_ms",
    "src2dst_min_piat_ms", "src2dst_mean_piat_ms",
    "src2dst_stddev_piat_ms", "src2dst_max_piat_ms",
    "dst2src_min_piat_ms", "dst2src_mean_piat_ms",
    "dst2src_stddev_piat_ms", "dst2src_max_piat_ms",
    # ---- TCP flag tallies ----
    "bidirectional_syn_packets", "bidirectional_cwr_packets",
    "bidirectional_ece_packets", "bidirectional_urg_packets",
    "bidirectional_ack_packets", "bidirectional_psh_packets",
    "bidirectional_rst_packets", "bidirectional_fin_packets",
    "src2dst_syn_packets", "src2dst_rst_packets",
    "src2dst_psh_packets", "src2dst_fin_packets",
    "dst2src_syn_packets", "dst2src_rst_packets",
    "dst2src_psh_packets", "dst2src_fin_packets",
]

# Names of the engineered ratio/rate features added in preprocessing.py.
# Listed here so the rest of the pipeline knows they are legitimate features.
ENGINEERED_FEATURES: list[str] = [
    "bytes_per_packet",
    "src2dst_bytes_ratio",
    "src2dst_packets_ratio",
    "download_upload_ratio",
    "bytes_per_ms",
    "packets_per_ms",
    "syn_ratio",
    "rst_ratio",
    "fin_ratio",
    "ack_ratio",
    "mean_ps_ratio",
]

# Reproducibility
RANDOM_STATE = 42
