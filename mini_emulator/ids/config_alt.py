"""
config.py
=========
Single source of truth for the intrusion-detection pipeline (per-packet variant).

Identical topology ground-truth and identity-column rules as the flow-based
version.  The only substantive change is the feature lists: BASE_FEATURES and
ENGINEERED_FEATURES now reflect the three-layer output of
packet_feature_extraction.py rather than NFStream's per-flow aggregates.

Design rule (task requirement #2)
----------------------------------
No feature handed to a model may encode a fixed identity or wall-clock time.
Identity columns (IP, MAC, port, absolute timestamps) live in IDENTITY_COLUMNS
and are dropped by preprocessing.build_matrix before any model sees them.
All features are either per-packet measurements or statistics derived purely
from relative deltas and counts within a flow.
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
#  Identity columns -- used only to build labels, dropped before training.
#  Matches the renamed _identity_* columns output by packet_feature_extraction,
#  plus any other columns that should never reach a model.
# --------------------------------------------------------------------------- #
IDENTITY_COLUMNS: list[str] = [
    # core identity (renamed from _identity_* by the extractor)
    "src_ip", "dst_ip",
    "src_mac", "dst_mac",
    "src_port", "dst_port",
    # if nDPI / application fields ever appear (e.g. from a hybrid extractor)
    "application_name", "application_category_name",
    "requested_server_name", "client_fingerprint",
    "server_fingerprint", "user_agent", "content_type",
]

LABEL_COLUMN = "label"
LABEL_NAMES  = ["normal", "malicious"]

# --------------------------------------------------------------------------- #
#  BASE_FEATURES -- direct measurements from packet_feature_extraction.py.
#  Three layers:
#    1. Packet-level     -- what this packet looks like in isolation
#    2. Running context  -- rolling stats up to and including this packet
#    3. Flow summary     -- completed-flow aggregates attached to every row
#
#  None of these encode who sent the packet or when in wall-clock time.
# --------------------------------------------------------------------------- #
BASE_FEATURES: list[str] = [

    # ── 1. Packet-level ────────────────────────────────────────────────── #
    "protocol",           # L4 protocol number (6=TCP, 17=UDP, …)
    "ip_ttl",             # IP time-to-live
    "ip_len",             # IP-layer length field
    "pkt_len",            # total captured frame length
    "tcp_window_size",    # TCP receive-window size (0 for non-TCP)
    "direction",          # 1 = forward (initiator→responder), 0 = reverse

    # TCP flag bits (individual, not a bitmask int)
    "tcp_syn",
    "tcp_ack",
    "tcp_rst",
    "tcp_fin",
    "tcp_psh",
    "tcp_urg",
    "tcp_ece",
    "tcp_cwr",

    # ── 2. Running context (up to and including this packet) ───────────── #
    # position in flow
    "flow_pkt_index",           # 0-based packet index within its flow

    # inter-arrival times (relative deltas, not absolute timestamps)
    "iat_from_prev_ms",         # ms since previous packet in flow (any dir)
    "fwd_iat_from_prev_ms",     # ms since previous forward packet
    "rev_iat_from_prev_ms",     # ms since previous reverse packet

    # cumulative volume
    "flow_pkts_so_far",
    "flow_bytes_so_far",
    "fwd_pkts_so_far",
    "fwd_bytes_so_far",
    "rev_pkts_so_far",
    "rev_bytes_so_far",

    # running packet-size distribution (Welford online)
    "run_mean_ps",
    "run_stddev_ps",
    "run_min_ps",
    "run_max_ps",
    "run_fwd_mean_ps",
    "run_rev_mean_ps",

    # running IAT distribution
    "run_mean_iat_ms",
    "run_stddev_iat_ms",
    "run_fwd_mean_iat_ms",
    "run_rev_mean_iat_ms",

    # running TCP flag tallies
    "flow_syn_so_far",
    "flow_ack_so_far",
    "flow_rst_so_far",
    "flow_fin_so_far",
    "flow_psh_so_far",
    "flow_fwd_syn_so_far",
    "flow_rev_syn_so_far",

    # running ratios
    "run_syn_ratio",
    "run_rst_ratio",
    "run_fwd_ratio",
    "run_bytes_per_pkt",

    # elapsed flow duration up to this packet (relative delta, ms)
    "flow_elapsed_ms",

    # ── 3. Completed-flow summary (attached to every row in the flow) ──── #
    # total volume
    "flow_total_pkts",
    "flow_total_bytes",
    "flow_fwd_total_pkts",
    "flow_fwd_total_bytes",
    "flow_rev_total_pkts",
    "flow_rev_total_bytes",

    # total flow duration (relative delta)
    "flow_duration_ms",

    # final packet-size distribution
    "flow_mean_ps",
    "flow_stddev_ps",
    "flow_min_ps",
    "flow_max_ps",
    "flow_fwd_mean_ps",
    "flow_rev_mean_ps",

    # final IAT distribution
    "flow_mean_iat_ms",
    "flow_stddev_iat_ms",
    "flow_fwd_mean_iat_ms",
    "flow_rev_mean_iat_ms",

    # final TCP flag tallies
    "flow_total_syn",
    "flow_total_ack",
    "flow_total_rst",
    "flow_total_fin",
    "flow_total_psh",
    "flow_fwd_total_syn",
    "flow_rev_total_syn",

    # final flow-level ratios
    "flow_syn_ratio",
    "flow_ack_ratio",
    "flow_rst_ratio",
    "flow_fin_ratio",
    "flow_bytes_per_pkt",
    "flow_bytes_per_ms",
    "flow_pkts_per_ms",
    "flow_fwd_pkt_ratio",
    "flow_fwd_byte_ratio",
    "flow_download_upload_ratio",
    "flow_mean_ps_ratio",
]

# --------------------------------------------------------------------------- #
#  ENGINEERED_FEATURES -- derived columns added by preprocessing.py.
#  Same philosophy as before: ratios / rates, no identity, no absolute time.
# --------------------------------------------------------------------------- #
ENGINEERED_FEATURES: list[str] = [
    # packet position as a fraction of the total flow length
    # (tells the model whether this is an early or late packet)
    "pkt_position_ratio",

    # how much of the flow's total bytes have arrived by this packet
    "bytes_progress_ratio",

    # ratio of this packet's size to the running mean so far
    # (spike detector: large relative to what we've seen)
    "pkt_size_vs_run_mean",

    # ratio of this packet's size to the completed-flow mean
    # (same idea but anchored to the final distribution)
    "pkt_size_vs_flow_mean",

    # how anomalous this IAT is relative to the running mean
    # (large value = unusually long gap or burst)
    "iat_vs_run_mean",

    # asymmetry between forward and reverse byte volumes so far
    "run_byte_asymmetry",

    # asymmetry between forward and reverse byte volumes (completed flow)
    "flow_byte_asymmetry",
]

# Reproducibility
RANDOM_STATE = 42