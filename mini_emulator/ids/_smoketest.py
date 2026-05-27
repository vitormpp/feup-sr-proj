"""Synthetic smoke test: fabricate an NFStream-like raw flow CSV (identity
columns + base features) for both normal and malicious traffic, then it is fed
to the pipeline via --features-csv. NOT part of the pipeline; safe to delete."""
import numpy as np, pandas as pd
from ids import config

rng = np.random.default_rng(0)
KNOWN = sorted(config.KNOWN_IPS)

def mac_for(ip):  # SEED scheme 02:42:0a:<as>:00:<host>
    o = ip.split("."); return f"02:42:{int(o[0]):02x}:{int(o[1]):02x}:{int(o[2]):02x}:{int(o[3]):02x}"

def make(n, malicious):
    rows = []
    for _ in range(n):
        if malicious:
            kind = rng.integers(0, 2)
            if kind == 0:  # rogue node
                src, dst = "10.162.0.74", rng.choice(KNOWN)
            else:          # foreign scanner IP
                src, dst = f"203.0.113.{rng.integers(1,254)}", rng.choice(KNOWN)
            pkts = rng.integers(1, 8); dur = rng.uniform(0, 500)
            syn = rng.integers(0, pkts + 1)            # scan-like: many SYNs
        else:
            src, dst = rng.choice(KNOWN, 2, replace=False)
            pkts = rng.integers(20, 1200); dur = rng.uniform(1000, 120000)
            syn = rng.integers(0, 3)
        b = pkts * rng.uniform(60, 400)
        s2dp = max(1, int(pkts * rng.uniform(0.3, 0.7))); d2sp = max(1, pkts - s2dp)
        rows.append(dict(
            id=0, src_ip=src, dst_ip=dst, src_mac=mac_for(src), dst_mac=mac_for(dst),
            src_port=int(rng.integers(1024, 65535)), dst_port=int(rng.choice([80, 443, 30303, 8545])),
            protocol=int(rng.choice([6, 17])), ip_version=4,
            bidirectional_first_seen_ms=1_700_000_000_000, bidirectional_last_seen_ms=1_700_000_120_000,
            bidirectional_packets=int(pkts), bidirectional_bytes=int(b),
            src2dst_packets=s2dp, src2dst_bytes=int(b * s2dp / pkts),
            dst2src_packets=d2sp, dst2src_bytes=int(b * d2sp / pkts),
            bidirectional_duration_ms=dur, src2dst_duration_ms=dur * 0.9, dst2src_duration_ms=dur * 0.8,
            bidirectional_min_ps=60, bidirectional_mean_ps=b / pkts,
            bidirectional_stddev_ps=rng.uniform(5, 80), bidirectional_max_ps=1500,
            src2dst_min_ps=60, src2dst_mean_ps=b / pkts * rng.uniform(0.8, 1.2),
            src2dst_stddev_ps=rng.uniform(5, 80), src2dst_max_ps=1500,
            dst2src_min_ps=60, dst2src_mean_ps=b / pkts * rng.uniform(0.8, 1.2),
            dst2src_stddev_ps=rng.uniform(5, 80), dst2src_max_ps=1500,
            bidirectional_mean_piat_ms=dur / max(pkts, 1), bidirectional_stddev_piat_ms=rng.uniform(0, 50),
            bidirectional_min_piat_ms=0, bidirectional_max_piat_ms=dur,
            src2dst_mean_piat_ms=dur / max(s2dp, 1), src2dst_stddev_piat_ms=rng.uniform(0, 50),
            src2dst_min_piat_ms=0, src2dst_max_piat_ms=dur,
            dst2src_mean_piat_ms=dur / max(d2sp, 1), dst2src_stddev_piat_ms=rng.uniform(0, 50),
            dst2src_min_piat_ms=0, dst2src_max_piat_ms=dur,
            bidirectional_syn_packets=int(syn), bidirectional_ack_packets=int(pkts - syn),
            bidirectional_rst_packets=int(rng.integers(0, 3)), bidirectional_fin_packets=int(rng.integers(0, 2)),
            bidirectional_psh_packets=int(rng.integers(0, pkts)),
            bidirectional_cwr_packets=0, bidirectional_ece_packets=0, bidirectional_urg_packets=0,
            src2dst_syn_packets=int(syn), src2dst_rst_packets=0, src2dst_psh_packets=0, src2dst_fin_packets=0,
            dst2src_syn_packets=0, dst2src_rst_packets=0, dst2src_psh_packets=0, dst2src_fin_packets=0,
        ))
    return rows

df = pd.DataFrame(make(900, False) + make(150, True))
out = "test_synth_flows.csv"
df.to_csv(out, index=False)
print(f"wrote {out}: {df.shape}")
