"""
real_time/main.py
=================
Real-time intrusion detection with a browser-based Wireshark-style dashboard.

Usage
-----
    sudo python3.9 ids/real_time/main.py <interface> [<model.joblib>] [<scaler.joblib>]

Open http://<node-ip>:5001/ in a browser to see the live dashboard.
Malicious packets appear in the table; counters update on every hit.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import warnings
from collections import deque
from typing import Deque, List

import joblib
import numpy as np
import pandas as pd
from flask import Flask, Response
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from scapy.all import ARP as ScapyARP

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from ids.feature_extraction import extract_features_from_packets  # noqa: E402

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WINDOW_SECONDS: float = 1.0
BUFFER_SECONDS: float = max(WINDOW_SECONDS * 5.0, 5.0)
DEFAULT_MODEL: str = os.path.join(_PKG_ROOT, "out_cls", "rf.joblib")
KNOWN_ADDRESSES: list[str] | None = None
WEB_PORT: int = 5001

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_MODEL = None
_SCALER = None
_BUFFER: Deque = deque()

_COUNT_TOTAL = 0
_COUNT_MALICIOUS = 0
_CAPTURE_START: float = 0.0

_listeners: List[queue.Queue] = []

# ---------------------------------------------------------------------------
# Model helpers
# ---------------------------------------------------------------------------

def _load_model(model_path: str, scaler_path: str | None) -> None:
    global _MODEL, _SCALER
    _MODEL = joblib.load(model_path)
    if scaler_path is not None:
        _SCALER = joblib.load(scaler_path)
    print(f"[*] Model loaded from  {model_path!r}", flush=True)
    if _SCALER is not None:
        print(f"[*] Scaler loaded from {scaler_path!r}", flush=True)


def _predict(features: pd.Series) -> int:
    X = features.to_numpy(dtype=np.float32).reshape(1, -1)
    if _SCALER is not None:
        X = _SCALER.transform(X)
    raw = _MODEL.predict(X)[0]
    return 1 if raw == -1 else int(raw)


# ---------------------------------------------------------------------------
# Packet summary (Wireshark-style fields from the raw scapy packet)
# ---------------------------------------------------------------------------

def _proto_from_layers(pkt) -> str:
    """Detect protocol directly from scapy's parsed layer stack."""
    try:
        from scapy.contrib.bgp import BGPHeader
        if pkt.haslayer(BGPHeader):
            return "BGP"
    except Exception:
        pass

    try:
        from scapy.layers.dns import DNS
        if pkt.haslayer(DNS):
            return "DNS"
    except Exception:
        pass

    if pkt.haslayer(ScapyARP): return "ARP"
    if pkt.haslayer(ICMP):     return "ICMP"
    if pkt.haslayer(TCP):      return "TCP"
    if pkt.haslayer(UDP):      return "UDP"
    if pkt.haslayer(IPv6):     return "IPv6"
    if pkt.haslayer(IP):       return "IP"

    return pkt.lastlayer().name.upper()[:8]


def _packet_summary(pkt) -> dict:
    src = dst = "-"
    length = len(pkt)
    info = ""

    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(ScapyARP):
        arp = pkt[ScapyARP]
        src, dst = arp.psrc, arp.pdst

    proto = _proto_from_layers(pkt)

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flag_names = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"),
                      (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
        flags = [name for bit, name in flag_names if tcp.flags & bit]
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        info = f"{tcp.sport} -> {tcp.dport}{flag_str}  Seq={tcp.seq}  Win={tcp.window}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        info = f"{udp.sport} -> {udp.dport}  Len={udp.len}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        info = f"Type={icmp.type}  Code={icmp.code}"
    elif pkt.haslayer(ScapyARP):
        arp = pkt[ScapyARP]
        info = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"

    return {
        "time": f"{float(pkt.time) - _CAPTURE_START:.6f}",
        "src": src,
        "dst": dst,
        "proto": proto,
        "length": length,
        "info": info,
    }


# ---------------------------------------------------------------------------
# SSE broadcast
# ---------------------------------------------------------------------------

def _broadcast(event: str, data: dict) -> None:
    payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    for q in list(_listeners):
        q.put(payload)


# ---------------------------------------------------------------------------
# Web dashboard
# ---------------------------------------------------------------------------

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IDS Live Monitor</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #1e1e2e; color: #cdd6f4;
         font-family: 'Consolas', 'Menlo', monospace; font-size: 13px; }

  header { background: #181825; padding: 12px 20px;
           display: flex; align-items: center; gap: 32px;
           border-bottom: 1px solid #313244; position: sticky; top: 0; z-index: 10; }
  header h1 { font-size: 15px; font-weight: bold; color: #cba6f7; letter-spacing: 1px; }

  .stat { display: flex; flex-direction: column; align-items: center; min-width: 70px; }
  .stat .label { font-size: 10px; color: #6c7086; text-transform: uppercase; letter-spacing: 1px; }
  .stat .value { font-size: 24px; font-weight: bold; }
  .total     .value { color: #89b4fa; }
  .normal    .value { color: #a6e3a1; }
  .malicious .value { color: #f38ba8; }

  .dot { width: 10px; height: 10px; border-radius: 50%; background: #a6e3a1;
         margin-left: auto; transition: background .3s; }
  .dot.idle { background: #45475a; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
  .dot.active { animation: blink .8s infinite; }

  #table-wrap { height: calc(100vh - 62px); overflow-y: auto; }

  table { width: 100%; border-collapse: collapse; }
  thead th { position: sticky; top: 0; background: #11111b;
             padding: 6px 10px; text-align: left; font-size: 11px;
             text-transform: uppercase; letter-spacing: .8px; color: #6c7086;
             border-bottom: 1px solid #313244; }
  td { padding: 4px 10px; border-bottom: 1px solid #181825; white-space: nowrap; }
  tr:hover td { background: #2a2a3e; cursor: default; }

  .col-no   { color: #6c7086; width: 50px; }
  .col-time { color: #fab387; width: 110px; }
  .col-src, .col-dst { color: #89b4fa; width: 130px; }
  .col-len  { color: #cdd6f4; width: 60px; text-align: right; }
  .col-info { color: #cdd6f4; max-width: 380px; overflow: hidden; text-overflow: ellipsis; }

  .badge { display: inline-block; padding: 1px 7px; border-radius: 3px;
           font-size: 11px; font-weight: bold; }
  .b-TCP  { background:#1a3550; color:#89b4fa; }
  .b-UDP  { background:#1a3828; color:#a6e3a1; }
  .b-ICMP { background:#3d2a1a; color:#fab387; }
  .b-ARP  { background:#35183d; color:#cba6f7; }
  .b-DNS  { background:#183535; color:#94e2d5; }
  .b-BGP  { background:#38381a; color:#f9e2af; }
  .b-OTHER{ background:#2a2a2a; color:#6c7086; }
</style>
</head>
<body>
<header>
  <h1>&#128737; IDS Live Monitor</h1>
  <div class="stat total">
    <span class="label">Total</span>
    <span class="value" id="c-total">0</span>
  </div>
  <div class="stat normal">
    <span class="label">Normal</span>
    <span class="value" id="c-normal">0</span>
  </div>
  <div class="stat malicious">
    <span class="label">Malicious</span>
    <span class="value" id="c-malicious">0</span>
  </div>
  <div class="dot idle" id="dot"></div>
</header>

<div id="table-wrap">
<table>
  <thead>
    <tr>
      <th class="col-no">No.</th>
      <th class="col-time">Time (s)</th>
      <th class="col-src">Source</th>
      <th class="col-dst">Destination</th>
      <th>Protocol</th>
      <th class="col-len">Len</th>
      <th class="col-info">Info</th>
    </tr>
  </thead>
  <tbody id="tbody"></tbody>
</table>
</div>

<script>
const tbody  = document.getElementById('tbody');
const dot    = document.getElementById('dot');
const cTotal = document.getElementById('c-total');
const cNorm  = document.getElementById('c-normal');
const cMal   = document.getElementById('c-malicious');
let rowNo = 0, dotTimer = null;

function badgeClass(p) {
  return 'badge b-' + (['TCP','UDP','ICMP','ARP','DNS','BGP'].includes(p) ? p : 'OTHER');
}

function flashDot() {
  dot.className = 'dot active';
  clearTimeout(dotTimer);
  dotTimer = setTimeout(() => dot.className = 'dot idle', 3000);
}

const es = new EventSource('/events');

es.addEventListener('malicious', function(e) {
  const d = JSON.parse(e.data);

  cTotal.textContent = d.total;
  cNorm.textContent  = d.normal;
  cMal.textContent   = d.malicious;
  flashDot();

  rowNo++;
  const tr = document.createElement('tr');
  tr.innerHTML =
    '<td class="col-no">'   + rowNo    + '</td>' +
    '<td class="col-time">' + d.time   + '</td>' +
    '<td class="col-src">'  + d.src    + '</td>' +
    '<td class="col-dst">'  + d.dst    + '</td>' +
    '<td><span class="' + badgeClass(d.proto) + '">' + d.proto + '</span></td>' +
    '<td class="col-len">'  + d.length + '</td>' +
    '<td class="col-info">' + d.info   + '</td>';
  tbody.prepend(tr);
});
</script>
</body>
</html>
"""

_flask_app = Flask(__name__)


@_flask_app.route("/")
def _index():
    return Response(_HTML, mimetype="text/html")


@_flask_app.route("/events")
def _sse():
    def _stream():
        q: queue.Queue = queue.Queue()
        _listeners.append(q)
        try:
            while True:
                yield q.get()
        finally:
            if q in _listeners:
                _listeners.remove(q)

    return Response(
        _stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------

def process_packet(pkt) -> None:
    global _COUNT_TOTAL, _COUNT_MALICIOUS

    _BUFFER.append(pkt)

    now = float(pkt.time)
    while _BUFFER and (now - float(_BUFFER[0].time)) > BUFFER_SECONDS:
        _BUFFER.popleft()

    df = extract_features_from_packets(
        list(_BUFFER),
        known_addresses=KNOWN_ADDRESSES,
        window_seconds=WINDOW_SECONDS,
        with_label=False,
    )
    if df.empty:
        return

    features = df.iloc[-1]
    label = _predict(features)

    _COUNT_TOTAL += 1
    if label == 1:
        _COUNT_MALICIOUS += 1
        payload = _packet_summary(pkt)
        payload["total"] = _COUNT_TOTAL
        payload["normal"] = _COUNT_TOTAL - _COUNT_MALICIOUS
        payload["malicious"] = _COUNT_MALICIOUS
        _broadcast("malicious", payload)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) not in (2, 3, 4):
        print(
            f"Usage: sudo python3.9 {sys.argv[0]} <interface> "
            f"[<model.joblib>] [<scaler.joblib>]",
            file=sys.stderr,
        )
        sys.exit(1)

    iface      = sys.argv[1]
    model_path = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_MODEL
    scaler_path = sys.argv[3] if len(sys.argv) == 4 else None

    _load_model(model_path, scaler_path)
    _CAPTURE_START = time.time()

    flask_thread = threading.Thread(
        target=lambda: _flask_app.run(host="0.0.0.0", port=WEB_PORT, threaded=True),
        daemon=True,
    )
    flask_thread.start()

    print(f"[*] Sniffing on {iface!r}", flush=True)
    print(f"[*] Dashboard  -> http://0.0.0.0:{WEB_PORT}/", flush=True)
    sniff(iface=iface, prn=process_packet, store=False)
