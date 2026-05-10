#!/usr/bin/env python3
"""
Attack orchestrator for the SEED emulator.

Runs on the attacker container (10.162.0.74).  Periodically launches
the compiled synflood binary against a randomly chosen target host/port
for a random duration, then sleeps before the next round.

Configuration via environment variables:
    ATTACK_BINARY       — path to the compiled synflood binary (default /synflood)
    ATTACK_DELAY_MIN    — minimum seconds between attacks (default 30)
    ATTACK_DELAY_MAX    — maximum seconds between attacks (default 120)
    ATTACK_DURATION_MIN — minimum seconds each attack runs  (default 5)
    ATTACK_DURATION_MAX — maximum seconds each attack runs  (default 20)
"""

import os
import logging
import random
import subprocess
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BINARY          = os.environ.get("ATTACK_BINARY", "/synflood")

DELAY_MIN       = float(os.environ.get("ATTACK_DELAY_MIN",    "30"))
DELAY_MAX       = float(os.environ.get("ATTACK_DELAY_MAX",   "120"))
DURATION_MIN    = float(os.environ.get("ATTACK_DURATION_MIN",  "5"))
DURATION_MAX    = float(os.environ.get("ATTACK_DURATION_MAX", "20"))

# All hosts in the topology except the attacker itself.
TARGETS = [
    "10.160.0.71", "10.160.0.72", "10.160.0.73",  # AS 160
    "10.161.0.71", "10.161.0.72", "10.161.0.73",  # AS 161
    "10.162.0.71", "10.162.0.72", "10.162.0.73",  # AS 162 (not .74 — that's us)
]

# Ports that are actually open on the emulator nodes (from traffic_gen.py).
PORTS = [23, 53, 80]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [attacker] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("attacker")

# ---------------------------------------------------------------------------
# Attack loop
# ---------------------------------------------------------------------------

def run_attack(target_ip: str, target_port: int, duration: float) -> None:
    """Launch synflood against target for `duration` seconds, then kill it."""
    log.info("START attack → %s:%d for %.1fs", target_ip, target_port, duration)
    try:
        proc = subprocess.Popen(
            [BINARY, target_ip, str(target_port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.info("STOP  attack → %s:%d", target_ip, target_port)
    except FileNotFoundError:
        log.error("Binary not found: %s", BINARY)
    except Exception as e:
        log.error("Attack failed: %s", e)


def main() -> None:
    log.info("Attack orchestrator starting")
    log.info(
        "Binary: %s | delay %.0f–%.0fs | duration %.0f–%.0fs",
        BINARY, DELAY_MIN, DELAY_MAX, DURATION_MIN, DURATION_MAX,
    )

    # Initial sleep so the network has time to come up before the first attack.
    initial = random.uniform(DELAY_MIN, DELAY_MAX)
    log.info("Waiting %.1fs before first attack...", initial)
    time.sleep(initial)

    while True:
        target_ip   = random.choice(TARGETS)
        target_port = random.choice(PORTS)
        duration    = random.uniform(DURATION_MIN, DURATION_MAX)

        run_attack(target_ip, target_port, duration)

        delay = random.uniform(DELAY_MIN, DELAY_MAX)
        log.info("Next attack in %.1fs", delay)
        time.sleep(delay)


if __name__ == "__main__":
    if os.environ.get("GEN_SYNFLOOD_TRAFFIC", "").lower() in ["1", "true", "yes"]:
        main()
