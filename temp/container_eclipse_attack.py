#!/usr/bin/env python3
"""Wrap fake and real Eclipse transactions for attacker-container execution."""

import argparse
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TX_SCRIPT = os.path.join(SCRIPT_DIR, "container_tx.py")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Send both fake and real Eclipse attack transactions from inside the attacker container",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--skip-fake",
        action="store_true",
        help="Send only the real transaction",
    )
    parser.add_argument(
        "--skip-real",
        action="store_true",
        help="Send only the fake transaction",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for receipts from either transaction",
    )
    return parser.parse_args()


def run_tx(tx_type, no_wait):
    cmd = [sys.executable, TX_SCRIPT, "--type", tx_type]
    if no_wait:
        cmd.append("--no-wait")
    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{tx_type} transaction failed with exit code {result.returncode}")


def main():
    args = parse_args()
    if args.skip_fake and args.skip_real:
        print("ERROR: both --skip-fake and --skip-real were passed; nothing to do")
        sys.exit(1)

    if not args.skip_fake:
        print("\n=== Sending fake transaction to isolated victim ===\n")
        run_tx("fake", args.no_wait)

    if not args.skip_real:
        print("\n=== Sending real transaction to the main network ===\n")
        run_tx("real", args.no_wait)

    print("\n[+] Container-based Eclipse transaction flow complete")


if __name__ == "__main__":
    main()
