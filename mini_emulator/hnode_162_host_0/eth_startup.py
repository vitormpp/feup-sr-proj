#!/usr/bin/env python3
"""
Ethereum node startup script.
Runs after the container has finished all other setup.
Starts a loop that sends random ETH transactions at random intervals.
"""

import socket
import datetime
import time
import random
import logging

from web3 import Web3
# NEW (web3 < 6.x / Python 3.8 environment)
from web3.middleware import geth_poa_middleware

# ── Configuration ────────────────────────────────────────────────────────────

RPC_URL          = "http://localhost:8545"
CHAIN_ID         = 1337

# Accounts that are unlocked in geth (see start.sh --unlock flag)
SENDER_ACCOUNTS = [
    "0x8c400205fDb103431F6aC7409655ad3cf8f6d007",
    "0x9105A373ce1d01B517aA54205A5E4c70FA9f34Fe",
]

# Pool of destination addresses drawn from the genesis alloc
RECIPIENT_POOL   = [
    "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9",
    "0x2e2e3a61daC1A2056d9304F79C168cD16aAa88e9",
    "0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24",
    "0xA2a28c011e281CA0dA0D878A82d854FD789C154c",
    "0x513C434dBA61AE5CFEf4552daC2D2f85450870aA",
    "0xBaED4A4Fffff4e047B8a39F00284732eF6244f4B",
    "0xF5D434D36dD2bF53d2D1dB4FD40076A0C1C44F8d",
    "0x3eE934c34747460C7083Ad052bab58E6DF5dbd84",
    "0x94Bfb5a96B191011892e23bceB2d1ae22B4f1C25",
    "0x468DaF3c6E9a79255F4b2985A3801C791Aa9037d",
    "0xf77d3Bb88460C58784c3112A1289D68105e28f60",
    "0x477a4e1fcdF12Cb8bAba4eAD4c43F1fF26cCeD12",
    "0x830EB42863505ACf1127905C835B6A7a36760Fa0",
    "0x1081c645CC8c21EfbB0114eAc5fcDBE01a1a4b19",
    "0xa6bBf9891a0689Fe91d9c1538478b95effe0a57A",
    "0x8c400205fDb103431F6aC7409655ad3cf8f6d007",
    "0x9105A373ce1d01B517aA54205A5E4c70FA9f34Fe",
]

# Amount range to send per transaction (in ETH)
MIN_ETH = 0.001
MAX_ETH = 0.1

# Delay range between transactions (in seconds)
MIN_DELAY = 5
MAX_DELAY = 30

# How long to wait for geth to become ready before starting (seconds)
GETH_READY_TIMEOUT = 60*20

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("eth_loop")

# ── Helpers ──────────────────────────────────────────────────────────────────

def wait_for_geth(w3: Web3) -> bool:
    while True:
        try:
            if w3.is_connected():
                chain_id = w3.eth.chain_id
                log.info("Connected to geth (chain ID %s)", chain_id)
                return True
            else:
                log.info("w3.is_connected() returned False")
        except Exception as e:
            log.info("Connection attempt failed: %s: %s", type(e).__name__, e)
        time.sleep(3)
        


def send_random_tx(w3: Web3) -> None:
    """Pick a random sender/recipient/amount and broadcast a transaction."""
    sender    = random.choice(SENDER_ACCOUNTS)
    recipient = random.choice([a for a in RECIPIENT_POOL if a.lower() != sender.lower()])
    amount_eth = round(random.uniform(MIN_ETH, MAX_ETH), 6)
    amount_wei = w3.to_wei(amount_eth, "ether")

    # Check the sender has enough balance (leave some for gas)
    balance = w3.eth.get_balance(sender)
    gas_price = w3.eth.gas_price
    gas_limit = 21_000
    if balance < amount_wei + gas_price * gas_limit:
        log.warning("Sender %s has insufficient balance (%s ETH), skipping",
                    sender, w3.from_wei(balance, "ether"))
        return

    tx_hash = w3.eth.send_transaction({
        "from":     sender,
        "to":       Web3.to_checksum_address(recipient),
        "value":    amount_wei,
        "gas":      gas_limit,
        "gasPrice": gas_price,
    })

    log.info("Sent %.6f ETH  |  %s → %s  |  tx: %s",
             amount_eth, sender[:10] + "…", recipient[:10] + "…", tx_hash.hex())


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    hostname  = socket.gethostname()
    timestamp = datetime.datetime.now().isoformat()
    log.info("[%s] Ethereum node '%s' startup script running.", timestamp, hostname)

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    # Required for PoA / clique / ethash dev chains that add extra data to headers
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    if not wait_for_geth(w3, GETH_READY_TIMEOUT):
        log.error("Geth RPC never became ready after %ss — exiting.", GETH_READY_TIMEOUT)
        return

    log.info("Starting random transaction loop  (%.3f–%.3f ETH every %d–%ds)",
             MIN_ETH, MAX_ETH, MIN_DELAY, MAX_DELAY)

    while True:
        try:
            send_random_tx(w3)
        except Exception as exc:
            log.error("Transaction failed: %s", exc)

        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        log.debug("Sleeping %.1fs until next transaction…", delay)
        time.sleep(delay)


if __name__ == "__main__":
    main()