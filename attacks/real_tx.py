#!/usr/bin/env python3
from web3 import Web3
from eth_account import Account

# Target: The Healthy Real-World Node
web3 = Web3(Web3.HTTPProvider('http://10.161.0.71:8545'))

# Attacker Origin Account (10 ETH) - MUST USE THE SAME KEY
key = 'e128a6b87aa1d934970fd0f2714dd2fe61c017636725dbfeb5e487cc83bcb7eb'
sender = Account.from_key(key)

# Attacker's "Safe" Address (Bob)
recipient = Web3.toChecksumAddress('0xaB5AaD8284868B91Eb537d28aB1A159740D54890')

tx = {
    'chainId': 1337,
    'nonce': web3.eth.getTransactionCount(sender.address),
    'from': sender.address,
    'to': recipient,
    'value': Web3.toWei("1", 'ether'), 
    'gas': 200000,
    'maxFeePerGas': Web3.toWei('4', 'gwei'),
    'maxPriorityFeePerGas': Web3.toWei('3', 'gwei'),
    'data': b''
}

print(f"[*] REAL TX: Sending 1 ETH to Safe Wallet using Nonce {tx['nonce']}...")
signed_tx = web3.eth.account.sign_transaction(tx, sender.key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)

print(f"[+] REAL TX SENT! Hash: {tx_hash.hex()}")
print("[*] Waiting for the real network to mine the block...")

tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
print(f"[+] REAL TX MINED in Block {tx_receipt['blockNumber']}!")
