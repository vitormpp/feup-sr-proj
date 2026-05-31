# Layer 3: BGP Hijacking Eclipse Attack

This module executes a global routing infrastructure attack to isolate the victim node at the Network layer.

### Network Architecture
* **The Real World (Main Chain):** AS 161 (`.71` Miner) and AS 162 (`.71` Miner)
* **The Victim:** AS 160 (`as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71`)
* **The Attacker (The Hijacker):** AS 161 Border Router (`as161brd-router0-10.161.0.254`)

---

## Phase 1: The Eclipse Attack (BGP Hijacking)

> **Automation Alternative:** To execute the automated attack sequence instead of entering the step-by-step terminal commands below, ensure your environment is initialized (`docker-compose up -d`) and run [`python3 bgp_eclipse_attack.py`](bgp_eclipse_attack.py) from the Host VM.

> **Important Pre-Attack Check:** Before launching the attack, ensure that all nodes are actively mining and that block heights are increasing globally. This can be verified using the **Check Current Block Heights** diagnostic block in the [Master Guide Appendix](../README.md#diagnostics). Execute it sequentially to confirm the block numbers are rising before proceeding.
> 
We will utilize the AS161 Border Router (`.254`) to announce a rogue BGP route to the global Internet Exchange (IX). By falsely claiming a more-specific route to the Victim's address (`10.160.0.71`), we will manipulate the other ASes into routing all traffic destined for the Victim directly into our attacker network, where it will be dropped into a black hole.

**1. Open a terminal inside the Attacker Border Router:**
```bash
docker exec -it as161brd-router0-10.161.0.254 /bin/bash
```

**2. Inject the Malicious Route (Inside Attacker Router):**
The SeedEmu architecture utilizes the BIRD routing daemon. We will create a static route targeting the Victim's exact IP address (`10.160.0.71/32`), bind it to the `t_direct` routing table, and instruct BGP to export this anomaly.

Open the BIRD configuration file:

```bash
nano /etc/bird/bird.conf
```

Scroll to the end of the file and append the following block:

```text
protocol static hijack {
    ipv4 { 
        table t_direct; 
    };
    route 10.160.0.71/32 blackhole;
}
```

**3. Trigger the Global BGP Update:**
Instruct BIRD to reload the configuration, prompting it to broadcast the poisoned route via an UPDATE message to the Route Server:

```bash
birdc configure
```
**4. Verify the Eclipse (From Host VM):**
Inspect AS162's border router routing table to confirm P2P traffic is now being misdirected to the Attacker AS (AS161) instead of the legitimate Victim AS (AS160).

```bash
docker exec -it as162brd-router0-10.162.0.254 ip route get 10.160.0.71
```

> **Expected Output:** The route should state `via 10.103.0.161` (AS161's IX connection). The Victim is now physically isolated from the consensus network.

---

## Phase 2: The Double Spend Execution

*Note: The network partition is now established. To execute the conflicting transactions and observe the resulting state divergence, proceed to **[Phase 2 in the Master Guide](../README.md#phase-2-the-double-spend)**.*

*Once the account balances have diverged across the network, return to this document to initiate the chain reorganization (Phase 3).*

---

## Phase 3: The Chain Reorganization (The Vanish)

In Proof-of-Work, the chain with the highest total difficulty is accepted as the canonical truth. Because the main network possesses the combined hashing power of two miners (Nodes 161 and 162), it holds a significant statistical advantage. Given sufficient time, the main network's chain will reliably outpace and become heavier than the isolated Victim's chain (Node 160). We will now withdraw the malicious BGP route to allow network convergence.

**1. Release the Victim (Inside Attacker Border Router Terminal):**
Remove the malicious route from the BIRD configuration.

```bash
nano /etc/bird/bird.conf
```

*Delete the entire `protocol static hijack { ... }` block previously added.*

**2. Broadcast the BGP Withdrawal:**
Apply the configuration changes to trigger a BGP `WITHDRAW` message across the global network:

```bash
birdc configure
```

**3. Observe the Consensus Resolution:**
Within seconds, the global routing tables will correct themselves. Node 160's P2P packets will successfully reach its peers. Node 160 will reconnect, evaluate the block heights, and recognize its local chain has a lower total difficulty. It will discard its isolated blocks (orphan the 5 ETH transaction) and adopt the canonical chain.

Execute the balance diagnostic on Node 160 to confirm:

```bash
docker exec -it as160h-Ethereum-POW-00-Miner-BootNode-10.160.0.71 geth attach --exec '["0xCBF1e330F0abD5c1ac979CF2B2B874cfD4902E24", "0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9", "0xaB5AaD8284868B91Eb537d28aB1A159740D54890"].forEach(addr => { console.log(addr + ": " + web3.fromWei(eth.getBalance(addr), "ether") + " ETH") })'
```

> **Final Expected Output (Node 160):**
> Origin: `8.999 ETH`
> Victim: `30 ETH` *(The 5 ETH transaction is successfully reversed)*
> Bob: `1 ETH`

The Double Spend exploit is complete. The attacker has successfully retained their funds (now secured by Bob) while the victim's ledger no longer reflects the payment for the released goods.
