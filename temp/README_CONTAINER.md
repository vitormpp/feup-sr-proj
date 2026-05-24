# Running Eclipse Attack Transactions from the Attacker Container

These helper scripts are designed for execution inside the attacker container
`as162h-new_eth_node-10.162.0.74`.

## Why this works

From inside the attacker container, the Node 162 attacker can reach the victim
and main-network Ethereum RPC endpoints directly by IP:

* Victim (isolated) RPC: `http://10.162.0.71:8545`
* Real network RPC: `http://10.161.0.71:8545`

That means the double-spend transaction flow can run entirely from the attacker
container without needing host VM `docker exec` or the host network environment.

The original host-side `eclipse_attack.py` workflow still exists, but
`container_arp_spoof.py` provides a container-native L2 isolation path.

## Files

* `container_tx.py` - sends either the fake or real transaction.
* `container_eclipse_attack.py` - helper wrapper that sends both the fake and
  real transactions in one command.
* `container_arp_spoof.py` - performs the Layer 2 ARP eclipse attack from
  inside the attacker container.

## Usage

1. Make sure the attacker container has access to this directory.
   If you are not mounting the repo into the container, copy these files into
   the attacker container first.

2. Run from inside the attacker container:

```bash
python3 /path/to/eclipse/container_tx.py --type fake
python3 /path/to/eclipse/container_tx.py --type real
```

To run the L2 ARP eclipse attack from inside the attacker container:

```bash
python3 /path/to/eclipse/container_arp_spoof.py
```

Or use both transaction scripts together:

```bash
python3 /path/to/eclipse/container_eclipse_attack.py
```

## Notes

* The transaction scripts will attempt to install `web3` and `eth-account`
  using pip if they are not already available.
* The ARP spoofing script will attempt to install `scapy` if needed.
* If you want to skip package installation, add `--skip-install` to
  `container_tx.py` or `container_arp_spoof.py`.
* The scripts preserve the same transaction parameters used by the host VM
  attack scripts.
