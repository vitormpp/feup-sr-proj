#!/usr/bin/env python3
"""
Ethereum node startup script.
Runs after the container has finished all other setup.
"""

import socket
import datetime

def main():
    hostname = socket.gethostname()
    timestamp = datetime.datetime.now().isoformat()
    print(f"[{timestamp}] Hello from Ethereum node '{hostname}'! Startup script running successfully.")

if __name__ == "__main__":
    main()
