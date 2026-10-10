"""Send DNS lookups whose names look like smuggled data, to test the DNS detector.

    python scripts/dns_tunnel_sim.py --count 60

Each lookup is for a name such as  k3j9...(40 random characters).t.example.com.
example.com is reserved for documentation and testing, and these names do not
exist, so every lookup simply fails. The point is the traffic pattern, not an
answer. Capture the network interface while it runs (filter: udp port 53).
"""
import argparse
import random
import socket
import time

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def lookup(name):
    try:
        socket.gethostbyname(name)
    except socket.gaierror:
        pass   # expected: the name does not exist


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=60)
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()

    for _ in range(args.count):
        label = "".join(random.choice(ALPHABET) for _ in range(40))
        lookup(f"{label}.t.example.com")
        time.sleep(args.delay)
    print(f"sent {args.count} lookups")
