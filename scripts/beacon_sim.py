"""Create REAL beacon-like traffic, entirely on this computer.

    python scripts/beacon_sim.py --seconds 180 --interval 5 --jitter 0.04 --port 8080

A tiny server listens on 127.0.0.1. A client connects to it every `interval`
seconds, plus or minus a random `jitter` (a fraction: 0.04 means +/- 4 percent).
Nothing leaves your machine. Capture the loopback interface while this runs:

    python scripts/capture.py --iface "Loopback Pseudo-Interface 1" --seconds 190 \\
        --filter "tcp port 8080" --out pcaps/beacon_regular.pcap

Use a small jitter to make a regular beacon, and a large one (0.4) to see the
timing detector miss a beacon that is deliberately irregular.
"""
import argparse
import random
import socket
import threading
import time


def serve(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen()
    while True:
        conn, _ = server.accept()
        conn.recv(1024)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        conn.close()


def beacon(port, seconds, interval, jitter):
    end = time.time() + seconds
    count = 0
    while time.time() < end:
        with socket.create_connection(("127.0.0.1", port)) as conn:
            conn.sendall(b"GET /checkin HTTP/1.1\r\nHost: localhost\r\n\r\n")
            conn.recv(1024)
        count += 1
        time.sleep(interval * (1 + random.uniform(-jitter, jitter)))
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--jitter", type=float, default=0.04)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    threading.Thread(target=serve, args=(args.port,), daemon=True).start()
    time.sleep(0.5)
    n = beacon(args.port, args.seconds, args.interval, args.jitter)
    print(f"made {n} connections, every {args.interval} s +/- {args.jitter * 100:.0f}%")
