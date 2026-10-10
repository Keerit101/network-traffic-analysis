"""Detector 3: beaconing (a program calling home on a fixed schedule).

Rule, in plain words: look at every (source, destination, port) triple. If a
source opened at least 8 connections to it, and the gaps between those
connections are very even, call it a beacon.

"Very even" is measured with the coefficient of variation: the standard
deviation of the gaps divided by their average. A perfect metronome scores 0.
We flag anything at or below 0.1, with an average gap of at least 1 second.

Why it works: malware often checks in with its controller every N seconds.
Humans and most software are far less regular than a timer.

Limits (know these): legitimate software also polls on timers (updaters, mail
clients, monitoring agents), and a very regular one is a false positive.
Malware that adds random jitter to its timing can push the score above 0.1 and
escape. The threshold is a trade-off between those two failures.

    python scripts/beaconing.py pcaps/sample_beacon.pcap
"""
import statistics
import sys
from collections import defaultdict

from scapy.all import IP, TCP, PcapReader

MIN_CONNECTIONS = 8
MAX_VARIATION = 0.1          # coefficient of variation
MIN_AVERAGE_GAP = 1.0        # seconds


def find_beacons(path):
    # starts[(source, destination, port)] = times at which a connection was opened
    starts = defaultdict(list)
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                if (flags & 0x02) and not (flags & 0x10):      # SYN without ACK
                    key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                    starts[key].append(float(pkt.time))

    alerts = []
    for (source, destination, port), times in starts.items():
        if len(times) < MIN_CONNECTIONS:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        average = statistics.mean(gaps)
        variation = statistics.pstdev(gaps) / average
        if average >= MIN_AVERAGE_GAP and variation <= MAX_VARIATION:
            alerts.append({"source": source, "destination": destination, "port": port,
                           "connections": len(times), "average_gap": average,
                           "variation": variation})
    return alerts


if __name__ == "__main__":
    found = find_beacons(sys.argv[1])
    if not found:
        print("no beacons found")
    for a in found:
        print(f"BEACON: {a['source']} -> {a['destination']}:{a['port']}  "
              f"{a['connections']} connections, every {a['average_gap']:.1f} s "
              f"(variation {a['variation']:.3f})")
