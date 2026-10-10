"""Detector 1: port scans.

Rule, in plain words: if ONE source sends connection-opening packets (SYN, no
ACK) to 20 or more different destination ports within 10 seconds, call it a
port scan.

Why it works: a normal program opens a few connections to a few ports. A scanner
knocks on many ports quickly to see which ones answer.

Limits (know these): a busy legitimate client, or a vulnerability scanner your
own IT team runs, can trip it. A slow scan (one port a minute) stays under the
radar because it never reaches 20 ports in 10 seconds.

    python scripts/port_scan.py pcaps/sample_portscan.pcap
"""
import sys
from collections import Counter, defaultdict

from scapy.all import IP, TCP, PcapReader

WINDOW_SECONDS = 10
PORT_THRESHOLD = 20


def is_syn_only(pkt):
    """True for a packet that opens a connection: SYN set, ACK not set."""
    flags = int(pkt[TCP].flags)
    return (flags & 0x02) != 0 and (flags & 0x10) == 0


def find_port_scans(path, window=WINDOW_SECONDS, threshold=PORT_THRESHOLD):
    """Return one alert per suspicious source, using its busiest time window."""
    # attempts[source] = list of (time, destination, port) for each SYN it sent
    attempts = defaultdict(list)
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and is_syn_only(pkt):
                attempts[pkt[IP].src].append(
                    (float(pkt.time), pkt[IP].dst, pkt[TCP].dport))

    alerts = []
    for source, events in attempts.items():
        events.sort()
        in_window = Counter()      # (destination, port) -> how many SYNs in the window
        left = 0
        best = (0, None)           # (distinct targets, window start time)
        for right in range(len(events)):
            in_window[events[right][1:]] += 1
            # slide the left edge forward until the window is `window` seconds wide
            while events[right][0] - events[left][0] > window:
                key = events[left][1:]
                in_window[key] -= 1
                if in_window[key] == 0:
                    del in_window[key]
                left += 1
            if len(in_window) > best[0]:
                best = (len(in_window), events[left][0])
        if best[0] >= threshold:
            alerts.append({"source": source, "distinct_targets": best[0],
                           "window_start": best[1]})
    return alerts


if __name__ == "__main__":
    found = find_port_scans(sys.argv[1])
    if not found:
        print("no port scans found")
    for a in found:
        print(f"PORT SCAN from {a['source']}: {a['distinct_targets']} different "
              f"ports within {WINDOW_SECONDS} s")
