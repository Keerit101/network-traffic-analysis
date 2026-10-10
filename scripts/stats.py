"""Basic statistics for a capture file: how big, what protocols, who talks most.

    python scripts/stats.py pcaps/sample_normal.pcap
"""
import sys
from collections import Counter

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, PcapReader


def protocol_of(pkt):
    """Name the most specific protocol we recognize in a packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    return "other"


def analyze(path):
    protocols = Counter()
    sources = Counter()
    conversations = Counter()
    total_bytes = 0
    first_time = last_time = None
    count = 0

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            count += 1
            total_bytes += len(pkt)
            t = float(pkt.time)
            first_time = t if first_time is None else first_time
            last_time = t
            protocols[protocol_of(pkt)] += 1
            if pkt.haslayer(IP):
                sources[pkt[IP].src] += 1
                # sort the two addresses so A->B and B->A count as one conversation
                pair = tuple(sorted((pkt[IP].src, pkt[IP].dst)))
                conversations[pair] += 1

    return {
        "packets": count,
        "bytes": total_bytes,
        "seconds": (last_time - first_time) if count else 0,
        "protocols": protocols,
        "top_sources": sources.most_common(5),
        "top_conversations": conversations.most_common(5),
    }


if __name__ == "__main__":
    result = analyze(sys.argv[1])
    print(f"packets: {result['packets']}   bytes: {result['bytes']}   "
          f"duration: {result['seconds']:.0f} s")
    print("protocols:", dict(result["protocols"]))
    print("top senders:")
    for ip, n in result["top_sources"]:
        print(f"  {ip:<18} {n} packets")
    print("top conversations:")
    for (a, b), n in result["top_conversations"]:
        print(f"  {a} <-> {b}   {n} packets")
