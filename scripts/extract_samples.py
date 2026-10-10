"""Cut small, shareable sample files out of the raw captures.

    python scripts/extract_samples.py

The raw captures in pcaps/ stay out of git because they can contain traffic
from other programs on the computer (see .gitignore). This script keeps only
the packets that belong to the tests we ran on purpose, and writes them as
pcaps/sample_*.pcap, which ARE committed.

    scan_localhost.pcap     -> sample_scan_localhost.pcap    nmap against 127.0.0.1, ports 1-1000
    dns_tunnel_real.pcap    -> sample_dnstunnel_real.pcap    only the names ending in .t.example.com
    beacon_regular.pcap     -> sample_beacon_regular.pcap    already filtered to port 8080
    beacon_jittery.pcap     -> sample_beacon_jittery.pcap    already filtered to port 8080
    scan_kali.pcap          -> sample_scan_kali.pcap         nmap SYN scan of a Kali VM, already filtered to that VM
"""
from pathlib import Path

from scapy.all import DNS, DNSQR, TCP, PcapReader, PcapWriter

PCAPS = Path(__file__).resolve().parent.parent / "pcaps"


def cut(source, destination, keep):
    kept = total = 0
    writer = PcapWriter(str(PCAPS / destination))
    with PcapReader(str(PCAPS / source)) as reader:
        for pkt in reader:
            total += 1
            if keep(pkt):
                writer.write(pkt)
                kept += 1
    writer.close()
    print(f"{source}: kept {kept} of {total} packets -> {destination}")


def is_scan_traffic(pkt):
    """TCP packets to or from a port in 1-1000: the range nmap was told to scan."""
    return pkt.haslayer(TCP) and (pkt[TCP].dport <= 1000 or pkt[TCP].sport <= 1000)


def is_tunnel_dns(pkt):
    return (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)
            and b".t.example.com" in pkt[DNSQR].qname.lower())


if __name__ == "__main__":
    cut("scan_localhost.pcap", "sample_scan_localhost.pcap", is_scan_traffic)
    cut("dns_tunnel_real.pcap", "sample_dnstunnel_real.pcap", is_tunnel_dns)
    cut("beacon_regular.pcap", "sample_beacon_regular.pcap", lambda pkt: True)
    cut("beacon_jittery.pcap", "sample_beacon_jittery.pcap", lambda pkt: True)
    cut("scan_kali.pcap", "sample_scan_kali.pcap", lambda pkt: True)
