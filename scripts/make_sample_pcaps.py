"""Build small synthetic capture files where we KNOW what is inside.

    python scripts/make_sample_pcaps.py

Real traffic is messy and you never know the ground truth. These files are
built by hand so the detectors can be tested against a known answer:

    sample_normal.pcap     ordinary browsing-like traffic, nothing malicious
    sample_portscan.pcap   normal traffic + one host scanning 1000 ports
    sample_dnstunnel.pcap  normal traffic + DNS queries that look like smuggled data
    sample_beacon.pcap     normal traffic + a host calling home every 30 seconds

The random generator is seeded, so running this twice gives identical files.
Only reserved example addresses are used (10.0.0.0/24 for the local network,
203.0.113.0/24 and 198.51.100.0/24 for "internet" servers, example domains).
"""
import random
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, wrpcap

PCAP_DIR = Path(__file__).resolve().parent.parent / "pcaps"
START = 1_790_000_000.0  # an arbitrary start time, in seconds since 1970

CLIENT = "10.0.0.5"
RESOLVER = "10.0.0.1"
SERVERS = ["203.0.113.10", "203.0.113.20", "198.51.100.30", "198.51.100.40"]
NORMAL_NAMES = ["www.example.com", "api.example.com", "cdn.example.net",
                "mail.example.org", "static.example.com", "login.example.net",
                "images.example.org", "updates.example.com"]


def stamp(pkt, t):
    pkt.time = t
    return pkt


def dns_query(src, name, t, sport):
    pkt = Ether() / IP(src=src, dst=RESOLVER) / UDP(sport=sport, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=name))
    return stamp(pkt, t)


def dns_answer(src, name, t, sport, answer_ip):
    pkt = Ether() / IP(src=RESOLVER, dst=src) / UDP(sport=53, dport=sport) / DNS(
        qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
        an=DNSRR(rrname=name, rdata=answer_ip))
    return stamp(pkt, t)


def tcp_connection(src, dst, dport, t, sport):
    """A full three-way handshake plus a short exchange and a clean close."""
    return [
        stamp(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=100), t),
        stamp(Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=500, ack=101), t + 0.02),
        stamp(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=501), t + 0.03),
        stamp(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=501) / (b"x" * 200), t + 0.05),
        stamp(Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=501, ack=301) / (b"y" * 800), t + 0.09),
        stamp(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=301, ack=1301), t + 0.12),
    ]


def normal_traffic(rng, duration=900):
    """DNS lookup then a connection, at random times, for several sites.

    Includes one mail-client-style poller that connects about every 60 seconds
    but with jitter, because real software is never perfectly regular. Over 15
    minutes it connects about 15 times, enough for the beacon detector to
    actually evaluate it (the detector ignores flows with fewer than 8
    connections). It is there to test the detector against ordinary polling.
    """
    packets = []
    port = 40000
    for _ in range(180):
        t = START + rng.uniform(0, duration)
        name = rng.choice(NORMAL_NAMES)
        server = rng.choice(SERVERS)
        port += 1
        packets.append(dns_query(CLIENT, name, t, port))
        packets.append(dns_answer(CLIENT, name, t + 0.03, port, server))
        packets += tcp_connection(CLIENT, server, rng.choice([80, 443, 443, 443]), t + 0.05, port + 20000)

    t = START + 5
    while t < START + duration:
        port += 1
        packets += tcp_connection(CLIENT, "203.0.113.50", 993, t, port + 20000)
        t += 60 * rng.uniform(0.7, 1.3)   # 60 s, give or take 30 percent
    return packets


def port_scan(rng):
    """One host sends a SYN to ports 1-1000 on one target within about 5 seconds."""
    scanner, target = "10.0.0.66", "10.0.0.20"
    open_ports = {22, 80, 443}
    packets = []
    t = START + 120
    for dport in range(1, 1001):
        t += 0.005
        sport = 50000 + rng.randint(0, 100)
        packets.append(stamp(Ether() / IP(src=scanner, dst=target) / TCP(sport=sport, dport=dport, flags="S"), t))
        if dport in open_ports:
            packets.append(stamp(Ether() / IP(src=target, dst=scanner) / TCP(sport=dport, dport=sport, flags="SA"), t + 0.001))
            packets.append(stamp(Ether() / IP(src=scanner, dst=target) / TCP(sport=sport, dport=dport, flags="R"), t + 0.002))
        else:
            packets.append(stamp(Ether() / IP(src=target, dst=scanner) / TCP(sport=dport, dport=sport, flags="RA"), t + 0.001))
    return packets


def dns_tunnel(rng):
    """Queries whose first label is 40 random characters, all to one domain.

    This is what data smuggled out through DNS looks like: the 'name' is
    really the encoded data.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    packets = []
    t = START + 100
    for i in range(60):
        t += rng.uniform(0.5, 2.0)
        label = "".join(rng.choice(alphabet) for _ in range(40))
        packets.append(dns_query("10.0.0.23", f"{label}.t.tunnel-example.com", t, 41000 + i))
    return packets


def beacon():
    """A host contacts the same server and port every 30 seconds, +/- 0.5 s."""
    rng = random.Random(7)
    packets = []
    t = START + 10
    for i in range(20):
        packets += tcp_connection("10.0.0.23", "203.0.113.7", 8443, t, 45000 + i)
        t += 30 + rng.uniform(-0.5, 0.5)
    return packets


def save(name, packets):
    PCAP_DIR.mkdir(exist_ok=True)
    packets = sorted(packets, key=lambda p: float(p.time))
    path = PCAP_DIR / name
    wrpcap(str(path), packets)
    print(f"wrote {path.name}: {len(packets)} packets")


if __name__ == "__main__":
    # a new generator per file, with a fixed seed, so each file is reproducible
    save("sample_normal.pcap", normal_traffic(random.Random(1)))
    save("sample_portscan.pcap", normal_traffic(random.Random(1)) + port_scan(random.Random(2)))
    save("sample_dnstunnel.pcap", normal_traffic(random.Random(1)) + dns_tunnel(random.Random(3)))
    save("sample_beacon.pcap", normal_traffic(random.Random(1)) + beacon())
