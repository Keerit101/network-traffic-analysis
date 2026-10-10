"""Detector 2: DNS tunneling (data smuggled out inside DNS names).

Rule, in plain words: a DNS query is suspicious if its first label (the part
before the first dot) is at least 25 characters long AND looks random. A domain
gets flagged if it receives 5 or more suspicious queries.

"Looks random" is measured with Shannon entropy, the average number of bits of
surprise per character. Normal names like "mail" or "www" are predictable and
score low. A 40-character string of random letters scores around 4.5.

Why it works: DNS is rarely blocked, so malware can encode stolen data into
names like  k3j9x...zq.evil.example  and let its own DNS server read them.

Limits (know these): some legitimate services use long random-looking names
(tracking, CDNs, some security products), which are false positives. Malware
that uses short or dictionary-word labels would not be flagged.

    python scripts/dns_anomaly.py pcaps/sample_dnstunnel.pcap
"""
import math
import sys
from collections import Counter, defaultdict

from scapy.all import DNS, DNSQR, PcapReader

MIN_LABEL_LENGTH = 25
ENTROPY_THRESHOLD = 3.5      # bits per character
QUERIES_PER_DOMAIN = 5


def shannon_entropy(text):
    """Average bits of surprise per character. 0 means every character is the same."""
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def base_domain(name):
    """The last two labels: a.b.c.example.com -> example.com."""
    labels = name.split(".")
    return ".".join(labels[-2:])


def find_dns_anomalies(path):
    suspicious = defaultdict(list)    # base domain -> list of suspicious query names
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            # qr == 0 means a question (not an answer)
            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0):
                continue
            name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".").lower()
            first_label = name.split(".")[0]
            if (len(first_label) >= MIN_LABEL_LENGTH
                    and shannon_entropy(first_label) >= ENTROPY_THRESHOLD):
                suspicious[base_domain(name)].append(name)

    return [{"domain": domain, "queries": len(names), "example": names[0]}
            for domain, names in suspicious.items() if len(names) >= QUERIES_PER_DOMAIN]


if __name__ == "__main__":
    found = find_dns_anomalies(sys.argv[1])
    if not found:
        print("no DNS anomalies found")
    for a in found:
        print(f"DNS ANOMALY: {a['queries']} random-looking queries to {a['domain']}")
        print(f"    example: {a['example']}")
