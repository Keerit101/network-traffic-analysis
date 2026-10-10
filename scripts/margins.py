"""How close did a capture come to each detector's threshold?

    python -m scripts.margins pcaps/normal.pcap

"No alerts" only means something if you know the margin. For each rule this
prints the closest the capture came to triggering it. It runs on any capture; the
output for the real normal capture is saved in results/normal_margins.txt (the
capture itself is not committed because it can contain other programs' traffic).
"""
import statistics
import sys
from collections import defaultdict

from scapy.all import DNS, DNSQR, IP, TCP, PcapReader

from scripts.beaconing import MAX_VARIATION, MIN_AVERAGE_GAP, MIN_CONNECTIONS
from scripts.dns_anomaly import ENTROPY_THRESHOLD, MIN_LABEL_LENGTH, shannon_entropy
from scripts.port_scan import PORT_THRESHOLD, WINDOW_SECONDS, busiest_windows


def connection_starts_and_dns_labels(path):
    starts = defaultdict(list)       # (src, dst, port) -> times a connection was opened
    labels = []                      # first label of every DNS question
    packets = 0
    first = last = None
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            packets += 1
            t = float(pkt.time)
            first = t if first is None else first
            last = t
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                if (flags & 0x02) and not (flags & 0x10):
                    starts[(pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)].append(t)
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".").lower()
                labels.append(name.split(".")[0])
    return starts, labels, packets, (last - first) if packets else 0


def report(path):
    starts, labels, packets, seconds = connection_starts_and_dns_labels(path)
    lines = [f"capture: {packets} packets over {seconds:.0f} s", ""]

    # --- port scan: busiest window of any source
    busiest = busiest_windows(path)
    if busiest:
        source, (count, _) = max(busiest.items(), key=lambda item: item[1][0])
        lines.append(f"PORT SCAN   rule: {PORT_THRESHOLD}+ distinct (destination, port) pairs from one source within {WINDOW_SECONDS} s")
        lines.append(f"            closest: {count} pairs in one {WINDOW_SECONDS} s window")
    else:
        lines.append("PORT SCAN   no SYN packets in this capture")

    # --- DNS: longest label and highest entropy among long labels
    lines.append("")
    lines.append(f"DNS         rule: first label {MIN_LABEL_LENGTH}+ chars AND entropy {ENTROPY_THRESHOLD}+ bits per char")
    if labels:
        longest = max(labels, key=len)
        long_labels = [label for label in labels if len(label) >= 8]
        top_entropy = max((shannon_entropy(label) for label in long_labels), default=0)
        lines.append(f"            {len(labels)} DNS questions; longest first label {len(longest)} chars; "
                     f"{sum(1 for label in labels if len(label) >= MIN_LABEL_LENGTH)} reach {MIN_LABEL_LENGTH} chars")
        lines.append(f"            highest entropy among labels of 8+ chars: {top_entropy:.2f} "
                     f"(entropy alone would be {'over' if top_entropy >= ENTROPY_THRESHOLD else 'under'} the threshold)")
    else:
        lines.append("            no DNS questions in this capture")

    # --- beaconing: flows long enough to be evaluated, and their variation
    lines.append("")
    lines.append(f"BEACONING   rule: {MIN_CONNECTIONS}+ connections to one destination, average gap {MIN_AVERAGE_GAP:g}+ s, variation <= {MAX_VARIATION}")
    evaluated = []
    for key, times in starts.items():
        if len(times) >= MIN_CONNECTIONS:
            times.sort()
            gaps = [b - a for a, b in zip(times, times[1:])]
            average = statistics.mean(gaps)
            evaluated.append((statistics.pstdev(gaps) / average, len(times), average))
    lines.append(f"            {len(starts)} distinct flows, {len(evaluated)} with enough connections to be evaluated")
    for variation, count, average in sorted(evaluated):
        lines.append(f"            flow with {count} connections, average gap {average:.1f} s, variation {variation:.2f}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(report(sys.argv[1]))
