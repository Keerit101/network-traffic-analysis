"""Record network traffic to a .pcap file.

    python scripts/capture.py --iface "Wi-Fi" --seconds 300 --out pcaps/normal.pcap
    python scripts/capture.py --list            # show interface names

Packets are written to disk as they arrive, so memory use stays small.

PRIVACY: a capture records every packet on the interface, including DNS names
and IP addresses of whatever else the computer is doing. That is why real
captures stay out of git (see .gitignore). Only small captures of traffic you
created on purpose, such as a scan of your own VM, should be committed.
"""
import argparse

from scapy.all import PcapWriter, conf, sniff


def list_interfaces():
    for iface in conf.ifaces.values():
        print(f"{iface.name:<32} {getattr(iface, 'ip', '') or '-':<18} {iface.description[:45]}")


def capture(iface, seconds, out, bpf_filter=None):
    writer = PcapWriter(out, sync=True)   # sync=True writes each packet immediately
    count = 0

    def on_packet(pkt):
        nonlocal count
        writer.write(pkt)
        count += 1

    sniff(iface=iface, timeout=seconds, prn=on_packet, store=False, filter=bpf_filter)
    writer.close()
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", help="interface name, e.g. Wi-Fi")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--out", default="pcaps/capture.pcap")
    parser.add_argument("--filter", default=None, help="optional BPF filter, e.g. 'host 192.168.56.101'")
    parser.add_argument("--list", action="store_true", help="list interfaces and exit")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
    else:
        n = capture(args.iface, args.seconds, args.out, args.filter)
        print(f"captured {n} packets to {args.out}")
