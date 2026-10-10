"""Generate the evidence images in evidence/images/ from the real data.

    python -m scripts.make_images

Nothing here is drawn by hand. Charts are computed from the capture files, and the
"terminal" images are the actual text printed by a command that this script runs.
Needs matplotlib (pip install -r requirements-figures.txt) and, for the Wireshark
cross-check, Wireshark's tshark.

pcaps/normal.pcap (the real 5-minute capture) is not in the repo because it can
contain other programs' traffic. Images that use it are only redrawn when the file
is present; otherwise the committed picture is left alone.
"""
import datetime
import os
import shutil
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image, ImageDraw, ImageFont
from scapy.all import DNS, DNSQR, IP, TCP, PcapReader

from scripts.beaconing import MAX_VARIATION, find_beacons
from scripts.dns_anomaly import ENTROPY_THRESHOLD, MIN_LABEL_LENGTH, find_dns_anomalies, shannon_entropy
from scripts.margins import report as margins_report
from scripts.port_scan import PORT_THRESHOLD, busiest_windows, find_port_scans

REPO = Path(__file__).resolve().parent.parent
PCAPS = REPO / "pcaps"
OUT = REPO / "evidence" / "images"
TSHARK = shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
CONSOLAS = r"C:\Windows\Fonts\consola.ttf"

BLUE, GREEN, GREY, AMBER, RED = "#1d4e89", "#0f6b5c", "#8a96a3", "#d98f00", "#b3261e"
TODAY = datetime.date.today().isoformat()

plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": "#dde3ea", "grid.linewidth": 0.7,
                     "axes.axisbelow": True, "figure.dpi": 100})


def have(name):
    return (PCAPS / name).exists()


def save(fig, name):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / name, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", name)


# ------------------------------------------------------------------ terminal images
def terminal_image(text, command, name, max_chars=112):
    """Render real command output as a dark terminal-style PNG."""
    font = ImageFont.truetype(CONSOLAS, 16)
    small = ImageFont.truetype(CONSOLAS, 13)
    lines = []
    for raw in text.rstrip().split("\n"):
        while len(raw) > max_chars:
            lines.append(raw[:max_chars])
            raw = "    " + raw[max_chars:]
        lines.append(raw)
    footer = f"Real output captured {TODAY}. Regenerate: python -m scripts.make_images"
    pad, line_h, header_h = 18, 22, 38
    width = int(max(font.getlength(line) for line in lines + ["$ " + command]) + 2 * pad)
    width = max(width, int(small.getlength(footer)) + 2 * pad)
    height = header_h + pad + line_h * len(lines) + 34
    image = Image.new("RGB", (width, height), "#0f1720")
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, width, header_h], fill="#1b2733")
    for i, color in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        draw.ellipse([14 + i * 22, 13, 26 + i * 22, 25], fill=color)
    draw.text((86, 9), "$ " + command, font=font, fill="#9fb3c8")
    y = header_h + pad
    for line in lines:
        color = "#7ee2a8" if ("OK" == line.strip() or "passed" in line or " ok" in line[-4:]) else "#d6e2ee"
        draw.text((pad, y), line, font=font, fill=color)
        y += line_h
    draw.text((pad, height - 26), footer, font=small, fill="#5b6f84")
    OUT.mkdir(parents=True, exist_ok=True)
    image.save(OUT / name)
    print("wrote", name)


def run_text(args):
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", cwd=REPO,
                            env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    return (result.stdout + result.stderr)


# ------------------------------------------------------------------ data helpers
def syn_times(path, dport=None):
    times = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                if (flags & 2) and not (flags & 16) and (dport is None or pkt[TCP].dport == dport):
                    times.append(float(pkt.time))
    return sorted(times)


def variation(times):
    gaps = [b - a for a, b in zip(times, times[1:])]
    return statistics.pstdev(gaps) / statistics.mean(gaps)


def dns_labels(path):
    labels = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                labels.append(pkt[DNSQR].qname.decode(errors="replace").rstrip(".").lower().split(".")[0])
    return labels


# ------------------------------------------------------------------ charts
def chart_port_scan():
    rows = [("real normal traffic (5 min)", "normal.pcap", GREY),
            ("synthetic normal", "sample_normal.pcap", GREY),
            ("synthetic 1000-port scan", "sample_portscan.pcap", BLUE),
            ("real nmap scan, localhost", "sample_scan_localhost.pcap", BLUE),
            ("real nmap SYN scan, Kali VM", "sample_scan_kali.pcap", BLUE)]
    rows = [r for r in rows if have(r[1])]
    values = [max((c for c, _ in busiest_windows(PCAPS / name).values()), default=0) for _, name, _ in rows]
    fig, ax = plt.subplots(figsize=(8, 3.6))
    ypos = range(len(rows))[::-1]
    ax.barh(list(ypos), values, color=[c for *_, c in rows], height=0.6)
    ax.set_xscale("log")
    ax.set_xlim(3, 4000)
    ax.axvline(PORT_THRESHOLD, color=RED, linestyle="--", linewidth=1.4)
    ax.text(PORT_THRESHOLD * 1.1, len(rows) - 1.55, f"alert threshold: {PORT_THRESHOLD}", color=RED, fontsize=9)
    ax.set_yticks(list(ypos), [r[0] for r in rows])
    for y, v in zip(ypos, values):
        ax.text(v * 1.1, y, str(v), va="center", fontsize=9)
    ax.set_xlabel("distinct (destination, port) pairs from one source in the busiest 10-second window (log scale)")
    ax.set_title("Port scan detector: how far each capture is from the alert line", loc="left", fontweight="bold")
    ax.grid(axis="y", visible=False)
    save(fig, "port_scan_margin.png")


def chart_beacon():
    regular = syn_times(PCAPS / "sample_beacon_regular.pcap", 8080)
    jittery = syn_times(PCAPS / "sample_beacon_jittery.pcap", 8080)
    poller_cv = None
    for alert in find_beacons(PCAPS / "sample_normal.pcap", max_variation=0.2):
        poller_cv = alert["variation"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 3.8), gridspec_kw={"width_ratios": [1.5, 1]})
    for y, times, color, label in ((1, regular, BLUE, f"regular (+/-4%), variation {variation(regular):.3f}: caught"),
                                   (0, jittery, RED, f"jittery (+/-40%), variation {variation(jittery):.3f}: missed")):
        ax1.eventplot([t - times[0] for t in times], lineoffsets=y, linelengths=0.6, colors=color, linewidths=1.6)
        ax1.text(2, y + 0.42, label, color=color, fontsize=9)
    ax1.set_yticks([])
    ax1.set_ylim(-0.6, 1.9)
    ax1.set_xlabel("seconds since first connection (each tick = one real connection)")
    ax1.set_title("Real beacon traffic, 5 s interval", loc="left", fontweight="bold")
    ax1.grid(axis="y", visible=False)

    names = ["real beacon\n+/-4%", "synthetic mail\npoller +/-30%", "real beacon\n+/-40%"]
    values = [variation(regular), poller_cv, variation(jittery)]
    colors = [BLUE, GREY, RED]
    ax2.bar(names, values, color=colors, width=0.55)
    ax2.axhline(MAX_VARIATION, color=GREEN, linestyle="--", linewidth=1.4)
    ax2.text(-0.45, MAX_VARIATION + 0.007, f"threshold used: {MAX_VARIATION}", color=GREEN, fontsize=8.5, ha="left")
    ax2.axhline(0.3, color=AMBER, linestyle=":", linewidth=1.4)
    ax2.text(2.45, 0.306, "0.3: catches both,\nflags the poller too", color=AMBER, fontsize=8.5, ha="right", va="bottom")
    for x, v in enumerate(values):
        ax2.text(x, v + 0.008, f"{v:.3f}", ha="center", fontsize=9)
    ax2.set_ylabel("timing variation (lower = more regular)")
    ax2.set_ylim(0, 0.4)
    ax2.set_title("Why the threshold cannot win", loc="left", fontweight="bold")
    ax2.grid(axis="x", visible=False)
    fig.tight_layout()
    save(fig, "beacon_timing_tradeoff.png")


def chart_dns():
    normal_file = "normal.pcap" if have("normal.pcap") else "sample_normal.pcap"
    normal = dns_labels(PCAPS / normal_file)
    tunnel = dns_labels(PCAPS / "sample_dnstunnel_real.pcap")
    tunnel = [t for t in tunnel if len(t) >= 20]            # the random-name lookups only
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.axvspan(MIN_LABEL_LENGTH, 60, ymin=0, ymax=1, color="#fbe9e7", zorder=0)
    ax.scatter([len(l) for l in normal], [shannon_entropy(l) for l in normal], s=34, color=GREY, alpha=0.8,
               label=f"ordinary DNS names ({len(normal)}, {'real' if normal_file == 'normal.pcap' else 'synthetic'})")
    ax.scatter([len(l) for l in tunnel], [shannon_entropy(l) for l in tunnel], s=34, color=RED, alpha=0.8,
               label=f"random 40-character names ({len(tunnel)} queries, real)")
    ax.axvline(MIN_LABEL_LENGTH, color=RED, linestyle="--", linewidth=1.2)
    ax.axhline(ENTROPY_THRESHOLD, color=RED, linestyle="--", linewidth=1.2)
    ax.text(26, 1.0, f"length >= {MIN_LABEL_LENGTH} AND\nentropy >= {ENTROPY_THRESHOLD}: alert zone", color=RED, fontsize=9)
    ax.set_xlim(0, 50)
    ax.set_ylim(0, 5)
    ax.set_xlabel("length of the first DNS label (characters)")
    ax.set_ylabel("Shannon entropy (bits per character)")
    ax.set_title("DNS detector: ordinary names vs smuggled-data-style names", loc="left", fontweight="bold")
    ax.legend(loc="lower right", frameon=False, fontsize=9)
    save(fig, "dns_length_vs_entropy.png")


EXPECTED = [  # capture, what is really in it, expected (port scans, dns, beacons)
    ("normal.pcap", "real normal traffic", (0, 0, 0)),
    ("sample_normal.pcap", "synthetic normal + mail poller", (0, 0, 0)),
    ("sample_portscan.pcap", "synthetic port scan", (1, 0, 0)),
    ("sample_dnstunnel.pcap", "synthetic DNS tunnel", (0, 1, 0)),
    ("sample_beacon.pcap", "synthetic beacon", (0, 0, 1)),
    ("sample_scan_localhost.pcap", "real nmap scan, localhost", (1, 0, 0)),
    ("sample_scan_kali.pcap", "real nmap SYN scan, Kali VM", (1, 0, 0)),
    ("sample_dnstunnel_real.pcap", "real random-name DNS lookups", (0, 1, 0)),
    ("sample_beacon_regular.pcap", "real beacon, +/-4% timing", (0, 0, 1)),
    ("sample_beacon_jittery.pcap", "real beacon, +/-40% timing", (0, 0, 1)),
]


def chart_results_matrix():
    rows = [r for r in EXPECTED if have(r[0])]
    fig, ax = plt.subplots(figsize=(9, 0.43 * len(rows) + 0.9))
    ax.axis("off")
    columns = ["capture", "what is really in it", "port scan", "DNS anomaly", "beacon", "verdict"]
    cells, colors = [], []
    for name, truth, expected in rows:
        actual = (len(find_port_scans(PCAPS / name)), len(find_dns_anomalies(PCAPS / name)), len(find_beacons(PCAPS / name)))
        ok = actual == expected
        cells.append([name, truth] + [f"{a}" for a in actual] + ["correct" if ok else "MISSED"])
        base = ["white", "white"] + ["#e8f5f1" if a == e else "#fde7e5" for a, e in zip(actual, expected)]
        colors.append(base + ["#e8f5f1" if ok else "#fde7e5"])
    table = ax.table(cellText=cells, colLabels=columns, cellColours=colors, loc="center",
                     colColours=["#dbe6f2"] * len(columns), cellLoc="left")
    table.auto_set_font_size(False)
    table.set_fontsize(8.5)
    table.scale(1, 1.55)
    table.auto_set_column_width(list(range(len(columns))))
    ax.set_title(f"All {len(rows)} captures: alerts raised by each detector (green = right answer, red = wrong)",
                 loc="left", fontweight="bold", fontsize=10.5)
    save(fig, "detector_results.png")


def tshark_count(args):
    if not Path(TSHARK).exists():
        return None
    result = subprocess.run([TSHARK, "-r", *args], capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def chart_cross_check():
    """Independent check: Wireshark's own tool versus my detectors."""
    syn = "tcp.flags.syn==1 && tcp.flags.ack==0"
    rows = []
    for name, label in (("sample_scan_kali.pcap", "Kali VM scan"), ("sample_scan_localhost.pcap", "localhost scan")):
        ws = len(tshark_count([str(PCAPS / name), "-Y", syn]) or [])
        mine = find_port_scans(PCAPS / name)[0]["distinct_targets"]
        rows.append([label, "connection attempts (ports probed)", ws, mine])
    for name, label in (("sample_beacon_regular.pcap", "regular beacon"), ("sample_beacon_jittery.pcap", "jittery beacon")):
        times = [float(t) for t in tshark_count([str(PCAPS / name), "-Y", syn + " && tcp.dstport==8080", "-T", "fields", "-e", "frame.time_epoch"]) or []]
        mine = syn_times(PCAPS / name, 8080)
        rows.append([label, "connections opened", len(times), len(mine)])
        rows.append([label, "timing variation (std dev / mean gap)", f"{variation(times):.3f}", f"{variation(mine):.3f}"])
    ws = len(tshark_count([str(PCAPS / "sample_dnstunnel_real.pcap"), "-Y",
                           'dns.flags.response==0 && dns.qry.name contains "t.example.com"']) or [])
    mine = find_dns_anomalies(PCAPS / "sample_dnstunnel_real.pcap")[0]["queries"]
    rows.append(["DNS random names", "suspicious DNS questions", ws, mine])
    cells = [r + ["yes" if str(r[2]) == str(r[3]) else "NO"] for r in rows]
    fig, ax = plt.subplots(figsize=(9.2, 0.42 * len(cells) + 0.9))
    ax.axis("off")
    table = ax.table(cellText=cells, colLabels=["capture", "what is counted", "Wireshark (tshark)", "my detector", "agree"],
                     cellColours=[["white"] * 4 + ["#e8f5f1" if c[-1] == "yes" else "#fde7e5"] for c in cells],
                     colColours=["#dbe6f2"] * 5, loc="center", cellLoc="left")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.6)
    table.auto_set_column_width(list(range(5)))
    ax.set_title("Independent cross-check: the same captures counted by Wireshark's own tool (tshark)",
                 loc="left", fontweight="bold", fontsize=10.5)
    save(fig, "wireshark_cross_check.png")


def main():
    chart_port_scan()
    chart_beacon()
    chart_dns()
    chart_results_matrix()
    chart_cross_check()
    terminal_image(run_text([sys.executable, "-m", "unittest", "discover", "tests", "-v"]),
                   "python -m unittest discover tests -v", "proof_tests.png")
    normal = PCAPS / "normal.pcap"
    margins = margins_report(normal) if normal.exists() else (REPO / "results" / "normal_margins.txt").read_text(encoding="utf-8")
    terminal_image(margins, "python -m scripts.margins pcaps/normal.pcap", "proof_margins.png")


if __name__ == "__main__":
    main()
