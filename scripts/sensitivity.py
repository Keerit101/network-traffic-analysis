"""Show how the beacon detector's threshold changes what it catches.

    python -m scripts.sensitivity

The beacon rule flags a flow when the variation in its timing is at or below a
threshold. A higher threshold catches sloppier beacons but also flags more
ordinary software. This prints the number of alerts at several thresholds so the
choice of 0.1 can be explained with data instead of guessed.
"""
import csv
from pathlib import Path

from scripts.beaconing import find_beacons

PCAPS = Path(__file__).resolve().parent.parent / "pcaps"
RESULTS = Path(__file__).resolve().parent.parent / "results"
THRESHOLDS = [0.05, 0.1, 0.2, 0.3, 0.5]

# (file, what is really in it)
CAPTURES = [
    ("normal.pcap", "real normal traffic (no beacon)"),
    ("sample_normal.pcap", "synthetic normal, includes a mail poller with +/-30% jitter"),
    ("sample_beacon_regular.pcap", "real beacon, +/-4% timing"),
    ("sample_beacon_jittery.pcap", "real beacon, +/-40% timing"),
    ("sample_beacon.pcap", "synthetic beacon, +/-0.5 s on 30 s"),
]

if __name__ == "__main__":
    header = ["capture", "what it contains"] + [f"<= {t}" for t in THRESHOLDS]
    rows = []
    for name, description in CAPTURES:
        row = [name, description]
        for threshold in THRESHOLDS:
            row.append(len(find_beacons(PCAPS / name, max_variation=threshold)))
        rows.append(row)

    print(f"{'capture':<28}" + "".join(f"{h:>8}" for h in header[2:]))
    for r in rows:
        print(f"{r[0]:<28}" + "".join(f"{v:>8}" for v in r[2:]))

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "beacon_sensitivity.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
