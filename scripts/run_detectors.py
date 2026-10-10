"""Run all three detectors on one or more captures and print a results table.

    python -m scripts.run_detectors pcaps/sample_normal.pcap pcaps/sample_beacon.pcap

Also writes results/detector_results.csv with one row per capture.
"""
import csv
import sys
from pathlib import Path

from scripts.beaconing import find_beacons
from scripts.dns_anomaly import find_dns_anomalies
from scripts.port_scan import find_port_scans

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def run(paths):
    rows = []
    for path in paths:
        rows.append({
            "capture": Path(path).name,
            "port_scans": len(find_port_scans(path)),
            "dns_anomalies": len(find_dns_anomalies(path)),
            "beacons": len(find_beacons(path)),
        })
    return rows


if __name__ == "__main__":
    rows = run(sys.argv[1:])
    print(f"{'capture':<28}{'port scans':>12}{'dns anomalies':>15}{'beacons':>10}")
    for r in rows:
        print(f"{r['capture']:<28}{r['port_scans']:>12}{r['dns_anomalies']:>15}{r['beacons']:>10}")

    RESULTS_DIR.mkdir(exist_ok=True)
    with open(RESULTS_DIR / "detector_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["capture", "port_scans", "dns_anomalies", "beacons"])
        writer.writeheader()
        writer.writerows(rows)
