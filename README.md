# Network Traffic Analysis

Three small Python detectors that read a packet capture and flag a port scan, DNS tunneling, or a beacon, tested on captures where I know what is inside and on real traffic from my own computer.

**Headline result:** all three detectors found their attack in both synthetic and real captures and stayed quiet on 5 minutes of real normal traffic, with one honest miss: a beacon with 40% timing jitter slipped past the timing rule, and loosening the rule enough to catch it also flags an ordinary mail-polling program. Details, margins and limitations are in [results/REPORT.md](results/REPORT.md).

> Scope: everything was captured on my own computer or my own virtual machine. Nothing was scanned or sent to anyone else's systems.

## What's here

| Path | What it does |
| --- | --- |
| `scripts/stats.py` | Packet counts, protocols, top talkers for a capture |
| `scripts/port_scan.py` | Detector: 20+ different ports from one source within 10 s |
| `scripts/dns_anomaly.py` | Detector: long, random-looking DNS names sent to one domain |
| `scripts/beaconing.py` | Detector: very regular connection timing to one destination |
| `scripts/run_detectors.py` | Runs all three on many captures, writes `results/detector_results.csv` |
| `scripts/sensitivity.py` | Shows how the beacon threshold changes what is caught |
| `scripts/capture.py` | Records traffic to a `.pcap` (works without administrator rights) |
| `scripts/make_sample_pcaps.py` | Builds synthetic captures with known contents |
| `scripts/beacon_sim.py`, `dns_tunnel_sim.py`, `generate_browsing.py` | Create the test traffic on purpose |
| `scripts/extract_samples.py` | Cuts the committed `sample_*.pcap` files out of raw captures |
| `pcaps/` | The committed samples. Raw captures stay out of git (they can contain other programs' traffic) |
| `tests/` | 10 tests that check each detector against captures with known contents |

[EXPLAINED.md](EXPLAINED.md) explains each detector and the questions you may be asked.

## Run it

Needs Python 3.12 and [Npcap](https://npcap.com) (installed with Wireshark) for capturing. The detectors only need Scapy.

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
python scripts/make_sample_pcaps.py
python scripts/port_scan.py pcaps/sample_portscan.pcap
python -m scripts.run_detectors pcaps/sample_*.pcap
python -m unittest discover tests
```
