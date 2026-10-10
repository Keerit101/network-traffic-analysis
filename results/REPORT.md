# Network traffic analysis: results

## What I did
I wrote three small detectors in Python (Scapy) that read a packet capture (`.pcap`) and flag one kind of suspicious behavior each:

| Detector | Rule |
| --- | --- |
| `port_scan.py` | One source sends connection-opening packets (SYN without ACK) to 20 or more different ports within 10 seconds |
| `dns_anomaly.py` | A domain receives 5 or more DNS queries whose first label is at least 25 characters long and has Shannon entropy of at least 3.5 bits per character |
| `beaconing.py` | A source opens at least 8 connections to the same destination and port, and the gaps between them vary by 10% or less (standard deviation divided by mean) |

I tested them on two kinds of capture:
- **Synthetic captures** that I built myself, so the contents are known exactly (`make_sample_pcaps.py`).
- **Real captures** of traffic created on this computer: nmap scans of localhost and of a Kali Linux virtual machine (my own, on an isolated host-only network), DNS lookups with random names, and a program that really connects to a local server on a timer. I also captured 5 minutes of real normal traffic.

All traffic was my own, on my own machine. Nothing was scanned or sent to anyone else. The only outside traffic was ordinary page fetches from public websites during the normal capture, and DNS lookups for names under `example.com` (a name reserved for testing).

## Results

| Capture | What is really in it | Port scans | DNS anomalies | Beacons | Correct? |
| --- | --- | --- | --- | --- | --- |
| `sample_normal` (synthetic) | Browsing plus a mail poller | 0 | 0 | 0 | Yes |
| `sample_portscan` (synthetic) | Normal plus a 1000-port scan | 1 | 0 | 0 | Yes |
| `sample_dnstunnel` (synthetic) | Normal plus 60 random-name queries | 0 | 1 | 0 | Yes |
| `sample_beacon` (synthetic) | Normal plus a 30 s beacon | 0 | 0 | 1 | Yes |
| `normal.pcap` (real, not committed) | 5 min of real traffic, 12,340 packets | 0 | 0 | 0 | Yes |
| `sample_scan_localhost` (real) | nmap scan of ports 1-1000 on this PC | 1 | 0 | 0 | Yes |
| `sample_scan_kali` (real) | nmap SYN scan of ports 1-1000 on a Kali VM, 1000 SYNs answered by 1000 resets | 1 | 0 | 0 | Yes |
| `sample_dnstunnel_real` (real) | 60 lookups of 40-character random names | 0 | 1 | 0 | Yes |
| `sample_beacon_regular` (real) | Connection every 5 s, +/-4% timing | 0 | 0 | 1 | Yes |
| `sample_beacon_jittery` (real) | Connection every 5 s, +/-40% timing | 0 | 0 | 0 | **No, missed** |

The synthetic captures were built to be detectable, so a perfect score on them only shows the code does what I intended. The real captures are the more meaningful test, and they include one miss.

## How close did normal traffic come to the thresholds?
"Zero alerts" means little without the margin. In the 5-minute real normal capture:
- **Beaconing:** only 1 flow had 8 or more connections, with variation 0.59, far above the 0.1 limit.
- **DNS:** 102 queries; the longest first label was 16 characters, so none reached the 25-character rule. Entropy alone would have been borderline (the highest entropy among labels of 8+ characters was 3.50, against a threshold of 3.5), so the length rule is what keeps normal traffic quiet.
- **Port scan:** the busiest source reached 31 different destination-and-port pairs across the whole 5 minutes, but never 20 within 10 seconds.

## The threshold trade-off (beaconing)
The number of beacon alerts at different variation thresholds (`results/beacon_sensitivity.csv`):

| Capture | <= 0.05 | <= 0.1 | <= 0.2 | <= 0.3 | <= 0.5 |
| --- | --- | --- | --- | --- | --- |
| real normal | 0 | 0 | 0 | 0 | 0 |
| synthetic normal (mail poller, +/-30% jitter) | 0 | 0 | **1** | 1 | 1 |
| real beacon, +/-4% | 1 | 1 | 1 | 1 | 1 |
| real beacon, +/-40% (variation 0.215) | 0 | 0 | 0 | **1** | 1 |

Loosening the threshold far enough to catch the +/-40% beacon (0.3) also flags the +/-30% mail poller. **Timing regularity alone cannot separate a sloppy beacon from a legitimate program that polls on a timer.** I kept 0.1 because it produced no false positives here, accepting that it misses jittery beacons. A real tool would combine timing with other signals (destination reputation, data sizes, process).

## Known limitations
- **Port scan:** a slow scan (under 20 ports per 10 seconds) is invisible. A busy legitimate client or an IT team's own scanner would trigger it.
- **DNS:** malware using short or dictionary-word labels would not be flagged. Services that use long random names would be false positives. The count of 67 queries for 60 lookups is because Windows retries lookups; the detector counts packets, not unique names.
- **Beaconing:** jitter defeats it, and perfectly regular legitimate software (updaters, monitoring agents) would be flagged. It only looks at TCP connection starts.
- **Encrypted traffic:** all three rules use only metadata (addresses, ports, timing, name lengths), so they work on HTTPS. They cannot see what is inside.
- **Small data:** one 5-minute real capture is not enough to estimate a false-positive rate. The zero here is a lower bound on how noisy these rules would be on a busy network.
- **Scan targets:** the localhost scan used full TCP connections (nmap `-sT`). The Kali VM scan was a true SYN scan (`-sS`), but a default Kali has no listening services, so all 1000 ports were closed and answered with resets. The detector only looks at the scanner's connection-opening packets, so it fires either way, but I have not tested a scan against a machine with many open ports. To make the VM reachable I temporarily moved its network adapter onto the host-only network, then restored its original settings.

## Reproduce
```
python -m venv .venv && .venv\Scripts\pip install -r requirements.txt
python scripts/make_sample_pcaps.py            # rebuild the synthetic captures
python -m scripts.run_detectors pcaps/sample_*.pcap
python -m scripts.sensitivity
python -m unittest discover tests
```
Raw captures (`pcaps/normal.pcap` and others) are not in the repo because they can contain traffic from other programs on the computer. `scripts/extract_samples.py` shows how the committed `sample_*` files were cut from them.
