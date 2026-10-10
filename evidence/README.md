# Evidence

Everything here backs a number or a claim in [../results/REPORT.md](../results/REPORT.md).

## The raw data

| Where | What it holds |
| --- | --- |
| `../pcaps/sample_*.pcap` | The packet captures the detectors were tested on: four synthetic ones with known contents, and real ones (a localhost nmap scan, an nmap SYN scan of a Kali VM, DNS lookups of random names, and two beacons with different timing) |
| `../results/detector_results.csv` | How many alerts each detector raised on each capture |
| `../results/beacon_sensitivity.csv` | The beacon detector's alerts at several thresholds |
| `../results/normal_margins.txt` | How close 5 minutes of real normal traffic came to each threshold |
| `../tests/` | 10 tests that assert the right answer for each known capture |

The 5-minute real normal capture (`pcaps/normal.pcap`) is **not** in the repo, because a raw capture can contain other programs' traffic. `results/normal_margins.txt` records what it showed, and `scripts/margins.py` reproduces that on any capture.

## The images (`images/`)

| Image | What it shows | Which claim it backs |
| --- | --- | --- |
| `detector_results.png` | Every detector on every capture, green where the answer is right and red where it is wrong | All three detectors found their attack, were quiet on normal traffic, and one beacon was missed |
| `wireshark_cross_check.png` | The same captures counted by Wireshark's own tool (`tshark`) next to my detectors' counts | The counts are independently confirmed: 1000 and 999 scan probes, 37 and 35 beacon connections, 67 DNS queries, and timing variation 0.024 and 0.215 |
| `port_scan_margin.png` | The busiest 10-second window of each capture against the alert line of 20 | Normal traffic stayed well under the line (10) and scans were far over it (about 1000) |
| `beacon_timing_tradeoff.png` | Left: the real connection times of the regular and the jittery beacon. Right: their timing variation next to the threshold | The jittery beacon is missed, and loosening the threshold to catch it would also flag an ordinary polling program |
| `dns_length_vs_entropy.png` | Each DNS name as a point: length against randomness, with the alert zone shaded | Ordinary names sit bottom-left; names that look like smuggled data sit far into the alert zone |
| `proof_tests.png` | Real output of the unit tests | The detectors behave as described, including the recorded weaknesses |
| `proof_margins.png` | Real output of `scripts/margins.py` on the real normal capture | The margins quoted in the report |

## How the images were made

`python -m scripts.make_images` regenerates all of them. The charts are computed from the capture files, the cross-check runs `tshark` on them, and the terminal images are the actual text printed by the commands the script runs. Images that use the private `normal.pcap` are redrawn only when that file is present; otherwise the committed picture is kept. Nothing is drawn by hand or edited afterwards.

## What this evidence does not show

- One 5-minute real capture is too small to estimate a false-positive rate. Zero alerts is a lower bound.
- The Kali VM had no listening services, so the Kali scan shows closed ports only. The detector keys on the scanner's packets, so it fires either way, but a host with many open ports was not tested.
- The cross-check shows the counts are right, not that the thresholds (20 ports, 25 characters, 0.1) are the best choice.
