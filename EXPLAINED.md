# EXPLAINED: the ideas and files in plain English

## The big picture
Most traffic today is encrypted, so you cannot read what is inside it. But you can still see **who talked to whom, on which port, when, and how much**. That metadata is enough to spot a lot of attacks. Each detector here is one simple rule over that metadata.

## Background you need
- A **packet** is one small chunk of data on the network. A **pcap** file is a recording of packets.
- A **TCP connection** starts with a three-way handshake: the client sends **SYN**, the server answers **SYN-ACK**, the client sends **ACK**. A packet with SYN set and ACK not set means "I want to open a connection".
- **DNS** turns names (like example.com) into addresses. A DNS query is a question, and its first **label** is the part before the first dot.
- **Port**: a number that says which service on a machine you are talking to (443 for HTTPS, 22 for SSH).

## The three detectors

### `port_scan.py`: someone is knocking on every door
- **Attack:** a scanner (like nmap) sends a SYN to many ports quickly to find which ones answer.
- **Rule:** one source sends SYN-only packets to 20 or more different (destination, port) pairs within 10 seconds.
- **How the code works:** it collects every SYN-only packet per source, sorts them by time, then slides a 10-second window along them and counts how many different targets are inside it (a "sliding window" with two pointers).
- **Weakness:** a slow scan stays under the limit. An IT team's own scanner would trigger it.

### `dns_anomaly.py`: data smuggled out through DNS
- **Attack:** DNS is rarely blocked, so malware encodes stolen data into names like `k3j9...zq.attacker.com`; the attacker's DNS server reads the data from the questions.
- **Rule:** the first label is 25+ characters AND has entropy of 3.5+ bits per character, and a domain gets flagged after 5 such queries.
- **Entropy** measures how unpredictable the characters are. `aaaa` scores 0. A random 40-character string scores about 4.5. A normal word scores low.
- **Why two conditions:** in my real normal capture, entropy alone was borderline (a short label reached 3.50). The length requirement is what keeps normal traffic quiet.
- **Weakness:** malware using short labels or real words is not caught; services that use long random names are false positives.

### `beaconing.py`: a program phoning home on a timer
- **Attack:** malware checks in with its controller every N seconds.
- **Rule:** at least 8 connections to the same destination and port, with gaps varying by 10% or less. Variation = standard deviation of the gaps divided by their average (the "coefficient of variation"). A perfect metronome scores 0.
- **Weakness:** jitter. A beacon with +/-40% timing scored 0.215 and was missed. Loosening the threshold to 0.3 caught it but also flagged an ordinary mail poller. **Timing alone cannot tell them apart.**

## Why two kinds of test captures
- **Synthetic** (`make_sample_pcaps.py`): built by hand so I know the right answer. Good for checking the code is correct. Because I built them to be detectable, a perfect score here proves less.
- **Real** (nmap against localhost and against a Kali VM, DNS lookups, a program beaconing to a local server, 5 minutes of normal traffic): messier and more convincing, and it found the miss.

## The files
`stats.py` summarizes a capture. `capture.py` records traffic (Scapy sniffs and writes packets straight to disk). `run_detectors.py` runs everything and writes a table. `sensitivity.py` repeats the beacon rule at several thresholds. `extract_samples.py` cuts clean, shareable files out of raw captures, because raw ones can contain other programs' traffic. `tests/test_detectors.py` asserts the expected answer for each known capture, including two recorded weaknesses.

## The evidence, explained
A detector that says "I found an attack" is only worth something if you can show it was right. So the repo keeps the proof in one place: `evidence/` (index: `evidence/README.md`). There are two kinds: the **raw data** the detectors ran on, and **images** made from it.

### The raw data
- **The captures** (`pcaps/sample_*.pcap`): a capture is a recording of network packets. Four are synthetic, built by `make_sample_pcaps.py` so I know exactly what is inside. The others are real, recorded on my own machine: an nmap scan of localhost, an nmap SYN scan of my Kali VM, DNS lookups of random names, and two beacons (one with regular timing, one with irregular timing).
- **The saved results**: `results/detector_results.csv` (alerts per detector per capture), `results/beacon_sensitivity.csv` (the beacon rule at several thresholds) and `results/normal_margins.txt` (how close real normal traffic came to each threshold).
- **The tests** (`tests/`): 10 tests that assert the right answer for each known capture, including two recorded weaknesses.
- **One thing is deliberately missing:** the 5-minute real normal capture. A raw capture can contain other programs' traffic, so it stays private. `results/normal_margins.txt` records what it showed, and `scripts/margins.py` reproduces that on any capture.

### The images (`evidence/images/`)
Each one is generated by `python -m scripts.make_images`; none is drawn by hand.
| Image | How to read it | What it proves |
| --- | --- | --- |
| `detector_results.png` | A table: one row per capture, one column per detector. Green means the right answer, red means wrong. | All three detectors found their attack and stayed quiet on normal traffic. The single red cell is the real miss (the beacon with irregular timing). |
| `wireshark_cross_check.png` | Wireshark's own command-line tool, `tshark`, counted the same things as my detectors. | The numbers are independently confirmed: 1000 and 999 scan probes, 37 and 35 beacon connections, 67 DNS queries, timing variation 0.024 and 0.215. A different program, written by different people, agrees with me. |
| `port_scan_margin.png` | Bars show the most distinct ports one machine tried in any 10-second window. The red dashed line is the alert threshold (20). | Normal traffic reached only 10, far under the line; the scans reached about 1000. |
| `beacon_timing_tradeoff.png` | Left: each tick is a real connection, so a regular beacon looks like a ruler and the jittery one looks uneven. Right: the timing variation of each against the threshold. | The jittery beacon (0.215) sits above my threshold (0.1) and is missed. Loosening the threshold to 0.3 would catch it but also flag an ordinary mail poller (0.186). Timing alone cannot tell them apart. |
| `dns_length_vs_entropy.png` | Each dot is one DNS name: how long its first part is, and how random it looks. The pink area is the alert zone. | Ordinary names cluster bottom-left. The 40-character random names sit far inside the alert zone. |
| `proof_tests.png`, `proof_margins.png` | A picture of the real terminal output of the tests and of `margins.py`. | The tests pass, and the margins quoted in the report are real. |

### The one number worth remembering
The localhost scan shows **999** probes, not 1000. nmap reported port 137 as filtered and no packet for it appears in the capture. Wireshark and my detector both count 999, which is exactly why a cross-check is useful.

### What the evidence cannot show
One 5-minute capture is too small to estimate a false-positive rate. The Kali VM had no open ports, so that scan shows closed ports only. And the cross-check proves the counts are right, not that my thresholds (20 ports, 25 characters, 0.1) are the best choice.

## Questions you may be asked
1. **If HTTPS is encrypted, what can you still see?** Addresses, ports, timing, packet sizes and DNS names.
2. **How does your port scan detector work, and why 20 ports in 10 seconds?** Sliding window over SYN-only packets. The numbers are my choice: normal traffic in my capture stayed well under it (the closest any source came was 10 distinct ports in one 10-second window; `scripts/margins.py` prints this). Slow scans evade it.
3. **What is entropy and why use it?** Average unpredictability per character; random-looking strings score high. I also need the length rule, because entropy alone was borderline on real traffic.
4. **What did your detectors get wrong?** They missed the +/-40% jittery beacon. Raising the threshold to catch it flagged an ordinary mail poller, so I kept 0.1 and documented the miss.
5. **Why the synthetic captures?** With real traffic you do not know the ground truth. Synthetic files let me test correctness; real ones test realism.
6. **Is one normal capture enough to claim a low false-positive rate?** No. It is five minutes from one computer; zero alerts is a lower bound on how noisy these rules would be elsewhere.
7. **What did you scan?** My own machine (localhost, a connect scan) and my own Kali VM (a true SYN scan, after moving its adapter onto a host-only network and restoring it afterward). Kali had no open ports, so every probe got a reset; the detector counts the scanner's connection-opening packets, so it fires either way, but I did not test a target with many open ports.
8. **Was this legal?** Yes. I only scanned my own computer and my own virtual machine, and sent DNS lookups for names under example.com, which is reserved for testing.
9. **How do you know your detectors' counts are right?** I counted the same captures with Wireshark's own tool (`tshark`) and it agrees on every row, including the timing variation. That is an independent check, because Wireshark is a different program written by different people.
10. **Why is the real normal capture not in the repo?** A raw capture can contain other programs' traffic. I saved what it showed in `results/normal_margins.txt`, and `scripts/margins.py` reproduces that on any capture.
11. **Why are there synthetic captures if you have real ones?** With a synthetic capture I know exactly what is inside, so I can check the detector is correct. Real captures show it works on messy traffic, and they are where the miss showed up.
12. **Why does the localhost scan show 999 probes and not 1000?** nmap reported port 137 as filtered and no packet for it appears in the capture. Wireshark and my detector both count 999.
