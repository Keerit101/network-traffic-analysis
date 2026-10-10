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
- **Real** (nmap against localhost, DNS lookups, a program beaconing to a local server, 5 minutes of normal traffic): messier and more convincing, and it found the miss.

## The files
`stats.py` summarizes a capture. `capture.py` records traffic (Scapy sniffs and writes packets straight to disk). `run_detectors.py` runs everything and writes a table. `sensitivity.py` repeats the beacon rule at several thresholds. `extract_samples.py` cuts clean, shareable files out of raw captures, because raw ones can contain other programs' traffic. `tests/test_detectors.py` asserts the expected answer for each known capture, including two recorded weaknesses.

## Questions you may be asked
1. **If HTTPS is encrypted, what can you still see?** Addresses, ports, timing, packet sizes and DNS names.
2. **How does your port scan detector work, and why 20 ports in 10 seconds?** Sliding window over SYN-only packets. The numbers are my choice: normal traffic in my capture never came close (the busiest source hit 31 pairs across five minutes but never 20 in 10 seconds). Slow scans evade it.
3. **What is entropy and why use it?** Average unpredictability per character; random-looking strings score high. I also need the length rule, because entropy alone was borderline on real traffic.
4. **What did your detectors get wrong?** They missed the +/-40% jittery beacon. Raising the threshold to catch it flagged an ordinary mail poller, so I kept 0.1 and documented the miss.
5. **Why the synthetic captures?** With real traffic you do not know the ground truth. Synthetic files let me test correctness; real ones test realism.
6. **Is one normal capture enough to claim a low false-positive rate?** No. It is five minutes from one computer; zero alerts is a lower bound on how noisy these rules would be elsewhere.
7. **Why scan localhost instead of another machine?** I planned to use a Kali VM, but it is on an isolated virtual network and the computer was short of memory. Localhost produced real scan traffic; the detector counts connection-opening packets either way.
8. **Was this legal?** Yes. I only scanned my own computer, and sent DNS lookups for names under example.com, which is reserved for testing.
