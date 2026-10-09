# Project 2 — Network Traffic Analysis

## Goal
Capture and analyze network traffic, understand normal vs. suspicious patterns, and write simple detectors for common attack/malware behaviors.

## Data sources
- **My own captures:** Wireshark/tshark on my machine while browsing, plus a port scan of my **own** VM (VirtualBox) with nmap
- **Public datasets** (pick 1–2):
  - malware-traffic-analysis.net (exercise pcaps; password-protected zips, so handle them in an isolated VM)
  - CIC-IDS2017 / CSE-CIC-IDS2018 (labeled intrusion traffic)
  - Wireshark sample captures wiki

## Tasks
1. **Capture** (`pcaps/`): record 5–10 min of normal traffic and a separate capture during a self-scan
2. **Explore** (`notebooks/`)
   - Protocol hierarchy, top talkers, conversation stats (`tshark -z io,phs`, `-z conv,ip`)
   - DNS queries, HTTP hosts, TLS SNI
3. **Detect** (`scripts/`)
   - `port_scan.py`: one source hitting many ports/hosts in a short window (SYN without completed handshake)
   - `dns_anomaly.py`: long/high-entropy subdomains (possible DNS tunneling), NXDOMAIN bursts
   - `beaconing.py`: regular-interval connections to the same host (possible C2)
4. **Report** (`results/`): findings with screenshots, Wireshark filters used, IOCs, and false positive notes

## Useful Wireshark filters
```
tcp.flags.syn==1 && tcp.flags.ack==0     # SYN-only (scan indicator)
dns && frame.len > 150                   # unusually large DNS
http.request                              # HTTP requests
tls.handshake.extensions_server_name      # TLS SNI
```

## Deliverables
- [ ] At least 2 captures + 1 public pcap analyzed
- [ ] 3 detection scripts with sample output
- [ ] `results/REPORT.md` with findings

> Don't commit large or sensitive pcaps. `pcaps/` is gitignored except for small samples.

## Schedule (week of Oct 12, 2026)

- **Wed:** capture own traffic + public pcaps, protocol breakdown, write 3 detectors, write `results/REPORT.md`
