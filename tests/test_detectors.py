"""Check each detector against captures whose contents we know.

    python -m unittest discover tests

The expected answers come from how scripts/make_sample_pcaps.py builds each
file: normal has nothing bad, and each attack file has exactly one attack.
"""
import unittest
from pathlib import Path

from scripts.beaconing import find_beacons
from scripts.dns_anomaly import find_dns_anomalies, shannon_entropy
from scripts.port_scan import find_port_scans

PCAPS = Path(__file__).resolve().parent.parent / "pcaps"


def sample(name):
    return PCAPS / f"sample_{name}.pcap"


class TestPortScan(unittest.TestCase):
    def test_finds_the_scan(self):
        alerts = find_port_scans(sample("portscan"))
        self.assertEqual([a["source"] for a in alerts], ["10.0.0.66"])
        self.assertEqual(alerts[0]["distinct_targets"], 1000)

    def test_quiet_on_other_captures(self):
        for name in ("normal", "dnstunnel", "beacon"):
            self.assertEqual(find_port_scans(sample(name)), [], name)

    def test_slow_scan_is_missed(self):
        # Known weakness: a scanner under 20 ports per 10 seconds is invisible.
        alerts = find_port_scans(sample("portscan"), window=10, threshold=2000)
        self.assertEqual(alerts, [])


class TestDnsAnomaly(unittest.TestCase):
    def test_finds_the_tunnel(self):
        alerts = find_dns_anomalies(sample("dnstunnel"))
        self.assertEqual([a["domain"] for a in alerts], ["tunnel-example.com"])
        self.assertEqual(alerts[0]["queries"], 60)

    def test_quiet_on_other_captures(self):
        for name in ("normal", "portscan", "beacon"):
            self.assertEqual(find_dns_anomalies(sample(name)), [], name)

    def test_entropy_values(self):
        self.assertEqual(shannon_entropy("aaaa"), 0)
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0)
        self.assertGreater(shannon_entropy("ix6ea6qom66zjojyaekctbr6y3z4ixgci7nq3t2y"), 3.5)


class TestBeaconing(unittest.TestCase):
    def test_finds_the_beacon(self):
        alerts = find_beacons(sample("beacon"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["destination"], "203.0.113.7")
        self.assertEqual(alerts[0]["port"], 8443)

    def test_quiet_on_other_captures(self):
        # sample_normal contains a mail poller with +/- 30% jitter. It must NOT
        # be flagged, which shows why the threshold is 0.1 and not higher.
        for name in ("normal", "portscan", "dnstunnel"):
            self.assertEqual(find_beacons(sample(name)), [], name)


if __name__ == "__main__":
    unittest.main()
