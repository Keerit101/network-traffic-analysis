"""Make ordinary web traffic on purpose, so a capture has something normal in it.

    python scripts/generate_browsing.py --minutes 5

Fetches a handful of public pages at random intervals, the way a person
browsing would. Run it while scripts/capture.py is recording.
"""
import argparse
import random
import time
import urllib.request

SITES = [
    "https://en.wikipedia.org/wiki/Computer_network",
    "https://www.python.org/",
    "https://example.com/",
    "https://www.mozilla.org/en-US/",
    "https://docs.python.org/3/",
    "https://www.iana.org/",
    "https://www.rfc-editor.org/",
    "https://httpbin.org/get",
]


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (traffic-lab)"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            size = len(response.read())
        print(f"fetched {url} ({size} bytes)")
    except Exception as error:     # a failed page is fine; we only want traffic
        print(f"could not fetch {url}: {error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=float, default=5)
    args = parser.parse_args()

    end = time.time() + args.minutes * 60
    while time.time() < end:
        fetch(random.choice(SITES))
        time.sleep(random.uniform(3, 15))   # a person pauses to read
