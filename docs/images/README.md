# Documentation screenshots

**Every screenshot here is of the fictional demo network** created by
[`video/seed_demo.py`](../../video/seed_demo.py) — an invented family home whose PC is called
`HOME-PC`, on a Wi-Fi network called `Home-WiFi`, behind the RFC 5737 documentation address
`203.0.113.42`, with eighteen made-up devices. It is not a real home, and nothing in these
images comes off anybody's real network: no real hostname, no real MAC address, no real public
IP. (`13-architecture.png` is not a screenshot at all — it is the architecture diagram, drawn
by [`video/slides.py`](../../video/slides.py).)

Regenerate them all with:

```
python video/seed_demo.py --force     # only if video/demo_data/homesoc.db is missing
python video/shoot_docs.py
```

Each image is 1600x900, rendered in the dark theme at 2x and downsampled, so the text stays
sharp on a high-DPI display.

| Image | What it shows |
| --- | --- |
| [`01-overview.png`](01-overview.png) | The Overview: security score and grade, open findings by severity, the device count, 24 hours of DNS filtering and what to fix first. |
| [`02-activity-feed.png`](02-activity-feed.png) | The activity feed — one timeline of everything that happened, with the kind chips and filters that narrow it. |
| [`03-summary.png`](03-summary.png) | The security summary: score, found all time, remediated and still open, over the found-versus-remediated-by-severity chart. |
| [`04-findings.png`](04-findings.png) | The findings list, open only and sorted by severity, so the criticals and highs come first. |
| [`05-finding-detail.png`](05-finding-detail.png) | A critical finding expanded — the exposed Telnet service on the unknown camera, with its evidence and its numbered remediation steps. |
| [`06-devices.png`](06-devices.png) | The device inventory: every address on the LAN with its vendor, kind, open findings and when it was last seen. |
| [`07-device-detail.png`](07-device-detail.png) | One device in detail — the unknown camera: its four open services, the CVE matched against its web server, and the six findings raised on it. |
| [`08-vulnerabilities.png`](08-vulnerabilities.png) | The CVE table matched from service banners — the KEV badge and the EPSS column that decide what gets fixed first, with the one KEV row opened. |
| [`09-host-posture.png`](09-host-posture.png) | Host posture on Windows: the Defender panel, pending updates, and the posture checks with their measured and expected values. |
| [`10-dns-filter.png`](10-dns-filter.png) | The DNS filter: queries and block rate over 24 hours, blocked requests per hour in red, and the domains being blocked most. |
| [`11-telemetry.png`](11-telemetry.png) | Telemetry: the metrics the agent records about itself and the scheduler's job table, with run counts, failures, durations and last errors. |
| [`12-scans.png`](12-scans.png) | Scan history — every scan the agent has run, what kind it was, how long it took and what it found. |
| [`13-architecture.png`](13-architecture.png) | The architecture diagram: definition feeds into scanners, scanners into the findings engine, and the engine into the dashboard, alerts and the DNS filter. |
