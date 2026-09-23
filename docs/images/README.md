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

Each image is 1600x900, rendered in the day theme ("Stone & Sage", the default) at 2x and
downsampled, so the text stays sharp on a high-DPI display. The dusk theme looks the same in
a warm dark palette.

The demo dashboard is started with `serve`, which never starts the web-blocking resolver, so
these images say (truthfully) that web blocking is switched on but not running; the look-up
numbers beside it come from the seeded household. The demo's timestamps are moved forward so it
reads as checked a few minutes ago.

| Image | What it shows |
| --- | --- |
| [`01-overview.png`](01-overview.png) | Home (the overview): the one-sentence status, the safety score, what needs fixing by urgency, the devices, web blocking over 24 hours and what to fix first. |
| [`02-activity-feed.png`](02-activity-feed.png) | What happened (the activity feed): one timeline of everything that happened, with each row's urgency in words, and the chips and filters that narrow it. |
| [`03-summary.png`](03-summary.png) | Your safety report (the security summary): score, found all time, fixed and still to fix, over the found-and-fixed-by-urgency chart. |
| [`04-findings.png`](04-findings.png) | Things to fix (the findings list): what needs attention, most urgent first, each with its plain headline, why it matters and the device it is on. |
| [`05-finding-detail.png`](05-finding-detail.png) | A "Fix now" finding opened: the exposed Telnet service on the unnamed camera, with what Home SOC found, how to fix it, and the technical details one click away. |
| [`06-devices.png`](06-devices.png) | Devices: every device by name with its address beside it, its kind, whether it was seen at the last check, what it has to fix and whether it is yours. |
| [`07-device-detail.png`](07-device-detail.png) | One device in detail — the unnamed camera: its open doors (ports), the known software flaw matched against its web server, and what depends on what. |
| [`08-vulnerabilities.png`](08-vulnerabilities.png) | Known software flaws (the CVE table): whether attackers are known to use each one (KEV), how bad it could be (CVSS) and the chance it is exploited somewhere in the next 30 days (EPSS), with the KEV row opened. |
| [`09-host-posture.png`](09-host-posture.png) | This computer (host posture on Windows): the antivirus panel, pending updates, and the safety settings with what was found. |
| [`10-dns-filter.png`](10-dns-filter.png) | Web blocking (the DNS filter): look-ups and blocks over 24 hours, the per-hour chart, and the websites being blocked most, with the reason in words. |
| [`11-telemetry.png`](11-telemetry.png) | System health (telemetry): whether each of Home SOC's background jobs is working, in plain words, with the technical job table one click away. |
| [`12-scans.png`](12-scans.png) | Checks (scan history): when each check last ran and how it went, with the full history one click away. |
| [`13-architecture.png`](13-architecture.png) | The architecture diagram: definition feeds into scanners, scanners into the findings engine, and the engine into the dashboard, alerts and the DNS filter. |
