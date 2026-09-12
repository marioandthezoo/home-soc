# Changelog

All notable changes to Home SOC are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-09-11

First public release. One Python process, one SQLite file, no cloud, no account and no telemetry.

### Added

**The five capabilities**

- **Definition updates.** 15 registered feeds — CISA KEV, EPSS, the IEEE OUI vendor database and a set of DNS
  blocklists (oisd, HaGeZi, URLhaus, ThreatFox, Phishing Army, OpenPhish and others) — fetched with ETag/`If-Modified-Since`
  caching so re-checks cost almost nothing, and with per-feed licence metadata recorded next to each entry.
- **Network scanning.** Device discovery from the ARP table first and then a gentle TCP sweep, followed by a service
  scan of each device with nmap when it is installed and a built-in Python connect-and-banner scanner when it is not.
  Records ports, banners, products, versions and CPEs, plus mDNS/SSDP and Wi-Fi encryption details.
- **Vulnerability matching.** Discovered services are matched against CISA KEV, NVD and EPSS, so "exploited in the
  wild" is separated from "theoretically vulnerable", with CVSS, EPSS probability and the evidence behind each match.
- **Host posture auditing.** Microsoft Defender state and recent detections, firewall profiles, Windows Update,
  local accounts, autostart entries, listening ports, Wi-Fi encryption, disk encryption and the router's exposure to
  the internet. Linux and macOS get a smaller posture check; Windows-only checks report "needs administrator"
  rather than failing.
- **LAN-wide DNS filtering** (optional). An embedded resolver on port 53 that blocks ads and trackers, sinkholes
  known-malicious domains, and keeps a live query log with per-domain allow/deny overrides, upstream forwarding
  (UDP, TCP on truncation, DoH as a last resort) and optional VirusTotal reputation lookups.

**Findings and remediation**

- A catalogue of **88 finding rules** across the network, Windows, POSIX, Defender, DNS, Wi-Fi, WAN and agent-health
  categories, each with a plain-English explanation, the evidence that triggered it, numbered remediation steps and
  reference links.
- A finding lifecycle engine (open → acknowledged → resolved → suppressed) with a security score and grade, and a
  "Fix these first" ranking showing how far the score would rise per finding type cleared.
- A first-run baseline: the initial discovery pass files every device as `info` rather than an alarm, and
  `homesoc baseline` accepts the devices you already own in one go.

**Dashboard**

- A local Flask dashboard on `http://127.0.0.1:8787` with **11 pages** — Overview, Activity feed, Summary, Findings,
  Devices, Vulnerabilities, Host posture, DNS filter, Telemetry, Scans and Settings — plus per-device detail pages,
  a token login, an RSS activity feed at `/feed.rss`, and Markdown/JSON/print export of the remediation summary.
  No CDN assets, so it works offline.

**Notifications**

- ntfy, Discord webhooks, generic JSON webhooks and Windows toast, batched to one message per scan with a
  configurable severity floor and an optional daily digest. Webhook URLs are treated as secrets and are never echoed
  back by the API or written into error messages.

**Command line**

- `init`, `update`, `scan`, `serve`, `dns`, `run`, `status`, `findings`, `baseline`, `export`, `report`, `feed`,
  `defender` and `dns-test`.

**Packaging and docs**

- `run.bat` and `run.sh` launchers that create the virtualenv, install dependencies, initialise the database and
  start the agent, checking each step and failing with one actionable sentence.
- Documentation set: walkthrough, home-protection guide, LAN DNS setup, finding playbooks, architecture, research
  notes, the build spec and the tested environment.
- MIT licensed.

### Testing

- **719 passing tests**, plus one live-network test that stays skipped unless both `--live` and `HOMESOC_LIVE=1` are given. The suite is
  offline and fixture-driven: it needs no nmap, no administrator rights and no network access.
- Verified on Python 3.12 (Linux), 3.13 (Windows) and 3.14 (Windows).

[Unreleased]: ../../compare/v0.1.0...HEAD
[0.1.0]: ../../releases/tag/v0.1.0
