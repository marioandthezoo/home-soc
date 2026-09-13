# Changelog

All notable changes to Home SOC are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**Lens — point your phone at a device.** A phone-sized web app Home SOC serves itself at `/lens`. Point the camera at
something in the house and Lens identifies which device on the network it is, then draws what Home SOC knows about it
over the live camera image: identity, open ports with a plain-English gloss, matched CVEs with EPSS as a sentence
rather than a decimal, findings with numbered fix steps, the domains that device has been talking to, and its recent
timeline — one round trip, one card. Off by default. Chrome on Android is the target; every other browser falls back
to a device picker rather than a dead viewfinder.

- **Identification by visual tag.** Any code the camera can decode — the barcode the manufacturer already printed on
  the device, or a QR sticker Home SOC generated. An unknown code is *learned*, not rejected: Lens shows a ranked
  device list that explains its own ordering ("camera, online, not marked trusted, first seen this week"), you tap
  once, and every later scan of that code resolves instantly. A manual picker is always available, and a "Devices" tab
  makes Lens useful with the camera closed.
- **Printable sticker sheet** at `/lens/stickers` for devices with no readable label: Avery 5160 (2.625 × 1 in) or
  40 mm square, exact millimetre print geometry, optional nicknames. Minting is idempotent, so reprinting never
  invalidates a sticker already stuck to something.
- **HTTPS.** New `serve --tls` and `run --tls`, with a self-signed certificate generated on first use in `data/tls/`,
  covering this machine's names and addresses, renewed automatically and fingerprinted at startup. TLS is required
  because browsers only grant camera access to a secure context.
- **Scoped, revocable phone tokens.** `/lens/pair` on the dashboard runs a preflight (reachable? certificate? HTTPS?
  free slots?) and refuses to mint a code until pairing can actually work, then shows a QR and the certificate
  fingerprint. New CLI: `lens pair`, `lens tokens`, `lens revoke <id> | --all`, `lens cert [--regenerate] [--hosts]`.
- **A hand-rolled QR encoder** (`homesoc/web/qr.py`, byte mode, error correction M, versions 1–10) with SVG and ASCII
  renderers — no external library and no CDN, so the sticker sheet and the terminal pairing code work offline like
  everything else.
- **New `[lens]` config section**: `enabled`, `require_https`, `tag_learning`, `allow_actions`, `token_ttl_days`,
  `max_tokens`. Deliberately not editable from the Settings page.
- **`scripts/enable-lens.ps1`** adds the one inbound firewall rule Lens needs, on the Private profile only, and is
  idempotent and reversible with `-Remove`.
- **`docs/LENS_SETUP.md`** — enabling Lens, the certificate, the two transport options, pairing, stickers, tag
  learning, troubleshooting and the security model, with the limits stated plainly.

### Security

- Lens is **off by default**; turning it on is a `config.toml` edit, because it moves the dashboard's reach from
  loopback to the LAN. When off, every Lens route answers 404.
- Serving Lens over plain HTTP to anything but a loopback peer is **refused** (`403 https_required`), with the fix on
  the page. `/lens/pair` and `/lens/stickers` are exempt, because the pairing page is where the fix is explained —
  but that page still **refuses to mint a pairing code** into a plain-HTTP URL that leaves this machine, whatever
  `lens.require_https` says. That flag governs serving a phone that is already paired, never issuing the credential.
- Phone tokens are 32 bytes from `secrets.token_urlsafe`, shown once, stored only as SHA-256, compared with
  `secrets.compare_digest`, expiring per `token_ttl_days` and revocable individually or wholesale. They are separate
  from the dashboard token and grant no dashboard access.
- The `act` scope (rescan, acknowledge, set trusted) is **off by default**: without `lens.allow_actions` a paired
  phone is strictly read-only — including `DELETE /api/lens/tag/<code>`, which is a destructive inventory change
  (deleting a sticker tag would make the next printed sheet disagree with the label already on the device). Unlearning
  a code is done from the computer, with the dashboard token.
- Pairing codes are 8 characters, single-use, valid five minutes, rate-limited to ten attempts an hour per source
  address (with an `events` row when that trips), and invalidated the moment Lens is switched off. The code travels in
  a URL fragment, which never reaches the server, and is stripped from the address bar once read.
- **No device data in any URL** — identification is a POST — and every Lens API response carries
  `Cache-Control: no-store`. The CSP stays `default-src 'self'`.
- Sticker QRs encode an opaque random token (`hs1:` + 22 URL-safe characters), never a MAC address, IP, hostname or
  device name, so photographing a sticker reveals nothing about the network.
- Every string a phone supplies — a decoded code, a token label, a tag label — is stripped of control characters
  before it is stored, logged or printed, so nothing off the network can forge or hide a row in the fixed-width table
  `python -m homesoc lens tokens` prints.
- New finding **SOC-LENS-001** (medium): "Lens is reachable on the LAN over plain HTTP", with real fix steps. Its
  description states what the plain-HTTP binding actually costs in each case — with the default
  `require_https = true` Lens refuses to serve phones at all rather than leaking anything — so it cannot contradict
  its own last fix step.

### Changed

- **The Lens timeline is bounded to its own device in SQL.** It used to build a 500-item whole-network feed and filter
  it in Python, so a few normal days of other clients' DNS blocks starved a device out of its own History section and
  the phone said "Nothing recorded for this device yet" when that was false. `feed.build_feed` now takes a
  `DeviceFilter`.
- **The "Talking to" figures are clamped to the device's own tenure of its address.** A DHCP lease that moved inside
  the window used to donate the previous holder's lookups — threat-list hits included — to whatever picked the
  address up afterwards, and `dns.note` claimed the figures were complete. The note now says when an address was
  shared, and the resolver's on/off state is read from the setting instead of being inferred from whether the window
  happened to be empty.
- **The manual picker's ranking bands are disjoint**, so a kind hint plus a vendor hint plus "untrusted" plus "new
  this week" can no longer out-score a device with an open critical finding, which is what B6's precedence says.
- A sticker tag keeps its kind when the owner re-learns it from the phone, and minting looks a sticker up by its
  `hs1:` payload rather than by that kind — so reprinting a sheet really does reproduce the QR already stuck to the
  device. Binding a code is now a single upsert, so two phones scanning the same new barcode at once cannot race.
- The optional dependency `cryptography` is available as the `lens` extra (`python -m pip install .[lens]`, or just
  `python -m pip install cryptography`). It is imported lazily and only for certificate work: Home SOC starts and runs
  normally without it.

### Fixed

- **Lens phone app.** A denied camera (or a browser with no `BarcodeDetector`) now leaves a permanent explanation in
  the viewfinder with a way back, instead of a black screen once the dismissible notice had been closed by the very
  button that sent you to the picker. An HTTP error from Home SOC is reported as what it was — "It replied HTTP 500:
  …" — rather than as "Home SOC is not reachable". A finding with no written fix steps can be acknowledged. The
  full-screen picker and unknown-code sheets are real dialogs: the dock behind them is no longer focusable and focus
  moves into and back out of them. "Close" on an unknown code sticks instead of re-opening 3.5 seconds later, and
  "Not a device — ignore this code" takes two taps and offers an undo. The card's dismiss control and the small
  buttons meet the 44px touch floor.
- The service worker's cache name is derived from the shell assets, so a Lens upgrade no longer serves the previous
  `lens.js` against fresh markup for one open. The manifest declares a maskable icon.
- `GET /api/lens/device/<id>` with an id larger than SQLite can hold answers 404 instead of raising `OverflowError`
  into a 500 with a traceback.
- Creating the Lens tables goes through `db.init_schema`, which holds the write lock, instead of running
  `executescript` on the shared connection — that issues an implicit COMMIT and could commit a scheduler thread's
  open transaction.

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
