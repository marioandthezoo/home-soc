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

**Dependencies and blast radius.** A new **Map** page (`/map`) showing what each device depends on, what depends on it,
and what stops working when it fails. Click a node and the map highlights its blast radius with one sentence a
non-expert can act on — *"If Living-room router fails, 5 devices lose their internet connection. They stay on the local
network and can still reach each other."* — separating **degraded** (still on the LAN, lost the way out or a service) from **offline** (genuinely unreachable),
which on a flat home network are very different lists. Hand-rolled SVG, deterministic layout, keyboard navigable, no
libraries.

- **Every edge is labelled with how it was established** — `observed` (a DNS query in the log, an mDNS/SSDP
  advertisement, a UPnP mapping, devices that dropped off together in a recorded outage), `inferred` (everything
  reaches the internet through the gateway) or `assumed` — drawn solid, dashed and dotted, with a legend.
- **Home SOC has no packet visibility, and the feature is built around admitting it.** LAN peer traffic never passes
  through it, so the map is not a traffic diagram and never claims to be. It would rather show fewer links than invent
  one: a printer advertising `_printer._tcp` becomes a provider node marked *no confirmed consumers* instead of
  sprouting edges to every device that might plausibly print. A permanent note on the page says so.
- **Blast radius learned from real outages.** Groups of devices that disappear and return in the same discovery cycle
  are recorded as outages with their members and, where one dropped too, which of them is the infrastructure device —
  an association, never a claim about cause, because a tripped power strip produces the identical record. Repeated
  co-drops promote an inferred edge to observed, one edge per pair: a single shared outage cannot say *which* of a
  device's services was involved, so it never claims to. The resolution is stated everywhere it is shown, from the
  cadence recorded with that outage rather than today's setting: "together" means *in the same discovery cycle* — ten
  minutes by default, not seconds. Devices whose absence is routine (the
  phone that leaves every morning) are excluded, so a commute does not become a dependency.
- **Three new findings.** `NET-DEP-001` (info) a device that has quietly become load-bearing; `NET-DEP-002` (medium) an
  observed single point of failure that has been offline alongside other devices at least twice, citing the dates — it fires on observed
  evidence only, never on inference, and its remediation is about redundancy and about what to check first during the
  next outage rather than about patching anything; `NET-DEP-003` (info) a device depending on a cloud endpoint that is
  repeatedly blocked or unreachable, so a feature you think you have may have silently stopped working.
- **The same data in three smaller places**: a "load-bearing devices" card on the Overview, a *Depends on / Depended on
  by / If this fails* section on each device page, and an "If this fails" line in the Lens card — point the phone at a
  box and learn what the house loses without it.
- **New CLI command `blast <device>`** — an IP, MAC or nickname — printing the same headline, the degraded and offline
  lists, the services lost and the evidence, in the terminal. `scan --only topology` rebuilds the map on demand.
- **New `[topology]` config section**: `enabled`, `window_hours`, `include_cloud`, `min_outage_members`,
  `criticality_alert`. New scheduler job `topology` (after `discovery`; it re-reads what discovery and the DNS filter
  already wrote and scans nothing itself), a new `topology` scan step, and new tables `dep_edges`, `outages`,
  `outage_members` (schema migrations 3 and 4). `dep_edges` is a cache — deleting it is harmless, and the next
  refresh rebuilds it with `first_seen` preserved.
- **`docs/TOPOLOGY.md`** — where every edge comes from, why there are three confidence levels, how blast radius is
  computed, how outage learning works and at what resolution, the four things Home SOC structurally cannot see
  (device-to-device traffic, anything behind a Zigbee/Z-Wave/Thread hub, devices using someone else's resolver,
  unadvertised services), and what would lift the map from inference to measurement: SNMP bridge tables from a managed
  switch, `conntrack` from an OpenWrt/pfSense router, or a passive listener on a spare machine — with the note that
  moving the resolver onto a spare Raspberry Pi would both remove the DNS single point of failure and make the
  dependency data far richer, because every device's lookups would then be visible.

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

- **The dependency map no longer describes one device's outage as another's.** A device that was merely caught in a
  large outage reported that outage's size, dates and cadence as its own blast radius — so a NAS that sat inside one
  twenty-device router failure was shown, at *observed* confidence, as something whose failure takes twenty devices
  down. Every figure that answers "what happens when this fails" is now built only from outages that device actually
  headed, and a device that has headed none reports no evidence at all instead of a sentence that contradicts its own
  headline. This reached the map panel, `/devices/<id>`, the Lens card, `blast` on the CLI and the persisted
  `NET-DEP-002` finding.
- **One shared outage now buys one dependency, not one per service.** A NAS offering SMB, SSH, AirPlay and printing
  turned a single co-drop into four confident claims that a doorbell used each of them. A co-drop is evidence of
  shared fate: where the device offers exactly one service the edge names it, and where it offers several the edge
  points at the device and says which service was involved is not known.
- **A co-drop no longer claims a device becomes unreachable.** A NAS failing does not make a laptop unreachable,
  whatever they have done together; that is reserved for a hub, an access point or a switch, where there is a path to
  sever. Everything else is reported as degraded, with the honest reason — they may simply share power or a switch.
  `NET-DEP-002` says the same thing instead of "has taken other devices down with it".
- **DNS history follows the device that made it.** Lookups were attributed to whoever holds the address *today*, so a
  recycled DHCP lease moved one household member's browsing onto another person's device card and minted an
  *observed* cloud dependency the device never had. Each query is now resolved against the sighting in force at the
  time, and an address two devices answered on at once is attributed to neither.
- **Recorded outages report the cadence they were recorded at.** `/api/map/blast` and `/api/map/outages` rebuilt the
  resolution sentence from today's `schedule.discovery_minutes`, so an outage recorded hourly was reported at
  ten-minute resolution — in the same payload as evidence that still said sixty. `/api/map/outages` now carries a
  `resolution` per outage, and the config-derived sentence is `resolution_now`.
- **A hub needs evidence.** Anything whose vendor or hostname *contained* "bridge", "hue" or "bond" was declared a
  Zigbee hub with fabricated "advertises itself as a bridge" evidence — "Cambridge Audio" qualified. A hub claimed
  from a broadcast stays *observed*; one guessed from a name is *assumed*, says so, and now needs a whole word.
- **The gateway edge checks the subnet it names.** Devices on another RFC1918 range, and stale public addresses, were
  drawn depending on the gateway under the words "the default route for this subnet".
- **The map legend describes the evidence that exists.** It advertised UPnP port mappings, SSDP advertisements and a
  DHCP-assigned resolver; none is implementable today, and all three have moved to docs/TOPOLOGY.md's "what would
  make this map dramatically better".
- **Lens shows the "If this fails" section the changelog promised.** The payload carried it and the client never
  rendered it, so every identification paid for a full graph build and threw the answer away.
- **The map's own picture matches its panel.** Services hosted on the failing device are highlighted as lost rather
  than dimmed as unaffected while the panel lists them under "what the house loses"; a blocked domain is no longer
  counted or sized as something devices depend on ("7 devices depend on it · not a dependency"); an `assumed` blast
  radius prints as *Assumed* rather than *Inferred* and has its own styling; the C2.6 hub note can render at all
  (it keyed off a node kind no payload has ever carried); "no confirmed consumers" is legible instead of truncated to
  "no …"; and the word *offline* really is in an offline node's drawn label, as the legend claims.
- **Sentences that did not add up.** The outage evidence line counted the device itself among the devices that went
  down with it and applied the largest outage's size to every date; it said "Seen five times" above three dates; it
  rendered dates in UTC while the rest of the dashboard renders local time; and a two-device house was told "1 device
  lose their internet connection".
- **The overview and device pages build the dependency graph once.** `/`, `/map` and `/devices/<id>` each rebuilt it
  two or three times per request — under the shared write lock, which stalls the resolver's own writes.
- **Schema migration 4** gives `outages.trigger_device_id` `ON DELETE SET NULL` and `outage_members.device_id`
  `ON DELETE CASCADE`. With `PRAGMA foreign_keys=ON`, a device that had ever been in an outage could not be deleted at
  all.

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
