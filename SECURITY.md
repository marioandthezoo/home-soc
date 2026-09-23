# Security Policy

Home SOC is a security tool that runs on your own machine and holds a detailed map of your home
network. That makes the agent itself worth thinking about carefully. This document covers how to
report a problem, what the agent protects against, what it deliberately refuses to do, and what to
change if you expose the dashboard beyond your own computer.

---

## 1. Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use your repository host's private vulnerability reporting instead. On GitHub that is the
**Security** tab of the project's repository → **Report a vulnerability**, which opens a draft
advisory only the maintainers can see. If you are running a fork, report it to whoever maintains
that fork. Private advisories are the only reporting channel for this project — there is no
published email address — so if you cannot use them, please open a public issue that says only
*"I would like to report a security issue privately"* with no technical detail, and wait to be
contacted.

Please include:

- the version (`python -m homesoc --version`) and your OS,
- what an attacker would gain, and what position they need to start from (a page in your browser?
  a device on your Wi-Fi? a compromised feed mirror?),
- the smallest set of steps that reproduces it,
- any patch or test you already have.

**Please do not include** your `data/homesoc.db`, your `config.toml`, or an unredacted support
bundle — those contain your network inventory, your DNS query log and your API keys. A redacted
excerpt of the relevant rows is enough. `python -m homesoc export --out report.json` contains no
settings at all, and the dashboard's support bundle (`/api/export?full=1`, linked from Settings)
reports secrets only as "set" or "not set" — but both still contain your full device inventory.

What to expect: an acknowledgement, a fix or a clear explanation of why the behaviour is intended,
and credit in the release notes if you want it. This is a small hobby-scale project run by
volunteers — there is no bug bounty and no formal SLA, and honesty about that is better than a
promise nobody can keep.

### In scope

The agent's own attack surface: the dashboard and its API, the DNS resolver, the feed downloader
and parsers, the findings pipeline, the CLI, the install scripts, and anything that lets untrusted
input from the network or from a feed change what the agent does.

### Out of scope

- Findings the agent reports about *your* network — that is the product working.
- Anything that requires you to have already been root/Administrator on the machine running the
  agent.
- Reports that the DNS filter can be bypassed by DNS-over-HTTPS or a hard-coded resolver, or that
  connect-mode port scanning misses things. Both are documented limitations
  (`docs/ARCHITECTURE.md` §11), not defects.
- Missing hardening on a dashboard you deliberately exposed to the internet. Don't do that; see §5.

---

## 2. What the agent knows about you

Threat modelling starts with the asset, and here the asset is the database. `data/homesoc.db`
contains:

- every device on your LAN: MAC address, IP, hostname, vendor, nickname, when you first saw it and
  when it was last online,
- every open port and service version found on those devices,
- CVEs matched against them,
- this computer's security posture: antivirus state, firewall state, account names, autostart
  entries, installed and outdated software, listening ports,
- your Wi-Fi SSID, authentication type and cipher (**never the passphrase**),
- your public IP address,
- if the DNS filter is on: every DNS name every device on your network looked up, with timestamps
  and the client's IP.

That last one is a browsing history for the whole household. Treat the database the way you would
treat one.

`config.toml` additionally holds your `web.token`, and any API keys you configured
(`dns.virustotal_api_key`, `dns.urlhaus_auth_key`, `vulns.nvd_api_key`) and notification URLs — the
Discord webhook and ntfy topic URLs *are* credentials, because their path is the secret.

`.gitignore` excludes `data/`, `*.db*`, `config.toml` and `.env` for exactly this reason. Anything
that logs or exports config runs it through `config.redacted()`, which masks every key in
`config.SECRET_KEYS`; `/api/settings` reports secrets as "set" or "not set" and never echoes their
value; notification failures have the webhook URL and its path scrubbed out of the error text before
it is stored.

### Who we are defending against

| Adversary | Position | What the agent does about it |
|---|---|---|
| A web page you visit | Runs JavaScript in your browser, same machine | Dashboard is loopback-only by default; Host-header allowlist blocks DNS rebinding; CSP + CSRF header requirement block cross-origin API calls |
| A device on your LAN | Can reach any listening port on this host | Dashboard is loopback-only by default. Bound to anything else, Home SOC will not start without a token of at least 16 characters, and generates and stores one if `web.token` is empty. `SOC-SYS-003` checks the address the server actually bound to |
| The wider internet | Can send packets if a port is forwarded | The resolver drops every query from a non-private source address; the dashboard is not exposed unless you exposed it |
| A compromised or hostile feed mirror | Controls the bytes of a blocklist or CVE file | TLS-verified, size-capped, atomically replaced; parsed by validating parsers that never execute anything |
| A hostile device being scanned | Controls its banners, hostname, mDNS names, XML | All of it is treated as data — escaped in HTML, parameterised in SQL, never interpolated into a command line |
| Another program or account on this computer | Can connect to `127.0.0.1` | With a `web.token` it needs the token like anyone else. Without one it cannot open the dashboard to the network, set its password, redirect DNS or alerts, or switch blocking off; a value planted before that rule is reported at startup |

---

## 3. How the agent defends itself

Every item below is implemented in the code, with the file that does it.

### The dashboard binds to localhost

`web.host` defaults to `127.0.0.1` (`config.example.toml`). Out of the box the dashboard is reachable
only from the machine it runs on. Loopback means `localhost`, `127.0.0.0/8` and `::1` / `[::1]`
(`config.is_loopback_host()`); everything else counts as exposed, including `""`, `0.0.0.0`, `::`,
a hostname and a LAN address.

**Home SOC will not listen on the network without a real token** (`cli.enforce_bind_policy()`,
run by `serve` and `run` before anything starts, plus a last check right before the socket is bound):

- Exposed with an **empty** `web.token` (no `config.toml`, a copy of `config.example.toml`, or a
  removed token): a token is generated (`secrets.token_urlsafe(32)`), stored as a Settings override so
  it survives restarts, and the login link is printed once. The stored override wins over
  `config.toml`; to use a token of your own, put it in `config.toml` and run
  `python -m homesoc config unset web.token`.
- Exposed with a token **shorter than 16 characters**: refused (exit code 2) with the exact fix. On
  loopback a short token still only logs a warning.
- On loopback with an **empty** `web.token` there is no login at all. Browsers still refuse
  requests from other websites (see the CSRF guard below), but the dashboard cannot tell you apart
  from any other program running on this computer, or another account on it. So without a password
  it refuses to change the settings that matter most (`api.PASSWORD_ONLY_SETTINGS`): a non-loopback
  `web.host`, `web.token`, `dns.upstreams`, `dns.doh_upstream`, `dns.listen`, `dns.enabled`,
  `dns.port`, `dns.lists`, `network.exclude`, `notify.min_severity` and the three alert URLs, and it
  will not clear a `web.host` or `web.token` override either. It answers HTTP 403 with one plain
  sentence pointing to `config.toml` or `python -m homesoc config set <key> <value>`. Posting a
  value that is already in force is not a change, so the Settings form still saves everything else.
  Anyone who can reach it can change every other setting (scan schedules, allow/deny overrides,
  acknowledging findings). Keep the token unless you are the only user and trust everything that
  runs here.
- A dashboard with no password also **answers only this computer**: any other peer address gets
  HTTP 403 for every page and API route (`app._peer_is_loopback()`), so `/lens/pair` and the
  Settings page are never reachable from the network without a token, even if something starts the
  app without the bind policy. The phone's own Lens routes keep their own checks (a phone token or
  a single-use pairing code, and HTTPS).
- There is no "no token on the LAN" switch. For remote access keep the dashboard on loopback and use
  a VPN or Tailscale Serve.
- If the startup message says the dashboard **"may already have been open to the network"** (an earlier
  non-loopback bind, active Lens tokens, or Settings overrides of `web.*`, `notify.*`,
  `dns.upstreams`, `dns.doh_upstream`, `dns.lists`, `dns.listen`, `dns.enabled` or
  `network.exclude`; the list is `config.TAMPER_SIGNAL_KEYS`), run `python -m homesoc lens revoke --all`
  and review `python -m homesoc config overrides`. A LAN host that reached a token-less dashboard could
  have planted its own token or redirected DNS and alerts, so a "token is set" check alone cannot tell.
- **A password or address Home SOC has no record of you setting is reported too.** Home SOC records a
  fingerprint (never the value) of each `web.host` / `web.token` override written by a trusted path:
  the token it generates, `python -m homesoc config set`, or the Settings page while you are signed in
  with a password (`config.confirm_web_overrides()`). When the dashboard opens to the network with an
  override that does not match, for example a token another program planted before this release, the
  start prints a WARNING with the same clean-up commands and records an event. It still starts: only
  you can tell whether you set it. If you did, `python -m homesoc config keep` stops the warning.

**`SOC-SYS-003` (high) — "Dashboard is reachable from the LAN without a token"** and `SOC-LENS-001`
remain as defence in depth. They follow the address the server actually bound to (recorded by
`serve`), not only `config.toml`, so a `scan` in a second terminal sees `serve --host 0.0.0.0`.

### A real token, generated for you

`python -m homesoc init` does not leave the token blank. It writes a fresh
`secrets.token_urlsafe(24)` into your new `config.toml`, and prints the login URL. When a token is
set, `homesoc/web/app.py` requires it on **every** route except `/login` and `/static/` — pages get a
login form with HTTP 401, API routes get `{"ok": false, "error": "unauthorized"}` with 401.

- The token itself is accepted only on sign-in (the login form posts it in the body; `?token=` on a
  GET still works for the links the CLI prints) and as an `X-Token` header for scripts.
- Signing in creates a **session**: the cookie holds a random session id, never the token. Only a
  hash of the id is stored. Sessions last 7 days and slide while used; signing out ends the session
  on the server, and changing `web.token` (in `config.toml` or on the Settings page) signs every
  browser out. Under `--tls` the cookie is `__Host-homesoc_token` (Secure, host-only).
- A `?token=` on a GET is immediately turned into a session and **redirected to the same URL without
  it**, so the secret does not linger in the address bar, browser history or `Referer`. A `?token=`
  on a navigation that another website started is ignored (neither accepted nor counted), so a
  web page cannot use wrong tokens to lock you out.
- The cookie is `HttpOnly` and `SameSite=Strict`.
- Wrong tokens are **rate-limited**: 10 per source address and 100 in total per 10 minutes, then a
  15-minute lockout, and a warning in the activity feed. The all-addresses lockout does not apply
  to this PC's own loopback address (which keeps its per-address limit), so a LAN host cannot lock
  you out at the desk. A token shorter than 16 characters is refused for any non-loopback bind
  and logs a warning at startup on loopback.
- Comparison uses `hmac.compare_digest`, not `==`.

### Host-header validation (anti DNS-rebinding)

A page on `attacker.example` can make its own hostname resolve to `127.0.0.1:8787`. To the browser
that is same-origin with your dashboard, and CORS will not save you. The one thing that still tells
the two apart is the `Host` header.

`app.trusted_hosts()` builds an allowlist at startup, and it only contains names an attacker cannot
answer for:

- On a **loopback** bind: `127.0.0.1`, `localhost`, `::1` and `[::1]`, nothing else.
- On a **LAN** bind over plain HTTP: those, plus the IP addresses the machine answers on (so a second
  NIC or a VPN does not lock you out). An IP literal cannot be rebound.
- This PC's name, `<name>.local` and a name set as `web.host` are accepted **only over HTTPS**
  (`--tls`). Any device on the LAN can answer mDNS for `<name>.local`, so over plain HTTP a page it
  served could become same-origin with the dashboard; under TLS it cannot present the dashboard's
  certificate without a new warning. Over plain HTTP, use the IP address.

Anything else is refused with HTTP 400 `"bad host header"` before authentication is even considered.
This check runs on every request, including `/static/` and `/login`, so a rebound page can neither
use the dashboard nor send wrong sign-in attempts that lock you out at the desk.

### Content-Security-Policy and friends

Every response carries:

```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store          (on /api/ responses)
```

`default-src 'self'` is only possible because the dashboard has **no inline scripts, no inline
styles, no inline event handlers and no external assets**. There is no CDN, no web font, no analytics
snippet. Everything the browser loads comes out of `homesoc/web/static/`. Jinja's autoescaping does
the rest; the RSS feed is built with `xml.etree.ElementTree`, which escapes every value, so a device
whose hostname is `<img src=x onerror=alert(1)>` renders as text (there is a test for exactly that).

### CSRF guard

Every `POST`, `PUT`, `PATCH` and `DELETE` must carry the header `X-Requested-With: fetch`, or it is
rejected with HTTP 403. A browser cannot add a custom header to a cross-origin form submission or a
simple request without a successful CORS preflight, which the dashboard never grants. The only
plain HTML forms are sign-in and the two Lens "create" buttons (a pairing code, sticker codes);
those are accepted only when the browser itself says they are same-origin (`Sec-Fetch-Site`, or an
exact `Origin`). **No GET changes anything**: loading `/lens/pair` or `/lens/stickers` shows the
page, and minting happens only on its own button.

On top of that, requests that the browser marks as coming from another site (`Sec-Fetch-Site`, or a
foreign `Origin`) are refused for every `/api/` route and every non-navigation load, even on an
install without a token, where cookies protect nothing. A plain link to an ordinary page still works.

### No shell, ever

There is no `shell=True`, no `os.system`, no `eval` and no `exec` anywhere in `homesoc/`. Every child
process goes through `homesoc.scanners.run_command()` or `homesoc.util.run_cmd()`, both of which:

- take an argv **list**, never a command string, and pass `shell=False`,
- are built from constants plus validated values (IP addresses, integers, fixed flags),
- carry a hard timeout and turn a missing binary or a timeout into a return code, not an exception,
- use `CREATE_NO_WINDOW` on Windows so nothing flashes a console at you.

The nmap command line is fixed in `ports.build_nmap_command()` and the timing template is clamped to
T0–T3 — a value from config cannot turn into a different flag.

### Feed downloads are treated as hostile

`homesoc/feeds/updater.py`:

- **TLS is verified.** Plain `requests.get` with default verification; there is no `verify=False`
  anywhere in the codebase.
- **Conditional GET** with the stored `ETag` / `Last-Modified`, so a normal refresh usually transfers
  nothing.
- **Size cap** from `feeds.max_download_mb` (64 MB default), checked against `Content-Length` before
  the first byte and again on **every 64 KB chunk** — a lying `Content-Length` does not help.
- **Decompression-bomb cap**: gzip is accepted only from feeds published gzipped (EPSS), and the
  inflated file is held to the same cap as the download. Whole-document feeds (KEV, EPSS, Feodo)
  also have their own absolute ceilings well below the configurable cap, checked before a file is
  read, and EPSS is parsed row by row.
- **Redirects are checked hop by hop**: at most 5, every hop must be `https`, and a hop to a
  loopback, private, link-local, CGNAT or multicast address (or a name resolving to one) is refused.
  A hop containing a backslash, whitespace, a control or non-ASCII character, or `user@` credentials
  is refused, and the host checked is the one urllib3 will connect to. Every connect a feed download
  makes is checked again on the socket against the address it is actually connecting to
  (`homesoc/feeds/netguard.py`), so no URL-parser trick or DNS rebinding can reach loopback or the
  LAN. NAT64, IPv4-compatible, site-local, Teredo and 6to4 forms of private addresses count as
  private. A configured HTTPS proxy is still allowed.
  NVD, VirusTotal (domain and file-hash lookups) and URLhaus calls do not follow redirects at all, so
  an API key header can never be forwarded to another host, and their answers are read with a size
  cap.
- **Timeouts everywhere**: 10 s connect and 60 s read per network read, a 180 s wall clock per feed
  and a 600 s wall clock for the whole batch. The per-feed wall clock is enforced on the socket itself
  (`homesoc/feeds/netguard.py`): when it runs out, the connection is shut down in whatever phase the
  server is stalling (TLS handshake, headers or body), so a server that trickles one byte at a time
  cannot hold the scheduler thread hostage. NVD requests get the same guard with a 30 s wall clock,
  VirusTotal file lookups 45 s and notification posts 30 s. A 1 KB/s throughput floor after a 30 s
  grace also applies between chunks.
- **Line length is bounded before parsing**: line-oriented feeds are read in lines of at most 4096
  characters (longer lines are drained and dropped, never split), so a feed that is one giant line
  cannot cost many times its size in memory. The OUI feed has its own 16 MB cap. Malformed JSON,
  including nesting deep enough to overflow the parser, costs one lookup, never a whole vulns scan.
- **Atomic replace**: the body streams to `<name>.tmp` and only `os.replace`s into place after it has
  been fully read and counted. A crash mid-download can never leave a truncated blocklist that the
  resolver would happily load. A SHA-256 sidecar is written next to each file.
- **Failure is inert**: an error leaves the previous file untouched, and per-feed exponential backoff
  (1 h → 24 h) stops a retry storm. After 48 h you get `SOC-FEED-001` (medium).

### Untrusted feed and scan data stays data

- Blocklist lines go through `policy.parse_list_line()`: length-limited, comment-stripped, and
  validated against a strict hostname regex. A line that is not a plausible domain is dropped. It is
  never evaluated, never used to build a path, never passed to a shell.
- Every SQL statement uses bound parameters. The two places where an identifier cannot be a
  parameter validate it instead: `db.purge_older_than()` checks the table name against the schema's
  own table list and the column name against a character allowlist.
- The findings engine's scope matching uses `substr(subject,1,n) = ?` rather than `LIKE`, so a `%` or
  `_` inside a device's subject cannot widen an auto-resolve and quietly close findings on other
  devices.
- Reputation lookups validate the hostname against a strict regex before it reaches the VirusTotal
  URL path or the URLhaus form field, because DNS labels may legally contain `/`, `?`, `#` and `%`.
- Rendering a finding title interpolates evidence through a `format_map` that tolerates missing keys
  and swallows stray braces, so malformed evidence produces a plain sentence rather than an exception
  that hides a security finding.

### The resolver cannot be used against anyone

`homesoc/dnsfilter/server.py`:

- **Not an open resolver.** Queries from any address that is not private, loopback or link-local are
  dropped without an answer. A port-forward to 53 or a spoofed victim address gets nothing back, so
  the host cannot be used as a DNS reflector.
- **Rate limits per source**, never shared: 300 queries/second per client, with separate UDP and TCP
  budgets. Over the limit a UDP query gets a bare TC=1 reply no larger than the query, so a victim
  whose address is being forged falls back to TCP (which cannot be forged) instead of losing DNS.
  The global ceiling (3000/second) applies only to UDP answers larger than 512 bytes, which are
  truncated rather than dropped. One device can no longer use up a bucket everyone shares.
- **One bad name cannot take DNS down for the house.** A query that fails upstream no longer opens
  the circuit breaker; the breaker opens only if the resolver's own canary query (`. NS`) fails too.
  A failing name is answered SERVFAIL locally for 5 s, a zone that keeps failing is held for 30 s.
  Upstream work in flight is capped per client (32, counted separately for UDP and TCP), per zone
  (32; reverse lookups are charged per IPv4 /16 or IPv6 /32) and, for UDP, in total (256). A UDP
  query over a shared limit is answered TC=1, never SERVFAIL, so the client retries over TCP, whose
  capacity forged packets cannot reach.
- **No thread per packet.** UDP is served by one listener thread and a fixed pool of 8 workers; the
  source check and rate limit run on the listener before a datagram is queued (at most 1024), a full
  queue is answered TC=1, and queries that need an upstream go to a separate bounded pool so slow
  names never hold the workers.
- **TCP connections are bounded**: 64 in total and 8 per source. When the table is full the oldest
  idle connection of the busiest source is closed instead of refusing the newcomer (RFC 7766
  §6.2.3), so a device holding many connections cannot lock out a victim that was sent TC=1. A 10 s
  idle wait (2 s while the table is more than half full), 5 s for a whole message, 120 s and 100
  queries per connection. Non-local sources are refused before a thread is started.
- **The query log has budgets**: 600 rows per client and 30,000 in total per minute (queries over
  budget are still answered, just not written), names are truncated, and the table is capped at
  2 million rows, oldest first. Devices in the inventory (seen in the last 30 days) have their own
  budget that forged source addresses cannot use up, and an overflow of the per-minute source table
  is recorded as a warning event and raises **`NET-DNS-007`** (medium, "Something on your network
  seems to be faking addresses to flood web blocking's lookup log") from the resolver's health
  check; it stays open for a day after the last overflow. The DNS page shows the flood-guard
  counters (answered but not logged, connections dropped, look-ups shed, slowed down) under
  Technical details while the resolver runs in the same process.
- **Reputation lookups cannot be starved by forged sources**: inventory devices have their own queue
  lane; one client may use at most 10% of the VirusTotal daily quota and all non-inventory sources
  together 50%; the reputation table keeps clean/unknown rows 30 days and at most 100,000 rows.
- **Response size is clamped to 1232 bytes** regardless of what the client's EDNS advertises. Larger
  answers set TC=1, forcing the client to retry over TCP — which a spoofed source cannot complete.
- **`ANY` queries and non-IN classes are refused** outright.
- Requests to upstreams are rebuilt from scratch with a new ID and minimal EDNS, so client-specific
  EDNS options never leak out, and question case is randomised (0x20) with the reply validated
  against it. An upstream that returns a wrong-case reply is asked without 0x20 for 60 s, doubling
  up to 1 h if it keeps happening; one correctly-cased reply restores it, so one spoofed reply cannot
  switch the protection off for good.
- **DNS attribution is by source address, and every surface says so.** On a flat LAN a host can forge
  another device's address over UDP. So the activity feed says "requested from Mum's iPhone's address
  (192.168.1.31)", the Home page says "Web blocking stopped a look-up ... from X's address", the DNS
  page's busiest-devices table notes that devices are matched by network address, the map legend and
  device page say an "observed" look-up link was recorded from the device's address, which another
  device can fake, and `NET-DEP-003` ("Lookups from {name}'s address ...") and `NET-DNS-004`
  ("Malicious domain looked up from {client}") tell you to confirm which device made the lookup
  before you reset anything. Names that are not valid hostnames are dropped before they reach the
  map or a finding.
- The UDP socket sets `SIO_UDP_CONNRESET` on Windows so a single ICMP port-unreachable cannot kill
  the listener.

### Text from the network is made harmless on the way in

Hostnames (reverse DNS and mDNS), service banners, certificate names and UPnP port-mapping fields
are chosen by the devices that send them. Where they enter the inventory they are reduced to one
printable line (control characters, line breaks, terminal escapes, every Unicode bidi control
including U+061C, and invisible default-ignorable characters such as zero-width spaces, BOM and
Hangul fillers removed) and capped in length; a UPnP "internal client" must be an IPv4 address. The
same helper (`util.safe_one_line`) is applied again to every notification line, every map label and
every finding title (`catalog.one_line`, and `catalog.safe_detail` line by line for the detail), so
rows stored before a fix, owner nicknames and text that reached a finding by another path are
covered too. A lone surrogate in a finding's subject or key is replaced before it reaches SQLite. Alert bodies are sized in the unit
each service counts (ntfy in UTF-8 bytes, at most 3900 of its 4096; Discord in UTF-16 units, at most
4000 of 4096) and every finding line gets an equal share, so device-chosen emoji cannot push an alert
past a service limit or push other findings out of it. The scheduled daily digest goes through the
same sanitiser as every other alert. On the way out they are escaped
again for each format: HTML, the Markdown report, Discord Markdown, RSS/toast XML, the terminal (CLI
output shows control characters as `\xNN`) and the log (a message is always one line). The
Windows toast never splices alert text into PowerShell source: the toast XML is passed as base64,
because PowerShell also treats typographic quotes (U+2018-U+201B) as string delimiters. A discovery
sweep adds at most 32 new devices (256 a day) after the first one, and reports a burst as
`NET-DEV-004`, so a device inventing MAC addresses cannot flood the inventory. The UPnP/IGD walk
only talks to the device that answered, inside your LAN range, never to loopback or link-local
addresses, and every fetch has a wall-clock deadline.

### The host scanners assume malware may be trying to hide

- **Autostart entries are compared by command, not only by name.** A changed Run value, Startup
  shortcut target, task action or service path opens a fresh finding worded as a change ("Autostart
  entry changed: OneDrive", with "Was: ... Now: ..." and a first step that says to check the new
  command, not just the familiar name), and the host page marks the row **Changed** and shows what it
  ran before. It stays open until you accept it with **Mark as known** / **Mark all as known** on the
  host page. Those buttons send the command you were shown, and an entry whose command changed after
  the page loaded is not accepted (`api.persistence_accept`); they are behind the token and the CSRF
  header like every other write. Unreviewed entries stay open for as long as they exist; they no
  longer auto-resolve after 7 days.
- **Nothing is hidden on a self-declared field.** Scheduled tasks are filtered only by the
  `\Microsoft\` folder (which a standard user cannot write), never by their Author. A service counts
  as part of Windows only when its binary sits in the Windows folder, outside user-writable
  subfolders, with a valid Microsoft signature, is not a script host or launcher, and has no outside
  paths in its arguments.
- **VirusTotal "unknown" and "clean" verdicts are provisional** and looked up again later (unknown
  after 6 h, doubling up to 7 days; clean after 3 days), within the shared daily budget, because a
  fresh payload is exactly what VirusTotal has not classified yet at download time.

Known limits: an attacker with administrator rights can still hide a task in `\Microsoft\`, or a
service behind a Microsoft- or WHQL-signed binary with Windows-only arguments, and an in-place swap
of a binary that keeps the same command line is not detected.

### Least privilege, and exactly what needs admin

Home SOC runs as your ordinary user account. Nothing in the agent requires elevation, and the
Windows environment it was built against is a non-admin Windows 11 Home install with UAC on.

Binding UDP and TCP port 53 works **without** administrator rights on Windows 11 (measured; see
`docs/TESTED_ENVIRONMENT.md`).

Three things do need admin, and each one is a separate script you run knowingly:

| What | How | Why |
|---|---|---|
| Let other LAN devices reach the resolver | `scripts/enable-lan-dns.ps1` | `New-NetFirewallRule` requires elevation |
| Start at logon via Task Scheduler | `scripts/make-autostart.ps1 -Mode task` | `Register-ScheduledTask` requires elevation |
| Nothing (the default path) | `scripts/install.ps1`, or `-Mode startup` | a Startup-folder shortcut needs no privileges |

The logon task runs with normal rights by default. `make-autostart.ps1 -Mode task -Elevated` is
opt-in and is refused unless the Home SOC tree, the base interpreter folder named in
`.venv\pyvenv.cfg` (`home`) and all their parent folders are writable by administrators alone; a
per-user python.org install (under `%LOCALAPPDATA%\Programs\Python`) therefore always fails the
check. The elevated task runs `pythonw.exe -I -S scripts\run-elevated.py run`, which ignores
`PYTHON*` variables and the user site, refuses an import path outside the venv and the base
interpreter, and replaces the inherited environment (which includes the user-writable
`HKCU\Environment`) with machine-wide values: a fixed Windows `PATH`, no per-user app folders. Only
`HOMESOC_DATA` and `HOMESOC_CONFIG` are kept. An elevated Home SOC never runs `winget` (it lives in
a user-writable folder), so the software-update check reports "winget not found" there.
`-CheckOnly` runs the checks and prints the command without registering anything.

Checks that a normal user cannot perform — Secure Boot state, TPM state, BitLocker volume status,
the Security event log — are recorded as `needs_admin`, a distinct state from `fail`, and listed
explicitly on `/host` and in the report's "not checked (needs administrator)" notes.
`SOC-SYS-002` (info) names the exact check IDs that were skipped. **A check the agent could not
perform is never reported as a check that passed.**

### Lens pairing and phones

- **A pairing code works once, even under a race.** It is spent with a single `DELETE` whose row
  count decides, and the phone-count ceiling (`lens.max_tokens`), spending the code and minting the
  token happen under one lock (`db.lens_pair_with_code`), so simultaneous claims with one code give
  one token, the ceiling holds, and a claim refused at the ceiling keeps your code.
- **Claim attempts are counted exactly.** 10 an hour per source (an IPv6 claimant is counted per /64,
  an IPv4-mapped address as its IPv4 address); the read, count and write run under one lock, so a
  burst of simultaneous guesses cannot slip past the limit or overwrite a lockout, and the lockout
  event is written once.
- **Only the dashboard creates sticker codes.** A phone cannot teach Home SOC a code that starts with
  `hs1:` (whatever kind it claims, in any letter case), and the sticker sheet always reprints the
  first dashboard-made code for a device, so a phone cannot change the QR code the sheet prints.

### Still open

Known gaps, stated plainly. None of them lets a web page or a LAN device take over the dashboard.

- **A token planted before this release is reported, not removed.** The startup WARNING names it and
  prints the clean-up commands, but the dashboard still starts with it, because only you can tell
  whether you set it. Someone who knows that token and signs in before you act can re-save it on
  the Settings page, which records it as yours; after that the warning stops.
- **With no password, this computer is trusted completely.** Any program or other account on this PC
  can still use a password-less dashboard for everything outside `api.PASSWORD_ONLY_SETTINGS`:
  change a finding's status (acknowledge, ignore), add allow overrides for blocked sites, change scan schedules and
  API keys, and mark autostart entries as known. Set a `web.token` if you share the computer.
- **Behind a reverse proxy everyone is `127.0.0.1`.** The proxied visitors share one address for the
  sign-in and pairing limits, so one of them can use up the limit for all (including you at the
  desk), and a password-less dashboard behind a proxy is open to everyone who can reach the proxy.
  There is no overall cap on pairing attempts across all addresses.
- **Sticker codes a phone taught Home SOC before this release** can still print for a device that has
  no dashboard-made sticker yet. Forget that tag on the device page, or print a new sheet after
  removing it.
- **Address-based attribution is only worded carefully, not fixed.** Home SOC still cannot tell which
  device really sent a UDP DNS query. `NET-DNS-007` reports a flood of forged sources, but a device
  that forges a few queries as another device is not detected; lookups from devices not yet in the
  inventory can still be pushed out of the query log and the reputation queue by a flood.
- **Flood counters need the resolver in the same process.** `serve` on its own does not run the
  resolver, so its DNS page has no protection counters; `run` shows them.
- **The map and graph are rebuilt on every request** (no short cache yet), each under the shared
  write lock. It is fast on a home-sized network but a busy dashboard costs the resolver some
  database time.
- **Autostart acceptance is per scan.** "Mark as known" updates the baseline at once, but the open
  finding closes on the next host check, not immediately.

---

## 4. What the agent deliberately does not do

These are design decisions, not gaps:

- **No exploitation.** Home SOC never attempts to exploit anything it finds. There is no payload, no
  proof-of-concept, no `--script`, no fuzzing, no brute force, no default-credential testing. It
  reads banners and version strings and looks them up. A KEV match without a usable version is
  reported as "possible" (`NET-VUL-002`, high) rather than asserted.
- **No credential capture.** It never collects, tests, stores or transmits passwords. `wifi.py`
  records the SSID, authentication mode and cipher, and explicitly not the passphrase. It does not
  read your browser's saved passwords, your credential manager, or your SSH keys.
- **No file uploads.** `scanners/files.py` computes SHA-256 hashes of new files in your Downloads
  folder and looks the *hash* up. The file itself never leaves your machine — there is no VirusTotal
  file-submission path in the code at all.
- **No outbound telemetry.** No analytics, no crash reporting, no version check, no phone-home, no
  usage counter, no account. Nothing is sent anywhere about you or your network.

Every outbound connection Home SOC can make is one of these, and no others:

1. the feed URLs listed in `homesoc/feeds/registry.py` (CISA KEV, FIRST EPSS, Wireshark OUI data, and
   the DNS blocklists you enabled),
2. `api.ipify.org` — to learn your public IP, so it can be checked,
3. `internetdb.shodan.io` — to ask what the internet already sees on that IP,
4. `services.nvd.nist.gov` — CVE enrichment, only when `vulns.nvd_enrich` is on,
5. `www.virustotal.com` — domain and file-hash lookups, **only when you supply an API key**,
6. `urlhaus-api.abuse.ch` — keyless domain reputation, part of the DNS filter,
7. your configured DNS upstreams and DoH endpoint, when the resolver forwards a query,
8. the notification endpoints you configured yourself (ntfy, Discord, a generic webhook).

Items 2–6 are queries about *your* network — your public IP, a service version string, a domain a
device looked up, a file hash. That is the trade you make by enabling those features. Turn any of
them off in `config.toml`: `vulns.nvd_enrich = false`, leave `dns.virustotal_api_key` empty,
`host.files_check = false`, `feeds.enabled = false`, `dns.enabled = false`.

---

## 5. Hardening if you expose the dashboard

The default is loopback-only, and for most people it should stay that way. If you want to reach the
dashboard from your phone on the same Wi-Fi:

1. **Set a token first, then change the host.** `python -m homesoc init` already generated one —
   keep it, or replace it with something at least as long:
   `python -c "import secrets; print(secrets.token_urlsafe(24))"`. Then set
   `web.host = "0.0.0.0"`. If you get the order wrong, Home SOC generates and stores a token for you
   and prints the login link; a token shorter than 16 characters is refused on a non-loopback
   address.
2. **Bind to one interface, not all of them.** If you know this machine's LAN address, put that in
   `web.host` instead of `0.0.0.0`. It will not then be reachable over a VPN interface or a second
   NIC you forgot about.
3. **Do not port-forward it, and do not expose it to the internet.** Wrong tokens are rate-limited
   and `--tls` serves HTTPS with a self-signed certificate, but it is still a small built-in server
   (TLS handshakes run per connection with a 10 s timeout, and idle connections close after 120 s).
   It is not built to survive the open internet, and it holds a map of your house. If you need
   remote access, use a VPN (WireGuard, Tailscale) or an SSH tunnel and leave the dashboard on
   loopback.
4. **If you must terminate TLS, put a reverse proxy in front.** Keep Home SOC on `127.0.0.1` and let
   the proxy listen on the LAN. The Host-header allowlist on a loopback bind is `127.0.0.1`,
   `localhost`, `::1` and `[::1]` only, so configure the proxy to send one of those as `Host` (for
   Tailscale Serve, proxy to `http://127.0.0.1:<port>`). Keep a `web.token` behind a proxy: every
   request then arrives from `127.0.0.1`, so the dashboard cannot tell proxied visitors from you at
   the desk, and the per-address guess and pairing limits are shared by everyone behind it.
5. **Treat the login link as a password.** `dashboard_url()` prints `/login?token=...`; the token is
   converted to a cookie and stripped from the URL on first use, but the link itself is a credential
   until then. Do not paste it into a chat.
6. **Use a standard user account for daily work.** `WIN-ACC-001` (medium) will tell you if your
   everyday account is an Administrator. That is good advice generally, and it also limits what an
   attacker who reaches the dashboard could do next.
7. **Back up `data/` the way you back up documents, and encrypt the backup.** It is your network
   inventory and DNS history. Home SOC keeps it private to you on the machine itself: on Linux and
   macOS the data folder is `0700` and the database, its WAL and the logs are `0600` (existing
   installs are tightened on the next start); on Windows, a data folder outside your user profile
   gets an owner + SYSTEM + Administrators ACL, and the Lens TLS key and certificate always get an
   explicit owner + SYSTEM ACL.
8. **Rotating a secret that was typed into the Settings page.** Values saved there win over
   `config.toml`. Press **Use config.toml value** next to the setting (or run
   `python -m homesoc config unset <key>`) and restart; clearing `web.token` also signs every
   browser out.
9. **Firewall the resolver deliberately.** `scripts/enable-lan-dns.ps1` creates the inbound rule for
   the Private profile only. If you never intend other devices to use the resolver, do not create the
   rule at all, or set `dns.listen = "127.0.0.1"`.

---

## 6. Dependencies and supply chain

Home SOC runs on **three direct third-party packages** (plus `cryptography`, only if you use Lens):

```
flask==3.1.3
requests==2.34.2
dnslib==0.9.26
```

`pytest>=9.0.3,<10` is a development-only extra and is never installed into a production venv.
Everything else is the Python standard library. There is no JavaScript build, no `node_modules`, no
bundler, no minifier, no CDN — `homesoc/web/static/` contains hand-written files that ship as source.

- **A hash-locked lock file.** `requirements.txt` pins the whole transitive closure (and pip itself)
  to exact versions with the SHA-256 of every published file, generated with pip-compile. Every
  launcher installs it with `pip install --require-hashes`, so pip refuses anything unpinned or any
  file whose bytes differ from the lock.
- **No install-time scripts.** The build backend is plain `setuptools>=77` with a declarative
  `pyproject.toml`. There is no `setup.py`, no `build` hook, no post-install step. `pip install`
  runs no project code.
- **Small transitive surface.** Flask brings Werkzeug, Jinja2, MarkupSafe, click, itsdangerous and
  blinker; requests brings urllib3, certifi, idna and charset-normalizer; dnslib brings nothing.
  MarkupSafe and charset-normalizer install compiled wheels, and those are hash-pinned too.
- **Updates reach existing installs.** `run.bat` / `run.sh` reinstall whenever the hash of
  `requirements.txt` changes, and a lock bump changes it. They do not fetch anything else and never
  install into the system Python.
- **Feeds are data, not code.** The definitions Home SOC downloads are blocklists, CSVs and JSON.
  Nothing downloaded at runtime is ever executed, imported, or used to construct a path or a command
  line. See §3 for how those downloads are bounded.

If you want to verify what is running, `pip freeze` inside `.venv` and the SHA-256 sidecars next to
each file in `data/feeds/` are both meant to be read by a human.

---

## 7. Supported versions

This project is pre-1.0. Security fixes go onto the latest release; older versions are not
back-patched. If you are running from a clone, `git pull` is the update path.

Python 3.12 or newer is required (`requires-python = ">=3.12"`); the launchers refuse to start on
anything older with a clear message rather than a traceback.
