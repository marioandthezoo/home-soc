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
| A device on your LAN | Can reach any listening port on this host | Dashboard is not bound to the LAN by default; when it is, a token is required and `SOC-SYS-003` (high) fires if you skipped it |
| The wider internet | Can send packets if a port is forwarded | The resolver drops every query from a non-private source address; the dashboard is not exposed unless you exposed it |
| A compromised or hostile feed mirror | Controls the bytes of a blocklist or CVE file | TLS-verified, size-capped, atomically replaced; parsed by validating parsers that never execute anything |
| A hostile device being scanned | Controls its banners, hostname, mDNS names, XML | All of it is treated as data — escaped in HTML, parameterised in SQL, never interpolated into a command line |

---

## 3. How the agent defends itself

Every item below is implemented in the code, with the file that does it.

### The dashboard binds to localhost

`web.host` defaults to `127.0.0.1` (`config.example.toml`). Out of the box the dashboard is reachable
only from the machine it runs on. Changing this to `0.0.0.0` is a deliberate act, and the agent
notices: `Config.Web.exposed` is true for anything other than loopback, and `cli.soc_health_drafts()`
raises **`SOC-SYS-003` (high) — "Dashboard is reachable from the LAN without a token"** whenever the
dashboard is exposed and `web.token` is empty.

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
  you out at the desk. A token shorter than 16 characters logs a
  warning at startup.
- Comparison uses `hmac.compare_digest`, not `==`.

### Host-header validation (anti DNS-rebinding)

A page on `attacker.example` can make its own hostname resolve to `127.0.0.1:8787`. To the browser
that is same-origin with your dashboard, and CORS will not save you. The one thing that still tells
the two apart is the `Host` header.

`app.trusted_hosts()` builds an allowlist at startup: loopback names and addresses, the configured
bind address, this machine's hostname and `<hostname>.local`, and every address the machine answers
on (so a second NIC or a VPN does not lock you out). Anything else is refused with HTTP 400
`"bad host header"` before authentication is even considered. This check runs on every request,
including `/static/` and `/login`.

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
  NVD, VirusTotal and URLhaus calls do not follow redirects at all, so an API key header can never
  be forwarded to another host, and their answers are read with a size cap.
- **Timeouts everywhere**: 10 s connect, 60 s read, a 180 s wall clock per feed, a 600 s wall clock
  for the whole batch, plus a throughput floor (1 KB/s after a 30 s grace) so a server that trickles
  one byte at a time cannot hold the scheduler thread hostage.
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
  A failing name is answered SERVFAIL locally for 5 s, a zone that keeps failing is held for 30 s,
  and upstream work in flight is capped per client (32), per zone (32) and in total (1024).
- **TCP connections are bounded**: 64 in total and 8 per source, a 10 s wait for the first byte,
  5 s for a whole message, 120 s and 100 queries per connection. Non-local sources are refused
  before a thread is started.
- **The query log has budgets**: 600 rows per client and 30,000 in total per minute (queries over
  budget are still answered, just not written), names are truncated, and the table is capped at
  2 million rows, oldest first.
- **Response size is clamped to 1232 bytes** regardless of what the client's EDNS advertises. Larger
  answers set TC=1, forcing the client to retry over TCP — which a spoofed source cannot complete.
- **`ANY` queries and non-IN classes are refused** outright.
- Requests to upstreams are rebuilt from scratch with a new ID and minimal EDNS, so client-specific
  EDNS options never leak out, and question case is randomised (0x20) with the reply validated
  against it.
- The UDP socket sets `SIO_UDP_CONNRESET` on Windows so a single ICMP port-unreachable cannot kill
  the listener.

### Text from the network is made harmless on the way in

Hostnames (reverse DNS and mDNS), service banners, certificate names and UPnP port-mapping fields
are chosen by the devices that send them. Where they enter the inventory they are reduced to one
printable line (control characters, line breaks, terminal escapes and bidi overrides removed) and
capped in length; a UPnP "internal client" must be an IPv4 address. On the way out they are escaped
again for each format: HTML, the Markdown report, Discord Markdown, RSS/toast XML, the terminal (CLI
output shows control characters as `\xNN`) and the log (a message is always one line). The
Windows toast never splices alert text into PowerShell source: the toast XML is passed as base64,
because PowerShell also treats typographic quotes (U+2018-U+201B) as string delimiters. A discovery
sweep adds at most 32 new devices (256 a day) after the first one, and reports a burst as
`NET-DEV-004`, so a device inventing MAC addresses cannot flood the inventory. The UPnP/IGD walk
only talks to the device that answered, inside your LAN range, never to loopback or link-local
addresses, and every fetch has a wall-clock deadline.

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

Checks that a normal user cannot perform — Secure Boot state, TPM state, BitLocker volume status,
the Security event log — are recorded as `needs_admin`, a distinct state from `fail`, and listed
explicitly on `/host` and in the report's "not checked (needs administrator)" notes.
`SOC-SYS-002` (info) names the exact check IDs that were skipped. **A check the agent could not
perform is never reported as a check that passed.**

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

1. **Set a token first, then change the host.** Not the other way round.
   `python -m homesoc init` already generated one — keep it, or replace it with something at least as
   long: `python -c "import secrets; print(secrets.token_urlsafe(24))"`. Then set
   `web.host = "0.0.0.0"`. If you get the order wrong, `SOC-SYS-003` (high) will appear on your
   dashboard, which is the point.
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
   the proxy listen on the LAN. Note that the Host-header allowlist is built from this machine's own
   names and addresses — a proxy presenting a different `Host` will be refused with HTTP 400, so
   configure it to pass through a hostname the agent already trusts (its own hostname, or the bind
   address).
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
