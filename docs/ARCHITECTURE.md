# Home SOC — Architecture

How the program is put together, what runs where, and what happens to a piece of information between
"a scanner noticed something" and "it is on your dashboard".

This document describes the code as it is written, not as it was planned. Where the two differ, the
code wins; `docs/SPEC.md` is the original contract and `docs/TESTED_ENVIRONMENT.md` records what
was actually measured on the Windows 11 Home environment it was developed against.

---

## 1. One process, a handful of threads

`python -m homesoc run` is the normal mode. It is a single Python process. Nothing is containerised,
there is no message broker, no background service, no separate worker. `homesoc/cli.py` wires
everything together — it is the only module that imports every other package, and it imports them
lazily and defensively, so a package that is missing or broken degrades to a logged "not available"
instead of taking the dashboard down.

```
                        python -m homesoc run   (one OS process)
  +---------------------------------------------------------------------------------------+
  |                                                                                       |
  |  main thread ............. Flask dev server, app.run(threaded=True)                   |
  |     |                      binds  web.host:web.port   -> 127.0.0.1:8787 by default     |
  |     +-- per-request worker threads (one per HTTP request, created by Flask)           |
  |                                                                                       |
  |  "homesoc-scheduler" .... homesoc/scheduler.py — ONE worker, jobs run one at a time    |
  |                            calls cli.scan_* -> scanners -> findings.engine -> notify    |
  |                                                                                       |
  |  "dns-udp" .............. socketserver.ThreadingUDPServer.serve_forever()             |
  |     +-- one short-lived thread per datagram                                           |
  |  "dns-tcp" .............. socketserver.ThreadingTCPServer.serve_forever()             |
  |     +-- one thread per connection, 2-byte length framing, 10 s idle timeout           |
  |                            both bind  dns.listen:dns.port  -> 0.0.0.0:53              |
  |  "dns-housekeeping" ..... 5 s tick: blocklist reload, rate-limiter cleanup,           |
  |                            cache expiry, DNS health findings (every 60 s)             |
  |  "dns-querylog" ......... batches query rows, flushes every 2 s or 500 rows           |
  |  "dns-reputation" ....... drains the lookup queue (VirusTotal / URLhaus)              |
  |                                                                                       |
  |  transient threads:                                                                   |
  |     "homesoc-scan-<kind>" ..... a dashboard scan button when no scheduler is present   |
  |     "homesoc-defender-<action>" / "defender-<ref>" ..... MpCmdRun.exe runs in the back |
  |                                                                                       |
  |  one sqlite3.Connection, shared by all of the above                                   |
  +---------------------------------------------------------------------------------------+
```

The DNS listeners, the query-log batcher and the reputation worker only exist when `dns.enabled` is
true (or when you run `python -m homesoc dns`). The scheduler only exists in `run` and `serve`.

### Why one thread for jobs

`homesoc/scheduler.py` runs a single worker thread and takes a per-job lock, so the same job can
never overlap itself and two different jobs never run at once. On a home network that is the point:
a discovery sweep, a service scan and a 4 MB blocklist download all hitting the Wi-Fi at the same
moment is exactly what makes a printer or a smart plug fall over. SQLite also prefers one writer.

`run_now(name)` puts a job at the front of the queue — that is what the dashboard's "Run quick scan"
button does. A second click while the job is running or queued returns `False` rather than stacking
another run.

### Ports

| Port | Protocol | Bound by | Default bind address | Config keys |
|---|---|---|---|---|
| 8787 | TCP | Flask dashboard | `127.0.0.1` (loopback only) | `web.host`, `web.port` |
| 53 | UDP **and** TCP | `dnsfilter.server.DnsServer` | `0.0.0.0` (all interfaces) | `dns.listen`, `dns.port` |

No other listener is opened. Everything else — feed downloads, NVD lookups, port scans, DNS
forwarding — is an outbound connection.

Binding UDP and TCP 53 needs no administrator rights on Windows 11 Home (measured; see
`docs/TESTED_ENVIRONMENT.md`). Being *reachable* from the rest of the LAN is a separate question — that
needs an inbound firewall rule, which does need admin. See §9.

---

## 2. From a scan to your screen

```
  scheduler job ("discovery", "host", ...)
        |
        v
  cli.scan_<kind>()                      homesoc/cli.py
        |   builds a list of (source, callable, scope) parts
        v
  cli.run_step()  -----> db.scan_start()  opens a row in `scans`
        |
        v
  scanner.run(cfg, conn, *, quick=False, progress=None) -> ScanResult
        |        writes the tables it owns (devices, services, host_checks, ...)
        |        returns findings as FindingDraft objects — it never writes `findings`
        v
  ScanResult(kind, findings=[FindingDraft, ...], summary={...}, error=None)
        |
        v
  cli.apply_findings()
        |   cli.effective_scope() decides whether this run is allowed to auto-resolve
        v
  findings.engine.apply(conn, drafts, source, scope=...)     homesoc/findings/engine.py
        |   - dedupe_key() -> upsert into `findings`
        |   - append a row to `finding_events`
        |   - auto-resolve anything in scope this source stopped reporting
        v
  ApplyResult(new=[...], reopened=[...], resolved=[...], updated=n)
        |
        +--> notify.channels.notify_new_findings(cfg, conn, new)
        |         filters by notify.min_severity, one message per batch,
        |         records a row in `notifications`
        |
        +--> db.scan_finish()  closes the `scans` row with a JSON summary
        |
        v
  the dashboard reads the tables               homesoc/web/api.py, feed.py, summary.py
     /            /findings           straight SQL over `findings`
     /feed        homesoc/web/feed.py merges findings + devices + scans + feeds +
                  dns_queries + events + notifications into one time-ordered stream
     /summary     homesoc/web/summary.py: found vs remediated, time-to-fix, worklist
```

The important separation: **scanners never decide a finding's life story.** They are stateless and
re-emit the same observation every run. `findings/engine.py` owns the memory — one row that
accumulates occurrences, resolves itself when the problem stops being reported, and keeps your
acknowledge/suppress decision across rescans.

The catalog (`homesoc/findings/catalog.py`) owns everything a human reads: the title template, why
it matters, the numbered remediation steps and the reference links. 88 finding IDs, grouped into 16
categories. A scanner emits an ID plus an evidence dict; the catalog turns that into a sentence.

---

## 3. The database

One SQLite file, `data/homesoc.db`, opened once in `homesoc/db.py`:

- `check_same_thread=False` — one connection is shared by the scheduler, the DNS threads and every
  Flask request thread.
- WAL journal mode, `synchronous=NORMAL`, `busy_timeout=30000`, `PRAGMA foreign_keys=ON`.
- Every **write** goes through `db.write()` / `db.writemany()` / `db.transaction()`, which hold a
  module-level `threading.RLock`. Reads are lock-free — WAL lets them proceed while a write is in
  flight.
- All timestamps are UTC ISO-8601 strings ending in `Z` (`util.utcnow_iso()`). Columns holding JSON
  are plain `TEXT`.
- Schema creation is idempotent (`CREATE TABLE IF NOT EXISTS`) and versioned through
  `schema_migrations`; `init_schema()` runs at every start and is a no-op once applied.

### Tables by area, and who writes them

Anyone may read any table. Writing is owned:

**Core and telemetry** — `homesoc/db.py`, `scheduler.py`, `cli.py`

| Table | Contents |
|---|---|
| `schema_migrations` | applied schema versions |
| `settings` | runtime config overrides (dotted keys) and small pieces of state |
| `events` | timestamped log lines with a level and a source |
| `metrics` | numeric series: `score`, `job.duration`, `dns.qps`, `dns.cache_size`, `feeds.bytes`, `discovery.hosts_online` |
| `jobs` | one row per scheduler job: last run, status, duration, next run, run/failure counters |
| `scans` | one row per scan step and one wrapping row of kind `full`; JSON summary, error text |

**Definitions** — `homesoc/feeds/updater.py`

| Table | Contents |
|---|---|
| `feeds` | one row per registry entry: url, kind, ETag, Last-Modified, last checked/updated, status, bytes, entries, error, enabled |

**Network inventory** — `homesoc/scanners/discovery.py`, `ports.py`

| Table | Contents |
|---|---|
| `devices` | one row per MAC (or `ip:<addr>` when no MAC is knowable): ip, hostname, vendor, kind, nickname, trusted, notes, first/last seen, online, mdns services |
| `device_sightings` | append-only "seen at" trail per device, with the discovery method |
| `services` | one row per (device, port, proto): state, name, product, version, extrainfo, cpe, tunnel |

**Vulnerabilities** — `homesoc/vulns/matcher.py`

| Table | Contents |
|---|---|
| `vulns` | one row per (device, CVE, matched_on): source, KEV flag, CVSS, EPSS, title, published, remediation |

**This computer's posture** — `homesoc/scanners/host_windows.py`, `host_posix.py`, `defender.py`, `updates.py`, `persistence.py`, `files.py`

| Table | Contents |
|---|---|
| `host_checks` | one row per check ID: status (`pass`/`fail`/`warn`/`unknown`/`needs_admin`), value, expected, `needs_admin` flag |
| `software` | installed/upgradable apps per source (winget, registry, apt, brew) |
| `persistence` | autostart entries: run keys, startup folder, scheduled tasks, services; `baseline=1` for what was there on the first run |
| `file_checks` | SHA-256 → verdict for files seen in the watched download folders |

**Findings** — `homesoc/findings/engine.py`

| Table | Contents |
|---|---|
| `findings` | one row per `dedupe_key`: finding_id, subject, severity, title, detail, evidence JSON, status, source, first/last seen, resolved_at, occurrences, device_id |
| `finding_events` | the audit trail: `opened`, `reopened`, `resolved`, `auto_resolved`, `acknowledged`, `suppressed` |

**DNS filter** — `homesoc/dnsfilter/querylog.py`, `policy.py`, `reputation.py`

| Table | Contents |
|---|---|
| `dns_queries` | raw query log: ts, client, qname, qtype, action (`allow`/`block`/`cache`/`error`), reason, milliseconds |
| `dns_hourly` | (hour, client) → total and blocked counts; survives the raw-row purge |
| `dns_overrides` | your manual allow/deny list |
| `reputation` | domain → verdict cache with malicious/suspicious counts and the raw response |

**Notifications** — `homesoc/notify/channels.py`

| Table | Contents |
|---|---|
| `notifications` | ts, channel, subject, status, error — one row per delivery attempt |

### Retention

`cli.housekeeping()` runs daily and purges: `metrics` and `notifications` and `scans` after 90 days,
`events` and `device_sightings` after 30 days (always keeping each device's newest sighting),
`finding_events` after 90 days but only for findings that have been resolved that long. It then runs
`PRAGMA wal_checkpoint(TRUNCATE)` so the WAL file goes back to the OS.

`dns_queries` is purged separately by the `dns_rollup` job using `dns.log_retention_days` (14 days by
default), *after* the hourly rollup has been written, so the charts keep their history.

---

## 4. The scheduler's timetable

Jobs are built in `cli.build_jobs()`. Every job on a timer runs once at startup as well, except
`dns_retry` and `digest` (both `run_at_start=False`). The manual-only jobs — `quick`, `full` and
`device_scan` — have no interval at all (`Job.manual_only`), so they never run on their own and
never run at startup; they exist so the dashboard's Run buttons can reach them through `run_now`.

| Job | Default interval | Config key | What it does |
|---|---|---|---|
| `feeds` | 6 h | `schedule.feeds_hours` | update every enabled feed (subject to per-feed staleness and backoff) |
| `discovery` | 10 min | `schedule.discovery_minutes` | ARP table + TCP sweep of the LAN |
| `services` | 24 h | `schedule.services_hours` | port/version scan of online devices |
| `vulns` | 24 h | `schedule.services_hours` | match services against KEV / NVD / EPSS |
| `host` | 6 h | `schedule.host_hours` | posture, Defender, updates, persistence — and Wi-Fi |
| `exposure` | 12 h | `schedule.exposure_hours` | public IP, Shodan InternetDB, UPnP port mappings |
| `files` | 24 h | fixed | hash new downloads and look the hashes up |
| `dns_rollup` | 1 h | fixed | hourly rollup, retention purge, `dns.qps` metric |
| `score` | 1 h | fixed | record the `score` metric and re-evaluate Home SOC's own health |
| `housekeeping` | 24 h | fixed | purge old telemetry, checkpoint the WAL |
| `dns_retry` | 5 min | fixed | re-bind the resolver if port 53 was busy at startup |
| `digest` | daily at `notify.digest_hour` (8 local) | `notify.digest_hour` (`-1` disables) | one summary notification |
| `quick`, `full`, `device_scan` | manual only | — | the dashboard's buttons, via `run_now` |

A job that raises is caught, recorded as `error` in `jobs` and `events`, and the scheduler carries on.
Three consecutive failures make `Scheduler.failing_jobs()` report it, which raises `SOC-SYS-004`.

`python -m homesoc serve` starts the same scheduler with every job rewritten to manual-only: the
dashboard's Run buttons still work, but nothing runs on a timer.

---

## 5. The DNS request pipeline

```
  a device on the LAN sends a DNS query to this host, UDP or TCP port 53
        |
        v
  _UdpHandler / _TcpHandler  (one socketserver thread)
        |
        v
  DnsServer.handle_query(data, client, tcp=)                     homesoc/dnsfilter/server.py
        |
   1.   is the source address private / loopback / link-local?  ---- no ---> DROP, no answer
        |                                                                    (never an open reflector)
   2.   per-client rate limit  (> 300 q/s)                       ---- over -> DROP
        global rate limit      (> 3000 q/s)                      ---- over -> DROP
        |
   3.   DNSRecord.parse(data)                                    ---- fails -> FORMERR
        response bit set? -> DROP.  no question? -> FORMERR.  opcode != QUERY -> NOTIMP
        |
   4.   class != IN, or qtype == ANY                             ---------> REFUSED (not logged)
        |
   5.   Policy.decide(qname, qtype, client)                      homesoc/dnsfilter/policy.py
        |     walks the name's suffixes, most specific first:
        |       a.b.example.com -> b.example.com -> example.com -> com
        |     and at each suffix checks, in this order:
        |       1. dns_overrides "allow"       -> ALLOW  (your word beats everything)
        |       2. dns_overrides "deny"        -> BLOCK
        |       3. never-block suffixes        -> ALLOW  (localhost, local, arpa, home.arpa, lan,
        |                                                 home, internal, localdomain, ...)
        |       4. loaded blocklists           -> BLOCK  reason "list:<feed name>"
        |       5. reputation verdicts         -> BLOCK  reason "reputation"
        |       6. otherwise                   -> ALLOW  reason "default"
        |
        +-- BLOCK -> block_mode "null":    A 0.0.0.0 / AAAA :: with TTL 60, other types NODATA
        |            block_mode "nxdomain": RCODE NXDOMAIN
        |
   6.   cache lookup, keyed on (lowercased name, qtype)          homesoc/dnsfilter/cache.py
        |     TTL-aware LRU; TTLs clamped to 30 s .. 1 h; NXDOMAIN/NODATA cached 60 s;
        |     hit returns the stored answer with TTLs already decremented
        |
        +-- HIT -> answer, action "cache"
        |
   7.   forward upstream                                         homesoc/dnsfilter/upstream.py
        |     a FRESH request is built (new id, minimal EDNS) so the client's EDNS options
        |     never leak upstream; 0x20 case randomisation on the question
        |     UDP to each upstream in order (2 s), TCP retry when TC is set,
        |     then DoH POST (application/dns-message, 5 s) when dns.doh_upstream is set
        |
        +-- all upstreams fail -> SERVFAIL, action "error", and the failure clock starts
        |
   8.   store in cache; if the answer was NOERROR, enqueue the name for the reputation worker
        |
   9.   querylog.record(...)  -> in-memory deque, flushed every 2 s or 500 rows
        |
  10.   _finalize(): copy the request id, question and RD flag; re-add EDNS if the client sent it;
        clamp the UDP answer to 1232 bytes and set TC=1 (forcing TCP) when it does not fit
        |
        v
  answer bytes back to the client
```

Policy runs **before** the cache on purpose: a name that was allowed and cached an hour ago must be
blocked the moment a list update or a reputation verdict says so.

The `dns-housekeeping` thread re-checks blocklist file mtimes at most once a minute and, when a list
or an override changed, clears the whole answer cache. Every 60 s it also samples metrics and
re-evaluates the DNS health findings (`NET-DNS-001`, `003`, `005`, `006`).

The `dns-reputation` worker looks up only *newly seen registrable domains* — anything in the built-in
well-known list (about 200 domains: Google, Microsoft, Apple, Amazon, CDNs, ...) is skipped, so a
chatty LAN does not burn a 400-lookup daily budget on `google.com`. A lookup never blocks a DNS
answer. When it comes back malicious, the policy is updated, the cached answers for that name are
thrown away, and `NET-DNS-004` is raised against the client that asked.

---

## 6. The finding lifecycle

A finding's identity is its **dedupe key**: `finding_id | subject`, plus `| evidence["key"]` when one
subject can carry several instances of the same problem (one CVE, one autostart entry, one threat
name). Subjects look like `host`, `device:<mac>`, `device:<mac>:443`, `wan`, `wifi`, `dns`,
`dns:<client>`, `feed:<name>`, `job:<name>`.

```
                       a scanner emits a draft with this dedupe key
                                        |
                +-----------------------+------------------------+
                |                                                |
        no row exists                                    a row already exists
                |                                                |
                v                                                v
        INSERT status='open'                    status is ...
        event "opened"                            open / acknowledged
        -> ApplyResult.new                             |  last_seen refreshed, occurrences += 1,
                                                       |  evidence/title/severity refreshed
                                                       |  -> ApplyResult.updated
                                                       |
                                                   suppressed
                                                       |  same refresh, still suppressed
                                                       |  (a user decision is not undone by a rescan)
                                                       |
                                                   resolved
                                                       |  status -> open, resolved_at cleared,
                                                       |  event "reopened"
                                                       |  (if the last event was "auto_resolved"
                                                       |   from an acknowledged row, it comes back
                                                       |   acknowledged, not open)
                                                       v
                                                 ApplyResult.reopened
```

And the other direction — **auto-resolve**, "it went away":

```
  engine.apply(..., scope="device:00:11:22:33:44:55")
        |
        v
  every OPEN or ACKNOWLEDGED finding from this same source whose subject is inside that scope
  but was NOT in this run's drafts
        |
        v
  status -> 'resolved', resolved_at = now, event "auto_resolved" (note: "was:open" / "was:acknowledged")
```

Suppressed findings are left alone. Scope matching uses `substr(subject,1,n)=` rather than `LIKE`, so
a `%` or `_` inside a subject cannot widen the match, and `ip:10.0.0.5` never swallows `ip:10.0.0.50`.

The guard that makes this safe is `cli.effective_scope()`. **Only a complete, successful run may
auto-resolve.** It returns no scope — meaning "resolve nothing" — when the scanner reported an error,
when the summary is flagged `partial`, or when it scanned zero targets. A scanner that knows exactly
what it covered lists it in `summary["scopes"]` (the service scanner returns one `device:<mac>` per
fully scanned device), and that list is used instead of a blanket prefix. The result: "we did not
look" is never mistaken for "the problem is gone".

Manual transitions from the dashboard go through `engine.set_status()` → `POST /api/findings/<id>/status`.

The **security score** (`findings/score.py`) turns the open findings into one number between 0 and
100. It is a halving curve with ceilings, not a subtraction — a subtraction pinned every real home
to 0, where it stayed no matter what the user fixed:

1. Each unfixed row is a *slot* worth `WEIGHTS[severity] × STATUS_FACTORS[status]` — critical 30,
   high 12, medium 5, low 1.5, info 0, times 1.0 when open and 0.25 when acknowledged. Resolved and
   suppressed rows are worth nothing.
2. Within one `finding_id` the slots are sorted worst-first and each successive one is discounted by
   `REPEAT_DECAY` (0.5), capped at `REPEAT_CAP × w0` (twice the first). Twenty-six "outdated app"
   rows cost 3 penalty points, not 39.
3. `score = 100 × 0.5 ** (penalty / HALF_LIFE)` with `HALF_LIFE = 60`, so the score never sticks at
   0 and always moves when something is fixed.
4. Ceilings override the arithmetic: one open critical caps the score at 34, two or more at 20, and
   any open high at 79 — so an A means "nothing high or critical is open".

Grades are `GRADE_BANDS`: A ≥ 80, B ≥ 65, C ≥ 50, D ≥ 35, F below. `score_detail(conn)` and
`score_breakdown(conn)` explain the number, one row per finding type with the penalty it contributes
and the points that clearing the whole type would give back — that is what `python -m homesoc status`
prints and what `/api/summary` carries. The hourly `score` job writes the number into `metrics`,
which is where the trend line comes from. `cli.fallback_score()` mirrors the same formula for the
case where the `findings` package cannot be imported; `tests/test_core.py` pins the two together.

---

## 7. Definitions and feeds

`homesoc/feeds/registry.py` holds `FEEDS`, the single source of truth: 15 entries, each a `FeedSpec`
with a name, URL, kind (`kev`, `epss`, `oui`, `hosts`, `domains`, `adblock`, `ip`, `json`), a parser
function, a default cadence, a licence note and whether it is on by default.

`homesoc/feeds/updater.py:update()` refreshes them:

```
  for each requested feed:
      is it enabled?  is it stale (older than its cadence, or the file is missing)?
      is it inside its failure backoff window?          1 h, 2 h, 4 h ... capped at 24 h
      is there still time in the 600 s batch budget?
          |
          v
      GET <url>  with  If-None-Match: <stored ETag>
                       If-Modified-Since: <stored Last-Modified>
          |
          +-- 304 Not Modified -> the disk copy is current. status 'ok', last_updated touched,
          |                       the file's mtime is bumped so mtime-based staleness agrees.
          |                       (A 304 with no local file is treated as a broken mirror.)
          |
          +-- not 200 ---------> FeedError, previous file untouched
          |
          +-- 200:
                 Content-Length above the cap?  -> reject before reading a byte
                 stream to data/feeds/<name>.tmp in 64 KB chunks, checking on every chunk:
                     total <= feeds.max_download_mb (64 MB default)
                     180 s per-feed wall clock
                     throughput floor (1 KB/s after a 30 s grace) — no slow-drip stalls
                 gzip? (decided by magic bytes, not the URL) -> inflate, capped at 8x the wire cap
                 count entries with the feed's parser
                 os.replace(tmp, data/feeds/<name>.<ext>)   <- atomic; a crash can never leave
                                                               a truncated blocklist in place
                 write a <file>.sha256 sidecar
                 UPDATE feeds SET etag, last_modified, last_checked, last_updated, bytes, entries
```

A failure leaves the previous file exactly where it was, so a flaky mirror degrades to "stale", never
to "empty". A feed that has had no successful fetch for 48 h raises `SOC-FEED-001`; KEV specifically
raises `SOC-FEED-002`.

Consumers read the files through cached loaders in `registry.py` (`load_kev`, `load_epss`,
`load_oui`, `load_blocklist`, `load_ipset`, `lookup_vendor`). Each caches on `(mtime_ns, size)`, so
the DNS policy and the vuln matcher can call them freely without re-parsing megabytes.

Cadence is per category, not per feed: `feeds.kev_hours` (6), `feeds.epss_hours` (24),
`feeds.oui_hours` (168), `feeds.threatintel_hours` (6) for the malware/phishing feeds, and
`feeds.blocklists_hours` (12) for everything else. The registry default applies when the config key
is absent.

---

## 8. The dashboard

`homesoc/web/app.py` is a Flask app factory: `create_app(cfg, conn, scheduler=None, dns_server=None)`.
Pages are server-rendered Jinja templates sharing `base.html`; `static/app.js` polls and enhances,
`static/charts.js` draws SVG charts with no library. There are **no external assets at all** — no CDN,
no web font, no image file. Everything the browser loads comes from `homesoc/web/static/`.

Pages: `/` overview, `/feed`, `/summary`, `/findings`, `/devices` (+ `/devices/<id>`), `/vulns`,
`/host`, `/dns`, `/telemetry`, `/scans`, `/settings`, plus `/login` and `/logout`.

The JSON API lives under `/api` (blueprint in `homesoc/web/api.py`); `/feed.rss` serves the activity
feed as RSS 2.0 for anyone who wants it in a reader.

`homesoc/web/api.py` reads the tables with SQL written in that module rather than by importing the
owning packages. That is deliberate: the dashboard renders even when a scanner package has never run,
is missing, or is mid-edit.

Two heavier read-models sit beside it:

- `homesoc/web/feed.py` — merges findings events, device arrivals/departures, scans, feed updates,
  DNS blocks (aggregated per client + registrable domain + hour), Defender detections, notifications
  and system events into one reverse-chronological stream. Each source query is bounded by
  `limit + offset` and uses an indexed timestamp column; the merge happens in Python.
- `homesoc/web/summary.py` — "what has been found and what has been fixed": totals, remediation rate,
  median and p90 time-to-fix, the open worklist with the catalog's remediation steps attached, and a
  coverage section. It returns a complete, valid dict on an empty database and never raises.

Both are also reachable with the dashboard stopped, via `python -m homesoc report` and
`python -m homesoc feed`.

Security-relevant behaviour of the web layer is documented in `SECURITY.md` §3.

---

## 9. What happens when things are missing

The whole program is written so that a missing tool, a missing privilege or a missing network is a
*degraded mode*, not a crash. Three cases in particular:

### No nmap (or nmap without Npcap)

`homesoc/scanners/ports.py` looks for nmap on PATH and in the Windows default install folders. If it
is absent, or `scan.use_nmap` is false, it falls back to `python_scan()`: a threaded TCP-connect scan
of a built-in top-100 port list plus a light banner grab (HTTP, SSH, FTP, SMTP, MySQL, and the TLS
certificate subject for HTTPS). You still get open ports and often a product name; you lose nmap's
service fingerprints and CPE strings, which means fewer confident CVE matches. `SOC-SYS-001` (info)
is raised once so the dashboard says why.

On the author's machine nmap *is* installed but Npcap is broken, so nmap itself falls back to
connect() mode. Home SOC never asks for anything else: the argv is fixed at
`-sT -sV --version-light -T<n> --top-ports N -n -Pn --host-timeout <s>s -oX -`, with `-sV` dropped and
a smaller port list for devices whose vendor matches `network.fragile_vendors`. There is no `-O`, no
`-sU`, no `--script`, and the timing template is clamped so it can never be faster than T3.

Discovery does not depend on nmap at all. It is ARP-first: read the OS neighbour table
(`Get-NetNeighbor` with an `arp -a` fallback on Windows, `ip -j neigh` on Linux, `arp -a` on macOS),
run a TCP-connect sweep across the subnet to populate that table, then read it again. On the target
machine that finds 17–23 hosts in seconds, where `nmap -sn` in connect mode found 2 in 50 seconds.

### Not running as administrator

This is the normal case, and the design target. Nothing in Home SOC requires elevation to run.

The Windows posture probe reports checks that throw AccessDenied as `status = "needs_admin"` with the
`needs_admin` column set — a distinct state from `fail`, shown as its own badge on `/host` and listed
in the summary's "not checked" notes. On the target machine that is Secure Boot state, TPM state,
BitLocker volume status and the Security event log. `SOC-SYS-002` (info) is raised once listing
exactly which check IDs were skipped.

Three things genuinely need admin, and each is a separate opt-in script rather than a requirement:

| Task | Script | Why admin |
|---|---|---|
| let other LAN devices reach the resolver | `scripts/enable-lan-dns.ps1` | `New-NetFirewallRule` needs elevation |
| start at logon via Task Scheduler | `scripts/make-autostart.ps1 -Mode task` | `Register-ScheduledTask` needs elevation |
| — (no-admin alternative) | `scripts/install.ps1` / `-Mode startup` | a Startup-folder shortcut needs nothing |

Binding port 53 itself does **not** need admin. `NET-DNS-006` (info) tells you when the resolver is
bound to the LAN but no inbound rule for port 53 was found.

### Offline

- Feeds fail with `FeedError`, the previous files stay on disk and keep being used, and per-feed
  exponential backoff (1 h → 24 h) stops a fourteen-feed retry storm. After 48 h without a successful
  fetch you get `SOC-FEED-001`; the blocklists themselves raise `NET-DNS-003` once they are 3 days old.
- The vuln matcher still matches against the KEV and EPSS copies already on disk; the NVD enrichment
  step is skipped.
- WAN exposure gets no public IP and no InternetDB answer, records the failure, and resolves nothing
  (the `effective_scope` rule above), so your existing WAN findings are not silently marked fixed.
- The DNS resolver keeps answering from cache and from the blocklists; when every upstream has failed
  for 60 s it raises `NET-DNS-005` and returns SERVFAIL rather than pretending.
- Everything else — discovery, service scans, host posture, Defender, the dashboard — is entirely
  local and unaffected.

---

## 10. Non-goals

Things Home SOC deliberately does not try to be:

- **Not an IDS/IPS.** It does not sit in the path of your traffic, does not inspect packet payloads,
  and cannot block a connection. The only thing it can refuse is a DNS name.
- **Not an EDR.** No kernel driver, no hooks, no process tree monitoring, no memory scanning. It reads
  what Windows already exposes to a normal user.
- **Not a vulnerability scanner in the offensive sense.** It never attempts an exploit, never sends a
  proof-of-concept payload, never brute-forces a login, never fuzzes. It reads banners and version
  strings and looks them up.
- **Not a password auditor.** It never collects, tests or stores credentials, and never records your
  Wi-Fi passphrase (only the SSID, the authentication type and the cipher).
- **Not a cloud service.** No account, no telemetry, no remote control plane. Every byte it produces
  stays in `data/`.
- **Not multi-user.** One dashboard, one token, no roles, no per-user views, no audit of who clicked
  what.
- **Not a router replacement.** It cannot change DHCP options, add firewall rules on your gateway, or
  reconfigure your network. It tells you what to click.
- **Not real-time.** The unit of work is a scheduled scan measured in minutes and hours, not a live
  event stream.

---

## 11. Known limitations

Honest list of what the design costs you:

1. **Connect-only scanning without Npcap.** Without a working packet driver, nmap runs in `-sT`
   connect mode: the scan is slower, appears as a completed TCP connection in every target's logs,
   and cannot do OS fingerprinting, SYN stealth or ARP ping. Discovery works around this by reading
   the OS neighbour table instead, but service detection is still connect-based.
2. **No packet inspection.** Home SOC never sees the contents of your traffic. Malware that uses a
   hard-coded IP address, a domain that is not on any list, or an encrypted channel to a legitimate
   host is invisible to it.
3. **No kernel visibility.** Running as a normal user, it can read Defender's own status and the
   Defender/Operational, System and PowerShell/Operational event logs, but not the Security log, and
   it cannot see process creation, driver loads or injected code. Its picture of this computer is the
   picture Windows hands to an unprivileged process.
4. **DNS filtering is bypassable by DoH.** A browser or app that resolves names over HTTPS (Firefox,
   Chrome, many smart devices with hard-coded resolvers) never asks the LAN resolver at all, and its
   lookups will not appear in the query log or be filtered. So is anything that talks to an IP address
   directly. Blocking a name is also not blocking a connection: a device that already has the address
   cached, or that uses a different resolver, still connects.
5. **Blocklists are someone else's judgement.** A false positive breaks a site until you add an
   override; a domain that is not on a list is not blocked. The lists are also large — the DNS policy
   holds them in memory.
6. **Version-based CVE matching is inference, not proof.** A banner saying "lighttpd 1.4.69" is
   matched against KEV and NVD by name and version. Backported vendor patches, custom builds and lying
   banners all produce wrong answers in both directions, which is why KEV matches without a usable
   version are reported as "possible" (`NET-VUL-002`) rather than confirmed.
7. **Only the machine it runs on is deeply inspected.** Every other device on the LAN is seen from the
   outside: MAC, IP, hostname, vendor, open ports, banners. Home SOC has no agent on your phone, your
   TV or your printer.
8. **The gateway is a black box.** Home SOC can port-scan it, ask it for UPnP port mappings and check
   your public IP against Shodan's InternetDB, but it cannot read your router's configuration or
   change it. On a common class of carrier-supplied gateway, DHCP cannot even be pointed at a custom
   DNS server — each device has to be configured by hand.
9. **The whole thing stops when the process stops.** There is no watchdog and no service wrapper; on a
   laptop that sleeps, scans and DNS filtering sleep with it.
10. **Single SQLite writer.** All writes serialise behind one lock. That is fine at home-network
    scale, and it is a hard ceiling if you point this at something much larger.
