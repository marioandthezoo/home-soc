# Home SOC — Build Specification (v1)

This is the build contract. Every module, table, config key, finding ID, route and file path below is normative.
When the spec is silent, pick the simplest option and leave a `# SPEC-GAP:` comment.

Target: Windows 11 Home first (no admin, no Docker, nmap in connect-only mode), Python 3.14, graceful on Linux/macOS.
Dependencies: `flask`, `requests`, `dnslib` + standard library only. No CDN assets. No telemetry. MIT.

## 1. Product summary

Home SOC is a single Python process (`python -m homesoc run`) that:

1. **Updates definitions** — threat-intel feeds, CISA KEV, EPSS, OUI vendor DB, DNS blocklists — with ETag caching.
2. **Scans** — discovers every LAN device (ARP-first), service-scans devices (nmap, with a pure-Python fallback),
   matches services to KEV/NVD/EPSS, audits the host's own posture (Defender AV, firewall, updates, accounts, persistence),
   checks WAN exposure (public IP, Shodan InternetDB, UPnP port mappings), checks Wi-Fi security.
3. **Alerts** — findings with severity, lifecycle and step-by-step remediation on a local dashboard; notifications via
   ntfy / Discord / generic webhook / Windows toast.
4. **Filters DNS for the whole LAN** — an embedded resolver (UDP+TCP 53) that blocks ads/trackers and sinkholes malicious
   domains from blocklists and reputation lookups (VirusTotal with the user's key, URLhaus), with query log and allow/deny lists.
5. **Shows telemetry** — every job, scan, DNS query, feed update and finding change is recorded and charted.

## 2. Repository layout

```
Home_SOC/
  README.md  LICENSE  SECURITY.md  CONTRIBUTING.md  .gitignore
  pyproject.toml  requirements.txt  config.example.toml
  run.bat  run.sh
  scripts/install.ps1  scripts/install.sh  scripts/enable-lan-dns.ps1  scripts/make-autostart.ps1
  homesoc/
    __init__.py  __main__.py  cli.py  config.py  db.py  models.py  scheduler.py  util.py  paths.py
    feeds/      __init__.py registry.py updater.py parsers.py
    scanners/   __init__.py discovery.py ports.py nmap_xml.py services.py exposure.py mdns_ssdp.py
                host_windows.py host_posix.py defender.py updates.py wifi.py persistence.py files.py
                ps/posture.ps1  ps/defender.ps1  ps/updates.ps1  ps/persistence.ps1
    vulns/      __init__.py matcher.py cpe.py enrich.py
    findings/   __init__.py catalog.py engine.py score.py
    notify/     __init__.py channels.py
    dnsfilter/  __init__.py server.py policy.py upstream.py cache.py reputation.py querylog.py
    web/        __init__.py app.py api.py templates/*.html static/app.js static/style.css static/charts.js
  tests/  conftest.py test_*.py  fixtures/{nmap,feeds,posture}/...
  docs/   SPEC.md ARCHITECTURE.md RESEARCH.md GUIDE_HOME_PROTECTION.md NETWORK_DNS_SETUP.md PLAYBOOKS.md
  data/   (runtime, gitignored) homesoc.db  feeds/  logs/
```

## 3. Paths, config, settings

`homesoc/paths.py`
```python
def project_root() -> Path            # folder containing pyproject.toml (walk up from __file__)
def data_dir() -> Path                # env HOMESOC_DATA or project_root()/"data"; created on demand
def feeds_dir() -> Path               # data_dir()/"feeds"
def logs_dir() -> Path                # data_dir()/"logs"
def db_path() -> Path                 # data_dir()/"homesoc.db"
def config_path() -> Path             # env HOMESOC_CONFIG or project_root()/"config.toml"
```

`homesoc/config.py` — reads `config.toml` with `tomllib`, deep-merged over `DEFAULTS`, then over the SQLite `settings`
table (runtime overrides set from the dashboard). Exposes:
```python
@dataclass(frozen=True) class Config: ...   # nested dataclasses mirroring the TOML sections below
def load(conn: sqlite3.Connection | None = None) -> Config
def write_example(path: Path) -> None       # writes config.example.toml content
def set_override(conn, key: str, value: str) -> None   # dotted key e.g. "dns.enabled"
```

`config.example.toml` — every key with its default:
```toml
[general]
name = "Home SOC"
timezone = "local"                 # display only; storage is UTC ISO-8601
log_level = "INFO"

[web]
host = "127.0.0.1"                 # set 0.0.0.0 to reach the dashboard from other devices (then set token!)
port = 8787
token = ""                         # if non-empty, required as ?token= or X-Token header / login cookie
refresh_seconds = 15

[network]
cidr = "auto"                      # "auto" = the /24 of the default interface, or e.g. "192.168.1.0/24"
gateway = "auto"
exclude = []                       # IPs never to port-scan (fragile devices)
fragile_vendors = ["Sonos", "Philips", "Hue", "Ring", "Nest", "Ecobee", "Roku", "Epson", "Brother", "Canon", "HP"]
                                   # devices whose vendor matches are scanned with the gentle profile only
discovery_ports = [80, 443, 22, 445, 139, 8080, 62078, 7000, 9100, 1900, 5353, 8443, 3389, 23, 21, 53]
discovery_threads = 128
discovery_timeout = 0.4

[scan]
use_nmap = true                    # falls back to the python scanner when nmap is missing
nmap_top_ports = 100
nmap_timing = "T3"                 # never faster than T3 on home networks
version_detection = true
gentle_top_ports = 25              # for fragile devices
per_host_timeout_sec = 180
max_parallel_hosts = 3
scan_gateway = true

[host]
posture = true
persistence_baseline = true        # alert on NEW autostart entries after the first baseline
files_check = true                 # hash new files in Downloads (last 24h) and look them up (VirusTotal key required)
files_dirs = ["~/Downloads"]

[vulns]
kev = true
nvd_enrich = true                  # per-service NVD 2.0 lookups, rate-limited (5 req / 30 s without key)
nvd_api_key = ""
epss = true
min_cvss_report = 7.0

[feeds]
enabled = true
kev_hours = 6
epss_hours = 24
oui_hours = 168
blocklists_hours = 12
threatintel_hours = 6
max_download_mb = 64

[dns]
enabled = false                    # turn on to run the LAN-wide resolver
listen = "0.0.0.0"
port = 53
upstreams = ["1.1.1.2", "9.9.9.9"] # UDP upstreams; 1.1.1.2 = Cloudflare malware-blocking, 9.9.9.9 = Quad9
doh_upstream = "https://cloudflare-dns.com/dns-query"   # used when udp upstreams fail; "" disables
block_mode = "null"                # "null" -> 0.0.0.0 / :: with TTL 60 ; "nxdomain"
cache_max_entries = 20000
lists = ["oisd_small", "hagezi_pro", "urlhaus", "threatfox", "phishing_army", "openphish"]   # names from feeds registry
log_queries = true
log_retention_days = 14
virustotal_api_key = ""
virustotal_daily_budget = 400      # free tier is 500/day, 4/min; keep headroom
reputation_min_malicious_votes = 2
reputation_ttl_hours = 72

[notify]
min_severity = "high"              # notify on new findings at/above this
ntfy_url = ""                      # e.g. https://ntfy.sh/your-secret-topic
discord_webhook = ""
webhook_url = ""                   # generic JSON POST
windows_toast = true
digest_hour = 8                    # daily digest local hour (-1 disables)

[schedule]
discovery_minutes = 10
services_hours = 24
host_hours = 6
exposure_hours = 12
feeds_hours = 6
```

## 4. Database (`homesoc/db.py`, owner: core)

SQLite, WAL mode, `PRAGMA foreign_keys=ON`, `check_same_thread=False` with a module-level `threading.Lock` around writes.
All timestamps are UTC ISO-8601 strings (`util.utcnow_iso()`). JSON columns are TEXT containing JSON.

```python
def connect(path: Path | None = None) -> sqlite3.Connection   # row_factory = sqlite3.Row
def init_schema(conn) -> None                                    # idempotent CREATE TABLE IF NOT EXISTS + migrations table
def write(conn, sql: str, params=()) -> int                      # locked execute+commit, returns lastrowid
def writemany(conn, sql, seq) -> None
def query(conn, sql, params=()) -> list[sqlite3.Row]
def one(conn, sql, params=()) -> sqlite3.Row | None
def get_setting(conn, key, default=None) -> str | None
def set_setting(conn, key, value) -> None
def record_event(conn, level: str, source: str, message: str, data: dict | None = None) -> None
def record_metric(conn, name: str, value: float, tags: dict | None = None) -> None
```

Tables (column: type; `*` = NOT NULL):

- `schema_migrations(version INTEGER PK, applied_at TEXT*)`
- `settings(key TEXT PK, value TEXT*, updated_at TEXT*)`
- `feeds(name TEXT PK, url TEXT*, kind TEXT*, etag TEXT, last_modified TEXT, last_checked TEXT, last_updated TEXT,
  status TEXT* DEFAULT 'never', bytes INTEGER, entries INTEGER, error TEXT, enabled INTEGER* DEFAULT 1)`
- `devices(id INTEGER PK, mac TEXT UNIQUE, ip TEXT, hostname TEXT, vendor TEXT, kind TEXT, nickname TEXT,
  trusted INTEGER* DEFAULT 0, notes TEXT, first_seen TEXT*, last_seen TEXT*, online INTEGER* DEFAULT 1,
  last_service_scan TEXT, mdns_services TEXT)`  — index on ip. Devices without a MAC (e.g. this host's own
  IP or off-subnet) use mac = 'ip:'||ip.
- `device_sightings(id INTEGER PK, device_id INTEGER* REFERENCES devices(id), ip TEXT*, seen_at TEXT*, method TEXT*)`
  index (device_id, seen_at)
- `services(id INTEGER PK, device_id INTEGER* REFERENCES devices(id), port INTEGER*, proto TEXT* DEFAULT 'tcp',
  state TEXT*, name TEXT, product TEXT, version TEXT, extrainfo TEXT, cpe TEXT, tunnel TEXT, first_seen TEXT*,
  last_seen TEXT*, UNIQUE(device_id, port, proto))`
- `vulns(id INTEGER PK, device_id INTEGER* REFERENCES devices(id), service_id INTEGER REFERENCES services(id),
  cve TEXT*, source TEXT*, kev INTEGER* DEFAULT 0, cvss REAL, epss REAL, title TEXT, published TEXT,
  matched_on TEXT*, remediation TEXT, first_seen TEXT*, last_seen TEXT*, UNIQUE(device_id, cve, matched_on))`
- `host_checks(check_id TEXT PK, status TEXT*, value TEXT, expected TEXT, checked_at TEXT*, needs_admin INTEGER* DEFAULT 0)`
  status ∈ {pass, fail, warn, unknown, needs_admin}
- `software(id INTEGER PK, name TEXT*, version TEXT, available TEXT, source TEXT*, publisher TEXT, seen_at TEXT*,
  UNIQUE(name, source))`  — source ∈ {winget, registry, apt, brew}
- `persistence(id INTEGER PK, kind TEXT*, name TEXT*, command TEXT, location TEXT*, first_seen TEXT*, last_seen TEXT*,
  baseline INTEGER* DEFAULT 0, UNIQUE(kind, location, name))`  kind ∈ {run_key, startup_folder, scheduled_task, service}
- `file_checks(sha256 TEXT PK, path TEXT*, size INTEGER, first_seen TEXT*, verdict TEXT*, source TEXT, detail TEXT)`
- `findings(id INTEGER PK, finding_id TEXT*, subject TEXT*, dedupe_key TEXT* UNIQUE, severity TEXT*, title TEXT*,
  detail TEXT, evidence TEXT, status TEXT* DEFAULT 'open', source TEXT*, first_seen TEXT*, last_seen TEXT*,
  resolved_at TEXT, occurrences INTEGER* DEFAULT 1, device_id INTEGER REFERENCES devices(id))`
  status ∈ {open, acknowledged, resolved, suppressed}; index (status, severity)
- `finding_events(id INTEGER PK, finding_row_id INTEGER* REFERENCES findings(id), event TEXT*, at TEXT*, note TEXT)`
- `scans(id INTEGER PK, kind TEXT*, started_at TEXT*, finished_at TEXT, status TEXT*, summary TEXT, error TEXT)`
  kind ∈ {discovery, services, host, exposure, feeds, files, full}
- `events(id INTEGER PK, ts TEXT*, level TEXT*, source TEXT*, message TEXT*, data TEXT)` index ts
- `metrics(id INTEGER PK, ts TEXT*, name TEXT*, value REAL*, tags TEXT)` index (name, ts)
- `dns_queries(id INTEGER PK, ts TEXT*, client TEXT*, qname TEXT*, qtype TEXT*, action TEXT*, reason TEXT,
  ms REAL)` index ts, index (action, ts); action ∈ {allow, block, cache, error}
- `dns_hourly(hour TEXT*, client TEXT*, total INTEGER*, blocked INTEGER*, PRIMARY KEY(hour, client))`
- `dns_overrides(domain TEXT PK, action TEXT*, note TEXT, created_at TEXT*)` action ∈ {allow, deny}
- `reputation(domain TEXT PK, source TEXT*, verdict TEXT*, malicious INTEGER* DEFAULT 0, suspicious INTEGER* DEFAULT 0,
  checked_at TEXT*, raw TEXT)` verdict ∈ {malicious, suspicious, clean, unknown}
- `notifications(id INTEGER PK, ts TEXT*, channel TEXT*, subject TEXT*, status TEXT*, error TEXT)`
- `jobs(name TEXT PK, last_run TEXT, last_status TEXT, last_duration_sec REAL, next_run TEXT, runs INTEGER* DEFAULT 0,
  failures INTEGER* DEFAULT 0, last_error TEXT)`

Table ownership (who writes): core → settings/events/metrics/jobs/scans/schema; feeds → feeds; scanners.discovery →
devices/device_sightings; scanners.ports → services; vulns → vulns; scanners.host_* / defender / updates / persistence /
files → host_checks/software/persistence/file_checks; findings.engine → findings/finding_events; dnsfilter →
dns_queries/dns_hourly/dns_overrides/reputation; notify → notifications. Anyone may read anything.

## 5. Models (`homesoc/models.py`, owner: core)

```python
@dataclass class Device: id: int|None; mac: str; ip: str; hostname: str|None; vendor: str|None; kind: str|None;
                         first_seen: str; last_seen: str; online: bool; trusted: bool = False; nickname: str|None = None
@dataclass class Service: device_id: int; port: int; proto: str; state: str; name: str|None; product: str|None;
                          version: str|None; extrainfo: str|None; cpe: str|None; tunnel: str|None
@dataclass class Vuln: device_id: int; service_id: int|None; cve: str; source: str; kev: bool; cvss: float|None;
                       epss: float|None; title: str|None; published: str|None; matched_on: str; remediation: str|None
@dataclass class HostCheck: check_id: str; status: str; value: str|None = None; expected: str|None = None; needs_admin: bool = False
@dataclass class FindingDraft: finding_id: str; subject: str; evidence: dict = field(default_factory=dict);
                               detail: str|None = None; severity: str|None = None; device_id: int|None = None
                               # subject examples: "host", "device:<mac>", "device:<mac>:443", "wan", "dns:<client>", "feed:<name>"
@dataclass class ScanResult: kind: str; findings: list[FindingDraft]; summary: dict; error: str|None = None
```

Severity values: `critical, high, medium, low, info`. Ordering helper `models.SEVERITY_ORDER`.

## 6. Scanner interface (all scanner modules)

Every scanner exposes exactly:
```python
def run(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False, progress: Callable[[str], None] | None = None) -> ScanResult
```
It writes to the tables it owns, returns findings as drafts (it does NOT persist findings — `findings.engine.apply()` does),
must never raise for expected failures (missing tool, no admin, timeouts → `ScanResult.error` and/or `SOC-*` findings),
and must respect `cfg.network.exclude` and fragile-vendor gentle profiles.

### 6.1 `scanners/discovery.py`
- ARP-first: Windows `Get-NetNeighbor -AddressFamily IPv4` (PowerShell JSON) with `arp -a` fallback; Linux `ip -j neigh`;
  macOS `arp -a`. Then a TCP-connect sweep of `cfg.network.discovery_ports` across the CIDR (thread pool) to refresh the
  neighbor cache and detect hosts, then re-read ARP. Hosts seen in ARP but not in the sweep still count (state Reachable/Stale).
- Hostname: `socket.gethostbyaddr` with 1 s timeout via thread; mDNS names from `mdns_ssdp.py` when available.
- Vendor: `feeds.registry.lookup_vendor(mac)` (OUI); randomized MAC detection (locally administered bit) → kind hint "randomized".
- Upserts devices (by MAC; the host itself by `ip:` key with its real MAC when obtainable via `getmac`/`ip link`), sightings,
  marks devices not seen for > 2 × discovery interval as `online=0`.
- Findings: `NET-DEV-001` new device (subject `device:<mac>`, evidence: ip, hostname, vendor, first_seen) unless `trusted`;
  `NET-DEV-002` unknown vendor / randomized MAC (info).
- Summary: `{hosts_total, hosts_new, hosts_online, duration_sec, method}`; metric `discovery.hosts_online`.

### 6.2 `scanners/ports.py` + `nmap_xml.py`
- `nmap_xml.parse(xml_text: str) -> list[dict]` — hosts with ports/services/cpe; must tolerate partial XML.
- If nmap present: `nmap -sT -sV --version-light -T3 --top-ports N -n -Pn --host-timeout <sec>s -oX - <ip>`;
  fragile devices: `--top-ports gentle_top_ports` without `-sV`. Never `-O`, `-sU`, `--script` in v1.
- Fallback (no nmap): Python connect scan of a built-in top-100 port list + banner grab (recv 256 bytes, 1 s) for a few
  well-known ports (21, 22, 25, 80, 110, 143, 443 via TLS SNI cert subject, 3306, 6379).
- Upserts `services`; marks services not seen this scan for that device as state='closed' (keep row).
- Findings via `scanners/services.py:evaluate(device, services) -> list[FindingDraft]` (rules table in §9).
- `quick=True` scans only the gateway and up to 5 most-recently-seen devices; full scans all online devices
  with `max_parallel_hosts` workers. Records `devices.last_service_scan`.

### 6.3 `scanners/exposure.py`
- Public IP via `https://api.ipify.org?format=json` (5 s). Shodan InternetDB `https://internetdb.shodan.io/<ip>`:
  200 → ports/vulns/cpes/hostnames; 404/"No information" → clean.
- UPnP: SSDP M-SEARCH bound to the default interface (ST `urn:schemas-upnp-org:device:InternetGatewayDevice:1`, 3 s);
  if an IGD answers, fetch its description XML, find WANIPConnection/WANPPPConnection, enumerate
  `GetGenericPortMappingEntry` 0..99 until error → mappings.
- Findings: `NET-WAN-001` open WAN ports, `NET-WAN-002` WAN vulns, `NET-WAN-003` UPnP mappings, `NET-RTR-002` UPnP IGD present.
- Summary stored in `settings` keys `exposure.public_ip`, `exposure.last_json`.

### 6.4 `scanners/mdns_ssdp.py`
- `probe(interface_ip: str, seconds: float = 3.0) -> dict[str, dict]` — mDNS `_services._dns-sd._udp.local` PTR (QU bit)
  parsed with dnslib, plus SSDP `ssdp:all`. Returns `{ip: {"mdns": [service types], "ssdp": [{"st","server","location"}]}}`.
  Purely passive-ish (two multicast packets); no findings; used by discovery for hostnames/kinds.

### 6.5 `scanners/host_windows.py` (+ `ps/posture.ps1`)
- One `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File posture.ps1` call (timeout 240 s) returning JSON
  (the shape of the probe in docs/TESTED_ENVIRONMENT.md is the reference: defender, firewall, smb, rdp, uac, lsa, secure_boot, tpm,
  device_guard, bitlocker, admins, guest, builtin_admin, listeners, hotfix, wifi, dns, llmnr, ps_v2, autologon, smartscreen,
  smart_app_control, screen lock, is_admin). Checks that throw AccessDenied are reported as `needs_admin`.
- Writes `host_checks` rows for every check ID `WIN-*` in §9 and returns the corresponding findings when status is fail/warn.
- `SOC-SYS-002` (info) when not admin, listing which checks were skipped.
- `host_posix.py`: firewall (ufw/pf), pending updates (apt/brew/softwareupdate), sshd PermitRootLogin, disk encryption
  (FileVault/LUKS heuristics), listening ports — emits `POSIX-*` findings; minimal but real.

### 6.6 `scanners/defender.py` (+ `ps/defender.ps1`)  — the AV integration
- `status(cfg) -> dict` (Get-MpComputerStatus + Get-MpPreference subset), `threats(cfg, days=30) -> list[dict]`
  (Get-MpThreatDetection + Defender/Operational events 1006/1007/1116/1117/1118/1119/5001/5010/5012 via Get-WinEvent),
  `trigger_quick_scan(cfg) -> bool` (`MpCmdRun.exe -Scan -ScanType 1`, background), `update_signatures(cfg) -> bool`
  (`MpCmdRun.exe -SignatureUpdate`). MpCmdRun path: `%ProgramFiles%\Windows Defender\MpCmdRun.exe` or the
  `Get-MpComputerStatus`-reported platform folder under `%ProgramData%\Microsoft\Windows Defender\Platform\<ver>\`.
- Optional ClamAV: if `clamscan` on PATH, expose `clamscan_available()`; not required.
- Findings `WIN-DEF-*` (§9). Stores latest status JSON under settings key `defender.status_json`.

### 6.7 `scanners/updates.py` (+ `ps/updates.ps1`)
- Windows: Windows Update COM search `IsInstalled=0 and IsHidden=0` (titles, KB, severity if present), last hotfix date,
  `winget upgrade --include-unknown --accept-source-agreements --disable-interactivity` parsed into `software`
  (name, id, current, available). Findings `WIN-UPD-*`. Linux/mac: apt/brew/softwareupdate counts → `POSIX-UPD-001`.

### 6.8 `scanners/wifi.py`
- Windows `netsh wlan show interfaces` (SSID, auth, cipher, band); Linux `nmcli -t -f ACTIVE,SSID,SECURITY dev wifi`;
  macOS `airport -I`/`wdutil`. Findings `NET-WIFI-*`. Never stores the Wi-Fi password.

### 6.9 `scanners/persistence.py` (+ `ps/persistence.ps1`)
- Run/RunOnce keys (HKCU+HKLM), Startup folders, scheduled tasks (non-Microsoft authors), services with StartMode Auto and
  non-Microsoft binaries (fallback: System log 7045 in last 7 days). First run stores baseline=1 for all; later runs emit
  `WIN-PER-001/002/003` for new entries.

### 6.10 `scanners/files.py`
- For each dir in `host.files_dirs`, files modified in last 24 h and < 64 MB: SHA-256; look up unknown hashes in
  VirusTotal `/api/v3/files/<sha256>` (only if `dns.virustotal_api_key` set; shares the daily budget via `dnsfilter.reputation`
  budget helper) and store verdicts in `file_checks`. Findings `AV-FILE-001` (malicious), `AV-FILE-002` (suspicious).
  Never uploads files.

## 7. Feeds (`homesoc/feeds/`, owner: feeds)

`registry.py` — `FEEDS: dict[str, FeedSpec]` with `FeedSpec(name, url, kind, parser, hours, license_note, enabled_default)`.
kinds: `kev, epss, oui, hosts, domains, adblock, ip, json`. Verified URLs (use exactly these):

| name | url | kind | cadence |
|---|---|---|---|
| kev | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | kev | 6h |
| epss | https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | epss | 24h |
| oui | https://www.wireshark.org/download/automated/data/manuf | oui | 168h |
| oisd_small | https://small.oisd.nl | domains (ABP-style `||domain^`) | 12h |
| oisd_big | https://big.oisd.nl | domains | 12h (disabled by default) |
| hagezi_pro | https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt | domains (wildcard `*.domain`) | 12h |
| stevenblack | https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | hosts | 24h (disabled by default) |
| adguard_dns | https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt | adblock | 12h (disabled by default) |
| urlhaus | https://urlhaus.abuse.ch/downloads/hostfile/ | hosts | 6h |
| urlhaus_filter | https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt | hosts | 6h |
| threatfox | https://threatfox.abuse.ch/downloads/hostfile/ | hosts | 6h |
| phishing_army | https://phishing.army/download/phishing_army_blocklist.txt | domains (plain) | 6h |
| openphish | https://openphish.com/feed.txt | urls → domains | 6h |
| feodo_ips | https://feodotracker.abuse.ch/downloads/ipblocklist.json | ip | 6h |
| spamhaus_drop | https://www.spamhaus.org/drop/drop.txt | ip (CIDR) | 24h |

`updater.py`
```python
def update(cfg, conn, names: list[str] | None = None, force: bool = False, progress=None) -> dict[str, str]  # name -> status
   # conditional GET with If-None-Match / If-Modified-Since, streaming to feeds_dir()/<name>.tmp, size cap, atomic replace,
   # gzip transparently for .gz, sha256 recorded; statuses: updated | not_modified | error | skipped
def feed_path(name) -> Path
def is_stale(conn, name, hours) -> bool
```
`parsers.py` — pure functions, each returns an iterator of normalized entries:
`parse_hosts(text)`, `parse_domains(text)`, `parse_adblock(text)`, `parse_wildcard(text)`, `parse_ips(text)`,
`parse_kev(json_text) -> list[dict]`, `parse_epss(csv_text) -> dict[str, float]`, `parse_oui(text) -> dict[str, str]`.
`registry.py` also exposes cached loaders backed by the on-disk files:
`load_kev() -> KevCatalog` (`.by_cve`, `.search(vendor, product) -> list[dict]`, `.count`, `.date_released`),
`load_epss() -> dict[str, float]`, `lookup_vendor(mac) -> str | None` (prefix match 24/28/36 bit),
`load_blocklist(name) -> set[str]`, `load_ipset(name) -> list[ipaddress.IPv4Network]`.

Findings: `SOC-FEED-001` (a feed failing > 48 h), `SOC-FEED-002` (KEV stale > 48 h).

## 8. Vulnerability management (`homesoc/vulns/`, owner: vulns)

- `cpe.py`: `parse_cpe(cpe: str) -> CPE(part, vendor, product, version)`; `guess_cpe(product: str, version: str|None) -> CPE|None`
  with a small alias table (lighttpd, unbound, openssh, nginx, apache httpd, dropbear, busybox, samba, vsftpd, proftpd,
  mysql, mariadb, postgresql, redis, mongodb, rtsp/hikvision/dahua, miniupnpd, dnsmasq, upnp, cups, avahi, iis, rdp).
- `matcher.py`: `match_services(cfg, conn) -> ScanResult` — for every open service with product/cpe: (1) KEV search by
  vendor+product; a KEV entry matches when the product matches and (no version info OR the service version is ≤ the
  highest version mentioned in the KEV notes/vulnerabilityName when a version can be parsed; else flag as "possible" with
  severity high instead of critical); (2) if `nvd_enrich`, `enrich.nvd_for_cpe(cpe, version)` (cached in `vulns` rows +
  settings key `nvd.cache.<cpe>` with 7-day TTL; ≤ 5 requests per 30 s without key, 50 with key; `apiKey` header) →
  count of CVEs, max CVSS v3.1, top 5 CVEs; (3) EPSS from `load_epss()`.
  Upserts `vulns`; findings `NET-VUL-001` (KEV confirmed), `NET-VUL-002` (KEV possible / version unknown), `NET-VUL-003`
  (NVD CVEs with CVSS ≥ min_cvss_report, includes count and max), `NET-VUL-004` (EPSS ≥ 0.5 on any matched CVE).
- `enrich.py`: `nvd_for_cpe(cpe, version, api_key) -> dict|None` using
  `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*&resultsPerPage=50`
  (fallback to `keywordSearch=<product> <version>` when cpe is unknown), respecting 429/403 with backoff; never blocks > 60 s total per scan.
- Software side: `software` rows (winget) → findings `WIN-UPD-003` for any outdated app and `WIN-UPD-004` (high) when the
  outdated app matches a high-risk list (java, adobe, chrome, firefox, edge, zoom, vlc, 7-zip, winrar, putty, openvpn, notepad++,
  teamviewer, anydesk, filezilla, python).

## 9. Findings catalog (`homesoc/findings/catalog.py`, owner: findings)

`CATALOG: dict[str, FindingSpec]` where `FindingSpec(id, severity, title, rationale, remediation: list[str], refs: list[str],
category, emits_per_subject: bool)`. Remediation steps must be click-by-click for Windows 11 Home when applicable, and
include a PowerShell alternative when one exists. Every ID below MUST exist in the catalog; scanners emit only these IDs.

Windows Defender (AV): WIN-DEF-001 AV disabled (critical); 002 real-time protection off (critical); 003 signatures > 3 days old (high);
004 tamper protection off (medium); 005 cloud-delivered protection off (medium); 006 PUA protection off (low);
007 no full scan in 30 days (low); 008 controlled folder access off (low); 009 network protection off (low);
010 no ASR rules (low); 011 threat detected in last 30 days (high; per threat); 012 Defender service unhealthy (high);
013 Smart App Control off (info); 014 sample submission/cloud block level basic (info).
Firewall: WIN-FW-001 profile disabled (critical, per profile); WIN-FW-002 default inbound allow (high).
Updates: WIN-UPD-001 updates pending (medium; high if any title contains "Security" or "Cumulative"); WIN-UPD-002 last
cumulative update > 45 days (high); WIN-UPD-003 outdated app via winget (low, per app); WIN-UPD-004 outdated high-risk app (high, per app).
Accounts: WIN-ACC-001 daily account is Administrator (medium); 002 built-in Administrator enabled (high); 003 Guest enabled (high);
004 autologon enabled (high); 005 UAC off or ConsentPromptBehaviorAdmin=0 (high).
Network services on host: WIN-NET-001 SMBv1 enabled (high); 002 RDP enabled (medium; high if NLA off); 003 SMB signing not
required (low); 004 LLMNR enabled (low); 005 WinRM/Remote Registry listening (medium); 006 unusual LAN listener (low, per port,
excluding 135/139/445/5040/5357/7680/49xxx and the dashboard/DNS ports).
System: WIN-SYS-001 Secure Boot off (medium); 002 BitLocker/device encryption off (high); 003 VBS/HVCI not running (low);
004 LSA protection off (medium); 005 PowerShell v2 enabled (low); 006 SmartScreen off (medium); 007 screen lock not enforced (low);
008 TPM absent/not ready (low).
Persistence: WIN-PER-001 new autostart entry (medium, per entry); 002 new scheduled task (medium); 003 new service (medium).
AV file checks: AV-FILE-001 malicious file in Downloads (critical); AV-FILE-002 suspicious file (medium).
POSIX: POSIX-FW-001 firewall inactive (high); POSIX-UPD-001 updates pending (medium); POSIX-SSH-001 root login permitted (high);
POSIX-ENC-001 disk not encrypted (medium); POSIX-NET-001 unusual listener (low).
Devices: NET-DEV-001 new device (medium; info if trusted); NET-DEV-002 unknown vendor / randomized MAC (info);
NET-DEV-003 device offline > 30 days still trusted (info).
Services on LAN devices (per device:port): NET-SVC-001 Telnet (critical); 002 FTP (high); 003 SMB on non-Windows device (medium);
004 RDP/VNC exposed (medium); 005 HTTP admin without HTTPS on router/IoT (low); 006 UPnP/SSDP control port (medium);
007 database port (high); 008 raw printer port 9100 / IPP without auth (low); 009 SNMP public (medium, only if nmap reports);
010 RTSP camera stream (medium); 011 outdated SSH server (low); 012 mDNS/other service exposing device model (info).
Vulnerabilities: NET-VUL-001 KEV match confirmed (critical); 002 KEV possible (high); 003 known CVEs ≥ threshold (medium);
004 high EPSS (high).
WAN: NET-WAN-001 open WAN ports (critical, per port); 002 WAN vulns (critical); 003 UPnP port mapping (high, per mapping);
NET-RTR-002 UPnP IGD enabled (medium).
Wi-Fi: NET-WIFI-001 open/WEP (critical); 002 WPA2 without WPA3 (info); 003 TKIP (high); 004 WPS likely enabled (info, only if detectable).
DNS filter: NET-DNS-001 devices not using Home SOC DNS (info, when enabled); 002 resolver not running / port conflict (high);
003 blocklists stale > 3 days (medium); 004 client hit a malicious domain (high, per client+domain, 24 h dedupe);
005 upstream unreachable (high); 006 resolver bound to LAN without firewall rule (info).
SOC health: SOC-FEED-001 feed failing > 48 h (medium); 002 KEV stale (medium); SOC-SYS-001 nmap missing (info);
002 not admin (info); 003 dashboard exposed on LAN without token (high); 004 scheduler job failing repeatedly (medium).

## 10. Findings engine (`homesoc/findings/engine.py`, owner: findings)

```python
def dedupe_key(draft: FindingDraft) -> str            # f"{finding_id}|{subject}" (+ "|" + evidence['key'] if present)
def apply(conn, drafts: list[FindingDraft], source: str, *, scope: str | None = None) -> ApplyResult
   # upsert by dedupe_key: new → status open, first_seen; existing open/ack → last_seen, occurrences+1, evidence refreshed;
   # existing resolved → reopen (event 'reopened'); suppressed stays suppressed (still updates last_seen).
   # scope: when given (e.g. "host", "device:<mac>", "wan", "dns"), findings from this source whose subject starts with scope and
   #   were NOT in drafts are auto-resolved (event 'auto_resolved') — "it went away".
   # Returns ApplyResult(new=[...], reopened=[...], resolved=[...], updated=int).
def set_status(conn, row_id: int, status: str, note: str | None = None) -> None
def list_findings(conn, *, status=None, severity=None, subject_prefix=None, limit=500) -> list[dict]
def counts(conn) -> dict            # {"open": {"critical": n, ...}, "acknowledged": ..., ...}
```
`score.py`: `security_score(conn) -> int` 0–100: start 100, subtract per open finding (critical 25, high 10, medium 4, low 1,
info 0), floor 0; plus `grade(score) -> "A".."F"`; `trend(conn, days=30) -> list[[date, score]]` from metric `score`.

## 11. Notifications (`homesoc/notify/channels.py`, owner: findings)

```python
def notify_new_findings(cfg, conn, new: list[dict]) -> None      # filters by min_severity; one message per batch
def send(cfg, conn, subject: str, body: str, *, severity="info") -> dict[str, bool]   # every configured channel
def test_channels(cfg, conn) -> dict[str, bool]
```
ntfy: `POST <ntfy_url>` body=text, headers Title, Priority (critical→5, high→4, else 3), Tags.
Discord: `POST webhook {"content": ..., "embeds":[{"title","description","color"}]}`.
Generic: `POST webhook_url {"subject","body","severity","findings":[...]}`.
Windows toast: PowerShell WinRT `Windows.UI.Notifications.ToastNotificationManager` with app id "Home SOC" (works without modules).
Daily digest at `digest_hour` (scheduler job): counts + top 5 open findings.

## 12. DNS filter (`homesoc/dnsfilter/`, owner: dnsfilter)

- `policy.py`: `Policy.load(cfg, conn)`; `decide(qname: str, qtype: str, client: str) -> Decision(action, reason)`
  order: dns_overrides allow → dns_overrides deny → built-in never-block (localhost, *.local, *.arpa, the upstreams' names)
  → blocklists (exact and parent-suffix match against a `set[str]`; wildcard lists load as suffix rules) → reputation
  table (verdict malicious with `malicious ≥ reputation_min_malicious_votes`) → allow. Lists reload when feed files change
  (mtime check every 60 s). Memory target: ≤ 150 MB with oisd_small + hagezi_pro + malware lists.
- `server.py`: `DnsServer(cfg, conn).start()/stop()`; threads: UDP receiver (socketserver.ThreadingUDPServer) and TCP
  (ThreadingTCPServer, 2-byte length framing), binding `cfg.dns.listen:port`; per-query: parse with dnslib; refuse non-IN
  class and `ANY`; cache lookup (`cache.py`, TTL-respecting, min TTL 30 s, negative cache 60 s, max entries); policy;
  block → `block_mode` response (null: A 0.0.0.0 / AAAA :: TTL 60; other qtypes NODATA; nxdomain: RCODE NXDOMAIN);
  allow → `upstream.py` (UDP to upstreams in order, 2 s timeout, TCP retry on TC bit, DoH POST wire-format fallback
  `application/dns-message`); errors → SERVFAIL. Rate limit: ≥ 300 qps per client → drop (amplification guard).
  Port-in-use → log + `NET-DNS-002` + keep the rest of the app running.
- `querylog.py`: in-memory queue flushed to `dns_queries` every 2 s or 500 rows; hourly rollup into `dns_hourly`;
  retention purge daily. `top_blocked(conn, hours) `, `top_clients(conn, hours)`, `recent(conn, limit, client=None, action=None)`,
  `series(conn, hours) -> list[{hour,total,blocked}]`.
- `reputation.py`: `Budget` (daily counter persisted in settings `vt.budget.<date>`, 4/min token bucket);
  `lookup_domain(cfg, conn, domain) -> verdict` — VirusTotal `GET /api/v3/domains/<d>` header `x-apikey`, read
  `last_analysis_stats.{malicious,suspicious}`; URLhaus `POST https://urlhaus-api.abuse.ch/v1/host/` (host=domain; optional
  Auth-Key) as a keyless second source; cached in `reputation` for `reputation_ttl_hours`. Newly-seen domains (first query
  for a registrable domain in the last 24 h, excluding top-1k well-known list embedded in the module) are enqueued for async
  lookup by a worker thread; lookups never block a DNS answer. Malicious verdicts also emit `NET-DNS-004` retroactively
  for the client that queried.
- Health: `NET-DNS-005` when all upstreams fail for 60 s; `NET-DNS-003` when list files older than 3 days; `NET-DNS-001`
  when enabled and the number of distinct clients in 24 h < 2.

## 13. Scheduler (`homesoc/scheduler.py`, owner: core)

```python
@dataclass class Job: name: str; interval_sec: int; func: Callable[[], None]; run_at_start: bool = True
class Scheduler: def __init__(self, cfg, conn, jobs: list[Job]); start(); stop(); run_now(name) -> bool; status() -> list[dict]
```
Single worker thread + a lock per job (no overlapping runs of the same job); each run wraps in try/except, records to
`jobs` and `events`, `record_metric("job.duration", ...)`. Jobs (built in `cli.build_jobs`): `feeds` (feeds_hours),
`discovery` (discovery_minutes), `services` (services_hours, quick=False), `host` (host_hours), `exposure` (exposure_hours),
`vulns` (after services), `files` (24 h), `dns_rollup` (1 h), `digest` (daily at digest_hour), `score` (1 h: record metric
`score`). Each scan job = scanner.run → `findings.engine.apply(scope=...)` → `notify_new_findings`.

## 14. CLI (`homesoc/cli.py`, argparse)

```
python -m homesoc init                     # create data dir, config.toml from example if missing, schema, first feed update (oui,kev)
python -m homesoc update [--feeds a,b] [--force]
python -m homesoc scan [--quick] [--only discovery,services,host,exposure,vulns,files,wifi]
python -m homesoc serve [--host H] [--port P]        # dashboard only
python -m homesoc dns [--port P]                      # resolver only (foreground, Ctrl-C)
python -m homesoc run                                 # dashboard + scheduler + resolver (if dns.enabled) — the normal mode
python -m homesoc status                              # score, counts, last scans, feeds, jobs (rich-free plain text)
python -m homesoc findings [--status open] [--severity high]
python -m homesoc export --out report.json            # findings + devices + vulns
python -m homesoc defender --quick-scan | --update    # AV actions
python -m homesoc dns-test <domain>                   # policy decision + upstream answer
```
Exit codes: 0 ok, 1 error, 2 bad args. Logging to stderr and `logs/homesoc.log` (RotatingFileHandler 5×2 MB).

## 15. Web dashboard (`homesoc/web/`, owner: web)

Flask app factory `create_app(cfg, conn, scheduler=None, dns_server=None) -> Flask`. Server-rendered Jinja templates with a
shared `base.html` (sidebar nav, severity badges, score gauge), vanilla JS in `static/app.js` polling `/api/summary` every
`web.refresh_seconds`, and `static/charts.js` — a tiny dependency-free SVG chart helper (bar, line/sparkline, donut).
Auth: if `web.token` set, require it (cookie set by `/login?token=`); reject others with 401. Always set
`X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self'`. All POSTs require header `X-Requested-With: fetch`
(CSRF guard) and are JSON.

Pages (GET, HTML):
- `/` Overview: score gauge + grade + 30-day trend sparkline; open findings by severity (donut); devices online/total;
  DNS 24 h total/blocked (%) + 24 h bar chart per hour; last run of each job with status; feed freshness table;
  latest 20 events; "Run quick scan / full scan / update feeds" buttons.
- `/findings` filters (status, severity, category, search), table, row expand → detail, evidence (pretty JSON),
  remediation steps, refs, buttons Acknowledge / Resolve / Suppress / Reopen.
- `/devices` inventory (nickname/hostname, ip, mac, vendor, kind, online, first/last seen, open ports count, open findings,
  trusted toggle); `/devices/<id>` detail with services, vulns, sightings timeline (last 7 days presence bar), findings,
  edit nickname/notes/trusted, "Scan this device now".
- `/vulns` table (cve, kev badge, cvss, epss, device, service, matched_on, first seen) + filters; link to NVD/KEV.
- `/host` posture: grouped check list (pass/fail/warn/needs_admin badges) + Defender panel (status, signature age, last scans,
  threats list, buttons Quick scan / Update signatures) + Updates panel (pending Windows updates, outdated apps) +
  Persistence panel (autostarts with new badge) + Listeners.
- `/dns` stats cards, per-hour chart, top blocked domains, top clients, lists table (name, entries, updated, enabled),
  overrides editor (add allow/deny), live query log tail (filter client/action) with "allow"/"block" quick actions,
  reputation cache table, VirusTotal budget used today.
- `/telemetry` every metric series as small charts (score, discovery.hosts_online, job.duration by job, dns.qps,
  feeds bytes), jobs table (runs, failures, last duration, next run), scans history, events stream with level filter.
- `/scans` history + run buttons; `/settings` form for the editable keys (web, network.exclude, scan, dns, notify, schedule)
  saved as settings overrides + "Test notifications" + "Download support bundle (json)".

JSON API (all under `/api`, GET unless noted):
`/api/summary` → `{score, grade, counts, devices:{online,total}, dns:{total24h,blocked24h,clients24h,running}, jobs:[...], feeds:[...], last_scans:{kind: ts}, events:[...]}`;
`/api/findings?status&severity&q` → list; `POST /api/findings/<id>/status {status, note}`;
`/api/devices`, `/api/devices/<id>`, `POST /api/devices/<id> {nickname, notes, trusted}`, `POST /api/devices/<id>/scan`;
`/api/vulns`; `/api/host` → `{checks, defender, updates, software, persistence, listeners}`; `POST /api/defender/quick-scan`, `POST /api/defender/update`;
`/api/dns/summary`, `/api/dns/series?hours=24`, `/api/dns/top?kind=blocked|clients&hours=24`, `/api/dns/log?limit&client&action`,
`/api/dns/lists`, `POST /api/dns/override {domain, action, note}`, `DELETE /api/dns/override/<domain>`, `/api/dns/reputation`;
`/api/telemetry/metrics?name&hours`, `/api/telemetry/jobs`, `/api/telemetry/events?level&limit`, `/api/scans`;
`POST /api/scan {kind: quick|full|host|exposure|feeds|files}` (runs via scheduler.run_now or a background thread);
`/api/settings` GET/POST; `POST /api/notify/test`; `/api/export`.

Look: clean dark theme by default (CSS variables, light theme via `prefers-color-scheme`), monospace for IPs/MACs, severity
colors critical #e5484d, high #f76b15, medium #ffb224, low #46a758, info #3e63dd. Responsive down to 800 px.

## 16. Install & run scripts (owner: core)

- `run.bat`: `@echo off`, cd to script dir, `if not exist .venv python -m venv .venv`, activate, `pip install -r requirements.txt -q`,
  `python -m homesoc init` (idempotent), `python -m homesoc run`. `run.sh` equivalent.
- `scripts/install.ps1`: same as run.bat steps without run; creates a Startup-folder shortcut to run.bat (no admin);
  prints next steps. `scripts/make-autostart.ps1`: `-Mode startup|task` (task requires admin, uses schtasks at logon, highest).
- `scripts/enable-lan-dns.ps1` (requires admin): `New-NetFirewallRule -DisplayName "Home SOC DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Private` (+TCP), prints router instructions.
- `requirements.txt`: a hash-locked runtime lock generated with pip-compile (`flask==3.1.3`, `requests==2.34.2`,
  `dnslib==0.9.26`, their whole transitive closure and pip), installed with `--require-hashes`. `pytest>=9.0.3`
  is only in the pyproject `[dev]` extra, never in a production venv.
- `pyproject.toml`: name `homesoc`, version 0.1.0, `[project.scripts] homesoc = "homesoc.cli:main"`.

## 17. Tests (owner: each package owns its test file; fixtures created by the owner)

Unit (offline, must pass in CI): nmap XML parsing (fixtures/nmap/router.xml, printer.xml, partial.xml), feed parsers
(fixtures/feeds/ hosts.txt, domains_abp.txt, wildcard.txt, kev_sample.json, epss_sample.csv, manuf_sample.txt), KEV/CPE matching,
findings engine dedupe/lifecycle/auto-resolve, score, DNS policy decisions, DNS server on an ephemeral port with a fake
upstream (block returns 0.0.0.0, allow forwards, TCP framing), cache TTL, querylog flush/rollup, web routes (Flask test client:
every page 200, every API shape), config merge, scheduler run_now/no-overlap, posture JSON → checks/findings
(fixtures/posture/win_nonadmin.json), notification payload builders. Live tests (marked `live`, skipped by default): feed update
against the real URLs, discovery on the current /24, InternetDB.

## 18. Work packages (parallel; owner edits only these files)

P1 core: `homesoc/__init__.py __main__.py cli.py config.py db.py models.py scheduler.py util.py paths.py`,
   `config.example.toml pyproject.toml requirements.txt run.bat run.sh scripts/*`, `tests/conftest.py tests/test_core.py`.
   cli.py wires everything by importing the other packages' `run`/`create_app`/`DnsServer`/`update` names exactly as specified.
P2 feeds: `homesoc/feeds/*`, `tests/test_feeds.py`, `tests/fixtures/feeds/*`.
P3 network: `homesoc/scanners/__init__.py discovery.py ports.py nmap_xml.py services.py exposure.py mdns_ssdp.py wifi.py`,
   `tests/test_network.py`, `tests/fixtures/nmap/*`.
P4 host+AV: `homesoc/scanners/host_windows.py host_posix.py defender.py updates.py persistence.py files.py ps/*.ps1`,
   `tests/test_host.py`, `tests/fixtures/posture/*`.
P5 vulns: `homesoc/vulns/*`, `tests/test_vulns.py`.
P6 findings+notify: `homesoc/findings/*`, `homesoc/notify/*`, `tests/test_findings.py`.
P7 dns: `homesoc/dnsfilter/*`, `tests/test_dns.py`.
P8 web: `homesoc/web/*`, `tests/test_web.py`.
P9 docs (after integration): `README.md SECURITY.md CONTRIBUTING.md docs/ARCHITECTURE.md docs/GUIDE_HOME_PROTECTION.md docs/NETWORK_DNS_SETUP.md docs/PLAYBOOKS.md`.

Cross-package imports allowed: everyone may import `homesoc.{config,db,models,util,paths}`; scanners may import `homesoc.feeds.registry`;
vulns may import feeds.registry; findings may import nothing from scanners; web imports findings/dnsfilter.querylog/feeds.registry/
scanners.defender read-only helpers; dnsfilter imports feeds.registry and findings.engine (for NET-DNS-004) only.
