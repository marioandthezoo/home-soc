# Tested environment

What Home SOC was actually developed and measured against, and the measurements that drove the
design decisions. Numbers here were taken on a single test environment (2026-09-02); they are
reported as *orders of magnitude that justify a design choice*, not as benchmarks. Your network and
machine will differ.

Nothing in this document identifies a specific host, network or person: hostnames, MAC addresses,
SSIDs and public IP addresses are deliberately omitted throughout.

---

## 1. The machine

| Property | Value |
|---|---|
| OS | Windows 11 Home |
| Privileges | standard (non-administrator) user, UAC on, admin-approval prompts enabled |
| Python | 3.14 |
| Container runtime | none (no Docker, no WSL distro in use) |
| nmap | installed (7.9x), **Npcap not functional** |

The two facts that shaped the most code are on the last two rows: the agent runs as a *non-admin
user*, and nmap on that machine could not capture or inject raw packets.

Everything Home SOC does by default works under those constraints. The features that genuinely need
elevation are isolated in separate opt-in scripts, never in the agent's own run loop.

---

## 2. nmap without Npcap, and why discovery is ARP-first

Without a working packet-capture driver, nmap on Windows loses `-sS`, `-O` and its ARP-based host
discovery, and falls back to making ordinary `connect()` calls. The consequence is measurable:

| Method | Time | Hosts found on the same /24 |
|---|---|---|
| `nmap -sn <cidr>` (connect mode, no Npcap) | **50 s** | **2** |
| Python TCP-connect sweep, 14 ports x 254 addresses, 128 threads, 0.4 s timeout | **11.5 s** | 5 with an open port |
| Read the OS neighbour (ARP) table right after the sweep | **0.04 s** | **17 with MAC addresses** |

A ping sweep that takes 50 seconds to find two of seventeen hosts is not a discovery mechanism.
The OS neighbour table, by contrast, is already populated by normal traffic, is free to read, needs
no privileges, and yields a MAC address (and therefore a vendor) per host.

So discovery is **ARP-first**: read the neighbour table (`Get-NetNeighbor`, `arp -a`, `ip neigh`),
then use a short TCP-connect sweep only to warm the table and to catch hosts that answer on a port
but are not yet cached. nmap is used for what it is uniquely good at — **service and version
detection on hosts we already know about** — where connect mode is perfectly adequate:
`-sT -sV --version-light -T3 --top-ports 50` against a single host took ~17 s and returned
product, version and CPE strings.

Implementation: `homesoc/scanners/discovery.py`, `homesoc/scanners/ports.py`.

---

## 3. What does and does not need administrator rights

Measured on the non-admin account:

| Operation | Needs admin? |
|---|---|
| Bind **UDP and TCP port 53** on `0.0.0.0` | **No** |
| Read the OS neighbour table, run TCP connect scans | No |
| Query Defender status, firewall profiles, SMB/RDP settings, LSA, UAC, listeners, hotfixes | No |
| Read Defender/Operational, System and PowerShell/Operational event logs | No |
| `Register-ScheduledTask` | **Yes** (Access Denied without it) |
| `New-NetFirewallRule` (inbound allow for LAN DNS) | **Yes** |
| `Confirm-SecureBootUEFI`, `Get-Tpm`, `Get-BitLockerVolume` | **Yes** |
| Read the Security event log | **Yes** |

Three consequences run through the whole codebase:

1. **The DNS sinkhole is an ordinary user-space listener.** Binding 53 needs no elevation, so the
   resolver lives in the agent process itself rather than in a container or a service. (Port 5355 is
   taken by LLMNR on Windows and must be avoided.) *Making* the listener reachable from the rest of
   the LAN is the part that needs an inbound firewall rule — hence a separate, opt-in script.
2. **The default autostart is a Startup-folder shortcut**, not a Scheduled Task, because
   registering a task fails for a standard user. Task Scheduler is offered only from the elevated
   installer script.
3. **Checks that require elevation are reported as `needs_admin`, never as failures.** Secure Boot,
   TPM and BitLocker come back Access Denied for a standard user; treating that as "insecure" would
   be a lie, so the posture scanner records the check as skipped and says why.

The Windows posture probe is a single `powershell -File` call returning one JSON document
(defender, firewall, smb, rdp, uac, lsa, secure_boot, tpm, device_guard, bitlocker, admins, guest,
builtin_admin, listeners, hotfix, wifi, dns, llmnr, ps_v2, autologon, smartscreen,
smart_app_control, screen lock, is_admin). It took **~29 s** end to end, dominated by the Windows
Update COM search — which is why posture runs on its own schedule rather than on every pass.

One posture finding worth calling out: on a typical consumer Windows 11 Home install the daily-use
account **is** a local administrator, which is exactly what `WIN-ACC-001` is for.

---

## 4. The gateway problem, and why the DNS guide reads the way it does

A very common class of ISP-supplied residential gateway:

- runs **its own DHCP server** and hands out **its own address** as the DNS server;
- runs **its own recursive resolver** on port 53 (an Unbound build, in the tested case);
- serves its admin UI over plain HTTP and HTTPS from an embedded web server;
- and — the important part — **exposes no setting anywhere in its admin pages to advertise a
  different LAN DNS server.** There is no field to change, and no firmware option unlocks one.

This is not an edge case, and it is not something a documentation page can wish away. It means the
standard "point your router's DHCP at the sinkhole" instruction simply does not apply to a large
fraction of home users, and the documented Pi-hole fallback — take over DHCP for the house — is a
risky thing to ask a non-expert to do on their only router.

`docs/NETWORK_DNS_SETUP.md` therefore documents the workarounds that *do* work on such gateways:
per-device DNS configuration (partial coverage, zero risk), and IP-passthrough / bridge mode with
your own router behind it (full coverage, more setup). The router-DHCP route is documented too, for
the gateways that allow it.

Also measured while validating the resolver design:

- Nothing else was listening on 53; a minimal `dnslib` forwarder answered blocked names in **~1 ms**
  (NXDOMAIN) and forwarded upstream in **~13 ms**; 100 sequential uncached forwards took 1.6 s.
- Cloudflare's DoH JSON endpoint works with a plain GET. Quad9's returns `505` for JSON GET — use
  wire-format POST, or plain UDP.
- On a machine that previously had container networking installed, leftover inbound allow rules for
  UDP/TCP 53 may already exist. Do not rely on that; the firewall script is explicit.

---

## 5. Feed reachability and sizes (why conditional GET matters)

Every feed in `homesoc/feeds/registry.py` was fetched once and checked for cache validators. The
sizes are the reason the updater is built around `If-None-Match` / `If-Modified-Since`, an on-disk
cache and a staleness window rather than "download everything on every run": a naive updater would
pull tens of megabytes per cycle to learn that nothing changed.

**Vulnerability data**

| Feed | Size | Notes |
|---|---|---|
| CISA KEV (JSON) | ~1.7 MB | ETag **and** Last-Modified |
| EPSS daily CSV (gzip) | ~2.6 MB | full daily snapshot |
| FIRST EPSS API | per-CVE | live lookup |
| NVD 2.0 API | ~87 KB per CVE, ~1 s | rate-limited; per-CVE |

**DNS blocklists**

| Feed | Size | Notes |
|---|---|---|
| oisd big / small | 6.2 MB / 1.4 MB | ETag, `max-age=3600` |
| Hagezi pro (wildcard `*-onlydomains.txt`) | 4.3 MB | the `hosts/` path 404s; one CDN mirror returns 403 — use the raw path |
| StevenBlack hosts | 2.3 MB | |
| AdGuard DNS filter (HostlistsRegistry) | 4.3 MB | |
| Peter Lowe list | 95 KB | |
| Phishing Army | 3.3 MB | |

**Threat intelligence**

| Feed | Size | Notes |
|---|---|---|
| URLhaus hostfile / recent text | 12 KB / 584 KB | |
| malware-filter urlhaus-filter-hosts | 157 KB | |
| ThreatFox hostfile | 1.7 MB | |
| OpenPhish `feed.txt` | 14 KB | 302 then 200 — follow redirects |
| Feodo `ipblocklist.json` | 1.8 KB | |
| Spamhaus DROP | 47 KB | |
| Emerging Threats open rules (tar.gz) | 5.6 MB | |

**Reference data**

| Feed | Size | Notes |
|---|---|---|
| Wireshark `manuf` (OUI table) | 3.1 MB | fetched once, cached; the local table is preferred over any API |
| macvendors API | per-MAC | no key, rate-limited — fallback only |

**Deliberately optional**

- VirusTotal v3 returns `401` without an API key, as expected — the integration is opt-in and
  budgeted.
- One community threat API timed out at 25 s during testing, so any such source is treated as
  optional and must never block a scan.

The practical rules that came out of this: always send conditional-GET headers, always keep the last
good copy on disk, never let a feed failure fail a scan, and never re-download a multi-megabyte list
to discover it is unchanged.

---

## 6. What this means for you

- If your nmap has a working Npcap/libpcap, discovery will be faster and richer than the numbers
  above — Home SOC still reads the neighbour table first, because it is free.
- If your router *does* let you set a LAN DNS server, use it; the per-device and passthrough routes
  in `docs/NETWORK_DNS_SETUP.md` exist for the routers that do not.
- If you run as an administrator, the `needs_admin` checks will resolve to real answers instead of
  being skipped. Home SOC will not ask you to.
