# Network-wide ad blocking and DNS sinkhole

Home SOC contains a small DNS resolver. Every device that asks it for a name gets ads, trackers,
phishing sites and malware command-and-control domains answered with "nothing here", and everything
else forwarded to a normal public resolver. Nothing is installed on the phones, TVs or laptops
themselves — they just have to be told to ask this PC.

That last sentence is the whole difficulty. The resolver itself is boring and reliable; **getting a
home network to point at it is the hard part**, and on some ISP-supplied gateways it is genuinely
impossible. This guide is honest about that: read [Pointing the whole network at
it](#4-pointing-the-whole-network-at-it) before you spend an evening on it.

**Contents**

1. [How the resolver works](#1-how-the-resolver-works)
2. [Turning it on](#2-turning-it-on)
3. [Opening the firewall (the one step that needs administrator)](#3-opening-the-firewall-the-one-step-that-needs-administrator)
4. [Pointing the whole network at it](#4-pointing-the-whole-network-at-it)
5. [Per-device DNS](#5-per-device-dns)
6. [The single point of failure](#6-the-single-point-of-failure)
7. [Encrypted DNS, and what you can actually do about it](#7-encrypted-dns-and-what-you-can-actually-do-about-it)
8. [Choosing blocklists](#8-choosing-blocklists)
9. [The VirusTotal key and its budget](#9-the-virustotal-key-and-its-budget)
10. [Allow and deny overrides — "why was this blocked?"](#10-allow-and-deny-overrides--why-was-this-blocked)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. How the resolver works

### The block decision, in order

Every query runs through `homesoc/dnsfilter/policy.py`, which checks these five things **in this
exact order** and stops at the first match:

| # | Step | What matches | Reason string in the log |
|---|---|---|---|
| 1 | **Allow overrides** | a domain you added on the DNS page with action `allow` | `override:allow` |
| 2 | **Deny overrides** | a domain you added with action `deny` | `override:deny` |
| 3 | **Never-block names** | `localhost`, and anything ending in `local`, `arpa`, `home.arpa`, `lan`, `home`, `internal`, `localdomain`, `intranet`, `corp`, `private` — plus the hostname of your DoH upstream (`cloudflare-dns.com` by default) | `never_block` |
| 4 | **Blocklists** | the lists named in `dns.lists` | `list:hagezi_pro` (the list that matched) |
| 5 | **Reputation** | a domain the reputation table marks `malicious` with at least `dns.reputation_min_malicious_votes` votes | `reputation` |
| — | nothing matched | forward it upstream | `default` (logged as blank) |

Three consequences worth knowing:

- **Matching is by suffix.** An entry for `example.com` also blocks `ads.example.com` and
  `a.b.example.com`. The same is true of overrides: an `allow` on `example.com` un-blocks every
  subdomain of it. This is what hosts-style and wildcard-style lists both intend.
- **An allow override beats a deny override**, even when the deny is more specific. If you allowed
  `example.com` and denied `tracker.example.com`, the name is allowed. You asked for it.
- **Overrides beat the never-block list**, because they are checked first. You can deny
  `something.home` if you really want to.

You can ask the policy about any name without running the resolver:

```
python -m homesoc dns-test scorecardresearch.com
```

On the development machine that prints (the exact wording of a real run):

```
policy: block  reason: list:hagezi_pro
upstream 1.1.1.2: rcode=0 ...
```

while `example.com` and, perhaps surprisingly, `doubleclick.net` both come back
`policy: allow  reason: default` — the default lists simply do not carry the `doubleclick.net`
apex. `dns-test` always also queries your first upstream directly, so you can see what the real
answer would have been.

### The lists that actually ship

`dns.lists` in `config.example.toml` defaults to six names, all of which are in the feed registry
(`homesoc/feeds/registry.py`) and download automatically. Measured on the author's machine on
2026-09-07:

| List name | Source | What it blocks | Entries |
|---|---|---|---|
| `oisd_small` | oisd | ads, trackers, telemetry — deliberately conservative, tuned not to break things | 63,109 |
| `hagezi_pro` | HaGeZi "Pro" wildcard list | ads, trackers, telemetry, some malware — noticeably more aggressive than oisd small | 224,442 |
| `urlhaus` | abuse.ch URLhaus | hosts currently distributing malware | 391 |
| `threatfox` | abuse.ch ThreatFox | malware command-and-control indicators | 47,001 |
| `phishing_army` | Phishing Army | phishing domains | 156,145 |
| `openphish` | OpenPhish community feed | phishing URLs, reduced to their hostnames | 267 |

Loaded together and de-duplicated, that is **416,639 unique blocked names** — the number the
resolver logs at startup:

```
homesoc.dnsfilter.policy: DNS blocklists loaded: 6 lists, 416639 entries
```

Three more domain lists exist in the registry but are **off by default**: `oisd_big`,
`stevenblack` and `adguard_dns`. One more, `urlhaus_filter` (a larger URLhaus-derived list,
4,826 entries), is downloaded by default but is *not* in `dns.lists`. See
[Choosing blocklists](#8-choosing-blocklists).

Lists are re-read when their files change on disk. The resolver checks the file timestamps at most
once a minute, so a feed update takes effect within a minute without a restart — and the answer
cache is cleared at that moment so a name that was allowed a second ago starts being blocked
immediately.

### The reputation layer

Blocklists are yesterday's knowledge. The reputation layer
(`homesoc/dnsfilter/reputation.py`) covers today's:

- When a query is forwarded successfully, the *registrable* domain (`cdn3.assets.example.co.uk` →
  `example.co.uk`) is handed to a background worker.
- The worker skips IP literals, single-label names, never-block names, about 200 hard-coded
  well-known domains (Google, Apple, Microsoft, Netflix, your ISP…), and anything it already looked
  at in the last 24 hours.
- What survives is checked against **VirusTotal** (only if you set a key — see
  [section 9](#9-the-virustotal-key-and-its-budget)) and **URLhaus** (no key needed).
- A verdict of `malicious` puts the domain in the `reputation` table, blocks it from that moment on,
  drops it and its subdomains from the answer cache, and raises a **NET-DNS-004** finding naming the
  device that asked for it.

**This never delays an answer.** The lookup happens after the client already has its reply; the
first request to a malicious domain goes through, and every later one is blocked. That is the
correct trade-off for a home resolver — a DNS answer that takes half a second is worse than one
extra request to a bad domain.

Verdicts are cached for `dns.reputation_ttl_hours` (72 by default). Lookups where nobody answered
(budget exhausted, no internet) are retried after an hour rather than being treated as a clean bill
of health.

### The cache

`homesoc/dnsfilter/cache.py` is a TTL-respecting LRU cache holding up to `dns.cache_max_entries`
(20,000) answers.

- TTLs are clamped to **at least 30 seconds** (many CDNs publish 5-second TTLs, which would make a
  LAN resolver hammer upstreams pointlessly) and **at most 1 hour** (so a blocklist update catches
  up with a hostile domain that published a multi-year TTL).
- NXDOMAIN and empty answers are cached for 60 seconds.
- A cache hit counts down the stored TTL, so clients never see a TTL longer than the origin's.
- **The policy runs before the cache.** A name that was cached while it was allowed is blocked the
  moment a list update or reputation verdict says so — it is not served from the cache first.

Cache hits appear in the query log with action `cache`, which is why the DNS page shows both
"Queries · 24 h" and how many of them came from cache.

### The upstreams

`homesoc/dnsfilter/upstream.py` forwards in this order:

1. **Plain UDP** to each address in `dns.upstreams`, in order, 2-second timeout. The defaults are
   `1.1.1.2` (Cloudflare's malware-blocking resolver) and `9.9.9.9` (Quad9, which also blocks
   malicious domains). So you get a second opinion for free, from a source that is not one of your
   blocklists.
2. **TCP** to the same address, but only when the UDP answer came back truncated.
3. **DoH** (`dns.doh_upstream`, default `https://cloudflare-dns.com/dns-query`) as a last resort
   when every UDP upstream failed — useful if your ISP intercepts port 53. Set it to `""` to
   disable.

Measured on the development machine: a blocked name is answered in about **1 ms**, a forwarded name
in about **13 ms**.

Some hardening you get without configuring anything: upstream sockets are `connect()`-ed so the
kernel drops replies from anyone else; outgoing question names are 0x20 case-randomised so an
off-path spoofer must guess the case pattern as well as the 16-bit ID; queries from public IP
addresses are dropped outright so the resolver cannot be abused as a DDoS reflector; per-client
queries are capped at 300/second and the whole server at 3,000/second; and UDP answers are clamped
to 1232 bytes with anything larger pushed to TCP.

When *every* path has failed for 60 seconds you get a **NET-DNS-005** finding, and a circuit breaker
lets only one probe query through every 5 seconds so the LAN fails fast instead of waiting out
timeouts on every lookup.

---

## 2. Turning it on

### The config keys

All of these live in the `[dns]` section of `config.toml` (copy them from `config.example.toml`).
Every one of them can also be edited on the dashboard's **Settings** page.

```toml
[dns]
enabled = false                    # turn on to run the LAN-wide resolver
listen = "0.0.0.0"
port = 53
upstreams = ["1.1.1.2", "9.9.9.9"] # UDP upstreams; 1.1.1.2 = Cloudflare malware-blocking, 9.9.9.9 = Quad9
doh_upstream = "https://cloudflare-dns.com/dns-query"   # used when udp upstreams fail; "" disables
block_mode = "null"                # "null" -> 0.0.0.0 / :: with TTL 60 ; "nxdomain"
cache_max_entries = 20000
lists = ["oisd_small", "hagezi_pro", "urlhaus", "threatfox", "phishing_army", "openphish"]
log_queries = true
log_retention_days = 14
virustotal_api_key = ""
virustotal_daily_budget = 400      # free tier is 500/day, 4/min; keep headroom
urlhaus_auth_key = ""              # optional abuse.ch Auth-Key for URLhaus reputation lookups
reputation_min_malicious_votes = 2
reputation_ttl_hours = 72
```

Notes on the ones that matter:

- **`enabled`** — the only key you must change. `python -m homesoc run` starts the resolver when
  this is `true` and skips it when it is `false`.
- **`listen`** — `0.0.0.0` accepts queries from the LAN. Set it to `127.0.0.1` to filter only this
  PC's own lookups (a perfectly reasonable way to try it out; no firewall rule needed).
- **`block_mode`** — `null` answers blocked A queries with `0.0.0.0` and AAAA with `::`, TTL 60.
  `nxdomain` answers "this name does not exist". `null` is friendlier (apps fail fast instead of
  retrying), `nxdomain` is what Firefox's DoH canary needs — see
  [section 7](#7-encrypted-dns-and-what-you-can-actually-do-about-it).
- **`log_queries`** — set to `false` if you do not want a record of every name every device on your
  network looked up. Statistics still work; the per-query log and the "why was this blocked"
  workflow do not.

Changing settings from the dashboard writes an override into the database and the page tells you a
restart is required. DNS settings are read when the resolver starts, so restart Home SOC after
changing them.

### Starting it

Three ways, depending on what you want:

```
python -m homesoc dns                  # resolver only, foreground, Ctrl-C to stop
python -m homesoc dns --port 5300      # ... on a different port, for testing
python -m homesoc run                  # dashboard + scheduler + resolver (the normal mode)
```

`python -m homesoc dns` forces `dns.enabled = true` for that run only, so you can try the resolver
without editing anything. Test it from the same PC:

```
nslookup scorecardresearch.com 127.0.0.1
nslookup example.com 127.0.0.1
```

The first should come back `0.0.0.0`, the second a real address.

### What needs administrator, and what does not

This was measured on the target machine (Windows 11 Home, standard non-admin session), not assumed:

| Action | Administrator needed? |
|---|---|
| Binding UDP **and** TCP port 53 on `0.0.0.0` | **No.** Windows does not reserve port 53 for privileged processes. |
| Running `python -m homesoc dns` / `run` | No |
| Adding the inbound Windows Firewall rule | **Yes** — this is the only step that needs it |
| Starting Home SOC at logon via the Startup folder | No |
| Registering a Scheduled Task instead | Yes (to register it; the task itself runs unprivileged) |

On Linux and macOS, binding port 53 *does* need root. Use `dns.port = 5353` with a redirect, or run
under a service manager that grants `CAP_NET_BIND_SERVICE`.

---

## 3. Opening the firewall (the one step that needs administrator)

The resolver can bind port 53 without administrator, but Windows Firewall will not let *other*
devices reach it until an inbound rule allows it. Home SOC ships that rule as a script:

1. Open PowerShell **as administrator** (right-click PowerShell → Run as Administrator).
2. Run:
   ```
   powershell -ExecutionPolicy Bypass -File scripts\enable-lan-dns.ps1
   ```

The script refuses to run unelevated and tells you so. It removes any previous "Home SOC DNS" rules
(so it is safe to re-run), adds an inbound Allow rule for **UDP and TCP port 53 on the Private
profile**, and then prints your PC's IP, your gateway's IP, and the router steps to follow.

Useful variations:

```
powershell -ExecutionPolicy Bypass -File scripts\enable-lan-dns.ps1 -Port 5300   # match a custom dns.port
powershell -ExecutionPolicy Bypass -File scripts\enable-lan-dns.ps1 -Remove      # undo it
```

The equivalent by hand, if you would rather not run a script:

```powershell
New-NetFirewallRule -DisplayName "Home SOC DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "Home SOC DNS" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Private
```

**Two things that silently break this:**

- **The rule is Private-profile only.** If Windows has your home Wi-Fi classified as Public, the
  rule does not apply and no device can reach the resolver. The script warns you when it detects
  this. Fix it in Settings → Network & internet → Wi-Fi → *your network* → set the network profile
  to **Private**.
- **You may already have a rule and not know it.** On the development machine, Docker/WSL had left
  behind "HNS Container Networking - DNS (UDP-In)" allow rules for UDP/TCP 53 on profile *Any*.
  Home SOC's own check (which raises **NET-DNS-006** when no inbound rule for port 53 exists) sees
  those and concludes a rule is present. That is fine — inbound DNS really is allowed — but do not
  read "no NET-DNS-006 finding" as proof that `enable-lan-dns.ps1` ran.

---

## 4. Pointing the whole network at it

### The idea

Your router hands every device an IP address over DHCP, and along with it, the address of a DNS
server. Normally that is the router itself. Change it to this PC's address and every device on the
network is filtered, with no per-device configuration.

### Generic steps (any router that supports it)

1. **Give this PC a fixed address.** In the router's DHCP settings, add a *reservation* (also called
   a static lease) tying this PC's MAC address to its current IP. If the PC's address changes later,
   the whole network loses DNS. This step is not optional.
2. **Set the DHCP DNS server.** Find the LAN or DHCP page and set the primary DNS server handed to
   clients to this PC's IP. Leave the secondary blank if the router allows it — see the warning in
   [section 6](#6-the-single-point-of-failure).
3. **Save and let devices pick it up.** Devices only learn the new DNS server when their DHCP lease
   renews. Reboot the router, or reconnect each device's Wi-Fi, to make it immediate.
4. **Verify from another device:**
   ```
   nslookup example.com 192.168.1.105        # replace with this PC's IP
   ```
   Then check the dashboard's **DNS** page: the "Clients · 24 h" card and the "Top clients" table
   should start filling in.

Home SOC will tell you if this did not work: when the resolver has been up for an hour and fewer
than two distinct devices have used it, you get a **NET-DNS-001** finding.

### Vendor notes

Menu labels move between firmware versions, so treat these as "where to look", not as gospel.

- **ASUS, TP-Link (non-mesh), Netgear, Linksys, Synology, OpenWrt, pfSense/OPNsense** — all support
  this. Look under LAN → DHCP Server for a "DNS Server 1" / "Primary DNS" field. On ASUS the field
  is on *LAN → DHCP Server*, not *WAN → DNS*; setting the WAN DNS only changes what the router
  itself uses upstream, which is not what you want.
- **eero** — supported in the eero app under Settings → Network Settings → DNS → Customized DNS.
  Two catches: you have to turn off eero Secure's ad blocking and content filters first, and eero
  asks to reboot the network before the change takes effect. Also add a DHCP reservation for this
  PC in the same app.
- **Google Wifi / Nest Wifi** — supported in the Google Home app under the Wi-Fi network's
  Advanced Networking → DNS → Custom. **But** these devices act as a DNS *proxy*: your devices keep
  using the Google Wifi router as their resolver and it relays their queries to yours. Filtering
  still works, but every query in Home SOC's log arrives from the router's IP, so the "Top clients"
  table and any per-device finding (**NET-DNS-004**) can only say "the router", never "the tablet in
  the kitchen".
- **Comcast/Xfinity XB gateways, most Verizon Fios routers** — generally do let you set LAN DNS,
  but the field can be hidden or ignored on some firmware. Verify with `nslookup` from a second
  device rather than trusting the UI.
- **AT&T BGW210 / BGW320 (Nokia and Arris models)** — **this does not work.** See below.

### When the gateway will not let you

This is not a rare edge case. Many ISP-supplied gateways deliberately hand out their own address as
the DNS server and give you no field to change it. The gateway this project was developed against
was exactly that kind — a carrier-supplied box running its own DHCP server and its own recursive
resolver on the usual `192.168.1.254`-style LAN address: **there is no LAN DNS field anywhere in
its admin pages, and no firmware setting unlocks one.** Its DHCP server hands out the gateway's own
address and that is that.

You have three real options.

**Option A — configure DNS on each device (easiest, partial coverage).**
Do nothing to the router; set the DNS server manually on the devices you care about. See
[section 5](#5-per-device-dns). Realistically this covers your laptops, phones and tablets, misses
most IoT gear, and needs redoing whenever you add a device. It is still the option most people end
up using, and it is a genuine improvement over nothing.

**Option B — put your own router behind the ISP gateway (best coverage, most work).**
Buy or reuse a normal router, connect its WAN port to the ISP gateway, and put the gateway into
**IP Passthrough** mode so it hands its public address straight to your router and stops doing
NAT and DHCP for your devices. Your router then runs the LAN, and you set its DHCP DNS server to
this PC.

On AT&T gateways the setting is under **Firewall → IP Passthrough**: pick an allocation mode
(`DHCPS-fixed` is the usual choice, pinned to your router's MAC), save, and restart the gateway.
Be aware of AT&T's own warning: putting a device in passthrough removes the gateway's firewall
protection for that device, and only one device can be configured this way. Your own router becomes
the firewall — which is fine, that is what it is for.

This is a real weekend project: an extra device, an extra hop, and a Wi-Fi network to migrate
everything onto. It is also the only option that gets *every* device, including the ones that cannot
be configured at all.

**Option C — accept per-device coverage.**
Set DNS on the handful of devices that generate most of the traffic and browsing (your PC, your
phone, the family laptop) and let the rest use the ISP's resolver. Home SOC's "Top clients" table
will show you honestly how many devices you are actually protecting. There is no shame in this;
partial filtering that works is better than complete filtering that you abandon after two evenings.

Whichever you pick, do not skip the firewall rule in [section 3](#3-opening-the-firewall-the-one-step-that-needs-administrator)
— nothing but this PC can reach the resolver without it.

---

## 5. Per-device DNS

In every case below, "the resolver's address" means this PC's LAN IP (the
`scripts\enable-lan-dns.ps1` output prints it; so does `ipconfig`). Use the IP, not the hostname.

### Windows 10 / 11

Settings → **Network & internet** → **Wi-Fi** (or Ethernet) → *your network* → **Hardware
properties** → **DNS server assignment** → **Edit** → **Manual** → turn **IPv4** on → Preferred DNS:
the resolver's address → Save.

Leave "Alternate DNS" empty (see [section 6](#6-the-single-point-of-failure)). Also turn **IPv6**
off in the same dialog, or set its DNS too — otherwise Windows may prefer an IPv6 resolver handed
out by the router and bypass the filter entirely.

PowerShell equivalent (needs administrator):

```powershell
Get-NetAdapter                                    # find the InterfaceIndex of your Wi-Fi adapter
Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses "192.168.1.105"
Clear-DnsClientCache
```

To undo: `Set-DnsClientServerAddress -InterfaceIndex 12 -ResetServerAddresses`.

### macOS

System Settings → **Network** → **Wi-Fi** → **Details…** → **DNS** → **+** under DNS Servers → type
the resolver's address → remove any other entries → **OK** → **Apply**.

macOS is one of the few systems that genuinely tries servers in order rather than round-robin, but
it still falls back to the second one when the first is slow, so keep the list to one entry.

### iOS / iPadOS

Settings → **Wi-Fi** → tap the **(i)** next to your network → **Configure DNS** → **Manual** →
remove the existing servers → **Add Server** → the resolver's address → **Save**.

This is per-Wi-Fi-network, so it does not affect the phone on mobile data — which is exactly what
you want.

### Android

Android does **not** let you set a DNS server while the Wi-Fi network uses DHCP. You have to switch
that network to a static IP:

Settings → **Network & internet** → **Internet** → tap the **gear** next to your network → **Edit**
(pencil) → **Advanced options** → **IP settings: Static** → then fill in an IP address outside the
router's DHCP pool, the gateway, the network prefix length (usually 24), and **DNS 1** = the
resolver's address.

Two warnings:

- A static IP that collides with the DHCP pool causes intermittent, baffling network failures. Pick
  something high, like `.200`, and check the router's DHCP range first.
- **Do not use "Private DNS" for this.** That setting (Settings → Network & internet → Private DNS)
  is DNS-over-TLS and requires a *hostname*, not an IP; Home SOC does not speak DoT. Leave Private
  DNS on **Automatic** (it will fall back to plain DNS because the resolver does not offer DoT) or
  **Off**. If it is set to a provider hostname, that provider — not Home SOC — is answering
  everything.

### Smart TVs and streaming boxes

This is where it falls apart, device by device:

- **Apple TV** — Settings → **Network** → *your network* → **Configure DNS** → **Manual**. Works
  properly.
- **Samsung (Tizen)** — Settings → General (or Connection) → **Network** → **Network Status** →
  **IP Settings** → **DNS Setting** → **Enter manually**. Labels move around by model year.
- **LG (webOS)** — Settings → **Network** → **Wi-Fi Connection** → **Advanced Wi-Fi Settings** →
  **Edit** → untick "Set Automatically" → fill in the **DNS Server** field.
- **Android TV / Google TV / Fire TV** — same story as Android phones: you must switch the Wi-Fi
  network to a static IP before a DNS field appears.
- **Roku** — **not possible.** Roku devices only take an address by DHCP and provide no DNS field at
  all. The only way to filter a Roku is at the router (or by not filtering it).

If a device offers no DNS field, that is your answer: it is either covered by a router-level change
or it is not covered. Do not fight it.

---

## 6. The single point of failure

**Say it plainly: if this PC sleeps, shuts down, or Home SOC stops, every device that points at it
loses the ability to resolve names. That looks exactly like "the internet is down" to everyone in
the house.**

This is inherent to the design, not a bug you can configure away. A Raspberry Pi that never sleeps
is the classic answer for a reason. If your Home SOC machine is a laptop that you close and carry
around, think hard before pointing the whole network at it — [Option A or C in section
4](#when-the-gateway-will-not-let-you) may suit you better.

### Mitigations that actually help

**Keep the machine awake on AC power.** On the development laptop the default plan already never
sleeps while plugged in, but sleeps after 60 minutes on battery. Check and set it:

```powershell
powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE   # inspect
powercfg /change standby-timeout-ac 0                  # never sleep on AC
powercfg /change hibernate-timeout-ac 0
```

Leave the battery timeouts alone — a laptop that never sleeps on battery is a dead laptop.

**Start it at logon.** Home SOC ships a script:

```
powershell -ExecutionPolicy Bypass -File scripts\make-autostart.ps1 -Mode startup
```

That drops a shortcut in your Startup folder — no administrator needed — which launches
`run.bat --autostart`. It runs after *you* log in, so the gap between power-on and DNS coming back
is however long it takes you to type your password. `-Mode task` registers a Scheduled Task instead
(needs an elevated PowerShell to register; the task itself runs with normal rights) and is only
marginally earlier.

### The secondary-DNS trap

Here is the mistake almost everyone makes: setting a secondary DNS server (the router, or `8.8.8.8`)
"just in case Home SOC is down".

**It does not work as a failover, and it silently disables your filtering.** DNS clients do not try
the primary first and only fall back on failure. Most operating systems and stub resolvers query
whichever server answers fastest, or round-robin across the list, or race both. A public resolver
in a datacentre will frequently beat your laptop. The practical result is that some fraction of
queries — often most of them — never reach Home SOC at all, ads come back, and nothing tells you
why. Home SOC's "Blocked · 24 h" percentage will just look mysteriously low.

So: **list exactly one DNS server** — this PC — everywhere. Accept that when the PC is off, DNS is
off. If someone in the house needs to get online while it is down, changing that one device back to
automatic DNS takes fifteen seconds, and that is a better failure mode than filtering that only
half-works and never tells you.

If your router refuses to save a single DNS entry and demands two, put this PC's address in both
fields.

---

## 7. Encrypted DNS, and what you can actually do about it

DNS filtering works by being the thing that answers name lookups. Anything that encrypts its
lookups and sends them somewhere else — DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) — walks straight
past the filter, and you will not see it in the query log.

### Browsers

- **Firefox** turns DoH on by default in some regions. Mozilla defined a "canary domain",
  `use-application-dns.net`: if the network's resolver answers it *negatively*, Firefox turns DoH
  back off. To use that lever with Home SOC you need two things, because `block_mode = "null"`
  answers with `0.0.0.0` — an ordinary positive answer that Firefox will happily accept:
  1. set `dns.block_mode = "nxdomain"` in `config.toml` (this changes *all* blocked answers, not
     just this one, so decide whether you want NXDOMAIN everywhere), and
  2. add a **deny** override for `use-application-dns.net` on the DNS page.

  Important limitation: the canary only applies to users who got DoH *by default*. If someone turned
  DoH on themselves in Firefox's settings, Firefox ignores the canary entirely.
- **Chrome and Edge** default to "automatic" secure DNS, which only upgrades to DoH when your
  configured resolver is recognised as a known public DoH provider. A private LAN address is not,
  so Chrome and Edge keep using Home SOC. They stop doing so the moment a user picks a specific
  provider in Settings → Privacy and security → Security → Use secure DNS. There is no network-side
  fix for that; on your own PCs you can set the DNS-over-HTTPS Group Policy, and on other people's
  devices you can only ask.

### Android

The **Private DNS** setting is DoT and, when set to a provider hostname, bypasses Home SOC
completely. Set it to **Automatic** or **Off** (see [section 5](#android)). You cannot enforce this
from the network — you can only check each device.

### Devices with hardcoded resolvers

Plenty of smart TVs, streaming sticks, thermostats and cameras ignore the DNS server they were
given and talk to `8.8.8.8` or `1.1.1.1` directly. On a normal home network there is nothing you can
do about this: blocking outbound port 53 to everything except your resolver requires firewall rules
on the router, and consumer routers — certainly the ISP-supplied ones — do not offer them.

What you *can* do is notice. Home SOC's device inventory and the DNS "Top clients" table together
tell you which devices never appear in the query log. A device that is clearly online but has never
asked Home SOC a single question is either using a hardcoded resolver or was never pointed at you.

**Be honest with yourself about the ceiling here.** A home DNS sinkhole blocks a large share of ads,
tracking and known-bad domains on cooperating devices. It is not a security boundary, it does not
stop anything determined, and it is not a substitute for Defender, updates, or a decent router. It
is a cheap, high-value layer — treat it as one.

---

## 8. Choosing blocklists

Set `dns.lists` in `config.toml`, or edit it on the dashboard's **Settings** page, then restart Home
SOC. Only the names below are valid — they must match feed names in `homesoc/feeds/registry.py`.

| Name | Size (measured) | Blocks | Breakage risk |
|---|---|---|---|
| `oisd_small` | 63k domains | ads, trackers, telemetry | **Low.** Deliberately curated to avoid breaking things. Good default. |
| `oisd_big` | ~6 MB download | the above plus much more | Medium. Off by default. |
| `hagezi_pro` | 224k domains | ads, trackers, telemetry, some malware | **Low–medium.** The default aggressive list; occasionally catches a link shortener or an affiliate redirect. |
| `stevenblack` | ~2.3 MB download | the classic unified hosts list | Low–medium. Off by default; overlaps heavily with the two above. |
| `adguard_dns` | ~4.3 MB download | AdGuard's own DNS filter | Medium. Off by default. |
| `urlhaus` | 391 domains | hosts actively distributing malware | **None.** Pure threat intel. |
| `urlhaus_filter` | 4.8k domains | a broader URLhaus-derived list | Very low. Downloaded by default but not in `dns.lists` — a good free addition. |
| `threatfox` | 47k domains | malware command-and-control | **None.** |
| `phishing_army` | 156k domains | phishing | Very low. |
| `openphish` | 267 domains | phishing (community feed) | **None.** |

**The trade-off, stated once:** every extra list raises coverage and raises the chance that
something you use stops working, usually in a way that does not look like DNS. A login button that
does nothing, a video that never starts, a checkout that hangs — those are what over-blocking looks
like. The threat-intel lists (`urlhaus*`, `threatfox`, `openphish`, `phishing_army`) are nearly
risk-free because they only carry domains that are actively malicious. The advertising lists are
where breakage comes from.

A sensible progression:

- **Cautious:** `["oisd_small", "urlhaus", "urlhaus_filter", "threatfox", "phishing_army", "openphish"]`
- **Default:** the six shipped lists, as above.
- **Aggressive:** add `oisd_big` or `adguard_dns` — and expect to add a few allow overrides.

Running `oisd_small` and `hagezi_pro` together is not redundant: they overlap a lot (491k raw
entries collapse to 417k unique) but each catches things the other misses. Memory cost for the
default six is well under 150 MB.

**Two things that will trip you up:**

- **`feodo_ips` and `spamhaus_drop` are IP lists, not domain lists.** They appear in the DNS page's
  Blocklists table because the table shows every blocklist-kind feed, but putting them in
  `dns.lists` does nothing — the parser rejects IP addresses, so they contribute zero entries.
- **`oisd_big`, `stevenblack` and `adguard_dns` are disabled feeds.** Adding one to `dns.lists` is
  not enough; the file is never downloaded, and you get a "file not found" warning in the log plus a
  **NET-DNS-003** stale-lists finding. Fetch it once, then enable it so it keeps refreshing:

  ```
  python -m homesoc update --feeds stevenblack --force
  python -c "from homesoc import db; c=db.connect(); db.write(c,'UPDATE feeds SET enabled=1 WHERE name=?',('stevenblack',))"
  ```

Check the result on the DNS page: the **Blocklists** table shows each list's entry count, when it
was last updated, its status, and an "in policy / not used" badge telling you whether `dns.lists`
actually references it.

---

## 9. The VirusTotal key and its budget

The reputation layer works without a key — URLhaus needs none — but VirusTotal is where most of the
value is, because it aggregates ~90 engines instead of one feed.

**Getting a key:** create a free account at virustotal.com, open your profile, and copy the API key
from the API key section. Then either paste it into the dashboard's **Settings** page
(`dns.virustotal_api_key`, stored as a secret and not displayed back) or put it in `config.toml`:

```toml
[dns]
virustotal_api_key = "your-key-here"
virustotal_daily_budget = 400
```

Restart Home SOC afterwards.

**The free-tier quota is 500 lookups per day and 4 per minute.** Home SOC defaults
`virustotal_daily_budget` to **400** to leave headroom — going over the quota gets you HTTP 429s and
no verdicts at all, which is worse than looking up fewer domains.

**How the budget is spent, and why it lasts:**

- Only **registrable** domains are looked up. All of `a.cdn.example.com`, `b.cdn.example.com` and
  `www.example.com` cost one lookup for `example.com`.
- About 200 hard-coded well-known domains (Google, Microsoft, Apple, Amazon, Netflix, Cloudflare,
  GitHub, your ISP…) are never looked up at all.
- Each domain is looked up **once per 24 hours**, and its verdict is cached in the database for
  `dns.reputation_ttl_hours` (72 hours by default).
- Rate limiting is a 4-per-minute token bucket; excess work waits in a queue rather than being
  thrown away, and the queue is capped at 5,000 so a flood can never delay a DNS answer.
- The daily counter is **persisted** (settings key `vt.budget.<date>`), so restarting Home SOC —
  which happens a lot on a laptop — does not reset it and blow through the quota.
- The same budget is shared with the Downloads-folder file scanner (`scanners/files.py`), so the two
  cannot double-spend.
- Lookups where nothing answered (budget spent, offline) are retried in an hour, not cached as
  "clean" for three days.

In practice a normal home network settles at a few dozen lookups a day after the first day or two,
because the set of domains a household visits is small and stable. The DNS page's **Resolver** card
shows "VirusTotal today: *used* / *limit*" with a progress bar, so you can see whether you are
anywhere near the ceiling.

`dns.reputation_min_malicious_votes` (default 2) is how many engines must call a domain malicious
before Home SOC blocks it. Do not set it to 1 — single-engine detections are frequently wrong.

The optional `dns.urlhaus_auth_key` is an abuse.ch Auth-Key. It is not required; it just gives your
URLhaus lookups a higher rate limit.

---

## 10. Allow and deny overrides — "why was this blocked?"

Something stopped working. Here is the routine, in order.

**1. Confirm it is DNS at all.** Open the DNS page's **Live query log**, put the affected device's
IP in the "client ip" filter and set the action filter to **block**. If the broken site's domain
is not in there, DNS is not your problem.

You can also ask directly, without touching the dashboard:

```
python -m homesoc dns-test cdn.example.com
```

**2. Read the reason.** The log's **Reason** column, and the Reason column in the "Top blocked
domains" table, tell you exactly which rule fired:

| Reason | Meaning | What to do |
|---|---|---|
| `list:oisd_small` (or another list name) | a blocklist matched | allow-override it, or drop that list |
| `reputation` | VirusTotal/URLhaus called it malicious | **Do not just allow it.** Check the Reputation cache table and look the domain up at virustotal.com first. |
| `override:deny` | you (or someone) denied it | remove the override |
| `override:allow` | it was allowed | — it was not blocked |
| `never_block` | a LAN-local name | — it was not blocked |
| blank / `default` | nothing matched | — it was not blocked |

Remember suffix matching: the reason names the entry that matched, which may be a parent of the name
you asked about.

**3. Add an override.** On the DNS page, under **Overrides**: type the domain, choose **allow** or
**deny**, add a note explaining why (you will not remember in three months), and press Add. There is
also an **allow** button on every row of the "Top blocked domains" table for one-click fixes, and
quick allow/deny buttons on each row of the live query log.

Overrides take effect **within a few seconds** — the resolver polls for changes and clears the
answer cache when it sees one. You do not need to restart anything. If a device still gets the old
answer, it cached it itself; on Windows, `ipconfig /flushdns`.

**Choose the right level.** An override on `example.com` covers every subdomain. If only one
subdomain is a problem, override that subdomain, not the parent — otherwise you have quietly
un-blocked a company's entire tracking infrastructure to fix one button.

The same UI is available over the API if you prefer scripting:

```
POST   /api/dns/override           {"domain": "...", "action": "allow"|"deny", "note": "..."}
DELETE /api/dns/override/<domain>
GET    /api/dns/overrides
```

**Deny overrides** are the other half: they are how you block something the lists miss — a
distracting site, a specific game's telemetry, or a domain you saw in a security advisory this
morning. They are checked before everything except allow overrides, so they always win.

When a **NET-DNS-004** finding appears ("a device tried to reach a malicious domain"), treat it as a
lead, not a verdict. It names the client and the domain and links to the VirusTotal page. Identify
the device on the Devices page, look at what else that client asked for in the query log, and — if
it is a PC — run a Defender scan. If you are confident it is a false positive, an allow override
clears it.

---

## 11. Troubleshooting

### "Port 53 is already in use" / the resolver will not start

You get a **NET-DNS-002** finding and the rest of Home SOC keeps running. Find the culprit:

```powershell
Get-NetUDPEndpoint -LocalPort 53 | Select-Object LocalAddress, OwningProcess
Get-NetTCPConnection -LocalPort 53 -State Listen | Select-Object LocalAddress, OwningProcess
Get-Process -Id <OwningProcess>
```

Usual suspects: another ad-blocker or resolver (Pi-hole in WSL, AdGuard Home, Technitium,
dnscrypt-proxy), a leftover Docker/WSL DNS proxy, or a VPN client. Either stop it, or move Home SOC
to a different port with `dns.port` and point your devices there (few clients let you specify a DNS
port, so a conflicting program is usually better removed than worked around).

Do **not** try to use port 5355 — Windows LLMNR owns it.

Home SOC retries the bind every 5 minutes on its own (`dns_retry` job), so freeing the port is
enough; you do not have to restart the app.

### Nothing is being blocked

Work down this list:

1. **Is the resolver running?** DNS page → Resolver card should say **running**. If it says
   "disabled in config", `dns.enabled` is still `false`.
2. **Are devices reaching it?** "Clients · 24 h" should be more than 1. If it is 0 or 1, the DHCP
   change did not take or the firewall rule is missing. Test from another device:
   `nslookup example.com <this PC's IP>`.
3. **Is the firewall rule there and on the right profile?**
   `Get-NetFirewallRule -DisplayName "Home SOC DNS"` — and check the Wi-Fi network is set to
   **Private**.
4. **Did the device really change?** On Windows: `ipconfig /all` and look at "DNS Servers". On a
   phone, check the Wi-Fi details. A device that shows the router's IP has not picked up the change
   — reconnect its Wi-Fi to force a DHCP renewal.
5. **Is a secondary DNS server set anywhere?** This is the most common cause of "it blocks
   sometimes". See [section 6](#the-secondary-dns-trap).
6. **Are the lists loaded?** DNS page → Blocklists table. Entry counts of 0 or a status other than
   `ok` means the feeds have not downloaded — run "Update feeds" on the Overview page or
   `python -m homesoc update --force`. Also check each list shows "in policy" rather than
   "not used".
7. **Is the browser using DoH?** See [section 7](#7-encrypted-dns-and-what-you-can-actually-do-about-it).
   A quick tell: everything is blocked in one browser and nothing in another.

### A site is broken by a blocklist

Follow the workflow in [section 10](#10-allow-and-deny-overrides--why-was-this-blocked). The short
version: filter the query log by that client and action `block`, find the domain, press **allow**,
flush the client's DNS cache.

If you find yourself adding overrides constantly, you are running too many lists — drop back to
`oisd_small` plus the threat-intel lists.

### Lookups are slow

- **Check where time is going.** The DNS page's "Queries · 24 h" card shows the average
  milliseconds. Forwarded lookups should be in the tens of milliseconds (13 ms is typical on the
  development machine); cache hits are effectively instant.
- **A slow first upstream drags everything.** Upstreams are tried in order, so if `1.1.1.2` is
  unreachable from your network, every query waits 2 seconds for it to time out before `9.9.9.9`
  is tried. Test them from the PC directly:
  ```
  nslookup example.com 1.1.1.2
  nslookup example.com 9.9.9.9
  ```
  and reorder or replace `dns.upstreams` accordingly.
- **A VPN on the Home SOC machine** frequently captures or blocks outbound port 53. Add the VPN's
  own DNS server as the first upstream, or rely on `doh_upstream`.
- **Raise `cache_max_entries`** if you have many devices; 20,000 is sized for a household, and each
  entry is only the packed reply — a few hundred bytes.
- If all upstreams are failing you will see a **NET-DNS-005** finding and clients will get SERVFAIL.

### Checking the query log

- **Dashboard:** the DNS page's **Live query log** with client and action filters, plus "Top blocked
  domains" and "Top clients" for the last 24 hours.
- **API:** `GET /api/dns/log?limit=200&client=192.168.1.108&action=block`, plus
  `/api/dns/summary`, `/api/dns/series?hours=24`, `/api/dns/top?kind=blocked|clients`,
  `/api/dns/lists` and `/api/dns/reputation`.
- **Activity feed:** the `/feed` page rolls repeated blocks up into one readable line per device per
  domain per hour, which is much easier to skim than raw queries.
- **Terminal:** `python -m homesoc feed --kinds dns_block,dns_threat --since 24h`.

Retention is `dns.log_retention_days` (14 by default). Raw queries older than that are purged, but
hourly per-client totals are rolled up into `dns_hourly` first, so the charts keep working over
longer windows. Set `dns.log_queries = false` if you would rather not keep per-query records at all.

### DNS findings you may see

| ID | Meaning |
|---|---|
| **NET-DNS-001** | Fewer than 2 devices used the resolver in 24 h (only raised after an hour of uptime) |
| **NET-DNS-002** | Resolver could not bind its port |
| **NET-DNS-003** | Blocklists missing or older than 3 days |
| **NET-DNS-004** | A device queried a domain flagged malicious |
| **NET-DNS-005** | All upstreams have been failing for 60 s |
| **NET-DNS-006** | Bound to the LAN with no inbound firewall rule for port 53 |

Each carries its own step-by-step remediation on the Findings page.

---

## Sources

External page consulted while writing this guide:

- AT&T, "Configuring IP Passthrough and DMZplus" —
  <https://www.att.com/support/smallbusiness/article/smb-internet/KM1188700/>

Everything else here was verified against this repository's own code
(`homesoc/dnsfilter/`, `homesoc/feeds/registry.py`, `homesoc/web/api.py`, `homesoc/cli.py`,
`config.example.toml`, `scripts/enable-lan-dns.ps1`, `scripts/make-autostart.ps1`) or measured on
the development environment and recorded in `docs/TESTED_ENVIRONMENT.md`. Router menu paths for other vendors
move between firmware versions — check your vendor's own support pages, and verify with
`nslookup` from a second device rather than trusting the UI.
