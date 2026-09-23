# Dependencies and blast radius — the map

Home SOC's Devices page tells you what is on your network. The **Map** page (`/map`) tells you what each of those
devices *needs*, what *needs it*, and what stops working when it fails.

That second question is the one nobody can answer during an actual outage. The television has no picture, the doorbell
app spins, the printer is "offline" and the smart plugs will not respond, and it takes twenty minutes to work out that
all four are symptoms of one box in a cupboard. The map exists to shorten those twenty minutes to one sentence.

> This file is also the document the map page itself links to. The dashboard serves it verbatim at
> `/docs/TOPOLOGY.md`, as plain text, because Home SOC ships no Markdown renderer and will not grow a dependency for
> one page. That is why the sections below stay readable without formatting.

---

**Contents**

1. [Read this first: Home SOC cannot see traffic](#1-read-this-first-home-soc-cannot-see-traffic)
2. [What the map shows](#2-what-the-map-shows)
3. [The three confidence levels](#3-the-three-confidence-levels)
4. [Blast radius: offline, degraded, unaffected](#4-blast-radius-offline-degraded-unaffected)
5. [Learning from real outages](#5-learning-from-real-outages)
6. [The three findings](#6-the-three-findings)
7. [What Home SOC fundamentally cannot see](#7-what-home-soc-fundamentally-cannot-see)
8. [Settings](#8-settings)
9. [What would make this map dramatically better](#9-what-would-make-this-map-dramatically-better)

---

## 1. Read this first: Home SOC cannot see traffic

Home SOC runs as an ordinary program on an ordinary PC. It is not your router, it is not a firewall, and there is no
tap or mirror port feeding it a copy of the network. When your laptop copies a file to the NAS, those packets go from
the laptop to the switch to the NAS and back. **They never come anywhere near Home SOC.** It has no idea the transfer
happened, let alone that it is happening now.

So there is a whole category of thing this map is structurally incapable of being: it is not a live traffic diagram,
and it never will be without new hardware. If you have used a tool that draws animated arrows between devices on a home
network, it was either sitting on the router, mirroring a switch port, or guessing.

The design decision that follows from that is the only one in this feature that really matters:

> **Home SOC would rather show you fewer links than invent one.**

Consider a printer that advertises `_printer._tcp` over mDNS. Home SOC genuinely knows the printer offers printing —
it heard the advertisement. It does *not* know who prints. The tempting thing is to draw a line from every laptop and
phone in the house to the printer, because probably some of them print, and the picture looks impressively complete.
The map refuses. The printer appears as a **provider** node labelled *no confirmed consumers*, and stays that way
until something real turns up: an mDNS query for that service, a UPnP subscription, or the printer and another device
dropping off the network together in a recorded outage.

An empty-looking map is telling you the truth about what Home SOC can see. A full-looking one would be telling you a
story. The same note appears on the page itself, permanently, so you never read the picture as more than it is.

## 2. What the map shows

The graph is laid out left to right in layers: the **internet**, then the **gateway**, then infrastructure — the
**resolver**, any **hubs**, any **providers** — and then the leaf devices. External endpoints sit in a collapsible
column on the right, folded into a single "*N* external services" node until you open it, because thirty cloud domains
turn a readable diagram into wallpaper. Domains that were **blocked** fold into a *separate* group, so a sinkholed
tracker is never mixed in with the endpoints a device actually depends on.

How a node is drawn, and why none of it depends on colour alone:

- **A letter inside the node** is its worst open finding — **C**ritical, **H**igh, **M**edium, **L**ow, **i**nfo. The
  colour repeats the letter; it never carries the meaning by itself.
- **Size** is criticality: bigger means more things depend on it.
- **Hollow, with a broken outline**, means offline right now — and the word *offline* is in the node's label too.
- **Shape** is what kind of thing it is: a square is the internet or an external service, a diamond is the DNS
  resolver, a pentagon is something offering a service to the house, a hexagon is a hub, and a circle is an ordinary
  device.
- **Edge style** is confidence — solid, dashed, dotted — with a legend that explains all three in one line each.

Everything is keyboard reachable: tab into the graph, arrow keys move between nodes, Enter opens blast-radius mode and
Escape leaves it. The layout is deterministic, so the same data always draws the same picture and you can learn where
things are. A window selector at the top of the page switches between 24 hours, 3 days, 7 days and 30 days
(`/map?hours=`), and external services can be folded away entirely (`/map?cloud=0`).

Where the edges come from:

- **Device → gateway.** Every device on the local subnet reaches the rest of the world through it.
- **Gateway → internet.** The single route out.
- **Device → resolver.** Real DNS queries in the query log, when the device appears there as a client.
- **Device → external service.** The registrable domains that device actually looked up, grouped by vendor where one
  is recognisable. Blocked domains are recorded but marked, so a sinkholed tracker does not read as a dependency.
- **Provider node.** A device advertising a service (`_printer._tcp`, `_airplay._tcp`, `_smb._tcp`, `_raop._tcp`,
  `_ipp._tcp`, `_spotify-connect._tcp`) or listening on a service port — with **consumers only when there is
  evidence**.
- **Hub.** A device whose advertisements identify it as a bridge. What is behind it is invisible; see
  [section 7](#7-what-home-soc-fundamentally-cannot-see).

The cloud column is the one place where Home SOC has genuinely rich data, and it is worth understanding why: the DNS
resolver is the one point where traffic really does pass through Home SOC. If you have turned the LAN-wide filter on
(`[dns] enabled = true`), every device that uses it hands Home SOC a continuous, honest record of which names it wants.
That is how a doorbell gets an edge to its vendor's cloud with a query count behind it. If you have *not* turned the
resolver on, the cloud column will be thin or empty, and that is not a bug — it is the map declining to guess.

## 3. The three confidence levels

Every edge carries one, and the page draws each differently.

**`observed` — solid line.** Home SOC saw this happen: a DNS query arriving from that device at its own resolver, a
service the device advertised over mDNS, or a set of devices that went offline in the same discovery cycle. Those
three are the whole list — it is deliberately short, and section 9 covers what would lengthen it.

**`inferred` — dashed line.** Not seen, but it follows from how the network is shaped: every device on the gateway's
own subnet reaches the internet through it.

**`assumed` — dotted line.** A reasonable default that nothing has confirmed, such as a LAN device being reachable
through the gateway when Home SOC has no route data at all.

The levels exist because of section 1. Without them, the map would have to choose between two bad options: show only
what was directly observed, which on a home network is almost nothing, or show the obvious structural facts as though
they had been measured, which is the inventing this feature refuses to do. Labelling each edge is the compromise that
lets the map be useful *and* honest simultaneously.

In practice, read them like this:

- **Solid** — act on it. Home SOC saw it.
- **Dashed** — it is almost certainly true, and it is true for a reason you could verify yourself in thirty seconds
  (everything goes out through the router; it does).
- **Dotted** — this is a prompt to check, not a fact. If a dotted edge matters to a decision you are making, go and
  confirm it.

An edge can be promoted. An inferred link becomes observed the moment real evidence turns up — a query in the log, or
the two devices going down together twice.

Nothing is ever left at a stale level, either, because the graph is **rebuilt from scratch** on every refresh rather
than accumulated. An edge whose evidence has gone either reappears at whatever confidence the current evidence
supports, or stops being drawn at all. The single thing carried across a rebuild is `first_seen` — "we have believed
this since Tuesday" is the only fact a rebuild cannot recompute. That is also why the `dep_edges` table is safe to
delete: it is a cache, and the next refresh restores exactly the same rows.

## 4. Blast radius: offline, degraded, unaffected

Click any node and the map enters blast-radius mode: everything the failure reaches keeps its colour and gets one ring
in the accent colour, everything outside it dims, and a side panel gives you a sentence plus the evidence behind it.

There is exactly one ring, deliberately. Which *kind* of harm a node takes — unreachable, degraded, or a service that
stops existing — is a word, on the node's own tooltip and screen-reader name and in the panel's lists, never a second
ring colour: the map already spends red and amber on finding severity, and a second meaning for the same two hues in
the same frame is the sort of thing [C7](SPEC_TOPOLOGY.md) exists to forbid.

Two things the ring covers that the counts do not. The three tiles count **devices**, and the panel says so; the
internet, the resolver and the external endpoints are ringed in the picture but are not devices and are not tallied.
And a service is only marked lost when the box hosting it actually stops — a printer whose router has died keeps
printing on the LAN, so its "Printing" node dims along with everything else that goes on working.

These are real sentences, from a six-device test network:

> If Living-room router fails, 5 devices lose their internet connection. They stay on the local network and can still
> reach each other.

> If speaker fails, the network loses airplay audio, but nothing has been seen using it, so no other device is known
> to be affected.

The second one is the discipline of [section 1](#1-read-this-first-home-soc-cannot-see-traffic) showing up in the
output. A speaker advertising AirPlay is a service the house has; who uses it is not something Home SOC can see, so
the sentence says so instead of guessing.

The distinction that makes this useful is **degraded** versus **offline**, and it is the distinction most network
diagrams get wrong.

**Degraded** means the device keeps running and stays reachable, but loses something. Your laptop with the router
unplugged is degraded: no internet, but it is still on the Wi-Fi, still printing, still reaching the NAS. A speaker
whose cloud endpoint is unreachable is degraded: local playback works, voice control does not.

**Offline** means genuinely unreachable — nothing on the network can talk to it at all.

On a flat home network, **a gateway failure degrades nearly everything and offlines nearly nothing**, which surprises
people. The devices are all still there, on the same switch and the same Wi-Fi, perfectly able to talk to each other.
They have simply lost the door to the outside. The cases that really do produce *offline* are narrower: the children
behind a failed smart-home hub, and the Wi-Fi clients of a failed access point.

Everything else lands in **unaffected**, and that list is worth reading too — it is the part of the house that keeps
working, which is exactly what you want to know at 9pm on a Sunday.

The panel also reports the **services lost** — from the same test network, `internet access for 5 devices`,
`DNS for 3 devices`, `printing (no confirmed consumers)` — and its own **confidence**: `observed` when the
classification came from watching a real outage, `inferred` when it was reasoned from structure, `mixed` when both
contributed.

Note that a provider with nobody confirmed using it is still listed as a service lost. That is deliberate: *"printing
(no confirmed consumers)"* is honest in both directions. Printing really does stop, and Home SOC really does not know
who that hurts.

When there is observed evidence, the evidence line gives it in dates and counts:

> Seen twice: on 11 September and 12 September, 4 devices went offline in the same 10-minute discovery cycle as this
> one.

When there is none, the panel says so rather than padding the sentence out.

## 5. Learning from real outages

The strongest edges on this map are not modelled at all. They are remembered.

Discovery already records which devices it can see, every time it runs. When several devices disappear in the same
cycle and come back in the same cycle, that is an **outage**, and it is far better evidence of a real dependency than
any amount of reasoning about network structure — because it is what actually happened in your house.

Home SOC records each outage with its members, its start and end, and, when one of the devices that dropped is
infrastructure (the gateway, a NAS, an access point), which one that was. Across several recorded outages it builds a
co-drop probability — *given that A was offline, how often was B also offline* — and uses it to promote inferred edges
to observed. An edge is only promoted after the pattern has repeated: seeing two devices drop together once is a
coincidence.

**"Trigger" is an association, not a measured cause.** Home SOC has no packet visibility and no power telemetry. All
it knows is that these devices vanished from the same sweep and that one of them is the infrastructure box, so that
one is named first — which is genuinely the useful thing to check first. A tripped power strip produces the identical
record. Nothing in the interface says the trigger "took the others down": the blast-radius panel, the `NET-DEP-002`
finding and the map's edge tooltips all say that they dropped in the same discovery cycle and that what connects them
was not established. For the same reason a co-drop does not make another device *unreachable* — that is reserved for
a failing hub, access point or switch, where there is a path to sever — and a co-drop with a device offering several
services never claims to know which service was involved, because one shared outage is one bit of information and
cannot be spent on four claims.

### The resolution is one discovery cycle, not seconds

This is the honest limit of outage learning, and it is worth stating plainly because the phrase "went offline
together" invites you to imagine a precision that does not exist.

Home SOC learns that a device is gone by running discovery and not finding it. Discovery runs on a schedule —
`schedule.discovery_minutes`, ten minutes by default. So "these devices went offline together" means **"they were both
missing from the same discovery cycle"**, which with the default settings is a ten-minute window. It does not mean
they dropped within seconds of each other, and it cannot: Home SOC was not watching in between.

Every recorded outage stores the cadence that was actually in force at the time, and every surface that reports one —
the map's side panel, the outage list, the `NET-DEP-002` finding — states it rather than implying precision the data
does not have:

> Discovery ran every 10 minutes at the time, so "dropped together" means "went missing in the same 10-minute
> discovery cycle", not "within seconds".

That number is **measured, not assumed**. It is the median gap between the discovery runs around that outage, so a
machine that was asleep for six hours, or a scheduler that was paused, does not quietly stretch the claimed resolution
of every outage near it — and an outage recorded while the interval was different keeps the interval it was really
measured with. If you shorten `schedule.discovery_minutes`, resolution improves from then on; old outages are not
retroactively sharpened.

The practical consequence: two devices that failed for completely unrelated reasons inside the same ten minutes will
look correlated once. That is why promotion needs repetition, and why `NET-DEP-002` will not fire until it has seen
the same group drop together at least twice.

### Devices that leave the house

A phone that goes to work every morning is offline every morning. So is a laptop that gets closed at eleven every
night. If those counted, every weekday would look like an outage, and the map would fill with confident nonsense about
your phone depending on your partner's phone.

So before anything is recorded, every device gets a baseline: how often it is missing overall, and how often it is
missing *at this hour of the day*. A device is excused from an outage only when both are true — it goes missing
regularly, **and** it goes missing at this particular hour most of the time, with enough samples of that hour to mean
something. A device discovered ten minutes ago has no baseline yet and is not excused on the strength of nothing.

The cost of that guard is that a genuine outage which happens to coincide with the school run may under-count its
members. The trade is deliberate: a map that is quiet and right is worth more than one that is loud and wrong.

## 6. The three findings

The topology scan emits three findings, all in the **topology** category. They appear on the Findings page like any
other, with the same numbered fix steps.

**`NET-DEP-001` (info) — *"{device} has become load-bearing"*.** More devices now depend on this one than the
`topology.criticality_alert` threshold. Nothing is wrong with it. The point is that it grew important gradually, which
is exactly the kind of change nobody notices until the evening it fails and the failure looks like five unrelated
problems at once. The fix steps are about knowing what it carries and, where you can, splitting its roles.

**`NET-DEP-002` (medium) — *"{device} is a single point of failure"*.** This one fires **only on observed evidence,
never on inference** — Home SOC has watched this device take a group of others down with it on at least two separate
occasions, and the finding cites the dates. There is nothing to patch. Its remediation is about redundancy (a
secondary DNS server, a tested hotspot, moving one role onto another box) and about knowing what to check first when
it happens again, which is the bit that actually saves you an evening. It also tells you to rehearse: unplug it for
two minutes on a quiet afternoon and see whether reality matches the map.

**`NET-DEP-003` (info) — *"{device} depends on {domain}, which is not answering it"*.** A device keeps asking for a
cloud endpoint and keeps not getting a usable answer — either the filter blocked it or the name does not resolve.
Consumer devices almost never tell you this. They keep their lights on and quietly stop doing something: notifications
stop arriving, recordings stop uploading, schedules stop firing, firmware stops updating. This finding is a note that
a feature you believe you have may not currently exist. Sometimes the right answer is "good, that was telemetry" —
which is why it is `info` and why the first fix step is to decide whether you wanted that connection at all.

## 7. What Home SOC fundamentally cannot see

Four blind spots. None of them is a bug, and none of them can be fixed in software on this machine.

**Device-to-device traffic.** Covered at length in [section 1](#1-read-this-first-home-soc-cannot-see-traffic).
LAN peer traffic does not pass through Home SOC, so it cannot know that the laptop mounts the NAS every morning, that
the television streams from the media server, or that one smart plug talks to another. This is the big one, and it is
why provider nodes sit there saying *no confirmed consumers* instead of sprouting plausible lines.

**Anything behind a smart-home hub.** A Hue bridge, a SmartThings hub, a Zigbee or Z-Wave or Thread controller, a
Bluetooth gateway — these appear on the map as one device with one IP, because that is exactly what they are on your
network. The twenty bulbs, sensors and switches behind them **are not on the IP network at all**. They speak a
different radio protocol to the hub, and the hub speaks IP to everything else. There is no packet to miss and no ARP
entry to read: those devices are invisible in the most literal sense.

What the map does about it: it draws the hub as a hub and puts a line under the graph saying so, in as many words —

> Hue bridge is a hub. Whatever it controls over Zigbee, Z-Wave, Thread or Bluetooth is not on the IP network, so
> Home SOC cannot see it — not even how many there are.

— rather than letting the picture imply that a hub with one line out of it is a device with one dependency. If you
want to know what is behind a hub, its own app is the only source.

**Anything using a DNS resolver that is not Home SOC.** The cloud column is built from the query log, so a device
hard-coded to `8.8.8.8` (plenty of smart TVs and consoles are), or using DNS-over-HTTPS to a resolver of its own, or
on a VPN, contributes nothing. It appears on the map with its gateway edge and no cloud edges, and that absence means
"not observed", not "does not talk to the internet".

**Encrypted or unadvertised services.** A device can run whatever it likes on a port without telling anyone. Home SOC
knows about services it finds by port scan or that the device advertises over mDNS/SSDP. Something listening quietly
on a high port, or reachable only over a tunnel, is not in the picture.

## 8. Settings

In `config.toml`:

```toml
[topology]
enabled = true              # master switch for the map, the scan job and the findings
window_hours = 168          # how far back to read DNS queries and sightings when building the graph
include_cloud = true        # show external endpoints as nodes
min_outage_members = 3      # devices that must drop together before it counts as an outage
criticality_alert = 5       # dependents before NET-DEP-001 fires
```

Two of these change what the map means, so they are worth a thought rather than a default:

- **`window_hours`** is the memory. A week (168 hours) is long enough to catch a device that phones home daily and
  short enough that a service you stopped using last month fades out. Shorten it and the map becomes a snapshot of
  this week; lengthen it and old, dead dependencies linger.
- **`min_outage_members`** is the noise floor. Three is deliberately conservative: two devices dropping together is
  most of what a home network does all day (a phone and a watch leaving the house share an owner, not a dependency).

The `dep_edges` table is a **cache**. Deleting it is harmless; the next refresh rebuilds it from the sightings, the
query log and the service records, which are the real data. The `outages` and `outage_members` tables are not a
cache — they are the recorded history that `NET-DEP-002` cites, and deleting those loses the observed evidence.

### When it runs

The map is refreshed by a scheduled job called `topology`, which runs after discovery and re-reads what discovery and
the DNS filter already wrote — it never scans anything itself, so it is cheap and safe to run at any time. To do it by
hand:

```sh
python -m homesoc scan --only topology
```

`topology` is also one of the steps `scan --full` runs.

### From the terminal

`python -m homesoc blast <device>` answers the same question as clicking a node, without a browser. The argument is
an IP, a MAC, or a nickname/hostname. Real output, from the same test network:

```
$ python -m homesoc blast 192.168.1.254
Living-room router   192.168.1.254  aa:bb:cc:00:00:01

If Living-room router fails, 6 devices lose their internet connection. They stay on the
local network and can still reach each other.

Keeps working, but degraded (6)
  - Front doorbell: loses its internet connection; it stays on the local network and can still reach devices here
  - Home PC: loses its route to the internet, though it has never been seen using it; it stays on the local network
  ...

Services lost
  - internet access for 6 devices
  - DNS for 2 devices

Confidence: inferred
  Seen three times: on 11 September, 12 September and 13 September, 4 devices went offline
  in the same 10-minute discovery cycle as this one.
  Discovery ran every 10 minutes at the time, so "dropped together" means "went missing in
  the same 10-minute discovery cycle", not "within seconds".

  Home SOC cannot see traffic between devices - it has no packet visibility. These links
  are what it has observed or can reasonably infer.
```

Two details in that transcript are the feature working as designed. *"though it has never been seen using it"* is Home
SOC declining to claim a device uses the internet just because it could. And the caveat about resolution is printed
even here, in a terminal, because the whole point is that it travels with the number.

### The API

Four JSON endpoints, for anyone who wants the data rather than the picture:

- `GET /api/map?hours=&cloud=` → `{nodes, edges, legend, generated_at, note}`. Both parameters default to
  `topology.window_hours` and `topology.include_cloud`.
- `GET /api/map/blast/<device_id>` → the blast radius: `offline`, `degraded`, `unaffected`, `services_lost`,
  `headline`, `confidence`, `evidence`.
- `GET /api/map/criticality?limit=` → the load-bearing devices, most dependents first.
- `GET /api/map/outages?limit=` → recorded outages with their members, plus a `resolution` string.

Two things about those payloads are deliberate rather than decorative.

**The caveat travels with the data.** Every one of them carries `note`, which is the same sentence printed on the page:
*"Home SOC cannot see traffic between devices — it has no packet visibility. These links are what it has observed or
can reasonably infer."* A script polling `/api/map` inherits the caveat along with the numbers. `/api/map/outages`
likewise carries `resolution`, which spells out the discovery interval in force so nobody reads the timestamps as
second-by-second truth.

**Every edge keeps its own `confidence` and `evidence`**, and the API layer never flattens them away for convenience.
An edge that arrives claiming to be `observed` with nothing behind it is downgraded rather than served, and an edge
with a confidence the legend does not explain is dropped rather than drawn in a style nobody can interpret.

The map routes are a **dashboard** view and refuse a paired Lens phone token: one request returning every device, every
dependency and every external service is the opposite shape from what a phone standing in front of one box needs.
Lens gets the blast-radius sentence for the device it has actually identified, through its own device endpoint, and
nothing more.

## 9. What would make this map dramatically better

Everything above is what can be done with no extra hardware, no admin rights and no packet capture. The ceiling is
low, and it is worth being clear about what lifts it — all three of these would raise edges from *inferred* to
*observed*, which is the whole game.

**A managed switch, read over SNMP.** Any managed switch keeps a bridge forwarding table: which MAC address it last
saw on which physical port. Read that (it is [BRIDGE-MIB, RFC 4188](https://www.rfc-editor.org/rfc/rfc4188), reachable
with [`snmpwalk`](https://www.net-snmp.org/docs/man/snmpwalk.html)) and you get something Home SOC currently has no
route to at all: **true physical topology**. Which devices are on which port, which ports feed which other switches,
and therefore which devices genuinely share a failure domain. A cheap second-hand managed switch is the single
highest-value upgrade here, and it needs no software on any device.

**`conntrack` from an OpenWrt or pfSense router.** If your router runs Linux — [OpenWrt](https://openwrt.org/docs/guide-user/network/dns/dnsmasq),
[pfSense](https://docs.netgate.com/pfsense/en/latest/), OPNsense, most of the enthusiast firmware — the kernel is
already tracking every connection through it, and [conntrack-tools](https://conntrack-tools.netfilter.org/) can list
them. That is **genuine per-flow data**: who talked to whom, on which port, for how long. It is the thing that would
let the map draw the laptop-to-NAS edge honestly. The catch is real: it only sees flows the router routes, so on a
flat network where the laptop and NAS are on the same subnet and the same switch, the router never sees that traffic
either. It buys you perfect internet-facing flows and inter-VLAN flows, not LAN peer flows.

**UPnP/SSDP and the DHCP lease file.** Two evidence sources the design contemplated and the shipped code does not
have. A UPnP port mapping, and an SSDP advertisement (Home SOC's discovery stores an `ssdp` key it does not yet read),
would each name a real relationship. So would the DHCP lease file: C2.3 allows an `inferred` resolver edge for a
device handed this resolver by DHCP, but Home SOC cannot read DHCP options, so that precondition can never be
established and the edge is deliberately not emitted. Until a collector supplies them, none of the three appear in the
legend — the legend describes the evidence that exists, not the evidence that was planned.

**A passive listener on a spare machine.** Even without a mirror port, a machine sitting on the LAN doing nothing but
listening hears more than you would expect, because a lot of the network is *broadcast* and arrives at every host by
design: ARP ("who has 192.168.1.40?" — which is a device announcing its intent to talk to another device), mDNS
service queries ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) and
[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763), which is how a phone says it is looking for a printer), SSDP, and
DHCP. Those broadcasts reveal genuine intent, and an mDNS *query* for `_printer._tcp` is exactly the evidence that
would finally give the printer a confirmed consumer.

### The one worth doing first: a Raspberry Pi running the resolver

If you only do one of these, do this one. It needs no new networking knowledge, it fixes a real problem, and it
enriches the map at the same time.

Right now, if you have the LAN-wide DNS filter turned on, your household DNS runs on the same PC as everything else.
That makes that PC a single point of failure — the kind `NET-DEP-002` will eventually tell you about, in dates. It is
also why plenty of people never point the router at it in the first place: a PC that sleeps, reboots for updates or
travels in a bag is not somewhere you want the whole house's name resolution to live. Moving it onto a spare Raspberry
Pi (or any always-on small box that can run Python) does two separate good things:

1. **It removes the DNS single point of failure from the machine that has every other job.** A dedicated box that does
   one thing and is never rebooted for unrelated reasons is a far better home for the service everything else needs
   before it can do anything at all.
2. **It makes the dependency map dramatically richer**, because once the resolver is somewhere always-on you can
   actually hand it out as *the* DNS server for the whole network — and then every device's lookups become visible.
   Cloud edges stop being a thin sample of whatever happened to be pointed at Home SOC and become a near-complete
   record of which device depends on which external service, with counts and timestamps, marked `observed` rather
   than inferred. Most of section 7's third blind spot closes, for every device that honours the router's DNS setting.

The one practical detail worth planning for: **the query log lives wherever the resolver runs**, and the graph is
built from that database. So run Home SOC itself on the Pi — `python -m homesoc run` gives you the resolver, the
scheduler and the dashboard in one process, and the map is then built next to the data that feeds it. Running only
the resolver there (`python -m homesoc dns`) works, but the lookups it records stay in *that* machine's database, so
the map on your PC would not see them. Point the router's DNS at the Pi, give the Pi a static address or a DHCP
reservation, and read [NETWORK_DNS_SETUP.md](NETWORK_DNS_SETUP.md) for the router side.

That second point is the one people underestimate. DNS is the only place where a home network volunteers its
intentions, in plain text, to a box you control — without a mirror port, a tap or a single captured packet. Sitting on
it is most of the way to a map worth trusting.

---

**See also:** [NETWORK_DNS_SETUP.md](NETWORK_DNS_SETUP.md) for pointing the router at the resolver,
[WALKTHROUGH.md](WALKTHROUGH.md#5-a-guided-tour-of-the-dashboard) for the map in the context of the rest of the
dashboard, and [SPEC_TOPOLOGY.md](SPEC_TOPOLOGY.md) for the build contract this was written against.
