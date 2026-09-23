# Home SOC — Spec Addendum C: Dependencies and blast radius

Normative extension of `docs/SPEC.md`. All existing rules apply: no external assets or CDNs, CSP `default-src 'self'`,
escape everything, dependencies limited to `flask` + `requests` + `dnslib` + stdlib, no telemetry, works offline.

## C1. What this is, and what it deliberately is not

**Is:** a map of what each device *depends on*, what *depends on it*, and what stops working when it fails —
built from evidence Home SOC already collects, with every edge labelled by how it was established.

**Is not:** a live traffic diagram. Home SOC has no packet visibility and LAN peer-to-peer traffic never passes
through it, so it cannot know that the laptop is talking to the NAS on port 445 right now. Producing arrows implying
otherwise would be inventing data. The UI must say this plainly, once, where a user would otherwise expect flows.

Getting true per-flow data needs a managed switch mirroring a port, Home SOC being the router, or working packet
capture. Section C8 keeps the door open for those without committing to them.

## C2. Where edges come from

Every edge carries a `confidence`, and the UI renders the three differently (solid / dashed / dotted, with a legend):

| confidence | meaning | sources |
|---|---|---|
| `observed` | Home SOC recorded it | a DNS query from that client's address (forgeable by another LAN device); an mDNS/SSDP advertisement; a UPnP port mapping; devices that dropped together in a recorded outage |
| `inferred` | follows from the network's shape with high confidence | every device reaching the internet via the default gateway; a device using the configured DNS server |
| `assumed` | a reasonable default that has not been confirmed | a device on the LAN being reachable through the gateway when no route data exists |

Concrete rules:

1. **Gateway** — every device on the local subnet → gateway, `edge_type='gateway'`, `inferred`.
2. **Internet** — gateway → internet, `inferred`. Devices reach the internet only through it.
3. **DNS** — a device that appears as a `dns_queries.client` → the resolver, `observed`, with the query count as
   evidence. A device that does not appear but sits on a subnet whose DHCP hands out the resolver → `inferred`.
4. **Cloud** — device → registrable domain, `observed`, aggregated from `dns_queries` over a window, grouped into a
   vendor label where recognisable. Blocked domains are recorded but marked so they do not read as a dependency.
5. **Offered services** — a device advertising `_printer._tcp`, `_airplay._tcp`, `_spotify-connect._tcp`, `_ipp._tcp`,
   `_smb._tcp`, `_raop._tcp` or similar, or listening on a service port, becomes a **provider node**.
   **Do not invent consumers.** Absent evidence, a provider is shown with "no confirmed consumers" rather than
   speculative edges to every device that might plausibly print. A consumer edge is only created when there is real
   evidence — an mDNS query for that service name, a UPnP subscription, or co-dropping in a recorded outage.
6. **Hubs** — a device whose advertisements identify it as a bridge or hub is flagged as one, and the map states
   explicitly that devices behind it (Zigbee, Z-Wave, Thread, Bluetooth) are **invisible to Home SOC** because they
   are not on the IP network at all. Never imply the child count is known when it is not.

## C3. Learning blast radius from real outages

The strongest edges are not modelled, they are watched. `device_sightings` already records presence over time.

`homesoc/topology/outages.py`:
```python
@dataclass(frozen=True)
class Outage:
    id: int; started_at: str; ended_at: str | None; cycle_seconds: int
    members: list[int]                 # device ids that went offline together
    trigger_device_id: int | None      # the infrastructure device that also dropped, when one did
    trigger_kind: str                  # "gateway" | "device" | "unknown"

def detect_outages(conn, *, min_members: int = 3, window_seconds: int | None = None) -> list[Outage]
def record_outages(conn) -> int                       # persist newly detected ones; idempotent
def co_drop_matrix(conn, *, min_outages: int = 2) -> dict[tuple[int, int], float]
    """P(b offline | a offline) across recorded outages, used to promote inferred edges to observed."""
def observed_blast_radius(conn, device_id: int) -> dict
```

**Honest resolution.** Discovery runs every `schedule.discovery_minutes` (default 10), so co-dropping means "went
offline in the same discovery cycle", not "within seconds". `Outage.cycle_seconds` records the interval in force at
the time, and every UI surface that reports an observed outage must state the resolution rather than implying
precision the data does not have. Default `window_seconds` is `2 × discovery interval`.

A device that is *always* offline at night (a phone that leaves the house) must not generate outages. Filter by
requiring the co-drop to be unusual for those devices: ignore members whose offline periods are routine
(a simple per-device baseline of how often it is offline, and at what hour).

## C4. The dependency graph

`homesoc/topology/graph.py`:
```python
@dataclass(frozen=True)
class Node:
    id: str                 # "device:7" | "internet" | "resolver" | "cloud:ring.com"
    kind: str               # device | internet | resolver | cloud | provider
    label: str; sublabel: str | None
    device_id: int | None; criticality: int; severity: str | None; online: bool

@dataclass(frozen=True)
class Edge:
    src: str; dst: str; edge_type: str; protocol: str | None
    confidence: str; evidence: str; observed_count: int

def build_graph(conn, *, hours: int = 168, include_cloud: bool = True) -> tuple[list[Node], list[Edge]]
def criticality(conn) -> list[dict]        # [{device_id, label, dependents, weight, why}], descending
def blast_radius(conn, device_id: int) -> dict
def refresh(conn) -> dict                  # recompute + persist; called by a scheduler job
```

`blast_radius` returns, for the device failing:
```python
{
  "device": {...},
  "offline":    [{device_id, label, why}],      # unreachable: their only path is through this
  "degraded":   [{device_id, label, why}],      # keep working locally, lose internet or a cloud service
  "unaffected": [{device_id, label}],
  "services_lost": ["DNS for 11 devices", "printing", ...],
  "headline": "If the router fails, 17 devices lose internet. Four keep working on the local network.",
  "confidence": "observed" | "inferred" | "mixed",
  "evidence": "Seen twice: on 3 September and 11 September, 14 devices went offline in the same
               discovery cycle as this one."      # or None when nothing has been observed
}
```
`headline` is one plain sentence a non-expert understands, in the same voice as the findings catalogue.

Classification rules: the gateway failing puts every device that only reaches the internet through it into
`degraded`, not `offline` — they are still on the LAN and still talk to each other. A device failing puts its
confirmed consumers into `degraded` (they lose that service). `offline` is reserved for devices that genuinely
become unreachable, which on a flat home network is mostly hub children and Wi-Fi clients of a failed AP.

## C5. Data model

```
dep_edges(id INTEGER PK, src TEXT*, dst TEXT*, edge_type TEXT*, protocol TEXT,
          confidence TEXT*, evidence TEXT, observed_count INTEGER* DEFAULT 0,
          first_seen TEXT*, last_seen TEXT*, UNIQUE(src, dst, edge_type))
outages(id INTEGER PK, started_at TEXT*, ended_at TEXT, cycle_seconds INTEGER*,
        trigger_device_id INTEGER REFERENCES devices(id), trigger_kind TEXT*, member_count INTEGER*)
outage_members(outage_id INTEGER* REFERENCES outages(id), device_id INTEGER* REFERENCES devices(id),
               dropped_at TEXT*, returned_at TEXT, PRIMARY KEY(outage_id, device_id))
```
Schema migration 3. Owned by a new `homesoc/topology/` package. `dep_edges` is a cache — deleting it must be
harmless, with `refresh()` rebuilding it.

## C6. Scanner, scheduler and findings

`homesoc/topology/__init__.py` exposes the standard scanner interface so it slots into the existing machinery:
```python
def run(cfg, conn, *, quick: bool = False, progress=None) -> ScanResult
```
It refreshes the graph, detects and records outages, and emits:

- `NET-DEP-001` (info) — a newly discovered load-bearing device: more than N devices now depend on it.
- `NET-DEP-002` (medium) — a single point of failure with no redundancy that took devices down at least twice,
  citing the dates. Only fires on *observed* evidence, never on inference alone.
- `NET-DEP-003` (info) — a device depends on a cloud endpoint that has been unreachable or blocked repeatedly,
  so it may be silently degraded.

Scheduler job `topology`, default interval 6 hours, after `discovery`. Add to `config.example.toml`:
```toml
[topology]
enabled = true
window_hours = 168          # how far back to read DNS and sightings when building the graph
include_cloud = true        # show external endpoints as nodes
min_outage_members = 3      # devices that must drop together before it counts as an outage
criticality_alert = 5       # dependents before NET-DEP-001 fires
```

## C7. Interface

**Page `/map`** — the graph. Hand-rolled SVG in `static/graph.js`, no libraries (follow `charts.js` precedent).
Layered left-to-right: internet → gateway → infrastructure (resolver, hubs, providers) → leaf devices, with cloud
endpoints as a collapsible column. Layout must be deterministic (same data → same picture) and readable at 25–40
nodes; collapse cloud endpoints into a single "12 external services" node until expanded.

- Node colour by severity, size by criticality, hollow when offline.
- Edge style by confidence, with a legend that explains all three in one line each.
- **Click a node → blast-radius mode:** everything that fails is highlighted, everything unaffected dims, and the
  headline sentence plus the evidence line appear in a side panel. Escape or a second click exits.
- A persistent, honest note: "Home SOC cannot see traffic between devices — it has no packet visibility. These links
  are what it has observed or can reasonably infer." with a link to the docs section explaining why.
- Keyboard accessible: nodes are focusable, arrow keys move, Enter enters blast-radius mode. Severity and confidence
  must not be conveyed by colour alone.

**Panels elsewhere:**
- `/devices/<id>` gains a "Depends on / Depended on by / If this fails" section.
- Overview gains a small "load-bearing devices" card listing the top three by criticality.
- **Lens** gains an "If this fails" section in the device card (`lens_device` payload grows a `blast` key with the
  headline, the counts and the confidence). This is the single best use of the feature: point the phone at a box and
  learn what the house loses without it.

**API:**
- `GET /api/map?hours=&cloud=` → `{nodes, edges, legend, generated_at, note}`
- `GET /api/map/blast/<device_id>` → the `blast_radius` shape
- `GET /api/map/criticality` → the ranked list
- `GET /api/map/outages?limit=` → recorded outages with members

## C8. Future flow sources (design for, do not build)

Model `dep_edges` so real flow data can raise an edge's confidence rather than requiring new structures. A later
collector would write `observed` edges with `protocol` and `observed_count` set from:
- SNMP bridge/FDB tables from a managed switch → true MAC-to-port physical topology;
- `conntrack` from an OpenWrt/pfSense router → genuine per-flow LAN traffic;
- a passive listener on a spare machine (ARP, mDNS, SSDP, DHCP are broadcast and reveal real intent) → peer edges.

Document these in `docs/TOPOLOGY.md` as "what would make this map dramatically better", including the note that a
spare Raspberry Pi running the resolver would both remove the DNS single point of failure and greatly enrich the
dependency data, since every device's lookups would then be visible.

## C9. Tests

- Edge inference per rule in C2, including the negative case: a printer with no evidence of consumers produces a
  provider node and **zero** consumer edges.
- Outage detection: three devices dropping in one cycle is an outage; a phone that leaves every evening is not;
  `cycle_seconds` records the interval actually in force.
- `co_drop_matrix` promotes an inferred edge to observed only after `min_outages`.
- `blast_radius` classification: gateway failure degrades rather than offlines; confirmed consumers degrade;
  the headline sentence renders for a gateway, a leaf device and an isolated device.
- Determinism: `build_graph` twice on identical data returns identical node and edge ordering.
- Graph renders on an empty database, a single-device database, and a 40-device one.
- Every finding ID emitted exists in the catalogue; `NET-DEP-002` never fires on inference alone.
- XSS: a device nicknamed `<img src=x onerror=alert(1)>` renders escaped in the map, the panel and the API.
- Migration 3 upgrades a v2 database with rows intact.
