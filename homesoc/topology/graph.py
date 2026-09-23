"""The dependency graph, criticality ranking and blast radius (SPEC addendum C4).

The one invariant that makes everything else simple:

    **every edge points from the dependent to the thing it depends on.**

``device:7 -> device:1`` means device 7 needs device 1. ``provider:12:printing ->
device:12`` means the printing service needs the printer to be up. Reverse-reachability
from a node is therefore exactly "what breaks when this fails", and no consumer of this
module has to remember which way round an arrow was drawn.

What this module will not do is invent an edge. Home SOC has no packet visibility: LAN
traffic between two devices never passes through it, so it cannot know that the laptop
is talking to the NAS. Everything here comes from :mod:`homesoc.topology.infer`, which
builds edges only from things that were actually recorded, and every edge carries the
``confidence`` that says which kind of knowledge it is.

Determinism is a requirement, not a nicety: the map in the dashboard must not reshuffle
itself between two refreshes of the same data, so nodes and edges come out of
:func:`build_graph` in a total order that depends on nothing but the rows in the database.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Any

from homesoc import db
from homesoc.util import utcnow_iso

logger = logging.getLogger(__name__)

#: Confidence values, weakest first. ``observed`` = Home SOC saw it happen; ``inferred`` =
#: follows from the shape of the network; ``assumed`` = a reasonable default not yet confirmed.
CONFIDENCES: tuple[str, ...] = ("assumed", "inferred", "observed")
CONFIDENCE_RANK: dict[str, int] = {name: rank for rank, name in enumerate(CONFIDENCES)}

#: Node kinds, in the left-to-right order the map draws them (C7). The UI owns the layout;
#: this ordering exists so ``build_graph`` can emit a stable, meaningful sequence.
NODE_KINDS: tuple[str, ...] = ("internet", "resolver", "provider", "device", "cloud")
KIND_RANK: dict[str, int] = {kind: rank for rank, kind in enumerate(NODE_KINDS)}

#: Edge types. ``cloud_blocked`` is deliberately *not* a dependency: it records that a device
#: keeps asking for a domain Home SOC blocks, which is the opposite of something it relies on.
EDGE_TYPES: tuple[str, ...] = ("gateway", "internet", "dns", "cloud", "cloud_blocked", "uses", "hosted_by")
#: Edge types that mean "src stops working properly when dst fails".
DEPENDENCY_EDGE_TYPES: frozenset[str] = frozenset({"gateway", "internet", "dns", "cloud", "uses", "hosted_by"})

INTERNET_ID = "internet"
RESOLVER_ID = "resolver"

#: A co-drop this likely, over at least this many outages *triggered by the device itself*,
#: is treated as real evidence that the other device could not work without it.
CO_DROP_CONFIRMED = 0.75
CO_DROP_MIN_OUTAGES = 2


@dataclass(frozen=True)
class Node:
    """One box on the map.

    ``criticality`` is the number of devices that depend on this node, directly or through
    other nodes — the map sizes boxes by it. ``severity`` is the worst open finding on the
    device (``None`` for anything that is not a device), and must never be the only way the
    UI conveys risk (C7: not by colour alone).
    """

    id: str
    kind: str
    label: str
    sublabel: str | None
    device_id: int | None
    criticality: int
    severity: str | None
    online: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "label": self.label, "sublabel": self.sublabel,
            "device_id": self.device_id, "criticality": self.criticality,
            "severity": self.severity, "online": self.online,
        }


@dataclass(frozen=True)
class Edge:
    """One link, always pointing from the dependent (``src``) to the dependency (``dst``).

    ``evidence`` is a sentence a person can read and argue with ("412 DNS queries in the last
    7 days"), not a code. ``observed_count`` is whatever the source counted — queries, outages,
    advertisements — and is 0 for anything purely inferred.
    """

    src: str
    dst: str
    edge_type: str
    protocol: str | None
    confidence: str
    evidence: str
    observed_count: int = 0

    @property
    def key(self) -> tuple[str, str, str]:
        """The identity ``dep_edges`` uses (its UNIQUE constraint)."""
        return (self.src, self.dst, self.edge_type)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src, "dst": self.dst, "edge_type": self.edge_type, "protocol": self.protocol,
            "confidence": self.confidence, "evidence": self.evidence, "observed_count": self.observed_count,
        }


# --------------------------------------------------------------------- building


def build_graph(conn: sqlite3.Connection, *, hours: int = 168, include_cloud: bool = True) -> tuple[list[Node], list[Edge]]:
    """Build the whole dependency graph from the database.

    Deterministic by construction: nodes come out ordered by (kind, address, id) and edges by
    (src, dst, type), so two builds over identical data return identical lists — which
    ``tests/test_topology.py::test_build_graph_is_deterministic`` checks by building twice.
    """
    # Imported here rather than at module scope: infer.py needs Node/Edge from this module, and
    # a top-level import in both directions would be a cycle. By the time anything calls this
    # function both modules are fully loaded, so the deferred import is free.
    from homesoc.topology import infer

    result = infer.infer_all(conn, hours=hours, include_cloud=include_cloud)
    device_nodes = _device_nodes(conn, result.edges)
    nodes = _sorted_nodes(list(device_nodes) + list(result.nodes))
    edges = sorted(result.edges, key=lambda e: (e.src, e.dst, e.edge_type))
    # Drop edges pointing at a node that does not exist. Nothing should produce one; if
    # something does, a dangling arrow in the UI is worse than a missing one.
    known = {n.id for n in nodes}
    kept = [e for e in edges if e.src in known and e.dst in known]
    if len(kept) != len(edges):
        logger.warning("dropped %d topology edge(s) with no matching node", len(edges) - len(kept))
    return nodes, kept


def _sorted_nodes(nodes: list[Node]) -> list[Node]:
    return sorted(nodes, key=lambda n: (KIND_RANK.get(n.kind, len(NODE_KINDS)), _node_sort_key(n), n.id))


def _node_sort_key(node: Node) -> tuple:
    """Devices sort by IP so the map reads like the address plan; everything else by label."""
    if node.kind == "device" and node.sublabel:
        return (0,) + _ip_key(node.sublabel.split(" ")[0])
    return (1, node.label.lower())


def _ip_key(text: str) -> tuple:
    parts = str(text or "").split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return tuple(int(p) for p in parts)
    return (999, 999, 999, 999)


def _device_nodes(conn: sqlite3.Connection, edges: list[Edge]) -> list[Node]:
    from homesoc.topology import infer

    severities = _worst_severities(conn)
    hubs = infer.hub_device_ids(conn)
    counts = _dependent_counts(edges)
    nodes: list[Node] = []
    for row in db.query(conn, "SELECT id, mac, ip, hostname, nickname, vendor, kind, online FROM devices ORDER BY id"):
        device_id = int(row["id"])
        node_id = f"device:{device_id}"
        sub = str(row["ip"] or row["mac"] or "")
        if device_id in hubs:
            sub = (sub + " · hub").strip(" ·")
        nodes.append(Node(
            id=node_id,
            kind="device",
            label=infer.display_name(row),
            sublabel=sub or None,
            device_id=device_id,
            criticality=counts.get(node_id, 0),
            severity=severities.get(device_id),
            online=bool(row["online"]),
        ))
    return nodes


def _worst_severities(conn: sqlite3.Connection) -> dict[int, str]:
    """Worst open finding per device, for the node colour (never the only signal — C7)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out: dict[int, str] = {}
    rows = db.query(
        conn,
        "SELECT device_id, severity FROM findings WHERE status = 'open' AND device_id IS NOT NULL",
    )
    for row in rows:
        device_id = int(row["device_id"])
        severity = str(row["severity"] or "info").lower()
        current = out.get(device_id)
        if current is None or order.get(severity, 9) < order.get(current, 9):
            out[device_id] = severity
    return out


# ------------------------------------------------------------------ reachability


def _reverse_adjacency(edges: list[Edge]) -> dict[str, list[str]]:
    """dst -> the nodes that depend on it (dependency edges only)."""
    out: dict[str, list[str]] = {}
    for edge in edges:
        if edge.edge_type in DEPENDENCY_EDGE_TYPES:
            out.setdefault(edge.dst, []).append(edge.src)
    return out


def dependents(edges: list[Edge], node_id: str, *, reverse: dict[str, list[str]] | None = None) -> list[str]:
    """Everything that transitively depends on ``node_id``, in a deterministic order.

    ``reverse`` is a :func:`_reverse_adjacency` the caller already built. Pass it whenever this
    is called more than once over the same edges: rebuilding it on every call is what made a
    graph build O(nodes x edges), and let a LAN device that churns MAC addresses turn every map,
    overview and Lens request into minutes of CPU inside the resolver's process.
    """
    if reverse is None:
        reverse = _reverse_adjacency(edges)
    seen: set[str] = set()
    stack = list(reverse.get(node_id, ()))
    while stack:
        current = stack.pop()
        if current in seen or current == node_id:
            continue
        seen.add(current)
        stack.extend(reverse.get(current, ()))
    return sorted(seen)


def _dependent_counts(edges: list[Edge]) -> dict[str, int]:
    """How many *devices* depend on each node — Node.criticality.

    Keys are the nodes that are the target of at least one dependency edge; the value is the
    number of distinct ``device:*`` nodes that reach it (never counting the node itself), which
    is exactly ``len([d for d in dependents(edges, n) if d.startswith("device:")])``.

    Computed in one pass rather than one traversal per node. The traversal-per-node version was
    O(targets x edges) — it also rebuilt the reverse map every time — and targets and edges both
    grow with the number of device identities a LAN device can mint, so the cost grew with the
    square of something an attacker controls. Here the reverse graph is condensed into strongly
    connected components (Tarjan, iteratively: no recursion limit to hit), and each component's
    set of dependent devices is a bitmask built from the components it points at, which Tarjan
    has always finished first. That is O(nodes + edges) set unions of at most one bit per device.
    """
    reverse = _reverse_adjacency(edges)
    if not reverse:
        return {}
    nodes: set[str] = set(reverse)
    referenced: set[str] = set()  # nodes some other node's closure reads: every dependency src
    for srcs in reverse.values():
        nodes.update(srcs)
        referenced.update(srcs)
    device_bit = {name: 1 << i for i, name in enumerate(sorted(n for n in nodes if n.startswith("device:")))}

    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    comp_of: dict[str, int] = {}
    closures: dict[int, int] = {}  # component -> bitmask of devices that reach it (kept only if referenced)
    counts: dict[str, int] = {}
    next_index = 0
    next_comp = 0

    for root in sorted(nodes):
        if root in index:
            continue
        index[root] = low[root] = next_index
        next_index += 1
        stack.append(root)
        on_stack.add(root)
        work: list[tuple[str, Any]] = [(root, iter(reverse.get(root, ())))]
        while work:
            node, successors = work[-1]
            descended = False
            for nxt in successors:
                if nxt not in index:
                    index[nxt] = low[nxt] = next_index
                    next_index += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(reverse.get(nxt, ()))))
                    descended = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] != index[node]:
                continue
            members: list[str] = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                members.append(member)
                comp_of[member] = next_comp
                if member == node:
                    break
            # Inside a cycle every member reaches every other, so the component's own devices
            # are dependents of each member (each member's own bit is masked off below).
            mask = 0
            if len(members) > 1:
                for member in members:
                    mask |= device_bit.get(member, 0)
            for member in members:
                for src in reverse.get(member, ()):
                    other = comp_of[src]
                    if other != next_comp:
                        mask |= device_bit.get(src, 0) | closures.get(other, 0)
            if any(m in referenced for m in members) and mask:
                closures[next_comp] = mask
            for member in members:
                if member in reverse:
                    counts[member] = (mask & ~device_bit.get(member, 0)).bit_count()
            next_comp += 1
    return counts


# ------------------------------------------------------------------ criticality


def criticality(conn: sqlite3.Connection, *, hours: int = 168,
                edges: list[Edge] | None = None) -> list[dict[str, Any]]:
    """Load-bearing devices, most load-bearing first.

    ``weight`` ranks devices the way a person would: how many devices depend on it first, with
    a bump for evidence that its failure has actually taken things down before. ``why`` is the
    sentence the overview card prints.

    ``edges`` lets a caller that has *just* built the graph hand it over instead of paying for a
    second :func:`build_graph`. The overview and /map both render the graph and the ranking on
    one request, and on a database with a week of DNS that second build was most of the page's
    time — spent under the shared write lock, so it stalled the resolver's own writes too.
    """
    from homesoc.topology import infer, outages as outages_mod

    if edges is None:
        _nodes, edges = build_graph(conn, hours=hours, include_cloud=False)
    else:
        # A supplied graph may or may not include the cloud column, and the ranking must not
        # depend on which: external endpoints are sinks (nothing depends on them), so dropping
        # them here makes a handed-in graph produce exactly the include_cloud=False answer.
        edges = [e for e in edges if e.edge_type not in ("cloud", "cloud_blocked")]
    triggered = outages_mod.trigger_counts(conn)
    # Everything per-device below is a lookup into maps built once. Scanning every edge for every
    # device row was O(devices x edges), and both grow with the identities a LAN device can mint.
    counts = _dependent_counts(edges)
    hosted_on: dict[str, set[str]] = {}
    users_of: dict[str, set[str]] = {}
    for edge in edges:
        if edge.edge_type == "hosted_by":
            hosted_on.setdefault(edge.dst, set()).add(edge.src)
        elif edge.edge_type == "uses":
            users_of.setdefault(edge.dst, set()).add(edge.src)
    out: list[dict[str, Any]] = []
    for row in db.query(conn, "SELECT id, mac, ip, hostname, nickname, kind FROM devices ORDER BY id"):
        device_id = int(row["id"])
        node_id = f"device:{device_id}"
        count = int(counts.get(node_id, 0))
        outage_count = int(triggered.get(device_id, 0))
        consumers: set[str] = set()
        for provider_id in hosted_on.get(node_id, ()):
            consumers |= users_of.get(provider_id, set())
        if not count and not outage_count:
            continue
        weight = count + (5 if outage_count >= 2 else 2 if outage_count else 0) + (3 if consumers else 0)
        out.append({
            "device_id": device_id,
            "label": infer.display_name(row),
            "dependents": count,
            "weight": weight,
            "why": _why_critical(count, outage_count, len(consumers), str(row["kind"] or "")),
        })
    out.sort(key=lambda item: (-item["weight"], -item["dependents"], item["device_id"]))
    return out


def _why_critical(count: int, outage_count: int, consumers: int, kind: str) -> str:
    bits: list[str] = []
    if count:
        bits.append(f"{count} device{'s' if count != 1 else ''} depend{'s' if count == 1 else ''} on it")
    if consumers:
        bits.append(f"{consumers} confirmed consumer{'s' if consumers != 1 else ''} of a service it offers")
    if outage_count:
        bits.append(f"it dropped with other devices in {outage_count} recorded outage{'s' if outage_count != 1 else ''}")
    if not bits:
        bits.append("nothing else is known to depend on it")
    if kind in ("router", "gateway"):
        bits.insert(0, "it is the way off the local network")
    return "; ".join(bits).capitalize()


# ----------------------------------------------------------------- blast radius


def blast_radius(conn: sqlite3.Connection, device_id: int, *, hours: int = 168,
                 graph: tuple[list[Node], list[Edge]] | None = None) -> dict[str, Any]:
    """What stops working when this device fails.

    Classification follows C4 exactly, and the distinction matters more than it looks:

    * the **gateway** failing *degrades* every device that reached the internet through it —
      they are still on the LAN, still reachable, still able to talk to each other. Calling
      them "offline" would be wrong, and would be the kind of wrong that makes a user stop
      believing the rest of the picture;
    * a **service** failing degrades its *confirmed* consumers — never the devices that might
      plausibly have used it;
    * **offline** is reserved for devices that genuinely become unreachable, which on a flat
      home network means hub children and the Wi-Fi clients of a failed access point — and is
      only claimed here when recorded outages show it happening.

    ``graph`` is the ``(nodes, edges)`` a caller already built — /devices/<id> renders the map
    payload and this radius on one request — so the page pays for one build rather than three.
    """
    from homesoc.topology import infer, outages as outages_mod

    try:
        device_id = int(device_id)
    except (TypeError, ValueError):
        return {}
    if not (0 < device_id <= 2**63 - 1):
        return {}
    row = db.one(conn, "SELECT id, mac, ip, hostname, nickname, vendor, kind, online FROM devices WHERE id = ?", (device_id,))
    if row is None:
        return {}

    nodes, edges = graph if graph is not None else build_graph(conn, hours=hours, include_cloud=True)
    by_id = {n.id: n for n in nodes}
    node_id = f"device:{device_id}"
    name = infer.display_name(row)
    is_gateway = any(e.src == node_id and e.edge_type == "internet" for e in edges)

    degraded: dict[int, dict[str, Any]] = {}
    offline: dict[int, dict[str, Any]] = {}
    services_lost: list[str] = []
    used_confidence: set[str] = set()

    # 1. The gateway: everything that routes through it loses the internet, nothing more.
    if is_gateway:
        # Devices that have been *seen* using the internet (a DNS query, a cloud lookup) versus
        # devices that merely have a route through it. Both are degraded — the spec is explicit
        # that a gateway failure degrades rather than offlines — but only the first group is
        # something Home SOC has watched happen, and the wording says so.
        seen_using = {e.src for e in edges if e.edge_type in ("dns", "cloud")}
        losers = [e for e in edges if e.edge_type == "gateway" and e.dst == node_id]
        for edge in sorted(losers, key=lambda e: e.src):
            other = by_id.get(edge.src)
            if other is None or other.device_id is None:
                continue
            degraded[other.device_id] = {
                "device_id": other.device_id, "label": other.label,
                "why": ("loses its internet connection; it stays on the local network and can still reach devices here"
                        if edge.src in seen_using else
                        "loses its route to the internet, though it has never been seen using it; it stays on the "
                        "local network"),
            }
            used_confidence.add(edge.confidence)
        if losers:
            services_lost.append(f"internet access for {len(degraded)} device{'s' if len(degraded) != 1 else ''}")
        dns_users = {e.src for e in edges if e.edge_type == "dns"}
        if dns_users and any(e.src == RESOLVER_ID and e.edge_type == "internet" for e in edges):
            services_lost.append(f"DNS for {len(dns_users)} device{'s' if len(dns_users) != 1 else ''}")

    # 2. Services this device hosts: their *confirmed* consumers degrade. A provider with no
    #    confirmed consumers is still a service lost — it is simply not attributed to anyone.
    phrases = {p.node_id: p.phrase for p in infer.providers(conn)}
    hosted = sorted([e for e in edges if e.edge_type == "hosted_by" and e.dst == node_id], key=lambda e: e.src)
    for edge in hosted:
        provider = by_id.get(edge.src)
        if provider is None:
            continue
        phrase = phrases.get(provider.id, "the hub it runs" if provider.id.endswith(":hub") else provider.label)
        consumers = sorted([c for c in edges if c.edge_type == "uses" and c.dst == provider.id], key=lambda e: e.src)
        for consumer in consumers:
            other = by_id.get(consumer.src)
            if other is None or other.device_id is None or other.device_id == device_id:
                continue
            used_confidence.add(consumer.confidence)
            if other.device_id in degraded:
                degraded[other.device_id]["why"] += f"; also loses {phrase}"
            else:
                degraded[other.device_id] = {
                    "device_id": other.device_id, "label": other.label,
                    "why": f"loses {phrase}",
                }
        if consumers:
            services_lost.append(f"{phrase} for {len(consumers)} device{'s' if len(consumers) != 1 else ''}")
        else:
            services_lost.append(f"{phrase} (no confirmed consumers)")

    # 3. Devices recorded dropping with this one, and only from outages it triggered.
    #    Skipped for the gateway: the gateway rule above already classified those devices, and
    #    a gateway outage does not make its clients unreachable to each other.
    observed = outages_mod.observed_blast_radius(conn, device_id)
    if int(observed.get("triggered") or 0):
        # Home SOC has watched this exact device fail and take others with it. The *classification*
        # above may still be inference (the gateway rule is), but the underlying claim — that this
        # device failing is a real event with a real radius — is observed, and the confidence must
        # say so rather than under-selling the one piece of hard evidence in the payload.
        used_confidence.add("observed")
    if not is_gateway:
        # ``co_members_triggered``, never ``co_members``: the latter is every device that dropped
        # in the same cycle for *any* reason, so a printer that merely went down alongside the
        # router would be reported — at "observed" confidence — as taking the router offline.
        #
        # And a co-drop lands in ``degraded``, not ``offline``, unless the failing box is
        # something whose failure genuinely severs a path: a hub, an access point or a switch
        # (C4 — "``offline`` is reserved for devices that genuinely become unreachable, which on
        # a flat home network is mostly hub children and Wi-Fi clients of a failed AP"). A NAS
        # going down does not make a laptop unreachable, however many times they have gone dark
        # together; the honest reading of that pair is shared fate of an unestablished cause,
        # which might just as easily be one power strip.
        severs = _severs_the_path(conn, row, device_id)
        for member in observed.get("co_members_triggered", []):
            other_id = int(member["device_id"])
            if other_id == device_id or other_id in degraded or other_id in offline:
                continue
            if member["probability"] < CO_DROP_CONFIRMED or member["together"] < CO_DROP_MIN_OUTAGES:
                continue
            times = f"{member['together']} recorded outage{'s' if member['together'] != 1 else ''}"
            if severs:
                offline[other_id] = {
                    "device_id": other_id, "label": member["label"],
                    "why": f"reaches the network through this device, and went offline in the same "
                           f"discovery cycle as it in {times}",
                }
            else:
                degraded[other_id] = {
                    "device_id": other_id, "label": member["label"],
                    "why": f"dropped in the same discovery cycle as this device in {times}; what "
                           "connects them has not been established — they may share power or a switch",
                }
            used_confidence.add("observed")

    affected = set(degraded) | set(offline) | {device_id}
    unaffected = [
        {"device_id": int(n.device_id), "label": n.label}
        for n in nodes
        if n.kind == "device" and n.device_id is not None and int(n.device_id) not in affected
    ]

    if not services_lost and not degraded and not offline:
        services_lost = []
    confidence = _mixed_confidence(used_confidence)
    return {
        "device": {
            "id": device_id, "label": name, "ip": row["ip"], "mac": row["mac"],
            "kind": row["kind"], "online": bool(row["online"]), "is_gateway": is_gateway,
        },
        "offline": sorted(offline.values(), key=lambda d: d["label"].lower()),
        "degraded": sorted(degraded.values(), key=lambda d: d["label"].lower()),
        "unaffected": sorted(unaffected, key=lambda d: d["label"].lower()),
        "services_lost": _dedupe_keep_order(services_lost),
        "headline": headline(_spoken_name(row, name), is_gateway, len(degraded), len(offline), len(unaffected), services_lost),
        "confidence": confidence,
        # Only outages this device actually headed may speak for its blast radius. A device that
        # was merely caught in three gateway outages has an evidence slot that must stay empty,
        # so the UI prints "nothing like this has actually been recorded" instead of a sentence
        # about four devices going down — under a headline that says nothing is known to break.
        # ``observed_blast_radius`` already returns None here; the guard is belt and braces.
        "evidence": observed.get("evidence") if int(observed.get("triggered") or 0) else None,
        "resolution": observed.get("resolution") if int(observed.get("triggered") or 0) else None,
        # The cadence recorded with those outages, so a consumer can state the resolution itself
        # rather than recomputing one from whatever the config says today.
        "cycle_seconds": observed.get("cycle_seconds") if int(observed.get("triggered") or 0) else None,
    }


def _severs_the_path(conn: sqlite3.Connection, row: Any, device_id: int) -> bool:
    """True when this device failing is a reason another device becomes *unreachable*.

    A hub's children are not on the IP network at all, and an access point or a switch is the
    physical path its clients arrive on. Everything else on a flat home network keeps its link
    when a peer dies — which is why C4 reserves ``offline`` for exactly these cases.
    """
    from homesoc.topology import infer

    if str(row["kind"] or "").lower() in ("ap", "access_point", "switch"):
        return True
    hub_row = db.one(conn, "SELECT id, hostname, nickname, vendor, mdns_services FROM devices WHERE id = ?",
                     (int(device_id),))
    return hub_row is not None and infer.is_hub(hub_row)


def _mixed_confidence(used: set[str]) -> str:
    if not used:
        return "inferred"
    if used == {"observed"}:
        return "observed"
    if "observed" in used:
        return "mixed"
    return "inferred" if "inferred" in used else "assumed"


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


_KIND_NOUN: dict[str, str] = {
    "router": "router", "gateway": "router", "camera": "camera", "printer": "printer", "phone": "phone",
    "tablet": "tablet", "tv": "TV", "speaker": "speaker", "computer": "computer", "laptop": "laptop",
    "pc": "computer", "iot": "smart device", "console": "games console", "nas": "network storage",
}


def _spoken_name(row: Any, name: str) -> str:
    """The name for a sentence: a device with no nickname or hostname is "the unnamed camera
    (192.168.1.142)", never a bare address standing in for a name."""
    from homesoc.topology import infer  # local: infer imports this module

    try:
        named = any(infer.clean_text(row[k]) for k in ("nickname", "hostname"))
        kind = str(row["kind"] or "").strip().lower()
        ip = infer.clean_text(row["ip"])
    except (KeyError, IndexError, TypeError):
        return name
    if named:
        return name
    noun = _KIND_NOUN.get(kind, "device")
    return f"the unnamed {noun} ({ip})" if ip else f"the unnamed {noun}"


def headline(name: str, is_gateway: bool, degraded: int, offline: int, unaffected: int, services_lost: list[str]) -> str:
    """One plain sentence in the voice of the findings catalogue.

    No jargon, no counts the data cannot support, and never a claim that a device goes
    offline when what actually happens is that it loses the internet.
    """
    name = name.strip() or "this device"
    if is_gateway and degraded:
        second = ""
        if unaffected:
            second = (f" {_count_words(unaffected).capitalize()} "
                      f"{_verb(unaffected, 'keeps', 'keep')} working on the local network.")
        return (f"If {name} fails, {_count_words(degraded)} {_verb(degraded, 'loses', 'lose')} "
                f"{_possessive(degraded)} internet connection. "
                f"{_pronoun(degraded)} {_verb(degraded, 'stays', 'stay')} on the local network and can still "
                f"reach {'the others' if degraded != 1 else 'other devices here'}.{second}")
    if offline and degraded:
        return (f"If {name} fails, {_count_words(offline)} {_verb(offline, 'goes', 'go')} offline and "
                f"{_count_words(degraded)} {_verb(degraded, 'loses', 'lose')} a service, "
                "based on what has been recorded.")
    if offline:
        return (f"If {name} fails, {_count_words(offline)} {_verb(offline, 'goes', 'go')} offline with it, "
                "based on what has been recorded.")
    if degraded:
        # Only a service with *confirmed* consumers is named here. ``services_lost`` also carries
        # the ones nobody has been seen using, worded "(no confirmed consumers)" — naming one of
        # those would tell the reader that two devices lose AirPlay in the same breath as the
        # list below tells them nothing has ever been seen using it.
        attributed = [s for s in services_lost if " for " in s]
        if attributed:
            return (f"If {name} fails, {_count_words(degraded)} {_verb(degraded, 'loses', 'lose')} "
                    f"{attributed[0].split(' for ')[0]}. Everything else keeps working.")
        # Degraded without a named service means the only evidence is shared fate: these went
        # dark in the same sweep, and what connects them was never established.
        return (f"If {name} fails, {_count_words(degraded)} may be affected: "
                f"{_verb(degraded, 'it has', 'they have')} been recorded going offline in the same "
                "discovery cycle as it, though what connects them is not known.")
    if services_lost:
        return (f"If {name} fails, the network loses {services_lost[0].split(' (')[0]}, but nothing has been "
                "seen using it, so no other device is known to be affected.")
    return f"If {name} fails, nothing else on the network is known to stop working — only {name} itself goes offline."


def _count_words(count: int) -> str:
    return "1 device" if count == 1 else f"{count} devices"


# A two-device house is not an exotic case — it is every new install on day one — and
# "1 device lose their internet connection" is the first sentence it reads.
def _verb(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def _pronoun(count: int) -> str:
    return "It" if count == 1 else "They"


def _possessive(count: int) -> str:
    return "its" if count == 1 else "their"


# ---------------------------------------------------------------------- refresh


def refresh(conn: sqlite3.Connection, *, hours: int = 168, include_cloud: bool = True) -> dict[str, Any]:
    """Recompute the graph and write it to ``dep_edges``; called by the ``topology`` job.

    ``dep_edges`` is a cache and nothing else reads it to make a decision, so this is safe to
    run at any time and safe to skip: deleting every row and calling refresh() again restores
    exactly the same table (``tests/test_topology.py::test_dep_edges_cache_rebuilds_after_delete``).
    ``first_seen`` on an existing row is preserved, because "we have believed this since
    Tuesday" is the one piece of information the rebuild cannot recover.
    """
    nodes, edges = build_graph(conn, hours=hours, include_cloud=include_cloud)
    return store(conn, nodes, edges, hours=hours)


def store(conn: sqlite3.Connection, nodes: list[Node], edges: list[Edge], *, hours: int = 168) -> dict[str, Any]:
    """Write a graph the caller already built to ``dep_edges`` (the second half of :func:`refresh`).

    Split out so the topology job can build the graph once and hand the same edges to
    :func:`criticality`, instead of paying for a second full build under the write lock.
    """
    now = utcnow_iso()
    existing = {
        (str(r["src"]), str(r["dst"]), str(r["edge_type"])): str(r["first_seen"])
        for r in db.query(conn, "SELECT src, dst, edge_type, first_seen FROM dep_edges")
    }
    with db.transaction(conn) as tx:
        tx.execute("DELETE FROM dep_edges")
        tx.executemany(
            "INSERT INTO dep_edges(src, dst, edge_type, protocol, confidence, evidence, observed_count, "
            "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (e.src, e.dst, e.edge_type, e.protocol, e.confidence, e.evidence, int(e.observed_count),
                 existing.get(e.key, now), now)
                for e in edges
            ],
        )
    counts: dict[str, int] = {}
    for edge in edges:
        counts[edge.confidence] = counts.get(edge.confidence, 0) + 1
    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "by_confidence": {c: counts.get(c, 0) for c in CONFIDENCES},
        "generated_at": now,
        "hours": int(hours),
    }


def stored_edges(conn: sqlite3.Connection) -> list[Edge]:
    """The cached graph, for a reader that does not want to pay for a rebuild."""
    return [
        Edge(str(r["src"]), str(r["dst"]), str(r["edge_type"]), r["protocol"], str(r["confidence"]),
             str(r["evidence"] or ""), int(r["observed_count"] or 0))
        for r in db.query(conn, "SELECT * FROM dep_edges ORDER BY src, dst, edge_type")
    ]


#: The honest note every surface that shows this graph must carry (C7).
NOTE = (
    "Home SOC cannot see traffic between devices — it has no packet visibility. These links are "
    "what it has observed or can reasonably infer."
)

#: One line per confidence value, for the map legend.
LEGEND: tuple[tuple[str, str], ...] = (
    ("observed", "Home SOC saw this happen — a DNS query, an advertisement, or devices dropping together."),
    ("inferred", "Follows from the shape of the network, such as every device reaching the internet through the router."),
    ("assumed", "A reasonable default that has not been confirmed."),
)


__all__ = [
    "CONFIDENCES", "CONFIDENCE_RANK", "NODE_KINDS", "EDGE_TYPES", "DEPENDENCY_EDGE_TYPES",
    "INTERNET_ID", "RESOLVER_ID", "NOTE", "LEGEND",
    "Node", "Edge",
    "build_graph", "criticality", "blast_radius", "refresh", "store", "stored_edges", "dependents", "headline",
]
