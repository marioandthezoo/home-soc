"""Security round two: regressions for the dependency map and outage detection.

Each test encodes an exploit a malicious or compromised LAN device could run against the
topology package and asserts it no longer works:

* MAC churn inflating the dependency graph until every build (map, overview, Lens, the
  topology job) cost minutes of CPU — graph.py rebuilt the reverse map once per node;
* MAC churn inflating outage detection's dense cycles x devices presence matrix toward
  gigabytes inside the resolver's process;
* forged-source DNS queries planting a NET-DEP-003 finding, worded as fact, on another
  household device — with a markup-bearing qname as the "domain".

Everything runs on in-memory databases. No traffic is sent anywhere.
"""

from __future__ import annotations

import random
import sqlite3
import time
import tracemalloc
from datetime import datetime, timedelta, timezone

import pytest

from homesoc import config, db
from homesoc.topology import graph, infer, outages
from homesoc.topology import run as topology_run
from homesoc.topology.graph import EDGE_TYPES, Edge
from homesoc.util import to_iso

START = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------- seeding


def add_device(conn: sqlite3.Connection, device_id: int, *, ip: str, kind: str | None = None,
               nickname: str | None = None, hostname: str | None = None, online: int = 1) -> None:
    stamp = to_iso(START)
    db.write(
        conn,
        "INSERT INTO devices(id, mac, ip, hostname, kind, nickname, first_seen, last_seen, online) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (device_id, "02:00:%02x:%02x:%02x:%02x" % ((device_id >> 24) & 255, (device_id >> 16) & 255,
                                                  (device_id >> 8) & 255, device_id & 255),
         ip, hostname, kind, nickname, stamp, stamp, online),
    )


def small_house(conn: sqlite3.Connection) -> None:
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", hostname="gateway", nickname="Home router", kind="router")
    add_device(conn, 2, ip="192.168.1.20", nickname="Laptop", kind="computer")
    add_device(conn, 3, ip="192.168.1.30", nickname="Phone", kind="phone")
    add_device(conn, 5, ip="192.168.1.60", nickname="Doorbell", kind="camera")


def churn(conn: sqlite3.Connection, count: int, *, first_id: int = 1000) -> None:
    """The finding's attack: many offline identities, each seen once and then querying six
    unique, answered domains five times each an hour later, rotating through 200 addresses."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=160)
    step = timedelta(hours=150) / max(1, count)
    devices, sightings, queries = [], [], []
    for i in range(count):
        device_id = first_id + i
        seen = start + step * i
        ip = f"192.168.1.{(i % 200) + 40}"
        devices.append((device_id, "02:aa:%02x:%02x:%02x:%02x" % ((i >> 24) & 255, (i >> 16) & 255,
                                                                  (i >> 8) & 255, i & 255),
                        ip, to_iso(seen), to_iso(seen)))
        sightings.append((device_id, ip, to_iso(seen), "arp"))
        asked = to_iso(seen + timedelta(hours=1, minutes=1))
        for k in range(6):
            queries.extend([(asked, ip, f"x{i}k{k}.com", "A", "allow")] * 5)
    db.writemany(conn, "INSERT INTO devices(id, mac, ip, first_seen, last_seen, online) VALUES (?,?,?,?,?,0)", devices)
    db.writemany(conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,?)", sightings)
    db.writemany(conn, "INSERT INTO dns_queries(ts, client, qname, qtype, action) VALUES (?,?,?,?,?)", queries)


# ------------------------------------------------------ 1. quadratic graph build


def _reference_counts(edges: list[Edge]) -> dict[str, int]:
    """The old definition, straight from dependents(): the thing the fast path must equal."""
    reverse = graph._reverse_adjacency(edges)
    return {
        node_id: sum(1 for d in graph.dependents(edges, node_id, reverse=reverse) if d.startswith("device:"))
        for node_id in reverse
    }


@pytest.mark.parametrize("seed", range(40))
def test_dependent_counts_equal_the_per_node_traversal(seed: int) -> None:
    """The one-pass count must agree with a traversal from every node, cycles and all."""
    rng = random.Random(seed)
    names = ([f"device:{i}" for i in range(rng.randint(1, 25))]
             + [f"provider:{i}:x" for i in range(rng.randint(0, 6))]
             + [f"cloud:c{i}.com" for i in range(rng.randint(0, 8))]
             + ["internet", "resolver"])
    edges = []
    for _ in range(rng.randint(0, 90)):
        src, dst = rng.choice(names), rng.choice(names)
        edges.append(Edge(src, dst, rng.choice(EDGE_TYPES), None, "observed", "", 0))
    assert graph._dependent_counts(edges) == _reference_counts(edges)


def test_dependent_counts_handle_a_dependency_cycle() -> None:
    edges = [
        Edge("device:1", "device:2", "uses", None, "observed", "", 0),
        Edge("device:2", "device:3", "uses", None, "observed", "", 0),
        Edge("device:3", "device:1", "uses", None, "observed", "", 0),
        Edge("device:4", "device:1", "gateway", None, "inferred", "", 0),
        Edge("device:1", "internet", "internet", None, "inferred", "", 0),
        Edge("device:4", "cloud:x.com", "cloud_blocked", None, "observed", "", 0),  # not a dependency
    ]
    counts = graph._dependent_counts(edges)
    assert counts == {"device:1": 3, "device:2": 3, "device:3": 3, "internet": 4}
    assert counts == _reference_counts(edges)


def test_a_churned_graph_builds_without_per_node_rebuilds(memory_conn: sqlite3.Connection,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    """The exploit: 600 churned identities made build_graph ~20 s, and 1600 made it 103 s,
    because _reverse_adjacency ran once per target node (O(targets x edges)), twice per build."""
    small_house(memory_conn)
    churn(memory_conn, 600)
    calls = {"reverse": 0, "dependents": 0}
    real_reverse, real_dependents = graph._reverse_adjacency, graph.dependents

    def counting_reverse(edges):
        calls["reverse"] += 1
        return real_reverse(edges)

    def counting_dependents(*args, **kwargs):
        calls["dependents"] += 1
        return real_dependents(*args, **kwargs)

    monkeypatch.setattr(graph, "_reverse_adjacency", counting_reverse)
    monkeypatch.setattr(graph, "dependents", counting_dependents)
    started = time.monotonic()
    nodes, edges = graph.build_graph(memory_conn, hours=168, include_cloud=True)
    ranked = graph.criticality(memory_conn, edges=edges)
    elapsed = time.monotonic() - started
    assert sum(1 for n in nodes if n.kind == "cloud") >= 600 * 6  # the attack really was in the graph
    # One reverse map per counting pass (support nodes, device nodes, criticality) — not one per node.
    assert calls["reverse"] <= 3
    assert calls["dependents"] == 0
    assert elapsed < 10, f"graph build took {elapsed:.1f}s for 600 churned identities"
    # And nothing changed about what the map says: the gateway still carries every device.
    gateway = next(item for item in ranked if item["device_id"] == 1)
    assert gateway["dependents"] == len([n for n in nodes if n.kind == "device"]) - 1


def test_criticality_matches_the_traversal_it_replaced(memory_conn: sqlite3.Connection) -> None:
    small_house(memory_conn)
    churn(memory_conn, 40)
    _nodes, edges = graph.build_graph(memory_conn, hours=168, include_cloud=True)
    ranked = graph.criticality(memory_conn, edges=edges)
    dependency = [e for e in edges if e.edge_type not in ("cloud", "cloud_blocked")]
    for item in ranked:
        expected = [d for d in graph.dependents(dependency, f"device:{item['device_id']}") if d.startswith("device:")]
        assert item["dependents"] == len(expected)
    # criticality() without a graph (its own include_cloud=False build) gives the same ranking.
    assert graph.criticality(memory_conn) == ranked


def test_the_topology_job_builds_the_graph_once(memory_conn: sqlite3.Connection,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    import homesoc.topology as topology

    small_house(memory_conn)
    builds = {"n": 0}
    real = graph.build_graph

    def counting(*args, **kwargs):
        builds["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(graph, "build_graph", counting)
    monkeypatch.setattr(topology, "build_graph", counting)
    result = topology_run(config.load(memory_conn), memory_conn)
    assert result.error is None
    assert builds["n"] == 1
    assert result.summary["edges"] == db.one(memory_conn, "SELECT COUNT(*) AS n FROM dep_edges")["n"]


@pytest.mark.parametrize("seed", range(20))
def test_address_owner_lookup_matches_the_linear_scan(seed: int) -> None:
    """owner_at now bisects a cached index; it must answer exactly what the per-row scan did."""
    rng = random.Random(seed)
    stamps = sorted({f"2026-09-{rng.randint(1, 20):02d}T{rng.randint(0, 23):02d}" for _ in range(30)})
    runs = []
    for device_id in range(rng.randint(2, 12)):
        a, b = sorted(rng.sample(stamps, 2))
        runs.append((a, b, device_id))
    runs.sort()
    owners = infer.AddressOwners(spans={"10.0.0.9": runs}, current={"10.0.0.9": 99})

    def linear(ts: str) -> int | None:
        if infer._overlapping(runs):
            return None
        for index in range(len(runs) - 1, -1, -1):
            if runs[index][0] <= ts:
                return runs[index][2]
        return None

    for probe in stamps + ["2026-08-31T00", "2026-09-30T23"]:
        assert owners.owner_at("10.0.0.9", probe) == linear(probe)


# ------------------------------------------------- 2. dense outage presence matrix


def _dense_detect(conn: sqlite3.Connection, min_members: int = 3) -> list[tuple]:
    """detect_outages as it was: the dense presence matrix, evaluated cycle by cycle."""
    interval = outages.discovery_interval_seconds(conn)
    cycles = outages.discovery_cycles(conn, interval_seconds=interval)
    if len(cycles) < outages.MIN_HISTORY_CYCLES + 1:
        return []
    present = outages.presence(cycles, outages.device_tolerances(cycles, 2 * interval))
    baselines = outages.device_baselines(cycles, present)
    first_seen: dict[int, int] = {}
    for cycle in cycles:
        for device_id in cycle.seen:
            first_seen.setdefault(device_id, cycle.index)
    kinds = outages._device_kinds(conn)
    gateway_id = outages._gateway_device_id(conn)
    found = []
    for index in range(1, len(cycles)):
        droppers = []
        for device_id, is_present in sorted(present[index].items()):
            if is_present or not present[index - 1].get(device_id):
                continue
            if index - first_seen.get(device_id, index) < outages.MIN_HISTORY_CYCLES:
                continue
            baseline = baselines.get(device_id)
            if baseline is not None and baseline.is_routine(cycles[index].hour):
                continue
            droppers.append(device_id)
        if len(droppers) < max(2, min_members):
            continue
        found.append((cycles[index].started_at, outages._ended_at(cycles, present, droppers, index),
                      outages.measured_cycle_seconds(cycles, index, interval), sorted(droppers),
                      outages._classify_trigger(droppers, kinds, gateway_id)))
    return found


def _random_history(conn: sqlite3.Connection, rng: random.Random) -> None:
    """A week of 30-minute sweeps with commuters, flaky devices, sparse devices, late joiners,
    leavers, jittered sweep times and a few genuine group drops."""
    interval = 1800
    db.set_setting(conn, "schedule.discovery_minutes", str(interval // 60))
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    total = 7 * 48
    device_count = rng.randint(4, 12)
    for device_id in range(1, device_count + 1):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}",
                   kind=rng.choice(["router", "nas", "phone", "computer", "ap", None]))
    behaviour = {d: rng.choice(["steady", "commuter", "flaky", "sparse", "late", "leaver"])
                 for d in range(1, device_count + 1)}
    group_drops = [(rng.randrange(10, total - 5), rng.randint(1, 4)) for _ in range(rng.randint(0, 6))]
    group = set(rng.sample(range(1, device_count + 1), k=min(device_count, rng.randint(2, 6))))
    joins = {d: rng.randrange(0, total // 2) for d in behaviour}
    leaves = {d: rng.randrange(total // 2, total) for d in behaviour}
    rows = []
    for index in range(total):
        stamp = to_iso(START + timedelta(seconds=index * interval + rng.randint(-240, 240)))
        hour = (index * interval // 3600) % 24
        for device_id, kind in behaviour.items():
            if kind == "commuter" and (hour >= 18 or hour < 7) and rng.random() < 0.9:
                continue
            if kind == "flaky" and rng.random() < 0.3:
                continue
            if kind == "sparse" and index % 3:
                continue
            if kind == "late" and index < joins[device_id]:
                continue
            if kind == "leaver" and index > leaves[device_id]:
                continue
            if device_id in group and any(at <= index < at + span for at, span in group_drops):
                continue
            rows.append((device_id, f"192.168.1.{device_id}", stamp, "arp"))
    db.writemany(conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,?)", rows)


@pytest.mark.parametrize("seed", range(25))
def test_sparse_detection_equals_the_dense_matrix(memory_conn: sqlite3.Connection, seed: int) -> None:
    rng = random.Random(seed)
    _random_history(memory_conn, rng)
    interval = outages.discovery_interval_seconds(memory_conn)
    cycles = outages.discovery_cycles(memory_conn, interval_seconds=interval)
    tolerances = outages.device_tolerances(cycles, 2 * interval)
    present = outages.presence(cycles, tolerances)

    # The sparse tracks describe exactly the dense matrix...
    tracks = outages.absence_tracks(cycles, tolerances)
    for device_id, track in tracks.items():
        absent = {i for start, stop in track.absences for i in range(start, stop)}
        for position, state in enumerate(present):
            expected = bool(state[device_id])
            assert (position >= track.first and position not in absent) == expected, (device_id, position)
    # ...the baselines built from them are the dense baselines...
    dense = outages.device_baselines(cycles, present)
    index = outages._BaselineIndex(cycles)
    assert {d: index.baseline(t) for d, t in tracks.items()} == dense
    # ...and detection finds the same outages.
    got = [(o.started_at, o.ended_at, o.cycle_seconds, o.members, (o.trigger_device_id, o.trigger_kind))
           for o in outages.detect_outages(memory_conn, min_members=2)]
    assert got == _dense_detect(memory_conn, min_members=2)


def test_mac_churn_does_not_build_a_dense_presence_matrix(memory_conn: sqlite3.Connection,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    """The exploit: identities minted at discovery's caps (32 a sweep, 256 a day), each seen once,
    cost one matrix entry per cycle of history — 1.8 GB and 77 s at the 30-day cap."""
    interval = 600
    conn = memory_conn
    db.set_setting(conn, "schedule.discovery_minutes", "10")
    real = list(range(1, 6))
    for device_id in real:
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", kind="router" if device_id == 1 else "phone")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = now - timedelta(days=7)
    cycles = int(timedelta(days=7).total_seconds() // interval)
    rows, fakes, minted = [], [], 0
    per_day: dict[str, int] = {}
    for index in range(cycles):
        stamp = to_iso(start + timedelta(seconds=index * interval))
        rows.extend((d, f"192.168.1.{d}", stamp, "arp") for d in real)
        room = min(32, 256 - per_day.get(stamp[:10], 0))
        for _ in range(max(0, room)):
            device_id = 10_000 + minted
            fakes.append((device_id, "192.168.1.99", stamp, stamp))
            rows.append((device_id, "192.168.1.99", stamp, "arp"))
            per_day[stamp[:10]] = per_day.get(stamp[:10], 0) + 1
            minted += 1
    db.writemany(conn, "INSERT INTO devices(id, mac, ip, first_seen, last_seen, online) VALUES (?,?,?,?,?,0)",
                 [(d, f"02:bb:00:{(d >> 16) & 255:02x}:{(d >> 8) & 255:02x}:{d & 255:02x}", ip, a, b)
                  for d, ip, a, b in fakes])
    db.writemany(conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,?)", rows)
    assert minted >= 1500

    def refuse(*_args, **_kwargs):
        raise AssertionError("detection must not build the dense presence matrix")

    monkeypatch.setattr(outages, "presence", refuse)
    monkeypatch.setattr(outages, "device_baselines", refuse)
    tracemalloc.start()
    try:
        started = time.monotonic()
        found = outages.detect_outages(conn)
        elapsed = time.monotonic() - started
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # Identities minted on the last day have not been gone long enough to look routine, so they
    # may form outages of their own (the dense path found the same); none may involve a real device.
    assert all(member >= 10_000 for outage in found for member in outage.members)
    # The dense matrix was ~1008 cycles x 1800 devices here: well over 100 MB and tens of seconds.
    assert peak < 60 * 1024 * 1024, f"peak {peak / 1e6:.0f} MB"
    assert elapsed < 20, f"detection took {elapsed:.1f}s"


# --------------------------------------- 3. forged-source DNS and hostile qnames


HOSTILE_QNAMES = [
    'x.[router\\032admin](https://evil)<img/src=x>"\'.com',  # dnslib's escaped form of the PoC label
    "x.<script>alert(1)</script>.com",
    "evil.com\\010forged",
    "a" * 300 + ".com",
]


@pytest.mark.parametrize("qname", HOSTILE_QNAMES)
def test_a_markup_qname_is_not_a_domain(qname: str) -> None:
    assert infer.registrable_domain(qname) == ""


@pytest.mark.parametrize("qname, expected", [
    ("www.eu.example.co.uk.", "example.co.uk"),
    ("_dmarc.Example.COM", "example.com"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ("telemetry-collect.cam-vendor.io", "cam-vendor.io"),
    ("localhost", "localhost"),
    ("", ""),
])
def test_real_names_still_resolve_to_their_registrable_domain(qname: str, expected: str) -> None:
    assert infer.registrable_domain(qname) == expected


def _blocked(conn: sqlite3.Connection, client: str, qname: str, *, count: int = 24,
             start: datetime | None = None, spacing_minutes: int = 60) -> None:
    base = start or datetime.now(timezone.utc) - timedelta(hours=count)
    db.writemany(conn, "INSERT INTO dns_queries(ts, client, qname, qtype, action) VALUES (?,?,?,'A','block')",
                 [(to_iso(base + timedelta(minutes=i * spacing_minutes)), client, qname) for i in range(count)])


def test_a_markup_qname_never_becomes_a_cloud_node_or_finding(memory_conn: sqlite3.Connection) -> None:
    small_house(memory_conn)
    qname = HOSTILE_QNAMES[0]
    _blocked(memory_conn, "192.168.1.1", qname)
    db.writemany(memory_conn, "INSERT INTO dns_queries(ts, client, qname, qtype, action) VALUES (?,?,?,'A','allow')",
                 [(to_iso(datetime.now(timezone.utc) - timedelta(hours=2)), "192.168.1.20", qname)] * 10)
    nodes, edges = graph.build_graph(memory_conn, hours=168, include_cloud=True)
    assert not [n for n in nodes if n.kind == "cloud"]
    assert not [e for e in edges if e.edge_type in ("cloud", "cloud_blocked")]
    drafts = [d for d in topology_run(config.load(memory_conn), memory_conn).findings if d.finding_id == "NET-DEP-003"]
    assert drafts == []


def test_net_dep_003_says_the_lookups_came_from_the_address_not_the_device(memory_conn: sqlite3.Connection) -> None:
    """Forged UDP from the router's address used to read 'Home router asked for ... 24 times',
    stated as fact. The resolver only knows the source address, and so must the sentence."""
    small_house(memory_conn)
    _blocked(memory_conn, "192.168.1.1", "ring-firmware-update.example-attacker.com")
    drafts = [d for d in topology_run(config.load(memory_conn), memory_conn).findings if d.finding_id == "NET-DEP-003"]
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.device_id == 1
    assert "Home router asked for" not in (draft.detail or "")
    assert "from Home router's address" in (draft.detail or "")
    assert "forge" in (draft.detail or "")
    assert draft.evidence["attributed_by"] == "source address"
    # The catalogue's placeholders are all still supplied.
    for key in ("domain", "failures", "name", "key"):
        assert draft.evidence[key]


def test_net_dep_003_credits_the_device_that_held_the_lease_at_the_time(memory_conn: sqlite3.Connection) -> None:
    """The finding used the address's *current* holder, so a recycled lease moved one device's
    blocked lookups onto whichever device holds the address today — the same mistake the map's
    AddressOwners timeline already prevents."""
    small_house(memory_conn)
    now = datetime.now(timezone.utc)
    # The phone held .60 two days ago; the doorbell has held it since this morning.
    db.writemany(memory_conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,?)",
                 [(3, "192.168.1.60", to_iso(now - timedelta(hours=h)), "arp") for h in range(48, 20, -1)]
                 + [(5, "192.168.1.60", to_iso(now - timedelta(hours=h)), "arp") for h in range(10, 0, -1)])
    _blocked(memory_conn, "192.168.1.60", "tracker.example", count=30, start=now - timedelta(hours=47),
             spacing_minutes=50)
    drafts = [d for d in topology_run(config.load(memory_conn), memory_conn).findings if d.finding_id == "NET-DEP-003"]
    assert [d.device_id for d in drafts] == [3]
