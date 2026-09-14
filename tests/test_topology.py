"""Dependencies and blast radius (SPEC addendum C9).

The tests that matter most here are the negative ones. This feature's only value is that a
user can trust the picture, so the suite spends more effort proving that Home SOC *does not*
draw an edge it cannot justify — the printer with no confirmed consumers, the device with no
DNS queries, the phone that leaves the house every evening — than on the happy paths.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from homesoc import config, db
from homesoc.models import ScanResult
from homesoc.topology import graph, infer, outages
from homesoc.topology import run as topology_run
from homesoc.util import parse_iso, to_iso

# --------------------------------------------------------------------- seeding

START = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)


def local_date(iso: str) -> str:
    """The date the evidence sentence will print for this UTC stamp.

    Outage dates are rendered in the host's timezone, because every other timestamp on the
    dashboard is (app.js formats with toLocaleString) and because a user checking "3 September"
    against their memory of Tuesday evening has to be able to reconcile the two. The test
    derives the expectation the same way rather than hard-coding a UTC day, so it passes in
    every timezone instead of only in UTC.
    """
    parsed = parse_iso(iso).astimezone()
    return f"{parsed.day} {parsed.strftime('%B')}"


def add_device(conn: sqlite3.Connection, device_id: int, *, mac: str | None = None, ip: str = "192.168.1.10",
               hostname: str | None = None, nickname: str | None = None, kind: str | None = None,
               vendor: str | None = None, mdns: str | None = None, online: int = 1) -> int:
    stamp = to_iso(START)
    db.write(
        conn,
        "INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, first_seen, last_seen, online, "
        "mdns_services) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (device_id, mac or f"00:11:22:33:44:{device_id:02x}", ip, hostname, vendor, kind, nickname,
         stamp, stamp, online, mdns),
    )
    return device_id


def add_service(conn: sqlite3.Connection, device_id: int, port: int, *, proto: str = "tcp",
                state: str = "open", name: str | None = None) -> None:
    stamp = to_iso(START)
    db.write(
        conn,
        "INSERT INTO services(device_id, port, proto, state, name, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
        (device_id, port, proto, state, name, stamp, stamp),
    )


def add_queries(conn: sqlite3.Connection, client: str, qname: str, count: int, *, action: str = "allow",
                start: datetime | None = None, spacing_minutes: int = 30) -> None:
    base = start or (datetime.now(timezone.utc) - timedelta(hours=count * spacing_minutes / 60 + 1))
    db.writemany(
        conn,
        "INSERT INTO dns_queries(ts, client, qname, qtype, action) VALUES (?,?,?,'A',?)",
        [(to_iso(base + timedelta(minutes=i * spacing_minutes)), client, qname, action) for i in range(count)],
    )


def seed_cycles(conn: sqlite3.Connection, device_ids: list[int], *, cycles: int, interval: int = 600,
                start: datetime | None = None, absent: dict[int, set[int]] | None = None) -> None:
    """Write sightings the way ``scanners.discovery`` does: one timestamp shared by the whole run."""
    origin = start or START
    absent = absent or {}
    rows = []
    for index in range(cycles):
        stamp = to_iso(origin + timedelta(seconds=index * interval))
        for device_id in device_ids:
            if index in absent.get(device_id, set()):
                continue
            rows.append((device_id, "192.168.1.%d" % device_id, stamp, "arp"))
    db.writemany(conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,?)", rows)


@pytest.fixture
def house(memory_conn: sqlite3.Connection) -> sqlite3.Connection:
    """A small, realistic house: router, laptop, phone, printer, camera, hub."""
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", hostname="gateway", nickname="Home router", kind="router")
    add_device(conn, 2, ip="192.168.1.20", hostname="laptop", nickname="Laptop", kind="computer")
    add_device(conn, 3, ip="192.168.1.30", hostname="phone", nickname="Phone", kind="phone")
    add_device(conn, 4, ip="192.168.1.50", hostname="epson", nickname="Printer", kind="printer",
               mdns='["_printer._tcp", "_ipp._tcp"]')
    add_service(conn, 4, 9100, name="jetdirect")
    add_device(conn, 5, ip="192.168.1.60", hostname="camera", nickname="Doorbell", kind="camera")
    add_service(conn, 5, 554, name="rtsp")
    add_device(conn, 6, ip="192.168.1.70", hostname="bridge", nickname="Hue bridge", kind="iot",
               mdns='["_hap._tcp"]')
    return conn


# ------------------------------------------------------------------ migration 3


def test_migration_3_creates_the_tables_and_keeps_v2_rows(tmp_path: Path) -> None:
    """C9: migration 3 upgrades a v2 database with rows intact."""
    path = tmp_path / "v2.db"
    old = sqlite3.connect(str(path))
    try:
        for version, ddl in db.MIGRATIONS[:2]:
            old.executescript(ddl)
            old.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (?, '2026-01-01T00:00:00Z')",
                        (version,))
        old.execute(
            "INSERT INTO devices(id, mac, ip, nickname, first_seen, last_seen, online) "
            "VALUES (1, 'aa:bb:cc:dd:ee:ff', '192.168.1.1', 'Old router', '2026-01-01T00:00:00Z', "
            "'2026-01-02T00:00:00Z', 1)")
        old.execute("INSERT INTO lens_tags(code, kind, created_at, created_by) "
                    "VALUES ('hs1:keep', 'sticker', '2026-01-01T00:00:00Z', 'test')")
        old.commit()
    finally:
        old.close()

    conn = db.connect(path)
    try:
        assert db.schema_version(conn) == db.SCHEMA_VERSION == 4
        assert db.one(conn, "SELECT nickname FROM devices WHERE id = 1")["nickname"] == "Old router"
        assert db.one(conn, "SELECT COUNT(*) AS n FROM lens_tags")["n"] == 1
        names = {r["name"] for r in db.query(conn, "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"dep_edges", "outages", "outage_members"} <= names
        # The new tables are usable, including the foreign key into the pre-existing device row.
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_kind, member_count) VALUES (?,600,'gateway',3)",
            ("2026-09-01T00:00:00Z",),
        )
        db.write(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,1,?)",
                 (outage_id, "2026-09-01T00:00:00Z"))
        assert db.one(conn, "SELECT device_id FROM outage_members")["device_id"] == 1
        db.init_schema(conn)  # idempotent
        assert db.one(conn, "SELECT COUNT(*) AS n FROM schema_migrations")["n"] == len(db.MIGRATIONS)
    finally:
        conn.close()


def test_dep_edges_is_a_cache_that_rebuilds_after_deletion(house: sqlite3.Connection) -> None:
    """C5: deleting dep_edges must be harmless, and refresh() must restore it exactly."""
    add_queries(house, "192.168.1.20", "example.com", 30)
    first = graph.refresh(house)
    before = graph.stored_edges(house)
    assert before and first["edges"] == len(before)

    db.write(house, "DELETE FROM dep_edges")
    assert graph.stored_edges(house) == []
    graph.refresh(house)
    after = graph.stored_edges(house)
    assert [e.key for e in after] == [e.key for e in before]
    assert [(e.confidence, e.observed_count) for e in after] == [(e.confidence, e.observed_count) for e in before]


def test_refresh_keeps_first_seen_for_an_edge_it_already_knew(house: sqlite3.Connection) -> None:
    graph.refresh(house)
    db.write(house, "UPDATE dep_edges SET first_seen = '2026-01-01T00:00:00Z'")
    graph.refresh(house)
    assert all(str(r["first_seen"]) == "2026-01-01T00:00:00Z"
               for r in db.query(house, "SELECT first_seen FROM dep_edges"))


# ------------------------------------------------------------- C2 edge rules


def test_gateway_and_internet_edges(house: sqlite3.Connection) -> None:
    """C2.1/C2.2: every device depends on the gateway; only the gateway reaches the internet."""
    _nodes, edges = graph.build_graph(house)
    gateway = [e for e in edges if e.edge_type == "gateway"]
    assert {e.src for e in gateway} == {f"device:{i}" for i in (2, 3, 4, 5, 6)}
    assert all(e.dst == "device:1" and e.confidence == "inferred" for e in gateway)
    internet = [e for e in edges if e.edge_type == "internet"]
    assert [e.src for e in internet] == ["device:1"]


def test_gateway_is_assumed_when_no_route_data_exists(memory_conn: sqlite3.Connection) -> None:
    """C2's `assumed` row: a router we only recognise by its own claim is not an inference."""
    add_device(memory_conn, 1, ip="10.0.0.1", kind="router", nickname="Some router")
    add_device(memory_conn, 2, ip="10.0.0.5", nickname="Laptop")
    _nodes, edges = graph.build_graph(memory_conn)
    gateway = [e for e in edges if e.edge_type == "gateway"]
    assert gateway and all(e.confidence == "assumed" for e in gateway)


def test_dns_edges_are_observed_and_carry_the_query_count(house: sqlite3.Connection) -> None:
    """C2.3, positive half."""
    add_queries(house, "192.168.1.20", "example.com", 12)
    _nodes, edges = graph.build_graph(house)
    dns = [e for e in edges if e.edge_type == "dns"]
    assert [e.src for e in dns] == ["device:2"]
    assert dns[0].confidence == "observed" and dns[0].observed_count == 12
    assert "12 DNS queries" in dns[0].evidence


def test_no_dns_edge_is_invented_for_a_device_that_never_queried(house: sqlite3.Connection) -> None:
    """C2.3, negative half: Home SOC cannot read DHCP options, so it must not claim the phone
    uses the resolver merely because it is on the same subnet."""
    add_queries(house, "192.168.1.20", "example.com", 12)
    _nodes, edges = graph.build_graph(house)
    assert {e.src for e in edges if e.edge_type == "dns"} == {"device:2"}
    assert not [e for e in edges if e.edge_type == "dns" and e.src == "device:3"]


def test_cloud_edges_separate_answered_from_blocked(house: sqlite3.Connection) -> None:
    """C2.4: a blocked domain is recorded, but never as a dependency."""
    add_queries(house, "192.168.1.60", "ring.com", 20)
    add_queries(house, "192.168.1.60", "tracker.example", 20, action="block")
    _nodes, edges = graph.build_graph(house)
    answered = [e for e in edges if e.edge_type == "cloud"]
    blocked = [e for e in edges if e.edge_type == "cloud_blocked"]
    assert [e.dst for e in answered] == ["cloud:ring.com"]
    assert [e.dst for e in blocked] == ["cloud:tracker.example"]
    assert "cloud_blocked" not in graph.DEPENDENCY_EDGE_TYPES
    # ...so a blocked endpoint contributes nothing to what depends on what.
    assert graph.dependents(edges, "cloud:tracker.example") == []


def test_cloud_can_be_switched_off(house: sqlite3.Connection) -> None:
    add_queries(house, "192.168.1.60", "ring.com", 20)
    _nodes, edges = graph.build_graph(house, include_cloud=False)
    assert not [e for e in edges if e.edge_type.startswith("cloud")]


def test_provider_nodes_come_from_advertisements_and_ports(house: sqlite3.Connection) -> None:
    """C2.5, first half."""
    nodes, edges = graph.build_graph(house)
    printer = next(n for n in nodes if n.id == "provider:4:printing")
    assert printer.kind == "provider" and printer.device_id == 4
    hosted = next(e for e in edges if e.src == "provider:4:printing")
    assert (hosted.dst, hosted.edge_type, hosted.confidence) == ("device:4", "hosted_by", "observed")
    assert "advertises _ipp._tcp" in hosted.evidence and "listens on tcp/9100" in hosted.evidence
    # The camera's provider came from a port alone.
    assert any(n.id == "provider:5:camera_stream" for n in nodes)


def test_a_printer_with_no_evidence_of_use_gets_zero_consumer_edges(house: sqlite3.Connection) -> None:
    """C2.5 and C9, the test this whole feature exists for.

    The printer advertises _printer._tcp and listens on 9100. Five other devices are on the
    network and any of them might plausibly print. Home SOC has never seen one do it, so it
    draws a provider node and **nothing else**.
    """
    nodes, edges = graph.build_graph(house)
    printer_node = next(n for n in nodes if n.id == "provider:4:printing")
    assert "no confirmed consumers" in (printer_node.sublabel or "")
    assert printer_node.criticality == 0
    assert [e for e in edges if e.edge_type == "uses"] == []
    assert [e for e in edges if e.dst == "provider:4:printing" and e.edge_type != "hosted_by"] == []
    # And nothing anywhere points from another device to the printer itself.
    assert [e for e in edges if e.dst == "device:4" and e.src.startswith("device:")] == []


def test_a_hub_says_its_children_are_invisible_and_never_counts_them(house: sqlite3.Connection) -> None:
    """C2.6: never imply the child count is known when it is not."""
    assert infer.hub_device_ids(house) == {6}
    nodes, _edges = graph.build_graph(house)
    hub = next(n for n in nodes if n.id == "provider:6:hub")
    assert "invisible to Home SOC" in (hub.sublabel or "")
    assert "unknown" in (hub.sublabel or "")
    assert hub.criticality == 0
    device = next(n for n in nodes if n.id == "device:6")
    assert "hub" in (device.sublabel or "")


def test_a_name_that_merely_contains_a_hint_is_not_a_hub(memory_conn: sqlite3.Connection) -> None:
    """C2.6: a hub node asserts an entire invisible dependency tree, so it needs real evidence.

    "Cambridge Audio" contains "bridge", so a bare substring test declared a music streamer a
    Zigbee hub - and said, at `observed` confidence, that it advertised itself as one. The word
    has to stand on its own, and a name is at best an `assumed` hub: an advertisement is the
    device saying so, a vendor string is not.
    """
    conn = memory_conn
    add_device(conn, 1, ip="192.168.1.10", hostname="cxn-streamer", vendor="Cambridge Audio",
               nickname="Streamer")
    add_device(conn, 2, ip="192.168.1.11", hostname="bondi-lamp", vendor="Bondi Lighting")
    add_device(conn, 3, ip="192.168.1.12", hostname="hue-bridge", mdns='["_hap._tcp"]')
    add_device(conn, 4, ip="192.168.1.13", hostname="smartthings-v3")   # a name, but no broadcast

    assert infer.hub_signal(db.one(conn, "SELECT * FROM devices WHERE id=1")) is None
    assert infer.hub_signal(db.one(conn, "SELECT * FROM devices WHERE id=2")) is None
    assert infer.hub_signal(db.one(conn, "SELECT * FROM devices WHERE id=3")) == "observed"
    assert infer.hub_signal(db.one(conn, "SELECT * FROM devices WHERE id=4")) == "assumed"

    nodes, edges = graph.build_graph(conn)
    assert [n.id for n in nodes if n.id.endswith(":hub")] == ["provider:3:hub", "provider:4:hub"]

    advertised = next(e for e in edges if e.src == "provider:3:hub")
    guessed = next(e for e in edges if e.src == "provider:4:hub")
    assert advertised.confidence == "observed" and "advertises itself" in advertised.evidence
    # The guess never claims a broadcast it did not receive.
    assert guessed.confidence == "assumed"
    assert "advertises" not in guessed.evidence and "nothing it advertised confirms it" in guessed.evidence
    assert "nothing it advertised confirms it" in next(n for n in nodes if n.id == "provider:4:hub").sublabel


def test_a_reused_dhcp_lease_keeps_its_queries_with_the_device_that_made_them(
        memory_conn: sqlite3.Connection) -> None:
    """C2.3/C2.4: attribute a query by when it happened, not by who holds the address today.

    The doorbell held 192.168.1.50 last week and looked up its vendor's cloud 40 times. It has
    since moved, and a guest laptop has the address now. Attributing by current holder gave the
    guest a solid, `observed` dependency on Ring it never had, moved one household member's
    lookup history onto another person's device card, and left the doorbell with no edge at all.
    """
    conn = memory_conn
    now = datetime.now(timezone.utc)
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    db.set_setting(conn, "dns.enabled", "1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.77", nickname="Doorbell")        # moved off .50
    add_device(conn, 3, ip="192.168.1.50", nickname="Guest laptop")    # holds .50 now

    def sight(device_id: int, ip: str, when: datetime) -> None:
        db.write(conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,'arp')",
                 (device_id, ip, to_iso(when)))

    for day in range(8, 2, -1):
        sight(2, "192.168.1.50", now - timedelta(days=day))
    for day in range(2, -1, -1):
        sight(2, "192.168.1.77", now - timedelta(days=day))
    sight(3, "192.168.1.50", now - timedelta(hours=20))
    sight(1, "192.168.1.1", now - timedelta(hours=1))

    add_queries(conn, "192.168.1.50", "api.ring.com", 40, start=now - timedelta(days=6), spacing_minutes=1)

    _nodes, edges = graph.build_graph(conn)
    cloud = [e for e in edges if e.edge_type == "cloud"]
    assert [(e.src, e.dst) for e in cloud] == [("device:2", "cloud:ring.com")]
    assert [e.src for e in edges if e.edge_type == "dns"] == ["device:2"]
    assert not [e for e in edges if e.src == "device:3" and e.edge_type in ("dns", "cloud")]


def test_an_address_two_devices_answered_on_at_once_attributes_nothing(
        memory_conn: sqlite3.Connection) -> None:
    """A missing edge is the documented preference over a wrong one.

    Two devices answering on the same address in interleaved sweeps is a misconfiguration, not
    a lease handover: which of them made a given query cannot be recovered, so neither gets it.
    """
    conn = memory_conn
    now = datetime.now(timezone.utc)
    db.set_setting(conn, "dns.enabled", "1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.60", nickname="One")
    add_device(conn, 3, ip="192.168.1.60", nickname="Two")
    for hours in range(48, 0, -6):
        for device_id in (2, 3):
            db.write(conn, "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES (?,?,?,'arp')",
                     (device_id, "192.168.1.60", to_iso(now - timedelta(hours=hours))))
    add_queries(conn, "192.168.1.60", "example.com", 30, start=now - timedelta(hours=24), spacing_minutes=1)

    _nodes, edges = graph.build_graph(conn)
    assert [e for e in edges if e.edge_type in ("dns", "cloud")] == []


def test_a_device_on_another_subnet_gets_no_gateway_edge(memory_conn: sqlite3.Connection) -> None:
    """C2.1 says "every device on the local subnet", and the subnet is now actually checked.

    A guest-VLAN device at 192.168.2.x used to be drawn depending on the 192.168.1.1 gateway,
    under the sentence "the default route for this subnet" - asserting a shared subnet nothing
    had looked at. Home SOC does not know how that device reaches the internet, and the honest
    picture is the one that does not claim to.
    """
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.20", nickname="Laptop")
    add_device(conn, 3, ip="192.168.2.30", nickname="Guest VLAN tablet")
    add_device(conn, 4, ip="203.0.113.9", nickname="Stale public address")

    _nodes, edges = graph.build_graph(conn)
    assert {e.src for e in edges if e.edge_type == "gateway"} == {"device:2"}


def test_the_internet_node_is_sized_by_what_actually_depends_on_it(
        memory_conn: sqlite3.Connection) -> None:
    """Node.criticality means one thing for every kind of node: devices that depend on it.

    Non-device nodes used to carry a raw inbound-edge tally instead, so the internet - the node
    every device in the house depends on - reported 2 (the gateway and the resolver) and was
    drawn at the minimum radius, under a legend reading "bigger means more depends on it".
    """
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    db.set_setting(conn, "dns.enabled", "1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    for device_id in range(2, 8):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", nickname=f"Device {device_id}")

    nodes, edges = graph.build_graph(conn)
    internet = next(n for n in nodes if n.id == "internet")
    assert internet.criticality == len([d for d in graph.dependents(edges, "internet")
                                        if d.startswith("device:")])
    assert internet.criticality == 7      # every device, through the gateway
    assert internet.criticality >= next(n for n in nodes if n.id == "device:1").criticality


def test_a_wholly_blocked_domain_is_not_something_anything_depends_on(
        house: sqlite3.Connection) -> None:
    """C2.4: the device asked and was told no, which is the opposite of a dependency."""
    add_queries(house, "192.168.1.20", "ads.doubleclick.net", 30, action="block")
    add_queries(house, "192.168.1.30", "ads.doubleclick.net", 30, action="block")
    nodes, _edges = graph.build_graph(house)
    blocked = next(n for n in nodes if n.id == "cloud:doubleclick.net")
    assert blocked.criticality == 0
    assert "blocked by the DNS filter" in (blocked.sublabel or "")


def test_criticality_ignores_the_cloud_column_of_a_handed_in_graph(
        house: sqlite3.Connection) -> None:
    """The reuse that stops a page building the same graph two or three times.

    A caller hands ``criticality`` the graph it just built, whichever way include_cloud went,
    and gets the same ranking as a fresh cloud-free build - so the saving cannot change what
    the overview card says.
    """
    add_queries(house, "192.168.1.20", "example.com", 30)
    _nodes, with_cloud = graph.build_graph(house, include_cloud=True)
    assert graph.criticality(house, edges=with_cloud) == graph.criticality(house)


def test_merge_edges_raises_confidence_for_a_new_evidence_source(house: sqlite3.Connection) -> None:
    """C8: a future flow collector must raise an edge's confidence, not need new structures."""
    inferred = graph.Edge("device:2", "device:1", "gateway", None, "inferred", "the default route", 0)
    observed = graph.Edge("device:2", "device:1", "gateway", "conntrack", "observed", "412 flows seen", 412)
    merged = infer.merge_edges([inferred, observed])
    assert len(merged) == 1
    assert merged[0].confidence == "observed" and merged[0].observed_count == 412
    assert merged[0].protocol == "conntrack"
    assert "412 flows seen" in merged[0].evidence and "the default route" in merged[0].evidence


def test_register_source_is_idempotent_and_feeds_the_graph(house: sqlite3.Connection) -> None:
    def fake_collector(conn, ctx):
        return [graph.Edge("device:3", "device:2", "uses", "smb", "observed", "seen on the wire", 7)]

    original = list(infer.EDGE_SOURCES)
    try:
        infer.register_source("fake_flows", fake_collector)
        infer.register_source("fake_flows", fake_collector)  # replaces, does not duplicate
        assert [n for n, _ in infer.EDGE_SOURCES].count("fake_flows") == 1
        _nodes, edges = graph.build_graph(house)
        assert any(e.src == "device:3" and e.dst == "device:2" and e.confidence == "observed" for e in edges)
    finally:
        infer.EDGE_SOURCES[:] = original


def test_a_broken_edge_source_does_not_take_the_map_down(house: sqlite3.Connection) -> None:
    def explodes(conn, ctx):
        raise RuntimeError("collector on fire")

    original = list(infer.EDGE_SOURCES)
    try:
        infer.register_source("explodes", explodes)
        nodes, edges = graph.build_graph(house)
        assert nodes and edges
    finally:
        infer.EDGE_SOURCES[:] = original


# --------------------------------------------------------------- C3 outages


def test_three_devices_dropping_in_one_cycle_is_an_outage(memory_conn: sqlite3.Connection) -> None:
    conn = memory_conn
    for device_id in range(1, 6):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", kind="router" if device_id == 1 else None)
    gone = set(range(40, 50))
    seed_cycles(conn, [1, 2, 3, 4, 5], cycles=60, interval=600,
                absent={2: gone, 3: gone, 4: gone})

    found = outages.detect_outages(conn, min_members=3)
    assert len(found) == 1
    assert found[0].members == [2, 3, 4]
    assert found[0].ended_at is not None
    assert found[0].trigger_kind == "unknown" and found[0].trigger_device_id is None


def test_an_outage_that_takes_the_gateway_with_it_is_labelled_as_one(memory_conn: sqlite3.Connection) -> None:
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    for device_id in range(1, 6):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", kind="router" if device_id == 1 else None)
    gone = set(range(30, 40))
    seed_cycles(conn, [1, 2, 3, 4, 5], cycles=60, interval=600,
                absent={1: gone, 2: gone, 3: gone, 4: gone})
    found = outages.detect_outages(conn, min_members=3)
    assert len(found) == 1 and found[0].trigger_kind == "gateway" and found[0].trigger_device_id == 1


def test_cycle_seconds_records_the_interval_actually_in_force(memory_conn: sqlite3.Connection) -> None:
    """C3/C9: the honest resolution. The configuration says 10 minutes; the data says 5, because
    that is what it was when these sightings were written. The record must say 5."""
    conn = memory_conn
    db.set_setting(conn, "schedule.discovery_minutes", "10")
    for device_id in range(1, 6):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}")
    gone = set(range(40, 55))
    seed_cycles(conn, [1, 2, 3, 4, 5], cycles=70, interval=300,
                absent={2: gone, 3: gone, 4: gone})
    found = outages.detect_outages(conn, min_members=3)
    assert len(found) == 1
    assert found[0].cycle_seconds == 300
    assert outages.discovery_interval_seconds(conn) == 600  # the config still says otherwise
    note = outages.resolution_note(found[0].cycle_seconds)
    assert "5-minute discovery cycle" in note and "within seconds" in note


def test_a_commuter_phone_leaving_every_evening_is_not_an_outage(memory_conn: sqlite3.Connection) -> None:
    """C3/C9: the false-positive guard, which is what makes this feature usable at all.

    Three phones leave the house at 18:00 every weekday evening and come back at 07:00. Without
    a per-device baseline this produces a confident five-device outage every single evening.
    """
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    for device_id in range(1, 6):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", kind="router" if device_id == 1 else "phone")
    interval, days = 1800, 7
    per_day = 24 * 3600 // interval
    commuters = {}
    for device_id in (2, 3, 4):
        away: set[int] = set()
        for day in range(days):
            for index in range(per_day):
                hour = (index * interval // 3600) % 24
                if hour >= 18 or hour < 7:
                    away.add(day * per_day + index)
        commuters[device_id] = away
    seed_cycles(conn, [1, 2, 3, 4, 5], cycles=days * per_day, interval=interval, absent=commuters)

    cycles = outages.discovery_cycles(conn, interval_seconds=interval)
    present = outages.presence(cycles, outages.device_tolerances(cycles, 2 * interval))
    baselines = outages.device_baselines(cycles, present)
    # The guard fired for the reason it is supposed to: this is normal for these devices.
    assert baselines[2].rate > 0.3
    assert baselines[2].is_routine(19) and baselines[2].is_routine(23)
    assert not baselines[2].is_routine(12)
    assert not baselines[5].is_routine(19)

    assert outages.detect_outages(conn, min_members=3) == []
    assert outages.record_outages(conn) == 0
    assert db.one(conn, "SELECT COUNT(*) AS n FROM outages")["n"] == 0


def test_the_same_phones_dropping_at_an_unusual_hour_is_an_outage(memory_conn: sqlite3.Connection) -> None:
    """The other half of the guard: it must not swallow a real event, only routine ones."""
    conn = memory_conn
    for device_id in range(1, 6):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", kind="phone")
    interval, days = 1800, 7
    per_day = 24 * 3600 // interval
    commuters: dict[int, set[int]] = {}
    for device_id in (2, 3, 4):
        away: set[int] = set()
        for day in range(days):
            for index in range(per_day):
                hour = (index * interval // 3600) % 24
                if hour >= 18 or hour < 7:
                    away.add(day * per_day + index)
        # ...and on day 5 they also all vanish mid-morning, which is not normal for them.
        away.update(range(5 * per_day + 20, 5 * per_day + 28))
        commuters[device_id] = away
    seed_cycles(conn, [1, 2, 3, 4, 5], cycles=days * per_day, interval=interval, absent=commuters)

    found = outages.detect_outages(conn, min_members=3)
    assert len(found) == 1
    assert found[0].members == [2, 3, 4]
    assert "T1" in found[0].started_at  # mid-morning, not the evening departure


def test_record_outages_is_idempotent_and_writes_members(memory_conn: sqlite3.Connection) -> None:
    conn = memory_conn
    for device_id in range(1, 6):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}")
    gone = set(range(40, 50))
    seed_cycles(conn, [1, 2, 3, 4, 5], cycles=60, absent={2: gone, 3: gone, 4: gone})
    assert outages.record_outages(conn) == 1
    assert outages.record_outages(conn) == 0
    assert db.one(conn, "SELECT COUNT(*) AS n FROM outages")["n"] == 1
    assert db.one(conn, "SELECT member_count FROM outages")["member_count"] == 3
    assert db.one(conn, "SELECT COUNT(*) AS n FROM outage_members")["n"] == 3
    stored = outages.stored_outages(conn)
    assert stored[0].members == [2, 3, 4] and stored[0].cycle_seconds == 600


def test_no_outages_from_a_thin_or_empty_history(memory_conn: sqlite3.Connection) -> None:
    assert outages.detect_outages(memory_conn) == []
    add_device(memory_conn, 1, ip="192.168.1.1")
    seed_cycles(memory_conn, [1], cycles=2)
    assert outages.detect_outages(memory_conn) == []


def test_co_drop_matrix_needs_min_outages_before_it_promotes_anything(memory_conn: sqlite3.Connection) -> None:
    """C9: promotion only after `min_outages` — one shared power cut is not a dependency."""
    conn = memory_conn
    for device_id in (1, 2, 3):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}")
    for index, stamp in enumerate(("2026-09-01T00:00:00Z", "2026-09-05T00:00:00Z")):
        outage_id = db.write(
            conn, "INSERT INTO outages(started_at, cycle_seconds, trigger_kind, member_count) VALUES (?,600,'device',3)",
            (stamp,))
        members = [1, 2, 3] if index == 0 else [1, 2]
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in members])

    once = outages.co_drop_matrix(conn, min_outages=1)
    twice = outages.co_drop_matrix(conn, min_outages=2)
    assert once[(1, 3)] == pytest.approx(0.5)   # seen together once out of 1's two outages
    assert (1, 3) not in twice                   # ...and once is not enough
    assert twice[(1, 2)] == pytest.approx(1.0)   # every time device 1 dropped, so did device 2


def test_observed_blast_radius_states_the_resolution(memory_conn: sqlite3.Connection) -> None:
    conn = memory_conn
    for device_id in (1, 2, 3):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", kind="router" if device_id == 1 else None)
    for stamp in ("2026-09-03T04:00:00Z", "2026-09-11T04:00:00Z"):
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'gateway',3)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (1, 2, 3)])

    observed = outages.observed_blast_radius(conn, 1)
    assert observed["outages"] == 2 and observed["triggered"] == 2
    assert observed["dates"] == [local_date("2026-09-03T04:00:00Z"), local_date("2026-09-11T04:00:00Z")]
    # Two *other* devices dropped in each, not three: member_count includes the subject itself.
    assert observed["evidence"] == (
        f"Seen twice: 2 other devices on {local_date('2026-09-03T04:00:00Z')} and 2 other devices on "
        f"{local_date('2026-09-11T04:00:00Z')} went offline in the same 10-minute discovery cycle as this one."
    )
    assert "not \"within seconds\"" in observed["resolution"]
    assert [m["device_id"] for m in observed["co_members"]] == [2, 3]
    assert outages.observed_blast_radius(conn, 2)["triggered"] == 0


# ------------------------------------------------------- C4 blast radius


def test_gateway_failure_degrades_rather_than_offlines(house: sqlite3.Connection) -> None:
    """C4's central classification rule."""
    add_queries(house, "192.168.1.20", "example.com", 30)
    blast = graph.blast_radius(house, 1)
    assert blast["offline"] == []
    assert {d["device_id"] for d in blast["degraded"]} == {2, 3, 4, 5, 6}
    assert all("local network" in d["why"] for d in blast["degraded"])
    assert "lose their internet connection" in blast["headline"]
    assert "stay on the local network" in blast["headline"]
    assert any("internet access for" in s for s in blast["services_lost"])
    assert blast["device"]["is_gateway"] is True
    # Nothing has been watched happening yet, so this is inference and says so.
    assert blast["confidence"] == "inferred" and blast["evidence"] is None

    # Record two outages the router triggered: the classification does not change (the gateway
    # rule still degrades rather than offlines) but the confidence stops under-selling itself.
    for stamp in ("2026-09-09T03:30:00Z", "2026-09-11T03:00:00Z"):
        outage_id = db.write(
            house,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'gateway',4)", (stamp,))
        db.writemany(house, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (1, 2, 3, 4)])
    again = graph.blast_radius(house, 1)
    assert again["offline"] == [] and len(again["degraded"]) == 5
    assert again["confidence"] == "mixed"
    assert again["evidence"].startswith("Seen twice: 3 other devices on "
                                        + local_date("2026-09-09T03:30:00Z"))
    assert "10-minute discovery cycle" in again["resolution"]


def test_confirmed_consumers_degrade_and_unconfirmed_ones_do_not(memory_conn: sqlite3.Connection) -> None:
    """C4: a device failing degrades its *confirmed* consumers. The confirmation here is two
    recorded outages that this device triggered, which is the only evidence C2.5 allows today."""
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.10", kind="nas", nickname="NAS", mdns='["_smb._tcp"]')
    add_device(conn, 3, ip="192.168.1.20", nickname="Laptop")
    add_device(conn, 4, ip="192.168.1.30", nickname="Tablet")
    for stamp in ("2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z"):
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,2,'device',2)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (2, 3)])

    _nodes, edges = graph.build_graph(conn)
    uses = [e for e in edges if e.edge_type == "uses"]
    assert [(e.src, e.dst) for e in uses] == [("device:3", "provider:2:file_sharing")]
    assert uses[0].confidence == "observed"

    blast = graph.blast_radius(conn, 2)
    assert [d["device_id"] for d in blast["degraded"]] == [3]
    assert "file sharing" in blast["degraded"][0]["why"]
    # The laptop is already accounted for as degraded (it loses file sharing), so it is not also
    # claimed to go offline. Nothing else was ever seen dropping with the NAS.
    assert blast["offline"] == []
    assert 4 in {d["device_id"] for d in blast["unaffected"]}
    assert blast["confidence"] in ("observed", "mixed")
    assert blast["evidence"] and "discovery cycle" in blast["evidence"]


def test_dropping_alongside_the_router_does_not_make_a_printer_its_cause(
        memory_conn: sqlite3.Connection) -> None:
    """Regression: blast_radius must read `co_members_triggered`, not `co_members`.

    The router took the printer, the laptop and the TV down with it three times. The printer
    triggered nothing. Reading the untriggered view reported — at "observed" confidence — that
    the printer failing takes the router offline, which is exactly the invented relationship
    this feature exists to avoid.
    """
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.50", kind="printer", nickname="Study printer")
    add_device(conn, 3, ip="192.168.1.20", nickname="Laptop")
    add_device(conn, 4, ip="192.168.1.30", nickname="TV")
    for stamp in ("2026-09-05T03:00:00Z", "2026-09-08T03:00:00Z", "2026-09-11T03:00:00Z"):
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'gateway',4)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (1, 2, 3, 4)])

    observed = outages.observed_blast_radius(conn, 2)
    assert observed["triggered"] == 0
    assert {m["device_id"] for m in observed["co_members"]} == {1, 3, 4}   # context...
    assert observed["co_members_triggered"] == []                          # ...but no evidence

    blast = graph.blast_radius(conn, 2)
    assert blast["offline"] == []
    assert 1 not in {d["device_id"] for d in blast["offline"] + blast["degraded"]}
    assert blast["confidence"] != "observed"
    assert "go offline with it" not in blast["headline"]
    # ...and the evidence slot stays empty. It used to carry "Seen three times: on 5 September,
    # 8 September and 11 September, 4 devices went offline in the same 10-minute discovery cycle
    # as this one" - a sentence about the router's outages, printed under a headline saying
    # nothing is known to stop working, on /devices/<id>, the map panel, Lens and the CLI. A
    # non-empty evidence line also *suppressed* the honest "nothing like this has been recorded"
    # fallback in all four. C4: evidence is None when nothing has been observed.
    assert blast["evidence"] is None
    assert blast["resolution"] is None


def test_a_bystander_never_reports_the_numbers_of_the_outage_it_was_caught_in(
        memory_conn: sqlite3.Connection) -> None:
    """The trigger-scoped/membership distinction, in the shape that produced a fabricated count.

    The NAS headed two small outages of its own; it was also one of twenty devices in a single
    router outage. Its blast radius must describe the two, never the twenty - the 20 and the
    date belong to the router, and reporting them as "what happens when the NAS fails" put an
    invented quantity at `observed` confidence on the map and inside a persisted finding.
    """
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.10", kind="nas", nickname="NAS")
    for device_id in range(3, 21):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", nickname=f"Device {device_id}")

    for stamp in ("2026-09-03T16:00:00Z", "2026-09-11T16:00:00Z"):   # the NAS's own, 3 members
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,2,'device',3)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (2, 3, 4)])
    everyone = tuple(range(1, 21))                                    # the router's, 20 members
    outage_id = db.write(
        conn,
        "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
        "VALUES ('2026-09-01T16:00:00Z',3600,1,'gateway',20)")
    db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                 [(outage_id, d, "2026-09-01T16:00:00Z") for d in everyone])

    observed = outages.observed_blast_radius(conn, 2)
    assert observed["outages"] == 3 and observed["triggered"] == 2 and observed["attended_outages"] == 1
    assert observed["member_count"] == 2            # two *other* devices, not twenty, not three
    assert observed["attended_member_count"] == 20  # the router's number, kept as context only
    assert observed["cycle_seconds"] == 600         # the NAS's cadence, not the router's 3600
    assert observed["dates"] == [local_date("2026-09-03T16:00:00Z"), local_date("2026-09-11T16:00:00Z")]
    assert local_date("2026-09-01T16:00:00Z") not in observed["dates"]
    assert "20 other devices" not in observed["evidence"]
    assert observed["evidence"].count("other device") == 2  # one number per date, no more
    assert "10-minute discovery cycle" in observed["evidence"]
    # The blast radius reads the same scoped figures, so nothing downstream can cite the twenty.
    assert graph.blast_radius(conn, 2)["evidence"] == observed["evidence"]


def test_one_co_drop_does_not_buy_one_claim_per_service(memory_conn: sqlite3.Connection) -> None:
    """C2.5: a co-drop is one bit of information and cannot be spent on four dependencies.

    A NAS advertising SMB, SSH, AirPlay and printing went down twice with a doorbell and a TV.
    That produced eight `observed` "uses" edges and a blast radius stating that the doorbell
    loses AirPlay, file sharing, printing *and* SSH - nothing in the database says the doorbell
    ever opened any of them, and the co-drop cannot tell the four apart. A multi-service device
    must therefore produce no more consumer edges than a single-service one.
    """
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.10", kind="nas", nickname="NAS",
               mdns='["_smb._tcp", "_ssh._tcp", "_airplay._tcp", "_ipp._tcp"]')
    add_device(conn, 3, ip="192.168.1.20", nickname="Doorbell")
    add_device(conn, 4, ip="192.168.1.30", nickname="TV")
    for stamp in ("2026-09-03T16:00:00Z", "2026-09-11T16:00:00Z"):
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,2,'device',3)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (2, 3, 4)])

    _nodes, edges = graph.build_graph(conn)
    uses = [e for e in edges if e.edge_type == "uses"]
    assert len(uses) == 2, "one edge per co-dropping pair, whatever the device offers"
    assert {(e.src, e.dst) for e in uses} == {("device:3", "device:2"), ("device:4", "device:2")}
    # No edge names a service, because which one (if any) was involved is exactly what is unknown.
    assert not [e for e in uses if e.dst.startswith("provider:")]
    assert all("is not known" in e.evidence for e in uses)
    # ...and the evidence no longer claims the NAS "triggered" anything: nothing established that.
    assert not any("it triggered" in e.evidence for e in uses)

    blast = graph.blast_radius(conn, 2)
    assert not [s for s in blast["services_lost"] if " for " in s], "no service has a confirmed consumer"
    for entry in blast["degraded"]:
        assert "loses AirPlay" not in entry["why"] and "loses SSH" not in entry["why"]
        assert "not been established" in entry["why"]


def test_a_nas_co_drop_degrades_rather_than_offlines(memory_conn: sqlite3.Connection) -> None:
    """C4: `offline` is for devices that genuinely become unreachable.

    A NAS failing does not make a laptop unreachable, however many times they have gone dark
    together - a shared power strip does that, and the "trigger" that gated this was only ever
    "which member has an infrastructure `kind`". Only a hub, an access point or a switch severs
    a path, so only those may claim it.
    """
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.10", kind="nas", nickname="NAS")   # no ports, no mDNS
    add_device(conn, 3, ip="192.168.1.20", nickname="Laptop")
    add_device(conn, 4, ip="192.168.1.30", nickname="Smart TV")
    for stamp in ("2026-09-03T16:00:00Z", "2026-09-11T16:00:00Z"):
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,2,'device',3)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (2, 3, 4)])

    blast = graph.blast_radius(conn, 2)
    assert blast["offline"] == [], "a NAS failing does not make a laptop unreachable"
    assert {d["device_id"] for d in blast["degraded"]} == {3, 4}
    assert all("may share power or a switch" in d["why"] for d in blast["degraded"])
    assert "go offline with it" not in blast["headline"]
    assert "what connects them is not known" in blast["headline"]

    # An access point is the case where the claim *is* warranted: its clients arrive on it.
    db.write(conn, "UPDATE devices SET kind = 'ap' WHERE id = 2")
    ap = graph.blast_radius(conn, 2)
    assert {d["device_id"] for d in ap["offline"]} == {3, 4}
    assert all("reaches the network through this device" in d["why"] for d in ap["offline"])


def test_a_gateway_outage_mints_no_consumer_edges(house: sqlite3.Connection) -> None:
    """The router runs DNS on port 53 and took the whole house down twice. That is still not
    evidence that anyone used *its* resolver: on a flat network the shared route explains every
    one of those co-drops on its own, and promoting them would hand the user five confident
    service dependencies built out of one power cut."""
    add_service(house, 1, 53, proto="udp", name="domain")
    for stamp in ("2026-09-03T04:00:00Z", "2026-09-11T04:00:00Z"):
        outage_id = db.write(
            house,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'gateway',5)", (stamp,))
        db.writemany(house, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (1, 2, 3, 4, 5)])

    nodes, edges = graph.build_graph(house)
    assert any(n.id == "provider:1:dns" for n in nodes)      # the service is real and is shown
    assert [e for e in edges if e.edge_type == "uses"] == []  # its consumers are not
    assert outages.trigger_members(house) == {}
    assert outages.trigger_members(house, exclude_gateway=False)[1][2] == 2
    # ...and the finding that *is* allowed to fire on this evidence still does.
    assert outages.trigger_counts(house) == {1: 2}


def test_headline_renders_for_a_gateway_a_leaf_and_an_isolated_device(house: sqlite3.Connection) -> None:
    """C9: the headline sentence has to work for all three shapes."""
    add_queries(house, "192.168.1.20", "example.com", 30)
    gateway = graph.blast_radius(house, 1)["headline"]
    leaf = graph.blast_radius(house, 4)["headline"]           # the printer: a service, no consumers
    isolated = graph.blast_radius(house, 3)["headline"]        # a phone: nothing depends on it

    for sentence in (gateway, leaf, isolated):
        assert sentence.startswith("If ") and sentence.endswith(".")
        assert len(sentence) < 260
    assert "17 devices" not in leaf
    assert "nothing has been seen using it" in leaf
    assert "nothing else on the network is known to stop working" in isolated


def test_the_evidence_sentence_never_states_a_count_it_then_contradicts(
        memory_conn: sqlite3.Connection) -> None:
    """Two ways the one sentence the whole feature asks to be believed used to be wrong.

    It rendered the *largest* outage's size against every date, and it counted the subject
    device among "devices that went offline with this one" - so two outages of different sizes
    both reported the bigger number, inflated by one. And with more than three outages it said
    "Seen five times" above a list of three dates, leaving a reader to count them and find four
    missing.
    """
    conn = memory_conn
    add_device(conn, 1, ip="192.168.1.1", kind="nas", nickname="NAS")
    for device_id in range(2, 7):
        add_device(conn, device_id, ip=f"192.168.1.{device_id}", nickname=f"Device {device_id}")

    sizes = {"2026-09-03T16:00:00Z": (1, 2, 3), "2026-09-11T16:00:00Z": (1, 2, 3, 4)}
    for stamp, members in sizes.items():
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'device',?)", (stamp, len(members)))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in members])

    sentence = outages.observed_blast_radius(conn, 1)["evidence"]
    assert sentence == (
        f"Seen twice: 2 other devices on {local_date('2026-09-03T16:00:00Z')} and 3 other devices on "
        f"{local_date('2026-09-11T16:00:00Z')} went offline in the same 10-minute discovery cycle as this one."
    )

    # ...and with more dates than it lists, it says so instead of quietly listing three.
    for stamp in ("2026-09-13T16:00:00Z", "2026-09-15T16:00:00Z", "2026-09-17T16:00:00Z"):
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'device',3)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (1, 2, 3)])

    longer = outages.observed_blast_radius(conn, 1)["evidence"]
    assert longer.startswith("Seen five times, the three most recent:")
    assert longer.count("other device") == 3, "the stated count and the listed dates must agree"


def test_an_outage_date_is_rendered_in_the_readers_timezone(memory_conn: sqlite3.Connection) -> None:
    """Every other timestamp on the dashboard is local (app.js uses toLocaleString), so this is
    too. A user west of UTC checking "3 September" against their memory of Tuesday *evening*
    has to be able to reconcile the two, and a UTC day silently moves an evening event forward."""
    conn = memory_conn
    add_device(conn, 1, ip="192.168.1.1", kind="nas", nickname="NAS")
    add_device(conn, 2, ip="192.168.1.2", nickname="Laptop")
    add_device(conn, 3, ip="192.168.1.3", nickname="TV")
    for stamp in ("2026-09-02T23:30:00+00:00", "2026-09-09T23:30:00+00:00"):
        outage_id = db.write(
            conn,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'device',3)", (stamp,))
        db.writemany(conn, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (1, 2, 3)])
    dates = outages.observed_blast_radius(conn, 1)["dates"]
    assert dates == [local_date("2026-09-02T23:30:00+00:00"), local_date("2026-09-09T23:30:00+00:00")]


def test_the_headline_agrees_with_itself_for_a_single_device(memory_conn: sqlite3.Connection) -> None:
    """A two-device house is every new install on day one, and read "1 device lose their
    internet connection" as its first sentence. C4 asks for one plain sentence a non-expert
    understands, which means it has to be grammatical."""
    conn = memory_conn
    db.set_setting(conn, "network.gateway", "192.168.1.1")
    add_device(conn, 1, ip="192.168.1.1", kind="router", nickname="Router")
    add_device(conn, 2, ip="192.168.1.20", nickname="Laptop")

    sentence = graph.blast_radius(conn, 1)["headline"]
    assert sentence == ("If Router fails, 1 device loses its internet connection. It stays on the "
                        "local network and can still reach other devices here.")
    assert "lose their" not in sentence and "They stay" not in sentence

    assert graph.headline("Hub", False, 0, 1, 0, []) == (
        "If Hub fails, 1 device goes offline with it, based on what has been recorded.")
    assert graph.headline("Hub", False, 2, 3, 0, []) == (
        "If Hub fails, 3 devices go offline and 2 devices lose a service, based on what has been recorded.")


def test_a_headline_never_names_a_service_nothing_was_seen_using(memory_conn: sqlite3.Connection) -> None:
    """``services_lost`` carries both "printing for 2 devices" and "printing (no confirmed
    consumers)". Taking the first entry blindly told the reader that two devices lose AirPlay in
    the same breath as the list below told them nothing has ever been seen using it."""
    assert "AirPlay" not in graph.headline(
        "NAS", False, 2, 0, 0, ["AirPlay (no confirmed consumers)", "file sharing (no confirmed consumers)"])
    assert graph.headline("NAS", False, 2, 0, 0, ["file sharing for 2 devices"]) == (
        "If NAS fails, 2 devices lose file sharing. Everything else keeps working.")


def test_blast_radius_of_an_unknown_device_is_empty(house: sqlite3.Connection) -> None:
    assert graph.blast_radius(house, 999) == {}
    assert graph.blast_radius(house, 0) == {}
    assert graph.blast_radius(house, 2**70) == {}
    assert graph.blast_radius(house, "nonsense") == {}  # type: ignore[arg-type]


def test_criticality_ranks_the_gateway_first_and_ignores_the_rest(house: sqlite3.Connection) -> None:
    ranked = graph.criticality(house)
    assert ranked[0]["device_id"] == 1 and ranked[0]["dependents"] == 5
    assert "way off the local network" in ranked[0]["why"]
    assert all(item["device_id"] == 1 for item in ranked)  # nothing else is load-bearing yet


# ------------------------------------------------------------- determinism


def test_build_graph_is_deterministic(house: sqlite3.Connection) -> None:
    """C9: identical data in, identical node and edge ordering out."""
    add_queries(house, "192.168.1.20", "example.com", 30)
    add_queries(house, "192.168.1.20", "ads.example", 30, action="block")
    add_queries(house, "192.168.1.60", "ring.com", 25)
    first_nodes, first_edges = graph.build_graph(house)
    second_nodes, second_edges = graph.build_graph(house)
    assert [n.to_dict() for n in first_nodes] == [n.to_dict() for n in second_nodes]
    assert [e.to_dict() for e in first_edges] == [e.to_dict() for e in second_edges]
    assert len(first_nodes) == len({n.id for n in first_nodes})
    assert len(first_edges) == len({e.key for e in first_edges})


def test_graph_renders_on_empty_single_and_large_databases(memory_conn: sqlite3.Connection) -> None:
    """C9: an empty database, one device, and forty."""
    nodes, edges = graph.build_graph(memory_conn)
    assert (nodes, edges) == ([], [])
    assert graph.criticality(memory_conn) == []

    add_device(memory_conn, 1, ip="192.168.1.1", nickname="Only device")
    nodes, edges = graph.build_graph(memory_conn)
    assert [n.id for n in nodes] == ["device:1"] and edges == []

    db.set_setting(memory_conn, "network.gateway", "192.168.1.1")
    for device_id in range(2, 41):
        add_device(memory_conn, device_id, ip=f"192.168.1.{device_id}", nickname=f"Device {device_id}")
    nodes, edges = graph.build_graph(memory_conn)
    assert len([n for n in nodes if n.kind == "device"]) == 40
    assert len([e for e in edges if e.edge_type == "gateway"]) == 39
    assert graph.blast_radius(memory_conn, 1)["headline"]


# ------------------------------------------------------------- C6 scanner


def test_run_is_a_normal_scanner(house: sqlite3.Connection, cfg_for) -> None:
    add_queries(house, "192.168.1.20", "example.com", 30)
    result = topology_run(cfg_for(house), house)
    assert isinstance(result, ScanResult)
    assert result.kind == "topology" and result.error is None
    assert result.summary["edges"] > 0 and result.summary["nodes"] > 0
    assert db.one(house, "SELECT COUNT(*) AS n FROM dep_edges")["n"] == result.summary["edges"]


def test_run_respects_the_disabled_switch(house: sqlite3.Connection, cfg_for) -> None:
    db.set_setting(house, "topology.enabled", "false")
    result = topology_run(cfg_for(house), house)
    assert result.summary == {"enabled": False, "skipped": "topology.enabled is false"}
    assert db.one(house, "SELECT COUNT(*) AS n FROM dep_edges")["n"] == 0


def test_run_on_an_empty_database_is_quiet(memory_conn: sqlite3.Connection, cfg_for) -> None:
    result = topology_run(cfg_for(memory_conn), memory_conn)
    assert result.error is None and result.findings == [] and result.summary["edges"] == 0


def test_findings_are_only_ids_the_spec_defines(house: sqlite3.Connection, cfg_for) -> None:
    add_queries(house, "192.168.1.20", "example.com", 30)
    for device_id in range(7, 16):
        add_device(house, device_id, ip=f"192.168.1.{100 + device_id}", nickname=f"Extra {device_id}")
    result = topology_run(cfg_for(house), house)
    emitted = {d.finding_id for d in result.findings}
    assert emitted <= {"NET-DEP-001", "NET-DEP-002", "NET-DEP-003"}
    assert "NET-DEP-001" in emitted
    load_bearing = next(d for d in result.findings if d.finding_id == "NET-DEP-001")
    assert load_bearing.subject.startswith("device:") and load_bearing.device_id == 1
    assert load_bearing.evidence["dependents"] > load_bearing.evidence["threshold"]


def test_net_dep_002_never_fires_on_inference_alone(house: sqlite3.Connection, cfg_for) -> None:
    """C9, explicitly. The house has a gateway every device depends on, which is as strong as
    inference gets — and it is still not enough for a medium-severity finding."""
    add_queries(house, "192.168.1.20", "example.com", 30)
    for device_id in range(7, 16):
        add_device(house, device_id, ip=f"192.168.1.{100 + device_id}", nickname=f"Extra {device_id}")
    result = topology_run(cfg_for(house), house)
    assert not [d for d in result.findings if d.finding_id == "NET-DEP-002"]
    assert db.one(house, "SELECT COUNT(*) AS n FROM outages")["n"] == 0

    # Now record two real outages this device triggered, and it fires — citing the dates.
    for stamp in ("2026-09-03T04:00:00Z", "2026-09-11T04:00:00Z"):
        outage_id = db.write(
            house,
            "INSERT INTO outages(started_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES (?,600,1,'gateway',4)", (stamp,))
        db.writemany(house, "INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES (?,?,?)",
                     [(outage_id, d, stamp) for d in (1, 2, 3, 4)])
    drafts = [d for d in topology_run(cfg_for(house), house).findings if d.finding_id == "NET-DEP-002"]
    assert len(drafts) == 1
    assert drafts[0].evidence["dates"] == [local_date("2026-09-03T04:00:00Z"),
                                           local_date("2026-09-11T04:00:00Z")]
    assert "discovery cycle" in (drafts[0].detail or "")


def test_net_dep_003_needs_a_habit_not_a_burst(house: sqlite3.Connection, cfg_for) -> None:
    now = datetime.now(timezone.utc)
    # A burst: 40 blocked lookups inside ten minutes.
    add_queries(house, "192.168.1.30", "burst.example", 40, action="block",
                start=now - timedelta(hours=2), spacing_minutes=0)
    # A habit: 40 blocked lookups spread over a day.
    add_queries(house, "192.168.1.60", "vendor.example", 40, action="block",
                start=now - timedelta(hours=30), spacing_minutes=36)
    drafts = [d for d in topology_run(cfg_for(house), house).findings if d.finding_id == "NET-DEP-003"]
    assert [d.evidence["domain"] for d in drafts] == ["vendor.example"]
    assert drafts[0].evidence["key"] == "vendor.example"  # one finding per device+domain


# ------------------------------------------------------------------- safety


def test_a_hostile_nickname_survives_intact_for_the_layer_that_escapes_it(house: sqlite3.Connection) -> None:
    """C9's XSS case, from this side of the fence.

    Escaping belongs to whatever renders the value — Jinja for the dashboard, JSON for the API.
    The engine's job is the opposite: hand the payload over byte-for-byte so the escaper sees
    the real string, while refusing to carry control characters that could forge a line in the
    CLI's own output.
    """
    payload = "<img src=x onerror=alert(1)>"
    db.write(house, "UPDATE devices SET nickname = ? WHERE id = 2", (payload,))
    nodes, _edges = graph.build_graph(house)
    node = next(n for n in nodes if n.id == "device:2")
    assert node.label == payload
    blast = graph.blast_radius(house, 1)
    assert any(d["label"] == payload for d in blast["degraded"])

    db.write(house, "UPDATE devices SET nickname = ? WHERE id = 2", ("evil\r\n  1  fake row",))
    nodes, _edges = graph.build_graph(house)
    label = next(n for n in nodes if n.id == "device:2").label
    assert "\n" not in label and "\r" not in label


def test_a_device_with_no_address_does_not_break_the_graph(memory_conn: sqlite3.Connection) -> None:
    add_device(memory_conn, 1, ip="", nickname="Nameless")
    add_device(memory_conn, 2, ip="192.168.1.2", kind="router")
    nodes, edges = graph.build_graph(memory_conn)
    assert len(nodes) >= 2
    assert not [e for e in edges if e.src == "device:1" and e.edge_type == "gateway"]


# ------------------------------------------------------------------- config


def test_topology_config_section_and_validation(conn: sqlite3.Connection) -> None:
    cfg = config.load(conn)
    assert cfg.topology.enabled is True and cfg.topology.window_hours == 168
    assert cfg.topology.include_cloud is True and cfg.topology.min_outage_members == 3
    assert cfg.topology.criticality_alert == 5

    config.set_override(conn, "topology.window_hours", "72")
    assert config.load(conn).topology.hours == 72
    for key, value in (("topology.window_hours", "0"), ("topology.min_outage_members", "1"),
                       ("topology.criticality_alert", "0")):
        with pytest.raises(ValueError):
            config.set_override(conn, key, value)
    with pytest.raises(ValueError):
        config.set_override(conn, "topology.enabled", "maybe")

    # The clamping properties make a hand-edited config.toml safe rather than fatal.
    built = config.build({**config.DEFAULTS, "topology": {**config.DEFAULTS["topology"],
                                                          "window_hours": 1, "min_outage_members": 0}})
    assert built.topology.hours == 24 and built.topology.outage_members == 2


# ---------------------------------------------------------------------- CLI


def test_cli_blast_resolves_by_ip_mac_and_nickname(house: sqlite3.Connection, capsys) -> None:
    from homesoc import cli

    assert cli.resolve_device(house, "192.168.1.1")[0] == 1
    assert cli.resolve_device(house, "00:11:22:33:44:01")[0] == 1
    assert cli.resolve_device(house, "00-11-22-33-44-01")[0] == 1
    assert cli.resolve_device(house, "Home router")[0] == 1
    assert cli.resolve_device(house, "home ROUTER")[0] == 1
    assert cli.resolve_device(house, "epson")[0] == 4          # hostname
    assert cli.resolve_device(house, "nothing here")[0] is None

    add_device(house, 7, ip="192.168.1.31", nickname="Phone two")
    assert cli.resolve_device(house, "Phone")[0] == 3          # an exact name still wins
    device_id, candidates = cli.resolve_device(house, "one")   # ...but a substring may not
    assert device_id is None and len(candidates) == 2          # ambiguous: ask, never guess


def test_cli_blast_prints_headline_lists_and_confidence(house: sqlite3.Connection, capsys) -> None:
    from homesoc import cli

    add_queries(house, "192.168.1.20", "example.com", 30)
    ctx = cli.Context(_Args(device="192.168.1.1"), config.load(house), house)
    assert cli.cmd_blast(ctx) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "lose their internet connection" in out
    assert "Keeps working, but degraded (5)" in out
    assert "Confidence: inferred" in out
    assert "no packet visibility" in out

    assert cli.cmd_blast(cli.Context(_Args(device="no-such-device"), config.load(house), house)) == cli.EXIT_ERROR


def test_cli_registers_the_topology_job_after_discovery(conn: sqlite3.Connection) -> None:
    from homesoc import cli

    cfg = config.load(conn)
    names = [j.name for j in cli.build_jobs(cfg, conn)]
    assert "topology" in names
    assert names.index("discovery") < names.index("topology")
    job = {j.name: j for j in cli.build_jobs(cfg, conn)}["topology"]
    assert job.interval_sec == cli.TOPOLOGY_JOB_HOURS * 3600
    assert "topology" in cli.SCAN_STEPS and "topology" in cli.SCAN_FUNCS


class _Args:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


@pytest.fixture
def cfg_for():
    def build(conn: sqlite3.Connection) -> config.Config:
        return config.load(conn)

    return build
