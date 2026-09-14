"""Dependency map over HTTP, and the Lens "if this fails" section (SPEC addendum C, T2-api).

The engine itself (``homesoc.topology``, addendum C3/C4) is a separate package built in parallel,
so these tests stand a fake engine in ``sys.modules`` and pin the *contract* between it and the
API: the shapes, the honesty rules and the authorisation rules this layer is responsible for.
Two consequences of that are deliberate:

* the fake returns frozen dataclasses with exactly the C4 field lists, so the normalisation here is
  exercised against the real shape rather than against dicts that happen to be convenient;
* every test that matters is also run with **no** engine installed, because on a live machine
  today that is the actual state of the world and neither the dashboard nor Lens may break.

The defining constraint of the feature gets its own group at the end: Home SOC has no packet
visibility, so a provider nobody was seen using must produce zero consumer edges, an edge that
claims to be observed with nothing behind it must not be served as observed, and the note that
says so must be in the payload rather than only in the UI.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import sys
import types
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from flask.testing import FlaskClient

from homesoc import db as core_db
from homesoc.web import api as webapi
from homesoc.web import create_app
from homesoc.web import lens as lensmod

FETCH = {"X-Requested-With": "fetch"}
LAN = {"REMOTE_ADDR": "192.168.1.50"}
XSS = "<img src=x onerror=alert(1)>"


def _now(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- the C4 shapes


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    label: str
    sublabel: str | None
    device_id: int | None
    criticality: int
    severity: str | None
    online: bool


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    edge_type: str
    protocol: str | None
    confidence: str
    evidence: str
    observed_count: int


# The graph the fake engine serves: a gateway, a laptop, a camera with real DNS traffic, and a
# printer that advertises _printer._tcp. The printer is the whole point of C2 rule 5 — it is a
# provider node with no edges at all, because nothing was ever observed printing to it.
NODES: list[Node] = [
    Node("internet", "internet", "Internet", None, None, 0, None, True),
    Node("device:1", "device", "Router", "192.168.1.254", 1, 3, "critical", True),
    Node("resolver", "resolver", "Home SOC resolver", "192.168.1.254:53", 1, 2, None, True),
    Node("device:2", "device", "Laptop", "192.168.1.40", 2, 0, None, True),
    Node("device:3", "device", "Printer", "192.168.1.50", 3, 0, "low", True),
    Node("provider:device:3:_printer._tcp", "provider", "Printing (_printer._tcp)",
         "no confirmed consumers", 3, 0, None, True),
    Node("device:4", "device", "Hall camera", "192.168.1.64", 4, 0, "critical", True),
    Node("cloud:ring.com", "cloud", "ring.com", "Ring", None, 0, None, True),
]

EDGES: list[Edge] = [
    Edge("device:1", "internet", "internet", None, "inferred", "Devices reach the internet only through the gateway.", 0),
    Edge("device:2", "device:1", "gateway", None, "inferred", "On the gateway's subnet.", 0),
    Edge("device:3", "device:1", "gateway", None, "inferred", "On the gateway's subnet.", 0),
    Edge("device:4", "device:1", "gateway", None, "inferred", "On the gateway's subnet.", 0),
    Edge("device:4", "resolver", "dns", "udp", "observed", "94 DNS queries in the last 7 days.", 94),
    Edge("device:2", "resolver", "dns", "udp", "inferred", "DHCP on this subnet hands out this resolver.", 0),
    Edge("device:4", "cloud:ring.com", "cloud", "tls", "observed", "31 lookups of ring.com in the last 7 days.", 31),
]

BLAST_GATEWAY = {
    "device": {"id": 1, "label": "Router", "ip": "192.168.1.254"},
    "offline": [],
    "degraded": [
        {"device_id": 2, "label": "Laptop", "why": "reaches the internet only through this device"},
        {"device_id": 3, "label": "Printer", "why": "reaches the internet only through this device"},
        {"device_id": 4, "label": "Hall camera", "why": "loses DNS and its cloud service"},
    ],
    "unaffected": [],
    "services_lost": ["DNS for 2 devices", "internet access"],
    "headline": "If the router fails, three devices lose the internet. They keep working on the local network.",
    "confidence": "observed",
    "evidence": "Seen twice: on 3 September and 11 September, three devices went offline in the same "
                "discovery cycle as this one.",
}

BLAST_LEAF = {
    "device": {"id": 3, "label": "Printer", "ip": "192.168.1.50"},
    "offline": [],
    "degraded": [],
    "unaffected": [{"device_id": 1, "label": "Router"}, {"device_id": 2, "label": "Laptop"}],
    "services_lost": [],
    "headline": "Nothing else on the network depends on this printer, so nothing stops working without it.",
    "confidence": "inferred",
    "evidence": None,
}

CRITICALITY = [
    {"device_id": 2, "label": "Laptop", "dependents": 0, "weight": 0.0, "why": "nothing depends on it"},
    {"device_id": 1, "label": "Router", "dependents": 3, "weight": 9.5, "why": "every device reaches the internet through it"},
    {"device_id": 4, "label": "Hall camera", "dependents": 1, "weight": 1.0, "why": "one cloud dependency"},
]


class FakeEngine:
    """Stands in for ``homesoc.topology``. Records what the API asked it for."""

    def __init__(self, *, nodes=None, edges=None, blast=None, criticality=None, raises: Exception | None = None):
        self.nodes = list(NODES if nodes is None else nodes)
        self.edges = list(EDGES if edges is None else edges)
        self.blast = {1: BLAST_GATEWAY, 3: BLAST_LEAF} if blast is None else blast
        self.criticality_rows = list(CRITICALITY if criticality is None else criticality)
        self.raises = raises
        self.calls: list[tuple] = []

    def build_graph(self, conn, *, hours: int = 168, include_cloud: bool = True):
        self.calls.append(("build_graph", hours, include_cloud))
        if self.raises is not None:
            raise self.raises
        nodes = self.nodes if include_cloud else [n for n in self.nodes if n.kind != "cloud"]
        keep = {n.id for n in nodes}
        edges = [e for e in self.edges if e.src in keep and e.dst in keep] if not include_cloud else self.edges
        return list(nodes), list(edges)

    def blast_radius(self, conn, device_id: int):
        self.calls.append(("blast_radius", int(device_id)))
        if self.raises is not None:
            raise self.raises
        return self.blast.get(int(device_id), {
            "device": {"id": int(device_id)},
            "offline": [], "degraded": [], "unaffected": [], "services_lost": [],
            "headline": "Home SOC has not worked out what depends on this device yet.",
            "confidence": "inferred", "evidence": None,
        })

    def criticality(self, conn):
        self.calls.append(("criticality",))
        if self.raises is not None:
            raise self.raises
        return list(self.criticality_rows)


# The fake is installed by pointing ``api.TOPOLOGY_MODULES`` at a module of our own rather than by
# shadowing ``homesoc.topology`` in sys.modules. The real package is being written in parallel, so
# shadowing would make these tests depend on how far that build has got — and a half-written engine
# on disk would leak into the "no engine installed" cases through its submodules. Pointing the
# lookup somewhere else isolates the contract under test from the implementation of it.
FAKE_MODULE = "homesoc._fake_topology_for_tests"
ABSENT_MODULE = "homesoc._topology_that_is_not_installed"


@pytest.fixture
def engine(monkeypatch) -> FakeEngine:
    return install_engine(monkeypatch, FakeEngine())


def install_engine(monkeypatch, fake: FakeEngine, *, only: tuple[str, ...] = ("build_graph", "blast_radius", "criticality")) -> FakeEngine:
    module = types.ModuleType(FAKE_MODULE)
    for name in only:
        setattr(module, name, getattr(fake, name))
    monkeypatch.setitem(sys.modules, FAKE_MODULE, module)
    monkeypatch.setattr(webapi, "TOPOLOGY_MODULES", (FAKE_MODULE,))
    return fake


@pytest.fixture
def no_engine(monkeypatch):
    """An install without the topology package at all."""
    monkeypatch.setattr(webapi, "TOPOLOGY_MODULES", (ABSENT_MODULE,))
    assert not webapi.topology_available()
    return None


# --------------------------------------------------------------------------- database


OUTAGE_DDL = """
CREATE TABLE IF NOT EXISTS outages (
    id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT, cycle_seconds INTEGER NOT NULL,
    trigger_device_id INTEGER REFERENCES devices(id), trigger_kind TEXT NOT NULL, member_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS outage_members (
    outage_id INTEGER NOT NULL REFERENCES outages(id), device_id INTEGER NOT NULL REFERENCES devices(id),
    dropped_at TEXT NOT NULL, returned_at TEXT, PRIMARY KEY(outage_id, device_id));
"""


def seed(conn: sqlite3.Connection, *, outages: bool = True) -> None:
    now, old = _now(), _now(60 * 24 * 30)
    conn.executescript(
        """
        INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online)
        VALUES(1,'00:11:22:00:00:01','192.168.1.254','gateway.lan','Example Networks','router','Router',1,'{old}','{now}',1);
        INSERT INTO devices(id, mac, ip, hostname, vendor, kind, trusted, first_seen, last_seen, online)
        VALUES(2,'00:11:22:00:00:02','192.168.1.40','laptop','Contoso','laptop',1,'{old}','{now}',1);
        INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online,
                            mdns_services)
        VALUES(3,'00:11:22:00:00:03','192.168.1.50','printer','Example Print','printer','Printer',1,'{old}','{now}',1,
               '["_printer._tcp"]');
        INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online,
                            last_service_scan)
        VALUES(4,'00:11:22:00:00:04','192.168.1.64','cam-hall','Example Optics','camera','Hall camera',0,'{old}','{now}',1,'{now}');
        INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(4,'192.168.1.64','{now}','arp');
        """.format(now=now, old=old)
    )
    if outages:
        conn.executescript(OUTAGE_DDL)
        conn.execute(
            "INSERT INTO outages(id, started_at, ended_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES(1,?,?,600,1,'gateway',3)",
            (_now(60 * 24 * 10), _now(60 * 24 * 10 - 30)),
        )
        conn.execute(
            "INSERT INTO outages(id, started_at, ended_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
            "VALUES(2,?,NULL,600,NULL,'unknown',2)",
            (_now(90),),
        )
        for device_id in (2, 3, 4):
            conn.execute(
                "INSERT INTO outage_members(outage_id, device_id, dropped_at, returned_at) VALUES(1,?,?,?)",
                (device_id, _now(60 * 24 * 10), _now(60 * 24 * 10 - 30)),
            )
        for device_id in (3, 4):
            conn.execute(
                "INSERT INTO outage_members(outage_id, device_id, dropped_at, returned_at) VALUES(2,?,?,NULL)",
                (device_id, _now(90)),
            )
    conn.commit()


@pytest.fixture
def conn():
    c = core_db.connect(":memory:")
    try:
        yield c
    finally:
        c.close()


@pytest.fixture
def seeded(conn):
    seed(conn)
    lensmod.reset_claim_limits(conn)
    return conn


def make_cfg(**over) -> SimpleNamespace:
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test", timezone="local", log_level="INFO"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token=over.get("web_token", ""), refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=[]),
        scan=SimpleNamespace(use_nmap=False, nmap_top_ports=100, nmap_timing="T3", version_detection=True,
                             gentle_top_ports=25, per_host_timeout_sec=180, max_parallel_hosts=3, scan_gateway=True),
        dns=SimpleNamespace(enabled=True, listen="0.0.0.0", port=53, upstreams=[], doh_upstream="", block_mode="null",
                            cache_max_entries=100, lists=[], log_queries=True, log_retention_days=14,
                            virustotal_api_key="", virustotal_daily_budget=400, reputation_min_malicious_votes=2,
                            reputation_ttl_hours=72),
        notify=SimpleNamespace(min_severity="high", ntfy_url="", discord_webhook="", webhook_url="",
                               windows_toast=True, digest_hour=8),
        schedule=SimpleNamespace(discovery_minutes=over.get("discovery_minutes", 10), services_hours=24, host_hours=6,
                                 exposure_hours=12, feeds_hours=6),
        topology=SimpleNamespace(enabled=True, window_hours=over.get("window_hours", 168),
                                 include_cloud=over.get("include_cloud", True), min_outage_members=3,
                                 criticality_alert=5),
        lens=SimpleNamespace(enabled=over.get("lens_enabled", True), require_https=True, tag_learning=True,
                             allow_actions=False, token_ttl_days=90, max_tokens=10),
    )


class TlsClient(FlaskClient):
    """A phone's request: SPEC B10 refuses Lens over plain HTTP from a non-loopback address."""

    def open(self, *args, **kwargs):
        kwargs.setdefault("base_url", "https://localhost")
        return super().open(*args, **kwargs)


def client_for(conn, **cfg_kwargs) -> FlaskClient:
    app = create_app(make_cfg(**cfg_kwargs), conn)
    app.config["TESTING"] = True
    app.test_client_class = TlsClient
    return app.test_client()


@pytest.fixture
def client(seeded):
    return client_for(seeded)


def paired(conn, *, scopes: str = "read") -> str:
    """A live read-only Lens token, stored as B4 requires (only its SHA-256)."""
    lensmod.ensure_tables(conn)
    token = secrets.token_urlsafe(32)
    webapi.write(
        conn,
        "INSERT INTO lens_tokens(token_hash, label, scopes, created_at) VALUES(?,?,?,?)",
        (lensmod.token_hash(token), "Test phone", scopes, _now()),
    )
    return token


def body(response) -> dict:
    assert response.headers["Content-Type"].startswith("application/json"), response.headers["Content-Type"]
    return json.loads(response.data)


# --------------------------------------------------------------------------- GET /api/map


def test_map_returns_the_documented_shape(client, engine):
    data = body(client.get("/api/map"))
    assert set(("nodes", "edges", "legend", "generated_at", "note")) <= set(data)
    assert data["note"] == webapi.MAP_NOTE
    assert len(data["nodes"]) == len(NODES)
    assert len(data["edges"]) == len(EDGES)
    assert data["counts"]["by_confidence"] == {"observed": 2, "inferred": 5, "assumed": 0}
    assert engine.calls[0] == ("build_graph", 168, True)


def test_map_note_states_the_packet_visibility_limit(client, engine):
    note = body(client.get("/api/map"))["note"]
    assert "cannot see traffic between devices" in note
    assert "no packet visibility" in note
    assert "observed or can reasonably infer" in note


def test_legend_explains_all_three_confidences_in_one_line_each(client, engine):
    legend = body(client.get("/api/map"))["legend"]
    keys = [item["key"] for item in legend["confidence"]]
    assert keys == ["observed", "inferred", "assumed"]
    styles = [item["style"] for item in legend["confidence"]]
    assert styles == ["solid", "dashed", "dotted"]
    for item in legend["confidence"]:
        assert item["line"].endswith(".") and len(item["line"].split(". ")) <= 2
    assert {k["key"] for k in legend["kinds"]} == set(webapi.MAP_NODE_KINDS)


def test_every_edge_carries_its_confidence_and_evidence(client, engine):
    for edge in body(client.get("/api/map"))["edges"]:
        assert edge["confidence"] in webapi.MAP_CONFIDENCES
        assert set(("src", "dst", "edge_type", "protocol", "confidence", "evidence", "observed_count")) <= set(edge)
        if edge["confidence"] == "observed":
            # An observed edge must be able to say what was seen, and how often.
            assert edge["evidence"] and edge["observed_count"] > 0


def test_map_nodes_keep_their_criticality_severity_and_online_state(client, engine):
    nodes = {n["id"]: n for n in body(client.get("/api/map"))["nodes"]}
    assert nodes["device:1"]["criticality"] == 3
    assert nodes["device:1"]["severity"] == "critical"
    assert nodes["device:1"]["device_id"] == 1
    assert nodes["internet"]["device_id"] is None
    assert nodes["device:1"]["depended_on_by"] == 3  # laptop, printer, camera
    assert nodes["device:1"]["depends_on"] == 1  # the internet


def test_map_is_deterministic(client, engine):
    first = body(client.get("/api/map"))
    second = body(client.get("/api/map"))
    assert [n["id"] for n in first["nodes"]] == [n["id"] for n in second["nodes"]]
    assert [(e["src"], e["dst"], e["edge_type"]) for e in first["edges"]] == [
        (e["src"], e["dst"], e["edge_type"]) for e in second["edges"]
    ]


def test_map_hours_and_cloud_arguments_reach_the_engine(client, engine):
    data = body(client.get("/api/map?hours=24&cloud=0"))
    assert engine.calls[-1] == ("build_graph", 24, False)
    assert data["window_hours"] == 24 and data["include_cloud"] is False
    assert not [n for n in data["nodes"] if n["kind"] == "cloud"]


def test_map_hours_is_clamped_and_junk_falls_back_to_the_configured_window(client, engine):
    client.get("/api/map?hours=999999")
    assert engine.calls[-1][1] == webapi.MAX_MAP_HOURS
    client.get("/api/map?hours=nonsense")
    assert engine.calls[-1][1] == 168


def test_map_window_default_comes_from_config(seeded, monkeypatch):
    engine = install_engine(monkeypatch, FakeEngine())
    c = client_for(seeded, window_hours=72, include_cloud=False)
    data = body(c.get("/api/map"))
    assert engine.calls[-1] == ("build_graph", 72, False)
    assert data["window_hours"] == 72


def test_map_renders_on_an_empty_database(conn, monkeypatch):
    install_engine(monkeypatch, FakeEngine(nodes=[], edges=[]))
    data = body(client_for(conn).get("/api/map"))
    assert data["nodes"] == [] and data["edges"] == []
    assert data["note"] == webapi.MAP_NOTE
    assert data["counts"]["nodes"] == 0


def test_map_renders_with_a_single_device(conn, monkeypatch):
    only = [Node("device:1", "device", "Router", None, 1, 0, None, True)]
    install_engine(monkeypatch, FakeEngine(nodes=only, edges=[]))
    data = body(client_for(conn).get("/api/map"))
    assert [n["id"] for n in data["nodes"]] == ["device:1"]
    assert data["edges"] == []


def test_map_renders_forty_devices(conn, monkeypatch):
    nodes = [Node(f"device:{i}", "device", f"Device {i}", None, i, 0, None, True) for i in range(1, 41)]
    nodes.append(Node("internet", "internet", "Internet", None, None, 0, None, True))
    edges = [Edge(f"device:{i}", "internet", "gateway", None, "inferred", "On the gateway's subnet.", 0)
             for i in range(1, 41)]
    install_engine(monkeypatch, FakeEngine(nodes=nodes, edges=edges))
    data = body(client_for(conn).get("/api/map"))
    assert data["counts"] == {
        "nodes": 41, "edges": 40, "by_confidence": {"observed": 0, "inferred": 40, "assumed": 0},
        "edges_dropped": 0, "edges_downgraded": 0, "providers_without_consumers": 0,
    }


# --------------------------------------------------------------------------- GET /api/map/blast


def test_blast_returns_the_c4_shape(client, engine):
    data = body(client.get("/api/map/blast/1"))
    for key in ("device", "offline", "degraded", "unaffected", "services_lost", "headline", "confidence", "evidence"):
        assert key in data, key
    assert data["counts"] == {"offline": 0, "degraded": 3, "unaffected": 0}
    assert data["headline"].startswith("If the router fails")
    assert data["confidence"] == "observed"
    assert "same discovery cycle" in data["evidence"]
    assert data["note"] == webapi.MAP_NOTE
    assert engine.calls[-1] == ("blast_radius", 1)


def test_blast_states_the_resolution_of_an_observed_outage(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine())
    data = body(client_for(seeded, discovery_minutes=15).get("/api/map/blast/1"))
    assert "every 15 minutes" in data["resolution"]
    assert "same discovery cycle" in data["resolution"]


def test_blast_evidence_is_null_when_nothing_was_observed(client, engine):
    data = body(client.get("/api/map/blast/3"))
    assert data["evidence"] is None
    assert data["resolution"] is None  # no observation to qualify
    assert data["confidence"] == "inferred"
    assert data["counts"] == {"offline": 0, "degraded": 0, "unaffected": 2}


def test_blast_gateway_failure_degrades_rather_than_offlines(client, engine):
    data = body(client.get("/api/map/blast/1"))
    assert data["offline"] == []
    assert {m["device_id"] for m in data["degraded"]} == {2, 3, 4}
    assert all(m["why"] for m in data["degraded"])


@pytest.mark.parametrize("device_id", ["999", "99999999999999999999999"])
def test_blast_on_an_unknown_device_is_404(client, engine, device_id):
    """The huge id is the SQLite OverflowError trap: it must be a 404, never a traceback."""
    r = client.get(f"/api/map/blast/{device_id}")
    assert r.status_code == 404
    assert body(r)["error"] == "no such device"
    assert engine.calls == [] or engine.calls[-1][0] != "blast_radius"


def test_blast_falls_back_to_the_device_row_when_the_engine_omits_it(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine(blast={2: {"offline": [], "degraded": [], "unaffected": [],
                                                      "services_lost": [], "headline": "Nothing depends on it.",
                                                      "confidence": "inferred", "evidence": None}}))
    data = body(client_for(seeded).get("/api/map/blast/2"))
    assert data["device"]["id"] == 2 and data["device"]["ip"] == "192.168.1.40"


# --------------------------------------------------------------------------- GET /api/map/criticality


def test_criticality_is_ranked_most_load_bearing_first(client, engine):
    data = body(client.get("/api/map/criticality"))
    assert [row["device_id"] for row in data["criticality"]] == [1, 4, 2]
    assert data["criticality"][0]["dependents"] == 3
    assert data["criticality"][0]["why"]
    assert data["note"] == webapi.MAP_NOTE


def test_criticality_limit_is_honoured(client, engine):
    assert len(body(client.get("/api/map/criticality?limit=1"))["criticality"]) == 1


# --------------------------------------------------------------------------- GET /api/map/outages


def test_outages_list_their_members_newest_first(client, engine):
    data = body(client.get("/api/map/outages"))
    assert [o["id"] for o in data["outages"]] == [2, 1]
    latest, older = data["outages"]
    assert latest["ongoing"] is True and latest["ended_at"] is None
    assert {m["device_id"] for m in latest["members"]} == {3, 4}
    assert older["trigger_device_id"] == 1 and older["trigger_kind"] == "gateway"
    assert older["trigger_label"] == "Router"
    assert older["cycle_seconds"] == 600
    assert {m["label"] for m in older["members"]} == {"laptop", "Printer", "Hall camera"}


def test_outages_state_the_resolution_and_the_note(client, engine):
    """C3: the resolution is per outage, from the cadence recorded with that one.

    A single top-level sentence built from today's ``schedule.discovery_minutes`` was stamped
    over every row, so an outage recorded at a 60-minute cadence was reported at 10-minute
    resolution. ``resolution_now`` still answers "what is the cadence today", which is a
    different question and is labelled as one.
    """
    data = body(client.get("/api/map/outages"))
    assert "same discovery cycle" in data["resolution_now"]
    assert "not 'within seconds'" in data["resolution_now"]
    assert data["note"] == webapi.MAP_NOTE
    for outage in data["outages"]:
        minutes = outage["cycle_seconds"] // 60
        assert f"{minutes}-minute discovery cycle" in outage["resolution"]
        assert "not \"within seconds\"" in outage["resolution"]


def test_an_outage_recorded_at_another_cadence_reports_its_own_resolution(seeded, engine):
    """The bug this pair exists for: today's config must not overwrite what was recorded."""
    core_db.write(seeded, "UPDATE outages SET cycle_seconds = 3600")
    core_db.set_setting(seeded, "schedule.discovery_minutes", "10")
    data = body(client_for(seeded).get("/api/map/outages"))
    assert data["outages"], "the fixture records outages"
    for outage in data["outages"]:
        assert "60-minute discovery cycle" in outage["resolution"]
    assert "every 10 minutes" in data["resolution_now"]


def test_outages_limit_is_honoured(client, engine):
    assert len(body(client.get("/api/map/outages?limit=1"))["outages"]) == 1


def test_outages_is_empty_not_an_error_before_the_tables_exist(conn, no_engine):
    seed(conn, outages=False)
    r = client_for(conn).get("/api/map/outages")
    assert r.status_code == 200
    assert body(r)["outages"] == []


# --------------------------------------------------------------------------- no topology package


@pytest.mark.parametrize("path", ["/api/map", "/api/map/blast/1", "/api/map/criticality"])
def test_map_routes_are_503_without_the_topology_package(seeded, no_engine, path):
    r = client_for(seeded).get(path)
    assert r.status_code == 503
    data = body(r)
    assert data["code"] == "topology_unavailable"
    assert "homesoc.topology" in data["error"]
    assert data["note"] == webapi.MAP_NOTE  # the caveat survives the failure


@pytest.mark.parametrize("path", ["/api/map", "/api/map/blast/1", "/api/map/criticality"])
def test_a_broken_engine_is_503_not_a_500(seeded, monkeypatch, path):
    """One package failing degrades its own panel; the traceback goes to the log, not the client."""
    install_engine(monkeypatch, FakeEngine(raises=RuntimeError("boom")))
    r = client_for(seeded).get(path)
    assert r.status_code == 503
    data = body(r)
    assert data["code"] == "topology_error"
    assert "RuntimeError" in data["error"] and "boom" not in data["error"]
    assert data["note"] == webapi.MAP_NOTE


def test_an_engine_missing_a_function_is_503(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine(), only=("build_graph",))
    r = client_for(seeded).get("/api/map/criticality")
    assert r.status_code == 503
    assert "criticality()" in body(r)["error"]
    assert client_for(seeded).get("/api/map").status_code == 200  # the half it does have still works


def test_the_rest_of_the_api_is_unaffected_without_topology(seeded, no_engine):
    c = client_for(seeded)
    assert c.get("/api/summary").status_code == 200
    assert c.get("/api/devices").status_code == 200


# --------------------------------------------------------------------------- authorisation


def test_map_needs_the_dashboard_token_when_one_is_set(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine())
    c = client_for(seeded, web_token="s3cret")
    for path in ("/api/map", "/api/map/blast/1", "/api/map/criticality", "/api/map/outages"):
        r = c.get(path, environ_base=LAN)
        assert r.status_code == 401, path
        assert body(r)["error"] == "unauthorized"
    ok = c.get("/api/map", headers={"X-Token": "s3cret"}, environ_base=LAN)
    assert ok.status_code == 200


def test_a_lens_token_does_not_open_the_dashboard_token_gate(seeded, monkeypatch):
    """A Lens token is not a dashboard credential: /api/map is not a self-authenticating Lens path."""
    install_engine(monkeypatch, FakeEngine())
    token = paired(seeded)
    c = client_for(seeded, web_token="s3cret")
    r = c.get("/api/map", headers={"X-Lens-Token": token}, environ_base=LAN)
    assert r.status_code == 401


@pytest.mark.parametrize("path", ["/api/map", "/api/map/blast/1", "/api/map/criticality", "/api/map/outages"])
def test_a_lens_token_is_refused_on_the_map_even_with_no_dashboard_token(seeded, monkeypatch, path):
    """The read-only phone is told where its answer lives instead of being handed the whole map."""
    install_engine(monkeypatch, FakeEngine())
    token = paired(seeded)
    c = client_for(seeded)
    r = c.get(path, headers={"X-Lens-Token": token}, environ_base=LAN)
    assert r.status_code == 403
    data = body(r)
    assert data["code"] == "dashboard_only"
    assert "/api/lens/device/" in data["error"]


def test_the_owner_at_the_desktop_may_read_the_map_while_carrying_a_lens_token(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine())
    token = paired(seeded)
    c = client_for(seeded, web_token="s3cret")
    r = c.get("/api/map", headers={"X-Lens-Token": token, "X-Token": "s3cret"}, environ_base=LAN)
    assert r.status_code == 200


def test_a_phone_still_gets_the_blast_radius_of_the_device_it_identified(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine())
    token = paired(seeded)
    c = client_for(seeded)
    r = c.get("/api/lens/device/1", headers={"X-Lens-Token": token}, environ_base=LAN)
    assert r.status_code == 200
    assert body(r)["blast"]["headline"].startswith("If the router fails")


def test_map_responses_are_not_cached(client, engine):
    assert client.get("/api/map").headers["Cache-Control"] == "no-store"


# --------------------------------------------------------------------------- Lens integration (C7)


def test_lens_device_gains_a_small_blast_section(seeded, engine):
    payload = lensmod.lens_device(seeded, 1)
    blast = payload["blast"]
    assert set(blast) == {"headline", "offline_count", "degraded_count", "confidence", "evidence", "note"}
    assert blast["offline_count"] == 0 and blast["degraded_count"] == 3
    assert blast["confidence"] == "observed"
    assert "same discovery cycle" in blast["evidence"]
    assert blast["note"] == webapi.MAP_NOTE


def test_lens_blast_does_not_carry_the_member_lists(seeded, engine):
    """The phone fetches this on every identification; it gets counts, not three device lists."""
    blast = lensmod.lens_device(seeded, 1)["blast"]
    assert "degraded" not in blast and "unaffected" not in blast
    assert len(json.dumps(blast)) < 1200


def test_lens_blast_is_none_without_the_topology_package(seeded, no_engine):
    payload = lensmod.lens_device(seeded, 1)
    assert "blast" in payload  # the key is always there
    assert payload["blast"] is None
    assert payload["posture"]["headline"]  # the rest of the overlay is untouched


def test_a_broken_engine_costs_lens_only_the_blast_section(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine(raises=RuntimeError("engine exploded")))
    payload = lensmod.lens_device(seeded, 4)
    assert payload["blast"] is None
    assert payload["device"]["id"] == 4
    assert payload["services"] == [] or isinstance(payload["services"], list)


def test_lens_blast_reaches_the_phone_over_the_api(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine())
    token = paired(seeded)
    r = client_for(seeded).get("/api/lens/device/3", headers={"X-Lens-Token": token}, environ_base=LAN)
    assert body(r)["blast"]["headline"].startswith("Nothing else on the network depends")


# --------------------------------------------------------------------------- the defining constraint
#
# Home SOC has no packet visibility. These are the tests that say so.


def test_a_printer_is_a_provider_with_no_consumer_edges(client, engine):
    """C2 rule 5: absent evidence, a provider sprouts no edges to everyone who might print."""
    data = body(client.get("/api/map"))
    provider = next(n for n in data["nodes"] if n["kind"] == "provider")
    assert provider["sublabel"] == "no confirmed consumers"
    assert [e for e in data["edges"] if e["dst"] == provider["id"]] == []
    assert provider["depended_on_by"] == 0
    assert data["counts"]["providers_without_consumers"] == 1


def test_an_observed_edge_with_no_evidence_is_downgraded_not_served_as_observed(seeded, monkeypatch):
    bogus = [Edge("device:2", "device:3", "smb", "tcp", "observed", "", 0)]
    install_engine(monkeypatch, FakeEngine(edges=EDGES + bogus))
    data = body(client_for(seeded).get("/api/map"))
    edge = next(e for e in data["edges"] if e["dst"] == "device:3" and e["edge_type"] == "smb")
    assert edge["confidence"] == "inferred"
    assert "nothing recorded behind it" in edge["evidence"]
    assert data["counts"]["edges_downgraded"] == 1


def test_an_edge_with_a_confidence_the_legend_cannot_explain_is_dropped(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine(
        edges=EDGES + [Edge("device:2", "device:3", "smb", "tcp", "probably", "a hunch", 0)]))
    data = body(client_for(seeded).get("/api/map"))
    assert [e for e in data["edges"] if e["edge_type"] == "smb"] == []
    assert data["counts"]["edges_dropped"] == 1


def test_an_edge_to_a_node_that_is_not_in_the_payload_is_dropped(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine(
        edges=EDGES + [Edge("device:2", "device:99", "gateway", None, "inferred", "ghost", 0)]))
    data = body(client_for(seeded).get("/api/map"))
    assert [e for e in data["edges"] if e["dst"] == "device:99"] == []
    assert data["counts"]["edges_dropped"] == 1


def test_a_cloud_edge_keeps_the_count_that_justifies_it(client, engine):
    edge = next(e for e in body(client.get("/api/map"))["edges"] if e["dst"] == "cloud:ring.com")
    assert edge["confidence"] == "observed" and edge["observed_count"] == 31
    assert "lookups of ring.com" in edge["evidence"]


def test_confidence_and_evidence_are_never_flattened_away(client, engine):
    """A client must be able to sort observed from inferred without asking a second question."""
    edges = body(client.get("/api/map"))["edges"]
    observed = [e for e in edges if e["confidence"] == "observed"]
    inferred = [e for e in edges if e["confidence"] == "inferred"]
    assert observed and inferred
    assert all(e["evidence"] for e in observed + inferred)


# --------------------------------------------------------------------------- XSS
#
# A nickname, an mDNS service name and an evidence line all come off the network, so all three are
# hostile text. The rule this module lives by (and states at the top of lens.py) is that it emits
# plain text as *data* and each consumer escapes for its own medium: the JSON here carries the
# string byte-for-byte, inside a JSON string, under a content type no browser will render as
# markup. So these tests pin two things — the value survives intact for the caller to escape, and
# the response can never be treated as a document.


def assert_inert_json(response) -> dict:
    """The response is JSON a browser will not render, whatever the strings inside it say."""
    assert response.headers["Content-Type"].startswith("application/json")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
    return json.loads(response.data)  # and it is still parseable JSON: nothing broke out


def test_a_hostile_nickname_travels_as_json_data_not_markup(seeded, monkeypatch):
    webapi.write(seeded, "UPDATE devices SET nickname=? WHERE id=3", (XSS,))
    nodes = [n for n in NODES if n.id != "device:3"]
    nodes.append(Node("device:3", "device", XSS, XSS, 3, 0, None, True))
    install_engine(monkeypatch, FakeEngine(nodes=nodes))
    r = client_for(seeded).get("/api/map")
    data = assert_inert_json(r)
    node = next(n for n in data["nodes"] if n["id"] == "device:3")
    assert node["label"] == XSS and node["sublabel"] == XSS  # carried verbatim, for the UI to escape


def test_a_hostile_nickname_in_an_outage_member_is_json_too(seeded, engine):
    webapi.write(seeded, "UPDATE devices SET nickname=? WHERE id=3", (XSS,))
    r = client_for(seeded).get("/api/map/outages")
    data = assert_inert_json(r)
    assert any(m["label"] == XSS for o in data["outages"] for m in o["members"])


def test_a_hostile_evidence_string_is_json_too(seeded, monkeypatch):
    install_engine(monkeypatch, FakeEngine(
        edges=[Edge("device:2", "device:1", "gateway", None, "observed", XSS, 2)]))
    r = client_for(seeded).get("/api/map")
    assert assert_inert_json(r)["edges"][0]["evidence"] == XSS


# --------------------------------------------------------------------------- the real engine
#
# Everything above pins the contract with a fake, deliberately. This group runs the same
# assertions against whatever ``homesoc.topology`` is actually installed, and skips while that
# package is still being built — so the day it lands, these start proving that the two halves
# agree without anyone having to remember to come back.


@pytest.fixture
def real_engine(seeded):
    try:
        webapi.map_graph(seeded, hours=24)
    except Exception as exc:  # noqa: BLE001 - incomplete or absent: nothing to integrate with yet
        pytest.skip(f"homesoc.topology cannot answer yet ({type(exc).__name__}: {exc})")
    return seeded


def test_the_real_engine_meets_the_api_contract(real_engine):
    data = body(client_for(real_engine).get("/api/map"))
    assert data["note"] == webapi.MAP_NOTE
    ids = [n["id"] for n in data["nodes"]]
    assert len(ids) == len(set(ids)), "node ids must be unique"
    # Nothing the engine produced had to be thrown away by the normalisation above.
    assert data["counts"]["edges_dropped"] == 0
    assert data["counts"]["edges_downgraded"] == 0
    for edge in data["edges"]:
        assert edge["confidence"] in webapi.MAP_CONFIDENCES
        assert edge["src"] in ids and edge["dst"] in ids
        if edge["confidence"] == "observed":
            assert edge["evidence"] or edge["observed_count"] > 0


def test_the_real_engine_is_deterministic_through_the_api(real_engine):
    c = client_for(real_engine)
    assert body(c.get("/api/map"))["nodes"] == body(c.get("/api/map"))["nodes"]
    assert body(c.get("/api/map"))["edges"] == body(c.get("/api/map"))["edges"]


def test_the_real_engine_gives_lens_and_the_map_the_same_headline(real_engine):
    over_http = body(client_for(real_engine).get("/api/map/blast/1"))
    on_the_phone = lensmod.lens_device(real_engine, 1)["blast"]
    assert on_the_phone is not None
    assert on_the_phone["headline"] == over_http["headline"][:webapi.BLAST_TEXT_LIMIT]
    assert on_the_phone["offline_count"] == over_http["counts"]["offline"]
    assert on_the_phone["degraded_count"] == over_http["counts"]["degraded"]


def test_the_real_engine_invents_no_consumers_for_a_printer(real_engine):
    """The seeded printer advertises _printer._tcp and nothing was ever seen printing to it."""
    data = body(client_for(real_engine).get("/api/map"))
    for node in data["nodes"]:
        if node["kind"] == "provider":
            assert node["depended_on_by"] == 0 or any(
                e["confidence"] == "observed" for e in data["edges"] if e["dst"] == node["id"]
            ), f"{node['id']} gained a consumer edge with no observation behind it"


# --------------------------------------------------------------------------- helpers, directly


def test_map_edge_normalises_a_plain_dict_as_well_as_a_dataclass():
    edge, reason = webapi.map_edge({"src": "a", "dst": "b", "edge_type": "dns", "protocol": None,
                                    "confidence": "OBSERVED", "evidence": " 4 queries ", "observed_count": "4"})
    assert reason is None
    assert edge == {"src": "a", "dst": "b", "edge_type": "dns", "protocol": None,
                    "confidence": "observed", "evidence": "4 queries", "observed_count": 4}


def test_map_edge_without_endpoints_is_dropped():
    assert webapi.map_edge({"src": "", "dst": "b", "confidence": "inferred"}) == (None, "dropped")


def test_map_node_without_an_id_is_dropped():
    assert webapi.map_node({"kind": "device", "label": "nameless"}) is None


def test_map_legend_is_a_copy_callers_cannot_corrupt():
    first = webapi.map_legend()
    first["confidence"][0]["line"] = "mutated"
    assert webapi.map_legend()["confidence"][0]["line"] != "mutated"


def test_blast_summary_rejects_an_absurd_device_id(seeded, engine):
    assert webapi.blast_summary(seeded, 2**70) is None
    assert webapi.blast_summary(seeded, 0) is None
