"""The dependency map page and its panels (SPEC addendum C7, package T3-graph-ui).

What these tests are really defending is the one property the feature lives or dies by: the page
must never show a relationship Home SOC did not establish, and must always say so. So alongside
the ordinary "does it render" checks there are tests that the honesty note is on every surface,
that a provider with no evidence of consumers grows no consumer edges, that every edge keeps the
confidence it arrived with, and that a device nicknamed with an HTML payload comes back as text.

``homesoc.topology`` is owned by another package and is stubbed through ``sys.modules`` here, in
both directions: a fake engine (so the assertions are about *this* package's rendering, whatever
the engine happens to produce today) and a missing one (``None`` in ``sys.modules`` makes
``import_module`` raise ImportError, which is exactly what an install without it looks like).
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from homesoc.web import api as webapi
from homesoc.web import app as appmod
from homesoc.web import create_app

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "homesoc" / "web" / "templates"
STATIC = ROOT / "homesoc" / "web" / "static"
XSS = "<img src=x onerror=alert(1)>"
TOPOLOGY_MODULES = ("homesoc.topology", "homesoc.topology.graph", "homesoc.topology.outages")


def _now(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")


def make_cfg(**over) -> SimpleNamespace:
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test", timezone="local", log_level="INFO"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token="", refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=[]),
        dns=SimpleNamespace(enabled=False, listen="0.0.0.0", port=53, upstreams=[], log_queries=True),
        schedule=SimpleNamespace(discovery_minutes=10),
        topology=SimpleNamespace(
            enabled=True,
            window_hours=over.get("window_hours", 168),
            include_cloud=over.get("include_cloud", True),
            min_outage_members=3,
            criticality_alert=5,
        ),
    )


def fresh_conn() -> sqlite3.Connection:
    from homesoc import db as core_db

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    core_db.init_schema(conn)
    return conn


def seed(conn: sqlite3.Connection) -> None:
    """Three devices: a gateway, one nicknamed with an HTML payload, and one offline."""
    now = _now()
    conn.execute(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online) "
        "VALUES(1,'00:11:22:00:00:01','192.168.1.1','gateway.lan','Example','router','Home router',1,?,?,1)", (now, now))
    conn.execute(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online) "
        "VALUES(2,'00:11:22:00:00:02','192.168.1.20','printer','Example','printer',?,0,?,?,1)", (XSS, now, now))
    conn.execute(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online) "
        "VALUES(3,'00:11:22:00:00:03','192.168.1.30','tablet','Example','tablet','Kitchen tablet',0,?,?,0)", (now, now))
    conn.execute("INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(1,'192.168.1.1',?,'arp')", (now,))
    conn.commit()


# --------------------------------------------------------------------------- the stub engine


def node(node_id, kind, label, **kw):
    return SimpleNamespace(
        id=node_id, kind=kind, label=label, sublabel=kw.get("sublabel"),
        device_id=kw.get("device_id"), criticality=kw.get("criticality", 0),
        severity=kw.get("severity"), online=kw.get("online", True),
    )


def edge(src, dst, edge_type, confidence, evidence="", protocol=None, observed_count=0):
    return SimpleNamespace(src=src, dst=dst, edge_type=edge_type, protocol=protocol,
                           confidence=confidence, evidence=evidence, observed_count=observed_count)


#: A graph with one of everything the page has to draw honestly: a gateway every device reaches
#: the internet through (inferred), one DNS edge that really was watched (observed), a printer
#: that advertises printing with **no consumer edge at all**, and a domain that was only ever
#: blocked. The device labelled with the XSS payload is the one carrying the observed edges.
NODES = [
    node("internet", "internet", "The internet", sublabel="everything beyond the router"),
    node("resolver", "resolver", "Home SOC DNS filter", sublabel="1 device seen using it", criticality=1),
    node("device:1", "device", "Home router", device_id=1, criticality=2, severity="critical", sublabel="192.168.1.1"),
    node("device:2", "device", XSS, device_id=2, criticality=0, severity="medium", sublabel="192.168.1.20"),
    node("device:3", "device", "Kitchen tablet", device_id=3, criticality=0, online=False, sublabel="192.168.1.30"),
    node("provider:2:printing", "provider", "Printing", device_id=2,
         sublabel="on " + XSS + " — no confirmed consumers"),
    node("cloud:example.com", "cloud", "Example", criticality=1, sublabel="example.com"),
    node("cloud:tracker.example", "cloud", "tracker.example", criticality=1,
         sublabel="tracker.example — blocked by the DNS filter"),
]
EDGES = [
    edge("device:1", "internet", "internet", "inferred", "devices reach the internet only through the gateway"),
    edge("device:2", "device:1", "gateway", "inferred", "the default route for this subnet"),
    edge("device:3", "device:1", "gateway", "inferred", "the default route for this subnet"),
    edge("device:2", "resolver", "dns", "observed", "31 lookups answered in the last 7 days", "dns", 31),
    edge("provider:2:printing", "device:2", "hosted_by", "observed", "advertises _printer._tcp", None, 1),
    edge("device:2", "cloud:example.com", "cloud", "observed", "9 lookups answered in the last 7 days", "dns", 9),
    edge("device:2", "cloud:tracker.example", "cloud_blocked", "observed",
         "12 lookups in the last 7 days, all blocked by the DNS filter — asked for, not depended on", "dns", 12),
]
BLAST = {
    1: {
        "device": {"id": 1, "label": "Home router"},
        "offline": [],
        "degraded": [{"device_id": 2, "label": XSS, "why": "loses its route to the internet"},
                     {"device_id": 3, "label": "Kitchen tablet", "why": "loses its route to the internet"}],
        "unaffected": [],
        "services_lost": ["internet access for 2 devices", "printing (no confirmed consumers)"],
        "headline": "If Home router fails, 2 devices lose their internet connection. They stay on the local network.",
        "confidence": "inferred",
        "evidence": None,
    },
    2: {
        "device": {"id": 2, "label": XSS},
        "offline": [],
        "degraded": [],
        "unaffected": [{"device_id": 1, "label": "Home router"}, {"device_id": 3, "label": "Kitchen tablet"}],
        "services_lost": ["printing (no confirmed consumers)"],
        "headline": "If this printer fails, nothing else stops working: nothing has been seen using it.",
        "confidence": "observed",
        "evidence": "Seen twice: on 3 September and 11 September, it went offline in the same discovery cycle.",
    },
}
CRITICALITY = [
    {"device_id": 1, "label": "Home router", "dependents": 2, "weight": 2.0,
     "why": "It is the way off the local network; 2 devices depend on it"},
    {"device_id": 2, "label": XSS, "dependents": 0, "weight": 0.5, "why": "It offers printing"},
]


@pytest.fixture
def engine(monkeypatch):
    """Install a fake ``homesoc.topology`` for the duration of one test."""
    mod = types.ModuleType("homesoc.topology")
    mod.build_graph = lambda conn, hours=168, include_cloud=True: (
        list(NODES) if include_cloud else [n for n in NODES if n.kind != "cloud"],
        list(EDGES) if include_cloud else [e for e in EDGES if not e.edge_type.startswith("cloud")],
    )
    mod.criticality = lambda conn: [dict(r) for r in CRITICALITY]
    mod.blast_radius = lambda conn, device_id: BLAST.get(int(device_id), {
        "device": {}, "offline": [], "degraded": [], "unaffected": [], "services_lost": [],
        "headline": "", "confidence": "inferred", "evidence": None})
    monkeypatch.setitem(sys.modules, "homesoc.topology", mod)
    return mod


@pytest.fixture
def no_engine(monkeypatch):
    """What an install without the topology package looks like to ``importlib``."""
    for name in TOPOLOGY_MODULES:
        monkeypatch.setitem(sys.modules, name, None)


@pytest.fixture
def conn():
    c = fresh_conn()
    yield c
    c.close()


@pytest.fixture
def client(conn):
    app = create_app(make_cfg(), conn)
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def seeded_client(conn):
    seed(conn)
    app = create_app(make_cfg(), conn)
    app.config["TESTING"] = True
    return app.test_client()


def embedded_map(html: str) -> dict:
    """The JSON the page hands to graph.js."""
    match = re.search(r'<script type="application/json" id="initial-map">(.*?)</script>', html, re.S)
    assert match, "the map page did not embed its payload"
    return json.loads(match.group(1))


# --------------------------------------------------------------------------- rendering


@pytest.mark.parametrize("path", ["/", "/map", "/devices/1"])
def test_touched_pages_render_on_an_empty_database(client, no_engine, path):
    """No devices, no topology package: still a page, still 200, never a traceback."""
    r = client.get(path if path != "/devices/1" else "/")
    assert r.status_code == 200
    assert b"Home SOC Test" in r.data


@pytest.mark.parametrize("path", ["/", "/map", "/devices/1", "/devices/2", "/devices/3", "/map?hours=24&cloud=0"])
def test_touched_pages_render_with_data(seeded_client, engine, path):
    r = seeded_client.get(path)
    assert r.status_code == 200, path
    assert r.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert r.headers["X-Frame-Options"] == "DENY"


def test_map_page_renders_the_graph_it_was_given(seeded_client, engine):
    payload = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    assert [n["id"] for n in payload["nodes"]] == [n.id for n in NODES]
    assert len(payload["edges"]) == len(EDGES)
    assert payload["available"] is True


def test_nav_has_the_map(seeded_client, engine):
    html = seeded_client.get("/").get_data(as_text=True)
    assert 'href="/map"' in html and "Dependency map" in html


def test_map_page_links_its_own_stylesheet_and_renderer(seeded_client, engine):
    html = seeded_client.get("/map").get_data(as_text=True)
    assert "/static/map.css" in html
    assert "/static/graph.js" in html


def test_map_css_is_linked_from_the_map_page_only(seeded_client, engine):
    """It is an extra stylesheet, not a second shared one: no other page may pull it in."""
    for path in ("/", "/devices/1", "/devices/2", "/findings", "/devices"):
        assert "map.css" not in seeded_client.get(path).get_data(as_text=True), path


# --------------------------------------------------------------------------- honesty


def test_the_note_is_on_every_surface(seeded_client, engine):
    """SPEC C7: said plainly, once, wherever a user would otherwise expect flows."""
    sentence = "no packet visibility"
    for path in ("/map", "/devices/1", "/"):
        html = seeded_client.get(path).get_data(as_text=True)
        assert sentence in html, path
    assert "/docs/TOPOLOGY.md" in seeded_client.get("/map").get_data(as_text=True)


def test_the_note_is_not_hidden_behind_a_disclosure(seeded_client, engine):
    """It must be ordinary page text, not a <details> the reader can leave closed."""
    html = seeded_client.get("/map").get_data(as_text=True)
    opening = html[html.index('<p class="map-note"'):]
    assert "<details" not in opening[:900]
    assert " hidden" not in opening[: opening.index(">") + 1]   # not hidden by default
    assert "display:none" not in opening[:900]


def test_legend_explains_all_three_confidences_in_one_line_each(seeded_client, engine):
    html = seeded_client.get("/map").get_data(as_text=True)
    for word, style in (("Observed", "solid"), ("Inferred", "dashed"), ("Assumed", "dotted")):
        assert word in html, word
        assert f"({style} line)" in html, style
    # and the style is named in words, so confidence never rides on colour alone
    assert "conf-observed" in html and "conf-inferred" in html and "conf-assumed" in html


def test_severity_is_not_conveyed_by_colour_alone(seeded_client, engine):
    """The letter inside each node is the severity; the legend has to say so."""
    html = seeded_client.get("/map").get_data(as_text=True)
    assert "C H M L i" in html
    assert "SEV_LETTER" in (STATIC / "graph.js").read_text(encoding="utf-8")


def test_a_provider_with_no_evidence_gets_no_consumer_edges(seeded_client, engine):
    """The negative case this whole feature exists for (SPEC C2.5/C9)."""
    payload = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    provider = "provider:2:printing"
    assert any(n["id"] == provider for n in payload["nodes"])
    incoming = [e for e in payload["edges"] if e["dst"] == provider]
    assert incoming == [], f"the page invented consumers for a provider: {incoming}"
    # its only edge is the one the engine gave: the provider depends on the device hosting it
    outgoing = [e for e in payload["edges"] if e["src"] == provider]
    assert [e["dst"] for e in outgoing] == ["device:2"]


def test_every_edge_keeps_its_confidence_and_evidence(seeded_client, engine):
    payload = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    for sent, drawn in zip(EDGES, payload["edges"]):
        assert drawn["confidence"] == sent.confidence
        assert drawn["edge_type"] == sent.edge_type
        assert drawn["evidence"] == sent.evidence
    assert {e["confidence"] for e in payload["edges"]} <= {"observed", "inferred", "assumed"}


def test_a_blocked_lookup_is_still_marked_as_blocked(seeded_client, engine):
    """C2.4: recorded, but never allowed to read as a dependency. The renderer needs the
    edge_type to draw it differently, so the payload must carry it through untouched."""
    payload = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    blocked = [e for e in payload["edges"] if e["edge_type"] == "cloud_blocked"]
    assert len(blocked) == 1
    assert "not depended on" in blocked[0]["evidence"]
    graph_js = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "cloud_blocked" in graph_js and "is-blocked" in graph_js


def test_layout_is_deterministic(seeded_client, engine):
    """C9: the same data must produce the same picture. The page's half of that is handing the
    renderer the same node and edge order every time; graph.js's half is having no randomness."""
    first = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    second = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    assert first["nodes"] == second["nodes"]
    assert first["edges"] == second["edges"]
    graph_js = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "Math.random" not in graph_js
    assert "Date.now" not in graph_js


# --------------------------------------------------------------------------- blast radius


def test_blast_is_embedded_only_when_the_api_cannot_serve_it(seeded_client, engine, monkeypatch):
    with_api = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    assert "blast" not in with_api, "the page shipped blast radii the API was going to serve"

    monkeypatch.setattr(appmod, "_has_blast_api", lambda app: False)
    without = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    assert set(without["blast"]) == {"1", "2", "3"}
    assert without["blast"]["1"]["headline"].startswith("If Home router fails")
    assert without["blast"]["1"]["counts"] == {"offline": 0, "degraded": 2, "unaffected": 0}


def test_device_panel_has_the_three_sections(seeded_client, engine):
    html = seeded_client.get("/devices/1").get_data(as_text=True)
    assert "Depends on" in html and "Depended on by" in html and "If this fails" in html
    assert "If Home router fails" in html
    assert "2 degraded" in html


def test_device_panel_names_the_evidence_or_says_there_is_none(seeded_client, engine):
    inferred = seeded_client.get("/devices/1").get_data(as_text=True)
    assert "not from a failure Home SOC has watched" in inferred
    observed = seeded_client.get("/devices/2").get_data(as_text=True)
    assert "Seen twice" in observed


def test_device_panel_says_no_confirmed_consumers(seeded_client, engine):
    """Device 3 has nothing depending on it, and the panel must say so in those words."""
    html = seeded_client.get("/devices/3").get_data(as_text=True)
    assert "No confirmed consumers" in html
    assert "will not guess" in html


def test_overview_card_ranks_the_load_bearing_devices(seeded_client, engine):
    html = seeded_client.get("/").get_data(as_text=True)
    assert "Load-bearing devices" in html
    assert "It is the way off the local network" in html
    assert html.index("Home router") < html.index("It is the way off the local network")


# --------------------------------------------------------------------------- degradation


def test_map_page_without_the_topology_package_explains_itself(seeded_client, no_engine):
    r = seeded_client.get("/map")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "homesoc.topology package is missing" in html or "not available" in html
    assert "no packet visibility" in html          # the note survives an empty map
    assert "Traceback" not in html


def test_panels_without_the_topology_package_explain_themselves(seeded_client, no_engine):
    device = seeded_client.get("/devices/1").get_data(as_text=True)
    assert "Depends on" in device
    overview = seeded_client.get("/").get_data(as_text=True)
    assert "Load-bearing devices" in overview
    assert "topology job" in overview


def test_a_broken_engine_does_not_500_the_page(seeded_client, monkeypatch):
    mod = types.ModuleType("homesoc.topology")

    def boom(*a, **kw):
        raise RuntimeError("engine exploded")

    mod.build_graph = boom
    mod.criticality = boom
    mod.blast_radius = boom
    monkeypatch.setitem(sys.modules, "homesoc.topology", mod)
    for path in ("/map", "/devices/1", "/"):
        r = seeded_client.get(path)
        assert r.status_code == 200, path
        assert b"engine exploded" not in r.data          # the traceback goes to the log, not the page


# --------------------------------------------------------------------------- XSS (SPEC C9)


@pytest.mark.parametrize("path", ["/map", "/devices/2", "/"])
def test_a_device_nicknamed_with_html_renders_escaped(seeded_client, engine, path):
    html = seeded_client.get(path).get_data(as_text=True)
    assert XSS not in html, f"{path} wrote an unescaped payload into the document"
    # the tag can never begin: no unescaped '<' arrives from a device nickname
    assert "<img" not in html.lower(), f"{path} let a tag out of a device nickname"
    # ...and it is there, escaped, so the owner still reads back what they typed
    assert "&lt;img src=x onerror=alert(1)&gt;" in html or "\\u003cimg" in html


def test_the_payload_survives_as_text_in_the_map_data(seeded_client, engine):
    """Escaped, but not mangled: the user must still see the nickname they typed."""
    payload = embedded_map(seeded_client.get("/map").get_data(as_text=True))
    labels = [n["label"] for n in payload["nodes"]]
    assert XSS in labels
    assert any(n["id"] == "device:2" and n["label"] == XSS for n in payload["nodes"])


def test_the_renderer_names_every_confidence_the_engine_can_report():
    """`assumed` used to print as "Inferred", beside a sentence defining *inferred*.

    It is reachable on any install that leaves ``network.gateway`` at "auto": ``gateway_device``
    returns 'assumed' and the blast radius inherits it. So the weakest level in the vocabulary
    the legend explains three lines above was shown as the middle one, and map.css had no rule
    for it either, so the colour cue silently fell back too.
    """
    source = (STATIC / "graph.js").read_text(encoding="utf-8")
    css = (STATIC / "map.css").read_text(encoding="utf-8")
    for level, word in (("observed", "Observed"), ("mixed", "Partly observed"),
                        ("inferred", "Inferred"), ("assumed", "Assumed")):
        assert f"{level}: '{word}'" in source, level
        assert f"CONF_FALLBACK.{level}" in source or f"{level}: '" in source
        assert f".map-evidence.conf-box-{level}" in css, level
    # 'assumed' gets its own sentence rather than borrowing the definition of 'inferred'.
    assert "Nothing has confirmed this" in source


def test_a_blocked_domain_is_never_counted_as_a_dependent():
    """C2.4, in the renderer. graph.py keeps ``cloud_blocked`` out of DEPENDENCY_EDGE_TYPES;
    graph.js built its own counter and excluded only ``hosted_by``, so a blocked domain's
    tooltip and accessible name read "7 devices depend on it · asked for and refused by the DNS
    filter — not a dependency" — and for a screen-reader user the false half was the only thing
    said about the node. The same count sized the node, under a legend reading "bigger means
    more depends on it"."""
    source = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "e.edge_type !== 'hosted_by' && !isBlockedEdge(e)" in source
    assert "and refused — not a dependency" in source
    assert "(n.blocked || isBlockedOnly(n, edges))" in source, "a refused lookup must not size the node"


def test_the_hub_note_keys_off_something_the_payload_actually_carries():
    """C2.6's statement could never render: the note filtered for ``kind === 'hub'`` and the
    engine emits hubs as ``Node("provider:<id>:hub", "provider", ...)``. ``api.MAP_NODE_KINDS``
    has no "hub" entry at all, so the paragraph stayed hidden, the hexagon was never drawn, and
    a Zigbee bridge looked exactly like an AirPlay service."""
    source = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "n.kind === 'hub'" not in source, "no payload has ever carried that kind"
    assert "/:hub$/.test(String(n.id))" in source
    assert "n.__hub" in source
    assert "not on the IP network" in source


def test_a_service_is_not_dimmed_while_the_panel_says_it_is_lost():
    """The blast payload lists devices only, so a provider hosted on the failing device was
    given ``is-dim`` while the panel beside it listed the same service under "What the house
    loses". The picture and the text must not contradict each other."""
    source = (STATIC / "graph.js").read_text(encoding="utf-8")
    css = (STATIC / "map.css").read_text(encoding="utf-8")
    assert "e.edge_type === 'hosted_by' && set[e.dst]" in source
    assert "'lost'" in source and "is-lost" in source
    assert ".map-node.is-affected.is-lost" in css


def test_the_spec_phrase_and_the_offline_word_survive_truncation():
    """Two claims the map makes about its own labels, both of which used to be cut off.

    C2.5's "no confirmed consumers" lived inside a longer sublabel that truncated to "on
    MacBook Air — no …", and was only drawn at all above a row height an expanded cloud column
    never reaches. And map.html's legend says the word "offline" is in the node's own label:
    it was only in the tooltip, and appending it naively left "Nintendo Switch…" for exactly
    the long names most likely to be cut.
    """
    source = (STATIC / "graph.js").read_text(encoding="utf-8")
    html = (TEMPLATES / "map.html").read_text(encoding="utf-8")
    assert "orphanText = orphan ? 'no confirmed consumers' : null" in source
    assert "(orphanText || lay.rowStep >= 28)" in source, "the phrase must not depend on row height"
    assert "MAX_SUBLABEL" in source and "fitText(subText, 9, MAX_SUBLABEL)" in source
    # The name is truncated to make room for the suffix, never the other way round.
    assert "MAX_LABEL - textWidth(OFFLINE_SUFFIX, LABEL_SIZE)) + OFFLINE_SUFFIX" in source
    assert "(offline)" in html, "the legend describes what is actually drawn"


def test_the_legend_only_promises_evidence_the_shipped_code_can_produce(seeded_client, engine):
    """The legend is the user's key for reading the picture.

    It advertised UPnP port mappings, SSDP advertisements and a DHCP-assigned resolver. There
    is no UPnP source in ``infer.EDGE_SOURCES``; ``mdns_types`` reads the "mdns" key and
    discards "ssdp"; and ``dns_edges``' own docstring explains that the DHCP half of C2.3 is
    deliberately not emitted because Home SOC cannot read DHCP options. Those belong in
    docs/TOPOLOGY.md's "what would make this better", and are there now.
    """
    lines = {c["key"]: c["line"] for c in webapi.map_legend()["confidence"]}
    for line in lines.values():
        assert "UPnP" not in line and "SSDP" not in line and "DHCP" not in line
    assert "advertised over mDNS" in lines["observed"]
    assert "DNS query" in lines["observed"] and "same discovery cycle" in lines["observed"]
    assert "default gateway" in lines["inferred"]

    page = seeded_client.get("/map").get_data(as_text=True)
    assert "UPnP" not in page and "DHCP" not in page

    doc = (ROOT / "docs" / "TOPOLOGY.md").read_text(encoding="utf-8")
    made_better = doc.split("What would make this map dramatically better")[-1]
    assert "UPnP" in made_better and "DHCP lease file" in made_better


def test_the_renderer_never_builds_dom_from_strings():
    """CSP is default-src 'self' and the map draws database text: textContent only, always."""
    graph_js = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "innerHTML" not in graph_js
    assert "outerHTML" not in graph_js
    assert "insertAdjacentHTML" not in graph_js
    assert "document.write" not in graph_js
    assert "eval(" not in graph_js
    assert not re.search(r"\bon(click|error|load|mouse\w+)\s*=", graph_js)


def test_the_map_page_has_no_inline_script_or_handler(seeded_client, engine):
    html = seeded_client.get("/map").get_data(as_text=True)
    for script in re.findall(r"<script(?![^>]*application/json)[^>]*>(.*?)</script>", html, re.S):
        assert script.strip() == "", "inline script on a default-src 'self' page"
    assert not re.search(r"<[^>]+\son(click|change|error|load)=", html)
    assert "javascript:" not in html


# --------------------------------------------------------------------------- the linked document


def test_the_why_document_is_served(seeded_client, engine):
    r = seeded_client.get("/docs/TOPOLOGY.md")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/plain")
    body = r.get_data(as_text=True)
    assert "packet" in body.lower() or "traffic" in body.lower()


def test_only_the_allowlisted_document_is_served(seeded_client, engine):
    for name in ("SPEC.md", "../config.toml", "..%2fconfig.toml", "homesoc.db"):
        assert seeded_client.get(f"/docs/{name}").status_code in (301, 308, 404), name


def test_the_document_link_answers_even_when_the_file_is_absent(seeded_client, engine, monkeypatch):
    monkeypatch.setattr(appmod, "DOC_PAGES", {"TOPOLOGY.md": "NO_SUCH_DOC.md"})
    r = seeded_client.get("/docs/TOPOLOGY.md")
    assert r.status_code == 200
    assert "packet capture" in r.get_data(as_text=True)


# --------------------------------------------------------------------------- keyboard / a11y


def test_nodes_are_focusable_and_keyboard_operable():
    graph_js = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "tabindex" in graph_js
    assert "role: 'button'" in graph_js
    assert "'aria-label'" in graph_js
    for key in ("ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Enter", "Escape"):
        assert key in graph_js, key


def test_the_graph_is_one_tab_stop_not_forty():
    """Roving tabindex: every node is reachable, but Tab does not walk through all of them."""
    graph_js = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "rovingId" in graph_js
    assert "setRoving" in graph_js
    assert "state.rovingId ? '0' : '-1'" in graph_js


def test_the_panel_is_a_live_region(seeded_client, engine):
    html = seeded_client.get("/map").get_data(as_text=True)
    assert 'aria-live="polite"' in html
