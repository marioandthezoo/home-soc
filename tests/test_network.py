"""Offline tests for the P3-network package (discovery, ports, nmap_xml, services, exposure, mdns_ssdp, wifi).

P1 (core) may not have landed ``homesoc.models`` / ``homesoc.db`` / ``homesoc.util``
yet when this file runs, so minimal stand-ins matching SPEC sections 4-5 are
installed *only if* the real modules are missing.  Nothing here touches the
network beyond 127.0.0.1.
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import socket
import sqlite3
import sys
import threading
import time
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "nmap"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------------- P1 stand-ins (test only)

def _install_stubs() -> None:
    import importlib

    try:
        importlib.import_module("homesoc.models")
    except ImportError:
        from dataclasses import dataclass, field

        m = types.ModuleType("homesoc.models")

        @dataclass
        class Device:
            id: int | None
            mac: str
            ip: str
            hostname: str | None
            vendor: str | None
            kind: str | None
            first_seen: str
            last_seen: str
            online: bool
            trusted: bool = False
            nickname: str | None = None

        @dataclass
        class Service:
            device_id: int
            port: int
            proto: str
            state: str
            name: str | None
            product: str | None
            version: str | None
            extrainfo: str | None
            cpe: str | None
            tunnel: str | None

        @dataclass
        class FindingDraft:
            finding_id: str
            subject: str
            evidence: dict = field(default_factory=dict)
            detail: str | None = None
            severity: str | None = None
            device_id: int | None = None

        @dataclass
        class ScanResult:
            kind: str
            findings: list
            summary: dict
            error: str | None = None

        m.Device, m.Service, m.FindingDraft, m.ScanResult = Device, Service, FindingDraft, ScanResult
        m.SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
        sys.modules["homesoc.models"] = m

    try:
        importlib.import_module("homesoc.util")
    except ImportError:
        from datetime import datetime, timezone

        u = types.ModuleType("homesoc.util")
        u.utcnow_iso = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sys.modules["homesoc.util"] = u

    try:
        importlib.import_module("homesoc.db")
    except ImportError:
        d = types.ModuleType("homesoc.db")
        lock = threading.Lock()

        def write(conn, sql, params=()):
            with lock:
                cur = conn.execute(sql, params)
                conn.commit()
                return cur.lastrowid

        def writemany(conn, sql, seq):
            with lock:
                conn.executemany(sql, seq)
                conn.commit()

        def query(conn, sql, params=()):
            return conn.execute(sql, params).fetchall()

        def one(conn, sql, params=()):
            return conn.execute(sql, params).fetchone()

        def set_setting(conn, key, value):
            write(conn, "INSERT INTO settings(key, value, updated_at) VALUES (?,?,datetime('now')) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                  (key, value))

        def get_setting(conn, key, default=None):
            row = one(conn, "SELECT value FROM settings WHERE key=?", (key,))
            return row["value"] if row else default

        def record_metric(conn, name, value, tags=None):
            write(conn, "INSERT INTO metrics(ts, name, value, tags) VALUES (datetime('now'),?,?,?)",
                  (name, float(value), json.dumps(tags) if tags else None))

        def record_event(conn, level, source, message, data=None):
            write(conn, "INSERT INTO events(ts, level, source, message, data) VALUES (datetime('now'),?,?,?,?)",
                  (level, source, message, json.dumps(data) if data else None))

        d.write, d.writemany, d.query, d.one = write, writemany, query, one
        d.set_setting, d.get_setting, d.record_metric, d.record_event = set_setting, get_setting, record_metric, record_event
        sys.modules["homesoc.db"] = d


_install_stubs()

from homesoc import db  # noqa: E402
from homesoc.models import Device, Service  # noqa: E402
from homesoc.scanners import discovery, exposure, mdns_ssdp, nmap_xml, ports, services, wifi  # noqa: E402

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT, hostname TEXT, vendor TEXT,
  kind TEXT, nickname TEXT, trusted INTEGER NOT NULL DEFAULT 0, notes TEXT, first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL, online INTEGER NOT NULL DEFAULT 1, last_service_scan TEXT, mdns_services TEXT);
CREATE TABLE IF NOT EXISTS device_sightings(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
  ip TEXT NOT NULL, seen_at TEXT NOT NULL, method TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
  port INTEGER NOT NULL, proto TEXT NOT NULL DEFAULT 'tcp', state TEXT NOT NULL, name TEXT, product TEXT, version TEXT,
  extrainfo TEXT, cpe TEXT, tunnel TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(device_id, port, proto));
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT NOT NULL,
  message TEXT NOT NULL, data TEXT);
CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, tags TEXT);
"""


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    initialised = False
    if hasattr(db, "init_schema"):
        try:
            db.init_schema(c)
            initialised = True
        except Exception:
            initialised = False
    if not initialised:
        c.executescript(_SCHEMA)
    yield c
    c.close()


def make_cfg(**over):
    network = SimpleNamespace(
        cidr="192.168.1.0/24", gateway="192.168.1.254", exclude=[],
        fragile_vendors=["Sonos", "Philips", "Hue", "Ring", "Nest", "Ecobee", "Roku", "Epson", "Brother", "Canon", "HP"],
        discovery_ports=[80, 443, 22, 445], discovery_threads=8, discovery_timeout=0.05,
    )
    scan = SimpleNamespace(use_nmap=True, nmap_top_ports=100, nmap_timing="T3", version_detection=True,
                           gentle_top_ports=25, per_host_timeout_sec=180, max_parallel_hosts=3, scan_gateway=True)
    schedule = SimpleNamespace(discovery_minutes=10)
    cfg = SimpleNamespace(network=network, scan=scan, schedule=schedule)
    for k, v in over.items():
        section, key = k.split("__")
        setattr(getattr(cfg, section), key, v)
    return cfg


def dev(mac="aa:bb:cc:dd:ee:01", ip="192.168.1.50", hostname=None, vendor=None, kind=None, id=1):
    return Device(id=id, mac=mac, ip=ip, hostname=hostname, vendor=vendor, kind=kind,
                  first_seen="2026-09-04T00:00:00Z", last_seen="2026-09-04T00:00:00Z", online=True)


def svc(port, name=None, product=None, version=None, extrainfo=None, tunnel=None, state="open", device_id=1):
    return Service(device_id=device_id, port=port, proto="tcp", state=state, name=name or ports.PORT_NAMES.get(port),
                   product=product, version=version, extrainfo=extrainfo, cpe=None, tunnel=tunnel)


def ids(drafts):
    return sorted(d.finding_id for d in drafts)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# =========================================================================== nmap_xml

class TestNmapXml:
    def test_router_fixture(self):
        hosts = nmap_xml.parse((FIXTURES / "router.xml").read_text(encoding="utf-8"))
        assert len(hosts) == 1
        h = hosts[0]
        assert h["ip"] == "192.168.1.254" and h["partial"] is False and h["status"] == "up"
        open_ports = {p["port"]: p for p in h["ports"] if p["state"] == "open"}
        assert set(open_ports) == {53, 80, 443}
        assert open_ports[53]["product"] == "Unbound" and open_ports[53]["version"] == "1.18.0"
        assert open_ports[53]["cpe"] == "cpe:/a:nlnetlabs:unbound:1.18.0"
        assert open_ports[443]["tunnel"] == "ssl" and open_ports[80]["product"] == "lighttpd"
        assert len(h["ports"]) == 20

    def test_printer_fixture(self):
        h = nmap_xml.parse((FIXTURES / "printer.xml").read_text(encoding="utf-8"))[0]
        assert h["mac"] == "00:22:33:00:00:08" and h["vendor"] == "Example Print Systems"
        assert h["hostnames"] == ["printer.lan"]
        assert {p["port"] for p in h["ports"] if p["state"] == "open"} == {80, 443, 631, 9100}
        ipp = next(p for p in h["ports"] if p["port"] == 631)
        assert ipp["product"] == "CUPS" and ipp["extrainfo"] == "EX-1200 Series"

    def test_partial_fixture_keeps_completed_ports(self):
        text = (FIXTURES / "partial.xml").read_text(encoding="utf-8")
        assert "</nmaprun>" not in text
        hosts = nmap_xml.parse(text)
        assert len(hosts) == 1
        h = hosts[0]
        assert h["partial"] is True and h["ip"] == "192.168.1.89" and h["vendor"] == "Example Storage Systems"
        assert {p["port"] for p in h["ports"]} == {22, 23, 445, 5000, 5432}

    def test_garbage_and_empty(self):
        assert nmap_xml.parse("") == []
        assert nmap_xml.parse("   \n") == []
        assert nmap_xml.parse("<<<not xml") == []
        assert nmap_xml.parse("<nmaprun><host><address addr='1.2.3.4' addrtype='ipv4'/><ports><port protocol='tcp' portid='x'/>")[0]["ports"] == []

    def test_bom_tolerated(self):
        text = chr(0xFEFF) + (FIXTURES / "router.xml").read_text(encoding="utf-8")
        assert nmap_xml.parse(text)[0]["ip"] == "192.168.1.254"

    def test_host_timeout_is_not_an_all_closed_answer(self):
        # nmap marks a host that hit --host-timeout with timedout="true" and emits no <ports>.
        # Treating that as "every port is closed" closed every service and auto-resolved every
        # NET-SVC finding for the device, so it must come back partial.
        h = nmap_xml.parse(
            '<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/>'
            '<address addr="192.168.1.89" addrtype="ipv4"/></host></nmaprun>'
        )[0]
        assert h["ip"] == "192.168.1.89" and h["ports"] == []
        assert h["timedout"] is True and h["partial"] is True

    def test_timed_out_host_keeps_the_ports_it_did_manage(self):
        h = nmap_xml.parse(
            '<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/>'
            '<address addr="192.168.1.89" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>'
            '<service name="ssh"/></port></ports></host></nmaprun>'
        )[0]
        assert [p["port"] for p in h["ports"]] == [22]
        assert h["timedout"] is True and h["partial"] is True

    def test_host_without_a_ports_section_is_partial(self):
        # -Pn on a host that never answered: nmap closes <host> cleanly but says nothing about ports.
        h = nmap_xml.parse(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="192.168.1.42" addrtype="ipv4"/></host></nmaprun>'
        )[0]
        assert h["timedout"] is False and h["partial"] is True

    def test_empty_ports_section_is_a_complete_all_closed_answer(self):
        h = nmap_xml.parse(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="192.168.1.42" addrtype="ipv4"/><ports/></host></nmaprun>'
        )[0]
        assert h["ports"] == [] and h["partial"] is False


# =========================================================================== services

class TestServiceRules:
    def _from_fixture(self, name, **devkw):
        h = nmap_xml.parse((FIXTURES / name).read_text(encoding="utf-8"))[0]
        d = dev(mac=h["mac"] or "aa:bb:cc:dd:ee:ff", ip=h["ip"], vendor=h["vendor"],
                hostname=(h["hostnames"] or [None])[0], **devkw)
        s = [svc(p["port"], p["name"], p["product"], p["version"], p["extrainfo"], p["tunnel"], p["state"]) for p in h["ports"]]
        return d, s

    def test_printer_fixture_rules(self):
        d, s = self._from_fixture("printer.xml")
        drafts = services.evaluate(d, s)
        assert ids(drafts) == ["NET-SVC-008", "NET-SVC-008", "NET-SVC-012"]
        protocols = {x.evidence["protocol"] for x in drafts if x.finding_id == "NET-SVC-008"}
        assert protocols == {"raw9100", "ipp"}
        assert all(x.subject.startswith("device:00:22:33:00:00:08") for x in drafts)
        assert services.device_kind(d, s) == "printer"

    def test_router_fixture_is_quiet(self):
        d, s = self._from_fixture("router.xml", kind="router")
        assert services.evaluate(d, s) == []  # HTTPS present, so no NET-SVC-005

    def test_nas_fixture_rules(self):
        d, s = self._from_fixture("partial.xml")
        got = ids(services.evaluate(d, s))
        assert got == ["NET-SVC-001", "NET-SVC-003", "NET-SVC-005", "NET-SVC-007", "NET-SVC-011", "NET-SVC-012"]
        assert services.device_kind(d, s) == "nas"

    def test_smb_quiet_on_windows(self):
        d = dev(hostname="DESKTOP-4F2K", vendor="Intel Corporate")
        s = [svc(135), svc(139), svc(445)]
        assert services.evaluate(d, s) == []
        d2 = dev(vendor="Intel Corporate")
        assert services.evaluate(d2, [svc(135), svc(445)]) == []          # port hint 135+445
        d3 = dev(vendor="Intel Corporate")
        assert ids(services.evaluate(d3, [svc(445)])) == ["NET-SVC-003"]  # lone SMB on unknown box

    def test_remote_access_and_media(self):
        d = dev()
        drafts = services.evaluate(d, [svc(3389), svc(5900), svc(554), svc(23), svc(21)])
        assert ids(drafts) == ["NET-SVC-001", "NET-SVC-002", "NET-SVC-004", "NET-SVC-004", "NET-SVC-010"]
        assert {x.evidence.get("protocol") for x in drafts if x.finding_id == "NET-SVC-004"} == {"rdp", "vnc"}

    def test_database_upnp_snmp(self):
        d = dev()
        drafts = services.evaluate(d, [
            svc(6379), svc(27017), svc(49152, name="upnp", product="Portable SDK for UPnP devices"),
            svc(161, name="snmp", extrainfo="community: public"),
        ])
        assert ids(drafts) == ["NET-SVC-006", "NET-SVC-007", "NET-SVC-007", "NET-SVC-009"]

    def test_http_without_https_only_on_embedded(self):
        router = dev(hostname="gateway.lan", vendor="Example Networks")
        assert ids(services.evaluate(router, [svc(80)])) == ["NET-SVC-005"]
        assert services.evaluate(router, [svc(80), svc(443)]) == []
        laptop = dev(hostname="DESKTOP-1", vendor="Intel Corporate")
        assert services.evaluate(laptop, [svc(80)]) == []

    def test_ssh_version_threshold(self):
        d = dev()
        assert ids(services.evaluate(d, [svc(22, product="OpenSSH", version="7.9p1")])) == ["NET-SVC-011"]
        assert services.evaluate(d, [svc(22, product="OpenSSH", version="9.3")]) == []
        assert services.evaluate(d, [svc(22, product="OpenSSH")]) == []
        assert ids(services.evaluate(d, [svc(22, product="Dropbear sshd", version="2019.78")])) == ["NET-SVC-011"]

    def test_closed_services_ignored(self):
        assert services.evaluate(dev(), [svc(23, state="closed")]) == []

    def test_device_kind_keywords_are_token_bounded(self):
        assert services.device_kind(dev(hostname="Matts-iPhone", vendor="Apple, Inc.")) == "apple"
        assert services.device_kind(dev(hostname="nasa-laptop")) == "unknown"
        assert services.device_kind(dev(vendor="QNAP Systems, Inc.")) == "nas"
        assert services.device_kind(dev(hostname="living-room-cam")) == "camera"
        assert services.device_kind(dev(kind="router", vendor="Brother Industries")) == "router"
        assert services.device_kind(dev(kind="randomized", vendor="Brother Industries")) == "printer"
        assert services.device_kind(dev(vendor="Google, Inc.", hostname="Pixel-8")) == "android"

    def test_fragile_and_gentle(self):
        fragile = ["Brother", "HP", "Sonos"]
        assert services.is_fragile(dev(vendor="Brother Industries"), fragile)
        assert services.is_fragile(dev(vendor="HP Inc."), fragile)
        assert not services.is_fragile(dev(vendor="Shp Labs"), fragile)
        assert services.wants_gentle(dev(hostname="garage-camera"), fragile)
        assert services.wants_gentle(dev(vendor="Sonos, Inc."), fragile)
        assert not services.wants_gentle(dev(hostname="DESKTOP-1", vendor="Intel Corporate"), fragile)


# =========================================================================== discovery helpers

NEIGHBOR_JSON = json.dumps([
    {"IPAddress": "239.255.255.250", "LinkLayerAddress": "01-00-5E-7F-FF-FA", "State": 6},
    {"IPAddress": "192.168.1.255", "LinkLayerAddress": "FF-FF-FF-FF-FF-FF", "State": 6},
    {"IPAddress": "192.168.1.254", "LinkLayerAddress": "00-11-22-00-00-01", "State": 5},
    {"IPAddress": "192.168.1.120", "LinkLayerAddress": "02-33-44-00-00-0E", "State": 4},
    {"IPAddress": "192.168.235.144", "LinkLayerAddress": "00-44-55-00-00-AB", "State": 4},
    {"IPAddress": "224.0.0.251", "LinkLayerAddress": "", "State": 6},
    {"IPAddress": "192.168.1.9", "LinkLayerAddress": "00-11-22-33-44-55", "State": "Reachable"},
])
ARP_WINDOWS = """
Interface: 192.168.1.105 --- 0x14
  Internet Address      Physical Address      Type
  192.168.1.65          02-44-55-00-00-18     dynamic
  192.168.1.254         00-11-22-00-00-01     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 192.168.224.1 --- 0x2e
  192.168.235.144       00-44-55-00-00-ab     dynamic
"""
ARP_MAC = """? (192.168.1.1) at 0:55:66:9:2:1 on en0 ifscope [ethernet]
? (192.168.1.73) at 0:22:33:0:0:8 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
"""


class TestDiscoveryHelpers:
    def test_normalize_mac(self):
        assert discovery.normalize_mac("00-11-22-00-00-01") == "00:11:22:00:00:01"
        assert discovery.normalize_mac("0011.2200.0001") == "00:11:22:00:00:01"
        assert discovery.normalize_mac("0:55:66:9:2:1") == "00:55:66:09:02:01"
        assert discovery.normalize_mac("") is None and discovery.normalize_mac("zz") is None

    def test_mac_bits(self):
        assert discovery.is_unicast_mac("00:11:22:00:00:01")
        assert not discovery.is_unicast_mac("01:00:5e:00:00:fb")
        assert not discovery.is_unicast_mac("ff:ff:ff:ff:ff:ff")
        assert discovery.is_randomized_mac("02:11:22:00:00:01")
        assert discovery.is_randomized_mac("02:33:44:00:00:0e")
        assert not discovery.is_randomized_mac("00:11:22:00:00:01")

    def test_parse_neighbor_json(self):
        rows = discovery.parse_neighbor_json(NEIGHBOR_JSON)
        by_ip = {r.ip: r for r in rows}
        assert by_ip["192.168.1.254"].mac == "00:11:22:00:00:01" and by_ip["192.168.1.254"].state == "Reachable"
        assert by_ip["192.168.1.120"].state == "Stale" and by_ip["192.168.1.9"].state == "Reachable"
        assert "224.0.0.251" not in by_ip  # empty MAC dropped
        single = discovery.parse_neighbor_json('{"IPAddress":"192.168.1.5","LinkLayerAddress":"00-11-22-33-44-55","State":5}')
        assert len(single) == 1 and single[0].ip == "192.168.1.5"
        assert discovery.parse_neighbor_json("") == [] and discovery.parse_neighbor_json("nope") == []

    def test_parse_arp_a(self):
        win = {r.ip: r for r in discovery.parse_arp_a(ARP_WINDOWS)}
        assert win["192.168.1.65"].mac == "02:44:55:00:00:18" and win["192.168.1.65"].state == "Stale"
        assert win["192.168.1.255"].state == "Permanent"
        mac = {r.ip: r for r in discovery.parse_arp_a(ARP_MAC)}
        assert mac["192.168.1.1"].mac == "00:55:66:09:02:01" and "192.168.1.99" not in mac

    def test_parse_ip_neigh(self):
        j = json.dumps([{"dst": "192.168.1.1", "dev": "wlan0", "lladdr": "aa:bb:cc:dd:ee:ff", "state": ["REACHABLE"]},
                        {"dst": "192.168.1.2", "dev": "wlan0", "state": ["FAILED"]}])
        rows = discovery.parse_ip_neigh(j)
        assert [(r.ip, r.mac, r.state) for r in rows] == [("192.168.1.1", "aa:bb:cc:dd:ee:ff", "Reachable")]
        text = "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff STALE\n192.168.1.3 dev wlan0  FAILED\n"
        rows = discovery.parse_ip_neigh(text)
        assert len(rows) == 1 and rows[0].state == "Stale"

    def test_read_neighbors_filters_to_cidr_and_unicast(self, monkeypatch):
        monkeypatch.setattr(discovery, "_raw_neighbors", lambda: (discovery.parse_neighbor_json(NEIGHBOR_JSON), "test"))
        got = discovery.read_neighbors(ipaddress.ip_network("192.168.1.0/24"))
        assert set(got) == {"192.168.1.254", "192.168.1.120", "192.168.1.9"}

    def test_sweep_localhost(self):
        port = _free_port()
        closed = _free_port()
        srv = socket.socket()
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        try:
            res = discovery.sweep(ipaddress.ip_network("127.0.0.1/32"), [port, closed], threads=4, timeout=0.5)
        finally:
            srv.close()
        assert res["127.0.0.1"]["open"] == [port] and res["127.0.0.1"]["alive"] is True

    def test_sweep_respects_exclude_and_deadline(self):
        net = ipaddress.ip_network("127.0.0.1/32")
        assert discovery.sweep(net, [9], exclude=["127.0.0.1"]) == {}
        assert discovery.sweep(net, [9], max_seconds=0) == {}

    def test_resolve_network_and_gateway(self, monkeypatch):
        monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
        assert str(discovery.resolve_network(make_cfg())) == "192.168.1.0/24"
        assert str(discovery.resolve_network(make_cfg(network__cidr="auto"))) == "192.168.1.0/24"
        assert str(discovery.resolve_network(make_cfg(network__cidr="garbage"))) == "192.168.1.0/24"
        net = discovery.resolve_network(make_cfg())
        assert discovery.default_gateway(make_cfg(), net) == "192.168.1.254"
        assert discovery.default_gateway(make_cfg(network__gateway="10.0.0.1"), net) is None

    def test_kind_hint_from_mdns(self):
        assert discovery.kind_hint_from_mdns(["_ipp._tcp.local", "_http._tcp.local"]) == "printer"
        assert discovery.kind_hint_from_mdns(["_googlecast._tcp.local"]) == "iot"
        assert discovery.kind_hint_from_mdns(["_http._tcp.local"]) is None


# =========================================================================== discovery.run

def _patch_discovery_env(monkeypatch, neighbors, swept=None, names=None, vendors=None):
    monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
    monkeypatch.setattr(discovery, "local_mac", lambda ip: "02:11:22:00:00:01")
    monkeypatch.setattr(discovery, "default_gateway", lambda cfg, net: "192.168.1.254")
    monkeypatch.setattr(discovery, "read_neighbors", lambda net: dict(neighbors))
    monkeypatch.setattr(discovery, "sweep", lambda *a, **k: dict(swept or {}))
    monkeypatch.setattr(discovery, "resolve_hostnames", lambda ips, timeout=1.0: dict(names or {}))
    monkeypatch.setattr(discovery, "_probe_mdns", lambda ip: {"192.168.1.73": {"mdns": ["_ipp._tcp.local"], "ssdp": [], "names": ["printer"]}})
    monkeypatch.setattr(discovery, "_lookup_vendor", lambda mac: (vendors or {}).get(mac))


NEIGHBORS = {
    "192.168.1.254": discovery.Neighbor("192.168.1.254", "00:11:22:00:00:01", "Reachable"),
    "192.168.1.73": discovery.Neighbor("192.168.1.73", "00:22:33:00:00:08", "Stale"),
    "192.168.1.120": discovery.Neighbor("192.168.1.120", "02:33:44:00:00:0e", "Stale"),
}
VENDORS = {"00:11:22:00:00:01": "Example Networks", "00:22:33:00:00:08": "Example Print Systems"}


class TestDiscoveryRun:
    def test_first_run_creates_devices_and_findings(self, conn, monkeypatch):
        _patch_discovery_env(monkeypatch, NEIGHBORS, swept={"192.168.1.50": {"open": [80], "alive": True}},
                             names={"192.168.1.254": "gateway.lan"}, vendors=VENDORS)
        msgs = []
        res = discovery.run(make_cfg(), conn, progress=msgs.append)
        assert res.error is None and res.kind == "discovery"
        assert res.summary["hosts_online"] == 5 and res.summary["hosts_new"] == 5 and res.summary["hosts_total"] == 5
        assert res.summary["method"] == "arp+tcp" and msgs
        rows = {r["mac"]: r for r in db.query(conn, "SELECT * FROM devices")}
        assert rows["00:11:22:00:00:01"]["hostname"] == "gateway.lan" and rows["00:11:22:00:00:01"]["kind"] == "router"
        assert rows["00:22:33:00:00:08"]["hostname"] == "printer" and rows["00:22:33:00:00:08"]["kind"] == "printer"
        assert json.loads(rows["00:22:33:00:00:08"]["mdns_services"])["mdns"] == ["_ipp._tcp.local"]
        assert rows["02:33:44:00:00:0e"]["kind"] == "randomized"
        assert rows["ip:192.168.1.50"]["ip"] == "192.168.1.50"
        assert rows["02:11:22:00:00:01"]["kind"] == "self"
        new = [f for f in res.findings if f.finding_id == "NET-DEV-001"]
        assert {f.subject for f in new} == {"device:00:11:22:00:00:01", "device:00:22:33:00:00:08",
                                            "device:02:33:44:00:00:0e", "device:ip:192.168.1.50"}
        unknown = [f for f in res.findings if f.finding_id == "NET-DEV-002"]
        assert {f.evidence["reason"] for f in unknown} == {"randomized_mac"}
        assert all(f.device_id for f in new)
        assert db.one(conn, "SELECT COUNT(*) AS n FROM device_sightings")["n"] == 5
        assert db.one(conn, "SELECT value FROM metrics WHERE name='discovery.hosts_online'")["value"] == 5.0

    def test_second_run_is_stable_and_marks_offline(self, conn, monkeypatch):
        _patch_discovery_env(monkeypatch, NEIGHBORS, vendors=VENDORS)
        discovery.run(make_cfg(), conn)
        db.write(conn, "UPDATE devices SET last_seen='2020-01-01T00:00:00Z' WHERE mac='02:33:44:00:00:0e'")
        db.write(conn, "UPDATE devices SET trusted=1, last_seen='2020-01-01T00:00:00Z' WHERE mac='00:22:33:00:00:08'")
        gone = {k: v for k, v in NEIGHBORS.items() if k not in ("192.168.1.120", "192.168.1.73")}
        monkeypatch.setattr(discovery, "read_neighbors", lambda net: dict(gone))
        res = discovery.run(make_cfg(), conn)
        assert res.summary["hosts_new"] == 0
        assert not [f for f in res.findings if f.finding_id == "NET-DEV-001"]
        assert db.one(conn, "SELECT online FROM devices WHERE mac='02:33:44:00:00:0e'")["online"] == 0
        assert db.one(conn, "SELECT online FROM devices WHERE mac='00:11:22:00:00:01'")["online"] == 1
        stale = [f for f in res.findings if f.finding_id == "NET-DEV-003"]
        assert len(stale) == 1 and stale[0].subject == "device:00:22:33:00:00:08"

    def test_ip_keyed_placeholder_retired_when_mac_learned(self, conn, monkeypatch):
        _patch_discovery_env(monkeypatch, {}, swept={"192.168.1.50": {"open": [80], "alive": True}})
        discovery.run(make_cfg(), conn)
        assert db.one(conn, "SELECT online FROM devices WHERE mac='ip:192.168.1.50'")["online"] == 1
        _patch_discovery_env(monkeypatch, {"192.168.1.50": discovery.Neighbor("192.168.1.50", "00:11:22:33:44:55", "Reachable")})
        discovery.run(make_cfg(), conn)
        assert db.one(conn, "SELECT online FROM devices WHERE mac='ip:192.168.1.50'")["online"] == 0
        assert db.one(conn, "SELECT online FROM devices WHERE mac='00:11:22:33:44:55'")["online"] == 1

    def test_never_outside_cidr(self, conn, monkeypatch):
        _patch_discovery_env(monkeypatch, {"10.9.9.9": discovery.Neighbor("10.9.9.9", "00:11:22:33:44:99", "Reachable")},
                             swept={"10.9.9.10": {"open": [80], "alive": True}})
        res = discovery.run(make_cfg(), conn)
        assert res.error is None
        ips = {r["ip"] for r in db.query(conn, "SELECT ip FROM devices")}
        assert ips == {"192.168.1.105"}

    def test_failure_becomes_error_not_raise(self, conn, monkeypatch):
        monkeypatch.setattr(discovery, "resolve_network", lambda cfg: (_ for _ in ()).throw(RuntimeError("boom")))
        res = discovery.run(make_cfg(), conn)
        assert res.error and "boom" in res.error and res.findings == []

    @pytest.mark.parametrize("bad_ip", ["127.0.0.1", "169.254.11.9", "0.0.0.0"])
    def test_no_lan_interface_fails_loudly_and_changes_nothing(self, conn, monkeypatch, bad_ip):
        # Wi-Fi not associated yet (Startup-folder autostart, or a resume): local_ip() has no route.
        # Sweeping 127.0.0.0/24 used to rewrite this host's own row to 127.0.0.1 and mark every real
        # device offline while the scans row still said "ok".
        _patch_discovery_env(monkeypatch, NEIGHBORS, vendors=VENDORS)
        discovery.run(make_cfg(), conn)
        before = [dict(r) for r in db.query(conn, "SELECT mac, ip, online FROM devices ORDER BY mac")]
        sightings = db.one(conn, "SELECT COUNT(*) AS n FROM device_sightings")["n"]
        assert before and all(r["online"] == 1 for r in before)

        monkeypatch.setattr(discovery, "local_ip", lambda: bad_ip)
        called = []
        monkeypatch.setattr(discovery, "sweep", lambda *a, **k: called.append("swept") or {})
        res = discovery.run(make_cfg(), conn)
        assert res.error == "no LAN interface (offline?)"
        assert res.findings == [] and res.summary["method"] == "none" and called == []
        after = [dict(r) for r in db.query(conn, "SELECT mac, ip, online FROM devices ORDER BY mac")]
        assert after == before
        assert db.one(conn, "SELECT COUNT(*) AS n FROM device_sightings")["n"] == sightings

    def test_first_run_is_an_info_baseline_later_devices_are_not(self, conn, monkeypatch):
        _patch_discovery_env(monkeypatch, NEIGHBORS, vendors=VENDORS)
        first = discovery.run(make_cfg(), conn)
        baseline = [f for f in first.findings if f.finding_id == "NET-DEV-001"]
        assert len(baseline) == 3 and first.summary["baseline"] is True
        # info instead of the catalog's medium: 17 owned devices would otherwise cost 68 points
        # and show grade F on the very first dashboard.
        assert {f.severity for f in baseline} == {"info"}
        assert all(f.evidence["baseline"] is True for f in baseline)
        assert all("First inventory" in (f.detail or "") for f in baseline)

        later = {**NEIGHBORS, "192.168.1.61": discovery.Neighbor("192.168.1.61", "b8:27:eb:11:22:33", "Reachable")}
        _patch_discovery_env(monkeypatch, later, vendors=VENDORS)
        second = discovery.run(make_cfg(), conn)
        new = [f for f in second.findings if f.finding_id == "NET-DEV-001"]
        assert second.summary["baseline"] is False
        assert [f.subject for f in new] == ["device:b8:27:eb:11:22:33"]
        assert new[0].severity is None and new[0].detail is None  # catalog default (medium)
        assert new[0].evidence["baseline"] is False


# =========================================================================== ports

class TestPortsHelpers:
    def test_top_ports_list(self):
        assert len(ports.TOP_PORTS) == 100 and len(set(ports.TOP_PORTS)) == 100
        assert ports.TOP_PORTS[:5] == (80, 23, 443, 21, 22)

    def test_build_nmap_command_exact(self):
        cfg = make_cfg()
        argv = ports.build_nmap_command("nmap", "192.168.1.254", cfg, gentle=False)
        assert argv == ["nmap", "-sT", "-sV", "--version-light", "-T3", "--top-ports", "100", "-n", "-Pn",
                        "--host-timeout", "180s", "-oX", "-", "192.168.1.254"]
        gentle = ports.build_nmap_command("nmap", "192.168.1.73", cfg, gentle=True)
        assert gentle == ["nmap", "-sT", "-T3", "--top-ports", "25", "-n", "-Pn", "--host-timeout", "180s", "-oX", "-", "192.168.1.73"]
        for flag in ("-O", "-sU", "--script"):
            assert flag not in argv and flag not in gentle
        with pytest.raises(ValueError):
            ports.build_nmap_command("nmap", "192.168.1.1; rm -rf /", cfg, gentle=False)

    def test_timing_never_faster_than_t3(self):
        assert ports.build_nmap_command("nmap", "1.2.3.4", make_cfg(scan__nmap_timing="T5"), gentle=False)[4] == "-T3"
        assert ports.build_nmap_command("nmap", "1.2.3.4", make_cfg(scan__nmap_timing="-T4"), gentle=False)[4] == "-T3"
        assert ports.build_nmap_command("nmap", "1.2.3.4", make_cfg(scan__nmap_timing="T2"), gentle=False)[4] == "-T2"
        assert ports.build_nmap_command("nmap", "1.2.3.4", make_cfg(scan__nmap_timing="weird"), gentle=False)[4] == "-T3"
        no_ver = ports.build_nmap_command("nmap", "1.2.3.4", make_cfg(scan__version_detection=False), gentle=False)
        assert "-sV" not in no_ver

    def test_parse_banner(self):
        ssh = ports.parse_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        assert (ssh["name"], ssh["product"], ssh["version"]) == ("ssh", "OpenSSH", "8.9p1")
        http = ports.parse_banner(80, "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.69\r\nContent-Type: text/html\r\n\r\n")
        assert (http["name"], http["product"], http["version"]) == ("http", "lighttpd", "1.4.69")
        ftp = ports.parse_banner(21, "220 ProFTPD 1.3.5 Server ready\r\n")
        assert (ftp["name"], ftp["product"], ftp["version"]) == ("ftp", "ProFTPD", "1.3.5")
        assert ports.parse_banner(6379, "")["name"] == "redis"

    def test_mysql_greeting(self):
        payload = b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00" + b"\x00" * 10
        info = ports._mysql_greeting(payload)
        assert info["product"] == "MySQL" and info["version"] == "8.0.36-0ubuntu0.22.04.1"

    def test_grab_banner_and_python_scan_localhost(self):
        port = _free_port()
        closed = _free_port()
        srv = socket.socket()
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        stop = threading.Event()

        def serve():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:  # listener closed by the test teardown
                    return
                with c:
                    try:
                        c.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
                    except OSError:
                        pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            info = ports.grab_banner("127.0.0.1", port)
            assert info["product"] == "OpenSSH" and info["version"] == "7.4"
            got = ports.python_scan("127.0.0.1", [port, closed], banners=False, timeout=0.5)
            assert [p["port"] for p in got] == [port] and got[0]["state"] == "open" and got[0]["method"] == "python"
        finally:
            stop.set()
            srv.close()

    def test_python_scan_rejects_bad_ip(self):
        with pytest.raises(ValueError):
            ports.python_scan("not-an-ip", [80])


def _seed_devices(conn, n=8):
    macs = []
    for i in range(n):
        mac = f"00:11:22:33:44:{i:02x}"
        macs.append(mac)
        db.write(conn, "INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen, online) VALUES (?,?,?,?,?,?,1)",
                 (mac, f"192.168.1.{10 + i}", None, None, "2026-09-04T00:00:00Z", f"2026-09-04T00:00:{i:02d}Z"))
    db.write(conn, "INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen, online) VALUES (?,?,?,?,?,?,1)",
             ("00:11:22:00:00:01", "192.168.1.254", "gateway.lan", "Example Networks", "2026-09-04T00:00:00Z", "2026-09-04T00:00:00Z"))
    db.write(conn, "INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen, online) VALUES (?,?,?,?,?,?,1)",
             ("00:22:33:00:00:08", "192.168.1.73", "printer", "Example Print Systems", "2026-09-04T00:00:00Z", "2026-09-04T00:01:00Z"))
    db.write(conn, "INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen, online) VALUES (?,?,?,?,?,?,1)",
             ("02:11:22:00:00:01", "192.168.1.105", "LAPTOP", None, "2026-09-04T00:00:00Z", "2026-09-04T00:09:00Z"))
    db.write(conn, "INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen, online) VALUES (?,?,?,?,?,?,0)",
             ("00:aa:bb:cc:dd:ee", "192.168.1.200", None, None, "2026-09-04T00:00:00Z", "2026-09-04T00:00:00Z"))
    return macs


def _patch_ports_env(monkeypatch, nmap=None):
    monkeypatch.setattr(ports, "find_nmap", lambda: nmap)
    monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
    monkeypatch.setattr(discovery, "default_gateway", lambda cfg, net: "192.168.1.254")


class TestPortsRun:
    def test_select_targets_quick_and_exclusions(self, conn, monkeypatch):
        _seed_devices(conn)
        net = ipaddress.ip_network("192.168.1.0/24")
        full = ports.select_targets(make_cfg(), conn, quick=False, network=net, gateway="192.168.1.254", me="192.168.1.105")
        ips = {d.ip for d in full}
        assert "192.168.1.105" not in ips and "192.168.1.200" not in ips and "192.168.1.254" in ips and len(full) == 10
        quick = ports.select_targets(make_cfg(), conn, quick=True, network=net, gateway="192.168.1.254", me="192.168.1.105")
        assert len(quick) == 6 and quick[0].ip == "192.168.1.254" and quick[0].kind == "router"
        assert quick[1].ip == "192.168.1.73"  # most recently seen after the gateway
        excl = ports.select_targets(make_cfg(network__exclude=["192.168.1.73"], scan__scan_gateway=False), conn,
                                    quick=False, network=net, gateway="192.168.1.254", me="192.168.1.105")
        assert {d.ip for d in excl} & {"192.168.1.73", "192.168.1.254"} == set()
        narrow = ports.select_targets(make_cfg(), conn, quick=False, network=ipaddress.ip_network("192.168.1.72/30"),
                                      gateway=None, me=None)
        assert {d.ip for d in narrow} == {"192.168.1.73"}

    def test_run_upserts_services_and_findings(self, conn, monkeypatch):
        _seed_devices(conn, n=0)
        _patch_ports_env(monkeypatch, nmap=None)
        fixtures = {"192.168.1.254": "router.xml", "192.168.1.73": "printer.xml"}
        gentle_seen = {}

        def fake_scan(cfg, device, *, nmap_path, gentle):
            gentle_seen[device.ip] = gentle
            h = nmap_xml.parse((FIXTURES / fixtures[device.ip]).read_text(encoding="utf-8"))[0]
            return ports.HostScan(device.id, device.ip, h["ports"], "python", gentle)

        monkeypatch.setattr(ports, "_scan_one", fake_scan)
        res = ports.run(make_cfg(), conn, progress=lambda m: None)
        assert res.error is None and res.kind == "services"
        assert res.summary["hosts_scanned"] == 2 and res.summary["services_open"] == 7
        assert gentle_seen == {"192.168.1.254": False, "192.168.1.73": True}
        assert res.summary["gentle_hosts"] == 1
        # SOC-SYS-001 (nmap missing) belongs to cli.soc_health_drafts alone: two sources emitting the same
        # dedupe key with different scopes left the row stuck open after nmap was installed.
        assert "SOC-SYS-001" not in ids(res.findings)
        assert ids(res.findings).count("NET-SVC-008") == 2 and "NET-SVC-012" in ids(res.findings)
        rows = db.query(conn, "SELECT d.ip, s.port, s.state, s.product, s.version, s.tunnel FROM services s JOIN devices d ON d.id=s.device_id ORDER BY d.ip, s.port")
        open_rows = [(r["ip"], r["port"]) for r in rows if r["state"] == "open"]
        assert open_rows == [("192.168.1.254", 53), ("192.168.1.254", 80), ("192.168.1.254", 443),
                             ("192.168.1.73", 80), ("192.168.1.73", 443), ("192.168.1.73", 631), ("192.168.1.73", 9100)]
        unbound = next(r for r in rows if r["port"] == 53)
        assert unbound["product"] == "Unbound" and unbound["version"] == "1.18.0"
        assert all(r["last_service_scan"] for r in db.query(conn, "SELECT last_service_scan FROM devices WHERE ip IN ('192.168.1.254','192.168.1.73')"))

        # Second pass: port 53 vanished -> row kept with state closed; product retained via COALESCE on a gentle pass.
        def fake_scan2(cfg, device, *, nmap_path, gentle):
            h = nmap_xml.parse((FIXTURES / fixtures[device.ip]).read_text(encoding="utf-8"))[0]
            ps = [dict(p, product=None, version=None) for p in h["ports"] if p["port"] != 53]
            return ports.HostScan(device.id, device.ip, ps, "python", True)

        monkeypatch.setattr(ports, "_scan_one", fake_scan2)
        ports.run(make_cfg(), conn)
        row53 = db.one(conn, "SELECT state FROM services WHERE port=53")
        assert row53["state"] == "closed"
        row80 = db.one(conn, "SELECT state, product FROM services s JOIN devices d ON d.id=s.device_id WHERE port=80 AND d.ip='192.168.1.254'")
        assert row80["state"] == "open" and row80["product"] == "lighttpd"

    def test_partial_result_does_not_close_ports(self, conn, monkeypatch):
        _seed_devices(conn, n=0)
        db.write(conn, "DELETE FROM devices WHERE ip != '192.168.1.254'")
        _patch_ports_env(monkeypatch, nmap=None)
        h = nmap_xml.parse((FIXTURES / "router.xml").read_text(encoding="utf-8"))[0]
        monkeypatch.setattr(ports, "_scan_one", lambda cfg, d, *, nmap_path, gentle: ports.HostScan(d.id, d.ip, h["ports"], "nmap", False))
        ports.run(make_cfg(), conn)
        monkeypatch.setattr(ports, "_scan_one", lambda cfg, d, *, nmap_path, gentle: ports.HostScan(d.id, d.ip, [], "nmap", False, partial=True))
        ports.run(make_cfg(), conn)
        assert db.one(conn, "SELECT COUNT(*) AS n FROM services WHERE state='open'")["n"] == 3

    def test_nmap_failure_falls_back_to_python(self, monkeypatch):
        from homesoc.scanners import CommandResult

        monkeypatch.setattr(ports, "run_command", lambda argv, timeout: CommandResult(1, "", "nmap: broken", False, False))
        called = {}

        def fake_python(ip, port_list, **kw):
            called["ip"] = ip
            called["n"] = len(port_list)
            return []

        monkeypatch.setattr(ports, "python_scan", fake_python)
        scan = ports._scan_one(make_cfg(), dev(ip="192.168.1.9"), nmap_path="nmap", gentle=True)
        assert scan.method == "python" and called["ip"] == "192.168.1.9" and called["n"] == 25

    def test_nmap_success_path(self, monkeypatch):
        from homesoc.scanners import CommandResult

        xml = (FIXTURES / "router.xml").read_text(encoding="utf-8")
        monkeypatch.setattr(ports, "run_command", lambda argv, timeout: CommandResult(0, xml, "", False, False))
        scan = ports._scan_one(make_cfg(), dev(ip="192.168.1.254"), nmap_path="nmap", gentle=False)
        assert scan.method == "nmap" and len([p for p in scan.ports if p["state"] == "open"]) == 3 and not scan.partial

    def test_nmap_host_timeout_is_reported_partial(self, monkeypatch):
        from homesoc.scanners import CommandResult

        xml = ('<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/>'
               '<address addr="192.168.1.89" addrtype="ipv4"/></host></nmaprun>')
        monkeypatch.setattr(ports, "run_command", lambda argv, timeout: CommandResult(0, xml, "", False, False))
        scan = ports._scan_one(make_cfg(), dev(ip="192.168.1.89"), nmap_path="nmap", gentle=False)
        assert scan.method == "nmap" and scan.ports == [] and scan.partial is True

    def test_timed_out_host_keeps_services_open_and_is_not_auto_resolvable(self, conn, monkeypatch):
        """A --host-timeout on a slow IoT device must not close every service and hand the caller a
        ``device:`` scope that auto-resolves its NET-SVC findings."""
        from homesoc.scanners import CommandResult

        _seed_devices(conn, n=0)
        db.write(conn, "DELETE FROM devices WHERE ip != '192.168.1.73'")
        _patch_ports_env(monkeypatch, nmap="nmap")
        printer = (FIXTURES / "printer.xml").read_text(encoding="utf-8")
        monkeypatch.setattr(ports, "run_command", lambda argv, timeout: CommandResult(0, printer, "", False, False))
        first = ports.run(make_cfg(), conn)
        assert db.one(conn, "SELECT COUNT(*) AS n FROM services WHERE state='open'")["n"] == 4
        assert first.summary["scopes"] == ["device:00:22:33:00:00:08"]

        timed_out = ('<?xml version="1.0"?><nmaprun><host timedout="true"><status state="up"/>'
                     '<address addr="192.168.1.73" addrtype="ipv4"/></host></nmaprun>')
        monkeypatch.setattr(ports, "run_command", lambda argv, timeout: CommandResult(0, timed_out, "", False, False))
        second = ports.run(make_cfg(), conn)
        assert second.error is None
        assert db.one(conn, "SELECT COUNT(*) AS n FROM services WHERE state='open'")["n"] == 4
        assert second.summary["scopes"] == []  # nothing to auto-resolve: the answer was incomplete

    def test_subprocess_timeout_is_also_partial(self, monkeypatch):
        from homesoc.scanners import CommandResult

        xml = (FIXTURES / "router.xml").read_text(encoding="utf-8")
        monkeypatch.setattr(ports, "run_command", lambda argv, timeout: CommandResult(0, xml, "", timed_out=True))
        scan = ports._scan_one(make_cfg(), dev(ip="192.168.1.254"), nmap_path="nmap", gentle=False)
        assert scan.method == "nmap" and scan.partial is True

    @pytest.mark.parametrize("bad_ip", ["127.0.0.1", "169.254.11.9"])
    def test_no_lan_interface_scans_nothing(self, conn, monkeypatch, bad_ip):
        _seed_devices(conn, n=0)
        _patch_ports_env(monkeypatch, nmap=None)
        monkeypatch.setattr(discovery, "local_ip", lambda: bad_ip)
        monkeypatch.setattr(ports, "_scan_one", lambda *a, **k: pytest.fail("must not scan without a LAN route"))
        res = ports.run(make_cfg(), conn)
        assert res.error == "no LAN interface (offline?)"
        assert res.findings == [] and res.summary["scopes"] == [] and res.summary["method"] == "none"
        assert db.one(conn, "SELECT COUNT(*) AS n FROM services")["n"] == 0


# =========================================================================== exposure

DESC_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <URLBase>http://127.0.0.1:{port}/</URLBase>
 <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList>
     <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
      <controlURL>/ctl/IPConn</controlURL></service>
     <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
      <controlURL>/ctl/L3F</controlURL></service>
     <service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
      <controlURL>http://evil.example.com/ctl</controlURL></service>
    </serviceList></device></deviceList></device></deviceList></device></root>"""
MAPPING_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>{int_}</NewInternalPort><NewInternalClient>192.168.1.50</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{desc}</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""
FAULT_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>713</errorCode>
<errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"""


class _IgdHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep pytest output clean
        pass

    def _send(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/desc.xml":
            self._send(200, DESC_XML.format(port=self.server.server_address[1]))
        else:
            self._send(404, "")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8", "replace")
        if self.path != "/ctl/IPConn":
            self._send(404, "")
            return
        idx = int(body.split("<NewPortMappingIndex>")[1].split("<")[0])
        table = [(22, 22, "ssh"), (32400, 32400, "Plex Media Server")]
        if idx < len(table):
            ext, int_, desc = table[idx]
            self._send(200, MAPPING_XML.format(ext=ext, int_=int_, desc=desc))
        else:
            self._send(500, FAULT_XML)


@pytest.fixture
def igd_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _IgdHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _serve(handler_cls):
    """Start a throwaway loopback HTTP server; yields (port, hits) and shuts it down after."""
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    srv.hits = []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1], srv.hits
    finally:
        srv.shutdown()
        srv.server_close()


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Every request answers 302 to a different host, the way a rogue SSDP responder would."""

    def log_message(self, *a):
        pass

    def _redirect(self):
        self.server.hits.append(self.path)
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:8787/api/scan")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _redirect

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))  # drain, or the client sees a reset
        self._redirect()


class _SlowIgdHandler(http.server.BaseHTTPRequestHandler):
    """A gateway that accepts the connection and answers correctly, but slowly."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.hits.append(self.path)
        time.sleep(0.2)
        data = MAPPING_XML.format(ext=8000 + len(self.server.hits), int_=80, desc="slow").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def redirect_server():
    yield from _serve(_RedirectHandler)


@pytest.fixture
def slow_igd_server():
    yield from _serve(_SlowIgdHandler)


@pytest.fixture
def loopback_is_lan(monkeypatch):
    """exposure now refuses loopback as an IGD address (SSRF fix). These tests use a loopback
    server as a stand-in for a real LAN gateway, so treat 127.0.0.1 as a LAN host for them only."""
    real = exposure._is_lan_address
    monkeypatch.setattr(exposure, "_is_lan_address", lambda host: host == "127.0.0.1" or real(host))


class TestExposure:
    def test_parse_ssdp_response(self):
        text = "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://192.168.1.254:1900/igd.xml\r\nSERVER: Linux UPnP/1.0 MiniUPnPd/2.1\r\nUSN: uuid:1::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        got = exposure.parse_ssdp_response(text)
        assert got["location"] == "http://192.168.1.254:1900/igd.xml" and "MiniUPnPd" in got["server"]
        assert exposure.parse_ssdp_response("NOTIFY * HTTP/1.1\r\n") is None

    def test_parse_mapping_response(self):
        m = exposure.parse_mapping_response(MAPPING_XML.format(ext=8080, int_=80, desc="cam"))
        assert m["external_port"] == 8080 and m["internal_port"] == 80 and m["protocol"] == "TCP"
        assert m["internal_client"] == "192.168.1.50" and m["enabled"] is True and m["description"] == "cam"
        assert exposure.parse_mapping_response(FAULT_XML) is None
        assert exposure.parse_mapping_response("<garbage") is None

    def test_igd_walk_against_local_server(self, igd_server, loopback_is_lan):
        port = igd_server.server_address[1]
        svcs = exposure.igd_services(f"http://127.0.0.1:{port}/desc.xml")
        assert [s["service_type"] for s in svcs] == ["urn:schemas-upnp-org:service:WANIPConnection:1"]  # evil host dropped
        assert svcs[0]["control_url"] == f"http://127.0.0.1:{port}/ctl/IPConn"
        maps = exposure.enumerate_mappings(svcs[0]["control_url"], svcs[0]["service_type"])
        assert [(m["external_port"], m["description"]) for m in maps] == [(22, "ssh"), (32400, "Plex Media Server")]

    def test_private_only(self):
        assert exposure.igd_services("http://8.8.8.8/desc.xml") == []
        assert exposure.enumerate_mappings("http://example.com/ctl", "x") == []

    def test_non_http_schemes_are_refused(self):
        for url in ("file:///c:/windows/win.ini", "ftp://192.168.1.254/x", "gopher://192.168.1.254/"):
            with pytest.raises(ValueError):
                exposure._http(url, timeout=1.0)

    def test_redirects_are_not_followed(self, redirect_server, loopback_is_lan):
        """The SSDP LOCATION is attacker-controlled: following a 302 would let a rogue device aim the
        description GET (and the SOAP POSTs after it) at any host, private-IP check already passed."""
        port, hits = redirect_server
        status, body = exposure._http(f"http://127.0.0.1:{port}/desc.xml", timeout=2.0)
        assert status == 302 and body == b""
        assert hits == ["/desc.xml"]  # the redirect target was never fetched
        assert exposure.igd_services(f"http://127.0.0.1:{port}/desc.xml") == []
        assert exposure.enumerate_mappings(f"http://127.0.0.1:{port}/ctl", "urn:x:WANIPConnection:1") == []
        assert hits == ["/desc.xml", "/desc.xml", "/ctl"]

    def test_enumerate_mappings_stops_at_the_deadline(self, igd_server, loopback_is_lan):
        port = igd_server.server_address[1]
        url = f"http://127.0.0.1:{port}/ctl/IPConn"
        st = "urn:schemas-upnp-org:service:WANIPConnection:1"
        assert exposure.enumerate_mappings(url, st, deadline=time.monotonic() - 1) == []
        assert len(exposure.enumerate_mappings(url, st, deadline=time.monotonic() + 30)) == 2

    def test_enumerate_mappings_gives_up_on_a_slow_gateway(self, slow_igd_server, monkeypatch, loopback_is_lan):
        port, hits = slow_igd_server
        monkeypatch.setattr(exposure, "SLOW_RESPONSE_SEC", 0.05)
        maps = exposure.enumerate_mappings(f"http://127.0.0.1:{port}/ctl", "urn:x:WANIPConnection:1")
        # 100 x 3 s of SOAP would hold the single scheduler thread for minutes.
        assert len(maps) == exposure.MAX_CONSECUTIVE_SLOW == len(hits)

    def test_run_has_a_wall_clock_budget(self, conn, monkeypatch):
        monkeypatch.setattr(exposure, "RUN_BUDGET_SEC", 0.0)
        monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: "203.0.113.5")
        monkeypatch.setattr(exposure, "internetdb", lambda ip, timeout=8.0: {"status": "clean", "ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": [], "error": None})
        monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
        igd = {"location": "http://192.168.1.254:1900/igd.xml", "server": "MiniUPnPd", "st": exposure.IGD_ST, "usn": "", "from": "192.168.1.254"}
        monkeypatch.setattr(exposure, "discover_igd", lambda iface, seconds=3.0: [igd])
        monkeypatch.setattr(exposure, "igd_services", lambda loc, timeout=5.0: [{"service_type": "urn:x:WANIPConnection:1", "control_url": "http://192.168.1.254:1900/ctl"}])
        monkeypatch.setattr(exposure, "enumerate_mappings", lambda *a, **k: pytest.fail("budget exhausted: must not enumerate"))
        res = exposure.run(make_cfg(), conn)
        assert res.error is None and res.summary["partial"] is True and res.summary["mappings"] == []
        assert ids(res.findings) == ["NET-RTR-002"]  # the IGD itself is still reported

    @pytest.mark.parametrize("bad_ip", ["127.0.0.1", "169.254.11.9"])
    def test_run_without_a_lan_interface(self, conn, monkeypatch, bad_ip):
        monkeypatch.setattr(discovery, "local_ip", lambda: bad_ip)
        monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: pytest.fail("no interface: must not go out"))
        res = exposure.run(make_cfg(), conn)
        assert res.error == "no LAN interface (offline?)" and res.findings == []

    def test_internetdb_parsing(self, monkeypatch):
        monkeypatch.setattr(exposure, "_http", lambda url, **k: (404, b'{"detail":"No information available"}'))
        assert exposure.internetdb("203.0.113.5")["status"] == "clean"
        payload = json.dumps({"ip": "203.0.113.5", "ports": [443, 22], "vulns": ["CVE-2023-1"], "cpes": ["cpe:/a:openbsd:openssh"], "hostnames": [], "tags": []}).encode()
        monkeypatch.setattr(exposure, "_http", lambda url, **k: (200, payload))
        got = exposure.internetdb("203.0.113.5")
        assert got["status"] == "exposed" and got["ports"] == [22, 443] and got["vulns"] == ["CVE-2023-1"]
        monkeypatch.setattr(exposure, "_http", lambda url, **k: (503, b"nope"))
        assert exposure.internetdb("203.0.113.5")["status"] == "error"
        bad = exposure.internetdb("not-an-ip")  # never raises: scanners report, they do not crash
        assert bad["status"] == "error" and bad["error"]

    def test_run_findings_and_settings(self, conn, monkeypatch):
        monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: "203.0.113.5")
        monkeypatch.setattr(exposure, "internetdb", lambda ip, timeout=8.0: {"status": "exposed", "ports": [22, 443], "vulns": ["CVE-2024-1234"], "cpes": [], "hostnames": ["h.example"], "tags": [], "error": None})
        monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
        igd = {"location": "http://192.168.1.254:1900/igd.xml", "server": "MiniUPnPd", "st": exposure.IGD_ST, "usn": "", "from": "192.168.1.254"}
        monkeypatch.setattr(exposure, "discover_igd", lambda iface, seconds=3.0: [igd])
        monkeypatch.setattr(exposure, "igd_services", lambda loc, timeout=5.0: [{"service_type": "urn:x:WANIPConnection:1", "control_url": "http://192.168.1.254:1900/ctl"}])
        monkeypatch.setattr(exposure, "enumerate_mappings", lambda url, st, **k: [{"external_port": 32400, "internal_port": 32400, "protocol": "TCP", "internal_client": "192.168.1.50", "enabled": True, "description": "Plex", "remote_host": "", "lease_duration": 0, "index": 0}])
        res = exposure.run(make_cfg(), conn)
        assert res.error is None and res.kind == "exposure"
        assert ids(res.findings) == ["NET-RTR-002", "NET-WAN-001", "NET-WAN-001", "NET-WAN-002", "NET-WAN-003"]
        keys = {f.evidence["key"] for f in res.findings if f.finding_id == "NET-WAN-001"}
        assert keys == {"22", "443"} and all(f.subject == "wan" for f in res.findings)
        mapping = next(f for f in res.findings if f.finding_id == "NET-WAN-003")
        assert mapping.evidence["key"] == "TCP/32400"
        assert db.one(conn, "SELECT value FROM settings WHERE key='exposure.public_ip'")["value"] == "203.0.113.5"
        snap = json.loads(db.one(conn, "SELECT value FROM settings WHERE key='exposure.last_json'")["value"])
        assert snap["public_ip"] == "203.0.113.5" and snap["mappings_count"] == 1 and snap["igd_found"] == 1

    def test_run_offline_is_graceful(self, conn, monkeypatch):
        monkeypatch.setattr(exposure, "public_ip", lambda timeout=5.0: None)
        monkeypatch.setattr(discovery, "local_ip", lambda: "192.168.1.105")
        monkeypatch.setattr(exposure, "discover_igd", lambda iface, seconds=3.0: [])
        res = exposure.run(make_cfg(), conn)
        assert res.findings == [] and res.error and "public IP" in res.error
        assert db.one(conn, "SELECT value FROM settings WHERE key='exposure.public_ip'")["value"] == ""


# =========================================================================== wifi

NETSH_TEXT = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Example Wireless-AC Adapter
    GUID                   : 11111111-2222-3333-4444-555555555555
    Physical address       : 02:11:22:00:00:01
    Interface type         : Primary
    State                  : connected
    SSID                   : ExampleNet-5G
    AP BSSID               : 00:11:22:00:00:0c
    Band                   : 5 GHz
    Channel                : 161
    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher =  00-0f-ac:04 ]
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 585
    Transmit rate (Mbps)   : 585
    Signal                 : 78%
    Rssi                   : -57
    Profile                : ExampleNet-5G
    QoS MSCS Configured         : 0
"""


class TestWifi:
    def test_parse_netsh(self):
        ifaces = wifi.parse_netsh_interfaces(NETSH_TEXT)
        assert len(ifaces) == 1
        i = ifaces[0]
        assert i["interface"] == "Wi-Fi" and i["connected"] and i["ssid"] == "ExampleNet-5G"
        assert i["bssid"] == "00:11:22:00:00:0c" and i["band"] == "5 GHz" and i["channel"] == "161"
        assert i["authentication"] == "WPA2-Personal" and i["cipher"] == "CCMP" and i["signal"] == "78%"
        assert "profile" not in i and "key" not in i

    def test_parse_netsh_disconnected_and_empty(self):
        text = "\nThere is 1 interface on the system:\n\n    Name : Wi-Fi\n    State : disconnected\n    Radio status : Hardware On\n"
        i = wifi.parse_netsh_interfaces(text)[0]
        assert not i["connected"] and i["ssid"] is None
        assert wifi.parse_netsh_interfaces("There is 0 interface on the system:\n") == []

    def test_findings(self):
        base = wifi.parse_netsh_interfaces(NETSH_TEXT)[0]
        assert ids(wifi.evaluate(base)) == ["NET-WIFI-002"]
        assert ids(wifi.evaluate({**base, "authentication": "WPA3-Personal", "cipher": "CCMP"})) == []
        assert ids(wifi.evaluate({**base, "authentication": "Open", "cipher": "None"})) == ["NET-WIFI-001"]
        assert ids(wifi.evaluate({**base, "authentication": "WEP", "cipher": "WEP"})) == ["NET-WIFI-001"]
        assert ids(wifi.evaluate({**base, "authentication": "WPA2-Personal", "cipher": "TKIP"})) == ["NET-WIFI-002", "NET-WIFI-003"]
        assert ids(wifi.evaluate({**base, "authentication": "WPA-Personal", "cipher": "TKIP"})) == ["NET-WIFI-003"]
        assert wifi.evaluate({**base, "connected": False}) == []
        ev = wifi.evaluate(base)[0].evidence
        assert ev["ssid"] == "ExampleNet-5G" and ev["key"] == "Wi-Fi" and "password" not in json.dumps(ev).lower()

    def test_parse_nmcli(self):
        rows = wifi.parse_nmcli("no:Neighbor:WPA2\nyes:MyNet:WPA2 WPA3\nyes:Cafe:\n")
        assert [(r["ssid"], r["authentication"]) for r in rows] == [("MyNet", "WPA2 WPA3"), ("Cafe", "Open")]
        assert ids(wifi.evaluate(rows[0])) == [] and ids(wifi.evaluate(rows[1])) == ["NET-WIFI-001"]

    def test_parse_airport(self):
        text = "     agrCtlRSSI: -57\n           SSID: ExampleNet\n          BSSID: 00:11:22:00:00:0c\n        channel: 36\n      link auth: wpa2-psk\n"
        d = wifi.parse_airport(text)
        assert d["ssid"] == "ExampleNet" and d["authentication"] == "wpa2-psk" and ids(wifi.evaluate(d)) == ["NET-WIFI-002"]
        assert wifi.parse_airport("AirPort: Off\n") is None

    def test_run(self, conn, monkeypatch):
        monkeypatch.setattr(wifi, "_collect", lambda: (wifi.parse_netsh_interfaces(NETSH_TEXT), "netsh", None))
        res = wifi.run(make_cfg(), conn)
        assert res.kind == "wifi" and res.error is None and res.summary["connected"] and res.summary["ssid"] == "ExampleNet-5G"
        assert ids(res.findings) == ["NET-WIFI-002"]
        assert "wifi.last_json" in {r["key"] for r in db.query(conn, "SELECT key FROM settings")}
        monkeypatch.setattr(wifi, "_collect", lambda: ([], "netsh", "netsh unavailable"))
        res = wifi.run(make_cfg(), conn)
        assert res.findings == [] and res.error == "netsh unavailable" and not res.summary["connected"]

    def test_every_draft_uses_the_wifi_subject(self):
        """cli.scan_wifi auto-resolves scope "wifi"; engine._auto_resolve matches the subject by
        prefix, so a draft with any other subject could never clear (NET-WIFI-001 is critical)."""
        base = wifi.parse_netsh_interfaces(NETSH_TEXT)[0]
        for iface in (base, {**base, "authentication": "Open", "cipher": "None"},
                      {**base, "authentication": "WPA-Personal", "cipher": "TKIP"}):
            drafts = wifi.evaluate(iface)
            assert drafts and {d.subject for d in drafts} == {"wifi"}

    def test_wifi_findings_auto_resolve_after_the_router_is_upgraded(self, conn, monkeypatch):
        engine = pytest.importorskip("homesoc.findings.engine")
        cli = pytest.importorskip("homesoc.cli")
        monkeypatch.setattr(wifi, "_collect", lambda: (wifi.parse_netsh_interfaces(NETSH_TEXT), "netsh", None))
        monkeypatch.setattr(cli, "_call_scanner", lambda name, cfg, conn_, **kw: (lambda: wifi.run(cfg, conn_)))
        cli.scan_wifi(make_cfg(), conn)
        row = db.one(conn, "SELECT subject, status FROM findings WHERE finding_id='NET-WIFI-002'")
        assert row is not None and row["subject"] == "wifi" and row["status"] == "open"

        wpa3 = NETSH_TEXT.replace("WPA2-Personal", "WPA3-Personal")
        monkeypatch.setattr(wifi, "_collect", lambda: (wifi.parse_netsh_interfaces(wpa3), "netsh", None))
        cli.scan_wifi(make_cfg(), conn)
        assert db.one(conn, "SELECT status FROM findings WHERE finding_id='NET-WIFI-002'")["status"] == "resolved"
        assert engine is not None


# =========================================================================== mdns_ssdp

class TestMdnsSsdp:
    def test_query_has_qu_bit(self):
        from dnslib import DNSRecord, QTYPE

        rec = DNSRecord.parse(mdns_ssdp.build_mdns_query())
        assert str(rec.questions[0].qname).rstrip(".") == mdns_ssdp.SERVICES_QNAME
        assert rec.questions[0].qclass == 0x8001 and QTYPE.get(rec.questions[0].qtype) == "PTR"
        assert len(rec.questions) == 1 + len(mdns_ssdp.EXTRA_TYPES)

    def test_parse_mdns_response(self):
        from dnslib import A, DNSRecord, PTR, RR, SRV

        rec = DNSRecord()
        rec.add_answer(RR("_services._dns-sd._udp.local", 12, rdata=PTR("_ipp._tcp.local")))
        rec.add_answer(RR("_ipp._tcp.local", 12, rdata=PTR("Example Printer._ipp._tcp.local")))
        rec.add_answer(RR("Example Printer._ipp._tcp.local", 33, rdata=SRV(0, 0, 631, "printer.local")))
        rec.add_answer(RR("printer.local", 1, rdata=A("192.168.1.73")))
        got = mdns_ssdp.parse_mdns_response(rec.pack())
        assert got["services"] == ["_ipp._tcp.local"]
        assert got["names"] == ["printer"]
        assert got["instances"] == ["Example Printer._ipp._tcp.local"]
        assert mdns_ssdp.parse_mdns_response(b"\x00\x01garbage") == {"services": [], "instances": [], "names": []}

    def test_ssdp_msearch_and_parse(self):
        msg = mdns_ssdp.build_ssdp_msearch().decode()
        assert msg.startswith("M-SEARCH * HTTP/1.1\r\n") and "ST: ssdp:all" in msg and msg.endswith("\r\n\r\n")
        got = mdns_ssdp.parse_ssdp_response("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Sonos/1\r\nLOCATION: http://192.168.1.80:1400/xml/device_description.xml\r\n\r\n")
        assert got == {"st": "upnp:rootdevice", "server": "Sonos/1", "location": "http://192.168.1.80:1400/xml/device_description.xml", "usn": ""}

    def test_probe_never_raises(self):
        out = mdns_ssdp.probe("127.0.0.1", seconds=0.2)
        assert isinstance(out, dict)
