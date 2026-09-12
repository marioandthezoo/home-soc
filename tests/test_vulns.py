"""Offline tests for homesoc.vulns (P5): CPE parsing, version compare, KEV/NVD/EPSS
matching and the winget software findings. No network: NVD is a fake session,
KEV/EPSS are fake catalogs.

The core package (db/models/util) is written by another work package; when it is
not importable yet, spec-shaped stand-ins are installed so this file passes on its
own and keeps passing once the real modules land.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import types
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _install_stubs() -> None:
    """Spec section 4/5 shapes, only for modules that do not exist yet."""
    if importlib.util.find_spec("homesoc.util") is None:
        util = types.ModuleType("homesoc.util")
        util.utcnow_iso = _utcnow_iso
        sys.modules["homesoc.util"] = util

    if importlib.util.find_spec("homesoc.models") is None:
        models = types.ModuleType("homesoc.models")

        @dataclass
        class Vuln:
            device_id: int
            service_id: int | None
            cve: str
            source: str
            kev: bool
            cvss: float | None
            epss: float | None
            title: str | None
            published: str | None
            matched_on: str
            remediation: str | None

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

        models.Vuln, models.FindingDraft, models.ScanResult = Vuln, FindingDraft, ScanResult
        sys.modules["homesoc.models"] = models

    if importlib.util.find_spec("homesoc.db") is None:
        dbm = types.ModuleType("homesoc.db")

        def write(conn, sql, params=()):
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid

        def query(conn, sql, params=()):
            return conn.execute(sql, params).fetchall()

        def one(conn, sql, params=()):
            return conn.execute(sql, params).fetchone()

        def get_setting(conn, key, default=None):
            row = one(conn, "SELECT value FROM settings WHERE key=?", (key,))
            return row["value"] if row else default

        def set_setting(conn, key, value):
            write(conn, "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                  (key, str(value), _utcnow_iso()))

        def record_metric(conn, name, value, tags=None):
            write(conn, "INSERT INTO metrics(ts,name,value,tags) VALUES(?,?,?,?)",
                  (_utcnow_iso(), name, float(value), json.dumps(tags) if tags else None))

        def record_event(conn, level, source, message, data=None):
            pass

        dbm.write, dbm.query, dbm.one = write, query, one
        dbm.get_setting, dbm.set_setting = get_setting, set_setting
        dbm.record_metric, dbm.record_event = record_metric, record_event
        sys.modules["homesoc.db"] = dbm


_install_stubs()

from homesoc import db  # noqa: E402
from homesoc.vulns import cpe as cpe_mod  # noqa: E402
from homesoc.vulns import enrich, matcher  # noqa: E402
from homesoc.vulns.cpe import CPE, compare_versions, guess_cpe, parse_cpe  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, name TEXT NOT NULL,
  value REAL NOT NULL, tags TEXT);
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT, hostname TEXT, vendor TEXT,
  kind TEXT, nickname TEXT, trusted INTEGER NOT NULL DEFAULT 0, notes TEXT, first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL, online INTEGER NOT NULL DEFAULT 1, last_service_scan TEXT, mdns_services TEXT);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
  port INTEGER NOT NULL, proto TEXT NOT NULL DEFAULT 'tcp', state TEXT NOT NULL, name TEXT, product TEXT,
  version TEXT, extrainfo TEXT, cpe TEXT, tunnel TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(device_id, port, proto));
CREATE TABLE IF NOT EXISTS vulns(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
  service_id INTEGER REFERENCES services(id), cve TEXT NOT NULL, source TEXT NOT NULL,
  kev INTEGER NOT NULL DEFAULT 0, cvss REAL, epss REAL, title TEXT, published TEXT, matched_on TEXT NOT NULL,
  remediation TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(device_id, cve, matched_on));
CREATE TABLE IF NOT EXISTS software(id INTEGER PRIMARY KEY, name TEXT NOT NULL, version TEXT, available TEXT,
  source TEXT NOT NULL, publisher TEXT, seen_at TEXT NOT NULL, UNIQUE(name, source));
"""


# --- fixtures ----------------------------------------------------------------

@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    yield c
    c.close()


@pytest.fixture
def cfg():
    return SimpleNamespace(vulns=SimpleNamespace(
        kev=True, nvd_enrich=True, nvd_api_key="", epss=True, min_cvss_report=7.0))


class FakeKev:
    """Mimics feeds.registry.KevCatalog.search(vendor, product)."""

    def __init__(self, entries):
        self.entries = entries
        self.calls: list[tuple[str, str]] = []

    def search(self, vendor, product):
        self.calls.append((vendor, product))
        needle = (product or "").lower()
        return [e for e in self.entries if needle and needle in e["product"].lower()]


KEV_ENTRIES = [
    {"cveID": "CVE-2022-41556", "vendorProject": "lighttpd", "product": "lighttpd",
     "vulnerabilityName": "lighttpd resource leak in versions prior to 1.4.67",
     "shortDescription": "Use-after-free.", "requiredAction": "Apply updates per vendor instructions.",
     "dueDate": "2024-01-01", "dateAdded": "2023-12-01", "notes": ""},
    {"cveID": "CVE-2099-0001", "vendorProject": "lighttpd", "product": "lighttpd",
     "vulnerabilityName": "lighttpd mod_wstunnel bug fixed in 1.4.70",
     "shortDescription": "", "requiredAction": "Update.", "dueDate": "", "dateAdded": "2026-01-01", "notes": ""},
    {"cveID": "CVE-2020-12662", "vendorProject": "NLnet Labs", "product": "Unbound",
     "vulnerabilityName": "Unbound amplification via NXNSAttack",
     "shortDescription": "Unbound resolver can be abused for amplification.",
     "requiredAction": "Apply updates.", "dueDate": "", "dateAdded": "2022-01-01", "notes": ""},
]


def _seed_device(conn, mac="00:11:22:00:00:01", ip="192.168.1.254", vendor="Example Networks", kind="router"):
    now = _utcnow_iso()
    return db.write(conn, "INSERT INTO devices(mac, ip, hostname, vendor, kind, first_seen, last_seen) "
                          "VALUES(?,?,?,?,?,?,?)", (mac, ip, "gateway.lan", vendor, kind, now, now))


def _seed_service(conn, device_id, port, product, version, cpe=None, state="open"):
    now = _utcnow_iso()
    return db.write(conn, "INSERT INTO services(device_id, port, proto, state, name, product, version, cpe, "
                          "first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (device_id, port, "tcp", state, "http", product, version, cpe, now, now))


def _ids(result):
    return sorted(d.finding_id for d in result.findings)


# --- cpe.py ------------------------------------------------------------------

def test_parse_cpe_nmap_22_form():
    c = parse_cpe("cpe:/a:lighttpd:lighttpd:1.4.69")
    assert c == CPE("a", "lighttpd", "lighttpd", "1.4.69")
    assert c.nvd_name() == "cpe:2.3:a:lighttpd:lighttpd:1.4.69:*:*:*:*:*:*:*"


def test_parse_cpe_23_form_and_wildcards():
    c = parse_cpe("cpe:2.3:a:nlnetlabs:unbound:1.18.0:*:*:*:*:*:*:*")
    assert c == CPE("a", "nlnetlabs", "unbound", "1.18.0")
    assert parse_cpe("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*").version is None
    assert parse_cpe("cpe:/o:linux:linux_kernel").version is None
    assert parse_cpe("cpe:/a:openbsd:openssh:9.2p1").version == "9.2p1"
    assert parse_cpe("cpe:/a:apache:http_server:2.4.41%2Bdeb").version == "2.4.41+deb"


def test_parse_cpe_rejects_garbage():
    for bad in ("", "lighttpd/1.4.69", "cpe:/a:lighttpd", "cpe:/x:a:b:1", "cpe:2.3:a::b:1:*"):
        with pytest.raises(ValueError):
            parse_cpe(bad)


@pytest.mark.parametrize("product,version,expected", [
    ("lighttpd", "1.4.69", CPE("a", "lighttpd", "lighttpd", "1.4.69")),
    ("Unbound DNS", "1.18.0", CPE("a", "nlnetlabs", "unbound", "1.18.0")),
    ("OpenSSH", "9.2p1 Debian 2", CPE("a", "openbsd", "openssh", "9.2p1")),
    ("Apache httpd", "2.4.41", CPE("a", "apache", "http_server", "2.4.41")),
    ("nginx", None, CPE("a", "f5", "nginx", None)),
    ("Dropbear sshd", "2019.78", CPE("a", "dropbear_ssh_project", "dropbear_ssh", "2019.78")),
    ("Microsoft IIS httpd", "10.0", CPE("a", "microsoft", "internet_information_services", "10.0")),
    ("MiniUPnPd", "v2.1", CPE("a", "miniupnp_project", "miniupnpd", "2.1")),
    ("dnsmasq", "2.80", CPE("a", "thekelleys", "dnsmasq", "2.80")),
    ("Hikvision IP camera rtspd", None, CPE("a", "hikvision", "hikvision", None)),
])
def test_guess_cpe_aliases(product, version, expected):
    assert guess_cpe(product, version) == expected


def test_guess_cpe_unknown_product_is_none():
    assert guess_cpe("Some Random Daemon", "1.0") is None
    assert guess_cpe("", "1.0") is None


@pytest.mark.parametrize("a,b,sign", [
    ("1.4.69", "1.4.70", -1),
    ("1.4.70", "1.4.69", 1),
    ("1.4", "1.4.0", 0),
    ("1.4", "1.4p1", -1),
    ("9.2p1", "9.3", -1),
    ("9.2p2", "9.2p1", 1),
    ("1.0rc1", "1.0", -1),
    ("1.0", "1.0beta2", 1),
    ("2.4.41a", "2.4.41", 1),
    ("1.18.0", "1.9.9", 1),
    ("10.0", "9.9", 1),
    (None, "1.0", -1),
])
def test_compare_versions(a, b, sign):
    assert compare_versions(a, b) == sign


def test_extract_versions_ignores_cve_ids_and_years():
    text = "Unbound before 1.19.0 and CVE-2023-50387 (2023) fixed in v1.19.1; also 1.9"
    assert cpe_mod.extract_versions(text) == ["1.19.0", "1.19.1", "1.9"]
    assert cpe_mod.max_version(cpe_mod.extract_versions(text)) == "1.19.1"
    assert cpe_mod.extract_versions("no versions here 2024") == []


def test_clean_version():
    assert cpe_mod.clean_version("v1.4.69 (Debian)") == "1.4.69"
    assert cpe_mod.clean_version("unknown") is None
    assert cpe_mod.clean_version(None) is None


# --- enrich.py ---------------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body=None, content_length=None):
        self.status_code = status
        self._raw = json.dumps(body).encode() if body is not None else b""
        self.headers = {"Content-Length": str(content_length if content_length is not None else len(self._raw))}

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._raw), chunk_size):
            yield self._raw[i:i + chunk_size]


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers, "timeout": timeout})
        if not self.responses:
            raise AssertionError("unexpected extra NVD request")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _nvd_body(*scores):
    vulns = []
    for i, s in enumerate(scores):
        metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": s}}]} if s is not None else {}
        vulns.append({"cve": {"id": f"CVE-2020-{1000 + i}", "published": "2020-05-01T00:00:00.000",
                              "descriptions": [{"lang": "en", "value": f"desc {i}"}], "metrics": metrics}})
    return {"totalResults": len(scores), "vulnerabilities": vulns}


@pytest.fixture
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(enrich, "_sleep", lambda s: slept.append(s))
    return slept


def test_nvd_summarize_orders_by_cvss_and_caps_top5():
    out = enrich.summarize(_nvd_body(5.0, 9.8, None, 7.5, 3.1, 8.8, 6.0))
    assert out["count"] == 7
    assert out["max_cvss"] == 9.8
    assert [c["cvss"] for c in out["top"]] == [9.8, 8.8, 7.5, 6.0, 5.0]
    assert out["top"][0]["cve"] == "CVE-2020-1001"
    assert out["top"][0]["published"] == "2020-05-01"


def test_nvd_for_cpe_uses_cpename_timeout_and_caches(conn, no_sleep):
    session = FakeSession([FakeResponse(200, _nvd_body(9.8, 4.0))])
    c = CPE("a", "lighttpd", "lighttpd", "1.4.69")
    first = enrich.nvd_for_cpe(c, "1.4.69", "", conn=conn, session=session)
    assert first["max_cvss"] == 9.8 and first["count"] == 2 and first["cached"] is False
    call = session.calls[0]
    assert call["url"] == enrich.NVD_URL
    assert call["params"]["cpeName"] == "cpe:2.3:a:lighttpd:lighttpd:1.4.69:*:*:*:*:*:*:*"
    assert call["params"]["resultsPerPage"] == "50"
    assert call["timeout"] == 15.0
    assert "apiKey" not in call["headers"]
    # second call is served from settings, no extra HTTP
    second = enrich.nvd_for_cpe(c, "1.4.69", "", conn=conn, session=session)
    assert second["cached"] is True and second["max_cvss"] == 9.8
    assert len(session.calls) == 1
    assert db.get_setting(conn, "nvd.cache.cpe:2.3:a:lighttpd:lighttpd:1.4.69:*:*:*:*:*:*:*")


def test_nvd_cache_expires_after_seven_days(conn, no_sleep):
    c = CPE("a", "lighttpd", "lighttpd", "1.4.69")
    stale = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    db.set_setting(conn, enrich.cache_key(c, None, None),
                   json.dumps({"fetched_at": stale, "result": {"count": 1, "max_cvss": 1.0, "top": []}}))
    session = FakeSession([FakeResponse(200, _nvd_body(5.5))])
    out = enrich.nvd_for_cpe(c, "1.4.69", "", conn=conn, session=session)
    assert out["cached"] is False and out["max_cvss"] == 5.5
    assert len(session.calls) == 1


def test_nvd_retries_once_on_429_with_six_second_sleep(conn, no_sleep):
    session = FakeSession([FakeResponse(429), FakeResponse(200, _nvd_body(7.2))])
    out = enrich.nvd_for_cpe(CPE("a", "f5", "nginx", "1.18.0"), "1.18.0", "key123", conn=conn, session=session)
    assert out["max_cvss"] == 7.2
    assert no_sleep == [6.0]
    assert session.calls[0]["headers"]["apiKey"] == "key123"


def test_nvd_gives_up_after_second_429_and_does_not_cache(conn, no_sleep):
    session = FakeSession([FakeResponse(429), FakeResponse(403)])
    assert enrich.nvd_for_cpe(CPE("a", "f5", "nginx", "1.18.0"), "1.18.0", "", conn=conn, session=session) is None
    assert db.get_setting(conn, enrich.cache_key(CPE("a", "f5", "nginx", "1.18.0"), None, None)) is None


def test_nvd_keyword_fallback_when_cpe_unknown(conn, no_sleep):
    session = FakeSession([FakeResponse(200, _nvd_body())])
    out = enrich.nvd_for_cpe(None, "3.2", "", conn=conn, session=session, product="Foo Daemon")
    assert out["count"] == 0 and out["max_cvss"] is None
    assert session.calls[0]["params"] == {"keywordSearch": "Foo Daemon 3.2", "resultsPerPage": "50"}
    assert enrich.nvd_for_cpe(None, "3.2", "", conn=conn, session=session, product="Foo Daemon")["cached"]


def test_nvd_budget_exhausted_returns_none_without_request(conn, no_sleep):
    session = FakeSession([])
    budget = enrich.Budget(seconds=1.0)  # less than one request timeout
    assert enrich.nvd_for_cpe(CPE("a", "f5", "nginx", "1.18.0"), "1.18.0", "", conn=conn,
                              budget=budget, session=session) is None
    assert budget.exhausted and session.calls == []


def test_nvd_rate_limiter_waits_only_within_budget(monkeypatch, no_sleep):
    clock = [1000.0]
    monkeypatch.setattr(enrich, "_monotonic", lambda: clock[0])
    limiter = enrich.RateLimiter(max_requests=2, window_sec=30.0)
    limiter.record(); limiter.record()
    assert limiter.wait_needed() == 30.0
    clock[0] += 31
    assert limiter.wait_needed() == 0.0


def test_nvd_response_size_cap_and_network_error(conn, no_sleep):
    import requests
    big = FakeResponse(200, _nvd_body(), content_length=enrich.MAX_RESPONSE_BYTES + 1)
    assert enrich.nvd_for_cpe(CPE("a", "f5", "nginx", "1.0"), "1.0", "", conn=conn, session=FakeSession([big])) is None
    boom = FakeSession([requests.ConnectionError("offline")])
    assert enrich.nvd_for_cpe(CPE("a", "f5", "nginx", "1.0"), "1.0", "", conn=conn, session=boom) is None


# --- matcher.py --------------------------------------------------------------

@pytest.fixture
def offline(monkeypatch):
    """KEV/EPSS fakes and an NVD stub that records calls; nothing reaches the network."""
    kev = FakeKev(KEV_ENTRIES)
    epss = {"CVE-2022-41556": 0.93, "CVE-2020-12662": 0.12, "CVE-2020-1001": 0.61}
    nvd_calls = []
    nvd_result = {"count": 12, "max_cvss": 9.8, "cached": False,
                  "top": [{"cve": "CVE-2020-1001", "cvss": 9.8, "published": "2020-05-01", "title": "rce"},
                          {"cve": "CVE-2020-1002", "cvss": 5.3, "published": "2020-06-01", "title": "dos"}]}

    def fake_nvd(cpe, version, api_key, **kw):
        nvd_calls.append((cpe, version, kw.get("product")))
        return dict(nvd_result)

    monkeypatch.setattr(matcher, "_load_kev", lambda: kev)
    monkeypatch.setattr(matcher, "_load_epss", lambda: epss)
    monkeypatch.setattr(matcher.enrich, "nvd_for_cpe", fake_nvd)
    return SimpleNamespace(kev=kev, epss=epss, nvd_calls=nvd_calls, nvd_result=nvd_result)


def test_kev_confirmed_when_version_at_or_below_advisory(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 80, "lighttpd", "1.4.69", cpe="cpe:/a:lighttpd:lighttpd:1.4.69")
    result = matcher.match_services(cfg, conn)
    assert result.kind == "vulns" and result.error is None
    ids = _ids(result)
    # 1.4.69 <= 1.4.70 -> confirmed; 1.4.69 > 1.4.67 -> dropped (patched)
    assert ids.count("NET-VUL-001") == 1 and "NET-VUL-002" not in ids
    kev_draft = next(d for d in result.findings if d.finding_id == "NET-VUL-001")
    assert kev_draft.subject == "device:00:11:22:00:00:01:80"
    assert kev_draft.device_id == dev
    assert kev_draft.evidence["cve"] == "CVE-2099-0001" and kev_draft.evidence["key"] == "CVE-2099-0001"
    assert kev_draft.evidence["kev_max_version"] == "1.4.70"
    assert "Update lighttpd to a version newer than 1.4.69" in kev_draft.detail
    assert "router/IoT" in kev_draft.detail
    assert result.summary["kev_confirmed"] == 1 and result.summary["services_checked"] == 1


def test_kev_possible_when_no_version_can_be_compared(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 53, "Unbound", "1.18.0", cpe="cpe:/a:nlnetlabs:unbound:1.18.0")
    _seed_service(conn, dev, 8080, "lighttpd", None)  # no version at all
    result = matcher.match_services(cfg, conn)
    possible = [d for d in result.findings if d.finding_id == "NET-VUL-002"]
    assert {d.subject for d in possible} == {"device:00:11:22:00:00:01:53", "device:00:11:22:00:00:01:8080"}
    assert "NET-VUL-001" not in _ids(result)
    assert all(d.evidence["verdict"] == "possible" for d in possible)
    assert result.summary["kev_possible"] == 3  # unbound x1, versionless lighttpd x2


def test_nvd_and_epss_findings_and_vulns_rows(conn, cfg, offline):
    dev = _seed_device(conn)
    svc = _seed_service(conn, dev, 80, "lighttpd", "1.4.69", cpe="cpe:/a:lighttpd:lighttpd:1.4.69")
    result = matcher.match_services(cfg, conn)
    ids = _ids(result)
    assert "NET-VUL-003" in ids and "NET-VUL-004" in ids
    nvd = next(d for d in result.findings if d.finding_id == "NET-VUL-003")
    assert nvd.evidence["count"] == 12 and nvd.evidence["max_cvss"] == 9.8 and len(nvd.evidence["top"]) == 2
    epss = next(d for d in result.findings if d.finding_id == "NET-VUL-004")
    # CVE-2099-0001 (KEV) has no EPSS score in the fake table; only the NVD CVE is hot
    assert {c["cve"] for c in epss.evidence["cves"]} == {"CVE-2020-1001"}
    assert offline.nvd_calls[0][0] == CPE("a", "lighttpd", "lighttpd", "1.4.69")
    rows = db.query(conn, "SELECT * FROM vulns ORDER BY cve")
    by_cve = {r["cve"]: r for r in rows}
    assert set(by_cve) == {"CVE-2099-0001", "CVE-2020-1001", "CVE-2020-1002"}
    assert by_cve["CVE-2099-0001"]["kev"] == 1 and by_cve["CVE-2099-0001"]["source"] == "kev"
    assert by_cve["CVE-2020-1001"]["cvss"] == 9.8 and by_cve["CVE-2020-1001"]["epss"] == 0.61
    assert by_cve["CVE-2020-1001"]["service_id"] == svc
    assert "Update lighttpd to a version newer than 1.4.69" in by_cve["CVE-2020-1001"]["remediation"]
    assert by_cve["CVE-2099-0001"]["matched_on"] == "cpe:2.3:a:lighttpd:lighttpd:1.4.69:*:*:*:*:*:*:*"


def test_epss_finding_only_at_or_above_half(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 53, "Unbound", "1.18.0", cpe="cpe:/a:nlnetlabs:unbound:1.18.0")
    offline.nvd_result["top"] = []
    offline.nvd_result["max_cvss"] = None
    result = matcher.match_services(cfg, conn)
    assert "NET-VUL-004" not in _ids(result) and "NET-VUL-003" not in _ids(result)
    row = db.one(conn, "SELECT epss FROM vulns WHERE cve='CVE-2020-12662'")
    assert row["epss"] == 0.12


def test_nvd_below_threshold_no_finding_but_rows_kept(conn, cfg, offline):
    dev = _seed_device(conn, vendor="Apple", kind="laptop")
    _seed_service(conn, dev, 22, "OpenSSH", "9.2p1")
    offline.kev.entries = []
    offline.nvd_result.update({"max_cvss": 6.5, "top": [{"cve": "CVE-2020-1002", "cvss": 6.5}]})
    result = matcher.match_services(cfg, conn)
    assert _ids(result) == []
    assert db.one(conn, "SELECT count(*) AS n FROM vulns")["n"] == 1


def test_upsert_is_idempotent_across_runs(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 80, "lighttpd", "1.4.69", cpe="cpe:/a:lighttpd:lighttpd:1.4.69")
    matcher.match_services(cfg, conn)
    first = db.query(conn, "SELECT id, first_seen FROM vulns ORDER BY id")
    matcher.match_services(cfg, conn)
    second = db.query(conn, "SELECT id, first_seen FROM vulns ORDER BY id")
    assert [tuple(r) for r in first] == [tuple(r) for r in second]


def test_closed_and_bannerless_services_are_skipped(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 23, "lighttpd", "1.0", state="closed")
    _seed_service(conn, dev, 443, None, None)
    result = matcher.match_services(cfg, conn)
    assert result.findings == [] and result.summary["services_checked"] == 0


def test_config_switches_and_quick_mode(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 80, "lighttpd", "1.4.69", cpe="cpe:/a:lighttpd:lighttpd:1.4.69")
    cfg.vulns.kev = False
    cfg.vulns.epss = False
    result = matcher.match_services(cfg, conn, quick=True)
    assert result.findings == [] and offline.nvd_calls == []
    assert result.summary["nvd_queried"] == 0 and result.summary["kev_confirmed"] == 0


def test_kev_failure_degrades_to_error_not_exception(conn, cfg, offline, monkeypatch):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 80, "lighttpd", "1.4.69")

    def boom():
        raise FileNotFoundError("kev.json missing")

    monkeypatch.setattr(matcher, "_load_kev", boom)
    result = matcher.match_services(cfg, conn)
    assert "kev" in (result.error or "")
    assert "NET-VUL-003" in _ids(result)  # NVD still ran


def test_run_alias_matches_scanner_signature(conn, cfg, offline):
    seen = []
    result = matcher.run(cfg, conn, quick=False, progress=seen.append)
    assert result.kind == "vulns" and result.findings == [] and seen == []


def test_kev_search_uses_cpe_vendor_product_then_banner(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 53, "Unbound DNS", "1.18.0")  # guessed cpe -> nlnetlabs/unbound
    matcher.match_services(cfg, conn)
    assert ("nlnetlabs", "unbound") in offline.kev.calls


# --- false-positive regressions ----------------------------------------------
#
# A Windows PC on the LAN banners "Microsoft Windows RPC" / "Microsoft Windows
# netbios-ssn" / "Microsoft Terminal Services" on 135/139/445/3389, each with the
# version-less CPE cpe:/o:microsoft:windows. The matcher used to search KEV for the
# banner's first word ("microsoft") and emitted one high NET-VUL-002 -- plus one
# vulns row -- per KEV entry of that vendor, hundreds per port, none of which could
# ever auto-resolve. These tests run the *real* KevCatalog, not the fake, because
# the bug lived in the interaction between the two.

from homesoc.feeds.registry import KevCatalog  # noqa: E402


def _real_kev_catalog(windows_entries: int = 170) -> KevCatalog:
    """A KEV catalog shaped like the real one: one enormous vendor family plus small products."""
    entries = [
        {"cveID": f"CVE-2015-{1000 + i}", "vendorProject": "Microsoft", "product": "Windows",
         "vulnerabilityName": f"Microsoft Windows Vulnerability {i}",
         "shortDescription": "Elevation of privilege.", "dateAdded": "2022-01-01",
         "requiredAction": "Apply updates per vendor instructions.", "notes": ""}
        for i in range(windows_entries)
    ]
    entries += [
        {"cveID": "CVE-2016-3000", "vendorProject": "Apple", "product": "Multiple Products",
         "vulnerabilityName": "Apple Multiple Products Bug", "dateAdded": "2022-01-01", "notes": ""},
        {"cveID": "CVE-2016-4000", "vendorProject": "Microsoft", "product": "Office",
         "vulnerabilityName": "Office RCE", "dateAdded": "2022-01-01", "notes": ""},
        {"cveID": "CVE-2018-19052", "vendorProject": "lighttpd", "product": "lighttpd",
         "vulnerabilityName": "lighttpd mod_alias path traversal before 1.4.50",
         "dateAdded": "2025-11-04", "notes": ""},
    ]
    return KevCatalog(entries=entries)


@pytest.fixture
def real_kev(monkeypatch):
    catalog = _real_kev_catalog()
    monkeypatch.setattr(matcher, "_load_kev", lambda: catalog)
    monkeypatch.setattr(matcher, "_load_epss", dict)
    monkeypatch.setattr(matcher.enrich, "nvd_for_cpe",
                        lambda *a, **k: pytest.fail("NVD must not be queried without a version"))
    return catalog


@pytest.mark.parametrize("port,product", [
    (135, "Microsoft Windows RPC"),
    (139, "Microsoft Windows netbios-ssn"),
    (445, "Microsoft Windows 10 microsoft-ds"),
    (3389, "Microsoft Terminal Services"),
])
def test_windows_port_produces_no_kev_findings_and_no_vulns_rows(conn, cfg, real_kev, port, product):
    dev = _seed_device(conn, mac="00:11:22:33:44:55", ip="192.168.1.42", vendor="Dell", kind="laptop")
    _seed_service(conn, dev, port, product, None, cpe="cpe:/o:microsoft:windows")
    result = matcher.match_services(cfg, conn)
    assert result.findings == [], f"{product} produced {len(result.findings)} findings"
    assert db.one(conn, "SELECT count(*) AS n FROM vulns")["n"] == 0
    assert result.summary["kev_confirmed"] == 0 and result.summary["kev_possible"] == 0
    assert result.summary["nvd_skipped"] == 1  # no version -> NVD is never asked


def test_versionless_family_match_is_counted_as_suppressed(conn, cfg, real_kev):
    dev = _seed_device(conn, mac="00:11:22:33:44:55", kind="laptop")
    _seed_service(conn, dev, 445, "Microsoft Windows RPC", None, cpe="cpe:/o:microsoft:windows")
    result = matcher.match_services(cfg, conn)
    # the 170 unconfirmable entries are visible in the scan summary, not as 170 findings
    assert result.summary["kev_suppressed"] == 170
    assert result.error is None


def test_versionless_narrow_match_is_still_reported(conn, cfg, real_kev):
    """The cap must not silence a genuinely specific product with no version banner."""
    dev = _seed_device(conn)
    _seed_service(conn, dev, 80, "lighttpd", None, cpe="cpe:/a:lighttpd:lighttpd")
    result = matcher.match_services(cfg, conn)
    possible = [d for d in result.findings if d.finding_id == "NET-VUL-002"]
    assert [d.evidence["cve"] for d in possible] == ["CVE-2018-19052"]
    assert result.summary["kev_possible"] == 1 and result.summary["kev_suppressed"] == 0


def test_confirmed_matches_are_never_capped(conn, cfg, real_kev, monkeypatch):
    """A version that the advisories actually cover stays reportable however many there are."""
    entries = [
        {"cveID": f"CVE-2020-{i}", "vendorProject": "Zyxel", "product": "NAS326",
         "vulnerabilityName": f"Zyxel NAS326 command injection before 5.21.{i}", "dateAdded": "2024-01-01"}
        for i in range(1, 26)  # deliberately more than KEV_POSSIBLE_MAX
    ]
    monkeypatch.setattr(matcher, "_load_kev", lambda: KevCatalog(entries=entries))
    cfg.vulns.nvd_enrich = False  # this test is about KEV only
    dev = _seed_device(conn, vendor="Zyxel", kind="nas")
    _seed_service(conn, dev, 80, "NAS326", "5.21.0", cpe="cpe:/a:zyxel:nas326:5.21.0")
    result = matcher.match_services(cfg, conn)
    ids = _ids(result)
    assert ids.count("NET-VUL-001") == 25 and "NET-VUL-002" not in ids
    assert result.summary["kev_suppressed"] == 0


@pytest.mark.parametrize("count,reported", [
    (matcher.KEV_POSSIBLE_MAX, matcher.KEV_POSSIBLE_MAX),  # a real appliance (FortiOS, Zimbra, ...)
    (matcher.KEV_POSSIBLE_MAX + 1, 0),                     # a family (Windows, Chromium V8, ...)
])
def test_versionless_cap_boundary(conn, cfg, monkeypatch, count, reported):
    entries = [
        {"cveID": f"CVE-2021-{i}", "vendorProject": "Fortinet", "product": "FortiOS",
         "vulnerabilityName": f"FortiOS path traversal {i}", "dateAdded": "2024-01-01"}
        for i in range(count)
    ]
    monkeypatch.setattr(matcher, "_load_kev", lambda: KevCatalog(entries=entries))
    monkeypatch.setattr(matcher, "_load_epss", dict)
    cfg.vulns.nvd_enrich = False
    dev = _seed_device(conn, vendor="Fortinet", kind="router")
    _seed_service(conn, dev, 443, "FortiOS", None, cpe="cpe:/o:fortinet:fortios")
    result = matcher.match_services(cfg, conn)
    assert len([d for d in result.findings if d.finding_id == "NET-VUL-002"]) == reported
    assert result.summary["kev_possible"] == reported
    assert result.summary["kev_suppressed"] == (0 if reported else count)
    assert db.one(conn, "SELECT count(*) AS n FROM vulns")["n"] == reported


def test_kev_search_is_never_called_with_the_banners_first_word(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 135, "Microsoft Windows RPC", None, cpe="cpe:/o:microsoft:windows")
    _seed_service(conn, dev, 5900, "Apple remote desktop vnc", None, cpe="cpe:/o:apple:mac_os_x")
    matcher.match_services(cfg, conn)
    assert offline.kev.calls == [("microsoft", "windows"), ("apple", "mac_os_x")]
    assert not any(v == "" for v, _ in offline.kev.calls)


# --- NVD must not fire on a version-less CPE ---------------------------------


def test_nvd_is_skipped_without_a_version(conn, cfg, offline):
    dev = _seed_device(conn)
    _seed_service(conn, dev, 135, "Microsoft Windows RPC", None, cpe="cpe:/o:microsoft:windows")
    result = matcher.match_services(cfg, conn)
    assert offline.nvd_calls == []
    assert result.summary["nvd_skipped"] == 1 and result.summary["nvd_queried"] == 0
    assert "NET-VUL-003" not in _ids(result)


def test_enrich_refuses_a_keyword_query_without_a_version(conn, no_sleep):
    session = FakeSession([])  # any HTTP call raises
    assert enrich.nvd_for_cpe(CPE("o", "microsoft", "windows", None), None, "", conn=conn,
                              session=session, product="Microsoft Windows RPC") is None
    assert enrich.nvd_for_cpe(None, None, "", conn=conn, session=session, product="windows") is None
    assert session.calls == []
    with pytest.raises(ValueError):
        enrich._query_params(None, None, "windows")
    with pytest.raises(ValueError):
        enrich._query_params(CPE("o", "microsoft", "windows", None), None, None)


def test_nvd_keyword_result_is_capped_and_qualified(conn, cfg, offline):
    """A keyword hit is a text match: report what came back, labelled, not totalResults."""
    dev = _seed_device(conn, vendor="Acme", kind="printer")
    _seed_service(conn, dev, 8080, "Some Random Daemon", "3.2")  # no CPE -> keyword search
    offline.kev.entries = []
    offline.nvd_result.update({"count": 42, "returned": 2, "match": "keyword"})
    result = matcher.match_services(cfg, conn)
    nvd = next(d for d in result.findings if d.finding_id == "NET-VUL-003")
    assert nvd.evidence["match"] == "keyword"
    assert nvd.evidence["count"] == 2 and nvd.evidence["total_results"] == 42
    assert "has 2 known CVEs" in nvd.detail and "not by CPE" in nvd.detail


def test_nvd_keyword_result_too_broad_is_dropped(conn, cfg, offline):
    dev = _seed_device(conn, vendor="Acme", kind="printer")
    _seed_service(conn, dev, 8080, "Some Random Daemon", "3.2")
    offline.kev.entries = []
    offline.nvd_result.update({"count": matcher.NVD_KEYWORD_MAX_TOTAL + 1, "returned": 2, "match": "keyword"})
    result = matcher.match_services(cfg, conn)
    assert _ids(result) == []
    assert db.one(conn, "SELECT count(*) AS n FROM vulns")["n"] == 0
    assert result.summary["nvd_queried"] == 1  # the call happened; only the finding is withheld


def test_nvd_cpe_match_still_reports_the_full_count(conn, cfg, offline):
    """The cap applies to keyword searches only; an exact cpeName count is trustworthy."""
    dev = _seed_device(conn)
    _seed_service(conn, dev, 80, "lighttpd", "1.4.69", cpe="cpe:/a:lighttpd:lighttpd:1.4.69")
    offline.kev.entries = []
    offline.nvd_result.update({"count": 4210, "returned": 2, "match": "cpe"})
    result = matcher.match_services(cfg, conn)
    nvd = next(d for d in result.findings if d.finding_id == "NET-VUL-003")
    assert nvd.evidence["count"] == 4210 and nvd.evidence["match"] == "cpe"
    assert "not by CPE" not in nvd.detail


def test_summarize_reports_page_size_and_query_kind(conn, no_sleep):
    out = enrich.summarize(_nvd_body(9.8, 4.0, 3.0))
    assert out["returned"] == 3 and out["count"] == 3
    session = FakeSession([FakeResponse(200, _nvd_body(9.8))])
    by_cpe = enrich.nvd_for_cpe(CPE("a", "lighttpd", "lighttpd", "1.4.69"), "1.4.69", "",
                                conn=conn, session=session)
    assert by_cpe["match"] == "cpe"
    session = FakeSession([FakeResponse(200, _nvd_body(9.8))])
    by_kw = enrich.nvd_for_cpe(None, "3.2", "", conn=conn, session=session, product="Foo Daemon")
    assert by_kw["match"] == "keyword" and by_kw["returned"] == 1


# --- software (winget) -------------------------------------------------------

def _seed_software(conn, name, version, available, source="winget", publisher=None):
    db.write(conn, "INSERT INTO software(name, version, available, source, publisher, seen_at) VALUES(?,?,?,?,?,?)",
             (name, version, available, source, publisher, _utcnow_iso()))


def test_software_findings_low_and_high_risk(conn, cfg):
    _seed_software(conn, "Oracle Java 8 Update 401", "8.0.4010.10", "8.0.4210.9", publisher="Oracle")
    _seed_software(conn, "Microsoft Visual Studio Code", "1.92.0", "1.93.1")
    _seed_software(conn, "7-Zip 23.01 (x64)", "23.01", "24.08")
    _seed_software(conn, "Notepad++", "Unknown", "8.7")
    _seed_software(conn, "OBS Studio", "30.2.3", "30.2.3")  # not actually outdated
    _seed_software(conn, "Weird App", "2.0", None)
    _seed_software(conn, "Downgrade App", "3.0", "2.9")  # available older than installed
    drafts = matcher.evaluate_software(cfg, conn)
    by_name = {d.evidence["name"]: d for d in drafts}
    assert set(by_name) == {"Oracle Java 8 Update 401", "Microsoft Visual Studio Code", "7-Zip 23.01 (x64)", "Notepad++"}
    assert by_name["Oracle Java 8 Update 401"].finding_id == "WIN-UPD-004"
    assert by_name["7-Zip 23.01 (x64)"].finding_id == "WIN-UPD-004"
    assert by_name["Notepad++"].finding_id == "WIN-UPD-004"
    assert by_name["Microsoft Visual Studio Code"].finding_id == "WIN-UPD-003"
    assert all(d.subject == "host" for d in drafts)
    assert by_name["Notepad++"].evidence["key"] == "notepad++"
    assert "newer than 8.0.4010.10" in by_name["Oracle Java 8 Update 401"].detail
    assert by_name["Oracle Java 8 Update 401"].evidence["high_risk"] is True


def test_software_findings_counted_but_not_emitted_by_match_services(conn, cfg, offline):
    # scanners/updates.py is the single WIN-UPD-003/004 emitter (see matcher.match_services).
    _seed_software(conn, "VideoLAN VLC media player", "3.0.20", "3.0.21")
    result = matcher.match_services(cfg, conn)
    assert _ids(result) == [] and result.summary["software_outdated"] == 1


def test_high_risk_list_matches_spec():
    for name in ("java", "adobe", "chrome", "firefox", "edge", "zoom", "vlc", "7-zip", "winrar", "putty",
                 "openvpn", "notepad++", "teamviewer", "anydesk", "filezilla", "python"):
        assert matcher._is_high_risk(f"Vendor {name.title()} 1.0")
    assert not matcher._is_high_risk("OBS Studio")
