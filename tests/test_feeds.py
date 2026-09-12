"""Offline tests for homesoc.feeds (P2): parsers, registry loaders, updater."""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
import shutil
import sqlite3
import sys
import types
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from homesoc.feeds import parsers, registry, updater

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"

# Mirrors the `feeds` table in SPEC §4 so these tests do not depend on db.py.
FEEDS_DDL = """
CREATE TABLE IF NOT EXISTS feeds (
    name TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    kind TEXT NOT NULL,
    etag TEXT,
    last_modified TEXT,
    last_checked TEXT,
    last_updated TEXT,
    status TEXT NOT NULL DEFAULT 'never',
    bytes INTEGER,
    entries INTEGER,
    error TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
)
"""

# The updater keeps its per-feed failure counters here (SPEC §4 settings table).
SETTINGS_DDL = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
"""


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def make_cfg(**feeds_overrides):
    feeds = {
        "enabled": True,
        "kev_hours": 6,
        "epss_hours": 24,
        "oui_hours": 168,
        "blocklists_hours": 12,
        "threatintel_hours": 6,
        "max_download_mb": 1,
    }
    feeds.update(feeds_overrides)
    return SimpleNamespace(feeds=SimpleNamespace(**feeds))


class FakeResponse:
    """Just enough of requests.Response for the updater: status, headers, chunked body, context manager."""

    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status
        self.headers = dict(headers or {})
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated data dir + in-memory feeds table + cleared parse cache."""
    monkeypatch.setenv("HOMESOC_DATA", str(tmp_path))
    registry.clear_cache()
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(FEEDS_DDL)
    conn.execute(SETTINGS_DDL)
    conn.commit()
    yield SimpleNamespace(conn=conn, data=tmp_path)
    registry.clear_cache()
    conn.close()


@pytest.fixture
def http(monkeypatch):
    """Route updater._http_get to a scripted response and capture the request headers."""
    calls: list[dict] = []
    queue: list[FakeResponse] = []

    def fake_get(url, headers, timeout):
        calls.append({"url": url, "headers": dict(headers), "timeout": timeout})
        if not queue:
            raise AssertionError("no scripted response left")
        return queue.pop(0)

    monkeypatch.setattr(updater, "_http_get", fake_get)
    return SimpleNamespace(calls=calls, queue=queue)


def install_fixture(name: str, fixture: str) -> Path:
    path = updater.feed_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / fixture, path)
    return path


# ----------------------------------------------------------------- parsers ---


def test_parse_hosts_handles_noise_ipv6_crlf_and_inline_comments():
    text = read_fixture("hosts.txt").replace("\n", "\r\n")
    got = set(parsers.parse_hosts(text))
    assert got == {
        "ads.example.com",
        "tracker.example.net",
        "analytics.example.org",
        "a.doubleclick.example",
        "b.doubleclick.example",
        "ipv6-sink.example.com",
        "bare.example.com",
    }
    assert "localhost" not in got and "0.0.0.0" not in got
    # duplicates (ads.example.com appears twice) are emitted once
    assert list(parsers.parse_hosts(text)).count("ads.example.com") == 1


def test_parse_adblock_extracts_only_dns_level_rules():
    got = set(parsers.parse_adblock(read_fixture("domains_abp.txt")))
    assert got == {
        "example-ads.com",
        "tracker.example.net",
        "telemetry.example.org",
        "static.cdn.example.com",
        "xn--bcher-kva.example",
        "under_score.example.com",
        "dupe-with-crlf.example",
        "a.b.c.d.example.co.uk",
        "plain-domain.example.net",
    }
    assert "allowed.example.com" not in got  # @@ exception ignored
    assert not any("/" in d or "*" in d for d in got)


def test_parse_wildcard_strips_prefix_and_junk():
    got = list(parsers.parse_wildcard(read_fixture("wildcard.txt").replace("\n", "\r\n")))
    assert got == [
        "ads.example.com",
        "telemetry.example.net",
        "metrics.example.org",
        "dot-prefixed.example",
        "plain.example.com",
    ]


def test_parse_domains_is_lenient_about_mixed_syntax():
    text = "# c\nPlain.Example.COM.\r\n0.0.0.0 hosts-style.example\n||abp.example^\n*.wild.example\n@@||ok.example^\nlocalhost\n"
    assert list(parsers.parse_domains(text)) == [
        "plain.example.com",
        "hosts-style.example",
        "abp.example",
        "wild.example",
    ]


def test_parse_urls_yields_hosts_and_drops_ip_literals():
    text = "http://Phish.Example.com/login?x=1\nhttps://1.2.3.4/evil\nftp://bad.example.net:2121/a\nnoscheme.example.org/path\n"
    assert list(parsers.parse_urls(text)) == ["phish.example.com", "bad.example.net", "noscheme.example.org"]


def test_parse_ips_drop_format_and_plain_hosts():
    nets = list(parsers.parse_ips(read_fixture("ips.txt")))
    assert all(isinstance(n, ipaddress.IPv4Network) for n in nets)
    assert ipaddress.ip_network("1.10.16.0/20") in nets
    assert ipaddress.ip_network("185.220.101.44/32") in nets
    assert len([n for n in nets if n.prefixlen == 32]) == 1  # deduped
    assert len(nets) == 6


def test_parse_feodo_json():
    payload = json.dumps(
        [
            {"ip_address": "45.155.205.233", "port": 443, "status": "online", "malware": "Emotet"},
            {"ip_address": "2001:db8::1", "port": 80},
            {"no_ip": True},
            "junk",
        ]
    )
    assert list(parsers.parse_feodo(payload)) == [ipaddress.ip_network("45.155.205.233/32")]
    assert list(parsers.parse_feodo("{not json")) == []


def test_parse_kev_normalizes_entries_and_metadata():
    text = read_fixture("kev_sample.json")
    entries = parsers.parse_kev(text)
    assert len(entries) == 6
    ids = [e["cveID"] for e in entries]
    assert "CVE-2019-11510" in ids  # lower-case input upper-cased
    first = entries[0]
    assert set(first) >= {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "notes", "cwes"}
    assert first["cwes"] == ["CWE-22"]
    assert entries[-1]["notes"] == "" and entries[-1]["cwes"] == []  # null / missing tolerated
    meta, _ = parsers.kev_document(text)
    assert meta["dateReleased"].startswith("2026-09-03") and meta["catalogVersion"] == "2026.09.03"
    assert parsers.parse_kev("<html>error</html>") == []


def test_parse_epss_skips_comment_header_and_bad_rows():
    scores = parsers.parse_epss(read_fixture("epss_sample.csv"))
    assert scores["CVE-2018-19052"] == pytest.approx(0.93251)
    assert scores["CVE-2020-0001"] == pytest.approx(0.12)
    assert "CVE-2099-BAD" not in scores and "CVE-2099-RANGE" not in scores
    assert len(scores) == 8


def test_parse_oui_supports_24_28_and_36_bit_prefixes():
    table = parsers.parse_oui(read_fixture("manuf_sample.txt"))
    assert table["3C:22:FB"] == "Apple, Inc."
    assert table["00:1B:C5:00:10/36"] == "OpenRB.com, Direct SIA"
    assert table["28:EE:D3:10/28"] == "IRAF SRL"
    assert table["00:50:C2:AB:C0/36"] == "ZycooCoLtd"  # short name only
    assert "GG:HH:II" not in table
    assert parsers.normalize_oui_prefix("aa-bb-cc") == "AA:BB:CC"
    assert parsers.normalize_oui_prefix("00:1b:c5:00:00/36") == "00:1B:C5:00:00/36"
    assert parsers.normalize_oui_prefix("28EED31/28") is None  # too short for whole octets
    assert parsers.normalize_oui_prefix("28EED310/28") == "28:EE:D3:10/28"


def test_normalize_domain_rules():
    assert parsers.normalize_domain("Example.COM.") == "example.com"
    assert parsers.normalize_domain("bücher.example") == "xn--bcher-kva.example"
    assert parsers.normalize_domain("localhost") is None
    assert parsers.normalize_domain("1.2.3.4") is None
    assert parsers.normalize_domain("bad domain.example") is None
    assert parsers.normalize_domain("a" * 64 + ".example") is None


# ---------------------------------------------------------------- registry ---

SPEC_URLS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "oui": "https://www.wireshark.org/download/automated/data/manuf",
    "oisd_small": "https://small.oisd.nl",
    "oisd_big": "https://big.oisd.nl",
    "hagezi_pro": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "adguard_dns": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "urlhaus_filter": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
    "threatfox": "https://threatfox.abuse.ch/downloads/hostfile/",
    "phishing_army": "https://phishing.army/download/phishing_army_blocklist.txt",
    "openphish": "https://openphish.com/feed.txt",
    "feodo_ips": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
}


def test_registry_matches_spec_table():
    assert list(registry.FEEDS) == list(SPEC_URLS)
    for name, url in SPEC_URLS.items():
        spec = registry.FEEDS[name]
        assert spec.url == url and spec.name == name
        assert spec.kind in {"kev", "epss", "oui", "hosts", "domains", "adblock", "ip", "json"}
        assert spec.parser is not None and spec.hours > 0 and spec.license_note
    assert {n for n, s in registry.FEEDS.items() if not s.enabled_default} == {"oisd_big", "stevenblack", "adguard_dns"}
    assert registry.FEEDS["kev"].hours == 6 and registry.FEEDS["oui"].hours == 168


def test_load_kev_and_search(env):
    assert registry.load_kev().count == 0  # nothing on disk yet
    install_fixture("kev", "kev_sample.json")
    kev = registry.load_kev()
    assert kev.count == 6 and kev.date_released.startswith("2026-09-03")
    assert kev.by_cve["CVE-2024-6387"]["product"] == "OpenSSH"

    def ids(vendor, product):
        return sorted(e["cveID"] for e in kev.search(vendor, product))

    assert ids(None, "lighttpd") == ["CVE-2018-19052"]
    assert ids("LIGHTTPD", "LightTPD") == ["CVE-2018-19052"]
    assert ids("openbsd", "openssh") == ["CVE-2024-6387"]
    assert ids(None, "OpenSSH") == ["CVE-2024-6387"]
    assert ids("Apache", "httpd") == ["CVE-2021-41773"]  # alias httpd -> HTTP Server
    assert ids("Microsoft", "Windows") == ["CVE-2017-0144"]
    assert ids("Citrix", "netscaler") == ["CVE-2023-4966"]  # token containment
    assert ids("Nokia", "lighttpd") == []  # contradicting vendor narrows
    assert ids(None, "nginx") == []
    assert ids(None, None) == [] and ids("", "") == []


def test_load_epss(env):
    assert registry.load_epss() == {}
    install_fixture("epss", "epss_sample.csv")
    assert registry.load_epss()["CVE-2017-0144"] == pytest.approx(0.97493)


def test_lookup_vendor_formats_and_prefix_lengths(env):
    assert registry.lookup_vendor("3c:22:fb:11:22:33") is None  # no OUI file yet
    install_fixture("oui", "manuf_sample.txt")
    apple = "Apple, Inc."
    assert registry.lookup_vendor("3c:22:fb:11:22:33") == apple
    assert registry.lookup_vendor("3C-22-FB-11-22-33") == apple
    assert registry.lookup_vendor("3c22.fb11.2233") == apple
    assert registry.lookup_vendor("3C22FB112233") == apple
    assert registry.lookup_vendor("3c:22:fb") == apple  # bare prefix
    assert registry.lookup_vendor("00:1b:c5:00:1f:aa") == "OpenRB.com, Direct SIA"  # /36
    assert registry.lookup_vendor("00:1b:c5:00:0f:aa") == "Converge ICT Solutions Inc."  # /36 sibling block
    assert registry.lookup_vendor("28:ee:d3:1a:bc:de") == "IRAF SRL"  # /28
    assert registry.lookup_vendor("28:ee:d3:0a:bc:de") == "REA Energie GmbH"
    assert registry.lookup_vendor("70:b3:d5:01:d5:00") == "Kaindl Electronic GmbH"
    assert registry.lookup_vendor("b8:27:eb:01:02:03") == "Raspberry Pi Foundation"
    assert registry.lookup_vendor("02:00:00:00:00:01") is None
    assert registry.lookup_vendor("") is None and registry.lookup_vendor("zz:zz") is None


def test_load_blocklist_and_ipset(env):
    assert registry.load_blocklist("oisd_small") == set()
    assert registry.load_blocklist("kev") == set()  # not a domain feed
    install_fixture("oisd_small", "domains_abp.txt")
    install_fixture("hagezi_pro", "wildcard.txt")
    install_fixture("urlhaus", "hosts.txt")
    install_fixture("spamhaus_drop", "ips.txt")
    oisd = registry.load_blocklist("oisd_small")
    assert "tracker.example.net" in oisd and "allowed.example.com" not in oisd
    assert all(d == d.lower() and not d.endswith(".") for d in oisd)
    assert "ads.example.com" in registry.load_blocklist("hagezi_pro")
    assert "analytics.example.org" in registry.load_blocklist("urlhaus")
    nets = registry.load_ipset("spamhaus_drop")
    assert ipaddress.ip_network("1.19.0.0/16") in nets
    assert registry.load_ipset("oisd_small") == []


def test_cache_invalidates_on_file_change(env):
    path = install_fixture("hagezi_pro", "wildcard.txt")
    first = registry.load_blocklist("hagezi_pro")
    assert registry.load_blocklist("hagezi_pro") is first  # same object: served from cache
    path.write_text("*.new.example.com\n", encoding="utf-8")
    # force a distinct mtime even on coarse filesystems
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
    second = registry.load_blocklist("hagezi_pro")
    assert second == {"new.example.com"} and second is not first
    registry.clear_cache("hagezi_pro")
    assert registry.load_blocklist("hagezi_pro") == {"new.example.com"}


def test_feed_status_shape(env, http):
    cfg = make_cfg()
    http.queue.append(FakeResponse(200, read_fixture("wildcard.txt").encode(), {"ETag": '"w1"'}))
    assert updater.update(cfg, env.conn, ["hagezi_pro"]) == {"hagezi_pro": "updated"}
    rows = registry.feed_status(env.conn)
    assert [r["name"] for r in rows] == list(registry.FEEDS)
    by = {r["name"]: r for r in rows}
    hz = by["hagezi_pro"]
    assert hz["status"] == "ok" and hz["entries"] == 5 and hz["file_exists"] and not hz["stale"]
    assert hz["etag"] == '"w1"' and hz["last_updated"] and hz["enabled"] is True
    kev = by["kev"]
    assert kev["status"] == "never" and kev["stale"] is True and kev["file_exists"] is False
    assert by["oisd_big"]["enabled"] is False
    expected_keys = {"name", "kind", "url", "hours", "enabled", "status", "last_checked", "last_updated",
                     "bytes", "entries", "error", "stale", "file_exists", "file_bytes", "license_note", "etag"}
    assert all(expected_keys <= set(r) for r in rows)


# ----------------------------------------------------------------- updater ---


def test_update_downloads_atomically_and_records_row(env, http):
    cfg = make_cfg()
    body = read_fixture("kev_sample.json").encode()
    http.queue.append(FakeResponse(200, body, {"ETag": '"abc"', "Last-Modified": "Wed, 03 Sep 2026 14:02:11 GMT",
                                                "Content-Length": str(len(body))}))
    assert updater.update(cfg, env.conn, ["kev"]) == {"kev": "updated"}
    path = updater.feed_path("kev")
    assert path.name == "kev.json" and path.read_bytes() == body
    assert not (path.parent / "kev.tmp").exists()
    assert path.with_suffix(".json.sha256").read_text().split()[0] == hashlib.sha256(body).hexdigest()
    row = dict(env.conn.execute("SELECT * FROM feeds WHERE name='kev'").fetchone())
    assert row["status"] == "ok" and row["etag"] == '"abc"' and row["bytes"] == len(body) and row["entries"] == 6
    assert row["last_updated"] and row["last_checked"] and row["error"] is None
    assert row["url"] == SPEC_URLS["kev"] and row["kind"] == "kev"
    # request carried no conditional headers because nothing was on disk yet
    assert "If-None-Match" not in http.calls[0]["headers"]
    assert http.calls[0]["headers"]["User-Agent"].startswith("HomeSOC/")
    assert registry.load_kev().count == 6


def test_update_conditional_get_and_staleness(env, http):
    cfg = make_cfg()
    body = read_fixture("epss_sample.csv").encode()
    http.queue.append(FakeResponse(200, body, {"ETag": '"e1"', "Last-Modified": "Wed, 03 Sep 2026 00:00:00 GMT"}))
    assert updater.update(cfg, env.conn, ["epss"])["epss"] == "updated"
    # fresh -> skipped without any HTTP call
    assert updater.update(cfg, env.conn, ["epss"])["epss"] == "skipped"
    assert len(http.calls) == 1
    # force -> conditional GET -> 304
    http.queue.append(FakeResponse(304))
    assert updater.update(cfg, env.conn, ["epss"], force=True)["epss"] == "not_modified"
    hdrs = http.calls[1]["headers"]
    assert hdrs["If-None-Match"] == '"e1"' and hdrs["If-Modified-Since"] == "Wed, 03 Sep 2026 00:00:00 GMT"
    assert updater.feed_path("epss").read_bytes() == body
    assert not updater.is_stale(env.conn, "epss", 24)
    # make the row old -> stale -> fetched again
    old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
    env.conn.execute("UPDATE feeds SET last_updated=? WHERE name='epss'", (old,))
    env.conn.commit()
    assert updater.is_stale(env.conn, "epss", 24)
    http.queue.append(FakeResponse(304))
    assert updater.update(cfg, env.conn, ["epss"])["epss"] == "not_modified"
    assert len(http.calls) == 3


def test_update_inflates_gzip(env, http):
    cfg = make_cfg()
    raw = read_fixture("epss_sample.csv").encode()
    http.queue.append(FakeResponse(200, gzip.compress(raw), {"Content-Type": "application/gzip"}))
    assert updater.update(cfg, env.conn, ["epss"])["epss"] == "updated"
    assert updater.feed_path("epss").read_bytes() == raw
    row = dict(env.conn.execute("SELECT bytes, entries FROM feeds WHERE name='epss'").fetchone())
    assert row["bytes"] == len(raw) and row["entries"] == 8
    assert registry.load_epss()["CVE-2024-6387"] == pytest.approx(0.61834)


def test_update_enforces_size_cap_and_keeps_old_file(env, http):
    cfg = make_cfg(max_download_mb=0.001)  # ~1 KB
    small = b"0.0.0.0 tiny.example.com\n"
    http.queue.append(FakeResponse(200, small))
    assert updater.update(cfg, env.conn, ["urlhaus"])["urlhaus"] == "updated"
    big = b"0.0.0.0 big.example.com\n" * 200
    http.queue.append(FakeResponse(200, big))
    assert updater.update(cfg, env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    assert updater.feed_path("urlhaus").read_bytes() == small
    assert not (updater.feed_path("urlhaus").parent / "urlhaus.tmp").exists()
    row = dict(env.conn.execute("SELECT status, error FROM feeds WHERE name='urlhaus'").fetchone())
    assert row["status"] == "error" and "cap" in row["error"]
    # declared Content-Length above the cap is refused before reading the body
    http.queue.append(FakeResponse(200, small, {"Content-Length": str(10 * 1024 * 1024)}))
    assert updater.update(cfg, env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    # gzip bomb: tiny on the wire, huge inflated
    http.queue.append(FakeResponse(200, gzip.compress(b"0.0.0.0 x.example.com\n" * 5000)))
    assert updater.update(cfg, env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    assert updater.feed_path("urlhaus").read_bytes() == small


def test_update_error_paths(env, http):
    cfg = make_cfg()
    http.queue.append(FakeResponse(500))
    http.queue.append(FakeResponse(200, b"<html>Not a list</html>\n"))
    http.queue.append(FakeResponse(200, b""))
    assert updater.update(cfg, env.conn, ["threatfox"])["threatfox"] == "error"
    assert updater.update(cfg, env.conn, ["threatfox"], force=True)["threatfox"] == "error"
    assert updater.update(cfg, env.conn, ["threatfox"], force=True)["threatfox"] == "error"
    assert not updater.feed_path("threatfox").exists()
    row = dict(env.conn.execute("SELECT * FROM feeds WHERE name='threatfox'").fetchone())
    assert row["status"] == "error" and row["last_checked"] and row["last_updated"] is None

    def boom(url, headers, timeout):
        import requests

        raise requests.ConnectionError("dns failure")

    http_calls_before = len(http.calls)
    import homesoc.feeds.updater as mod

    orig = mod._http_get
    mod._http_get = boom
    try:
        assert updater.update(cfg, env.conn, ["openphish"])["openphish"] == "error"
    finally:
        mod._http_get = orig
    assert len(http.calls) == http_calls_before
    assert "request failed" in env.conn.execute("SELECT error FROM feeds WHERE name='openphish'").fetchone()[0]


def test_update_skips_unknown_disabled_and_globally_disabled(env, http):
    cfg = make_cfg()
    assert updater.update(cfg, env.conn, ["nope"]) == {"nope": "skipped"}
    assert updater.update(cfg, env.conn, ["oisd_big"]) == {"oisd_big": "skipped"}  # disabled by default
    assert http.calls == []
    http.queue.append(FakeResponse(200, read_fixture("domains_abp.txt").encode()))
    assert updater.update(cfg, env.conn, ["oisd_big"], force=True) == {"oisd_big": "updated"}
    assert updater.update(make_cfg(enabled=False), env.conn, ["kev"]) == {"kev": "skipped"}
    # user enabled a default-off list from the dashboard -> honoured
    env.conn.execute("UPDATE feeds SET enabled=1, last_updated=NULL WHERE name='oisd_big'")
    env.conn.commit()
    http.queue.append(FakeResponse(304))
    assert updater.update(cfg, env.conn, ["oisd_big"]) == {"oisd_big": "not_modified"}


def test_update_all_uses_registry_order_and_progress(env, http):
    cfg = make_cfg()
    # every enabled feed gets one 500 -> error; disabled ones are skipped; order preserved
    for _ in registry.FEEDS:
        http.queue.append(FakeResponse(500))
    seen: list[str] = []
    results = updater.update(cfg, env.conn, progress=seen.append)
    assert list(results) == list(registry.FEEDS)
    assert results["kev"] == "error" and results["oisd_big"] == "skipped"
    assert any("kev" in m for m in seen)
    assert env.conn.execute("SELECT COUNT(*) FROM feeds").fetchone()[0] == len(registry.FEEDS)


def test_effective_hours_prefers_config(env):
    cfg = make_cfg(kev_hours=2, blocklists_hours=48, threatintel_hours=3)
    assert updater.effective_hours(cfg, registry.FEEDS["kev"]) == 2
    assert updater.effective_hours(cfg, registry.FEEDS["oisd_small"]) == 48
    assert updater.effective_hours(cfg, registry.FEEDS["urlhaus"]) == 3
    assert updater.effective_hours(SimpleNamespace(), registry.FEEDS["oui"]) == 168


def test_health_findings(env, monkeypatch):
    if "homesoc.models" not in sys.modules:
        try:
            import homesoc.models  # noqa: F401
        except ImportError:
            stub = types.ModuleType("homesoc.models")

            @dataclass
            class FindingDraft:  # minimal stand-in until P1 lands models.py
                finding_id: str
                subject: str
                evidence: dict = field(default_factory=dict)
                detail: str | None = None
                severity: str | None = None
                device_id: int | None = None

            stub.FindingDraft = FindingDraft
            monkeypatch.setitem(sys.modules, "homesoc.models", stub)

    now = datetime.now(timezone.utc)
    fresh = now.isoformat()
    old = (now - timedelta(hours=72)).isoformat()
    rows = [
        ("kev", "ok", old, old),  # stale KEV -> SOC-FEED-002
        ("epss", "error", old, fresh),  # failing for 3 days -> SOC-FEED-001
        ("oui", "error", fresh, fresh),  # errored just now but recent success -> nothing
        ("urlhaus", "ok", fresh, fresh),
    ]
    for name, status, last_updated, last_checked in rows:
        spec = registry.FEEDS[name]
        env.conn.execute(
            "INSERT INTO feeds(name,url,kind,status,last_updated,last_checked,error) VALUES (?,?,?,?,?,?,?)",
            (name, spec.url, spec.kind, status, last_updated, last_checked, "HTTP 500" if status == "error" else None),
        )
    env.conn.execute("INSERT INTO feeds(name,url,kind,status,enabled) VALUES ('oisd_big','u','domains','error',0)")
    env.conn.commit()
    drafts = updater.health_findings(env.conn)
    got = {(d.finding_id, d.subject) for d in drafts}
    assert got == {("SOC-FEED-002", "feed:kev"), ("SOC-FEED-001", "feed:epss")}
    epss = next(d for d in drafts if d.subject == "feed:epss")
    assert epss.evidence["error"] == "HTTP 500" and epss.evidence["url"] == SPEC_URLS["epss"]


# ------------------------------------------- KEV search precision (regression) ---
#
# Regression cover for the false-positive bug: a bare vendor word ("microsoft",
# "apple", "cisco") used to match every KEV entry of that vendor, which turned one
# Windows port into hundreds of "high" findings.


def _kev_catalog_windows_shaped() -> registry.KevCatalog:
    """A catalog with the shape that broke the matcher: one huge vendor family."""
    entries = [
        {"cveID": f"CVE-2015-{1000 + i}", "vendorProject": "Microsoft", "product": "Windows",
         "vulnerabilityName": f"Microsoft Windows Vulnerability {i}", "dateAdded": "2022-01-01"}
        for i in range(170)
    ]
    entries += [
        {"cveID": "CVE-2016-2000", "vendorProject": "Microsoft", "product": "Internet Explorer",
         "vulnerabilityName": "Internet Explorer Memory Corruption", "dateAdded": "2022-01-01"},
        {"cveID": "CVE-2016-2001", "vendorProject": "Microsoft", "product": "Office",
         "vulnerabilityName": "Office RCE", "dateAdded": "2022-01-01"},
        {"cveID": "CVE-2016-3000", "vendorProject": "Apple", "product": "Multiple Products",
         "vulnerabilityName": "Apple Multiple Products Bug", "dateAdded": "2022-01-01"},
        {"cveID": "CVE-2016-4000", "vendorProject": "Cisco", "product": "IOS and IOS XE Software",
         "vulnerabilityName": "Cisco IOS Bug", "dateAdded": "2022-01-01"},
        {"cveID": "CVE-2018-19052", "vendorProject": "lighttpd", "product": "lighttpd",
         "vulnerabilityName": "lighttpd path traversal before 1.4.50", "dateAdded": "2025-11-04"},
    ]
    return registry.KevCatalog(entries=entries)


@pytest.mark.parametrize("vendor_word", ["microsoft", "Microsoft", "apple", "cisco", "MICROSOFT"])
def test_kev_search_never_expands_a_bare_vendor_word(vendor_word):
    kev = _kev_catalog_windows_shaped()
    assert kev.search("", vendor_word) == []
    assert kev.search(None, vendor_word) == []


def test_kev_search_requires_a_product_not_just_a_vendor():
    kev = _kev_catalog_windows_shaped()
    # the real product column still matches, and the caller's vendor narrows it
    assert len(kev.search("microsoft", "windows")) == 170
    assert [e["cveID"] for e in kev.search("microsoft", "office")] == ["CVE-2016-2001"]
    # vendor + product spelled out together is a product match, a vendor word alone is not
    assert len(kev.search("", "microsoft windows")) == 170
    assert kev.search("", "microsoft") == []
    # a product filed under both columns (lighttpd/lighttpd) must keep working
    assert [e["cveID"] for e in kev.search("", "lighttpd")] == ["CVE-2018-19052"]
    assert [e["cveID"] for e in kev.search("lighttpd", "lighttpd")] == ["CVE-2018-19052"]
    # a banner that is really vendor + product + service name matches nothing
    assert kev.search("", "Microsoft Windows RPC") == []
    assert kev.search("", "Apple remote desktop vnc") == []


def test_kev_search_contradicting_vendor_still_narrows():
    kev = _kev_catalog_windows_shaped()
    assert kev.search("nokia", "windows") == []
    assert kev.search("apple", "office") == []


# ----------------------------------------- 304 / deadlines (regression) ---


def test_not_modified_counts_as_a_successful_refresh(env, http):
    """HTTP 304 means "your copy is current" -- it must clear staleness, not preserve it."""
    cfg = make_cfg()
    http.queue.append(FakeResponse(200, read_fixture("kev_sample.json").encode(), {"ETag": '"v1"'}))
    assert updater.update(cfg, env.conn, ["kev"])["kev"] == "updated"
    path = updater.feed_path("kev")
    body = path.read_bytes()

    # Age the row and the file as if CISA had published nothing for three days.
    old_iso = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    env.conn.execute("UPDATE feeds SET last_updated=?, last_checked=? WHERE name='kev'", (old_iso, old_iso))
    env.conn.commit()
    old_epoch = (datetime.now(timezone.utc) - timedelta(hours=72)).timestamp()
    os.utime(path, (old_epoch, old_epoch))
    assert updater.is_stale(env.conn, "kev", 6)

    http.queue.append(FakeResponse(304))
    assert updater.update(cfg, env.conn, ["kev"])["kev"] == "not_modified"

    row = dict(env.conn.execute("SELECT status, error, last_checked, last_updated FROM feeds WHERE name='kev'").fetchone())
    assert row["status"] == "ok" and row["error"] is None
    assert row["last_updated"] == row["last_checked"]
    # SOC-FEED-002 / NET-DNS-003 read these three signals; all three must say "fresh"
    assert not updater.is_stale(env.conn, "kev", 6)
    assert path.stat().st_mtime > old_epoch + 3600
    assert path.read_bytes() == body  # the content itself is untouched
    assert updater.health_findings(env.conn) == []


def test_not_modified_without_a_local_copy_is_an_error(env, http):
    """A mirror answering 304 to an unconditional request must not fake freshness."""
    cfg = make_cfg()
    http.queue.append(FakeResponse(304))
    assert updater.update(cfg, env.conn, ["threatfox"])["threatfox"] == "error"
    row = dict(env.conn.execute("SELECT status, last_updated, error FROM feeds WHERE name='threatfox'").fetchone())
    assert row["status"] == "error" and row["last_updated"] is None
    assert "304" in row["error"]
    assert updater.is_stale(env.conn, "threatfox", 6)


class FakeClock:
    """Monotonic clock the test advances by hand; the server advances it per chunk."""

    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t


class TricklingResponse(FakeResponse):
    """A mirror that keeps the socket alive but takes `seconds` per chunk."""

    def __init__(self, chunks: int, chunk_bytes: int, seconds: float, clock: FakeClock):
        super().__init__(200, b"0" * (chunks * chunk_bytes))
        self._chunks, self._chunk_bytes, self._seconds, self._clock = chunks, chunk_bytes, seconds, clock

    def iter_content(self, chunk_size=65536):
        for _ in range(self._chunks):
            self._clock.t += self._seconds
            yield b"0" * self._chunk_bytes


@pytest.fixture
def fake_clock(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(updater, "time", SimpleNamespace(monotonic=clock.monotonic))
    return clock


def test_slow_mirror_hits_the_per_feed_wall_clock(env, http, fake_clock):
    """requests' read timeout is per-recv; without a deadline this held the scheduler thread."""
    cfg = make_cfg(max_download_mb=64)
    install_fixture("urlhaus", "hosts.txt")
    previous = updater.feed_path("urlhaus").read_bytes()
    # 1 MB per minute: fast enough for the throughput floor, far past FEED_MAX_SECONDS
    http.queue.append(TricklingResponse(chunks=20, chunk_bytes=1024 * 1024, seconds=60.0, clock=fake_clock))
    assert updater.update(cfg, env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    error = env.conn.execute("SELECT error FROM feeds WHERE name='urlhaus'").fetchone()[0]
    assert "exceeded" in error and str(int(updater.FEED_MAX_SECONDS)) in error
    assert updater.feed_path("urlhaus").read_bytes() == previous  # old list survives
    assert not (updater.feed_path("urlhaus").parent / "urlhaus.tmp").exists()


def test_dribbling_mirror_hits_the_throughput_floor(env, http, fake_clock):
    cfg = make_cfg(max_download_mb=64)
    # 16 bytes per 40 s: never reaches the 180 s deadline before the floor trips
    http.queue.append(TricklingResponse(chunks=50, chunk_bytes=16, seconds=40.0, clock=fake_clock))
    assert updater.update(cfg, env.conn, ["urlhaus"], force=True)["urlhaus"] == "error"
    error = env.conn.execute("SELECT error FROM feeds WHERE name='urlhaus'").fetchone()[0]
    assert "too slow" in error


def test_update_batch_deadline_skips_the_remaining_feeds(env, http, fake_clock, monkeypatch):
    """One stalling mirror must not eat the scheduler thread for the whole feed list."""
    cfg = make_cfg(max_download_mb=64)
    monkeypatch.setattr(updater, "UPDATE_MAX_SECONDS", 200.0)
    http.queue.append(TricklingResponse(chunks=20, chunk_bytes=1024 * 1024, seconds=60.0, clock=fake_clock))
    results = updater.update(cfg, env.conn, ["urlhaus", "threatfox", "openphish"], force=True)
    assert results["urlhaus"] == "error"
    # the first feed burned the whole allowance, so the rest are not even attempted
    assert fake_clock.t >= updater.UPDATE_MAX_SECONDS
    assert results["threatfox"] == "skipped" and results["openphish"] == "skipped"
    assert len(http.calls) == 1


def test_failing_feed_backs_off_instead_of_retrying_every_run(env, http):
    cfg = make_cfg()
    http.queue.append(FakeResponse(500))
    assert updater.update(cfg, env.conn, ["threatfox"])["threatfox"] == "error"
    assert updater.consecutive_failures(env.conn, "threatfox") == 1
    assert updater.error_since(env.conn, "threatfox") is not None
    # a second run inside the backoff window must not touch the network at all
    assert updater.update(cfg, env.conn, ["threatfox"])["threatfox"] == "skipped"
    assert len(http.calls) == 1
    retry_at = updater.backoff_until(env.conn, "threatfox")
    assert retry_at is not None and retry_at > datetime.now(timezone.utc)
    # force is the user pressing the button: it bypasses the backoff
    http.queue.append(FakeResponse(200, b"0.0.0.0 bad.example.com\n"))
    assert updater.update(cfg, env.conn, ["threatfox"], force=True)["threatfox"] == "updated"
    assert updater.consecutive_failures(env.conn, "threatfox") == 0
    assert updater.error_since(env.conn, "threatfox") is None


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("HOMESOC_LIVE"), reason="live network test; set HOMESOC_LIVE=1")
def test_live_update_real_urls(env):
    """Network test against the real feeds; run with `HOMESOC_LIVE=1 pytest -m live`."""
    cfg = make_cfg(max_download_mb=64)
    results = updater.update(cfg, env.conn, ["kev", "urlhaus", "feodo_ips"], force=True)
    assert set(results.values()) <= {"updated", "not_modified"}
    assert registry.load_kev().count > 1000
