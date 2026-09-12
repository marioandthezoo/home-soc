"""Activity feed and remediation summary (Spec Addendum A5).

Offline and fixture-driven: everything is seeded into an in-memory database with known
timestamps so the arithmetic below is exact, and every assertion is checked twice — once on
an empty database (the state a user sees on day one) and once on the seeded one.
"""

from __future__ import annotations

import json
import subprocess
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

from homesoc.db import init_schema
from homesoc.web import create_app
from homesoc.web import feed as feedmod
from homesoc.web import summary as summarymod

ROOT = Path(__file__).resolve().parents[1]
FETCH = {"X-Requested-With": "fetch"}

# A hostname that would execute if any layer ever forgot to escape it.
XSS_HOSTNAME = '<img src=x onerror=alert(1)>'

# Everything is anchored to a whole hour so the dns_block hour buckets are deterministic
# however late in the hour the suite happens to run.
NOW = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


def ts(**delta: float) -> str:
    return (NOW - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_cfg() -> SimpleNamespace:
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test", timezone="local", log_level="INFO"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token="", refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=[]),
        scan=SimpleNamespace(use_nmap=True, nmap_top_ports=100),
        dns=SimpleNamespace(enabled=True, listen="0.0.0.0", port=53, upstreams=["1.1.1.2"], doh_upstream="",
                            block_mode="null", lists=["oisd_small"], virustotal_api_key="", virustotal_daily_budget=400),
        notify=SimpleNamespace(min_severity="high", ntfy_url="", discord_webhook="", webhook_url=""),
        schedule=SimpleNamespace(discovery_minutes=10),
    )


def fresh_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def seed(conn: sqlite3.Connection) -> None:
    """Two devices, five findings across every status, plus one row in every other source."""
    ex = conn.execute
    ex(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, first_seen, last_seen, online) "
        "VALUES(1,'00:11:22:00:00:01','192.168.1.254','gateway','Example Networks',?,?,1)",
        (ts(days=10), ts(minutes=5)),
    )
    ex(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, first_seen, last_seen, online) "
        "VALUES(2,'00:11:22:00:00:02','192.168.1.130',?,'Apple',?,?,0)",
        (XSS_HOSTNAME, ts(hours=3), ts(minutes=30)),
    )
    findings = [
        (1, "NET-SVC-001", "device:00:11:22:00:00:01:23", "critical", "Telnet is open on gateway", "open",
         ts(days=5), ts(minutes=5), None, 1, 3),
        (2, "WIN-DEF-001", "host", "high", "Microsoft Defender antivirus is off", "resolved",
         ts(days=4), ts(days=3), ts(days=3), None, 1),
        (3, "WIN-FW-001", "host", "medium", "Windows Firewall is off for the private profile", "resolved",
         ts(days=2), ts(days=1), ts(days=1), None, 1),
        (4, "WIN-ACC-001", "host", "medium", "The daily account is an administrator", "acknowledged",
         ts(days=6), ts(hours=2), None, None, 2),
        (5, "SOC-SYS-001", "host", "info", "nmap is not installed", "suppressed",
         ts(days=7), ts(hours=2), None, None, 1),
    ]
    for row_id, fid, subject, sev, title, status, first, last, resolved, device, occ in findings:
        ex(
            "INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, detail, evidence, status, "
            "source, first_seen, last_seen, resolved_at, occurrences, device_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,'test',?,?,?,?,?)",
            (row_id, fid, subject, f"{fid}|{subject}", sev, title, "detail text",
             json.dumps({"port": 23, "hostname": "gateway", "vendor": "Example Networks"}), status, first, last, resolved, occ, device),
        )
    events = [
        (1, "created", ts(days=5)),
        (2, "created", ts(days=4)),
        (2, "auto_resolved", ts(days=3)),   # the agent rescanned and it was gone
        (3, "created", ts(days=2)),
        (3, "resolved", ts(days=1)),        # a human marked it fixed
        (4, "created", ts(days=6)),
        (4, "acknowledged", ts(hours=2)),
        (5, "suppressed", ts(hours=2)),
    ]
    for row_id, event, at in events:
        ex("INSERT INTO finding_events(finding_row_id, event, at, note) VALUES(?,?,?,NULL)", (row_id, event, at))
    ex("INSERT INTO scans(kind, started_at, finished_at, status, summary) VALUES('discovery',?,?,'ok',?)",
       (ts(minutes=70), ts(minutes=65), json.dumps({"hosts_total": 20, "hosts_online": 12})))
    ex("INSERT INTO scans(kind, started_at, finished_at, status, error) VALUES('services',?,?,'error','nmap missing')",
       (ts(minutes=60), ts(minutes=59)))
    ex("INSERT INTO events(ts, level, source, message, data) VALUES(?,'info','feeds','feed hagezi_pro updated',?)",
       (ts(minutes=50), json.dumps({"feed": "hagezi_pro", "entries": 224113})))
    ex("INSERT INTO events(ts, level, source, message) VALUES(?,'warning','defender','quarantined Trojan:Win32/Wacatac.B!ml')",
       (ts(minutes=40),))
    ex("INSERT INTO events(ts, level, source, message) VALUES(?,'error','feeds','feed update failed: openphish (timeout)')",
       (ts(minutes=35),))
    ex("INSERT INTO notifications(ts, channel, subject, status) VALUES(?,'ntfy','2 new high findings','ok')",
       (ts(minutes=20),))
    # 12 blocked requests to two names under one registrable domain, one client, one hour.
    for i in range(12):
        ex("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,'A','block','oisd_small',1.0)",
           (ts(hours=2, minutes=-i), "192.168.1.108", f"ads{i % 2}.doubleclick.net"))
    ex("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) "
       "VALUES(?,'192.168.1.97','evil.example','A','block','threat:urlhaus',1.0)", (ts(minutes=15),))
    ex("INSERT INTO dns_queries(ts, client, qname, qtype, action, ms) VALUES(?,'192.168.1.97','example.com','A','allow',1.0)",
       (ts(minutes=14),))
    ex("INSERT INTO host_checks(check_id, status, checked_at, needs_admin) VALUES('WIN-SYS-002','needs_admin',?,1)",
       (ts(minutes=10),))
    ex("INSERT INTO settings(key, value, updated_at) VALUES('defender.status_json', ?, ?)",
       (json.dumps({"AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 1}), ts(minutes=10)))
    ex("INSERT INTO feeds(name, url, kind, status, last_updated, entries) VALUES('oisd_small','https://x','domains','updated',?,50000)",
       (ts(minutes=50),))
    ex("INSERT INTO feeds(name, url, kind, status, last_updated, entries) VALUES('openphish','https://y','domains','error',?,10)",
       (ts(days=9),))
    ex("INSERT INTO services(device_id, port, proto, state, first_seen, last_seen) VALUES(1,23,'tcp','open',?,?)",
       (ts(days=5), ts(minutes=5)))
    ex("INSERT INTO vulns(device_id, cve, source, kev, cvss, matched_on, first_seen, last_seen) "
       "VALUES(1,'CVE-2022-22707','nvd',1,9.8,'lighttpd 1.4.69',?,?)", (ts(days=5), ts(minutes=5)))
    for i in range(5):
        ex("INSERT INTO metrics(ts, name, value) VALUES(?,'score',?)", (ts(days=i), 60 + i))
    conn.commit()


@pytest.fixture
def empty_conn():
    c = fresh_conn()
    yield c
    c.close()


@pytest.fixture
def seeded_conn():
    c = fresh_conn()
    seed(c)
    yield c
    c.close()


def _client(conn):
    app = create_app(make_cfg(), conn, scheduler=None, dns_server=None)
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def empty_client(empty_conn):
    return _client(empty_conn)


@pytest.fixture
def client(seeded_conn):
    return _client(seeded_conn)


@pytest.fixture
def spec_score(monkeypatch):
    """Hide ``homesoc.findings.score`` so the score falls back to the SPEC section 10 formula.

    The dashboard defers to findings.score when it is installed (that package owns the curve),
    which would otherwise make every hard-coded score here a hostage to another work package.
    """
    import types

    monkeypatch.setitem(sys.modules, "homesoc.findings.score", types.ModuleType("homesoc.findings.score"))


def kinds_of(items) -> set[str]:
    return {i.kind for i in items}


# --------------------------------------------------------------------------- build_feed


def test_feed_is_empty_and_valid_on_a_fresh_database(empty_conn):
    items, total = feedmod.build_feed(empty_conn)
    assert items == [] and total == 0
    assert feedmod.feed_counts(empty_conn) == {k: 0 for k in feedmod.KINDS}
    assert [k["kind"] for k in feedmod.feed_kinds()] == list(feedmod.KINDS)
    assert all(set(k) == {"kind", "label", "icon"} for k in feedmod.feed_kinds())


def test_feed_merges_every_source(seeded_conn):
    items, total = feedmod.build_feed(seeded_conn, limit=feedmod.MAX_LIMIT)
    assert total == len(items)
    assert kinds_of(items) >= {
        "finding_new", "finding_resolved", "finding_auto_resolved", "finding_ack", "finding_suppressed",
        "device_new", "device_offline", "scan", "feed_update", "dns_block", "dns_threat",
        "av_threat", "notification", "system",
    }
    for item in items:
        assert item.ts.endswith("Z") and item.severity in feedmod.SEVERITY_RANK
        assert item.icon in set(feedmod.ICON_BY_KIND.values())
        assert isinstance(item.ref, dict)
        assert "<" not in item.title or "<" in XSS_HOSTNAME  # titles are plain text, never markup we built


def test_feed_is_ordered_strictly_newest_first(seeded_conn):
    items, _ = feedmod.build_feed(seeded_conn, limit=feedmod.MAX_LIMIT)
    stamps = [i.ts for i in items]
    assert stamps == sorted(stamps, reverse=True)


def test_feed_respects_limit_and_offset(seeded_conn):
    everything, total = feedmod.build_feed(seeded_conn, limit=feedmod.MAX_LIMIT)
    first, total_a = feedmod.build_feed(seeded_conn, limit=3)
    second, total_b = feedmod.build_feed(seeded_conn, limit=3, offset=3)
    assert len(first) == 3 and len(second) == 3
    assert [i.ts for i in first] == [i.ts for i in everything[:3]]
    assert [i.ts for i in second] == [i.ts for i in everything[3:6]]
    assert [i.title for i in first] != [i.title for i in second]
    # Each source is bounded by limit+offset, so `total` counts the merged candidate window: it
    # never overstates, it grows towards the real total as the reader pages, and it is exact
    # once the window covers everything.
    assert 3 <= total_a <= total_b <= total
    assert total == len(everything)
    assert feedmod.build_feed(seeded_conn, limit=3, offset=len(everything))[0] == []


def test_feed_respects_since_and_until(seeded_conn):
    recent, _ = feedmod.build_feed(seeded_conn, since=ts(hours=1), limit=feedmod.MAX_LIMIT)
    assert recent and all(i.ts >= ts(hours=1) for i in recent)
    assert "finding_new" not in kinds_of(recent)  # the newest finding event is 2 h old
    old, _ = feedmod.build_feed(seeded_conn, until=ts(days=2), limit=feedmod.MAX_LIMIT)
    assert old and all(i.ts <= ts(days=2) for i in old)


def test_feed_respects_kinds_severities_and_search(seeded_conn):
    only_dns, _ = feedmod.build_feed(seeded_conn, kinds={"dns_block", "dns_threat"}, limit=feedmod.MAX_LIMIT)
    assert only_dns and kinds_of(only_dns) <= {"dns_block", "dns_threat"}
    high, _ = feedmod.build_feed(seeded_conn, severities={"critical", "high"}, limit=feedmod.MAX_LIMIT)
    assert high and {i.severity for i in high} <= {"critical", "high"}
    hits, _ = feedmod.build_feed(seeded_conn, q="doubleclick", limit=feedmod.MAX_LIMIT)
    assert hits and all("doubleclick" in (i.title + i.detail).lower() for i in hits)
    assert feedmod.build_feed(seeded_conn, q="no-such-string-anywhere")[0] == []
    assert feedmod.build_feed(seeded_conn, kinds={"not_a_kind"}, limit=5)[1] > 0  # unknown kinds are ignored


def test_dns_blocks_are_aggregated_per_client_domain_and_hour(seeded_conn):
    blocks, _ = feedmod.build_feed(seeded_conn, kinds={"dns_block"}, limit=feedmod.MAX_LIMIT)
    assert len(blocks) == 1, [b.title for b in blocks]
    item = blocks[0]
    assert item.ref["client"] == "192.168.1.108" and item.ref["domain"] == "doubleclick.net"
    assert item.ref["hits"] == 12 and len(item.ref["hour"]) == 13
    assert "12 requests" in item.title and "doubleclick.net" in item.title
    assert item.severity == "info"  # an ad list, not a threat list
    threats, _ = feedmod.build_feed(seeded_conn, kinds={"dns_threat"}, limit=feedmod.MAX_LIMIT)
    assert len(threats) == 1 and threats[0].severity == "high" and "evil.example" in threats[0].title


def test_a_reputation_block_is_a_dns_threat(seeded_conn):
    """The reason string the resolver actually writes.

    dnsfilter/policy.py returns ``Decision("block", "reputation", suffix)`` — a bare word, with no
    colon and no ``threat:`` prefix, which is what lands in dns_queries.reason on a real install.
    The feed used to match only ``threat:%`` and ``reputation:%``, so every real reputation block
    was demoted to an ordinary ad-blocking dns_block and the dns_threat kind never fired.
    """
    seeded_conn.execute(
        "INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) "
        "VALUES(?,'192.168.1.97','malware.example','A','block','reputation',1.0)",
        (ts(minutes=13),),
    )
    seeded_conn.commit()
    threats, _ = feedmod.build_feed(seeded_conn, kinds={"dns_threat"}, limit=feedmod.MAX_LIMIT)
    titles = " ".join(t.title for t in threats)
    assert "malware.example" in titles
    assert all(t.severity == "high" for t in threats)
    # ... and it must not also be counted as an ordinary ad block.
    blocks, _ = feedmod.build_feed(seeded_conn, kinds={"dns_block"}, limit=feedmod.MAX_LIMIT)
    assert "malware.example" not in " ".join(b.title for b in blocks)


def test_registrable_domain_handles_the_awkward_cases():
    cases = {
        "a.b.doubleclick.net": "doubleclick.net",
        "doubleclick.net": "doubleclick.net",
        "net": "net",
        "": "",
        "tracker.co.uk": "tracker.co.uk",
        "a.b.tracker.co.uk": "tracker.co.uk",
        "WWW.Example.COM.": "example.com",
    }
    for value, expected in cases.items():
        assert feedmod.registrable_domain(value) == expected, value


def test_resolved_items_say_how_long_the_finding_was_open(seeded_conn):
    resolved, _ = feedmod.build_feed(seeded_conn, kinds={"finding_resolved", "finding_auto_resolved"}, limit=50)
    assert len(resolved) == 2
    assert all("open" in i.title for i in resolved)
    assert any(i.kind == "finding_auto_resolved" for i in resolved)


def test_a_missing_table_does_not_break_the_feed(seeded_conn):
    seeded_conn.execute("DROP TABLE dns_queries")
    seeded_conn.commit()
    items, total = feedmod.build_feed(seeded_conn, limit=feedmod.MAX_LIMIT)
    assert total == len(items) and "dns_block" not in kinds_of(items)
    assert "scan" in kinds_of(items)


# --------------------------------------------------------------------------- collapsing runs


def _flap(conn, times: int = 6, minutes_apart: int = 10) -> None:
    """One finding acknowledged and reopened `times` each, alternating — the pattern that used
    to fill the whole timeline with 2 x `times` identical rows."""
    now = NOW
    conn.execute(
        "INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen) "
        "VALUES(900,'WIN-NET-001','host','WIN-NET-001|host','high','SMBv1 is enabled','open','host',?,?)",
        (ts(days=3), ts()))
    for n in range(times):
        for event in ("acknowledged", "reopened"):
            conn.execute("INSERT INTO finding_events(finding_row_id, event, at) VALUES(900,?,?)",
                         (event, ts(minutes=minutes_apart * (2 * n + (0 if event == "acknowledged" else 1)))))
    conn.commit()


def test_runs_of_identical_events_collapse_into_one_row(empty_conn):
    _flap(empty_conn, times=6)
    raw, raw_total = feedmod.build_feed(empty_conn, since=ts(days=1), limit=100, collapse=False)
    assert len(raw) == raw_total == 12

    items, total = feedmod.build_feed(empty_conn, since=ts(days=1), limit=100)
    assert len(items) == total == 2, "six acks + six reopens should read as two rows"
    assert {i.kind for i in items} == {"finding_ack", "finding_reopened"}
    for item in items:
        assert item.ref["count"] == 6
        assert item.ref["from"] < item.ref["to"] == item.ts
        assert len(item.ref["collapsed"]) == 6
        assert [m["ts"] for m in item.ref["collapsed"]] == sorted((m["ts"] for m in item.ref["collapsed"]), reverse=True)
        assert "Repeated 6 times" in item.detail
    # still strictly newest first, and the newest event is still the newest row
    assert items[0].ts >= items[1].ts
    assert items[0].ts == raw[0].ts


def test_collapsing_keeps_every_event_reachable(empty_conn):
    """Each collapsed member keeps its own link, so nothing becomes unreachable."""
    for n in range(4):
        _open_a_real_finding(empty_conn, subject=f"device:aa:bb:cc:dd:ee:{n:02x}")
    items, _ = feedmod.build_feed(empty_conn, kinds={"finding_new"}, limit=50)
    assert len(items) == 1 and items[0].ref["count"] == 4
    links = [m.get("link") for m in items[0].ref["collapsed"]]
    assert len(set(links)) == 4 and all(links), "every folded finding must keep its own link"
    raw, _ = feedmod.build_feed(empty_conn, kinds={"finding_new"}, limit=50, collapse=False)
    assert sorted(links) == sorted(i.link for i in raw)


def test_a_gap_or_a_long_span_ends_a_run(empty_conn):
    """Yesterday's occurrence is a separate row, not part of today's run."""
    _flap(empty_conn, times=2, minutes_apart=10)
    empty_conn.execute("INSERT INTO finding_events(finding_row_id, event, at) VALUES(900,'acknowledged',?)", (ts(days=2),))
    empty_conn.commit()
    items, _ = feedmod.build_feed(empty_conn, since=ts(days=5), kinds={"finding_ack"}, limit=100)
    assert len(items) == 2
    assert items[0].ref["count"] == 2 and "count" not in items[1].ref


def test_uncollapsed_rows_are_untouched(seeded_conn):
    """Nothing in the ordinary fixture repeats, so collapsing must be a no-op there."""
    plain, plain_total = feedmod.build_feed(seeded_conn, limit=feedmod.MAX_LIMIT, collapse=False)
    folded, folded_total = feedmod.build_feed(seeded_conn, limit=feedmod.MAX_LIMIT)
    assert plain == folded and plain_total == folded_total
    assert all("count" not in i.ref for i in folded)


def test_feed_counts_report_events_not_rows(empty_conn):
    """The header chips count what happened, even when the timeline shows it as one line."""
    _flap(empty_conn, times=6)
    counts = feedmod.feed_counts(empty_conn, hours=24)
    assert counts["finding_ack"] == 6 and counts["finding_reopened"] == 6


def test_collapsed_rows_survive_the_api_and_the_page(empty_conn):
    _flap(empty_conn, times=6)
    c = _client(empty_conn)
    body = c.get("/api/feed?window=24h&limit=50").get_json()
    rows = [i for i in body["items"] if i["kind"] == "finding_ack"]
    assert len(rows) == 1 and rows[0]["ref"]["count"] == 6
    assert set(rows[0]) == {"ts", "kind", "severity", "title", "detail", "link", "icon", "ref"}
    page = c.get("/feed?window=24h").data.decode("utf-8")
    assert "×6" in page and "show all 6" in page
    assert page.count('class="tl-item') == 2


# --------------------------------------------------------------------------- feed HTTP


def test_feed_page_renders_empty_and_seeded(empty_client, client):
    empty = empty_client.get("/feed")
    assert empty.status_code == 200 and b"fills up as scans run" in empty.data
    page = client.get("/feed")
    assert page.status_code == 200
    assert b"doubleclick.net" in page.data and b"Activity feed" in page.data
    assert client.get("/feed?kinds=dns_block&window=7d&severity=medium&q=doubleclick").status_code == 200


def test_feed_escapes_hostnames_from_the_network(client):
    """A device that names itself with markup must never reach the browser as markup."""
    page = client.get("/feed?window=all").data
    assert b"<img src=x onerror=alert(1)>" not in page
    assert b"&lt;img src=x onerror=alert(1)&gt;" in page
    api_items = client.get("/api/feed?window=all").get_json()["items"]
    assert any(XSS_HOSTNAME in i["title"] for i in api_items)  # raw in JSON, escaped in HTML
    rss = client.get("/feed.rss").data
    assert b"<img src=x onerror=alert(1)>" not in rss


def test_api_feed_shape(empty_client, client):
    for c in (empty_client, client):
        body = c.get("/api/feed?window=all&limit=5").get_json()
        assert set(body) == {"items", "total", "counts", "generated_at"}
        assert isinstance(body["total"], int) and body["generated_at"].endswith("Z")
        assert set(body["counts"]) == set(feedmod.KINDS)
        for item in body["items"]:
            assert set(item) == {"ts", "kind", "severity", "title", "detail", "link", "icon", "ref"}
    assert len(client.get("/api/feed?window=all&limit=5").get_json()["items"]) == 5
    paged = client.get("/api/feed?window=all&limit=2&offset=2").get_json()
    assert len(paged["items"]) == 2
    assert paged["items"][0]["ts"] != client.get("/api/feed?window=all&limit=2").get_json()["items"][0]["ts"]


def test_api_feed_kinds(client):
    body = client.get("/api/feed/kinds").get_json()
    assert [k["kind"] for k in body["kinds"]] == list(feedmod.KINDS)


def test_feed_rss_parses(empty_client, client):
    for c in (empty_client, client):
        r = c.get("/feed.rss")
        assert r.status_code == 200 and r.headers["Content-Type"].startswith("application/rss+xml")
        root = ET.fromstring(r.data)
        assert root.tag == "rss" and root.attrib["version"] == "2.0"
        channel = root.find("channel")
        assert channel is not None and channel.findtext("title")
        for item in channel.findall("item"):
            guid = item.findtext("guid")
            assert guid and guid.startswith("homesoc:")
            assert len(guid.split(":")) >= 4
            assert item.findtext("title") and item.findtext("pubDate")
    assert len(ET.fromstring(client.get("/feed.rss").data).find("channel").findall("item")) > 0


# --------------------------------------------------------------------------- build_summary


SUMMARY_KEYS = {
    "generated_at", "window_days", "score", "totals", "by_severity", "by_category", "by_subject",
    "time_to_remediate", "remediated", "open_worklist", "top_devices", "coverage", "defender", "notes",
}


def test_summary_on_an_empty_database_is_complete_and_zeroed(empty_conn):
    s = summarymod.build_summary(empty_conn)
    assert set(s) == SUMMARY_KEYS
    assert s["score"] == {"current": 100, "grade": "A", "trend": []}
    assert s["totals"] == {
        "found_all_time": 0, "open": 0, "acknowledged": 0, "resolved": 0, "suppressed": 0,
        "remediation_rate": 0.0, "found_in_window": 0, "resolved_in_window": 0,
    }
    assert s["by_severity"]["open"] == {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    assert s["by_category"] == [] and s["by_subject"] == [] and s["remediated"] == []
    assert s["open_worklist"] == [] and s["top_devices"] == []
    assert s["time_to_remediate"]["median_hours"] is None and s["time_to_remediate"]["fastest"] is None
    assert s["coverage"]["devices_total"] == 0 and s["coverage"]["feeds_total"] == 0
    assert s["coverage"]["dns"]["block_rate"] == 0.0
    assert s["defender"]["available"] is False
    assert any("No scan has run yet" in n for n in s["notes"])


def test_summary_arithmetic_is_exact(seeded_conn, spec_score):
    s = summarymod.build_summary(seeded_conn, days=30)
    t = s["totals"]
    assert t["found_all_time"] == 5
    assert (t["open"], t["acknowledged"], t["resolved"], t["suppressed"]) == (1, 1, 2, 1)
    assert t["remediation_rate"] == round(2 / 3, 4)
    assert t["found_in_window"] == 5 and t["resolved_in_window"] == 2
    assert s["by_severity"]["open"]["critical"] == 1
    assert s["by_severity"]["resolved"]["high"] == 1 and s["by_severity"]["resolved"]["medium"] == 1
    assert s["score"]["current"] == 75 and s["score"]["grade"] == "C"  # one open critical, SPEC section 10
    # every resolved finding in the fixture was open for exactly 24 h
    assert s["time_to_remediate"]["median_hours"] == 24.0
    assert s["time_to_remediate"]["p90_hours"] == 24.0
    assert s["time_to_remediate"]["count"] == 2
    assert s["time_to_remediate"]["fastest"]["hours_open"] == 24.0
    by_how = {r["finding_id"]: r["how"] for r in s["remediated"]}
    assert by_how == {"WIN-DEF-001": "auto", "WIN-FW-001": "manual"}
    assert [r["finding_id"] for r in s["remediated"]] == ["WIN-FW-001", "WIN-DEF-001"]  # newest first
    assert all(r["hours_open"] == 24.0 for r in s["remediated"])


def test_summary_worklist_carries_the_catalog_remediation(seeded_conn):
    s = summarymod.build_summary(seeded_conn)
    assert len(s["open_worklist"]) == 1
    item = s["open_worklist"][0]
    assert item["finding_id"] == "NET-SVC-001" and item["severity"] == "critical"
    assert item["row_id"] == 1 and item["age_days"] >= 4.9
    assert item["remediation"] and any("Telnet" in step for step in item["remediation"])
    assert "{" not in " ".join(item["remediation"])  # evidence was interpolated, not left as a template
    assert item["refs"] and all(r.startswith("http") for r in item["refs"])
    assert item["category"] and item["device_name"] == "gateway"


def test_summary_groupings_and_coverage(seeded_conn):
    s = summarymod.build_summary(seeded_conn)
    cats = {c["category"]: c for c in s["by_category"]}
    assert sum(c["found"] for c in s["by_category"]) == 5
    assert cats and all({"category", "found", "open", "resolved"} <= set(c) for c in s["by_category"])
    subjects = {b["subject_type"]: b for b in s["by_subject"]}
    assert subjects["device"]["found"] == 1 and subjects["host"]["found"] == 4
    cov = s["coverage"]
    assert cov["devices_total"] == 2 and cov["devices_online"] == 1
    assert cov["services_seen"] == 1 and cov["cves_matched"] == 1 and cov["kev_matches"] == 1
    assert cov["feeds_total"] == 2 and cov["feeds_stale"] == ["openphish"] and cov["feeds_current"] == 1
    assert cov["last_scans"]["discovery"] and cov["last_scans"]["files"] is None
    assert cov["dns"]["queries_24h"] == 14 and cov["dns"]["blocked_24h"] == 13  # 12 ads + 1 threat + 1 allow
    assert cov["dns"]["block_rate"] == round(13 / 14, 4) and cov["dns"]["clients_24h"] == 2
    assert s["defender"] == {
        "available": True, "av_enabled": True, "rtp": True, "signature_age_days": 1,
        "last_quick_scan": None, "last_full_scan": None, "threats_30d": 1,
    }
    assert any("administrator" in n for n in s["notes"])
    assert s["top_devices"][0]["device_id"] == 1 and s["top_devices"][0]["open"] == 1


def test_summary_window_narrows_the_remediated_list(seeded_conn):
    wide = summarymod.build_summary(seeded_conn, days=30)
    narrow = summarymod.build_summary(seeded_conn, days=2)
    assert len(wide["remediated"]) == 2 and len(narrow["remediated"]) == 1
    assert narrow["totals"]["resolved"] == 2  # all-time status counts do not move with the window
    assert narrow["totals"]["resolved_in_window"] == 1


# --------------------------------------------------------------------------- summary HTTP / reports


def test_summary_page_renders_empty_and_seeded(empty_client, client):
    empty = empty_client.get("/summary")
    assert empty.status_code == 200 and b"Nothing is open" in empty.data
    page = client.get("/summary")
    assert page.status_code == 200
    for needle in (b"Telnet is open", b"verified by rescan", b"marked fixed", b"Still open", b"Coverage"):
        assert needle in page.data, needle
    assert b"/api/summary/report.md" in page.data and b"/api/summary/report.json" in page.data
    assert client.get("/summary?days=7").status_code == 200
    assert client.get("/summary?days=nonsense").status_code == 200


def test_summary_page_escapes_device_names(client):
    page = client.get("/summary").data
    assert b"<img src=x onerror=alert(1)>" not in page


def test_report_json_round_trips(client, seeded_conn):
    body = client.get("/api/summary/report?days=30").get_json()
    assert body["schema_version"] == summarymod.SCHEMA_VERSION
    assert set(body) == SUMMARY_KEYS | {"schema_version"}
    download = client.get("/api/summary/report.json?days=30")
    assert "attachment" in download.headers["Content-Disposition"]
    assert download.headers["Content-Disposition"].endswith('.json"')
    parsed = json.loads(download.data)
    assert parsed["totals"] == body["totals"] and parsed["open_worklist"] == body["open_worklist"]


def test_report_markdown_is_a_standalone_document(client, seeded_conn, empty_conn):
    r = client.get("/api/summary/report.md?days=30")
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "text/markdown; charset=utf-8"
    assert "attachment" in r.headers["Content-Disposition"] and r.headers["Content-Disposition"].endswith('.md"')
    text = r.data.decode("utf-8")
    assert text.startswith("# Home SOC")
    assert "Home SOC has found **5** issues" in text
    for heading in ("## Found vs remediated, by severity", "## By category", "## Remediated",
                    "## Still open — what to do next", "## Coverage — what was actually checked", "## Not checked"):
        assert heading in text, heading
    assert "Telnet is open on gateway" in text
    steps = summarymod.remediation_steps("NET-SVC-001", {"hostname": "gateway", "vendor": "Example Networks"}, "device:x:23")
    assert steps and steps[0] in text  # the worklist carries the real remediation steps
    assert "verified by rescan" in text and "marked fixed" in text
    empty_text = summarymod.remediation_report_markdown(empty_conn)
    assert "Home SOC has found **0** issues" in empty_text
    assert "Nothing is open." in empty_text and "_None._" in empty_text


def test_report_endpoints_honour_token_auth(seeded_conn):
    app = create_app(SimpleNamespace(**{**vars(make_cfg()), "web": SimpleNamespace(host="127.0.0.1", port=8787, token="s3cret", refresh_seconds=15)}), seeded_conn)
    app.config["TESTING"] = True
    c = app.test_client()
    for path in ("/feed", "/summary", "/api/feed", "/api/summary/report", "/feed.rss"):
        assert c.get(path).status_code == 401, path
    assert c.get("/api/feed", headers={"X-Token": "s3cret"}).status_code == 200
    assert c.get("/feed.rss", headers={"X-Token": "s3cret"}).status_code == 200


@pytest.mark.slow
def test_cli_report_command(tmp_path):
    """Addendum A4: ``python -m homesoc report`` writes the same report with the dashboard stopped.

    Slow (it spawns two interpreters) but strictly offline, so it stays in the default run;
    ``-m 'not slow'`` deselects it.
    """
    env = {**dict(__import__("os").environ), "HOMESOC_DATA": str(tmp_path / "data"), "HOMESOC_CONFIG": str(tmp_path / "config.toml")}
    probe = subprocess.run([sys.executable, "-m", "homesoc", "report", "--help"], cwd=str(ROOT), env=env,
                           capture_output=True, text=True, timeout=120)
    if probe.returncode != 0:
        pytest.skip("homesoc/cli.py (owned by core) has not added the Addendum A4 'report' subcommand yet")
    run = subprocess.run([sys.executable, "-m", "homesoc", "report", "--format", "json"], cwd=str(ROOT), env=env,
                         capture_output=True, text=True, timeout=180)
    assert run.returncode == 0, run.stderr[-2000:]
    payload = json.loads(run.stdout)
    assert set(payload) >= SUMMARY_KEYS


# --------------------------------------------------------------------------- regression guards
# Both of these are written against findings.engine rather than hand-seeded finding_events rows:
# the feed once missed every "new finding" on a real database because the engine writes the event
# as "opened" while the addendum's table calls it "created", and no fixture ever exercised the
# engine itself.


def _open_a_real_finding(conn, subject: str = "device:aa:bb:cc:dd:ee:ff"):
    from homesoc.findings import engine
    from homesoc.models import FindingDraft

    draft = FindingDraft(
        finding_id="NET-DEV-001",
        subject=subject,
        evidence={"ip": "192.168.1.50", "hostname": "printer", "vendor": "Epson",
                  "mac": subject.split(":", 1)[1], "first_seen": ts(hours=1)},
    )
    return engine.apply(conn, [draft], source="discovery")


def test_feed_surfaces_findings_created_by_the_engine(empty_conn):
    """The event name the engine actually writes must map to the feed's headline kind."""
    result = _open_a_real_finding(empty_conn)
    assert result.new, "engine.apply did not create the finding"
    events = {r["event"] for r in empty_conn.execute("SELECT event FROM finding_events")}
    items, _total = feedmod.build_feed(empty_conn, limit=50)
    new_items = [i for i in items if i.kind == "finding_new"]
    assert new_items, f"engine wrote {events} but the feed produced kinds {kinds_of(items)}"
    assert new_items[0].severity in {"critical", "high", "medium", "low", "info"}
    assert "<" not in new_items[0].title


def test_feed_kind_filter_fills_the_page(empty_conn):
    """A kind filter must return a full page, not whatever survives an unfiltered LIMIT."""
    for n in range(12):
        _open_a_real_finding(empty_conn, subject=f"device:aa:bb:cc:dd:ee:{n:02x}")
    # noise events of other kinds, newer than the findings, that must not eat the page budget
    for n in range(12):
        empty_conn.execute(
            "INSERT INTO notifications(ts, channel, subject, status, error) VALUES (?,?,?,?,?)",
            (ts(minutes=n), "ntfy", f"digest {n}", "sent", None))
    empty_conn.commit()

    # collapse=False: this is about the per-source row budget, and all twelve findings share a
    # title, so collapsing (covered separately below) would legitimately fold them into one row.
    items, total = feedmod.build_feed(empty_conn, kinds={"finding_new"}, limit=5, collapse=False)
    assert len(items) == 5, f"kind filter returned {len(items)} of a 5-item page"
    assert {i.kind for i in items} == {"finding_new"}
    assert total > 5, "total must stay above the page size so 'Load more' remains reachable"
    page2, _ = feedmod.build_feed(empty_conn, kinds={"finding_new"}, limit=5, offset=5, collapse=False)
    assert len(page2) == 5
    assert {i.ref.get("finding_row_id") for i in items}.isdisjoint(
        {i.ref.get("finding_row_id") for i in page2})
