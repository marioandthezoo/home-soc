"""Web dashboard tests (SPEC section 15 / 17): every page renders on an empty and on a seeded
database, every API route returns the documented shape, and auth/CSRF/CSP behave.

Other packages may or may not exist while this runs, so their integration points are
stubbed through ``sys.modules`` to make the outcome deterministic either way.
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from homesoc.web import create_app
from homesoc.web import api as webapi

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "homesoc" / "web" / "templates"
STATIC = ROOT / "homesoc" / "web" / "static"

# Copy of the SPEC section 4 DDL, used when homesoc.db.init_schema is not importable yet.
DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feeds(name TEXT PRIMARY KEY, url TEXT NOT NULL, kind TEXT NOT NULL, etag TEXT, last_modified TEXT,
  last_checked TEXT, last_updated TEXT, status TEXT NOT NULL DEFAULT 'never', bytes INTEGER, entries INTEGER, error TEXT,
  enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT, hostname TEXT, vendor TEXT, kind TEXT,
  nickname TEXT, trusted INTEGER NOT NULL DEFAULT 0, notes TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  online INTEGER NOT NULL DEFAULT 1, last_service_scan TEXT, mdns_services TEXT);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE TABLE IF NOT EXISTS device_sightings(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
  ip TEXT NOT NULL, seen_at TEXT NOT NULL, method TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
  port INTEGER NOT NULL, proto TEXT NOT NULL DEFAULT 'tcp', state TEXT NOT NULL, name TEXT, product TEXT, version TEXT,
  extrainfo TEXT, cpe TEXT, tunnel TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(device_id, port, proto));
CREATE TABLE IF NOT EXISTS vulns(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
  service_id INTEGER REFERENCES services(id), cve TEXT NOT NULL, source TEXT NOT NULL, kev INTEGER NOT NULL DEFAULT 0,
  cvss REAL, epss REAL, title TEXT, published TEXT, matched_on TEXT NOT NULL, remediation TEXT, first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL, UNIQUE(device_id, cve, matched_on));
CREATE TABLE IF NOT EXISTS host_checks(check_id TEXT PRIMARY KEY, status TEXT NOT NULL, value TEXT, expected TEXT,
  checked_at TEXT NOT NULL, needs_admin INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS software(id INTEGER PRIMARY KEY, name TEXT NOT NULL, version TEXT, available TEXT,
  source TEXT NOT NULL, publisher TEXT, seen_at TEXT NOT NULL, UNIQUE(name, source));
CREATE TABLE IF NOT EXISTS persistence(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, command TEXT,
  location TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, baseline INTEGER NOT NULL DEFAULT 0,
  UNIQUE(kind, location, name));
CREATE TABLE IF NOT EXISTS file_checks(sha256 TEXT PRIMARY KEY, path TEXT NOT NULL, size INTEGER, first_seen TEXT NOT NULL,
  verdict TEXT NOT NULL, source TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, subject TEXT NOT NULL,
  dedupe_key TEXT NOT NULL UNIQUE, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT, evidence TEXT,
  status TEXT NOT NULL DEFAULT 'open', source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  resolved_at TEXT, occurrences INTEGER NOT NULL DEFAULT 1, device_id INTEGER REFERENCES devices(id));
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, severity);
CREATE TABLE IF NOT EXISTS finding_events(id INTEGER PRIMARY KEY, finding_row_id INTEGER NOT NULL REFERENCES findings(id),
  event TEXT NOT NULL, at TEXT NOT NULL, note TEXT);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
  status TEXT NOT NULL, summary TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT NOT NULL,
  message TEXT NOT NULL, data TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, tags TEXT);
CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics(name, ts);
CREATE TABLE IF NOT EXISTS dns_queries(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, client TEXT NOT NULL, qname TEXT NOT NULL,
  qtype TEXT NOT NULL, action TEXT NOT NULL, reason TEXT, ms REAL);
CREATE INDEX IF NOT EXISTS idx_dns_queries_ts ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_queries_action_ts ON dns_queries(action, ts);
CREATE TABLE IF NOT EXISTS dns_hourly(hour TEXT NOT NULL, client TEXT NOT NULL, total INTEGER NOT NULL,
  blocked INTEGER NOT NULL, PRIMARY KEY(hour, client));
CREATE TABLE IF NOT EXISTS dns_overrides(domain TEXT PRIMARY KEY, action TEXT NOT NULL, note TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reputation(domain TEXT PRIMARY KEY, source TEXT NOT NULL, verdict TEXT NOT NULL,
  malicious INTEGER NOT NULL DEFAULT 0, suspicious INTEGER NOT NULL DEFAULT 0, checked_at TEXT NOT NULL, raw TEXT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, channel TEXT NOT NULL,
  subject TEXT NOT NULL, status TEXT NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS jobs(name TEXT PRIMARY KEY, last_run TEXT, last_status TEXT, last_duration_sec REAL, next_run TEXT,
  runs INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, last_error TEXT);
"""

PAGES = ["/", "/feed", "/summary", "/findings", "/devices", "/vulns", "/host", "/dns", "/telemetry", "/scans", "/settings"]
FETCH = {"X-Requested-With": "fetch"}


def _now(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")


def make_cfg(**web) -> SimpleNamespace:
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test", timezone="local", log_level="INFO"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token=web.get("token", ""), refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=["192.168.1.9"]),
        scan=SimpleNamespace(use_nmap=True, nmap_top_ports=100, nmap_timing="T3", version_detection=True, gentle_top_ports=25, per_host_timeout_sec=180, max_parallel_hosts=3, scan_gateway=True),
        dns=SimpleNamespace(enabled=True, listen="0.0.0.0", port=53, upstreams=["1.1.1.2", "9.9.9.9"], doh_upstream="", block_mode="null", cache_max_entries=20000, lists=["oisd_small", "hagezi_pro"], log_queries=True, log_retention_days=14, virustotal_api_key="", virustotal_daily_budget=400, reputation_min_malicious_votes=2, reputation_ttl_hours=72),
        notify=SimpleNamespace(min_severity="high", ntfy_url="", discord_webhook="", webhook_url="", windows_toast=True, digest_hour=8),
        schedule=SimpleNamespace(discovery_minutes=10, services_hours=24, host_hours=6, exposure_hours=12, feeds_hours=6),
    )


class FakeScheduler:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run_now(self, name: str) -> bool:
        self.calls.append(name)
        return name != "unknown"

    def status(self) -> list[dict]:
        # one job that has a table row, one the scheduler knows but never ran
        return [{"name": "discovery", "next_run": _now(-5)}, {"name": "digest", "next_run": _now(-60), "running": False}]


def fresh_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        from homesoc import db as core_db  # type: ignore

        core_db.init_schema(conn)
    except Exception:
        conn.executescript(DDL)
    return conn


def seed(conn: sqlite3.Connection) -> None:
    now = _now()
    conn.execute("INSERT INTO devices(id, mac, ip, hostname, vendor, kind, trusted, first_seen, last_seen, online, mdns_services) VALUES(1,'00:11:22:00:00:01','192.168.1.254','gateway.lan','Example Networks','router',0,?,?,1,'[\"_http._tcp\"]')", (now, now))
    conn.execute("INSERT INTO devices(id, mac, ip, hostname, vendor, first_seen, last_seen, online) VALUES(2,'ip:192.168.1.40','192.168.1.40','laptop','Contoso',?,?,0)", (now, now))
    conn.execute("INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(1,'192.168.1.254',?, 'arp')", (now,))
    conn.execute("INSERT INTO services(id, device_id, port, proto, state, name, product, version, cpe, first_seen, last_seen) VALUES(1,1,80,'tcp','open','http','lighttpd','1.4.69','cpe:/a:lighttpd:lighttpd:1.4.69',?,?)", (now, now))
    conn.execute("INSERT INTO services(id, device_id, port, proto, state, name, first_seen, last_seen) VALUES(2,1,23,'tcp','open','telnet',?,?)", (now, now))
    conn.execute("INSERT INTO vulns(device_id, service_id, cve, source, kev, cvss, epss, title, matched_on, first_seen, last_seen) VALUES(1,1,'CVE-2022-22707','nvd',1,9.8,0.71,'lighttpd overflow','lighttpd 1.4.69',?,?)", (now, now))
    conn.execute("INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, detail, evidence, status, source, first_seen, last_seen, device_id) VALUES(1,'NET-SVC-001','device:00:11:22:00:00:01:23','NET-SVC-001|device:00:11:22:00:00:01:23','critical','Telnet exposed <script>x</script>','Telnet on router','{\"port\": 23, \"ip\": \"192.168.1.254\"}','open','services',?,?,1)", (now, now))
    conn.execute("INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, evidence, status, source, first_seen, last_seen) VALUES(2,'WIN-ACC-001','host','WIN-ACC-001|host','medium','Daily account is admin','not json{','acknowledged','host',?,?)", (now, now))
    conn.execute("INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen) VALUES(3,'SOC-SYS-001','host','SOC-SYS-001|host','info','nmap missing','open','host',?,?)", (now, now))
    conn.execute("INSERT INTO host_checks(check_id, status, value, expected, checked_at, needs_admin) VALUES('WIN-DEF-001','pass','AV on','on',?,0)", (now,))
    conn.execute("INSERT INTO host_checks(check_id, status, value, checked_at, needs_admin) VALUES('WIN-SYS-002','needs_admin',NULL,?,1)", (now,))
    conn.execute("INSERT INTO host_checks(check_id, status, value, checked_at) VALUES('WIN-NET-006','warn','7680 svchost',?)", (now,))
    conn.execute("INSERT INTO software(name, version, available, source, seen_at) VALUES('Java 8','8.0.401','8.0.421','winget',?)", (now,))
    conn.execute("INSERT INTO persistence(kind, name, command, location, first_seen, last_seen, baseline) VALUES('run_key','ExampleSync','C:\\\\sync.exe','HKCU\\\\Run',?,?,1)", (now, now))
    conn.execute("INSERT INTO settings(key, value, updated_at) VALUES('defender.status_json', ?, ?)", (json.dumps({"AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 1}), now))
    conn.execute("INSERT INTO settings(key, value, updated_at) VALUES(?, '12', ?)", (f"vt.budget.{now[:10]}", now))
    conn.execute("INSERT INTO settings(key, value, updated_at) VALUES('web.refresh_seconds', '30', ?)", (now,))
    conn.execute("INSERT INTO feeds(name, url, kind, status, last_updated, entries, bytes) VALUES('oisd_small','https://small.oisd.nl','domains','updated',?,50000,1400000)", (now,))
    conn.execute("INSERT INTO feeds(name, url, kind, status, error) VALUES('kev','https://x','kev','error','timeout')")
    conn.execute("INSERT INTO jobs(name, last_run, last_status, last_duration_sec, runs, failures) VALUES('discovery',?,'ok',11.5,3,0)", (now,))
    conn.execute("INSERT INTO scans(kind, started_at, finished_at, status, summary) VALUES('discovery',?,?,'ok','{\"hosts_total\": 17}')", (_now(2), now))
    conn.execute("INSERT INTO scans(kind, started_at, status, error) VALUES('services',?,'error','nmap missing')", (now,))
    conn.execute("INSERT INTO events(ts, level, source, message, data) VALUES(?,'INFO','scheduler','job discovery ok','{\"hosts\": 17}')", (now,))
    conn.execute("INSERT INTO events(ts, level, source, message) VALUES(?,'ERROR','feeds','kev failed')", (now,))
    for i in range(5):
        conn.execute("INSERT INTO metrics(ts, name, value, tags) VALUES(?,'score',?,NULL)", (_now(60 * i), 90 - i))
        conn.execute("INSERT INTO metrics(ts, name, value, tags) VALUES(?,'job.duration',?,'{\"job\": \"discovery\"}')", (_now(60 * i), 10 + i))
        conn.execute("INSERT INTO metrics(ts, name, value, tags) VALUES(?,'discovery.hosts_online',?,NULL)", (_now(60 * i), 12))
    for i in range(30):
        action = "block" if i % 3 == 0 else ("cache" if i % 5 == 0 else "allow")
        conn.execute("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,?)", (_now(i * 20), "192.168.1.10" if i % 2 else "192.168.1.11", f"ads{i % 4}.example.net" if action == "block" else "example.com", "A", action, "oisd_small" if action == "block" else None, 1.5))
    conn.execute("INSERT INTO dns_overrides(domain, action, note, created_at) VALUES('good.example','allow','test',?)", (now,))
    conn.execute("INSERT INTO reputation(domain, source, verdict, malicious, suspicious, checked_at) VALUES('bad.example','virustotal','malicious',7,1,?)", (now,))
    conn.commit()


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = fresh_conn()
    yield c
    c.close()


@pytest.fixture
def scheduler() -> FakeScheduler:
    return FakeScheduler()


@pytest.fixture
def client(conn, scheduler):
    app = create_app(make_cfg(), conn, scheduler=scheduler, dns_server=SimpleNamespace(running=True))
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def seeded_client(conn, scheduler):
    seed(conn)
    app = create_app(make_cfg(), conn, scheduler=scheduler, dns_server=None)
    app.config["TESTING"] = True
    return app.test_client()


def stub_module(monkeypatch, name: str, **attrs):
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, name, mod)
    return mod


@pytest.fixture
def spec_score(monkeypatch):
    """Hide ``homesoc.findings.score`` so the dashboard uses its own SPEC section 10 formula.

    api.security_score/grade/score_breakdown defer to findings when that package is installed —
    it owns the formula — which makes any hard-coded score in a test a hostage to that module.
    Tests that assert exact numbers pin the fallback instead; the delegation itself is covered by
    test_score_delegates_to_findings_package.
    """
    stub_module(monkeypatch, "homesoc.findings.score")


# --------------------------------------------------------------------------- pages


@pytest.mark.parametrize("path", PAGES)
def test_every_page_renders_on_empty_db(client, path):
    r = client.get(path)
    assert r.status_code == 200, path
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert b"Home SOC Test" in r.data


@pytest.mark.parametrize("path", PAGES + ["/devices/1", "/findings?status=open&severity=critical&category=services&q=telnet", "/vulns?kev=1&min_cvss=7"])
def test_every_page_renders_with_data(seeded_client, path):
    r = seeded_client.get(path)
    assert r.status_code == 200, path


def test_user_data_is_escaped(seeded_client):
    r = seeded_client.get("/findings")
    assert b"<script>x</script>" not in r.data
    assert b"&lt;script&gt;x&lt;/script&gt;" in r.data


def test_unknown_device_is_404(client):
    assert client.get("/devices/999").status_code == 404
    assert client.get("/api/devices/999").status_code == 404


def test_templates_have_no_inline_handlers_or_styles():
    """CSP default-src 'self' would silently break inline JS/CSS, so none may exist."""
    for tpl in TEMPLATES.glob("*.html"):
        text = tpl.read_text(encoding="utf-8")
        assert not re.search(r"\son[a-z]+\s*=", text), tpl.name
        assert not re.search(r"\sstyle\s*=", text), tpl.name
        assert not re.search(r"<script(?![^>]*type=\"application/json\")(?![^>]*src=)", text), tpl.name
        assert "http://" not in text.replace("http://nvd", "") or "url_for" in text
    for js in STATIC.glob("*.js"):
        assert "innerHTML" not in js.read_text(encoding="utf-8"), js.name


def test_chart_svgs_cannot_escape_their_card():
    """Regression: `.chart-wrap .chart-svg { width: 150px }` also matched the donut's 10x10
    legend swatches and blew each one up to 150x150, out of the card and over the panel next to
    it. Any rule that sizes a chart SVG must use `>` so it hits only the chart it means, and the
    base rule must cap every SVG at its container's width."""
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    sizing = re.findall(r"^([^{}\n]*\.chart-svg[^{}\n]*)\{([^}]*)\}", css, re.MULTILINE)
    assert sizing, "no .chart-svg rules found — did the selector get renamed?"
    for selector, block in sizing:
        if re.search(r"\bwidth\s*:", block) or re.search(r"\bheight\s*:", block):
            ancestor = selector.split(".chart-svg")[0].strip()
            assert not ancestor or ancestor.endswith(">"), f"descendant selector sizes SVGs: {selector.strip()}"
    assert re.search(r"\.chart-svg\s*\{[^}]*max-width:\s*100%", css), "the base .chart-svg rule must cap its width"
    # The swatch has its own class precisely so no chart rule can ever reach it again.
    assert ".legend-swatch" in css
    charts = (STATIC / "charts.js").read_text(encoding="utf-8")
    assert "'legend-swatch'" in charts


# --------------------------------------------------------------------------- auth / csrf


def test_token_auth_flow(conn):
    app = create_app(make_cfg(token="s3cret"), conn)
    app.config["TESTING"] = True
    c = app.test_client()
    assert c.get("/").status_code == 401
    assert c.get("/api/summary").status_code == 401
    assert c.get("/api/summary").get_json()["error"] == "unauthorized"
    assert c.get("/static/style.css").status_code == 200
    assert c.get("/login").status_code == 200
    assert c.get("/login?token=wrong").status_code == 401
    # ?token= on a normal page is turned into the cookie and redirected away, so the secret
    # never stays in the address bar, history or referrers.
    r = c.get("/?token=s3cret&status=open")
    assert r.status_code == 302
    assert r.headers["Location"] == "/?status=open" and "token=" not in r.headers["Location"]
    assert "homesoc_token=" in r.headers.get("Set-Cookie", "")
    assert c.get("/").status_code == 200  # cookie now set on the client
    assert c.get("/logout").status_code == 302
    assert c.get("/api/summary", headers={"X-Token": "s3cret"}).status_code == 200
    r = c.get("/login?token=s3cret")
    assert r.status_code == 302 and "homesoc_token=" in r.headers.get("Set-Cookie", "")
    assert c.get("/").status_code == 200  # cookie now set on the client
    assert c.get("/logout").status_code == 302
    assert c.get("/").status_code == 401


def test_host_header_must_be_local(conn):
    """DNS rebinding: a page on attacker.example that points its own name at 127.0.0.1 is
    same-origin in the browser, and the Host header is the only thing left that tells it apart."""
    app = create_app(make_cfg(), conn)
    app.config["TESTING"] = True
    c = app.test_client()
    assert c.get("/", headers={"Host": "attacker.example"}).status_code == 400
    assert c.get("/api/devices", headers={"Host": "attacker.example"}).status_code == 400
    assert c.post("/api/settings", json={"dns.upstreams": "6.6.6.6"}, headers={**FETCH, "Host": "evil.test"}).status_code == 400
    assert conn.execute("SELECT count(*) FROM settings WHERE key='dns.upstreams'").fetchone()[0] == 0
    for host in ("127.0.0.1", "127.0.0.1:8787", "localhost:8787", "[::1]:8787"):
        assert c.get("/", headers={"Host": host}).status_code == 200, host


def test_no_token_means_open(client):
    assert client.get("/login").status_code == 302


def test_post_requires_fetch_header(client):
    r = client.post("/api/scan", json={"kind": "quick"})
    assert r.status_code == 403
    r = client.delete("/api/dns/override/x.example")
    assert r.status_code == 403
    r = client.post("/api/scan", json={"kind": "quick"}, headers=FETCH)
    assert r.status_code == 202


# --------------------------------------------------------------------------- summary / findings


def test_summary_shape(seeded_client, spec_score):
    s = seeded_client.get("/api/summary").get_json()
    for key in ("score", "grade", "counts", "devices", "dns", "jobs", "feeds", "last_scans", "events", "score_breakdown"):
        assert key in s, key
    assert s["score"] == 75  # 100 - 25 critical - 0 info (acknowledged medium does not count)
    assert s["grade"] == "C"
    assert s["counts"]["open"]["critical"] == 1 and s["counts"]["acknowledged"]["medium"] == 1
    assert set(s["counts"]) >= set(webapi.STATUSES)
    assert s["devices"] == {"online": 1, "total": 2}
    assert set(s["dns"]) >= {"total24h", "blocked24h", "clients24h", "running"}
    assert s["dns"]["total24h"] == 30 and s["dns"]["blocked24h"] == 10 and s["dns"]["clients24h"] == 2
    assert s["dns"]["running"] is False
    assert s["last_scans"]["discovery"]
    assert s["jobs"][0]["name"] == "discovery" and s["jobs"][0]["next_run"]  # merged from scheduler.status()
    assert len(s["events"]) == 2 and len(s["trend"]) >= 1


def test_summary_empty(client):
    s = client.get("/api/summary").get_json()
    assert s["score"] == 100 and s["grade"] == "A" and s["devices"] == {"online": 0, "total": 0}
    assert s["dns"]["running"] is True
    assert s["score_breakdown"] == []  # nothing found means nothing costs points


# --------------------------------------------------------------------------- score breakdown


def test_score_delegates_to_findings_package(seeded_client, monkeypatch):
    """findings owns the formula: the card and the breakdown under it must use *its* numbers."""
    stub_module(
        monkeypatch,
        "homesoc.findings.score",
        security_score=lambda conn: 42,
        grade=lambda score: "B",
        score_breakdown=lambda conn: [
            {"finding_id": "NET-SVC-001", "title": "Telnet is open", "count": 1, "penalty": 30.0, "score_gain": 21},
        ],
    )
    s = seeded_client.get("/api/summary").get_json()
    assert s["score"] == 42 and s["grade"] == "B"
    row = s["score_breakdown"][0]
    assert len(s["score_breakdown"]) == 1
    assert (row["finding_id"], row["title"], row["count"]) == ("NET-SVC-001", "Telnet is open", 1)
    assert (row["penalty"], row["gain"], row["severity"]) == (30, 21, "critical")
    assert row["category"]  # from findings.catalog when present, else the ID prefix map


def test_score_breakdown_falls_back_to_the_spec_weights(seeded_client, spec_score):
    """Without findings.score the dashboard ranks open findings by the SPEC section 10 weights."""
    rows = seeded_client.get("/api/summary").get_json()["score_breakdown"]
    # seeded: one open critical (25), one open info (0), one *acknowledged* medium (does not count)
    assert [(r["finding_id"], r["penalty"], r["gain"]) for r in rows] == [("NET-SVC-001", 25, 25)]
    assert rows[0]["severity"] == "critical" and rows[0]["count"] == 1
    # JSON carries the title raw (markup and all); escaping is the HTML layer's job, asserted
    # by test_overview_renders_the_score_breakdown.
    assert rows[0]["title"] == "Telnet exposed <script>x</script>"


def test_score_breakdown_survives_a_broken_findings_package(seeded_client, monkeypatch):
    def boom(conn):
        raise RuntimeError("mid-refactor")

    stub_module(monkeypatch, "homesoc.findings.score", security_score=boom, grade=boom, score_breakdown=boom)
    s = seeded_client.get("/api/summary").get_json()
    assert s["score"] == 75 and s["grade"] == "C"  # SPEC section 10 fallback
    assert [r["finding_id"] for r in s["score_breakdown"]] == ["NET-SVC-001"]


def test_score_breakdown_groups_repeats_under_the_catalog_title(client, conn, spec_score):
    """Ten "new device" findings are one line with x10, named generically — not ten lines
    naming one arbitrary device."""
    now = _now(0)
    for n in range(10):
        conn.execute(
            "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen) "
            "VALUES('NET-DEV-001',?,?,'medium',?,'open','discovery',?,?)",
            (f"device:aa:bb:cc:00:00:{n:02x}", f"NET-DEV-001|{n}", f"New device on the network: 192.168.1.{n} (Apple)", now, now))
    conn.commit()
    rows = client.get("/api/summary").get_json()["score_breakdown"]
    assert len(rows) == 1
    assert rows[0]["count"] == 10 and rows[0]["penalty"] == 40
    assert "192.168.1." not in rows[0]["title"] and "{" not in rows[0]["title"]


def test_overview_renders_the_score_breakdown(seeded_client, spec_score):
    page = seeded_client.get("/").data.decode("utf-8")
    assert 'id="score-breakdown"' in page
    assert "Fix these first" in page
    assert "/findings?status=open&q=NET-SVC-001" in page
    assert "&lt;script&gt;" in page and "<script>x</script>" not in page  # title escaped


def test_summary_page_has_a_breakdown_placeholder(client):
    """The summary page fills the list from /api/summary, so it must ship the container."""
    page = client.get("/summary").data.decode("utf-8")
    assert 'id="score-breakdown"' in page and "costing the most points" in page


def test_findings_list_and_filters(seeded_client):
    items = seeded_client.get("/api/findings").get_json()
    assert [f["finding_id"] for f in items] == ["NET-SVC-001", "WIN-ACC-001", "SOC-SYS-001"]
    assert items[0]["evidence"] == {"port": 23, "ip": "192.168.1.254"}
    # category comes from findings.catalog when present, else from the ID prefix map
    assert items[0]["category"] and isinstance(items[0]["category"], str)
    assert items[0]["device_name"] == "gateway.lan"
    assert items[1]["evidence"] == {}  # malformed JSON never breaks the page
    assert [f["id"] for f in seeded_client.get("/api/findings?status=open&severity=critical").get_json()] == [1]
    assert [f["id"] for f in seeded_client.get("/api/findings?q=nmap").get_json()] == [3]
    acc_category = items[1]["category"]
    assert [f["id"] for f in seeded_client.get(f"/api/findings?category={acc_category}").get_json()] == [2]


def test_findings_use_catalog_when_available(seeded_client, monkeypatch):
    spec = SimpleNamespace(remediation=["Open Settings", "Disable Telnet"], refs=["https://example.org/telnet"], rationale="Cleartext", category="lan-services")
    stub_module(monkeypatch, "homesoc.findings.catalog", CATALOG={"NET-SVC-001": spec})
    f = seeded_client.get("/api/findings?status=open&severity=critical").get_json()[0]
    assert f["remediation"] == spec.remediation and f["refs"] == spec.refs and f["category"] == "lan-services"
    page = seeded_client.get("/findings").data
    assert b"Disable Telnet" in page and b"https://example.org/telnet" in page


def test_finding_status_calls_engine(seeded_client, monkeypatch):
    calls = []
    stub_module(monkeypatch, "homesoc.findings.engine", set_status=lambda conn, row_id, status, note=None: calls.append((row_id, status, note)))
    r = seeded_client.post("/api/findings/1/status", json={"status": "acknowledged", "note": "known"}, headers=FETCH)
    assert r.status_code == 200 and r.get_json() == {"ok": True, "id": 1, "status": "acknowledged"}
    assert calls == [(1, "acknowledged", "known")]


def test_finding_status_fallback_without_engine(seeded_client, conn, monkeypatch):
    monkeypatch.setitem(sys.modules, "homesoc.findings.engine", None)
    r = seeded_client.post("/api/findings/1/status", json={"status": "resolved"}, headers=FETCH)
    assert r.status_code == 200
    row = conn.execute("SELECT status, resolved_at FROM findings WHERE id=1").fetchone()
    assert row["status"] == "resolved" and row["resolved_at"]
    assert conn.execute("SELECT event FROM finding_events WHERE finding_row_id=1").fetchone()["event"] == "resolved"
    assert seeded_client.post("/api/findings/1/status", json={"status": "bogus"}, headers=FETCH).status_code == 400
    assert seeded_client.post("/api/findings/99/status", json={"status": "open"}, headers=FETCH).status_code == 404


# --------------------------------------------------------------------------- devices / vulns / host


def test_devices_api(seeded_client, conn):
    devs = seeded_client.get("/api/devices").get_json()
    assert len(devs) == 2 and devs[0]["ip"] == "192.168.1.254"
    assert devs[0]["open_ports"] == 2 and devs[0]["open_findings"] == 1 and devs[0]["online"] is True
    d = seeded_client.get("/api/devices/1").get_json()
    assert len(d["services"]) == 2 and len(d["vulns"]) == 1 and len(d["findings"]) == 1
    assert len(d["presence"]) == 7 and d["presence"][-1]["count"] == 1 and d["mdns_services"] == ["_http._tcp"]
    r = seeded_client.post("/api/devices/1", json={"nickname": "Router", "notes": "AT&T", "trusted": True}, headers=FETCH)
    assert r.status_code == 200
    row = conn.execute("SELECT nickname, notes, trusted FROM devices WHERE id=1").fetchone()
    assert (row["nickname"], row["notes"], row["trusted"]) == ("Router", "AT&T", 1)
    assert seeded_client.post("/api/devices/1", json={"trusted": False}, headers=FETCH).status_code == 200
    assert conn.execute("SELECT trusted FROM devices WHERE id=1").fetchone()["trusted"] == 0


def test_device_scan_uses_scan_device_when_offered(seeded_client, monkeypatch):
    calls = []
    stub_module(monkeypatch, "homesoc.scanners.ports", scan_device=lambda cfg, conn, device_id: calls.append(device_id) or SimpleNamespace(findings=[], summary={}))
    r = seeded_client.post("/api/devices/1/scan", json={}, headers=FETCH)
    assert r.status_code == 202 and r.get_json()["ok"] is True
    for _ in range(50):
        if calls:
            break
        time.sleep(0.05)
    assert calls == [1]
    assert seeded_client.post("/api/devices/99/scan", json={}, headers=FETCH).status_code == 404


def test_vulns_api(seeded_client):
    v = seeded_client.get("/api/vulns").get_json()
    assert len(v) == 1 and v[0]["kev"] is True and v[0]["port"] == 80 and v[0]["nvd_url"].endswith("CVE-2022-22707")
    assert seeded_client.get("/api/vulns?min_cvss=9.9").get_json() == []
    assert len(seeded_client.get("/api/vulns?kev=1&q=lighttpd").get_json()) == 1


def test_host_shape(seeded_client):
    h = seeded_client.get("/api/host").get_json()
    assert set(h) >= {"checks", "defender", "updates", "software", "persistence", "listeners"}
    by_id = {c["check_id"]: c for c in h["checks"]}
    assert len(h["checks"]) == 3 and by_id["WIN-SYS-002"]["needs_admin"] is True and by_id["WIN-DEF-001"]["needs_admin"] is False
    assert h["defender"]["status"]["AntivirusEnabled"] is True and h["defender"]["signature_age_days"] == 1
    assert h["software"][0]["name"] == "Java 8" and h["persistence"][0]["baseline"] is True
    assert h["listeners"][0]["value"] == "7680 svchost"
    empty_app = create_app(make_cfg(), fresh_conn())
    empty = empty_app.test_client().get("/api/host").get_json()
    assert empty["checks"] == [] and empty["defender"]["status"] == {} and empty["defender"]["threats"] == []


def test_defender_actions(client, monkeypatch):
    monkeypatch.setitem(sys.modules, "homesoc.scanners.defender", None)
    webapi._defender_jobs.clear()
    assert client.post("/api/defender/quick-scan", json={}, headers=FETCH).status_code == 503
    seen = []
    stub_module(monkeypatch, "homesoc.scanners.defender", trigger_quick_scan=lambda cfg: seen.append("q") or True, update_signatures=lambda cfg: seen.append("u") or True)
    assert client.post("/api/defender/quick-scan", json={}, headers=FETCH).status_code == 202
    assert client.post("/api/defender/update", json={}, headers=FETCH).status_code == 202
    for _ in range(100):
        if len(seen) == 2:
            break
        time.sleep(0.05)
    assert sorted(seen) == ["q", "u"]


def test_defender_update_does_not_block_the_request(client, monkeypatch):
    """A signature update can take 15 minutes; the request must return at once and the UI polls."""
    webapi._defender_jobs.clear()
    release = threading.Event()
    stub_module(monkeypatch, "homesoc.scanners.defender", update_signatures=lambda cfg: release.wait(10) or True)
    started = time.monotonic()
    r = client.post("/api/defender/update", json={}, headers=FETCH)
    assert r.status_code == 202 and r.get_json()["status"] == "started"
    assert time.monotonic() - started < 2.0
    # a second click while it runs is de-duplicated, not a second MpCmdRun
    r2 = client.post("/api/defender/update", json={}, headers=FETCH)
    assert r2.status_code == 202 and r2.get_json()["status"] == "already running"
    status = client.get("/api/defender/status").get_json()
    assert status["available"] is True and status["actions"]["update"]["running"] is True
    release.set()
    for _ in range(100):
        if not client.get("/api/defender/status").get_json()["actions"]["update"]["running"]:
            break
        time.sleep(0.05)
    done = client.get("/api/defender/status").get_json()["actions"]["update"]
    assert done["running"] is False and done["ok"] is True and done["finished_at"]
    webapi._defender_jobs.clear()


def test_defender_status_reports_the_scanners_outcome_not_the_trigger(client, monkeypatch):
    """The scanner's trigger returns as soon as MpCmdRun is LAUNCHED, not when it finishes.

    Regression: the web layer used to stamp finished_at/ok the moment the trigger returned, so a
    15-minute signature update was reported "finished, ok" milliseconds after the click. When the
    scanner publishes update_status()/update_running(), those are authoritative.
    """
    webapi._defender_jobs.clear()
    state = {"running": True, "started_at": "2026-09-07T10:00:00Z", "finished_at": None,
             "ok": None, "rc": None, "message": "", "available": True}
    stub_module(
        monkeypatch,
        "homesoc.scanners.defender",
        trigger_signature_update=lambda cfg: True,   # fire-and-forget, like the real one
        update_status=lambda: dict(state),
        update_running=lambda: bool(state["running"]),
    )
    assert client.post("/api/defender/update", json={}, headers=FETCH).status_code == 202
    for _ in range(100):  # the web worker thread hands off; nothing must claim completion
        after = client.get("/api/defender/status").get_json()["actions"]["update"]
        if after.get("handed_off") is None and after["running"] is True:
            break
        time.sleep(0.02)
    assert after["running"] is True and after["finished_at"] is None and after["ok"] is None
    assert client.post("/api/defender/update", json={}, headers=FETCH).get_json()["status"] == "already running"

    state.update(running=False, finished_at="2026-09-07T10:12:00Z", ok=True, rc=0, message="done")
    done = client.get("/api/defender/status").get_json()["actions"]["update"]
    assert done["running"] is False and done["ok"] is True and done["finished_at"] == "2026-09-07T10:12:00Z"
    # and the button is usable again rather than dead-ended on the stale "running" flag
    assert client.post("/api/defender/update", json={}, headers=FETCH).get_json()["status"] == "started"
    webapi._defender_jobs.clear()


# --------------------------------------------------------------------------- dns


def test_dns_endpoints(seeded_client, conn):
    s = seeded_client.get("/api/dns/summary").get_json()
    assert s["total24h"] == 30 and s["blocked24h"] == 10 and s["clients24h"] == 2 and s["running"] is False
    assert s["vt_budget"]["used"] == 12 and s["vt_budget"]["limit"] == 400 and s["overrides"] == 1
    series = seeded_client.get("/api/dns/series?hours=24").get_json()
    assert len(series) == 24 and sum(p["total"] for p in series) == 30 and sum(p["blocked"] for p in series) == 10
    assert len(seeded_client.get("/api/dns/series?hours=6").get_json()) == 6
    blocked = seeded_client.get("/api/dns/top?kind=blocked").get_json()
    assert blocked and blocked[0]["domain"].startswith("ads") and blocked[0]["hits"] >= 2
    clients = seeded_client.get("/api/dns/top?kind=clients").get_json()
    assert {c["client"] for c in clients} == {"192.168.1.10", "192.168.1.11"}
    log = seeded_client.get("/api/dns/log?limit=5&action=block").get_json()
    assert len(log) == 5 and all(q["action"] == "block" for q in log)
    assert all(q["client"] == "192.168.1.10" for q in seeded_client.get("/api/dns/log?client=192.168.1.10").get_json())
    lists = seeded_client.get("/api/dns/lists").get_json()
    assert [l["name"] for l in lists] == ["oisd_small"] and lists[0]["active"] is True and lists[0]["entries"] == 50000
    rep = seeded_client.get("/api/dns/reputation").get_json()
    assert rep[0]["domain"] == "bad.example" and rep[0]["verdict"] == "malicious"


def test_dns_override_roundtrip(client, conn):
    r = client.post("/api/dns/override", json={"domain": " Tracker.Example. ", "action": "deny", "note": "n"}, headers=FETCH)
    assert r.status_code == 200 and r.get_json()["domain"] == "tracker.example"
    row = conn.execute("SELECT action, note FROM dns_overrides WHERE domain='tracker.example'").fetchone()
    assert (row["action"], row["note"]) == ("deny", "n")
    client.post("/api/dns/override", json={"domain": "tracker.example", "action": "allow"}, headers=FETCH)
    assert conn.execute("SELECT action FROM dns_overrides WHERE domain='tracker.example'").fetchone()["action"] == "allow"
    assert client.get("/api/dns/overrides").get_json()[0]["domain"] == "tracker.example"
    assert client.post("/api/dns/override", json={"domain": "bad domain", "action": "deny"}, headers=FETCH).status_code == 400
    assert client.post("/api/dns/override", json={"domain": "x.example", "action": "nuke"}, headers=FETCH).status_code == 400
    assert client.delete("/api/dns/override/tracker.example", headers=FETCH).status_code == 200
    assert conn.execute("SELECT count(*) FROM dns_overrides").fetchone()[0] == 0


# --------------------------------------------------------------------------- telemetry / scans


def test_telemetry_metrics_group_by_name_and_tags(seeded_client):
    m = seeded_client.get("/api/telemetry/metrics?hours=24").get_json()
    assert m["names"] == ["discovery.hosts_online", "job.duration · discovery", "score"]
    assert len(m["series"]["score"]) == 5 and m["series"]["score"][-1][1] == 90.0
    only = seeded_client.get("/api/telemetry/metrics?name=score").get_json()
    assert only["names"] == ["score"]
    assert seeded_client.get("/telemetry").data.count(b"job.duration") >= 1


def test_telemetry_jobs_events_scans(seeded_client):
    jobs = seeded_client.get("/api/telemetry/jobs").get_json()
    assert jobs[0]["name"] == "discovery" and jobs[0]["runs"] == 3
    ev = seeded_client.get("/api/telemetry/events").get_json()
    assert len(ev) == 2 and ev[1]["data"] == {"hosts": 17}
    assert [e["level"] for e in seeded_client.get("/api/telemetry/events?level=error").get_json()] == ["ERROR"]
    scans = seeded_client.get("/api/scans").get_json()
    assert scans[0]["kind"] == "services" and scans[1]["summary"] == {"hosts_total": 17} and scans[1]["duration_sec"] >= 100


def test_scan_via_scheduler(client, scheduler):
    r = client.post("/api/scan", json={"kind": "full"}, headers=FETCH)
    assert r.status_code == 202 and r.get_json()["mode"] == "scheduler"
    assert scheduler.calls == ["full"]
    assert client.post("/api/scan", json={"kind": "nope"}, headers=FETCH).status_code == 400


def test_scan_via_thread_records_scans_rows(conn, monkeypatch):
    stub_module(monkeypatch, "homesoc.scanners.exposure", run=lambda cfg, conn, quick=False, progress=None: SimpleNamespace(findings=[], summary={"public_ip": "1.2.3.4"}, error=None))
    app = create_app(make_cfg(), conn)
    app.config["TESTING"] = True
    c = app.test_client()
    r = c.post("/api/scan", json={"kind": "exposure"}, headers=FETCH)
    assert r.status_code == 202 and r.get_json()["mode"] == "thread"
    for _ in range(100):
        row = conn.execute("SELECT status, summary FROM scans WHERE kind='exposure'").fetchone()
        if row and row["status"] != "running":
            break
        time.sleep(0.05)
    assert row["status"] == "ok" and json.loads(row["summary"]) == {"public_ip": "1.2.3.4"}


# --------------------------------------------------------------------------- settings / notify / export


def test_settings_get_and_post(seeded_client, conn):
    items = {i["key"]: i for i in seeded_client.get("/api/settings").get_json()}
    assert items["web.refresh_seconds"]["value"] == "30" and items["web.refresh_seconds"]["source"] == "override"
    assert items["network.exclude"]["value"] == "192.168.1.9" and items["dns.enabled"]["value"] is True
    assert items["web.token"]["value"] == "" and items["web.token"]["set"] is False
    # Switching DNS off and hiding addresses from scans need a password since round three (a
    # dashboard with none cannot tell the owner from another program on the PC), so sign in.
    refused = seeded_client.post("/api/settings", json={"dns.enabled": False}, headers=FETCH)
    assert refused.status_code == 403 and refused.get_json()["needs_password"] is True
    app = create_app(make_cfg(token="settings-test-token-0123456789"), conn)
    app.config["TESTING"] = True
    signed = {**FETCH, "X-Token": "settings-test-token-0123456789"}
    r = app.test_client().post("/api/settings", json={"dns.enabled": False, "network.exclude": "10.0.0.1, 10.0.0.2", "scan.nmap_top_ports": 50, "web.token": ""}, headers=signed)
    assert r.status_code == 200 and sorted(r.get_json()["saved"]) == ["dns.enabled", "network.exclude", "scan.nmap_top_ports"]
    get = lambda k: conn.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()["value"]
    assert get("dns.enabled") == "false" and get("network.exclude") == '["10.0.0.1", "10.0.0.2"]' and get("scan.nmap_top_ports") == "50"
    assert conn.execute("SELECT count(*) FROM settings WHERE key='web.token'").fetchone()[0] == 0
    bad = seeded_client.post("/api/settings", json={"general.name": "x", "scan.nmap_top_ports": "lots"}, headers=FETCH)
    assert bad.status_code == 400 and set(bad.get_json()["errors"]) == {"general.name", "scan.nmap_top_ports"}
    assert b'name="dns.enabled"' in seeded_client.get("/settings").data


def test_notify_test(client, monkeypatch):
    monkeypatch.setitem(sys.modules, "homesoc.notify.channels", None)
    assert client.post("/api/notify/test", json={}, headers=FETCH).status_code == 503
    stub_module(monkeypatch, "homesoc.notify.channels", test_channels=lambda cfg, conn: {"ntfy": True})
    r = client.post("/api/notify/test", json={}, headers=FETCH)
    assert r.status_code == 200 and r.get_json()["channels"] == {"ntfy": True}


def test_export(seeded_client):
    r = seeded_client.get("/api/export")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]
    data = json.loads(r.data)
    assert set(data) >= {"findings", "devices", "vulns"} and len(data["findings"]) == 3
    bundle = json.loads(seeded_client.get("/api/export?full=1").data)
    assert {"settings", "jobs", "feeds", "scans", "events", "host", "dns"} <= set(bundle)
    assert all(s["value"] == "" for s in bundle["settings"] if s["type"] == "secret")


def test_api_404_is_json(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["ok"] is False


def test_missing_table_renders_empty(client, conn):
    """A package that has not created its table yet must not break the dashboard."""
    conn.execute("DROP TABLE dns_queries")
    conn.commit()
    assert client.get("/dns").status_code == 200
    assert client.get("/api/dns/summary").get_json()["total24h"] == 0
