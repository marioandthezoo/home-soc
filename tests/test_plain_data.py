"""The plain-language data layer: what the redesigned pages say beside the technical values.

The dashboard redesign gives the templates plain words instead of making them compute them:
device names instead of addresses, action words beside severities, one sentence about the whole
network, and an honest answer to "is this picture current?". Every new field is pinned here,
together with the two honesty rules the words must never break:

* the network is never called healthy when the data is stale or a check did not finish;
* EPSS is a worldwide forecast for a flaw, never "the chance you will be attacked".

Offline: an in-memory database seeded with known timestamps, and the Flask test client for the
JSON endpoints. Existing keys are checked to still be there — every field here is additive.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from homesoc.db import init_schema
from homesoc.web import api, create_app
from homesoc.web import feed as feedmod
from homesoc.web import summary as summarymod

FETCH = {"X-Requested-With": "fetch"}
HOST_MAC = "A4:34:D9:7C:5E:12"
CAMERA_MAC = "8E:35:A1:4F:0C:D2"


def ts(**delta: float) -> str:
    """A time ``delta`` before *now* — taken per call, not at import: staleness is measured against
    the real clock, and a module-level anchor goes stale while the rest of the suite runs."""
    return (datetime.now(timezone.utc) - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_cfg(discovery_minutes: int = 10) -> SimpleNamespace:
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test", timezone="local", log_level="INFO"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token="", refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=[]),
        scan=SimpleNamespace(use_nmap=True, nmap_top_ports=100),
        dns=SimpleNamespace(enabled=True, listen="0.0.0.0", port=53, upstreams=["1.1.1.2"], doh_upstream="",
                            block_mode="null", lists=["oisd_small"], virustotal_api_key="", virustotal_daily_budget=400),
        notify=SimpleNamespace(min_severity="high", ntfy_url="", discord_webhook="", webhook_url=""),
        schedule=SimpleNamespace(discovery_minutes=discovery_minutes),
    )


def fresh_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def add_scan(conn: sqlite3.Connection, kind: str, status: str, finished: str | None) -> None:
    conn.execute("INSERT INTO scans(kind, started_at, finished_at, status) VALUES(?,?,?,?)",
                 (kind, finished or ts(minutes=1), finished, status))
    conn.commit()


def add_core_checks(conn: sqlite3.Connection, minutes: int = 3) -> None:
    """A finished run of every core check (open ports, software flaws, this computer, threat
    lists): without them the status line may not call the network healthy."""
    for kind in ("services", "vulns", "host", "feeds"):
        add_scan(conn, kind, "ok", ts(minutes=minutes))


def add_finding(conn, row_id, fid, subject, severity, title, status="open", device_id=None, first=None,
                resolved=None):
    conn.execute(
        "INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, detail, evidence, status, "
        "source, first_seen, last_seen, resolved_at, occurrences, device_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (row_id, fid, subject, f"{fid}|{subject}|{row_id}", severity, title, "detail", "{}", status, "test",
         first or ts(days=2), ts(minutes=5), resolved, 1, device_id),
    )
    conn.commit()


def seed(conn: sqlite3.Connection) -> None:
    """A router with a name, the host PC (nickname over hostname), an unnamed camera, a phone."""
    ex = conn.execute
    ex("INSERT INTO devices(id, mac, ip, hostname, nickname, kind, vendor, first_seen, last_seen, online) "
       "VALUES(1,'50:C7:BF:3A:1D:04','192.168.1.1','gateway','Home router','router','TP-Link',?,?,1)",
       (ts(days=30), ts(minutes=5)))
    ex("INSERT INTO devices(id, mac, ip, hostname, nickname, kind, vendor, first_seen, last_seen, online) "
       "VALUES(2,?,'192.168.1.20','HOME-PC','Home PC','computer','Intel',?,?,1)",
       (HOST_MAC, ts(days=30), ts(minutes=5)))
    ex("INSERT INTO devices(id, mac, ip, hostname, nickname, kind, vendor, first_seen, last_seen, online) "
       "VALUES(18,?,'192.168.1.142',NULL,NULL,'camera',NULL,?,?,1)",
       (CAMERA_MAC, ts(hours=2), ts(minutes=5)))
    ex("INSERT INTO devices(id, mac, ip, hostname, nickname, kind, vendor, first_seen, last_seen, online) "
       "VALUES(7,'AC:BC:32:70:2D:9E','192.168.1.32','iphone-ellie',?,'phone','Apple',?,?,0)",
       ("Ellie's iPhone", ts(days=20), ts(minutes=40)))
    conn.commit()
    add_finding(conn, 1, "NET-SVC-001", f"device:{CAMERA_MAC}:23", "critical", "Telnet open on 192.168.1.142:23",
                device_id=18)
    add_finding(conn, 2, "WIN-NET-001", "host:HOME-PC", "high", "SMBv1 file sharing protocol is enabled")
    add_finding(conn, 3, "WIN-UPD-004", "host:HOME-PC", "high", "Outdated high-risk app: Chrome")
    add_finding(conn, 4, "WIN-UPD-004", "host:HOME-PC", "high", "Outdated high-risk app: Java")
    add_finding(conn, 5, "NET-DNS-004", "dns:192.168.1.32", "high", "192.168.1.32 tried to reach a malicious domain")
    add_finding(conn, 6, "NET-WAN-003", "wan:203.0.113.42", "medium", "UPnP port mapping")
    add_finding(conn, 7, "NET-WIFI-002", "wifi:Wi-Fi", "info", "Wi-Fi uses WPA2 without WPA3")
    add_finding(conn, 8, "WIN-SYS-007", "host:HOME-PC", "low", "Screen lock is not enforced", status="acknowledged")
    add_finding(conn, 9, "WIN-FW-001", "host:HOME-PC", "critical", "Firewall off", status="resolved",
                first=ts(days=3), resolved=ts(days=2, hours=12))
    ex("INSERT INTO vulns(id, device_id, cve, source, kev, cvss, epss, title, matched_on, first_seen, last_seen) "
       "VALUES(1,1,'CVE-2023-1389','nvd',1,8.8,0.9437,'TP-Link command injection','cpe',?,?)", (ts(days=3), ts(hours=1)))
    ex("INSERT INTO vulns(id, device_id, cve, source, kev, cvss, epss, title, matched_on, first_seen, last_seen) "
       "VALUES(2,18,'CVE-2017-9833','nvd',0,7.5,0.0042,'Boa directory traversal','cpe',?,?)", (ts(days=3), ts(hours=1)))
    for i, client in enumerate(["192.168.1.32", "192.168.1.32", "192.168.1.142", "10.9.9.9"]):
        ex("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,?)",
           (ts(minutes=10 + i), client, "ads.doubleclick.net", "A", "block", "oisd_small", 1.0))
    conn.commit()


@pytest.fixture
def conn():
    c = fresh_conn()
    seed(c)
    add_scan(c, "discovery", "ok", ts(minutes=4))
    add_core_checks(c)
    return c


@pytest.fixture
def empty_conn():
    return fresh_conn()


def client_for(conn, cfg=None):
    app = create_app(cfg or make_cfg(), conn, scheduler=None, dns_server=None)
    app.config["TESTING"] = True
    return app.test_client()


# --------------------------------------------------------------------------- words


def test_severity_status_and_score_words():
    assert [api.sev_word(s) for s in api.SEVERITIES] == [
        "Fix now", "Fix this week", "Worth fixing", "When you have time", "Good to know"]
    assert [api.status_word(s) for s in api.STATUSES] == [
        "Needs attention", "Seen, not fixed yet", "Fixed", "Ignored (your choice)"]
    assert api.sev_word("CRITICAL") == "Fix now" and api.sev_word("bogus") == "" and api.sev_word(None) == ""
    assert api.status_word("weird") == ""
    assert (api.score_word(10), api.score_word(49), api.score_word(50), api.score_word(79), api.score_word(80)) == (
        "Needs work", "Needs work", "Fair", "Fair", "Good")
    assert api.score_word(None) == ""


def test_numbers_up_to_ten_are_words():
    assert [api.number_words(n) for n in (1, 2, 10, 11, 1204)] == ["one", "two", "ten", "11", "1,204"]


# --------------------------------------------------------------------------- device naming


def test_device_label_naming_rule():
    label = api.device_label
    assert label({"nickname": "Kitchen TV", "hostname": "tv", "ip": "192.168.1.40"}) == "Kitchen TV"
    assert label({"hostname": "HOME-PC", "ip": "192.168.1.20"}) == "HOME-PC"
    # unnamed: the kind, never the IP (the IP goes next to it, muted)
    assert label({"ip": "192.168.1.142", "kind": "camera"}) == "Unnamed camera"
    assert label({"ip": "192.168.1.142", "hostname": "192.168.1.142", "kind": "iot"}) == "Unnamed smart device"
    assert label({"ip": "192.168.1.9", "mac": "aa:bb:cc:dd:ee:ff"}) == "Unnamed device"
    assert label({"ip": "192.168.1.9", "kind": "something-new"}) == "Unnamed device"
    assert label({"device_name": "192.168.1.9", "device_ip": "192.168.1.9"}) == "Unnamed device"
    assert label({"kind": "self"}) == "This computer"
    assert label(None) == "Unnamed device"
    # host subjects read "This computer (<name>)"
    assert label({"subject": "host:HOME-PC"}) == "This computer (HOME-PC)"
    assert label({"subject": "host"}) == "This computer"
    # a precomputed label wins; other subjects get plain words
    assert label({"device_label": "This computer (Home PC)", "subject": "host:HOME-PC"}) == "This computer (Home PC)"
    assert label({"subject": "wan:203.0.113.4"}) == "Your internet connection"
    assert label({"subject": "wifi:Wi-Fi"}) == "Your Wi-Fi"
    assert label({"subject": "soc:dns"}) == "Home SOC itself"


def test_device_label_accepts_sqlite_rows(conn):
    row = conn.execute("SELECT * FROM devices WHERE id=18").fetchone()
    assert api.device_label(row) == "Unnamed camera"


def test_findings_carry_device_label_and_link_host_findings_to_the_host_device(conn):
    by_id = {f["id"]: f for f in api.findings_list(conn)}
    camera = by_id[1]
    # the doubled "192.168.1.142 192.168.1.142" came from device_name falling back to the IP
    assert camera["device_label"] == "Unnamed camera" and camera["device_name"] == "Unnamed camera"
    assert camera["device_ip"] == "192.168.1.142" and camera["link_device_id"] == 18
    host = by_id[2]
    assert host["device_label"] == "This computer (Home PC)"
    assert host["link_device_id"] == 2 and host["device_id"] is None  # linked, not rewritten
    assert host["device_ip"] == "192.168.1.20"  # the host's own address, shown muted beside the name
    # a dns:<ip> finding without a device row still names the device that holds the address
    assert by_id[5]["device_label"] == "Ellie's iPhone" and by_id[5]["link_device_id"] == 7
    assert by_id[6]["device_label"] == "Your internet connection" and by_id[6]["link_device_id"] is None
    assert by_id[7]["device_label"] == "Your Wi-Fi"
    assert (by_id[1]["severity_word"], by_id[8]["status_word"]) == ("Fix now", "Seen, not fixed yet")
    for f in by_id.values():  # every existing key survives
        assert {"id", "finding_id", "subject", "severity", "title", "status", "device_ip", "device_name",
                "evidence", "remediation", "category"} <= set(f)


def test_host_computer_is_marked_on_devices_and_its_detail(conn):
    devices = {d["id"]: d for d in api.devices_list(conn)}
    assert devices[2]["is_this_computer"] is True and devices[2]["host_findings_open"] == 3
    assert devices[2]["host_findings_link"] == "/findings?status=open&q=host%3AHOME-PC"
    assert devices[18]["is_this_computer"] is False and devices[18]["host_findings_open"] == 0
    assert devices[18]["device_label"] == "Unnamed camera" and devices[18]["display_name"] == "192.168.1.142"
    detail = api.device_detail(conn, 2)
    assert detail["device_label"] == "Home PC" and detail["is_this_computer"] is True
    assert detail["host_findings_open"] == 3
    assert api.device_detail(conn, 18)["findings"][0]["device_label"] == "Unnamed camera"


def test_kind_self_is_the_host_even_without_a_hostname_match(conn):
    conn.execute("UPDATE devices SET kind='self', hostname='desk' WHERE id=2")
    conn.commit()
    assert api.host_device(conn)["id"] == 2
    assert {f["id"]: f for f in api.findings_list(conn)}[2]["link_device_id"] == 2


# --------------------------------------------------------------------------- vulns: CVSS, EPSS, KEV


def test_vulns_have_plain_numbers(conn):
    by_cve = {v["cve"]: v for v in api.vulns_list(conn)}
    router = by_cve["CVE-2023-1389"]
    assert router["device_label"] == "Home router" and router["device_ip"] == "192.168.1.1"
    assert router["cvss_text"] == "8.8 / 10"
    assert router["epss_pct"] == 94.4
    assert router["epss_text"] == "94% chance this flaw is exploited somewhere in the next 30 days"
    assert router["kev_text"].startswith("Yes: attackers are known to have used this flaw")
    camera = by_cve["CVE-2017-9833"]
    assert camera["device_label"] == "Unnamed camera" and camera["device_name"] == "Unnamed camera"
    assert camera["epss_text"].startswith("Less than 1% chance")
    assert camera["kev_text"] == "Not on CISA's known-exploited list"
    assert "worldwide" in camera["epss_note"]


@pytest.mark.parametrize("epss, expected", [
    (0.9437, "94%"), (0.042, "4.2%"), (0.05, "5%"), (0.001, "Less than 1%"), (12.5, "12%"), (0.1, "10%"),
])
def test_epss_is_worded_as_exploitation_somewhere_never_as_attack(epss, expected):
    text = api.epss_text(epss)
    assert text == f"{expected} chance this flaw is exploited somewhere in the next 30 days"
    lowered = (text + " " + api.EPSS_NOTE).lower()
    assert "chance of attack" not in lowered and "you will be attacked" not in lowered
    assert "attacked" not in text.lower()


def test_cvss_and_epss_missing_values():
    assert api.cvss_text(None) is None and api.cvss_text("x") is None and api.cvss_text(10) == "10.0 / 10"
    assert api.epss_text(None) is None and api.epss_pct(-1) is None


# --------------------------------------------------------------------------- DNS clients


def test_dns_top_clients_and_log_name_devices(conn):
    top = {r["client"]: r for r in api.dns_top(conn, "clients", hours=24)}
    assert top["192.168.1.32"]["device_label"] == "Ellie's iPhone" and top["192.168.1.32"]["device_id"] == 7
    assert top["192.168.1.142"]["device_label"] == "Unnamed camera"
    assert top["10.9.9.9"]["device_label"] == "Unnamed device" and top["10.9.9.9"]["device_id"] is None
    assert all({"client", "total", "blocked", "device_ip"} <= set(r) for r in top.values())
    log = api.dns_log(conn, 10)
    assert {r["client"]: r["device_label"] for r in log}["192.168.1.32"] == "Ellie's iPhone"
    assert {"id", "ts", "client", "qname", "action"} <= set(log[0])


# --------------------------------------------------------------------------- fix these first


def test_fix_these_first_rows_say_where_and_how_many_points(conn):
    rows = {r["finding_id"]: r for r in api.score_breakdown(conn)}
    telnet = rows["NET-SVC-001"]
    assert telnet["severity_word"] == "Fix now" and telnet["device_label"] == "Unnamed camera"
    assert telnet["link_device_id"] == 18 and telnet["where_text"] == "Unnamed camera"
    assert telnet["gain_text"] == f"+{telnet['gain']} points"
    apps = rows["WIN-UPD-004"]  # two open, both on this computer: one place
    assert apps["device_label"] == "This computer (Home PC)" and apps["link_device_id"] == 2


def test_fix_these_first_across_several_devices_lists_them(conn):
    for i, dev in enumerate((1, 18, 7), start=20):
        add_finding(conn, i, "NET-SVC-009", f"device:x:{i}", "high", "Admin page over HTTP", device_id=dev)
    row = next(r for r in api.score_breakdown(conn, limit=20) if r["finding_id"] == "NET-SVC-009")
    assert row["device_label"] is None and row["link_device_id"] is None
    assert row["where_text"] == "Home router, Unnamed camera and 1 more"


# --------------------------------------------------------------------------- staleness


def test_staleness_fresh_stale_and_never(conn, empty_conn):
    fresh = api.staleness(conn, make_cfg())
    assert fresh["stale"] is False and fresh["never"] is False and fresh["message"] is None
    assert fresh["age_text"] == "4 minutes ago" and fresh["schedule_minutes"] == 10
    assert fresh["threshold_minutes"] == 30 and fresh["last_check"].endswith("Z")

    never = api.staleness(empty_conn, make_cfg())
    assert never["never"] is True and never["stale"] is False and never["age_text"] == "never"
    assert never["last_check"] is None

    add_scan(empty_conn, "discovery", "ok", ts(days=8, hours=3))
    old = api.staleness(empty_conn, make_cfg())
    assert old["stale"] is True and old["age_text"] == "8 days ago"
    assert old["message"] == "Home SOC last checked your network 8 days ago — what you see may be out of date."


def test_staleness_follows_the_schedule_and_is_capped_at_a_day(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=45))
    assert api.staleness(empty_conn, make_cfg(10))["stale"] is True    # 45 > 3 x 10
    assert api.staleness(empty_conn, make_cfg(20))["stale"] is False   # 45 < 3 x 20
    assert api.staleness(empty_conn, make_cfg(60 * 24))["threshold_minutes"] == 24 * 60


def test_only_a_finished_look_counts_as_a_check(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(days=2))
    add_scan(empty_conn, "discovery", "error", ts(minutes=1))     # failed: did not look
    add_scan(empty_conn, "discovery", "aborted", ts(minutes=1))
    add_scan(empty_conn, "services", "ok", ts(minutes=1))         # not a discovery sweep
    assert api.staleness(empty_conn, make_cfg())["age_text"] == "2 days ago"
    add_scan(empty_conn, "discovery", "partial", ts(minutes=2))
    assert api.staleness(empty_conn, make_cfg())["age_text"] == "2 minutes ago"


# --------------------------------------------------------------------------- status line


def status(conn, cfg=None):
    return api.status_summary(conn, cfg or make_cfg())


def test_status_line_with_urgent_things(conn):
    s = status(conn)
    # 1 critical + 4 high open
    assert s["status_line"] == "Five things need your attention, one of them urgent; two more can wait."
    assert s["status_tone"] == "attention" and s["status_link"] == "/findings?status=open"


def test_status_line_two_things_one_urgent(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    add_finding(empty_conn, 1, "A", "host", "critical", "a")
    add_finding(empty_conn, 2, "B", "host", "high", "b")
    assert status(empty_conn)["status_line"] == "Two things need your attention, one of them urgent."
    empty_conn.execute("UPDATE findings SET severity='critical'")
    empty_conn.commit()
    assert status(empty_conn)["status_line"] == "Two things need your attention, and both are urgent."


def test_status_line_this_week_only(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    add_finding(empty_conn, 1, "B", "host", "high", "b")
    s = status(empty_conn)
    assert s["status_line"] == "One thing needs your attention this week."
    assert s["status_tone"] == "week" and s["status_link"] == "/findings?status=open&severity=high"


def test_status_line_healthy_only_when_fresh_and_complete(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    s = status(empty_conn)
    assert s["status_line"] == "Your network looks healthy — nothing needs your attention right now."
    assert s["status_tone"] == "healthy"
    for i in range(12):
        add_finding(empty_conn, 10 + i, f"L{i}", "host", "low", "l")
    assert status(empty_conn)["status_line"] == (
        "Your network looks healthy; 12 small things are worth fixing when you have time.")


def test_status_line_never_says_healthy_when_stale(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(days=8, hours=1))
    s = status(empty_conn)
    assert "healthy" not in s["status_line"].lower() and s["status_tone"] == "stale"
    assert s["status_line"] == "Home SOC hasn't checked your network for 8 days, so what you see may be out of date."
    add_finding(empty_conn, 1, "A", "host", "critical", "a")
    add_finding(empty_conn, 2, "B", "host", "critical", "b")
    for i in range(6):
        add_finding(empty_conn, 3 + i, f"H{i}", "host", "high", "h")
    assert status(empty_conn)["status_line"] == (
        "Home SOC hasn't checked your network for 8 days, so what you see may be out of date; "
        "at that check, two things needed fixing right away and six more this week.")


def test_status_line_never_says_healthy_after_a_failed_check(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    add_scan(empty_conn, "services", "error", ts(minutes=3))
    s = status(empty_conn)
    assert "healthy" in s["status_line"] and "can't confirm" in s["status_line"]
    assert s["status_line"] == "The last open-port check did not finish, so Home SOC can't confirm your network is healthy."
    assert s["status_tone"] == "stale" and s["unfinished"][0]["kind"] == "services"
    add_scan(empty_conn, "services", "ok", ts(minutes=1))  # a later run that worked clears it
    assert status(empty_conn)["status_tone"] == "healthy"


def test_status_line_with_urgent_things_and_a_failed_check(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    add_scan(empty_conn, "exposure", "aborted", ts(minutes=3))
    add_finding(empty_conn, 1, "A", "host", "critical", "a")
    assert status(empty_conn)["status_line"] == (
        "One thing needs your attention, and it is urgent — and the last internet-exposure check did not "
        "finish, so there may be more.")


def test_status_line_before_the_first_check(empty_conn):
    s = status(empty_conn)
    assert s["status_line"] == "Home SOC hasn't checked your network yet." and s["status_tone"] == "stale"


# --------------------------------------------------------------------------- overview + summary payloads


def test_api_summary_carries_status_line_and_staleness(conn):
    body = client_for(conn).get("/api/summary").get_json()
    # make_cfg() switches web blocking on and no DNS server is attached: the line says so.
    assert body["status_line"] == "Five things need your attention, one of them urgent; two more can wait. Web blocking is not running."
    assert body["status_tone"] == "attention" and body["status_link"].startswith("/findings")
    assert body["staleness"]["stale"] is False and body["staleness"]["age_text"] == "4 minutes ago"
    assert body["staleness"] == api.staleness(conn, make_cfg()) | {"age_seconds": body["staleness"]["age_seconds"]}
    assert body["score_word"] in ("Needs work", "Fair", "Good") and body["unfinished_checks"] == []
    assert body["dns_note"] == "Web blocking is switched on but not running, so nothing is being filtered right now."
    # every key the overview already used is still there
    assert {"generated_at", "name", "refresh_seconds", "score", "grade", "trend", "score_breakdown", "counts",
            "devices", "dns", "jobs", "feeds", "last_scans", "events", "scheduler"} <= set(body)
    assert body["score_breakdown"][0]["severity_word"] and "gain_text" in body["score_breakdown"][0]


def test_api_summary_on_stale_data_is_not_healthy(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(days=3))
    body = client_for(empty_conn).get("/api/summary").get_json()
    assert body["staleness"]["stale"] is True and body["status_tone"] == "stale"
    assert "healthy" not in body["status_line"].lower()


def test_build_summary_plain_fields_are_opt_in(conn):
    base = summarymod.build_summary(conn)
    assert "status_line" not in base and "staleness" not in base  # the exported schema is unchanged
    plain = summarymod.build_summary(conn, cfg=make_cfg(), plain=True)
    assert set(plain) == set(base) | {"status_line", "status_tone", "status_link", "unfinished_checks",
                                      "staleness", "score_word"}
    assert plain["status_line"] == api.status_summary(conn, make_cfg())["status_line"]
    assert plain["staleness"]["stale"] is False


def test_summary_rows_are_named(conn):
    s = summarymod.build_summary(conn)
    work = {w["row_id"]: w for w in s["open_worklist"]}
    assert work[1]["device_label"] == "Unnamed camera" and work[1]["device_ip"] == "192.168.1.142"
    assert work[1]["device_name"] == "Unnamed camera" and work[1]["severity_word"] == "Fix now"
    assert work[2]["device_label"] == "This computer (Home PC)" and work[2]["link_device_id"] == 2
    assert work[1]["age_text"] == "Found today" or work[1]["age_text"].startswith("Open for")
    fixed = s["remediated"][0]
    assert fixed["device_label"] == "This computer (Home PC)" and fixed["how_text"] == "Marked fixed"
    assert fixed["time_open_text"] == "Open for 12 hours"
    top = {t["device_id"]: t for t in s["top_devices"]}
    assert top[18]["device_label"] == "Unnamed camera" and top[18]["ip"] == "192.168.1.142"


def test_markdown_report_names_the_host(conn):
    md = summarymod.remediation_report_markdown(conn)
    assert "Affects: This computer (Home PC)" in md and "Affects: Unnamed camera" in md


# --------------------------------------------------------------------------- time to fix


def test_time_to_fix_wording():
    t = api.time_to_fix_text
    assert t(11.3, 70.0, 9) == "Usually fixed within 12 hours; almost always within 3 days."
    assert t(0.4, 0.5, 6) == "Usually fixed within 24 minutes; almost always within 30 minutes."
    assert t(5.0, 5.0, 6) == "Usually fixed within 5 hours."
    # too few fixes for "almost always": say so rather than invent a percentile
    assert t(10.0, 30.0, 3) == ("Usually fixed within 10 hours; the slowest took 30 hours "
                                "(only three fixes so far, so this is a rough guide).")
    assert t(24.0, 24.0, 1) == "The one fix in this period took about 24 hours."
    assert t(None, None, 0) == "Nothing was fixed in this period, so there is no typical time to fix yet."


def test_summary_time_to_remediate_has_text(conn):
    ttr = summarymod.build_summary(conn)["time_to_remediate"]
    assert ttr["count"] == 1 and ttr["text"] == "The one fix in this period took about 12 hours."


# --------------------------------------------------------------------------- activity feed


def test_feed_items_name_devices_without_doubling_the_ip(conn):
    items, _ = feedmod.build_feed(conn, since=ts(days=31), limit=200)
    new_camera = next(i for i in items if i.kind == "device_new" and i.ref.get("device_id") == 18)
    assert new_camera.title == "New device joined the network: Unnamed camera (192.168.1.142)"
    assert new_camera.device_label == "Unnamed camera"
    blocks = [i for i in items if i.kind == "dns_block"]
    phone = next(i for i in blocks if i.ref["client"] == "192.168.1.32")
    assert "from Ellie's iPhone (192.168.1.32)" in phone.title and phone.device_label == "Ellie's iPhone"
    stranger = next(i for i in blocks if i.ref["client"] == "10.9.9.9")
    assert stranger.title.endswith("from 10.9.9.9") and stranger.device_label == "Unnamed device"
    # the item's JSON shape is pinned by the API contract: the label travels inside ref
    assert set(new_camera.as_dict()) == {"ts", "kind", "severity", "title", "detail", "link", "icon", "ref"}
    assert new_camera.as_dict()["ref"]["device_label"] == "Unnamed camera"


def test_feed_finding_items_name_the_host(conn):
    conn.execute("INSERT INTO finding_events(finding_row_id, event, at, note) VALUES(2,'opened',?,NULL)", (ts(hours=1),))
    conn.commit()
    items, _ = feedmod.build_feed(conn, since=ts(days=1))
    smb = next(i for i in items if i.kind == "finding_new")
    assert smb.device_label == "This computer (Home PC)" and smb.detail.startswith("This computer (Home PC)")
    assert smb.ref["link_device_id"] == 2


def test_feed_chips_flag_zero_counts(conn):
    counts = feedmod.feed_counts(conn, 24)
    chips = feedmod.feed_chips(counts)
    assert [c["kind"] for c in chips] == list(feedmod.KINDS)
    by_kind = {c["kind"]: c for c in chips}
    assert by_kind["dns_block"]["zero"] is False and by_kind["dns_block"]["count"] == counts["dns_block"] > 0
    assert by_kind["av_threat"]["zero"] is True and by_kind["av_threat"]["plain_label"] == "Antivirus detections"
    assert by_kind["scan"]["label"] == "Scan"  # technical label kept beside the plain one
    assert all(c["zero"] for c in feedmod.feed_chips(None))


def test_feed_empty_state_reasons(conn, empty_conn):
    assert feedmod.feed_empty_state(conn, 5)["reason"] is None
    never = feedmod.feed_empty_state(empty_conn, 0, cfg=make_cfg())
    assert never["reason"] == "never_run" and never["empty"] is True and "hasn't run any checks" in never["message"]

    quiet = feedmod.feed_empty_state(conn, 0, window_hours=1, cfg=make_cfg())
    assert quiet["reason"] == "quiet"
    assert quiet["message"] == "Nothing new in the last hour — that is normal on a quiet day."
    assert quiet["suggest_window"] == "7d" and quiet["last_activity"] and quiet["last_activity_text"]

    filtered = feedmod.feed_empty_state(conn, 0, window_hours=24 * 7, filtered=True, cfg=make_cfg())
    assert filtered["reason"] == "filtered" and filtered["suggest_window"] == "30d"
    assert filtered["message"] == "Nothing matches these filters in the last 7 days."


def test_feed_empty_state_does_not_call_a_stale_screen_quiet(empty_conn):
    seed(empty_conn)
    add_scan(empty_conn, "discovery", "ok", ts(days=8, hours=2))
    state = feedmod.feed_empty_state(empty_conn, 0, window_hours=24, cfg=make_cfg())
    assert state["reason"] == "not_checking"
    assert state["message"] == ("Nothing new in the last 24 hours, but Home SOC hasn't checked your network for "
                                "8 days, so this may just mean it isn't looking.")
    assert "normal" not in state["message"]


def test_api_feed_keeps_its_shape_and_carries_labels(conn):
    body = client_for(conn).get("/api/feed?window=30d&limit=50").get_json()
    assert set(body) >= {"items", "total", "counts", "generated_at"}
    labelled = [i for i in body["items"] if i["ref"].get("device_label")]
    assert labelled and all(set(i) == {"ts", "kind", "severity", "title", "detail", "link", "icon", "ref"}
                            for i in body["items"])


# --------------------------------------------------------------------------- JSON endpoints


def test_json_endpoints_carry_device_label(conn):
    c = client_for(conn)
    findings = c.get("/api/findings?status=open").get_json()
    assert all(f["device_label"] for f in findings)
    assert {f["id"]: f["link_device_id"] for f in findings}[2] == 2
    devices = c.get("/api/devices").get_json()
    assert {d["id"]: d["device_label"] for d in devices}[18] == "Unnamed camera"
    assert c.get("/api/devices/18").get_json()["device_label"] == "Unnamed camera"
    vulns = c.get("/api/vulns").get_json()
    assert {v["cve"]: v["epss_text"] for v in vulns}["CVE-2023-1389"].startswith("94% chance")
    top = c.get("/api/dns/top?kind=clients").get_json()
    assert {r["client"]: r["device_label"] for r in top}["192.168.1.32"] == "Ellie's iPhone"
    log = c.get("/api/dns/log?limit=5").get_json()
    assert all("device_label" in r for r in log)


def test_map_payload_names_device_nodes(conn, monkeypatch):
    nodes = [
        {"id": "device:18", "kind": "device", "label": "192.168.1.142", "device_id": 18},
        {"id": "device:1", "kind": "device", "label": "Home router", "device_id": 1},
        {"id": "internet", "kind": "internet", "label": "Internet"},
    ]
    edges = [{"src": "device:18", "dst": "device:1", "confidence": "inferred", "edge_type": "gateway"}]
    monkeypatch.setattr(api, "_topology_fn", lambda *names: (lambda conn, **kw: (nodes, edges)))
    api._MAP_SLOW.clear()
    payload = api.map_graph(conn, hours=24)
    by_id = {n["id"]: n for n in payload["nodes"]}
    assert by_id["device:18"]["device_label"] == "Unnamed camera" and by_id["device:18"]["device_ip"] == "192.168.1.142"
    assert by_id["device:1"]["device_label"] == "Home router"
    assert by_id["internet"]["device_label"] is None
    assert by_id["device:18"]["label"] == "192.168.1.142"  # the engine's own label is untouched


def test_outage_members_are_named(conn):
    conn.execute("INSERT INTO outages(id, started_at, ended_at, cycle_seconds, trigger_device_id, trigger_kind, "
                 "member_count) VALUES(1,?,?,600,1,'gateway',2)", (ts(days=1), ts(hours=23)))
    conn.execute("INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES(1,18,?)", (ts(days=1),))
    conn.execute("INSERT INTO outage_members(outage_id, device_id, dropped_at) VALUES(1,7,?)", (ts(days=1),))
    conn.commit()
    outage = api.map_outages(conn)[0]
    assert outage["trigger_device_label"] == "Home router"
    assert {m["device_id"]: m["device_label"] for m in outage["members"]} == {18: "Unnamed camera", 7: "Ellie's iPhone"}
    assert {m["device_id"]: m["label"] for m in outage["members"]}[18] == "192.168.1.142"  # existing key kept


def test_status_line_accepts_a_staleness_dict_without_age():
    """A caller may pass the shell's own staleness dict (age_text only); the sentence still reads."""
    conn = fresh_conn()
    line = api.status_summary(conn, make_cfg(), stale={"stale": True, "never": False, "age_text": "3 days ago"})
    assert line["status_line"] == "Home SOC hasn't checked your network for 3 days, so what you see may be out of date."


# --------------------------------------------------------------------------- core checks (review H1)


def test_status_line_is_not_healthy_when_only_the_device_check_ran(empty_conn):
    """A fresh device check and nothing else must not read as a clean bill of health."""
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    s = status(empty_conn)
    assert "looks healthy" not in s["status_line"] and s["status_tone"] == "stale"
    assert s["status_line"].startswith("Home SOC has only looked for devices so far; it hasn't checked the devices' open doors")
    assert "checked this computer" in s["status_line"] and "can't say whether your network is healthy" in s["status_line"]
    assert {o["kind"] for o in s["overdue"]} == {"services", "vulns", "host", "feeds"}


def test_status_line_names_the_one_core_check_that_never_ran(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    for kind in ("services", "vulns", "feeds"):
        add_scan(empty_conn, kind, "ok", ts(minutes=3))
    assert status(empty_conn)["status_line"] == (
        "Home SOC hasn't checked this computer yet, so it can't say whether your network is healthy.")


def test_status_line_reports_an_overdue_core_check(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    add_scan(empty_conn, "host", "ok", ts(days=3))  # newest host run is old (3 x 6 h = 18 h window)
    empty_conn.execute("DELETE FROM scans WHERE kind='host' AND id <> (SELECT max(id) FROM scans WHERE kind='host')")
    empty_conn.commit()
    s = status(empty_conn)
    assert s["status_tone"] == "stale" and "looks healthy" not in s["status_line"]
    assert "the check of this computer last finished 3 days ago" in s["status_line"]


def test_feeds_are_not_required_when_switched_off(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    for kind in ("services", "vulns", "host"):
        add_scan(empty_conn, kind, "ok", ts(minutes=3))
    cfg = make_cfg()
    cfg.feeds = SimpleNamespace(enabled=False)
    assert api.status_summary(empty_conn, cfg)["status_tone"] == "healthy"


def test_status_line_adds_web_blocking_not_running(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    line = api.status_summary(empty_conn, make_cfg(), dns={"enabled": True, "running": False})["status_line"]
    assert line == "Your network looks healthy — nothing needs your attention right now. Web blocking is not running."
    line = api.status_summary(empty_conn, make_cfg(), dns={"enabled": True, "running": True})["status_line"]
    assert "Web blocking" not in line


def test_overview_never_says_working_normally_when_a_core_check_never_ran(empty_conn):
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    html = client_for(empty_conn).get("/").get_data(as_text=True)
    assert "working normally" not in html and "looks healthy" not in html
    assert "has not run yet" in html


def test_status_line_adds_up_to_the_to_fix_count(empty_conn):
    """The banner and the "N to fix" chip sit side by side on Home. When the banner counted only the
    urgent and this-week items ("Eight things need your attention" beside "33 to fix") a reader saw
    two numbers that disagree; the rest must be accounted for so they add up."""
    add_scan(empty_conn, "discovery", "ok", ts(minutes=2))
    add_core_checks(empty_conn)
    add_finding(empty_conn, 1, "A", "host", "critical", "a")
    add_finding(empty_conn, 2, "B", "host", "high", "b")
    for i, sev in enumerate(["medium", "low", "low", "info"], start=3):
        add_finding(empty_conn, i, f"X{i}", "host", sev, f"x{i}")
    line = status(empty_conn)["status_line"]
    assert line == "Two things need your attention, one of them urgent; four more can wait."
    total = empty_conn.execute("SELECT count(*) FROM findings WHERE status='open'").fetchone()[0]
    assert total == 2 + 4
