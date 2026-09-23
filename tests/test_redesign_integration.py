"""The redesign's integration seams: what only shows up once the shell, the data layer, the
catalogue, the pages and Lens are wired together.

* plain headlines and filled-in "why it matters" actually reach the rows the pages render;
* "Things to fix" opens on what needs attention, and ``?status=`` still means everything;
* a never-checked network never reads as a clean bill of health;
* EPSS on Lens is a forecast for the flaw, never a chance of attack;
* a device with no name is never described by its bare address in a sentence;
* the one-tap "allow" in the live DNS log knows when a domain came from a threat list;
* times read as words ("8 days ago"), the same as the staleness banner.
"""

from __future__ import annotations

import re

import pytest

from homesoc.web import api
from homesoc.web import app as appmod
from homesoc.web import lens as lensmod
from homesoc.web import summary as summarymod

from test_plain_data import add_scan, client_for, fresh_conn, seed, ts  # noqa: F401  (shared fixtures)


@pytest.fixture
def conn():
    c = fresh_conn()
    seed(c)
    add_scan(c, "discovery", "ok", ts(minutes=4))
    return c


# --------------------------------------------------------------------------- plain headlines


def test_findings_rows_carry_the_plain_headline_and_a_filled_in_why(conn):
    rows = api.findings_list(conn)
    assert rows
    for f in rows:
        assert f["plain_title"], f["finding_id"]
        assert f["plain_title"] != f["title"]
        assert "{" not in f["rationale"] and "}" not in f["rationale"]
    telnet = next(f for f in rows if f["finding_id"] == "NET-SVC-001")
    assert "192.168.1.142" not in telnet["plain_title"], "device findings say 'This device', the name sits beside it"


def test_fix_these_first_and_the_report_worklist_carry_plain_headlines(conn):
    breakdown = api.score_breakdown(conn)
    assert breakdown and all(b.get("plain_title") for b in breakdown)
    data = summarymod.build_summary(conn, days=30)
    assert data["open_worklist"] and all(w.get("plain_title") for w in data["open_worklist"])
    assert all("plain_title" in r for r in data["remediated"])


def test_the_catalogue_is_optional_for_a_plain_headline():
    assert api.catalog_plain_title("NO-SUCH-ID", {}, "") == ""
    assert api.catalog_why("NO-SUCH-ID", "not json", "") == ""


# --------------------------------------------------------------------------- Things to fix


def test_things_to_fix_opens_on_what_needs_attention(conn):
    client = client_for(conn)
    default = client.get("/findings").get_data(as_text=True)
    everything = client.get("/findings?status=").get_data(as_text=True)
    # WIN-FW-001 is resolved and WIN-SYS-007 acknowledged in the seed.
    assert "WIN-FW-001" not in default and "WIN-SYS-007" not in default
    assert "WIN-FW-001" in everything and "WIN-SYS-007" in everything
    assert "WIN-FW-001" in client.get("/findings?status=resolved").get_data(as_text=True)


def test_the_host_device_page_lists_its_settings_findings(conn):
    html = client_for(conn).get("/devices/2").get_data(as_text=True)
    assert "WIN-NET-001" in html and "WIN-UPD-004" in html


def test_overview_names_the_devices_that_need_attention_worst_first(conn):
    rows = appmod._devices_needing_attention(conn)
    assert rows[0]["id"] == 18 and rows[0]["worst_severity"] == "critical"
    host = next(r for r in rows if r["id"] == 2)
    assert host["to_fix"] >= 3 and host["worst_severity"] == "high"
    html = client_for(conn).get("/").get_data(as_text=True)
    assert 'id="devices-attention"' in html and "Unnamed camera" in html


# --------------------------------------------------------------------------- honesty


def test_a_never_checked_network_has_no_score_to_show():
    conn = fresh_conn()
    client = client_for(conn)
    html = client.get("/summary").get_data(as_text=True)
    assert "not checked yet" in html
    assert not re.search(r"<b>100</b>\s*<span class=\"muted\">/100", html)
    js = (appmod.Path(appmod.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    assert "not checked yet" in js and "unknown: true" in js


def test_lens_epss_is_a_forecast_for_the_flaw_never_a_chance_of_attack():
    for value in (0.9437, 0.05, 0.004):
        text = lensmod._epss_text(value)
        assert "exploited somewhere in the next 30 days" in text
        assert "attack" not in text.lower()
    assert "attack" not in lensmod.FINDING_CLAUSE["NET-VUL-004"]
    assert "UPnP" in lensmod.FINDING_CLAUSE["NET-RTR-002"], "NET-RTR-002 is UPnP, not a default password"


def test_a_sentence_never_uses_a_bare_address_as_a_name():
    from homesoc.topology import graph

    row = {"nickname": None, "hostname": None, "kind": "camera", "ip": "192.168.1.142"}
    assert graph._spoken_name(row, "192.168.1.142") == "the unnamed camera (192.168.1.142)"
    named = {"nickname": "Home router", "hostname": "gateway", "kind": "router", "ip": "192.168.1.1"}
    assert graph._spoken_name(named, "Home router") == "Home router"


def test_dns_log_flags_threat_list_and_reputation_blocks_for_the_allow_warning(conn):
    conn.execute("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,?)",
                 (ts(minutes=1), "192.168.1.32", "bad.example", "A", "block", "list:urlhaus", 1.0))
    conn.execute("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,?)",
                 (ts(minutes=1), "192.168.1.32", "worse.example", "A", "block", "reputation", 1.0))
    conn.execute("INSERT INTO reputation(domain, source, verdict, malicious, suspicious, checked_at) "
                 "VALUES('shady.example','virustotal','suspicious',0,4,?)", (ts(minutes=2),))
    conn.execute("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,?)",
                 (ts(minutes=1), "192.168.1.32", "shady.example", "A", "allow", None, 1.0))
    conn.commit()
    by_name = {r["qname"]: r for r in api.dns_log(conn, 50)}
    assert by_name["bad.example"]["reputation"] == "malicious"
    assert by_name["worse.example"]["reputation"] == "malicious"
    assert by_name["shady.example"]["reputation"] == "suspicious"
    assert by_name["ads.doubleclick.net"]["reputation"] is None


def test_times_read_as_words(conn):
    app = client_for(conn).application
    ago = app.jinja_env.filters["ago"]
    assert ago(ts(days=8, minutes=1)) == "8 days ago"
    assert ago(ts(hours=3, minutes=1)) == "3 hours ago"
    assert ago(ts(seconds=5)) == "just now"
    assert ago(None) == "never"


def test_one_staleness_rule_for_the_shell_and_the_api(conn):
    shell = appmod.staleness(conn, None)
    data = api.staleness(conn, None)
    assert {k: shell[k] for k in ("stale", "never", "last_check", "threshold_minutes")} == \
           {k: data[k] for k in ("stale", "never", "last_check", "threshold_minutes")}
