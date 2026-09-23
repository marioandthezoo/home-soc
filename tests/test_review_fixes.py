"""Regression tests for the redesign review (2026-09-22): honesty, accessibility and wording.

Each test names the review finding it pins. Offline: the in-memory database and Flask test client
from test_plain_data, plus reads of the shipped templates and static files.
"""

from __future__ import annotations

from pathlib import Path

import test_plain_data as P
from homesoc.findings import catalog
from homesoc.web import api, lens
from homesoc.web import feed as feedmod
from homesoc.web.app import code_parts

WEB = Path(__file__).resolve().parents[1] / "homesoc" / "web"
STATIC = WEB / "static"
TEMPLATES = WEB / "templates"


def page(conn, path):
    r = P.client_for(conn).get(path)
    assert r.status_code == 200, (path, r.status_code)
    return r.get_data(as_text=True)


def seeded():
    conn = P.fresh_conn()
    P.seed(conn)
    P.add_scan(conn, "discovery", "ok", P.ts(minutes=4))
    P.add_core_checks(conn)
    return conn


# --------------------------------------------------------------------------- honesty


def test_kev_is_never_worded_as_happening_right_now():
    """KEV records past exploitation in the wild; it says nothing about 'right now'."""
    html = page(seeded(), "/vulns")
    assert "right now" not in html
    assert "attackers are known to have used this flaw in real attacks" in html
    for text in (TEMPLATES / "vulns.html").read_text(encoding="utf-8"), (TEMPLATES / "device_detail.html").read_text(encoding="utf-8"):
        assert "using this right now" not in text
    for fid in ("NET-VUL-001", "NET-VUL-002"):
        assert "right now" not in lens.FINDING_CLAUSE[fid]
    assert "right now" not in catalog.get("NET-VUL-001").rationale
    assert "taken over automatically" not in catalog.get("NET-VUL-001").rationale


def test_plain_titles_claim_no_more_than_the_check_saw():
    assert "no antivirus running" not in catalog.get("WIN-DEF-001").plain_title
    assert "Defender" in catalog.get("WIN-DEF-001").plain_title
    assert "without a password" not in catalog.get("NET-SVC-006").plain_title
    assert "may still ask for a password" in catalog.get("NET-SVC-010").plain_title
    assert "to anyone who asks" not in lens.FINDING_CLAUSE["NET-SVC-010"]
    assert "open holes in the router" not in lens.FINDING_CLAUSE["NET-SVC-006"]


def test_blast_panel_never_says_unaffected_as_fact():
    js = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "'carry on as before'" not in js and "'not known to be affected'" in js
    tpl = (TEMPLATES / "device_detail.html").read_text(encoding="utf-8")
    assert "would carry on as normal" not in tpl and "not known to be affected" in tpl


def test_online_is_seen_at_last_check_and_the_map_is_never_about_connections():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert "devices seen at last check" in base and "devices online</a>" not in base
    tpl = (TEMPLATES / "map.html").read_text(encoding="utf-8")
    assert "offline right now" not in tpl and "not seen at Home SOC's last network" in tpl
    js = (STATIC / "graph.js").read_text(encoding="utf-8")
    assert "'Infrastructure'" not in js and "'Shared services'" in js
    for word in ("connection", "traffic flow"):
        assert word not in js.split("var EDGE_WORDS")[1].split("};")[0]


def test_dns_log_is_only_live_while_running():
    html = page(seeded(), "/dns")
    assert "(live, newest first)" not in html
    assert "web blocking is not running" in html


def test_a_device_never_port_checked_is_not_called_all_clear():
    conn = seeded()
    conn.execute("INSERT INTO devices(id, mac, ip, hostname, nickname, kind, first_seen, last_seen, online) "
                 "VALUES(16,'98:B6:E9:00:00:16','192.168.1.80',NULL,'Nintendo Switch','console',?,?,0)",
                 (P.ts(days=9), P.ts(days=1)))
    conn.commit()
    html = page(conn, "/devices/16")
    assert "Nothing to fix on it" not in html
    assert "hasn&#39;t checked this device&#39;s open doors" in html or "hasn't checked this device's open doors" in html
    conn.execute("UPDATE devices SET last_service_scan=? WHERE id=16", (P.ts(hours=3),))
    conn.commit()
    html = page(conn, "/devices/16")
    assert "Nothing to fix on it" in html and "it had no open doors" in html


def test_marked_fixed_is_not_fixed():
    conn = seeded()  # row 9 was resolved with no auto_resolved event: a person marked it fixed
    html = page(conn, "/findings?status=resolved")
    assert "Marked fixed" in html
    split = api.resolved_split(conn)
    assert split == {"resolved": 1, "confirmed": 0, "marked": 1}
    conn.execute("INSERT INTO finding_events(finding_row_id, event, at, note) VALUES(9,'auto_resolved',?,NULL)",
                 (P.ts(days=2),))
    conn.commit()
    assert api.resolved_split(conn)["confirmed"] == 1
    rows = api.findings_list(conn, status="resolved")
    assert rows[0]["resolved_how"] == "auto"


def test_event_type_findings_say_they_cannot_be_rechecked():
    rows = {r["finding_id"]: r for r in api.findings_list(seeded())}
    assert rows["NET-DNS-004"]["rechecks"] is False and rows["NET-SVC-001"]["rechecks"] is True
    html = page(seeded(), "/findings?status=open&q=NET-DNS-004")
    assert "cannot re-check this one" in html


def test_recent_activity_is_plain_sentences_with_names():
    conn = seeded()
    for msg, src in (("paired a new device: Pixel in the hallway", "lens"),
                     ("paired a new device: Pixel in the hallway", "lens"),
                     ("blocked a known-malicious domain for 192.168.1.32", "dnsfilter")):
        conn.execute("INSERT INTO events(ts, level, source, message) VALUES(?,?,?,?)", (P.ts(minutes=1), "info", src, msg))
    conn.commit()
    events = api.collapse_repeats(api.plain_events(conn, api.telemetry_events(conn, limit=10)))
    plain = [e["plain"] for e in events]
    assert any("Ellie's iPhone's address (192.168.1.32)" in p for p in plain)  # DNS: an address match
    lens_rows = [e for e in events if e["source"] == "lens"]
    assert len(lens_rows) == 1 and lens_rows[0]["repeats"] == 2
    assert "not a new device on your network" in lens_rows[0]["plain"]
    assert lens_rows[0]["message"] == "paired a new device: Pixel in the hallway"  # raw kept


def test_empty_metrics_window_says_when_the_last_one_was():
    conn = seeded()
    conn.execute("INSERT INTO metrics(ts, name, value) VALUES(?,?,?)", (P.ts(days=8), "score", 10))
    conn.commit()
    body = P.client_for(conn).get("/api/telemetry/metrics?hours=168", headers=P.FETCH).get_json()
    assert body["names"] == [] and body["last_ts"]
    assert "first job" in (STATIC / "app.js").read_text(encoding="utf-8")  # kept only for a truly empty table


# --------------------------------------------------------------------------- accessibility


def test_every_expandable_row_has_a_keyboard_toggle():
    html = page(seeded(), "/findings")
    assert 'class="row-toggle" aria-expanded="false" aria-controls="detail-1"' in html
    assert 'id="detail-1"' in html and "Click a row" not in html
    for name in ("findings.html", "devices.html", "vulns.html", "host.html"):
        assert "row-toggle" in (TEMPLATES / name).read_text(encoding="utf-8")
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "function setRowOpen" in js and "aria-expanded" in js


def test_filter_selects_do_not_submit_on_change():
    for name in ("findings.html", "vulns.html"):
        assert "data-submit-on-change" not in (TEMPLATES / name).read_text(encoding="utf-8")
    assert "f.submit()" not in (STATIC / "app.js").read_text(encoding="utf-8")
    assert "f.submit()" not in (STATIC / "graph.js").read_text(encoding="utf-8")


def test_skip_link_and_main_target():
    html = page(seeded(), "/")
    assert html.index('class="skip-link" href="#main"') < html.index('class="sidebar"')
    assert '<main class="main" id="main" tabindex="-1">' in html


def test_map_focus_wins_in_every_blast_state():
    css = (STATIC / "map.css").read_text(encoding="utf-8")
    assert ".map-node.is-dim:focus { opacity: 1; }" in css
    assert ".map-node.is-affected:not(.is-source):focus .map-focus-ring" in css
    assert ".map-node:focus .map-focus-outer" in css


def test_feed_rows_state_urgency_in_words():
    tpl = (TEMPLATES / "feed.html").read_text(encoding="utf-8")
    assert 'class="tl-sev sev-word' in tpl
    assert "tl-sev sev-word sev-word-" in (STATIC / "app.js").read_text(encoding="utf-8")


def test_status_pills_use_status_tokens_not_severity():
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    rule = [line for line in css.splitlines() if line.startswith(".badge-open ")][0]
    assert "--status-open" in rule and "--sev-high" not in rule


# --------------------------------------------------------------------------- wording


def test_feed_chip_is_singular_for_one():
    chips = {c["kind"]: c for c in feedmod.feed_chips({"system": 1, "scan": 3})}
    assert chips["system"]["plain_label"] == "Home SOC message"
    assert chips["scan"]["plain_label"] == "Checks run"


def test_pairing_steps_keep_prose_out_of_monospace():
    parts = code_parts("Run scripts/enable-lens.ps1 as administrator to open the port.")
    assert parts == [("Run ", False), ("scripts/enable-lens.ps1", True),
                     (" as administrator to open the port.", False)]
    assert code_parts("python -m homesoc lens cert --regenerate") == [("python -m homesoc lens cert --regenerate", True)]
