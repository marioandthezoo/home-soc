"""Round three, integration: the cross-area pieces the per-area fixes needed from each other.

* the startup warning for a web.host / web.token Settings-page value the owner is not known to
  have set (a token planted before the password rule existed), and ``config set`` / ``config keep``;
* ``config.TAMPER_SIGNAL_KEYS`` shared by the CLI and the web layer;
* NET-DNS-007 raised by the resolver's health check when the query log overflows;
* the DNS page's protection counters and address-match note;
* the host page's "Mark as known" routes (only the command the owner saw is accepted);
* Lens pairing through the one atomic database helper;
* the map legend's "recorded it" wording in graph.js and the device page.

Offline: temporary databases, Flask test clients, no sockets bound.
"""

from __future__ import annotations

import json
import sqlite3
import time
import types
from pathlib import Path

import pytest

import test_web as web_tests
from homesoc import cli, config, db
from homesoc.dnsfilter import querylog as querylog_mod
from homesoc.dnsfilter import server as dns_server
from homesoc.findings import catalog
from homesoc.scanners import persistence
from homesoc.web import api as webapi
from homesoc.web import create_app
from homesoc.web import lens as lensmod

FETCH = {"X-Requested-With": "fetch"}
ROOT = Path(__file__).resolve().parents[1]
PLANTED = "attacker-planted-token-0123456789"


# ------------------------------------------------------------ startup warning for planted values


def test_a_token_planted_before_the_upgrade_is_reported_at_startup(cfg, conn, capsys):
    """Round two's open item: a 16+ character token someone else saved passed silently."""
    db.set_setting(conn, "web.host", "0.0.0.0")
    db.set_setting(conn, "web.token", PLANTED)
    checked = cli.enforce_bind_policy(config.load(conn), conn)
    assert checked is not None and checked.web.token == PLANTED  # still starts: the owner decides
    out = capsys.readouterr().out
    assert "WARNING" in out and "may already have been open" in out
    assert "web.host and web.token" in out
    assert "python -m homesoc config unset web.host web.token" in out and "config keep" in out
    assert PLANTED not in out
    events = db.query(conn, "SELECT message FROM events WHERE message LIKE '%no record of you setting%'")
    assert events


def test_values_the_owner_confirmed_do_not_warn(cfg, conn, capsys):
    db.set_setting(conn, "web.host", "0.0.0.0")
    db.set_setting(conn, "web.token", PLANTED)
    config.confirm_web_overrides(conn)
    assert cli.enforce_bind_policy(config.load(conn), conn) is not None
    assert "may already have been open" not in capsys.readouterr().out
    # A later change of the value (by anyone) is a new, unconfirmed value.
    db.set_setting(conn, "web.token", PLANTED + "-changed")
    assert cli.enforce_bind_policy(config.load(conn), conn) is not None
    assert "may already have been open" in capsys.readouterr().out


def test_a_generated_token_is_confirmed_and_never_warns_later(cfg, conn, capsys):
    exposed = config.with_overrides(cfg, {"web.host": "0.0.0.0"})
    assert cli.enforce_bind_policy(exposed, conn) is not None
    capsys.readouterr()
    assert cli.enforce_bind_policy(config.with_overrides(config.load(conn), {"web.host": "0.0.0.0"}), conn)
    assert "WARNING" not in capsys.readouterr().out


def test_a_loopback_start_never_warns(cfg, conn, capsys):
    db.set_setting(conn, "web.token", PLANTED)
    assert cli.enforce_bind_policy(config.load(conn), conn) is not None
    assert "WARNING" not in capsys.readouterr().out


def test_a_host_given_on_the_command_line_is_not_blamed_on_the_settings_page(cfg, conn, capsys):
    db.set_setting(conn, "web.host", "0.0.0.0")  # unconfirmed, but --host overrides it
    db.set_setting(conn, "web.token", PLANTED)
    config.confirm_web_overrides(conn, ["web.token"])
    assert cli.enforce_bind_policy(config.load(conn), conn, host="0.0.0.0") is not None
    assert "WARNING" not in capsys.readouterr().out


def test_config_set_and_keep(data_dir, conn, capsys):
    assert cli.main(["config", "set", "web.token", "short"]) == cli.EXIT_USAGE
    assert cli.main(["config", "set", "web.token", PLANTED]) == cli.EXIT_OK
    assert "web.token" not in config.unconfirmed_web_overrides(conn)
    db.set_setting(conn, "web.host", "0.0.0.0")
    assert config.unconfirmed_web_overrides(conn) == ["web.host"]
    assert cli.main(["config", "keep"]) == cli.EXIT_OK
    assert config.unconfirmed_web_overrides(conn) == []
    assert cli.main(["config", "set", "no.such_key", "1"]) == cli.EXIT_USAGE
    out = capsys.readouterr().out
    assert PLANTED not in out


def test_the_password_message_names_a_command_that_exists():
    assert "python -m homesoc config set" in webapi.NEEDS_PASSWORD_MESSAGE
    parser = cli.build_parser()
    args = parser.parse_args(["config", "set", "dns.upstreams", '["1.1.1.1"]'])
    assert args.config_command == "set" and args.key == "dns.upstreams"


def test_a_signed_in_settings_save_counts_as_the_owners(conn):
    web_conn = web_tests.fresh_conn()
    try:
        cfg = web_tests.make_cfg(token="owner-token-0123456789abcdef")
        app = create_app(cfg, web_conn)
        app.config["TESTING"] = True
        client = app.test_client()
        r = client.post("/api/settings", json={"web.token": "a-new-owner-token-0123456789"},
                        headers={**FETCH, "X-Token": "owner-token-0123456789abcdef"})
        assert r.status_code == 200, r.get_json()
        assert config.unconfirmed_web_overrides(web_conn) == []
    finally:
        web_conn.close()


def test_one_list_of_tamper_keys():
    assert cli.TAMPER_SIGNAL_KEYS == config.TAMPER_SIGNAL_KEYS
    assert webapi.TAMPER_SIGNAL_KEYS == config.TAMPER_SIGNAL_KEYS
    assert {"dns.lists", "network.exclude"} <= set(webapi.SHADOW_WARN_KEYS)


# ------------------------------------------------------------------------------ NET-DNS-007


def _dns_cfg():
    dns = dict(enabled=True, listen="127.0.0.1", port=0, upstreams=["127.0.0.1:1"], doh_upstream="",
               block_mode="null", cache_max_entries=100, lists=[], log_queries=True, log_retention_days=14,
               virustotal_api_key="", virustotal_daily_budget=0, reputation_min_malicious_votes=2,
               reputation_ttl_hours=72)
    return types.SimpleNamespace(dns=types.SimpleNamespace(**dns))


def test_a_query_log_flood_raises_net_dns_007_and_it_clears_after_a_day(conn, tmp_path):
    srv = dns_server.DnsServer(_dns_cfg(), conn, list_dir=tmp_path)
    now = time.monotonic()
    assert "NET-DNS-007" not in [d.finding_id for d in srv.health_findings(now=now)]
    srv.querylog.overflowed = 5120
    srv.querylog.last_overflow_sample = ["10.9.8.7", "172.16.4.4"]
    drafts = {d.finding_id: d for d in srv.health_findings(now=now + 1)}
    flood = drafts["NET-DNS-007"]
    assert flood.subject == "dns" and flood.evidence["not_logged"] == 5120
    assert flood.evidence["sources_per_minute_limit"] == querylog_mod.LOG_BUDGET_MAX_CLIENTS
    assert flood.evidence["sample_sources"] == ["10.9.8.7", "172.16.4.4"]
    title = catalog.render_plain_title("NET-DNS-007", flood.evidence, "dns")
    assert "faking addresses" in title
    # Still open within the day, gone once a quiet day has passed.
    assert "NET-DNS-007" in [d.finding_id for d in srv.health_findings(now=now + 3600)]
    assert "NET-DNS-007" not in [d.finding_id for d in srv.health_findings(now=now + 1 + 86400)]


def test_the_query_log_keeps_the_overflow_sample_for_the_finding(conn):
    log = querylog_mod.QueryLog(conn, flush_interval=60)
    log._overflow_rows, log._overflow_sample = 3, ["10.0.0.9"]
    log._report_over_budget()
    assert log.last_overflow_sample == ["10.0.0.9"]


# ------------------------------------------------------------------------------ DNS page


class _FakeResolver:
    running = True

    def stats(self):
        return {"log_overflowed": 12, "tcp_evicted": 3, "udp_shed": 4, "rate_limited": 5, "known_clients": 9,
                "upstream_guard": {"inflight_udp": 2}}


def test_the_dns_page_shows_protection_counters_and_the_address_note():
    conn = web_tests.fresh_conn()
    try:
        cfg = web_tests.make_cfg()
        app = create_app(cfg, conn)
        app.config["TESTING"] = True
        app.extensions["homesoc"].dns_server = _FakeResolver()
        counters = webapi.dns_protection_counters(app.extensions["homesoc"])
        assert counters == {"not_logged": 12, "connections_dropped": 3, "lookups_shed": 4, "rate_limited": 5,
                            "known_devices": 9, "waiting_upstream": 2}
        html = app.test_client().get("/dns").get_data(as_text=True)
        assert "Protection counters since it started" in html
        app.extensions["homesoc"].dns_server = None
        assert webapi.dns_protection_counters(app.extensions["homesoc"]) is None
    finally:
        conn.close()


def test_address_match_note_on_named_dns_rows():
    rows = [{"client": "192.168.1.31", "total": 4, "blocked": 1}]
    conn = web_tests.fresh_conn()
    try:
        labelled = webapi.label_clients(conn, rows)
        assert labelled[0]["matched_by"] == "address"
    finally:
        conn.close()


# ------------------------------------------------------------------------------ host page


def _pending_entry(conn: sqlite3.Connection, name: str, command: str, *, changed_from: str | None = None) -> None:
    now = "2026-09-22T10:00:00Z"
    db.write(conn, "INSERT INTO persistence(kind, name, command, location, first_seen, last_seen, baseline) "
                   "VALUES ('run_key', ?, ?, 'HKCU\\Run', ?, ?, 0)", (name, command, now, now))
    if changed_from is not None:
        changes = json.loads(db.get_setting(conn, persistence.CHANGES_SETTING, "{}") or "{}")
        changes[persistence._entry_id("run_key", "HKCU\\Run", name)] = {
            "previous": changed_from, "accepted": True, "changed_at": now}
        db.set_setting(conn, persistence.CHANGES_SETTING, json.dumps(changes))


def test_host_page_constants_match_the_scanner():
    assert webapi.PERSISTENCE_CHANGES_SETTING == persistence.CHANGES_SETTING
    assert webapi._persistence_entry_id("a", "b", "c") == persistence._entry_id("a", "b", "c")


def test_host_page_marks_changed_entries_and_accepts_only_what_was_shown():
    conn = web_tests.fresh_conn()
    try:
        _pending_entry(conn, "OneDrive", "C:/Users/Public/x.exe", changed_from="C:/OneDrive/OneDrive.exe /background")
        _pending_entry(conn, "Updater", "C:/Tools/up.exe")
        data = webapi.host_data(conn)
        assert data["persistence_accept"] is True
        by_name = {p["name"]: p for p in data["persistence"]}
        assert by_name["OneDrive"]["change"] == "modified"
        assert by_name["OneDrive"]["previous_command"] == "C:/OneDrive/OneDrive.exe /background"
        assert "change" not in by_name["Updater"]

        app = create_app(web_tests.make_cfg(), conn)
        app.config["TESTING"] = True
        client = app.test_client()
        html = client.get("/host").get_data(as_text=True)
        assert "Changed" in html and "Mark all as known" in html

        # No CSRF header: refused like every other write.
        r = client.post("/api/host/persistence/accept", json={"kind": "run_key", "location": "HKCU\\Run",
                                                               "name": "Updater", "command": "C:/Tools/up.exe"})
        assert r.status_code in (400, 403)
        # A command other than the one stored (swapped after the page loaded): not accepted.
        r = client.post("/api/host/persistence/accept", headers=FETCH,
                        json={"kind": "run_key", "location": "HKCU\\Run", "name": "OneDrive",
                              "command": "C:/OneDrive/OneDrive.exe /background"})
        assert r.status_code == 200 and r.get_json()["accepted"] is False
        r = client.post("/api/host/persistence/accept", headers=FETCH,
                        json={"kind": "run_key", "location": "HKCU\\Run", "name": "OneDrive",
                              "command": "C:/Users/Public/x.exe"})
        assert r.get_json()["accepted"] is True
        r = client.post("/api/host/persistence/accept-all", headers=FETCH,
                        json={"entries": [{"kind": "run_key", "location": "HKCU\\Run", "name": "Updater",
                                           "command": "C:/Tools/up.exe"},
                                          {"kind": "run_key", "location": "HKCU\\Run", "name": "Missing",
                                           "command": "x"}]})
        assert r.get_json() == {"ok": True, "accepted": 1, "skipped": 1}
        assert not db.query(conn, "SELECT 1 FROM persistence WHERE baseline=0")
        r = client.post("/api/host/persistence/accept-all", headers=FETCH, json={"entries": "all"})
        assert r.status_code == 400
    finally:
        conn.close()


def test_a_group_of_autostart_findings_with_a_changed_one_is_not_called_new():
    conn = web_tests.fresh_conn()
    try:
        now = "2026-09-22T10:00:00Z"
        for i, ev in enumerate(({"name": "A", "change": "modified"}, {"name": "B"})):
            db.write(conn, "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, evidence, status, "
                           "source, first_seen, last_seen) VALUES ('WIN-PER-001','host',?, 'medium', ?, ?, 'open', "
                           "'host', ?, ?)", (f"k{i}", f"t{i}", json.dumps(ev), now, now))
        facts = webapi._open_finding_facts(conn)
        assert "changed" in facts["WIN-PER-001"]["title"].lower()
    finally:
        conn.close()


# ------------------------------------------------------------------------------ Lens pairing


def test_lens_claim_goes_through_the_atomic_helper(conn, monkeypatch):
    calls = []
    real = db.lens_pair_with_code

    def spy(*a, **k):
        calls.append(k)
        return real(*a, **k)

    monkeypatch.setattr(db, "lens_pair_with_code", spy)
    code = lensmod.mint_pairing_code(conn)
    first = lensmod.claim(conn, code, label="phone")
    again = lensmod.claim(conn, code, label="phone 2")
    assert first["ok"] is True and first["token"] and len(calls) == 2
    assert again["ok"] is False and again["error"] == lensmod.BAD_CODE_MESSAGE


def test_lens_claim_at_the_ceiling_keeps_the_code(conn):
    db.lens_mint_token(conn, label="one")
    code = lensmod.mint_pairing_code(conn)
    refused = lensmod.claim(conn, code, max_tokens=1)
    assert refused["ok"] is False and "already paired" in refused["error"]
    assert lensmod.claim(conn, code, max_tokens=2)["ok"] is True


# ------------------------------------------------------------------------------ wording


def test_the_map_wording_says_recorded_from_the_address():
    js = (ROOT / "homesoc/web/static/graph.js").read_text(encoding="utf-8")
    assert "saw it happen" not in js and "recorded it (from this device's address)" in js
    page = (ROOT / "homesoc/web/templates/device_detail.html").read_text(encoding="utf-8")
    assert "saw this happen" not in page and "another device can fake" in page
    line = webapi._MAP_LEGEND_CONFIDENCE[0]["line"]
    assert "recorded" in line and "fake" in line


def test_the_net_dns_004_detail_names_an_address_not_a_device():
    from homesoc.dnsfilter import reputation

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    emitter = reputation.MaliciousFindingEmitter(conn)
    result = types.SimpleNamespace(domain="evil.example", verdict="malicious", malicious=5, suspicious=0,
                                   source="urlhaus", checked_at="2026-09-22T10:00:00Z")
    import homesoc.dnsfilter.reputation as rep

    captured = []
    orig = rep.apply_findings
    rep.apply_findings = lambda _c, drafts, _s: captured.extend(drafts)
    try:
        emitter.emit("192.168.1.50", "x.evil.example", result)
    finally:
        rep.apply_findings = orig
    assert captured and captured[0].detail.startswith("A lookup from 192.168.1.50 asked for")
    assert "can be faked" in captured[0].detail


def test_a_passwordless_dashboard_cannot_switch_dns_off_or_hide_the_network():
    """Another program or account on this PC, with no password to stop it, could otherwise turn
    off the house's resolver or its blocklists, or stop the scans seeing the network."""
    conn = web_tests.fresh_conn()
    try:
        app = create_app(web_tests.make_cfg(), conn)
        app.config["TESTING"] = True
        client = app.test_client()
        for payload in ({"dns.enabled": False}, {"dns.port": 5353}, {"dns.lists": []},
                        {"network.exclude": ["192.168.1.0/24"]}, {"notify.min_severity": "critical"}):
            r = client.post("/api/settings", json=payload, headers=FETCH)
            assert r.status_code == 403, payload
            assert webapi.get_setting(conn, next(iter(payload))) is None, payload
        # Unchanged values posted by the Settings form are still fine.
        current = {k: webapi.cfg_get(app.extensions["homesoc"].cfg, k) for k in ("dns.enabled", "dns.port")}
        r = client.post("/api/settings", json={**current, "scan.use_nmap": False}, headers=FETCH)
        assert r.status_code == 200 and r.get_json()["saved"] == ["scan.use_nmap"]
    finally:
        conn.close()
