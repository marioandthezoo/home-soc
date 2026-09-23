"""Security integration tests: the cross-area fixes applied after the per-area fixers.

* dns.lists names are refused at the Settings API and dropped at config load.
* Device-supplied text is cleaned where it enters the inventory (UPnP mapping, banners, hostnames).
* MAC churn cannot flood the device table (NET-DEV-004).
* Toast XML survives XML-invalid characters; log messages cannot forge a second line.
* VirusTotal / URLhaus never follow redirects and read bounded bodies.
* The scheduler watchdog reports a job that overruns its budget.
* `homesoc config unset` clears an override and, for web.token, signs browsers out.
* A revoked Lens token gets Clear-Site-Data; the login form posts.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
import xml.dom.minidom

import pytest

import test_lens_api as lens_tests
import test_network as net_tests
import test_web as web_tests
from homesoc import cli, config, db, scheduler
from homesoc.dnsfilter import reputation
from homesoc.notify import channels
from homesoc.scanners import discovery, exposure, ports
from homesoc.web import api as webapi
from homesoc.web import create_app

FETCH = {"X-Requested-With": "fetch"}


def _client(conn, **web):
    app = create_app(web_tests.make_cfg(**web), conn)
    app.config["TESTING"] = True
    return app.test_client()


# --------------------------------------------------------------------------- dns.lists


@pytest.mark.parametrize("bad", ["../../private/notes", "//attacker/share/x", "C:/Users/me/hosts", "oisd_small, ../x"])
def test_settings_refuse_list_names_that_are_not_feeds(bad):
    conn = web_tests.fresh_conn()
    try:
        r = _client(conn).post("/api/settings", json={"dns.lists": bad}, headers=FETCH)
        assert r.status_code in (200, 400)
        body = r.get_json()
        assert "dns.lists" in body["errors"] and "dns.lists" not in body["saved"]
        assert db.get_setting(conn, "dns.lists") is None
    finally:
        conn.close()


def test_settings_accept_real_feed_names():
    conn = web_tests.fresh_conn()
    try:
        body = _client(conn).post("/api/settings", json={"dns.lists": "oisd_small"}, headers=FETCH).get_json()
        assert body["saved"] == ["dns.lists"]
    finally:
        conn.close()


def test_config_load_drops_path_like_list_names(caplog):
    with caplog.at_level(logging.WARNING, logger="homesoc.config"):
        assert config.coerce("dns.lists", "oisd_small, ../../x, //host/share/y, C:/z") == ("oisd_small",)
    assert "not blocklist feeds" in caplog.text


# --------------------------------------------------------------------------- ingestion


def test_upnp_mapping_fields_are_validated_at_ingestion():
    desc = "x)\n[CRITICAL] Router firmware backdoored - install the fix: [homesoc.dev/fix](https://203.0.113.9/fix.exe)\n("
    xml_text = net_tests.MAPPING_XML.format(ext=8554, int_=554, desc=desc).replace(
        "<NewInternalClient>192.168.1.50</NewInternalClient>",
        "<NewInternalClient>192.168.1.66\n[CRITICAL] fake</NewInternalClient>")
    m = exposure.parse_mapping_response(xml_text)
    assert "\n" not in m["description"] and "\r" not in m["description"]
    assert len(m["description"]) <= 120
    assert m["internal_client"] == ""                      # not an IPv4 address: dropped
    good = exposure.parse_mapping_response(net_tests.MAPPING_XML.format(ext=22, int_=22, desc="ssh"))
    assert good["internal_client"] == "192.168.1.50" and good["description"] == "ssh" and good["protocol"] == "TCP"


def test_banner_fields_are_one_printable_line():
    banner = "220 \x1b[2J\x1b[H\x1b]0;Home SOC\x07\x1b]8;;https://evil.example\x07hikvision CAM-1234\x1b]8;;\x07 ready\r\n"
    info = ports.parse_banner(21, banner)
    for key in ("product", "version", "extrainfo"):
        value = info.get(key) or ""
        assert "\x1b" not in value and "\x07" not in value and "\n" not in value, key
    http = ports.parse_banner(80, "HTTP/1.0 200 OK\r\nServer: lighttpd/1.4.59\u202e\r\n\r\n")
    assert http["product"] == "lighttpd" and "\u202e" not in (http.get("extrainfo") or "")


def test_hostnames_are_cleaned_before_they_are_stored(conn, monkeypatch):
    net_tests._patch_discovery_env(monkeypatch, net_tests.NEIGHBORS, vendors=net_tests.VENDORS,
                                   names={"192.168.1.254": "gw\u202egnp.exe\x0b"})
    discovery.run(net_tests.make_cfg(), conn)
    host = db.one(conn, "SELECT hostname FROM devices WHERE mac='00:11:22:00:00:01'")["hostname"]
    assert host and "\u202e" not in host and "\x0b" not in host


# --------------------------------------------------------------------------- MAC churn


def _churn_neighbors(n: int, salt: str) -> dict:
    out = {}
    for i in range(n):
        ip = f"192.168.1.{10 + i}"
        out[ip] = discovery.Neighbor(ip, f"02:{salt}:00:00:{i // 256:02x}:{i % 256:02x}", "Reachable")
    return out


def test_mac_churn_is_capped_and_reported_once(conn, monkeypatch):
    net_tests._patch_discovery_env(monkeypatch, net_tests.NEIGHBORS, vendors=net_tests.VENDORS)
    discovery.run(net_tests.make_cfg(), conn)                     # baseline: never capped
    before = db.one(conn, "SELECT COUNT(*) AS n FROM devices")["n"]
    for sweep in range(3):
        monkeypatch.setattr(discovery, "read_neighbors", lambda net, s=sweep: _churn_neighbors(200, f"{s:02x}"))
        res = discovery.run(net_tests.make_cfg(), conn)
        churn = [f for f in res.findings if f.finding_id == "NET-DEV-004"]
        assert len(churn) == 1 and churn[0].evidence["skipped"] > 0
        assert res.summary["hosts_new"] <= discovery.MAX_NEW_DEVICES_PER_SWEEP
    after = db.one(conn, "SELECT COUNT(*) AS n FROM devices")["n"]
    assert after - before <= 3 * discovery.MAX_NEW_DEVICES_PER_SWEEP


def test_churn_finding_renders(conn):
    from homesoc.findings import catalog
    from homesoc.models import FindingDraft

    draft = FindingDraft(finding_id="NET-DEV-004", subject="network:192.168.1.0/24",
                         evidence={"count": 200, "added": 32, "skipped": 168, "sample": ["192.168.1.10 02:00"]})
    title, _detail = catalog.render(draft)
    assert title == "200 new devices appeared in one network scan"
    steps = catalog.render_remediation("NET-DEV-004", draft.evidence, draft.subject)
    assert any("192.168.1.10 02:00" in s for s in steps)


def test_normal_new_devices_are_not_capped(conn, monkeypatch):
    net_tests._patch_discovery_env(monkeypatch, net_tests.NEIGHBORS, vendors=net_tests.VENDORS)
    discovery.run(net_tests.make_cfg(), conn)
    monkeypatch.setattr(discovery, "read_neighbors", lambda net: {**net_tests.NEIGHBORS, **_churn_neighbors(3, "aa")})
    res = discovery.run(net_tests.make_cfg(), conn)
    assert res.summary["hosts_new"] == 3 and not [f for f in res.findings if f.finding_id == "NET-DEV-004"]


# --------------------------------------------------------------------------- output channels


def test_toast_xml_stays_well_formed_with_invalid_characters():
    xml_text = channels.build_toast_xml("New device: cam\x0b\x00", "[HIGH] New device cam\x0b\x1f <x> & 'q'")
    xml.dom.minidom.parseString(xml_text)


def test_log_messages_cannot_forge_a_second_line():
    fmt = cli._TerminalSafeFormatter("%(levelname)s %(message)s")
    record = logging.LogRecord("x", logging.WARNING, __file__, 1, "location: %s",
                               ("http://8.8.8.8/\r2026-09-22 INFO defender: no threats\nnext\u2028line\x1b[2K",), None)
    out = fmt.format(record)
    assert "\n" not in out and "\r" not in out and "\u2028" not in out and "\x1b" not in out
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed", (), sys.exc_info())
    assert fmt.format(record).count("\n") >= 2                  # tracebacks keep their lines


# --------------------------------------------------------------------------- reputation APIs


class _RecordingSession:
    def __init__(self, response):
        self.response = response
        self.kwargs: list[dict] = []

    def get(self, url, **kwargs):
        self.kwargs.append(kwargs)
        return self.response

    def post(self, url, **kwargs):
        self.kwargs.append(kwargs)
        return self.response


class _StreamedResponse:
    def __init__(self, status: int, chunks: list[bytes], headers: dict | None = None):
        self.status_code = status
        self._chunks = chunks
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, chunk_size=65536):
        yield from self._chunks

    def close(self):
        self.closed = True


def test_reputation_calls_do_not_follow_redirects_and_close_the_response():
    resp = _StreamedResponse(302, [], {"Location": "http://evil.example/steal"})
    s = _RecordingSession(resp)
    assert reputation.vt_lookup("example.com", "VT-SECRET", session=s) is None
    assert reputation.urlhaus_lookup("example.com", auth_key="UH-SECRET", session=s) is None
    assert all(k.get("allow_redirects") is False and k.get("stream") is True for k in s.kwargs)
    assert resp.closed


def test_reputation_bodies_are_size_capped():
    big = [b" " * 65536] * (reputation.MAX_API_RESPONSE_BYTES // 65536 + 2)
    assert reputation.vt_lookup("example.com", "k", session=_RecordingSession(_StreamedResponse(200, big))) is None
    assert reputation.urlhaus_lookup("example.com", session=_RecordingSession(_StreamedResponse(200, big))) is None
    ok = _StreamedResponse(200, [b'{"data":{"attributes":{"last_analysis_stats":{"malicious":3}}}}'])
    assert reputation.vt_lookup("example.com", "k", session=_RecordingSession(ok))["malicious"] == 3


# --------------------------------------------------------------------------- scheduler watchdog


def test_watchdog_reports_an_overrunning_job_once(conn):
    release = threading.Event()
    job = scheduler.Job("slow", 0, lambda: release.wait(5), run_at_start=False, budget_sec=0)
    sched = scheduler.Scheduler(None, conn, [job])
    worker = threading.Thread(target=sched.run_now, args=("slow",), daemon=True)
    worker.start()
    try:
        deadline = time.time() + 2
        while not sched.is_running("slow") and time.time() < deadline:
            time.sleep(0.01)
        time.sleep(0.05)
        assert sched.check_overruns() == ["slow"]
        assert sched.check_overruns() == []                       # once per run
        status = {j["name"]: j for j in sched.status()}["slow"]
        assert status["overrunning"] and status["running_for_sec"] is not None
        assert db.one(conn, "SELECT COUNT(*) AS n FROM events WHERE message LIKE 'job slow has been running%'")["n"] == 1
    finally:
        release.set()
        worker.join(5)
    assert {j["name"]: j for j in sched.status()}["slow"]["overrunning"] is False


# --------------------------------------------------------------------------- CLI: config unset


def test_config_unset_clears_an_override_and_signs_browsers_out(data_dir, capsys):
    conn = db.connect()
    try:
        config.set_override(conn, "web.token", "a-token-that-leaked-0123456789")
        config.set_override(conn, "notify.discord_webhook", "https://discord.com/api/webhooks/1/LEAKED")
        sid = webapi.session_create(conn)
        assert webapi.session_check(conn, sid) is not None
    finally:
        conn.close()
    assert cli.main(["config", "overrides"]) == 0
    listed = capsys.readouterr().out
    assert "web.token" in listed and "LEAKED" not in listed and "a-token-that-leaked" not in listed
    assert cli.main(["config", "unset", "web.token", "notify.discord_webhook"]) == 0
    out = capsys.readouterr().out
    assert "signed out 1 browser session" in out
    conn = db.connect()
    try:
        assert config.overrides(conn) == {}
        assert webapi.session_check(conn, sid) is None
    finally:
        conn.close()


# --------------------------------------------------------------------------- web odds and ends


def test_revoked_lens_token_gets_clear_site_data():
    conn = db.connect(":memory:")
    try:
        lens_tests.seed(conn)
        c = lens_tests.client_for(conn)
        r = c.get("/api/lens/health", headers={"X-Lens-Token": "not-a-real-token"}, environ_base=lens_tests.LAN)
        assert r.status_code == 401
        assert r.headers.get("Clear-Site-Data") == '"storage"'
    finally:
        conn.close()


def test_login_form_posts_the_token_in_the_body():
    conn = web_tests.fresh_conn()
    try:
        c = _client(conn, token="a-long-enough-dashboard-token")
        page = c.get("/login").data.decode()
        assert 'method="post" action="/login"' in page
        r = c.post("/login", data={"token": "a-long-enough-dashboard-token"})
        assert r.status_code == 302 and "token=" not in r.headers["Location"]
    finally:
        conn.close()


def test_a_large_baseline_does_not_use_up_the_daily_allowance(conn, monkeypatch):
    big = {**net_tests.NEIGHBORS, **_churn_neighbors(240, "bb")}
    net_tests._patch_discovery_env(monkeypatch, big, vendors=net_tests.VENDORS)
    monkeypatch.setattr(discovery, "resolve_network", lambda cfg: __import__("ipaddress").ip_network("192.168.0.0/22"))
    discovery.run(net_tests.make_cfg(), conn)                     # 243 devices on day one
    extra = {f"192.168.2.{i}": discovery.Neighbor(f"192.168.2.{i}", f"02:cc:00:00:00:{i:02x}", "Reachable") for i in range(1, 4)}
    monkeypatch.setattr(discovery, "read_neighbors", lambda net: {**big, **extra})
    res = discovery.run(net_tests.make_cfg(), conn)
    assert res.summary["hosts_new"] == 3 and not [f for f in res.findings if f.finding_id == "NET-DEV-004"]
