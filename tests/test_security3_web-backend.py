"""Regression tests for the final web-layer security pass (round three, 2026-09-22).

Each test encodes one reproduced issue in ``homesoc/web`` and asserts it now fails:

* a login-free dashboard letting any local program (or a rebound page) set web.host=0.0.0.0
  with its own web.token, redirect the house's DNS or add an alert webhook (deferred item 1);
* a web.token shorter than config.MIN_TOKEN_LENGTH accepted by the Settings page;
* app.py keeping its own MIN_TOKEN_LENGTH, and the "overriding config.toml" startup warning
  skipping planted dns.lists / network.exclude overrides (deferred items 3 and 4);
* the Host allowlist trusting ``<pc-name>`` and ``<pc-name>.local`` over plain HTTP, which a LAN
  device can answer for (mDNS rebinding), including the owner lock-out that rides on it;
* a read-only Lens phone choosing the code the sticker sheet prints;
* the map legend and the DNS feed / Home events stating as fact that a named device made a
  DNS query, when only its (forgeable) address was matched.

Everything is offline: in-memory SQLite and Flask test clients.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import test_lens_api as lens_tests
import test_web as web_tests
from homesoc import cli
from homesoc import config as config_mod
from homesoc import db as core_db
from homesoc.web import api as webapi
from homesoc.web import app as appmod
from homesoc.web import create_app
from homesoc.web import feed as feedmod
from homesoc.web import lens as lensmod

FETCH = {"X-Requested-With": "fetch"}
LAN = {"REMOTE_ADDR": "192.168.1.50"}
TOKEN = "round-three-token-0123456789"
PC_NAME = "mypc-test"
PC_IP = "192.168.1.105"


def _now(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(autouse=True)
def _fresh_guess_counters():
    webapi._guesses.clear()
    yield
    webapi._guesses.clear()


@pytest.fixture
def conn():
    c = web_tests.fresh_conn()
    try:
        yield c
    finally:
        c.close()


@pytest.fixture
def pc_identity(monkeypatch):
    """This PC is "mypc-test" at 192.168.1.105; nothing is resolved on the real network."""
    from homesoc import util

    monkeypatch.setattr(util, "local_hostname", lambda: PC_NAME)
    monkeypatch.setattr(util, "default_interface_ip", lambda: PC_IP)

    def no_lookup(*_a, **_k):
        raise OSError("offline test")

    monkeypatch.setattr(appmod.socket, "getaddrinfo", no_lookup)


def _client(conn: sqlite3.Connection, *, host: str = "127.0.0.1", token: str = ""):
    cfg = web_tests.make_cfg(token=token)
    cfg.web.host = host
    app = create_app(cfg, conn)
    app.config["TESTING"] = True
    return app.test_client()


def _setting(conn: sqlite3.Connection, key: str) -> str | None:
    return webapi.get_setting(conn, key)


# --------------------------------------------------------------- 1. settings without a password


def test_a_passwordless_dashboard_refuses_to_open_itself_to_the_network(conn):
    """The PoC: another local program posts web.host=0.0.0.0 plus its own token."""
    c = _client(conn)
    r = c.post("/api/settings", json={"web.host": "0.0.0.0", "web.token": "attacker-planted-token-0123456789"},
               headers=FETCH)
    body = r.get_json()
    assert r.status_code == 403 and body["needs_password"] is True and body["saved"] == []
    assert "no password" in body["error"] and "config.toml" in body["error"]
    assert set(body["errors"]) == {"web.host", "web.token"}
    assert _setting(conn, "web.host") is None and _setting(conn, "web.token") is None


def test_a_passwordless_dashboard_refuses_dns_and_alert_redirection(conn):
    c = _client(conn)
    for payload in ({"dns.upstreams": "203.0.113.66"}, {"dns.doh_upstream": "https://203.0.113.66/dns-query"},
                    {"dns.listen": "192.168.1.105"}, {"notify.webhook_url": "http://203.0.113.66/hook"},
                    {"notify.discord_webhook": "https://discord.com/api/webhooks/1/x"},
                    {"notify.ntfy_url": "https://ntfy.sh/attacker"}):
        r = c.post("/api/settings", json=payload, headers=FETCH)
        assert r.status_code == 403, payload
        assert _setting(conn, next(iter(payload))) is None, payload


def test_a_passwordless_dashboard_still_saves_everyday_settings(conn):
    """The Settings form posts every field: values already in force are not a change."""
    c = _client(conn)
    r = c.post("/api/settings", headers=FETCH, json={
        "web.host": " 127.0.0.1 ", "dns.upstreams": "1.1.1.2, 9.9.9.9", "dns.listen": "0.0.0.0",
        "dns.doh_upstream": "", "scan.use_nmap": False, "schedule.discovery_minutes": 20,
    })
    body = r.get_json()
    assert r.status_code == 200 and body["ok"] is True, body
    assert "scan.use_nmap" in body["saved"] and "schedule.discovery_minutes" in body["saved"]
    assert "dns.upstreams" not in body["saved"] and _setting(conn, "dns.upstreams") is None
    assert _setting(conn, "web.host") == "127.0.0.1"  # loopback is fine, and stripped


def test_a_passwordless_dashboard_cannot_clear_the_bind_or_password_overrides(conn):
    """Clearing falls back to config.toml, which the caller cannot vouch for."""
    webapi.set_setting(conn, "web.host", "127.0.0.1")
    webapi.set_setting(conn, "web.token", "")
    webapi.set_setting(conn, "scan.use_nmap", "false")
    c = _client(conn)
    r = c.post("/api/settings/clear", json={"keys": ["web.host", "web.token", "scan.use_nmap"]}, headers=FETCH)
    body = r.get_json()
    assert r.status_code == 403 and body["cleared"] == ["scan.use_nmap"]
    assert set(body["errors"]) == {"web.host", "web.token"}
    assert c.delete("/api/settings/web.host", headers=FETCH).status_code == 403
    assert _setting(conn, "web.host") == "127.0.0.1"


def test_with_a_password_the_owner_keeps_full_control_but_not_a_short_token(conn):
    c = _client(conn, token=TOKEN)
    c.get(f"/login?token={TOKEN}")
    r = c.post("/api/settings", json={"web.token": "1234"}, headers=FETCH)
    assert r.status_code == 400 and "too short" in r.get_json()["errors"]["web.token"]
    assert _setting(conn, "web.token") is None
    short = "x" * (config_mod.MIN_TOKEN_LENGTH - 1)
    assert c.post("/api/settings", json={"web.token": short}, headers=FETCH).status_code == 400
    good = "y" * config_mod.MIN_TOKEN_LENGTH
    r = c.post("/api/settings", headers=FETCH, json={
        "web.token": good, "web.host": " 0.0.0.0 ", "dns.upstreams": "9.9.9.9",
        "notify.webhook_url": "https://example.org/hook",
    })
    assert r.status_code == 200, r.get_json()
    assert _setting(conn, "web.token") == good and _setting(conn, "web.host") == "0.0.0.0"
    assert _setting(conn, "dns.upstreams") == '["9.9.9.9"]'


def test_the_planted_override_poc_no_longer_reaches_the_bind_policy(conn, tmp_path):
    """End to end: after the refused POST, the next start is the owner's loopback config."""
    toml = tmp_path / "config.toml"
    toml.write_text('[web]\nhost = "127.0.0.1"\ntoken = ""\n', encoding="utf-8")
    c = _client(conn)
    c.post("/api/settings", json={"web.host": "0.0.0.0", "web.token": "Attacker-Chosen-Token-000000",
                                  "dns.upstreams": "203.0.113.66"}, headers=FETCH)
    cfg = cli.enforce_bind_policy(config_mod.load(conn, toml), conn)
    assert cfg is not None and cfg.web.host == "127.0.0.1" and cfg.web.token == ""
    assert "203.0.113.66" not in list(cfg.dns.upstreams)


# --------------------------------------------------------------- 2. one token length, one key list


def test_app_uses_config_min_token_length(monkeypatch, caplog):
    assert not hasattr(appmod, "MIN_TOKEN_LENGTH")
    monkeypatch.setattr(config_mod, "MIN_TOKEN_LENGTH", 24)
    with caplog.at_level(logging.WARNING, logger=appmod.logger.name):
        appmod._warn_weak_token("z" * 20)
    assert any("only 20 characters" in r.getMessage() for r in caplog.records)


def test_shadow_warning_covers_every_tamper_signal_key(conn, monkeypatch):
    assert webapi.TAMPER_SIGNAL_KEYS == cli.TAMPER_SIGNAL_KEYS
    for key in ("dns.lists", "network.exclude", "dns.upstreams", "web.token", "notify.min_severity"):
        assert key in webapi.SHADOW_WARN_KEYS, key
    webapi.set_setting(conn, "dns.lists", "[]")
    webapi.set_setting(conn, "network.exclude", '["192.168.1.0/24"]')
    webapi.set_setting(conn, "dns.upstreams", '["6.6.6.6"]')
    monkeypatch.setattr(webapi, "_config_file_values", lambda: {
        "dns.lists": ["oisd_small"], "network.exclude": [], "dns.upstreams": ["1.1.1.2"]})
    warned = webapi.warn_shadowed_overrides(conn)
    assert set(warned) == {"dns.lists", "network.exclude", "dns.upstreams"}


# --------------------------------------------------------------- 3. Host allowlist


def test_loopback_bind_trusts_only_loopback_names(pc_identity):
    assert appmod.trusted_hosts("127.0.0.1") == frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
    assert appmod.trusted_hosts("127.0.0.1", include_names=True) == appmod.trusted_hosts("127.0.0.1")


def test_plain_http_lan_bind_trusts_addresses_not_the_pc_name(pc_identity):
    plain = appmod.trusted_hosts("0.0.0.0")
    assert PC_IP in plain and "127.0.0.1" in plain
    assert PC_NAME not in plain and f"{PC_NAME}.local" not in plain
    named = appmod.trusted_hosts("0.0.0.0", include_names=True)
    assert PC_NAME in named and f"{PC_NAME}.local" in named


def test_a_rebound_dot_local_page_is_refused_over_http(conn, pc_identity):
    """The PoC: same-origin requests from a page served at <pc>.local over plain HTTP."""
    c = _client(conn)  # login-free, loopback: the case the PoC read and wrote everything on
    rebound = {"Host": f"{PC_NAME}.local:8787", "Sec-Fetch-Site": "same-origin", **FETCH}
    assert c.get("/api/devices", headers=rebound).status_code == 400
    assert c.get("/api/export?full=1", headers=rebound).status_code == 400
    r = c.post("/api/settings", json={"scan.use_nmap": False}, headers=rebound)
    assert r.status_code == 400 and _setting(conn, "scan.use_nmap") is None
    # A loopback bind has no business answering to its LAN address either.
    assert c.get("/api/devices", headers={"Host": f"{PC_IP}:8787"}).status_code == 400
    assert c.get("/api/devices", headers={"Host": "127.0.0.1:8787"}).status_code == 200


def test_on_a_lan_bind_the_name_works_only_over_https(conn, pc_identity):
    c = _client(conn, host="0.0.0.0", token=TOKEN)
    assert c.get("/login", base_url=f"http://{PC_NAME}.local:8787").status_code == 400
    assert c.get("/login", base_url=f"http://{PC_IP}:8787").status_code == 200
    assert c.get("/login", base_url=f"https://{PC_NAME}.local:8443").status_code == 200


def test_a_rebound_page_cannot_lock_the_owner_out(conn, pc_identity):
    c = _client(conn, token=TOKEN)
    rebound = {"Host": f"{PC_NAME}.local:8787", "Origin": f"http://{PC_NAME}.local:8787",
               "Sec-Fetch-Site": "same-origin"}
    for _ in range(12):
        assert c.post("/login", data={"token": "wrong-guess"}, headers=rebound).status_code == 400
    assert webapi.token_guess_retry_after("127.0.0.1") in (0, None)
    owner = _client(conn, token=TOKEN)
    r = owner.get(f"/login?token={TOKEN}")
    assert r.status_code == 302 and "homesoc_token=" in r.headers.get("Set-Cookie", "")


# --------------------------------------------------------------- 4. Lens sticker codes


@pytest.fixture
def lens_conn():
    c = core_db.connect(":memory:")
    lens_tests.seed(c)
    lensmod.reset_claim_limits(c)
    try:
        yield c
    finally:
        c.close()


def test_a_read_only_phone_cannot_choose_a_sticker_code(lens_conn):
    printed = lensmod.mint_sticker_codes(lens_conn, [1])[1]
    phone = lens_tests.phone(lens_tests.paired(lens_conn, scopes="read"), **FETCH)
    client = lens_tests.client_for(lens_conn)
    for code, device in (("hs1:PHONE-CHOSEN-FOR-DEVICE-1", 1), ("hs1:PHONE-CHOSEN-FOR-DEVICE-3", 3),
                         ("HS1:upper-case-still-matches-like", 3), ("  hs1:padded", 3)):
        r = client.post("/api/lens/learn", json={"code": code, "device_id": device}, headers=phone, environ_base=LAN)
        assert r.status_code == 403 and r.get_json()["code"] == "sticker_kind", code
        assert r.get_json()["error"] == "Only the dashboard creates sticker codes."
    assert lensmod.existing_sticker_codes(lens_conn, [1, 3]) == {1: printed}
    # Ordinary barcodes are still learnable (B8), and a known sticker still identifies exactly.
    r = client.post("/api/lens/learn", json={"code": "0123456789012", "device_id": 3}, headers=phone, environ_base=LAN)
    assert r.status_code == 200
    body = client.post("/api/lens/identify", json={"code": printed}, headers=phone, environ_base=LAN).get_json()
    assert body["device_id"] == 1


def test_a_later_sticker_shaped_row_never_replaces_the_printed_code(lens_conn):
    """Rows planted before this fix: the sheet keeps printing the dashboard's own code."""
    printed = lensmod.mint_sticker_codes(lens_conn, [1])[1]
    webapi.write(lens_conn, "INSERT INTO lens_tags(code, kind, device_id, created_at, created_by, scans) "
                            "VALUES('hs1:planted-later', 'learned', 1, ?, 'dashboard', 0)", (_now(),))
    assert lensmod.existing_sticker_codes(lens_conn, [1]) == {1: printed}
    assert lensmod.mint_sticker_codes(lens_conn, [1]) == {1: printed}


def test_the_dashboard_can_still_learn_a_sticker_shaped_code(lens_conn):
    client = lens_tests.client_for(lens_conn)
    r = client.post("/api/lens/learn", json={"code": "hs1:owner-typed", "device_id": 2}, headers=FETCH)
    assert r.status_code == 200, r.get_json()


# --------------------------------------------------------------- 5. address matches, worded as such


def test_the_map_legend_says_the_address_can_be_faked():
    line = webapi._MAP_LEGEND_CONFIDENCE[0]["line"]
    assert "saw this happen" not in line
    assert "this device's address" in line and "fake" in line


def _named_device(conn: sqlite3.Connection) -> None:
    now = _now()
    conn.execute("INSERT INTO devices(id, mac, ip, hostname, nickname, first_seen, last_seen, online) "
                 "VALUES(6,'aa:bb:cc:00:00:06','192.168.1.31','mums-iphone','Mum''s iPhone',?,?,1)", (now, now))
    conn.execute("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) "
                 "VALUES(?,'192.168.1.31','stalkerware-c2.example','A','block','reputation',1)", (_now(1),))
    for i in range(3):
        conn.execute("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) "
                     "VALUES(?,'192.168.1.31','tracker.bad-ads.example','A','block','oisd_small',1)", (_now(2 + i),))
    conn.commit()


def test_dns_feed_rows_say_whose_address_not_who_did_it(conn):
    _named_device(conn)
    items, _ = feedmod.build_feed(conn, since=_now(60), limit=50)
    dns = [i for i in items if i.kind in ("dns_threat", "dns_block")]
    assert dns
    for item in dns:
        assert "Mum's iPhone's address (192.168.1.31)" in item.title, item.title
        assert "requested by" not in item.title
        assert webapi.ADDRESS_MATCH_NOTE in item.detail
        assert item.ref["device_id"] == 6  # the link to the device stays


def test_dns_events_say_whose_address_other_events_keep_the_name(conn):
    _named_device(conn)
    events = webapi.plain_events(conn, [
        {"source": "dnsfilter", "message": "blocked a known-malicious domain for 192.168.1.31"},
        {"source": "dns", "message": "192.168.1.31 sent more DNS queries than the query log keeps (600/min)"},
        {"source": "scanners.ports", "message": "Telnet is open on 192.168.1.31:23"},
    ])
    assert events[0]["plain"] == ("Web blocking stopped a look-up of a known-dangerous website from "
                                  "Mum's iPhone's address (192.168.1.31).")
    assert events[1]["plain"].startswith("Mum's iPhone's address (192.168.1.31) sent")
    assert "Mum's iPhone (192.168.1.31)" in events[2]["plain"]  # a port scan Home SOC ran itself


def test_dns_top_clients_carry_the_address_match_note(conn):
    _named_device(conn)
    rows = webapi.dns_top(conn, "clients")
    mum = next(r for r in rows if r["device_ip"] == "192.168.1.31")
    assert mum["device_label"] == "Mum's iPhone" and mum["matched_by"] == "address"
    assert mum["match_note"] == webapi.ADDRESS_MATCH_NOTE
