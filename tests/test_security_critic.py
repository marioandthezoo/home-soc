"""Regression tests for the completeness-critic findings (2026-09-22).

* A LAN device's text (a UPnP mapping description, a hostname) carrying a typographic quote
  (U+2018..U+201B) closed the single-quoted PowerShell literal in the toast script and ran code
  as the owner. The XML now travels as base64 and the script body is otherwise constant.
* Any website could lock the owner out of signing in by sending cross-site navigations with a
  wrong ``?token=`` (each counted as a failed guess from 127.0.0.1), and a LAN host facing an
  exposed dashboard could trip the all-addresses lockout for loopback too.

Everything is offline: in-memory SQLite, Flask test clients, no PowerShell is executed.
"""

from __future__ import annotations

import base64
import re
import sys

import pytest

import test_web as web_tests
from homesoc.notify import channels
from homesoc.util import device_text
from homesoc.web import api as webapi
from homesoc.web import create_app

TOKEN = "correct-horse-battery-staple-123"
LOCAL = {"REMOTE_ADDR": "127.0.0.1"}
CROSS_SITE_NAV = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
SAME_ORIGIN_FORM = {"Sec-Fetch-Site": "same-origin", "Origin": "http://localhost"}

#: Every character PowerShell accepts as a single- or double-quote delimiter.
PS_QUOTES = "'‘’‚‛\"“”„"


# --------------------------------------------------------------------------- toast script


def _decoded_xml(script: str) -> str:
    m = re.search(r"FromBase64String\('([A-Za-z0-9+/=]*)'\)", script)
    assert m, "toast XML must be passed as a base64 literal"
    return base64.b64decode(m.group(1)).decode("utf-8")


@pytest.mark.parametrize("quote", list(PS_QUOTES))
def test_toast_script_body_is_constant_whatever_the_alert_text(quote):
    payload = f"printer{quote}+(ni $env:TEMP\\pwned -Force)+{quote}; calc; #"
    desc = device_text(payload, 120)
    assert quote in desc  # device_text keeps typographic quotes, so the script must not rely on it
    script = channels.build_toast_script("Home SOC", f"[HIGH] UPnP port mapping ({desc})")
    benign = channels.build_toast_script("Home SOC", "[HIGH] UPnP port mapping (x)")
    # Apart from the base64 blob, the script is byte-for-byte the benign one: no alert text
    # reaches PowerShell's parser.
    strip = re.compile(r"FromBase64String\('[A-Za-z0-9+/=]*'\)")
    assert strip.sub("B64", script) == strip.sub("B64", benign)
    assert "ni $env" not in script and "calc" not in script
    assert script.isascii()
    # The text still arrives intact, XML-escaped, inside the toast.
    xml = _decoded_xml(script)
    assert "ni $env:TEMP\\pwned" in xml and "<toast>" in xml


def test_toast_script_keeps_unicode_names_readable():
    script = channels.build_toast_script("Home SOC", "Marie’s iPhone — café \U0001F4F7")
    assert "Marie’s iPhone — café \U0001F4F7" in _decoded_xml(script)


def test_toast_argv_round_trips():
    argv = channels.build_toast_argv("t", "a’b")
    assert argv[-2] == "-EncodedCommand"
    assert base64.b64decode(argv[-1]).decode("utf-16-le") == channels.build_toast_script("t", "a’b")


# --------------------------------------------------------------------------- sign-in lockout


@pytest.fixture(autouse=True)
def _fresh_guess_counters():
    webapi._guesses.clear()
    yield
    webapi._guesses.clear()


@pytest.fixture()
def client():
    conn = web_tests.fresh_conn()
    app = create_app(web_tests.make_cfg(token=TOKEN), conn)
    app.config["TESTING"] = True
    try:
        yield app.test_client()
    finally:
        conn.close()


def test_cross_site_query_tokens_are_not_counted_as_guesses(client):
    for i in range(webapi.TOKEN_GUESS_LIMIT * 3):
        r = client.get(f"/?token=wrong{i}", headers=CROSS_SITE_NAV, environ_base=LOCAL)
        assert r.status_code == 401
        r = client.get(f"/login?token=wrong{i}", headers=CROSS_SITE_NAV, environ_base=LOCAL)
        assert r.status_code == 200 and "Set-Cookie" not in r.headers
    assert webapi.token_guess_retry_after("127.0.0.1") == 0
    # The owner can still sign in, by form and by script header.
    r = client.post("/login", data={"token": TOKEN}, headers=SAME_ORIGIN_FORM, environ_base=LOCAL)
    assert r.status_code == 302 and "Set-Cookie" in r.headers
    assert client.get("/api/summary", headers={"X-Token": TOKEN}, environ_base=LOCAL).status_code == 200


def test_cross_site_query_token_never_signs_in_even_when_right(client):
    """A site that learned the token must not be able to plant a session through a link."""
    r = client.get(f"/?token={TOKEN}", headers=CROSS_SITE_NAV, environ_base=LOCAL)
    assert r.status_code == 401 and "Set-Cookie" not in r.headers
    r = client.get(f"/login?token={TOKEN}", headers=CROSS_SITE_NAV, environ_base=LOCAL)
    assert r.status_code == 200 and "Set-Cookie" not in r.headers


def test_owner_links_with_query_token_still_work(client):
    # Typed or pasted into the address bar (Sec-Fetch-Site: none), or a client with no fetch metadata.
    r = client.get(f"/login?token={TOKEN}", headers={"Sec-Fetch-Site": "none"}, environ_base=LOCAL)
    assert r.status_code == 302 and "Set-Cookie" in r.headers
    r = client.get(f"/?token={TOKEN}&status=open", environ_base=LOCAL)
    assert r.status_code == 302 and "token" not in r.headers["Location"]


def test_same_origin_wrong_query_tokens_are_still_limited(client):
    lan = {"REMOTE_ADDR": "192.168.1.66"}
    for i in range(webapi.TOKEN_GUESS_LIMIT):
        client.get(f"/login?token=wrong{i}", environ_base=lan)
    assert client.get(f"/login?token={TOKEN}", environ_base=lan).status_code == 429


def test_lan_guess_flood_does_not_lock_out_loopback(client):
    # Spread over many LAN addresses to trip the all-addresses lockout.
    for i in range(webapi.TOKEN_GUESS_GLOBAL_LIMIT):
        client.get("/api/summary", headers={"X-Token": f"g{i}"}, environ_base={"REMOTE_ADDR": f"192.168.1.{i % 90 + 10}"})
    # Every LAN address is now refused, as designed...
    assert client.get("/api/summary", headers={"X-Token": TOKEN}, environ_base={"REMOTE_ADDR": "192.168.1.200"}).status_code == 401
    # ...but the owner at the desk still signs in.
    for addr in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        assert client.get("/api/summary", headers={"X-Token": TOKEN}, environ_base={"REMOTE_ADDR": addr}).status_code == 200
    r = client.post("/login", data={"token": TOKEN}, headers=SAME_ORIGIN_FORM, environ_base=LOCAL)
    assert r.status_code == 302 and "Set-Cookie" in r.headers


def test_loopback_keeps_its_own_per_address_limit(client):
    for i in range(webapi.TOKEN_GUESS_LIMIT):
        client.get("/api/summary", headers={"X-Token": f"g{i}"}, environ_base=LOCAL)
    assert client.get("/api/summary", headers={"X-Token": TOKEN}, environ_base=LOCAL).status_code == 401


@pytest.mark.parametrize("addr,expected", [
    ("127.0.0.1", True), ("127.5.5.5", True), ("::1", True), ("::ffff:127.0.0.1", True),
    ("192.168.1.5", False), ("::ffff:192.168.1.5", False), ("unknown", False), ("", False),
])
def test_guess_source_loopback_detection(addr, expected):
    assert webapi._guess_source_is_loopback(addr) is expected
