"""Lens phone-app package tests (SPEC addendum B4/B8/B9/B11 — the L3 slice).

Everything here is offline and deterministic. The Lens transport (``homesoc.web.qr``,
``homesoc.web.lens_auth``) and identification (``homesoc.web.lens``) modules are owned by other
packages and may not be installed while this runs, so each is stubbed through ``sys.modules``
where its behaviour matters — and every page is also asserted to render *without* them, because
that is what a half-installed build looks like.
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from homesoc.web import app as appmod
from homesoc.web import create_app

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "homesoc" / "web" / "templates"
STATIC = ROOT / "homesoc" / "web" / "static"

PHONE_PAGES = ["/lens", "/lens/claim"]
DESK_PAGES = ["/lens/pair", "/lens/stickers"]
LENS_PAGES = PHONE_PAGES + DESK_PAGES
XSS_NICKNAME = '<img src=x onerror=alert(1)>'


def _now(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")


def make_cfg(**over) -> SimpleNamespace:
    """A config shaped like homesoc.config.Config, including the [lens] section of SPEC B3."""
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test", timezone="local", log_level="INFO"),
        web=SimpleNamespace(host=over.get("host", "192.168.10.5"), port=over.get("port", 8443), token=over.get("token", ""), refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=[]),
        scan=SimpleNamespace(use_nmap=True, nmap_top_ports=100, nmap_timing="T3", version_detection=True, gentle_top_ports=25, per_host_timeout_sec=180, max_parallel_hosts=3, scan_gateway=True),
        dns=SimpleNamespace(enabled=True, listen="0.0.0.0", port=53, upstreams=["192.168.10.1"], doh_upstream="", block_mode="null", cache_max_entries=20000, lists=[], log_queries=True, log_retention_days=14, virustotal_api_key="", virustotal_daily_budget=400, reputation_min_malicious_votes=2, reputation_ttl_hours=72),
        notify=SimpleNamespace(min_severity="high", ntfy_url="", discord_webhook="", webhook_url="", windows_toast=True, digest_hour=8),
        schedule=SimpleNamespace(discovery_minutes=10, services_hours=24, host_hours=6, exposure_hours=12, feeds_hours=6),
        lens=SimpleNamespace(
            enabled=over.get("enabled", True),
            require_https=over.get("require_https", True),
            tag_learning=over.get("tag_learning", True),
            allow_actions=over.get("allow_actions", False),
            token_ttl_days=over.get("token_ttl_days", 90),
            max_tokens=over.get("max_tokens", 10),
        ),
    )


def fresh_conn() -> sqlite3.Connection:
    from homesoc import db as core_db

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    core_db.init_schema(conn)
    return conn


def seed(conn: sqlite3.Connection) -> None:
    """Two devices, one of them nicknamed with an XSS payload (SPEC B11's required case)."""
    now = _now()
    conn.execute(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online) "
        "VALUES(1,'00:11:22:00:00:01','192.168.10.1','gateway.example','Example Networks','router',?,0,?,?,1)",
        (XSS_NICKNAME, now, now),
    )
    conn.execute(
        "INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online) "
        "VALUES(2,'00:11:22:00:00:02','192.168.10.42','printer.example','Example Print','printer','Hall printer',1,?,?,0)",
        (now, now),
    )
    conn.execute(
        "INSERT INTO services(device_id, port, proto, state, name, first_seen, last_seen) VALUES(1,23,'tcp','open','telnet',?,?)",
        (now, now),
    )
    conn.execute(
        "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen, device_id) "
        "VALUES('NET-SVC-001','device:00:11:22:00:00:01:23','NET-SVC-001|telnet','critical','Telnet exposed','open','services',?,?,1)",
        (now, now),
    )
    conn.commit()


def stub_module(monkeypatch: pytest.MonkeyPatch, name: str, **attrs) -> types.ModuleType:
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


HTTPS = "https://192.168.10.5:8443"   # base_url for the pages a phone/owner reaches over TLS


def client_for(conn: sqlite3.Connection, **cfg_over):
    app = create_app(make_cfg(**cfg_over), conn)
    app.config["TESTING"] = True
    # The pairing pages are reached over the LAN address, which is exactly what the Host
    # allowlist is there to police; tests talk to the configured bind host.
    app.config["HOMESOC_TRUSTED_HOSTS"] = frozenset({"127.0.0.1", "localhost", "192.168.10.5"})
    return app.test_client()


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = fresh_conn()
    yield c
    c.close()


@pytest.fixture
def client(conn):
    return client_for(conn)


@pytest.fixture
def seeded_client(conn):
    seed(conn)
    return client_for(conn)


# --------------------------------------------------------------------------- rendering


@pytest.mark.parametrize("path", LENS_PAGES)
def test_every_lens_page_renders_on_an_empty_db(client, path):
    r = client.get(path)
    assert r.status_code == 200, path
    assert r.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert r.headers["X-Frame-Options"] == "DENY"


@pytest.mark.parametrize(
    "path",
    LENS_PAGES
    + [
        "/lens/stickers?size=40mm",
        "/lens/stickers?size=avery&which=all&names=0",
        "/lens/stickers?size=bogus&which=bogus",
    ],
)
def test_every_lens_page_renders_with_data(seeded_client, path):
    assert seeded_client.get(path).status_code == 200, path


def test_lens_page_has_the_camera_shell_and_the_always_present_picker(client):
    body = client.get("/lens").data.decode()
    for marker in ('id="cam"', 'id="reticle"', 'id="btn-pick"', 'id="tab-devices"', 'id="picker"', 'id="unknown"'):
        assert marker in body, marker
    assert "manifest.webmanifest" in body and "lens.js" in body and "lens.css" in body
    assert 'name="viewport"' in body and "viewport-fit=cover" in body


def test_lens_page_carries_no_device_data(seeded_client):
    """The phone shell is served before the token is checked, so it must contain no inventory."""
    body = seeded_client.get("/lens").data.decode()
    assert "192.168.10.1" not in body
    assert "Hall printer" not in body
    assert "00:11:22" not in body


def test_sticker_sheet_paginates_by_format(seeded_client):
    avery = seeded_client.get("/lens/stickers?size=avery&which=all").data.decode()
    assert 'class="page"' in avery and "sheet-avery" in avery
    forty = seeded_client.get("/lens/stickers?size=40mm&which=all").data.decode()
    assert "sheet-40mm" in forty


def test_sticker_nickname_toggle(seeded_client):
    with_names = seeded_client.get("/lens/stickers?which=all&names=1").data.decode()
    without = seeded_client.get("/lens/stickers?which=all&names=0").data.decode()
    assert "label-name" in with_names
    assert "label-name" not in without


# --------------------------------------------------------------------------- master switch


@pytest.mark.parametrize("path", LENS_PAGES + ["/lens-sw.js"])
def test_lens_disabled_is_404_everywhere(conn, path):
    c = client_for(conn, enabled=False)
    assert c.get(path).status_code == 404, path


def test_dashboard_still_works_with_lens_disabled(conn):
    c = client_for(conn, enabled=False)
    assert c.get("/").status_code == 200


# --------------------------------------------------------------------------- authentication


def test_phone_shell_is_reachable_without_the_dashboard_token(conn):
    """The phone has a Lens token, not the dashboard one; the shell it loads shows nothing."""
    c = client_for(conn, token="s3cret")
    for path in PHONE_PAGES + ["/lens-sw.js"]:
        assert c.get(path).status_code == 200, path


def test_pair_and_sticker_pages_still_require_the_dashboard_token(conn):
    seed(conn)
    c = client_for(conn, token="s3cret")
    for path in DESK_PAGES:
        assert c.get(path).status_code == 401, path
        assert c.get(path, headers={"X-Token": "s3cret"}).status_code == 200, path


def test_lens_api_paths_are_left_to_the_lens_endpoints(conn):
    """/api/lens/* authenticates on X-Lens-Token, so the dashboard gate must not answer first.

    The refusal must come from the Lens endpoint (which tells a phone how to pair) rather than
    from the dashboard gate (which would just say "unauthorized" and strand it).
    """
    c = client_for(conn, token="s3cret")
    r = c.get("/api/lens/health")
    assert r.status_code in (401, 404, 503)
    body = r.get_json() or {}
    assert body.get("error") != "unauthorized", "the dashboard gate answered a Lens endpoint"
    assert c.get("/api/summary").get_json()["error"] == "unauthorized"  # the rest is untouched


def test_lens_paths_are_not_widened_while_lens_is_disabled(conn):
    c = client_for(conn, token="s3cret", enabled=False)
    assert c.get("/lens").status_code == 401
    assert c.get("/api/lens/health").status_code == 401


def test_pairing_pages_are_never_cached(seeded_client):
    for path in DESK_PAGES:
        assert seeded_client.get(path).headers["Cache-Control"] == "no-store", path


# --------------------------------------------------------------------------- escaping (B11)


def test_device_nickname_with_an_img_payload_is_escaped_everywhere(seeded_client):
    for path in LENS_PAGES + ["/lens/stickers?which=all&names=1", "/lens/stickers?size=40mm&which=all"]:
        body = seeded_client.get(path, base_url=HTTPS).data.decode()
        assert XSS_NICKNAME not in body, path
        assert "<img" not in body, path        # the payload never becomes an element
        assert "onerror=" not in body.replace("onerror=alert(1)&gt;", ""), path
    printed = seeded_client.get("/lens/stickers?which=all&names=1").data.decode()
    assert "&lt;img src=x onerror=alert(1)&gt;" in printed  # shown, as text, on the label


def test_lens_javascript_never_builds_markup_from_data():
    """The card is built from network data; one innerHTML would hand the DOM to the network."""
    for name in ("lens.js", "sw.js"):
        source = (STATIC / name).read_text(encoding="utf-8")
        for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert forbidden not in source, f"{name}: {forbidden}"


def test_lens_templates_have_no_inline_script_style_or_handlers():
    for name in ("lens.html", "lens_pair.html", "lens_claim.html", "lens_stickers.html"):
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        assert not re.search(r"\son[a-z]+\s*=\s*[\"']", text), name
        assert not re.search(r"\sstyle\s*=", text), name
        assert not re.search(r"<script(?![^>]*src=)", text), name
        assert "//cdn" not in text and "https://" not in text.replace("https://www.w3.org/2000/svg", ""), name


# --------------------------------------------------------------------------- pairing screen


def qr_stub(monkeypatch, calls: list) -> None:
    def to_svg(payload, **kw):
        calls.append(payload)
        return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 21 21"><rect width="21" height="21"/></svg>'

    stub_module(monkeypatch, "homesoc.web.qr", to_svg=to_svg)


def tls_stub(monkeypatch, *, fingerprint: str = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99", sans=("192.168.10.5",), days_left: int = 800, missing: bool = False) -> None:
    class _Path:
        def exists(self):
            return not missing

        def __str__(self):
            return "/tmp/cert.pem"

    def cert_paths():
        return (_Path(), _Path())

    def cert_info(_cert):
        return {"subject": "CN=homesoc", "sans": list(sans), "not_before": "2026-01-01", "not_after": "2028-04-06", "fingerprint": fingerprint, "days_left": days_left}

    stub_module(monkeypatch, "homesoc.web.tls", cert_paths=cert_paths, cert_info=cert_info, cert_fingerprint_sha256=lambda _c: fingerprint)


def test_pair_page_renders_the_qr_and_the_fingerprint(conn, monkeypatch):
    calls: list = []
    qr_stub(monkeypatch, calls)
    tls_stub(monkeypatch)
    stub_module(monkeypatch, "homesoc.web.lens_auth", mint_pairing_code=lambda _conn: {"code": "K7QF2M9X", "expires_at": "2026-09-13T10:05:00+00:00"})
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert "<svg" in body
    assert calls and calls[0] == "https://192.168.10.5:8443/lens/claim#c=K7QF2M9X"
    assert "/lens/claim#c=K7QF2M9X" in body
    assert "AA:BB:CC:DD" in body            # fingerprint, grouped for reading aloud
    assert body.count('class="fp-group"') == 8
    assert "Fix" not in body or "check-pill-fail" not in body


def test_a_wildcard_bind_never_reaches_the_qr_code(conn, monkeypatch):
    """Regression, found on the pairing page in Chrome: ``serve --host 0.0.0.0`` — the exact
    invocation SPEC B3 documents — put ``https://0.0.0.0:8443/lens/claim#c=...`` inside the QR.
    A socket listens on 0.0.0.0; no phone can dial it, so the code was a dead link on the one
    screen whose whole job is handing a working link to a phone."""
    from homesoc import db as core_db

    calls: list = []
    qr_stub(monkeypatch, calls)
    tls_stub(monkeypatch)
    core_db.set_setting(conn, appmod.BIND_SETTING, "0.0.0.0:8443")
    monkeypatch.setattr(appmod, "_lan_host", lambda *a, **k: "192.168.10.5")
    stub_module(monkeypatch, "homesoc.web.lens_auth", mint_pairing_code=lambda _conn: {"code": "K7QF2M9X"})
    # Reached over loopback, so the Host header cannot stand in for the LAN address either.
    body = client_for(conn).get("/lens/pair", base_url="https://127.0.0.1:8443").data.decode()
    assert calls, "a code should still be minted: 0.0.0.0 is a healthy, reachable binding"
    for url in calls:
        assert "0.0.0.0" not in url, url
        assert url.startswith("https://192.168.10.5:8443/lens/claim#c="), url
    assert "0.0.0.0/lens/claim" not in body and "//0.0.0.0" not in body


def test_pair_page_explains_a_loopback_binding_instead_of_minting(conn, monkeypatch):
    tls_stub(monkeypatch)
    minted: list = []
    stub_module(monkeypatch, "homesoc.web.lens_auth", mint_pairing_code=lambda _conn: minted.append(1) or {"code": "NOPE"})
    body = client_for(conn, host="127.0.0.1").get("/lens/pair", base_url=HTTPS).data.decode()
    assert "check-pill-fail" in body
    assert "0.0.0.0" in body and "enable-lens.ps1" in body
    assert not minted, "a pairing code must not be minted while the preflight is failing"
    assert "#c=" not in body


def test_pair_page_refuses_to_mint_a_code_over_plain_http(conn, monkeypatch):
    """B10 the other way round: `require_https` governs whether Lens will *serve* a phone that
    is already paired. It has no business governing whether Home SOC will *issue a credential*
    over a cleartext link — the 8-character pairing code and the 90-day token it buys would both
    cross the Wi-Fi where anyone on it can copy them."""
    from homesoc import db as core_db

    tls_stub(monkeypatch)
    minted: list = []
    stub_module(monkeypatch, "homesoc.web.lens_auth",
                mint_pairing_code=lambda _conn: minted.append(1) or {"code": "K7QF2M9X"})
    core_db.set_setting(conn, appmod.BIND_SETTING, "0.0.0.0:8787")
    for require_https in (True, False):
        body = client_for(conn, host="0.0.0.0", require_https=require_https).get(
            "/lens/pair", base_url="http://192.168.10.5:8787").data.decode()
        assert not minted, f"a code was minted over plain HTTP with require_https={require_https}"
        assert "#c=" not in body
        assert "check-pill-fail" in body
        assert "clear text" in body, "the warning must name the real cost, not just the camera"
    # ...and over TLS it mints as usual, with require_https either way.
    for require_https in (True, False):
        minted.clear()
        body = client_for(conn, host="0.0.0.0", require_https=require_https).get(
            "/lens/pair", base_url=HTTPS).data.decode()
        assert minted and "#c=K7QF2M9X" in body


def test_the_plain_http_refusal_page_names_the_token_not_only_the_camera(conn):
    """The refusal a phone actually lands on framed `require_https = false` as costing nothing
    but the camera. It costs the token."""
    body = client_for(conn, host="0.0.0.0").get(
        "/lens", base_url="http://192.168.10.5:8787", environ_base={"REMOTE_ADDR": "192.168.10.42"}
    ).data.decode()
    assert "clear text" in body and "token" in body

    api_body = client_for(conn, host="0.0.0.0").get(
        "/api/lens/health", base_url="http://192.168.10.5:8787",
        environ_base={"REMOTE_ADDR": "192.168.10.42"}).get_json()
    assert api_body["code"] == "https_required" and "clear text" in api_body["error"]


def test_disabling_lens_kills_outstanding_pairing_codes_at_startup(conn):
    """B10 requires it, and config.set_override's hook never runs in the product: no lens.* key
    is in the dashboard's editable allowlist, so the only way to turn Lens off is config.toml
    plus a restart. The restart is therefore where the control has to live."""
    from homesoc import db as core_db

    code = core_db.lens_new_pairing_code(conn)
    assert core_db.lens_normalise_pairing_code(code)
    create_app(make_cfg(enabled=False), conn)
    assert core_db.lens_consume_pairing_code(conn, code) is False

    live = core_db.lens_new_pairing_code(conn)
    create_app(make_cfg(enabled=True), conn)
    assert core_db.lens_consume_pairing_code(conn, live) is True


def test_pair_page_explains_a_missing_certificate(conn, monkeypatch):
    tls_stub(monkeypatch, missing=True)
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert "lens cert --regenerate" in body
    assert "check-pill-fail" in body


def test_pair_page_explains_a_missing_cryptography_package(conn, monkeypatch):
    def cert_info(_cert):
        raise RuntimeError("install cryptography to use Lens over HTTPS")

    class _Path:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/cert.pem"

    stub_module(monkeypatch, "homesoc.web.tls", cert_paths=lambda: (_Path(), _Path()), cert_info=cert_info)
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert "install cryptography" in body
    assert "Tailscale" in body


def test_pair_page_warns_when_the_certificate_does_not_cover_the_lan_address(conn, monkeypatch):
    qr_stub(monkeypatch, [])
    tls_stub(monkeypatch, sans=("192.168.99.9",))
    stub_module(monkeypatch, "homesoc.web.lens_auth", mint_pairing_code=lambda _conn: "ABCD1234")
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert "check-pill-warn" in body
    assert "--hosts 192.168.10.5" in body


def test_pair_page_survives_a_build_with_no_lens_packages(conn):
    """Half-installed is a real state: the page must explain it, not traceback."""
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert "<svg" not in body
    assert "pairing service is not installed" in body or "check-pill-fail" in body


def test_pair_page_counts_paired_phones_when_the_table_exists(conn, monkeypatch):
    tls_stub(monkeypatch)
    conn.execute("CREATE TABLE IF NOT EXISTS lens_tokens(id INTEGER PRIMARY KEY, token_hash TEXT, label TEXT, scopes TEXT, created_at TEXT, revoked_at TEXT)")
    conn.execute("INSERT INTO lens_tokens(token_hash, label, scopes, created_at) VALUES('h','Pixel','read',?)", (_now(),))
    conn.commit()
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert "1 of 10 slots" in body


def test_fingerprint_grouping():
    groups = appmod._fingerprint_groups("aa:bb:cc:dd:ee:ff:00:11")
    assert groups == ["AA:BB:CC:DD", "EE:FF:00:11"]
    assert appmod._fingerprint_groups("aabbccdd") == ["AA:BB:CC:DD"]
    assert appmod._fingerprint_groups(None) == []


def test_qr_markup_that_is_not_svg_is_dropped(conn, monkeypatch):
    """A renderer that returned anything else must never be interpolated into the page."""
    stub_module(monkeypatch, "homesoc.web.qr", to_svg=lambda payload, **kw: "<script>alert(1)</script>")
    tls_stub(monkeypatch)
    stub_module(monkeypatch, "homesoc.web.lens_auth", mint_pairing_code=lambda _conn: "ABCD1234")
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert "<script>alert(1)</script>" not in body


def test_qr_is_rendered_from_a_matrix_encoder_too(conn, monkeypatch):
    """The encoder may be split into encode() + to_svg(matrix); both shapes must work."""
    seen: list = []

    def to_svg(matrix, **kw):
        if not isinstance(matrix, list):
            raise TypeError("to_svg takes a matrix")
        seen.append(matrix)
        return '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>'

    stub_module(monkeypatch, "homesoc.web.qr", to_svg=to_svg, encode=lambda payload: [[1, 0], [0, 1]])
    tls_stub(monkeypatch)
    stub_module(monkeypatch, "homesoc.web.lens_auth", mint_pairing_code=lambda _conn: "ABCD1234")
    body = client_for(conn).get("/lens/pair", base_url=HTTPS).data.decode()
    assert seen and "<svg" in body


# --------------------------------------------------------------------------- stickers (B9)


def test_sticker_minting_is_passed_through_and_is_stable_across_reprints(conn, monkeypatch):
    seed(conn)
    minted = {1: "hs1:AAAAAAAAAAAAAAAAAAAAAA", 2: "hs1:BBBBBBBBBBBBBBBBBBBBBB"}
    asked: list = []

    def mint(_conn, device_ids):
        asked.append(sorted(device_ids))
        return dict(minted)

    stub_module(monkeypatch, "homesoc.web.lens", mint_sticker_codes=mint)
    qr_stub(monkeypatch, [])
    c = client_for(conn)
    first = c.get("/lens/stickers?which=all").data.decode()
    second = c.get("/lens/stickers?which=all").data.decode()
    assert asked == [[1, 2], [1, 2]]
    assert first.count("<svg") == 2 and second.count("<svg") == 2
    assert first == second, "reprinting the same sheet must produce the same labels"


def test_untagged_is_the_default_selection(conn, monkeypatch):
    seed(conn)
    conn.execute("CREATE TABLE IF NOT EXISTS lens_tags(id INTEGER PRIMARY KEY, code TEXT UNIQUE, kind TEXT, device_id INTEGER, created_at TEXT, created_by TEXT)")
    conn.execute("INSERT INTO lens_tags(code, kind, device_id, created_at, created_by) VALUES('hs1:x','sticker',2,?,'test')", (_now(),))
    conn.commit()
    asked: list = []
    stub_module(monkeypatch, "homesoc.web.lens", mint_sticker_codes=lambda _c, ids: asked.append(sorted(ids)) or {i: f"hs1:{i}" for i in ids})
    c = client_for(conn)
    c.get("/lens/stickers")
    assert asked[-1] == [1], "the device that already has a tag must not be reprinted by default"
    c.get("/lens/stickers?which=all")
    assert asked[-1] == [1, 2]


def test_sticker_codes_never_carry_network_identifiers(seeded_client, monkeypatch):
    body = seeded_client.get("/lens/stickers?which=all").data.decode()
    assert "00:11:22:00:00:01" not in body
    assert "192.168.10.1" not in body


def test_print_css_sizes_both_label_formats_in_millimetres():
    css = (STATIC / "lens.css").read_text(encoding="utf-8")
    assert "66.675mm" in css and "25.4mm" in css          # Avery 5160
    assert "repeat(4, 40mm)" in css and "grid-auto-rows: 40mm" in css
    assert re.search(r"@page\s*\{[^}]*margin:\s*0", css)
    assert "page-break-inside: avoid" in css and "break-inside: avoid" in css
    assert "page-break-after: always" in css
    assert ".no-print { display: none !important; }" in css


# --------------------------------------------------------------------------- PWA


def test_manifest_is_valid_and_self_hosted():
    data = json.loads((STATIC / "manifest.webmanifest").read_text(encoding="utf-8"))
    assert data["name"] and data["short_name"]
    assert data["display"] == "standalone"
    assert data["start_url"] == "/lens" and data["scope"] == "/lens"
    assert data["theme_color"].startswith("#") and data["background_color"].startswith("#")
    assert data["icons"], "a PWA needs at least one icon"
    for icon in data["icons"]:
        assert icon["src"].startswith("/static/"), icon
        assert (STATIC / Path(icon["src"]).name).exists(), icon["src"]


def test_service_worker_is_served_from_the_root_so_it_can_own_the_lens_scope(client):
    r = client.get("/lens-sw.js")
    assert r.status_code == 200
    assert "javascript" in r.headers["Content-Type"]
    assert b"homesoc-lens-shell" in r.data
    served = r.data.decode()
    source = (STATIC / "sw.js").read_text(encoding="utf-8")
    # The only difference between the file and what is served is the cache name, which the route
    # stamps from a fingerprint of the shell assets.
    assert "__SHELL_VERSION__" not in served
    assert source.replace("__SHELL_VERSION__", appmod.shell_version(str(STATIC))).strip() == served.strip()


def test_the_shell_cache_name_changes_when_a_shell_asset_changes(tmp_path):
    """A hard-coded cache name meant an upgraded lens.js was served from cache against fresh
    HTML for one whole open. The worker's identity has to move with the assets."""
    import shutil

    folder = tmp_path / "static"
    shutil.copytree(STATIC, folder)
    before = appmod.shell_version(str(folder))
    (folder / "lens.js").write_text("/* changed */\n", encoding="utf-8")
    after = appmod.shell_version(str(folder))
    assert before != after and len(after) == 12


def test_service_worker_caches_the_shell_and_nothing_authenticated():
    source = (STATIC / "sw.js").read_text(encoding="utf-8")
    assert "'/api/'" in source and "return;" in source
    assert "X-Lens-Token" in source
    for cached in ("/lens", "/static/lens.css", "/static/lens.js"):
        assert f"'{cached}'" in source
    assert "/lens/pair" not in source.split("var SHELL")[1].split("]")[0]
    assert "request.method !== 'GET'" in source


def test_the_lens_client_registers_the_worker_at_the_root_path():
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert "navigator.serviceWorker.register('/lens-sw.js', { scope: '/lens' })" in source


# --------------------------------------------------------------------------- client contract


def test_the_token_travels_in_a_header_and_never_in_a_url():
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert "'X-Lens-Token'" in source
    assert "token=" not in source.replace("TOKEN_KEY", "")  # never as a query parameter
    assert "/api/lens/identify" in source and "body: { code: code }" in source
    # identification is a POST, so no decoded code and no device id lands in the access log
    assert "method: options.method || (options.body !== undefined ? 'POST' : 'GET')" in source


def test_the_client_decodes_at_about_five_frames_a_second_from_a_small_canvas():
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert "var DECODE_MS = 200;" in source
    assert "var GRAB_WIDTH = 480;" in source
    assert "requestAnimationFrame" not in source


def test_the_client_handles_every_documented_failure(seeded_client):
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    for case in ("NotAllowedError", "NotFoundError", "BarcodeDetector' in window", "err.status === 401", "navigator.vibrate", "cachedCard"):
        assert case in source, case
    body = seeded_client.get("/lens").data.decode()
    assert "id=\"notice\"" in body


def test_phone_rules_never_leak_onto_the_dashboard_pages():
    """/lens/pair and /lens/stickers load style.css *and* lens.css, and both files use `.card`,
    `.topbar` and `.btn`.

    Regression: an unscoped `.card { position: fixed; bottom: 0 }` from the phone viewfinder
    pinned every panel of the pairing page to the bottom of the window, stacked on top of each
    other. Every rule in the phone half of the file is therefore scoped to ``body.lens``.
    """
    css = (STATIC / "lens.css").read_text(encoding="utf-8")
    phone = css[css.index("phone: the shell") : css.index("desktop: pair page")]
    depth = 0
    for line in phone.splitlines():
        stripped = line.strip()
        opens = "{" in line
        if depth == 0 and opens and not stripped.startswith(("@", "/*", "}")):
            for part in line.split("{")[0].split(","):
                part = part.strip()
                if part and part != "[hidden]":
                    assert part.startswith("body.lens"), f"unscoped phone rule: {part}"
        depth += line.count("{") - line.count("}")


def test_hidden_actually_hides_the_phone_panels():
    """Regression: the sheets are display:flex, which outranks the UA's [hidden] rule, so a
    closed picker stayed over the dock and swallowed every tap."""
    css = (STATIC / "lens.css").read_text(encoding="utf-8")
    assert "[hidden] { display: none !important; }" in css


def test_reachability_is_probed_and_not_guessed_from_navigator_online():
    """Regression, found driving /lens in Chrome: the boot decided it was offline from
    ``navigator.onLine``, which is true whenever the phone has *a* network — so a phone on the
    home Wi-Fi with Home SOC stopped, or a shell opened from the service-worker cache, showed a
    healthy viewfinder that led nowhere. The boot now asks /api/lens/health (B7) instead."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert "request('/api/lens/health')" in source
    assert "if (token()) { bootProbe(); }" in source
    # navigator.onLine may still narrow the answer, but never widen it on its own.
    assert "return reachable && navigator.onLine;" in source


def test_an_unreachable_boot_restores_the_last_card_marked_stale():
    """B8: the worker caches the shell so Lens opens instantly and shows the last-seen device.
    Restoring it only after a failed request left an offline reload with an empty viewfinder."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    offline = source[source.index("function goOffline()") : source.index("function unreachableNotice()")]
    assert "cachedCard()" in offline and "{ stale: true }" in offline
    assert "reachable = false;" in offline
    # Never over the top of whatever the user is already reading.
    assert "!card.hidden || !picker.hidden || !unknown.hidden" in offline
    assert "Offline — this is the last card Lens saw" in source


def test_a_late_camera_start_cannot_clobber_an_offline_notice():
    """Regression: ``startCamera`` cleared whatever notice was up when the hardware finally
    answered, silently wiping the 'Home SOC is not reachable' message the boot probe had just
    put there. Notices are named, and only their own owner retracts them."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert "function hideNoticeIf(why)" in source
    assert "hideNoticeIf('camera')" in source
    # The camera's success path must not reach for the unconditional hide any more.
    started = source[source.index("cam.srcObject = media;") : source.index("startScanner();")]
    assert "hideNotice()" not in started.replace("hideNoticeIf('camera')", "")
    for why in ("'camera'", "'nobarcode'", "'unpaired'", "'offline'"):
        assert why in source, why


def test_the_scan_state_never_claims_to_be_looking_while_unreachable():
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    scan = source[source.index("function scanState()") : source.index("function bootProbe()")]
    assert "online()" in scan and "offline · scanning" in scan
    # Every "back to the viewfinder" path goes through reconcile(), which calls scanState()
    # *and* re-asserts a degraded camera/scanner state the user may have dismissed the notice for.
    assert "function reconcile()" in source
    for caller in ("function closePicker()", "function closeUnknown()", "function dismissCard()"):
        body = source[source.index(caller):]
        assert "reconcile();" in body[: body.index("\n    }") + 8], caller
    # Regression: after a revoke, the camera finishing its start-up put "looking for a code…"
    # in the chip directly above a notice reading "this phone is no longer paired".
    assert "if (!notice.hidden) { return; }" in scan


def test_a_degraded_viewfinder_keeps_a_permanent_explanation(client):
    """B8: never leave the user staring at a camera that silently does nothing. The #notice is
    dismissible — and its own button sends the user to the picker — so it cannot be the only
    thing carrying the explanation."""
    markup = client.get("/lens").data.decode()
    assert 'id="fallback"' in markup and 'id="fallback-body"' in markup
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert source.count("setDegraded(") >= 6
    assert "function reconcile()" in source
    # The video is opaque black and covers the whole viewport, so it has to go too or the
    # no-video gradient the stylesheet defines is never visible.
    no_video = source[source.index("function noVideo("):]
    assert "show(cam, !on)" in no_video[: no_video.index("\n    }")]


def test_a_server_error_is_reported_as_a_server_error(client):
    """Everything except 401/403/404 fell through to "Home SOC is not reachable", which sent the
    user to check their Wi-Fi while Home SOC was running and saying what was wrong."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    handler = source[source.index("function onError("):source.index("function cachedCard(")]
    status_branch = handler.index("if (err && err.status) {")
    assert status_branch < handler.index("reachable = false")
    assert "'It replied HTTP '" in handler and "servererror" in handler


def test_full_screen_sheets_are_modal(client):
    markup = client.get("/lens").data.decode()
    for panel in ('id="picker"', 'id="unknown"'):
        block = markup[markup.index(panel):]
        head = block[: block.index(">")]
        assert 'role="dialog"' in head and 'aria-modal="true"' in head and 'tabindex="-1"' in head
    css = (STATIC / "lens.css").read_text(encoding="utf-8")
    assert "body.lens.pane-open .dock" in css and "body.lens.sheet-open .dock" in css


def test_every_touch_target_meets_the_44px_floor():
    css = (STATIC / "lens.css").read_text(encoding="utf-8")
    handle = css[css.index("body.lens .card-handle {"):]
    assert "min-height: 48px" in handle[: handle.index("}")]
    small = css[css.index("body.lens .btn-small {"):]
    assert "min-height: 44px" in small[: small.index("}")]
    assert "min-height: 36px" not in css


def test_ignoring_a_code_is_confirmed_and_reversible():
    """It is permanent, it is the only full-width control on the sheet, and it sits right under
    the device list. One stray tap used to kill a printed sticker on that phone for good."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert "function unignore(" in source and "function offerUndo(" in source
    assert "dataset.armed" in source
    assert "/api/lens/tag/" in source, "the undo must also clear the server-side 'ignored' tag"


def test_closing_the_unknown_sheet_sticks():
    """closeUnknown left lastCode alone, so the repeat guard expired 3.5 s later and the same
    code re-opened the sheet — for ever, on a phone still pointed at the same label."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    close = source[source.index("function closeUnknown()"):]
    assert "snoozed[pendingCode]" in close[: close.index("\n    }")]
    on_code = source[source.index("function onCode("):]
    assert "snoozed[code]" in on_code[: on_code.index("function payloadOf(")]


def test_a_finding_with_no_fix_steps_can_still_be_acknowledged():
    """The acknowledge button lived inside the steps-gated <details>, so a finding with an empty
    remediation array was never acknowledgeable from the phone even though the API allows it."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    problems = source[source.index("function problemsSection("):source.index("function exposedSection(")]
    ack_at = problems.index("actions.can_acknowledge")
    steps_block = problems.index("if (steps.length) {")
    assert ack_at > problems.index("sec.appendChild(fix);"), "the button is outside the steps block"
    assert steps_block < ack_at


def test_severity_is_never_colour_alone():
    """B8 accessibility: the chip spells the severity out next to the count."""
    source = (STATIC / "lens.js").read_text(encoding="utf-8")
    assert "el('span', { text: sev })" in source
    css = (STATIC / "lens.css").read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in css


# ---------------------------------------------------------------- the real bind address
# Added during integration: `serve --host/--port` override config.toml for the life of the
# process, so a preflight reading only `web.host` refused to mint a code for the exact
# invocation SPEC B3 documents (`serve --tls --host 0.0.0.0 --port 8443` with the shipped
# config, which is loopback). cli.record_bind_state now records where the server really is.


def test_preflight_believes_the_recorded_bind_over_config(conn, monkeypatch):
    """`serve --host 0.0.0.0` with a loopback config.toml must still be able to pair."""
    tls_stub(monkeypatch)
    qr_stub(monkeypatch, [])
    stub_module(monkeypatch, "homesoc.web.lens_auth",
                mint_pairing_code=lambda _conn: {"code": "K7QF2M9X"})
    from homesoc import cli

    cli.record_bind_state(conn, "0.0.0.0", 8443)
    body = client_for(conn, host="127.0.0.1").get("/lens/pair", base_url=HTTPS).data.decode()
    assert "check-pill-fail" not in body, "the server is reachable; the preflight must not block"
    assert "#c=K7QF2M9X" in body


def test_preflight_believes_the_recorded_bind_when_it_is_loopback(conn, monkeypatch):
    """And the other way round: config says 0.0.0.0 but the server was started on loopback."""
    tls_stub(monkeypatch)
    minted: list = []
    stub_module(monkeypatch, "homesoc.web.lens_auth",
                mint_pairing_code=lambda _conn: minted.append(1) or {"code": "NOPE"})
    from homesoc import cli

    cli.record_bind_state(conn, "127.0.0.1", 8443)
    body = client_for(conn, host="0.0.0.0").get("/lens/pair", base_url=HTTPS).data.decode()
    assert "check-pill-fail" in body
    assert not minted, "no code for an address nothing is listening on"


def test_a_spoofed_host_header_cannot_claim_the_server_is_reachable(conn, monkeypatch):
    """The Host header is attacker-influencable and trusted_hosts accepts this machine's own
    LAN address even on a loopback-only socket, so effective_bind must ignore it."""
    tls_stub(monkeypatch)
    from homesoc.web import app as appmod

    cfg = make_cfg(host="127.0.0.1")
    assert appmod.effective_bind(cfg, conn) == ("127.0.0.1", cfg.web.port)
    body = client_for(conn, host="127.0.0.1").get("/lens/pair", base_url=HTTPS).data.decode()
    assert "check-pill-fail" in body


def test_effective_bind_falls_back_to_config_when_nothing_was_recorded(conn):
    from homesoc.web import app as appmod

    assert appmod.effective_bind(make_cfg(host="0.0.0.0", port=8443), conn) == ("0.0.0.0", 8443)
    assert appmod.effective_bind(make_cfg(host="0.0.0.0", port=8443), None) == ("0.0.0.0", 8443)


# --------------------------------------------------------------- B10: HTTPS is not optional

HTTP_LAN = "http://192.168.10.5:8443"          # the same server, reached without TLS
PHONE_ENV = {"REMOTE_ADDR": "192.168.10.42"}   # a phone on the LAN, not this machine


def test_lens_is_refused_over_plain_http_from_the_lan(seeded_client):
    """SPEC B10: serving Lens over plain HTTP from a non-loopback address is refused.

    Without this the token travels in clear text over the air and the camera never starts
    anyway, so the page would be a dead end that also leaks its own credential.
    """
    for path in PHONE_PAGES + ["/lens-sw.js"]:
        r = seeded_client.get(path, base_url=HTTP_LAN, environ_base=PHONE_ENV)
        assert r.status_code == 403, path
        assert b"needs HTTPS" in r.data and b"--tls" in r.data, path
        # It borrows the app's own stylesheet rather than an inline <style>, which
        # default-src 'self' would drop, leaving an unreadable page at the worst moment.
        assert b'href="/static/lens.css"' in r.data and b"<style" not in r.data, path
        assert b"style=" not in r.data, path
    r = seeded_client.get("/api/lens/health", base_url=HTTP_LAN, environ_base=PHONE_ENV,
                          headers={"X-Lens-Token": "whatever"})
    assert r.status_code == 403
    assert r.get_json()["code"] == "https_required"


def test_plain_http_lens_still_works_from_this_machine(seeded_client):
    """``http://127.0.0.1`` is a secure context as far as getUserMedia is concerned, and the
    traffic never leaves the box, so the refusal would cost the owner their own preview."""
    for path in PHONE_PAGES + ["/lens-sw.js"]:
        assert seeded_client.get(path, base_url="http://127.0.0.1:8443").status_code == 200, path


def test_the_desktop_lens_pages_survive_the_refusal(seeded_client):
    """/lens/pair is where the fix is explained. Refusing to serve it over HTTP would hide
    the instructions behind the very condition they exist to resolve."""
    for path in DESK_PAGES:
        r = seeded_client.get(path, base_url=HTTP_LAN, environ_base=PHONE_ENV)
        assert r.status_code == 200, path
    assert seeded_client.get("/devices", base_url=HTTP_LAN, environ_base=PHONE_ENV).status_code == 200


def test_require_https_false_lifts_the_refusal(conn):
    seed(conn)
    c = client_for(conn, require_https=False)
    assert c.get("/lens", base_url=HTTP_LAN, environ_base=PHONE_ENV).status_code == 200


def test_https_makes_the_question_moot(seeded_client):
    for path in PHONE_PAGES:
        assert seeded_client.get(path, base_url=HTTPS, environ_base=PHONE_ENV).status_code == 200
