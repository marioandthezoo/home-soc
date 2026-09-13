"""Lens identification engine and API (SPEC addendum B, sections B5–B7 and B10).

Everything here is offline and deterministic. The token, pairing-code and rate-limit helpers
belong to the transport package (L1), which ships them as ``db.lens_*`` on ``homesoc.db``.
``homesoc.web.lens`` delegates to whichever of those it can find and otherwise implements B4
itself against the ``lens_tokens`` table, so these tests pass either way; the "L1 seam" group at
the end of this file pins the delegation so a rename on either side fails loudly here rather
than quietly splitting pairing into two stores that never agree.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from flask.testing import FlaskClient

from homesoc import db as core_db
from homesoc.web import api as webapi
from homesoc.web import create_app
from homesoc.web import lens as lensmod

FETCH = {"X-Requested-With": "fetch"}
#: A phone, not the desktop. It reaches Lens over TLS (see :class:`TlsClient`), because
#: SPEC B10 refuses Lens over plain HTTP from anywhere but this machine.
LAN = {"REMOTE_ADDR": "192.168.1.50"}


def _now(minutes_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_cfg(**lens) -> SimpleNamespace:
    """A config stub. ``lens.*`` is L1's config section; reading it structurally through
    ``api.cfg_get`` means these tests work before and after L1 lands it in config.py."""
    return SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token=lens.pop("web_token", ""), refresh_seconds=15),
        network=SimpleNamespace(cidr="auto", gateway="auto", exclude=[]),
        scan=SimpleNamespace(use_nmap=False),
        dns=SimpleNamespace(enabled=lens.pop("dns_enabled", True), listen="0.0.0.0", port=53, upstreams=[],
                            doh_upstream="", block_mode="null", cache_max_entries=100, lists=[], log_queries=True,
                            log_retention_days=14, virustotal_api_key="", virustotal_daily_budget=400,
                            reputation_min_malicious_votes=2, reputation_ttl_hours=72),
        notify=SimpleNamespace(min_severity="high"),
        schedule=SimpleNamespace(discovery_minutes=10),
        lens=SimpleNamespace(
            enabled=lens.pop("enabled", True),
            require_https=lens.pop("require_https", True),
            tag_learning=lens.pop("tag_learning", True),
            allow_actions=lens.pop("allow_actions", False),
            token_ttl_days=lens.pop("token_ttl_days", 90),
            max_tokens=lens.pop("max_tokens", 10),
        ),
    )


# --------------------------------------------------------------------------- fixtures


@pytest.fixture
def conn():
    c = core_db.connect(":memory:")
    try:
        yield c
    finally:
        c.close()


def seed(conn: sqlite3.Connection) -> None:
    """A rich device (camera, telnet + web open, a KEV vuln, findings, DNS traffic), a bare one
    (never scanned), and a quiet offline one, so both payload shapes are covered."""
    now, old = _now(), _now(60 * 24 * 3)
    conn.executescript(
        """
        INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen,
                            online, last_service_scan)
        VALUES(1,'00:11:22:00:00:01','192.168.1.64','cam-hall','Example Optics','camera','Hall camera',0,
               '{old}','{now}',1,'{now}');
        INSERT INTO devices(id, mac, ip, hostname, vendor, kind, trusted, first_seen, last_seen, online)
        VALUES(2,'00:11:22:00:00:02','192.168.1.40','laptop','Contoso','laptop',1,'{old}','{now}',1);
        INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online)
        VALUES(3,'00:11:22:00:00:03','192.168.1.77','plug','Example Home','plug','Lamp plug',1,'{old}','{old}',0);
        INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(1,'192.168.1.64','{now}','arp');
        INSERT INTO services(id, device_id, port, proto, state, name, product, version, first_seen, last_seen)
        VALUES(1,1,23,'tcp','open','telnet','BusyBox telnetd','1.3','{old}','{now}');
        INSERT INTO services(id, device_id, port, proto, state, name, product, version, first_seen, last_seen)
        VALUES(2,1,80,'tcp','open','http','lighttpd','1.4.69','{old}','{now}');
        INSERT INTO services(id, device_id, port, proto, state, name, first_seen, last_seen)
        VALUES(3,1,9999,'tcp','closed','unknown','{old}','{now}');
        INSERT INTO vulns(device_id, service_id, cve, source, kev, cvss, epss, title, matched_on, first_seen, last_seen)
        VALUES(1,2,'CVE-2022-22707','nvd',1,9.8,0.71,'lighttpd buffer overflow','lighttpd 1.4.69','{old}','{now}');
        INSERT INTO vulns(device_id, service_id, cve, source, kev, cvss, epss, title, matched_on, first_seen, last_seen)
        VALUES(1,2,'CVE-2021-9999','nvd',0,5.3,0.004,'minor information leak','lighttpd 1.4.69','{old}','{now}');
        INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, detail, evidence, status, source,
                             first_seen, last_seen, device_id)
        VALUES(1,'NET-SVC-001','device:00:11:22:00:00:01:23','k1','critical','Telnet open on 192.168.1.64:23',
               'Telnet on the hall camera','{{"ip":"192.168.1.64","port":23}}','open','services','{old}','{now}',1);
        INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, detail, evidence, status, source,
                             first_seen, last_seen, device_id)
        VALUES(2,'NET-SVC-005','device:00:11:22:00:00:01:80','k2','low','HTTP admin interface without HTTPS',
               'Web page on port 80','{{"ip":"192.168.1.64","port":80}}','open','services','{old}','{now}',1);
        INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, evidence, status, source,
                             first_seen, last_seen, device_id)
        VALUES(3,'NET-DEV-001','device:00:11:22:00:00:01','k3','medium','New device on the network',
               '{{"ip":"192.168.1.64"}}','resolved','discovery','{old}','{now}',1);
        INSERT INTO finding_events(finding_row_id, event, at) VALUES(1,'opened','{now}');
        INSERT INTO reputation(domain, source, verdict, malicious, suspicious, checked_at)
        VALUES('tracker.example','virustotal','malicious',7,1,'{now}');
        """.format(now=now, old=old)
    )
    for i in range(12):
        conn.execute(
            "INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,1.0)",
            (_now(i * 5), "192.168.1.64", "updates.example" if i % 3 else "ads.example", "A",
             "allow" if i % 3 else "block", None if i % 3 else "oisd_small"),
        )
    conn.execute(
        "INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,1.0)",
        (_now(7), "192.168.1.64", "malware.example", "A", "block", "urlhaus"),
    )
    conn.execute(
        "INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES(?,?,?,?,?,?,1.0)",
        (_now(9), "192.168.1.64", "tracker.example", "A", "allow", None),
    )
    conn.commit()


@pytest.fixture
def seeded(conn):
    seed(conn)
    lensmod.reset_claim_limits(conn)
    return conn


class TlsClient(FlaskClient):
    """A test client whose requests arrive over TLS, like a real phone's.

    SPEC B10 refuses Lens over plain HTTP from any non-loopback address, so a LAN request
    built on werkzeug's ``http://localhost`` default never reaches the handler under test.
    ``environ_base`` cannot express this - ``EnvironBuilder`` writes ``wsgi.url_scheme``
    from ``base_url`` afterwards - so the scheme has to be set here. Pass ``base_url``
    explicitly in a test that is *about* the plain-HTTP refusal.
    """

    def open(self, *args, **kwargs):
        kwargs.setdefault("base_url", "https://localhost")
        return super().open(*args, **kwargs)


def client_for(conn, **cfg_kwargs):
    app = create_app(make_cfg(**cfg_kwargs), conn)
    app.config["TESTING"] = True
    app.test_client_class = TlsClient
    return app.test_client()


@pytest.fixture
def client(seeded):
    return client_for(seeded)


def paired(conn, *, scopes: str = "read") -> str:
    """A live Lens token, written the way B4 requires: only its SHA-256 is stored."""
    lensmod.ensure_tables(conn)
    import secrets

    token = secrets.token_urlsafe(32)
    webapi.write(
        conn,
        "INSERT INTO lens_tokens(token_hash, label, scopes, created_at) VALUES(?,?,?,?)",
        (lensmod.token_hash(token), "Test phone", scopes, _now()),
    )
    return token


def phone(token: str, **extra) -> dict:
    headers = {"X-Lens-Token": token}
    headers.update(extra)
    return headers


# --------------------------------------------------------------------------- B10: the master switch

LENS_GET = ["/api/lens/health", "/api/lens/devices", "/api/lens/device/1"]
LENS_POST = ["/api/lens/identify", "/api/lens/learn", "/api/lens/action", "/api/lens/claim"]


@pytest.mark.parametrize("path", LENS_GET)
def test_every_lens_get_is_404_when_lens_is_disabled(seeded, path):
    c = client_for(seeded, enabled=False)
    assert c.get(path).status_code == 404


@pytest.mark.parametrize("path", LENS_POST)
def test_every_lens_post_is_404_when_lens_is_disabled(seeded, path):
    c = client_for(seeded, enabled=False)
    assert c.post(path, json={}, headers=FETCH).status_code == 404


def test_disabled_lens_does_not_leak_a_different_error(seeded):
    c = client_for(seeded, enabled=False)
    r = c.delete("/api/lens/tag/hs1:whatever", headers=FETCH)
    assert r.status_code == 404 and r.get_json()["error"] == "not found"


# --------------------------------------------------------------------------- B7: authorisation


@pytest.mark.parametrize("path", LENS_GET)
def test_lan_requests_without_a_token_are_401(client, path):
    r = client.get(path, environ_base=LAN)
    assert r.status_code == 401
    assert r.get_json()["code"] == "no_token"
    assert r.headers["Cache-Control"] == "no-store"


def test_a_wrong_or_revoked_token_is_401(client, seeded):
    token = paired(seeded)
    assert client.get("/api/lens/health", headers=phone(token), environ_base=LAN).status_code == 200
    webapi.write(seeded, "UPDATE lens_tokens SET revoked_at=?", (_now(),))
    r = client.get("/api/lens/health", headers=phone(token), environ_base=LAN)
    assert r.status_code == 401 and r.get_json()["code"] == "unpaired"
    assert client.get("/api/lens/health", headers=phone("not-a-token"), environ_base=LAN).status_code == 401


def test_an_expired_token_is_401(client, seeded):
    token = paired(seeded)
    webapi.write(seeded, "UPDATE lens_tokens SET expires_at=?", (_now(60),))
    assert client.get("/api/lens/health", headers=phone(token), environ_base=LAN).status_code == 401


def test_the_desktop_reaches_lens_through_the_dashboard_session(client):
    """B7: X-Lens-Token *or* dashboard auth. From this machine, the owner needs no phone token."""
    r = client.get("/api/lens/health")
    assert r.status_code == 200 and r.get_json()["paired_as"] == "dashboard"


def test_a_lan_request_is_the_dashboard_only_with_the_dashboard_token(seeded):
    c = client_for(seeded, web_token="s3cret-dashboard-token")
    assert c.get("/api/lens/health", environ_base=LAN).status_code == 401
    r = c.get("/api/lens/health", headers={"X-Token": "s3cret-dashboard-token"}, environ_base=LAN)
    assert r.status_code == 200 and r.get_json()["paired_as"] == "dashboard"


def test_using_a_token_updates_last_seen_and_ip(client, seeded):
    token = paired(seeded)
    client.get("/api/lens/health", headers=phone(token), environ_base=LAN)
    row = webapi.one(seeded, "SELECT last_seen_at, last_ip FROM lens_tokens")
    assert row["last_ip"] == "192.168.1.50" and row["last_seen_at"]


def test_act_endpoints_are_403_without_the_scope_and_without_allow_actions(seeded):
    read_only = paired(seeded, scopes="read")
    full = paired(seeded, scopes="read act")
    body = {"device_id": 1, "action": "set_trusted", "payload": {"trusted": True}}

    off = client_for(seeded, allow_actions=False)
    r = off.post("/api/lens/action", json=body, headers=phone(full, **FETCH), environ_base=LAN)
    assert r.status_code == 403 and r.get_json()["code"] == "actions_disabled"

    on = client_for(seeded, allow_actions=True)
    r = on.post("/api/lens/action", json=body, headers=phone(read_only, **FETCH), environ_base=LAN)
    assert r.status_code == 403 and r.get_json()["code"] == "missing_scope"

    r = on.post("/api/lens/action", json=body, headers=phone(full, **FETCH), environ_base=LAN)
    assert r.status_code == 200 and r.get_json()["trusted"] is True
    assert webapi.one(seeded, "SELECT trusted FROM devices WHERE id=1")["trusted"] == 1


def test_actions_report_themselves_honestly_in_the_payload(seeded):
    read_only = paired(seeded, scopes="read")
    full = paired(seeded, scopes="read act")
    off = client_for(seeded, allow_actions=False).get("/api/lens/device/1", headers=phone(full), environ_base=LAN)
    assert off.get_json()["actions"] == {"can_rescan": False, "can_acknowledge": False, "can_set_trusted": False}
    on = client_for(seeded, allow_actions=True)
    assert on.get("/api/lens/device/1", headers=phone(read_only), environ_base=LAN).get_json()["actions"]["can_rescan"] is False
    assert on.get("/api/lens/device/1", headers=phone(full), environ_base=LAN).get_json()["actions"]["can_rescan"] is True


def test_acknowledge_refuses_a_finding_that_belongs_to_another_device(seeded):
    full = paired(seeded, scopes="read act")
    c = client_for(seeded, allow_actions=True)
    r = c.post("/api/lens/action", json={"device_id": 2, "action": "acknowledge", "payload": {"row_id": 1}},
               headers=phone(full, **FETCH), environ_base=LAN)
    assert r.status_code == 404
    r = c.post("/api/lens/action", json={"device_id": 1, "action": "acknowledge", "payload": {"row_id": 1}},
               headers=phone(full, **FETCH), environ_base=LAN)
    assert r.status_code == 200
    assert webapi.one(seeded, "SELECT status FROM findings WHERE id=1")["status"] == "acknowledged"


def test_unknown_action_and_unknown_device_are_rejected(seeded):
    full = paired(seeded, scopes="read act")
    c = client_for(seeded, allow_actions=True)
    assert c.post("/api/lens/action", json={"device_id": 1, "action": "wipe"},
                  headers=phone(full, **FETCH), environ_base=LAN).status_code == 400
    assert c.post("/api/lens/action", json={"device_id": 999, "action": "rescan"},
                  headers=phone(full, **FETCH), environ_base=LAN).status_code == 404


# --------------------------------------------------------------------------- B10: no data in URLs


def test_identification_is_post_only(client):
    assert client.get("/api/lens/identify").status_code == 405


@pytest.mark.parametrize("path", LENS_GET + ["/api/lens/identify"])
def test_every_lens_response_is_no_store(client, path):
    r = client.post(path, json={}, headers=FETCH) if path.endswith("identify") else client.get(path)
    assert r.headers["Cache-Control"] == "no-store"


# --------------------------------------------------------------------------- B6: identification


def test_an_unknown_code_returns_the_ranked_picker_not_an_error(client):
    r = client.post("/api/lens/identify", json={"code": "0123456789012"}, headers=FETCH)
    body = r.get_json()
    assert r.status_code == 200
    assert body["device_id"] is None and body["confidence"] == "unknown" and body["via"] == "manual"
    assert body["learnable"] is True
    assert [c["device_id"] for c in body["candidates"]]


def test_learning_a_code_makes_the_next_scan_exact(client, seeded):
    code = "0123456789012"
    learned = client.post("/api/lens/learn", json={"code": code, "device_id": 1}, headers=FETCH).get_json()
    assert learned["ok"] and learned["kind"] == "learned"
    body = client.post("/api/lens/identify", json={"code": code}, headers=FETCH).get_json()
    assert body["confidence"] == "exact" and body["device_id"] == 1 and body["via"] == "learned"
    assert body["device"]["device"]["nickname"] == "Hall camera"
    assert webapi.one(seeded, "SELECT scans FROM lens_tags WHERE code=?", (code,))["scans"] == 1


def test_a_sticker_code_resolves_exactly_and_reveals_nothing(client, seeded):
    codes = lensmod.mint_sticker_codes(seeded, [1])
    code = codes[1]
    assert code.startswith("hs1:") and len(code) == len("hs1:") + 22
    for secret in ("192.168", "00:11:22", "cam-hall", "Hall camera"):
        assert secret not in code
    body = client.post("/api/lens/identify", json={"code": code}, headers=FETCH).get_json()
    assert body["confidence"] == "exact" and body["via"] == "sticker" and body["device_id"] == 1


def test_minting_stickers_is_idempotent(seeded):
    first = lensmod.mint_sticker_codes(seeded, [1, 2])
    again = lensmod.mint_sticker_codes(seeded, [1, 2, 999])
    assert first == {k: v for k, v in again.items() if k in first}
    assert 999 not in again  # a device that does not exist gets no sticker


def test_forgetting_a_code_unbinds_it(client, seeded):
    code = "CODE-42"
    client.post("/api/lens/learn", json={"code": code, "device_id": 1}, headers=FETCH)
    assert client.delete(f"/api/lens/tag/{code}", headers=FETCH).status_code == 200
    assert client.delete(f"/api/lens/tag/{code}", headers=FETCH).status_code == 404
    assert client.post("/api/lens/identify", json={"code": code}, headers=FETCH).get_json()["confidence"] == "unknown"


def test_a_read_only_phone_cannot_delete_a_tag(seeded):
    """Deleting a tag is a destructive inventory change, not a read: a sticker tag maps a label
    physically stuck to a device, and killing it makes the next sheet print a different QR.
    B10 says that without the ``act`` scope Lens is strictly read-only, and docs/LENS_SETUP.md
    says unlearning is done from the computer."""
    code = lensmod.mint_sticker_codes(seeded, [1])[1]
    c = client_for(seeded)
    r = c.delete(f"/api/lens/tag/{code}", headers=phone(paired(seeded, scopes="read"), **FETCH), environ_base=LAN)
    assert r.status_code == 403 and r.get_json()["code"] == "actions_disabled"
    assert lensmod.tag_for_code(seeded, code) is not None, "the printed sticker still resolves"


def test_the_act_scope_alone_is_not_enough_to_delete_a_tag(seeded):
    code = lensmod.mint_sticker_codes(seeded, [1])[1]
    token = paired(seeded, scopes="read,act")
    off = client_for(seeded).delete(f"/api/lens/tag/{code}", headers=phone(token, **FETCH), environ_base=LAN)
    assert off.status_code == 403 and off.get_json()["code"] == "actions_disabled"
    on = client_for(seeded, allow_actions=True).delete(
        f"/api/lens/tag/{code}", headers=phone(token, **FETCH), environ_base=LAN)
    assert on.status_code == 200 and lensmod.tag_for_code(seeded, code) is None


def test_the_dashboard_can_still_unlearn_a_code(client, seeded):
    """The documented recovery path: "unlearn it, using the dashboard token"."""
    lensmod.learn_tag(seeded, "WRONG-TAG", 1)
    assert client.delete("/api/lens/tag/WRONG-TAG", headers=FETCH).status_code == 200


def test_learning_a_code_does_not_downgrade_a_sticker(seeded):
    """B9: reprinting a sheet must not invalidate stickers already stuck to devices. The owner
    scanning their own sticker and tapping the same device sends kind='learned'."""
    printed = lensmod.mint_sticker_codes(seeded, [1])[1]
    lensmod.learn_tag(seeded, printed, 1, kind="learned")
    assert lensmod.tag_for_code(seeded, printed)["kind"] == "sticker"
    assert lensmod.mint_sticker_codes(seeded, [1])[1] == printed
    assert webapi.scalar(seeded, "SELECT count(*) FROM lens_tags WHERE code LIKE 'hs1:%'") == 1


def test_a_sticker_is_reused_by_its_payload_not_by_its_kind(seeded):
    """Belt and braces on the same rule: STICKER_PREFIX is what makes a code a sticker."""
    printed = lensmod.mint_sticker_codes(seeded, [1])[1]
    webapi.write(seeded, "UPDATE lens_tags SET kind='learned' WHERE code=?", (printed,))
    assert lensmod.mint_sticker_codes(seeded, [1])[1] == printed


def test_relearning_the_same_code_concurrently_does_not_raise(seeded):
    """lens_tags.code is UNIQUE and the old shape was SELECT-then-INSERT, so two phones scanning
    the same new barcode at once produced an unhandled IntegrityError (HTTP 500)."""
    import threading

    errors: list = []

    def bind():
        try:
            lensmod.learn_tag(seeded, "RACE-CODE", 1)
        except Exception as exc:  # noqa: BLE001 - the point of the test
            errors.append(repr(exc))

    threads = [threading.Thread(target=bind) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert webapi.scalar(seeded, "SELECT count(*) FROM lens_tags WHERE code='RACE-CODE'") == 1


def test_a_device_id_sqlite_cannot_hold_is_not_found_rather_than_a_500(client):
    """Flask's <int:> converter accepts any number of digits; SQLite raises OverflowError."""
    r = client.get("/api/lens/device/99999999999999999999")
    assert r.status_code == 404 and r.get_json()["ok"] is False
    assert client.get("/api/lens/device/1").status_code == 200


def test_a_phone_supplied_label_cannot_carry_control_characters(seeded):
    """The label is printed by `lens tokens` in a fixed-width table and written into an events
    row, so CR/LF and ANSI escapes in it would forge or hide a row in the owner's audit output."""
    tag = lensmod.learn_tag(seeded, "LABEL-TEST", 1, label="a\x1b[31mX\r\nb", created_by="ph\x00one")
    row = webapi.one(seeded, "SELECT label, created_by FROM lens_tags WHERE id=?", (tag,))
    assert row["label"] == "a[31mXb" and row["created_by"] == "phone"


def test_ignoring_a_code_records_it_so_lens_stops_asking(client):
    r = client.post("/api/lens/learn", json={"code": "SOFA-BARCODE", "device_id": None}, headers=FETCH)
    assert r.status_code == 200 and r.get_json()["kind"] == "ignored"
    body = client.post("/api/lens/identify", json={"code": "SOFA-BARCODE"}, headers=FETCH).get_json()
    assert body["confidence"] == "unknown" and body["via"] == "ignored" and body["learnable"] is False


def test_a_tag_whose_device_is_gone_is_unlearned_rather_than_dangling(seeded):
    """B5: the tag survives, unlearned, and identification falls back to the picker.

    The delete runs with foreign keys on, the way the product deletes a device: ``lens_tags``
    declares ``device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL``, so this exercises
    the schema clause that makes B5 true rather than a synthetic orphan.
    """
    lensmod.learn_tag(seeded, "TAG-DEL", 3)
    assert seeded.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    webapi.write(seeded, "DELETE FROM devices WHERE id=3")
    assert webapi.one(seeded, "SELECT device_id FROM lens_tags WHERE code='TAG-DEL'")["device_id"] is None, \
        "ON DELETE SET NULL unlearns the tag; identification does not have to repair it"
    match = lensmod.identify(seeded, code="TAG-DEL")
    assert match.device_id is None and match.confidence == "unknown" and match.candidates
    row = webapi.one(seeded, "SELECT device_id, code FROM lens_tags WHERE code='TAG-DEL'")
    assert row is not None, "the tag itself is kept, so it can be re-learned"
    assert row["device_id"] is None, "identification self-heals the dangling pointer"


def test_learning_refuses_a_device_that_does_not_exist_and_a_hostile_code(client):
    assert client.post("/api/lens/learn", json={"code": "X1", "device_id": 999}, headers=FETCH).status_code == 404
    assert client.post("/api/lens/learn", json={"code": "", "device_id": 1}, headers=FETCH).status_code == 400
    assert client.post("/api/lens/identify", json={"code": "x" * 600}, headers=FETCH).status_code == 400
    assert client.post("/api/lens/identify", json={"code": "bad\x00code"}, headers=FETCH).status_code == 400


def test_learning_is_refused_when_tag_learning_is_off(seeded):
    c = client_for(seeded, tag_learning=False)
    r = c.post("/api/lens/learn", json={"code": "X2", "device_id": 1}, headers=FETCH)
    assert r.status_code == 403 and r.get_json()["code"] == "learning_off"


def test_relearning_a_code_moves_it_instead_of_duplicating(seeded):
    first = lensmod.learn_tag(seeded, "MOVE-ME", 1)
    second = lensmod.learn_tag(seeded, "MOVE-ME", 2)
    assert first == second
    assert webapi.scalar(seeded, "SELECT count(*) FROM lens_tags WHERE code='MOVE-ME'") == 1
    assert lensmod.identify(seeded, code="MOVE-ME").device_id == 2


# --------------------------------------------------------------------------- B6: ranking


def test_rank_candidates_follows_the_documented_precedence(seeded):
    ranked = lensmod.rank_candidates(seeded)
    order = [c["device_id"] for c in ranked]
    # 1 and 2 are online; 1 also has open findings, so it leads. 3 is offline and comes last.
    assert order == [1, 2, 3]
    assert "open finding" in ranked[0]["why"] and "online" in ranked[0]["why"]
    assert "offline" in ranked[-1]["why"]


def test_an_online_device_outranks_an_offline_one_with_more_findings(seeded):
    now = _now()
    webapi.write(seeded, "UPDATE devices SET online=0, last_seen=? WHERE id=1", (_now(60 * 24),))
    for i in range(4, 9):
        webapi.write(
            seeded,
            "INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, status, source, "
            "first_seen, last_seen, device_id) VALUES(?,?,?,?,?,?,'open','services',?,?,1)",
            (i, "NET-SVC-002", f"s{i}", f"key{i}", "critical", "FTP open", now, now),
        )
    order = [c["device_id"] for c in lensmod.rank_candidates(seeded)]
    assert order[0] == 2, "an online device must outrank an offline one however bad its findings"


def test_a_stale_online_flag_does_not_count_as_online(seeded):
    webapi.write(seeded, "UPDATE devices SET last_seen=? WHERE id=2", (_now(120),))
    why = {c["device_id"]: c["why"] for c in lensmod.rank_candidates(seeded)}
    assert "online" not in why[2].split(", ")


def test_the_hint_kind_breaks_a_tie_and_can_make_a_probable_match(seeded):
    """The hint boosts inside its band; it never jumps the online tier."""
    plain = {c["device_id"]: c["score"] for c in lensmod.rank_candidates(seeded)}
    ranked = lensmod.rank_candidates(seeded, hint={"kind": "plug"})
    hinted = {c["device_id"]: c["score"] for c in ranked}
    # Device 3 is the only plug, and it is offline; 1 and 2 are online.
    assert hinted[3] - plain[3] == lensmod._SCORE_HINT_KIND
    assert hinted[1] == plain[1] and hinted[2] == plain[2]
    assert [c["device_id"] for c in ranked][0] in (1, 2), "the hint must not jump the online tier"
    match = lensmod.identify(seeded, hint={"q": "Lamp"})
    assert match.confidence == "probable" and match.device_id == 3


def test_nothing_below_the_findings_band_can_overtake_an_open_finding(seeded):
    """B6 rule 2 beats rules 3 and 4. Summed raw, kind hint + vendor hint + untrusted + new
    came to 450 and overtook the 445 an offline device with one open critical can reach."""
    webapi.write(seeded, "UPDATE devices SET online=0, last_seen=? WHERE id IN (1,2,3)", (_now(60 * 48),))
    # Device 3 (the plug): no findings, but every lower-band bonus at once.
    webapi.write(seeded, "UPDATE devices SET vendor='Acme Print', trusted=0, first_seen=? WHERE id=3", (_now(60,),))
    # Device 1 (the camera) keeps its one open critical finding and nothing else.
    webapi.write(seeded, "UPDATE devices SET trusted=1, vendor='Other' WHERE id=1")
    webapi.write(seeded, "UPDATE findings SET status='resolved' WHERE device_id=1 AND severity<>'critical'")
    ranked = lensmod.rank_candidates(seeded, hint={"kind": "plug", "vendor": "Acme"})
    by_id = {c["device_id"]: c["score"] for c in ranked}
    assert by_id[3] < lensmod._SCORE_FINDINGS, "the lower band is clamped below the findings band"
    assert ranked[0]["device_id"] == 1, "an open finding outranks every hint and flag below it"


def test_the_picker_endpoint_filters_with_q(client):
    body = client.get("/api/lens/devices?q=laptop").get_json()
    assert [d["device_id"] for d in body["devices"]] == [2]


# --------------------------------------------------------------------------- B7: the payload


PAYLOAD_KEYS = {"device", "posture", "services", "vulns", "findings", "dns", "timeline", "actions"}
DEVICE_KEYS = {"id", "nickname", "hostname", "ip", "mac", "vendor", "kind", "trusted", "online",
               "first_seen", "last_seen", "last_service_scan"}


def test_payload_has_every_documented_section_and_device_key(client):
    body = client.get("/api/lens/device/1").get_json()
    assert PAYLOAD_KEYS <= set(body)
    assert DEVICE_KEYS <= set(body["device"])
    assert body["device"]["id"] == 1 and body["device"]["ip"] == "192.168.1.64"
    assert body["device"]["online"] is True and body["device"]["trusted"] is False


def test_posture_counts_only_open_findings_and_costs_the_right_points(client):
    posture = client.get("/api/lens/device/1").get_json()["posture"]
    assert posture["severity_counts"] == {"critical": 1, "high": 0, "medium": 0, "low": 1, "info": 0}
    assert posture["score_contribution"] == webapi.SCORE_PENALTY["critical"] + webapi.SCORE_PENALTY["low"]


def test_the_headline_is_a_sentence_a_human_can_read(client):
    headline = client.get("/api/lens/device/1").get_json()["posture"]["headline"]
    assert headline.startswith("Two problems, one of them critical:")
    assert "this camera accepts Telnet logins" in headline
    assert headline.endswith(".")
    for jargon in ("NET-SVC-001", "{", "}", "None"):
        assert jargon not in headline


def test_the_headline_names_at_most_three_problems_and_counts_the_rest(seeded):
    now = _now()
    for i, (fid, sev) in enumerate([("NET-SVC-010", "high"), ("NET-SVC-006", "medium"), ("NET-SVC-009", "medium")], 10):
        webapi.write(
            seeded,
            "INSERT INTO findings(id, finding_id, subject, dedupe_key, severity, title, status, source, "
            "first_seen, last_seen, device_id) VALUES(?,?,?,?,?,?,'open','services',?,?,1)",
            (i, fid, f"s{i}", f"k{i}", sev, f"{fid} title", now, now),
        )
    headline = client_for(seeded).get("/api/lens/device/1").get_json()["posture"]["headline"]
    assert headline.startswith("Five problems, one of them critical:")
    # The tail count is spelled out like the lead: "Five problems ... and 2 more" reads like two
    # different voices in one sentence.
    assert headline.endswith(", and two more.")
    assert headline.count(", and ") == 1, "exactly one closing conjunction, never 'and ... and'"
    assert not any(ch.isdigit() for ch in headline), "no bare digits in a sentence that spells its counts"


def test_the_headline_is_honest_about_a_device_that_was_never_scanned(client):
    headline = client.get("/api/lens/device/2").get_json()["posture"]["headline"]
    assert "has not scanned" in headline and "run a scan" in headline


def test_a_clean_scanned_device_says_so_plainly(seeded):
    webapi.write(seeded, "UPDATE devices SET last_service_scan=? WHERE id=2", (_now(),))
    headline = client_for(seeded).get("/api/lens/device/2").get_json()["posture"]["headline"]
    assert headline.startswith("Nothing is open on this laptop")


def test_services_carry_a_risk_and_a_plain_english_gloss(client):
    services = client.get("/api/lens/device/1").get_json()["services"]
    by_port = {s["port"]: s for s in services}
    assert by_port[23]["risk"] == "critical" and "no encryption" in by_port[23]["gloss"]
    assert by_port[23]["label"] == "Telnet"
    assert by_port[80]["risk"] == "low" and "without encryption" in by_port[80]["gloss"]
    assert by_port[80]["gloss"].endswith("Running lighttpd 1.4.69.")
    assert "clear. Running" in by_port[80]["gloss"], "the gloss is sentences, not two clauses jammed together"
    assert by_port[9999]["risk"] == "info"  # a closed port is not an exposure
    assert services[0]["port"] == 23, "worst first"
    assert {"port", "proto", "name", "product", "version", "state", "risk"} <= set(services[0])


@pytest.mark.parametrize("port,expected", [(23, "critical"), (21, "high"), (445, "high"), (3389, "high"),
                                           (554, "high"), (9100, "medium"), (1900, "medium"), (5900, "high"),
                                           (22, "low"), (80, "low"), (443, "info")])
def test_every_well_known_port_named_in_the_spec_has_a_gloss(port, expected):
    view = lensmod.service_view({"port": port, "state": "open", "proto": "tcp"})
    assert view["risk"] == expected
    assert len(view["gloss"]) > 20 and view["label"]


def test_vulns_express_epss_as_a_probability_and_flag_kev_first(client):
    vulns = client.get("/api/lens/device/1").get_json()["vulns"]
    assert {"cve", "kev", "cvss", "epss", "title", "service", "remediation"} <= set(vulns[0])
    assert vulns[0]["cve"] == "CVE-2022-22707" and vulns[0]["kev"] is True
    assert "actively exploited" in vulns[0]["kev_note"]
    assert vulns[0]["epss_pct"] == 71.0 and "71% chance of exploitation in the next 30 days" in vulns[0]["epss_text"]
    assert vulns[1]["kev"] is False and vulns[1]["epss_pct"] == 0.4
    assert "unlikely" in vulns[1]["epss_text"]
    assert vulns[0]["remediation"]


def test_findings_arrive_worst_first_with_numbered_fix_steps(client):
    findings = client.get("/api/lens/device/1").get_json()["findings"]
    assert {"row_id", "finding_id", "severity", "title", "detail", "status", "first_seen",
            "remediation", "refs"} <= set(findings[0])
    assert [f["severity"] for f in findings[:2]] == ["critical", "low"]
    assert findings[-1]["status"] == "resolved"
    assert findings[0]["remediation"] and all(isinstance(s, str) for s in findings[0]["remediation"])
    assert "192.168.1.64" in " ".join(findings[0]["remediation"])  # evidence really is interpolated


def test_the_timeline_reuses_the_activity_feed(client):
    timeline = client.get("/api/lens/device/1").get_json()["timeline"]
    assert timeline and {"ts", "kind", "severity", "title"} == set(timeline[0])
    assert any(t["kind"].startswith("finding") for t in timeline)
    assert all(isinstance(t["ts"], str) for t in timeline)


def test_a_bare_device_still_returns_every_section(client):
    body = client.get("/api/lens/device/2").get_json()
    assert PAYLOAD_KEYS <= set(body)
    assert body["services"] == [] and body["vulns"] == [] and body["findings"] == []
    assert body["posture"]["score_contribution"] == 0
    assert body["dns"]["total"] == 0


def test_an_unknown_device_is_404(client):
    assert client.get("/api/lens/device/999").status_code == 404


# --------------------------------------------------------------------------- B7: the DNS section


def test_dns_shows_what_the_device_talks_to(client):
    dns = client.get("/api/lens/device/1").get_json()["dns"]
    assert dns["enabled"] is True and dns["window_hours"] == 24
    assert dns["total"] == 14 and dns["blocked"] == 5
    assert dns["block_rate"] == round(5 / 14, 4)
    assert dns["top_allowed"][0] == {"domain": "updates.example", "count": 8}
    assert {"domain", "count", "reason"} == set(dns["top_blocked"][0])
    domains = {t["domain"] for t in dns["threats"]}
    assert "malware.example" in domains, "a threat-list block is a threat"
    assert "tracker.example" in domains, "a domain the reputation table calls malicious is a threat"
    assert "ads.example" not in domains, "an advertising block is not a threat"


def test_dns_is_honest_when_the_resolver_is_off(seeded):
    c = client_for(seeded, dns_enabled=False)
    dns = c.get("/api/lens/device/1").get_json()["dns"]
    assert dns["enabled"] is False and dns["total"] == 0
    assert "switched off" in dns["note"] and "dns.enabled" in dns["note"]


def test_dns_is_honest_when_the_device_changed_address_inside_the_window(seeded):
    webapi.write(
        seeded,
        "INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(1,'192.168.1.99',?,'arp')",
        (_now(30),),
    )
    dns = client_for(seeded).get("/api/lens/device/1").get_json()["dns"]
    assert "192.168.1.99" in dns["note"] and "partial" in dns["note"]


def test_dns_is_honest_when_nothing_was_logged_for_this_device(client):
    dns = client.get("/api/lens/device/2").get_json()["dns"]
    assert dns["enabled"] is True and dns["total"] == 0
    assert "No DNS queries from 192.168.1.40" in dns["note"]


def test_dns_does_not_attribute_another_device_traffic_after_a_lease_moves(conn):
    """B7 honesty: the figures are keyed on the device's *current* IP, and a DHCP lease moves.
    Without a floor the previous holder's threat hits show up on the new holder's card."""
    now, t22, t20, t1 = _now(), _now(60 * 22), _now(60 * 20), _now(60)
    conn.executescript(
        f"""
        INSERT INTO devices(id, mac, ip, kind, nickname, trusted, first_seen, last_seen, online)
        VALUES(1,'00:11:22:00:00:0a','192.168.1.70','laptop','Laptop',1,'{_now(60 * 24 * 30)}','{now}',1);
        INSERT INTO devices(id, mac, ip, kind, nickname, trusted, first_seen, last_seen, online)
        VALUES(2,'00:11:22:00:00:0b','192.168.1.64','camera','Camera',0,'{_now(120)}','{now}',1);
        INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(1,'192.168.1.64','{t22}','arp');
        INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(1,'192.168.1.64','{t20}','arp');
        INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(1,'192.168.1.70','{t1}','arp');
        INSERT INTO device_sightings(device_id, ip, seen_at, method) VALUES(2,'192.168.1.64','{t1}','arp');
        INSERT INTO dns_queries(ts, client, qname, qtype, action, reason)
        VALUES('{t22}','192.168.1.64','private-banking.example','A','block','urlhaus');
        INSERT INTO dns_queries(ts, client, qname, qtype, action, reason)
        VALUES('{t22}','192.168.1.64','private-banking.example','A','block','urlhaus');
        INSERT INTO dns_queries(ts, client, qname, qtype, action, reason)
        VALUES('{now}','192.168.1.64','ok.example','A','allow',NULL);
        """
    )
    conn.commit()
    dns = lensmod.dns_section(conn, {"id": 2, "ip": "192.168.1.64"}, hours=24, enabled=True)
    assert dns["total"] == 1 and dns["blocked"] == 0 and dns["block_rate"] == 0.0
    assert dns["threats"] == [], "the laptop's malware-list hits are not the camera's"
    assert "also used by another device" in dns["note"]


def test_dns_does_not_clamp_when_the_address_was_never_shared(client):
    """The floor is only applied on a real handover: device_sightings holds one row per scan, so
    clamping to the earliest sighting unconditionally would discard the device's own traffic."""
    dns = client.get("/api/lens/device/1").get_json()["dns"]
    assert dns["total"] == 14 and "also used by another device" not in dns["note"]


def test_an_empty_window_is_not_reported_as_a_switched_off_resolver(conn):
    """lens_device's default inferred "enabled" from whether anything was logged, so a quiet
    network, log_queries=false or a retention purge all read as "the DNS filter is off"."""
    conn.executescript(
        f"INSERT INTO devices(id, mac, ip, kind, first_seen, last_seen, online) "
        f"VALUES(1,'00:11:22:00:00:0c','192.168.1.5','plug','{_now()}','{_now()}',1);"
    )
    conn.commit()
    unknown = lensmod.dns_section(conn, {"id": 1, "ip": "192.168.1.5"})
    assert unknown["enabled"] is None and "could not tell" in unknown["note"]
    core_db.set_setting(conn, "dns.enabled", "true")
    quiet = lensmod.dns_section(conn, {"id": 1, "ip": "192.168.1.5"})
    assert quiet["enabled"] is True and "switched off" not in quiet["note"]
    assert "No DNS queries from 192.168.1.5" in quiet["note"]
    core_db.set_setting(conn, "dns.enabled", "false")
    assert lensmod.dns_section(conn, {"id": 1, "ip": "192.168.1.5"})["enabled"] is False


def test_a_busy_network_does_not_starve_a_device_out_of_its_own_history(seeded):
    """B7 asks for "the last 20 feed items for this device". The timeline used to build a
    whole-network 500-item feed and filter it in Python, so a few normal days of other clients'
    DNS blocks emptied the History section and the phone said "Nothing recorded for this device
    yet" — which was false."""
    device = {"id": 1, "ip": "192.168.1.64", "mac": "00:11:22:00:00:01"}
    before = lensmod.timeline(seeded, device)
    assert before, "the seeded camera has history"
    seeded.executemany(
        "INSERT INTO dns_queries(ts, client, qname, qtype, action, reason) VALUES(?,?,?,?,?,?)",
        [(_now(i % 2000), f"192.168.9.{i % 200}", f"noise{i}.example", "A", "block", "oisd_small")
         for i in range(4000)],
    )
    seeded.commit()
    after = lensmod.timeline(seeded, device)
    assert len(after) == len(before)
    assert all("192.168.9." not in item["title"] for item in after)


def test_the_dns_window_is_configurable_and_bounded(client):
    assert client.get("/api/lens/device/1?hours=1").get_json()["dns"]["window_hours"] == 1
    assert client.get("/api/lens/device/1?hours=99999").get_json()["dns"]["window_hours"] == 24 * 30


# --------------------------------------------------------------------------- B4: claim


def test_claim_succeeds_once_and_never_again(seeded):
    code = lensmod.mint_pairing_code(seeded)
    c = client_for(seeded)
    first = c.post("/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN)
    assert first.status_code == 200
    body = first.get_json()
    assert body["token"] and body["scopes"] == ["read"] and body["expires_at"]
    second = c.post("/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN)
    assert second.status_code == 400
    # The token is stored only as a hash, and it works.
    assert webapi.scalar(seeded, "SELECT count(*) FROM lens_tokens WHERE token_hash=?", (body["token"],)) == 0
    assert c.get("/api/lens/health", headers=phone(body["token"]), environ_base=LAN).status_code == 200


def test_claim_grants_the_act_scope_only_when_actions_are_allowed(seeded):
    code = lensmod.mint_pairing_code(seeded)
    body = client_for(seeded, allow_actions=True).post(
        "/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN
    ).get_json()
    assert body["scopes"] == ["read", "act"]


def _expire_pairing_codes(conn) -> int:
    """Backdate every stored pairing code's expiry, whichever layer wrote it."""
    changed = 0
    for row in webapi.rows(conn, "SELECT key, value FROM settings WHERE key LIKE 'lens.pairing%'"):
        state = webapi.loads(row["value"], None)
        if isinstance(state, dict) and state.get("expires_at"):
            state["expires_at"] = _now(10)
            webapi.set_setting(conn, row["key"], webapi.json.dumps(state))
            changed += 1
    return changed


def test_claim_refuses_an_expired_code(seeded):
    code = lensmod.mint_pairing_code(seeded)
    assert _expire_pairing_codes(seeded) == 1
    r = client_for(seeded).post("/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN)
    assert r.status_code == 400 and "expired" in r.get_json()["error"]
    assert webapi.scalar(seeded, "SELECT count(*) FROM lens_tokens") == 0


def test_claim_is_rate_limited_per_source_ip_and_records_it(seeded):
    c = client_for(seeded)
    for _ in range(lensmod.CLAIM_MAX_ATTEMPTS):
        assert c.post("/api/lens/claim", json={"code": "WRONG123"}, headers=FETCH, environ_base=LAN).status_code == 400
    blocked = c.post("/api/lens/claim", json={"code": "WRONG123"}, headers=FETCH, environ_base=LAN)
    assert blocked.status_code == 429 and blocked.get_json()["code"] == "rate_limited"
    # a different phone is unaffected
    other = c.post("/api/lens/claim", json={"code": "WRONG123"}, headers=FETCH,
                   environ_base={"REMOTE_ADDR": "192.168.1.51"})
    assert other.status_code == 400
    assert webapi.scalar(
        seeded,
        "SELECT count(*) FROM events WHERE source='lens' AND level='warning' AND message LIKE '%pairing attempts%'",
    ) == 1


def test_claim_enforces_max_tokens(seeded):
    for _ in range(2):
        paired(seeded)
    code = lensmod.mint_pairing_code(seeded)
    r = client_for(seeded, max_tokens=2).post("/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN)
    assert r.status_code == 400 and "revoke one" in r.get_json()["error"]


# --------------------------------------------------------------------------- B10 / B11: hostile input


def test_a_hostile_nickname_stays_plain_text_all_the_way_through(seeded):
    webapi.write(seeded, "UPDATE devices SET nickname=?, kind='' WHERE id=2", ("<img src=x onerror=alert(1)>",))
    webapi.write(seeded, "UPDATE devices SET last_service_scan=? WHERE id=2", (_now(),))
    body = client_for(seeded).get("/api/lens/device/2").get_json()
    assert body["device"]["nickname"] == "<img src=x onerror=alert(1)>"
    assert "<img" not in body["posture"]["headline"], "the headline never interpolates a nickname"
    picker = client_for(seeded).get("/api/lens/devices").get_json()["devices"]
    assert any(d["name"] == "<img src=x onerror=alert(1)>" for d in picker)


def test_a_code_is_never_echoed_into_a_url(client):
    """Identification is POST and the payload never carries a code, so nothing reaches a log."""
    body = client.post("/api/lens/identify", json={"code": "hs1:something"}, headers=FETCH).get_json()
    assert "code" not in body


def test_health_reports_the_transport_honestly(client):
    body = client.get("/api/lens/health").get_json()
    assert body["ok"] is True and body["https"] is True, "TlsClient speaks https; say so"
    # ...and the other way round, from this machine, where plain HTTP is still allowed.
    plain = client.get("/api/lens/health", base_url="http://127.0.0.1:8787").get_json()
    assert plain["ok"] is True and plain["https"] is False
    assert body["devices"] == 3 and body["dns_enabled"] is True
    assert body["version"] and set(body) >= {"ok", "https", "version", "dns_enabled", "devices", "paired_as"}


def test_the_api_is_refused_over_plain_http_from_the_lan(client, seeded):
    """SPEC B10, from the API's side: a token sent in clear text over the LAN is not a
    secret, so the request is declined before any handler sees it."""
    r = client.get("/api/lens/health", base_url="http://localhost:8787", environ_base=LAN)
    assert r.status_code == 403 and r.get_json()["code"] == "https_required"
    allowed = client_for(seeded, require_https=False).get(
        "/api/lens/health", base_url="http://localhost:8787", environ_base=LAN)
    assert allowed.status_code == 401, "the transport gate is lifted; the token gate is not"


# --------------------------------------------------------------------------- B10: the catalogue entry


def test_soc_lens_001_exists_with_real_fix_steps():
    from homesoc.findings import catalog

    spec = catalog.get("SOC-LENS-001")
    assert spec is not None and spec.severity == "medium" and spec.category == "soc"
    steps = " ".join(spec.remediation)
    assert "pip install cryptography" in steps
    assert "--tls" in steps and "lens.enabled = false" in steps
    assert all(r.startswith("https://") for r in spec.refs) and spec.refs


def test_the_dashboard_exposure_finding_does_not_contradict_lens():
    """SOC-SYS-003 says "go back to 127.0.0.1", which no Lens user can do; it has to say so."""
    from homesoc.findings import catalog

    steps = " ".join(catalog.get("SOC-SYS-003").remediation)
    assert "Lens" in steps and "web.token" in steps


# --------------------------------------------------------------------------- the L1 seam
#
# lens.py prefers the transport package's token/pairing helpers and only falls back to its own
# B4-conformant copy when they are absent. Once L1 has landed, the fallback must NOT be what runs:
# the desktop mints a pairing code through L1 and /api/lens/claim redeems it here, so a rename on
# either side would silently split them into two stores that never agree. These tests pin the seam
# and are skipped (not failed) on an install where the transport layer is genuinely absent.

L1_CALL_SITES: list[tuple[str, tuple[str, ...]]] = [
    ("verify_token", ("verify_token",)),
    ("active_token_count", ("active_tokens",)),
    ("claim_allowed", ("claim_attempt",)),
    ("claim_reset", ("claim_reset",)),
    ("mint_pairing_code", ("new_pairing_code", "mint_pairing_code", "create_pairing_code")),
    ("consume_pairing_code", ("consume_pairing_code", "redeem_pairing_code")),
    ("mint_token", ("mint_token",)),
]


def _l1_present() -> bool:
    return lensmod._l1("mint_token") is not None


@pytest.mark.parametrize("site, names", L1_CALL_SITES, ids=[s for s, _ in L1_CALL_SITES])
def test_each_token_call_site_resolves_to_the_transport_layer(site, names):
    if not _l1_present():
        pytest.skip("transport package (L1) is not installed; the documented fallback is in use")
    fn = lensmod._l1(*names)
    assert fn is not None, f"{site} fell back to lens.py's own copy; L1 renamed one of {names}"


def test_a_pairing_code_minted_by_the_desktop_is_redeemable_by_the_phone(seeded):
    """The end-to-end seam: `homesoc lens pair` mints, `/api/lens/claim` redeems, once."""
    if not _l1_present():
        pytest.skip("transport package (L1) is not installed")
    code = core_db.lens_new_pairing_code(seeded)
    c = client_for(seeded)
    r = c.post("/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    token = body["token"]
    assert body["scopes"] == ["read"] and body["expires_at"]
    # Only the hash is stored, never the secret itself (B10).
    assert webapi.one(seeded, "SELECT id FROM lens_tokens WHERE token_hash=?", (token,)) is None
    assert webapi.one(seeded, "SELECT id FROM lens_tokens WHERE token_hash=?", (lensmod.token_hash(token),))
    assert c.get("/api/lens/device/1", headers=phone(token), environ_base=LAN).status_code == 200
    # Single use.
    assert c.post("/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN).status_code == 400


def test_hitting_max_tokens_refuses_without_spending_the_pairing_code(seeded):
    """The ceiling is checked before the code is consumed, so the user can retry after revoking."""
    if not _l1_present():
        pytest.skip("transport package (L1) is not installed")
    core_db.lens_mint_token(seeded, label="phone A", scopes="read", ttl_days=90, max_tokens=5)
    code = core_db.lens_new_pairing_code(seeded)
    r = client_for(seeded, max_tokens=1).post("/api/lens/claim", json={"code": code}, headers=FETCH, environ_base=LAN)
    assert r.status_code == 400 and "revoke" in r.get_json()["error"]
    assert core_db.lens_consume_pairing_code(seeded, code) is True, "the code must survive a refusal"


def test_a_revoked_token_stops_working_immediately(seeded):
    if not _l1_present():
        pytest.skip("transport package (L1) is not installed")
    minted = core_db.lens_mint_token(seeded, label="Old phone", scopes="read", ttl_days=90, max_tokens=5)
    c = client_for(seeded)
    assert c.get("/api/lens/device/1", headers=phone(minted["token"]), environ_base=LAN).status_code == 200
    core_db.lens_revoke_token(seeded, int(minted["id"]))
    r = c.get("/api/lens/device/1", headers=phone(minted["token"]), environ_base=LAN)
    assert r.status_code == 401 and r.get_json()["code"] == "unpaired"
