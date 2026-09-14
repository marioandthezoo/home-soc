"""Lens transport and authentication: TLS, tokens, pairing, migration, CLI (addendum B3/B4/B5/B10).

Everything here is offline and deterministic. The pieces under test are the ones that
decide whether a phone on the LAN may see the whole network inventory, so the negative
cases matter more than the positive ones and get most of the space: a revoked token, an
expired token, a replayed pairing code, a guessing loop, an eleventh phone.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

from homesoc import cli, config, db, paths
from homesoc.web import tls

PAIRING_PREFIX = "lens.pairing."
# Documentation addresses only: never a real host from anyone's network.
LAN_IP = "192.168.10.5"
PHONE_IP = "192.168.10.42"

# `cryptography` is an optional extra (SPEC B3): a stock install has flask, requests and
# dnslib and nothing else, and Home SOC must be fully green there. Tests that need a real
# certificate to exist therefore skip rather than fail when it is absent; the tests for
# the *absence* path below patch the import instead and always run, so the behaviour that
# matters on a stock install - a clear message rather than a traceback - is never skipped.
needs_cryptography = pytest.mark.skipif(
    not tls.available(),
    reason="optional 'cryptography' extra not installed (python -m pip install homesoc[lens])",
)


# --------------------------------------------------------------------------- config


def test_lens_section_defaults_are_safe(cfg: config.Config) -> None:
    """B10: Lens is off, read-only and HTTPS-only until the owner says otherwise."""
    assert cfg.lens.enabled is False
    assert cfg.lens.require_https is True
    assert cfg.lens.allow_actions is False
    assert cfg.lens.tag_learning is True
    assert cfg.lens.token_ttl_days == 90
    assert cfg.lens.max_tokens == 10
    assert "lens" in config.SECTIONS
    assert set(config.DEFAULTS["lens"]) == {f.name for f in __import__("dataclasses").fields(config.Lens)}


def test_lens_config_example_matches_the_constant() -> None:
    example = paths.project_root() / "config.example.toml"
    assert "[lens]" in example.read_text(encoding="utf-8")
    assert example.read_text(encoding="utf-8") == config.EXAMPLE_TOML


def test_lens_overrides_are_type_checked(conn: sqlite3.Connection) -> None:
    config.set_override(conn, "lens.enabled", "true")
    config.set_override(conn, "lens.max_tokens", "3")
    reloaded = config.load(conn)
    assert reloaded.lens.enabled is True and reloaded.lens.max_tokens == 3
    with pytest.raises(ValueError):
        config.set_override(conn, "lens.enabled", "sometimes")
    with pytest.raises(ValueError):
        config.set_override(conn, "lens.max_tokens", "lots")
    with pytest.raises(ValueError):
        config.set_override(conn, "lens.no_such_key", "1")


def test_lens_helpers_clamp_nonsense(cfg: config.Config) -> None:
    odd = config.with_overrides(cfg, {"lens.token_ttl_days": -5, "lens.max_tokens": 0})
    assert odd.lens.ttl_days == 0  # 0 means "never expires", not "already expired"
    assert odd.lens.token_ceiling == 1  # pairing must remain possible


def test_disabling_lens_invalidates_outstanding_pairing_codes(conn: sqlite3.Connection) -> None:
    """B10: a code left on a screen stops working the moment Lens is switched off."""
    config.set_override(conn, "lens.enabled", "true")
    code = db.lens_new_pairing_code(conn)
    config.set_override(conn, "lens.enabled", "false")
    assert db.lens_consume_pairing_code(conn, code) is False


# --------------------------------------------------------------------------- schema


def test_lens_tables_match_the_spec(memory_conn: sqlite3.Connection) -> None:
    def columns(table: str) -> list[str]:
        return [r["name"] for r in memory_conn.execute(f"PRAGMA table_info({table})")]

    assert columns("lens_tokens") == [
        "id", "token_hash", "label", "scopes", "created_at", "last_seen_at", "last_ip",
        "expires_at", "revoked_at",
    ]
    assert columns("lens_tags") == [
        "id", "code", "kind", "device_id", "label", "created_at", "created_by",
        "last_seen_at", "scans",
    ]
    # A tag points at a device but does not require one: deleting a device must leave the
    # tag unlearned rather than dangling (B5), which needs a nullable foreign key.
    tag_columns = {r["name"]: r for r in memory_conn.execute("PRAGMA table_info(lens_tags)")}
    assert tag_columns["device_id"]["notnull"] == 0
    assert tag_columns["code"]["notnull"] == 1
    keys = list(memory_conn.execute("PRAGMA foreign_key_list(lens_tags)"))
    assert [(k["table"], k["from"], k["to"]) for k in keys] == [("devices", "device_id", "id")]
    assert keys[0]["on_delete"] == "SET NULL"


def test_deleting_a_device_unlearns_its_tags_rather_than_dangling(memory_conn: sqlite3.Connection) -> None:
    """B5, with foreign keys on as they are in production."""
    now = "2026-09-13T00:00:00Z"
    device_id = db.write(
        memory_conn,
        "INSERT INTO devices(mac, ip, nickname, first_seen, last_seen) VALUES (?,?,?,?,?)",
        ("00:11:22:33:44:77", "192.168.10.30", "Study printer", now, now),
    )
    db.write(memory_conn, "INSERT INTO lens_tags(code, kind, device_id, created_at, created_by) VALUES (?,?,?,?,?)",
             ("hs1:StickerOnThePrinter", "sticker", device_id, now, "test"))
    assert memory_conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    db.write(memory_conn, "DELETE FROM devices WHERE id = ?", (device_id,))
    row = db.one(memory_conn, "SELECT code, device_id FROM lens_tags")
    assert row is not None and row["device_id"] is None
    assert list(memory_conn.execute("PRAGMA foreign_key_check")) == []


def test_unique_constraints(memory_conn: sqlite3.Connection) -> None:
    now = "2026-09-13T00:00:00Z"
    db.write(memory_conn, "INSERT INTO lens_tags(code, kind, created_at, created_by) VALUES (?,?,?,?)",
             ("hs1:AbCdEfGhIjKlMnOpQrStUv", "sticker", now, "test"))
    with pytest.raises(sqlite3.IntegrityError):
        db.write(memory_conn, "INSERT INTO lens_tags(code, kind, created_at, created_by) VALUES (?,?,?,?)",
                 ("hs1:AbCdEfGhIjKlMnOpQrStUv", "learned", now, "test"))
    db.write(memory_conn, "INSERT INTO lens_tokens(token_hash, label, scopes, created_at) VALUES (?,?,?,?)",
             ("a" * 64, "phone", "read", now))
    with pytest.raises(sqlite3.IntegrityError):
        db.write(memory_conn, "INSERT INTO lens_tokens(token_hash, label, scopes, created_at) VALUES (?,?,?,?)",
                 ("a" * 64, "other phone", "read", now))


# ----------------------------------------------------------------------- migration

# The exact v1 schema subset a database written before this addendum would contain,
# together with rows in the tables a real install fills. Deliberately written out here
# rather than imported from db.SCHEMA_V1: the point of the test is that a database
# created by *the previous release* still upgrades, so it must not track future edits.
V1_SQL = """
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE devices (
    id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT, hostname TEXT, vendor TEXT, kind TEXT,
    nickname TEXT, trusted INTEGER NOT NULL DEFAULT 0, notes TEXT, first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, online INTEGER NOT NULL DEFAULT 1, last_service_scan TEXT,
    mdns_services TEXT);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, subject TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT,
    evidence TEXT, status TEXT NOT NULL DEFAULT 'open', source TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT,
    occurrences INTEGER NOT NULL DEFAULT 1, device_id INTEGER REFERENCES devices(id));
CREATE TABLE events (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT NOT NULL,
    message TEXT NOT NULL, data TEXT);
INSERT INTO schema_migrations(version, applied_at) VALUES (1, '2026-01-01T00:00:00Z');
INSERT INTO settings(key, value, updated_at) VALUES ('dns.enabled', 'true', '2026-01-01T00:00:00Z');
INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online)
  VALUES (1, '00:11:22:33:44:55', '192.168.10.1', 'gateway', 'Example Networks', 'router',
          'Front room router', 1, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 1);
INSERT INTO devices(id, mac, ip, hostname, vendor, kind, nickname, trusted, first_seen, last_seen, online)
  VALUES (2, '00:11:22:33:44:66', '192.168.10.20', 'printer', 'Example Print', 'printer',
          'Study printer', 0, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 0);
INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, status, source, first_seen, last_seen)
  VALUES ('NET-SVC-001', 'device:00:11:22:33:44:66:23', 'NET-SVC-001|device:00:11:22:33:44:66:23',
          'critical', 'Telnet is open', 'open', 'services', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z');
INSERT INTO events(ts, level, source, message) VALUES ('2026-01-01T00:00:00Z', 'info', 'cli', 'initialised');
"""


def _make_v1_database(path: Path) -> None:
    old = sqlite3.connect(str(path))
    try:
        old.executescript(V1_SQL)
        old.commit()
    finally:
        old.close()


def test_v1_database_upgrades_and_keeps_its_rows(tmp_path: Path) -> None:
    """B5: this is the project's first real migration; an existing install must survive it."""
    path = tmp_path / "homesoc.db"
    _make_v1_database(path)

    conn = db.connect(path)
    try:
        assert db.schema_version(conn) == db.SCHEMA_VERSION
        versions = [int(r["version"]) for r in db.query(conn, "SELECT version FROM schema_migrations ORDER BY version")]
        # Every migration ran, in order, starting from the one this v1 database already had.
        # Written against db.MIGRATIONS rather than a literal so that adding migration 3
        # (SPEC addendum C5) — or 4 — does not break the thing this test is actually about,
        # which is that a v1 install survives the upgrade with its rows.
        assert versions == [version for version, _ddl in db.MIGRATIONS]
        assert versions[:2] == [1, 2]
        # Every pre-existing row is still there, unchanged.
        devices = db.rows_to_dicts(db.query(conn, "SELECT * FROM devices ORDER BY id"))
        assert [d["nickname"] for d in devices] == ["Front room router", "Study printer"]
        assert devices[0]["trusted"] == 1 and devices[1]["online"] == 0
        assert db.one(conn, "SELECT COUNT(*) AS n FROM findings")["n"] == 1
        assert db.get_setting(conn, "dns.enabled") == "true"
        assert db.one(conn, "SELECT COUNT(*) AS n FROM events")["n"] == 1
        # And the new tables are usable, including the foreign key into the old rows.
        db.write(conn, "INSERT INTO lens_tags(code, kind, device_id, created_at, created_by) VALUES (?,?,?,?,?)",
                 ("hs1:MigratedTagAaaaaaaaaa", "sticker", 2, "2026-09-13T00:00:00Z", "test"))
        assert db.one(conn, "SELECT device_id FROM lens_tags")["device_id"] == 2
        token = db.lens_mint_token(conn, label="phone")
        assert db.lens_verify_token(conn, token["token"]) is not None
        # Running it again changes nothing (start-up calls init_schema every time).
        db.init_schema(conn)
        assert db.schema_version(conn) == db.SCHEMA_VERSION
        assert db.one(conn, "SELECT COUNT(*) AS n FROM schema_migrations")["n"] == len(db.MIGRATIONS)
        assert db.one(conn, "SELECT COUNT(*) AS n FROM lens_tags")["n"] == 1
    finally:
        conn.close()


def test_v1_database_with_foreign_keys_on_still_migrates(tmp_path: Path) -> None:
    """The connection turns foreign keys on before init_schema; the new table references
    devices(id), so a badly ordered migration would fail here rather than in production."""
    path = tmp_path / "fk.db"
    _make_v1_database(path)
    conn = db.connect(path)
    try:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
    finally:
        conn.close()


# --------------------------------------------------------------------------- tokens


def test_token_is_shown_once_and_stored_only_as_a_hash(conn: sqlite3.Connection) -> None:
    minted = db.lens_mint_token(conn, label="Hallway phone", scopes="read")
    token = minted["token"]
    assert len(token) >= 40  # 32 bytes url-safe
    row = db.one(conn, "SELECT * FROM lens_tokens WHERE id = ?", (minted["id"],))
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    # The secret itself appears nowhere in the database.
    dumped = "\n".join(str(line) for line in conn.iterdump())
    assert token not in dumped
    # ...nor in anything the API would hand back.
    assert "token_hash" not in db.lens_list_tokens(conn)[0]
    assert "token" not in db.lens_list_tokens(conn)[0]


def test_verify_accepts_only_the_real_token(conn: sqlite3.Connection) -> None:
    minted = db.lens_mint_token(conn, label="phone")
    token = minted["token"]
    assert db.lens_verify_token(conn, token)["id"] == minted["id"]
    for wrong in (None, "", "   ", token[:-1], token + "x", token.upper(), "x" * 600,
                  hashlib.sha256(token.encode()).hexdigest()):
        assert db.lens_verify_token(conn, wrong) is None


def test_verify_records_last_seen_and_ip(conn: sqlite3.Connection) -> None:
    minted = db.lens_mint_token(conn, label="phone")
    assert minted["last_seen_at"] is None and minted["last_ip"] is None
    seen = db.lens_verify_token(conn, minted["token"], ip=PHONE_IP)
    assert seen["last_ip"] == PHONE_IP and seen["last_seen_at"]
    # touch=False leaves the row alone, for callers that only want a yes/no.
    db.write(conn, "UPDATE lens_tokens SET last_ip = NULL WHERE id = ?", (minted["id"],))
    db.lens_verify_token(conn, minted["token"], ip=PHONE_IP, touch=False)
    assert db.one(conn, "SELECT last_ip FROM lens_tokens WHERE id = ?", (minted["id"],))["last_ip"] is None


def test_revocation_is_immediate_and_idempotent(conn: sqlite3.Connection) -> None:
    minted = db.lens_mint_token(conn, label="lost phone")
    assert db.lens_revoke_token(conn, minted["id"]) is True
    assert db.lens_verify_token(conn, minted["token"]) is None
    assert db.lens_revoke_token(conn, minted["id"]) is False  # already revoked
    assert db.lens_revoke_token(conn, 9999) is False
    listed = db.lens_list_tokens(conn)[0]
    assert listed["revoked_at"] and listed["active"] is False
    assert db.lens_list_tokens(conn, include_revoked=False) == []


def test_revoke_all(conn: sqlite3.Connection) -> None:
    tokens = [db.lens_mint_token(conn, label=f"phone {i}") for i in range(3)]
    assert db.lens_revoke_all_tokens(conn) == 3
    assert db.lens_revoke_all_tokens(conn) == 0
    for token in tokens:
        assert db.lens_verify_token(conn, token["token"]) is None


def test_expiry(conn: sqlite3.Connection) -> None:
    minted = db.lens_mint_token(conn, label="phone", ttl_days=90)
    assert minted["expires_at"] > db.utcnow_iso()
    db.write(conn, "UPDATE lens_tokens SET expires_at = ? WHERE id = ?",
             ("2020-01-01T00:00:00Z", minted["id"]))
    assert db.lens_verify_token(conn, minted["token"]) is None
    assert db.lens_active_tokens(conn) == []
    assert db.lens_list_tokens(conn)[0]["active"] is False


def test_ttl_zero_never_expires(conn: sqlite3.Connection) -> None:
    minted = db.lens_mint_token(conn, label="phone", ttl_days=0)
    assert minted["expires_at"] is None
    assert db.lens_verify_token(conn, minted["token"]) is not None


def test_max_tokens_is_enforced_and_freed_by_revocation(conn: sqlite3.Connection) -> None:
    first = db.lens_mint_token(conn, label="a", max_tokens=2)
    db.lens_mint_token(conn, label="b", max_tokens=2)
    with pytest.raises(db.LensTokenLimit) as excinfo:
        db.lens_mint_token(conn, label="c", max_tokens=2)
    assert "revoke" in str(excinfo.value)  # the message says how to fix it
    db.lens_revoke_token(conn, first["id"])
    assert db.lens_mint_token(conn, label="c", max_tokens=2)["id"]
    # An expired token does not occupy a slot either.
    db.write(conn, "UPDATE lens_tokens SET expires_at = '2020-01-01T00:00:00Z' WHERE label = 'b'")
    assert db.lens_mint_token(conn, label="d", max_tokens=2)["id"]


def test_scopes(conn: sqlite3.Connection) -> None:
    assert db.lens_normalise_scopes("read") == "read"
    assert db.lens_normalise_scopes("act") == "read,act"       # act never stands alone
    assert db.lens_normalise_scopes("read,act") == "read,act"
    assert db.lens_normalise_scopes("act read") == "read,act"  # canonical order
    assert db.lens_normalise_scopes(["READ", "ACT"]) == "read,act"
    assert db.lens_normalise_scopes("root,admin") == "read"    # unknown scopes are dropped
    assert db.lens_normalise_scopes(None) == "read"
    read_only = db.lens_mint_token(conn, label="phone", scopes="read")
    assert db.lens_has_scope(read_only["scopes"], "read") is True
    assert db.lens_has_scope(read_only["scopes"], "act") is False
    acting = db.lens_mint_token(conn, label="tablet", scopes="read,act")
    assert db.lens_has_scope(acting["scopes"], "act") is True


def test_minting_is_audited(conn: sqlite3.Connection) -> None:
    minted = db.lens_mint_token(conn, label="Hallway phone")
    rows = db.query(conn, "SELECT * FROM events WHERE source = 'lens' ORDER BY id")
    assert any("Hallway phone" in str(r["message"]) for r in rows)
    db.lens_revoke_token(conn, minted["id"])
    assert any("revoked" in str(r["message"]) for r in db.query(conn, "SELECT * FROM events WHERE source='lens'"))
    # The event payload never carries the token itself.
    assert all(minted["token"] not in str(r["data"] or "") for r in
               db.query(conn, "SELECT data FROM events"))


def test_a_phone_supplied_label_cannot_forge_a_row_in_the_token_listing(conn: sqlite3.Connection) -> None:
    """The label arrives in the /api/lens/claim body, is stored, written into an events row, and
    printed by `python -m homesoc lens tokens` in a fixed-width table. CR/LF and ANSI escapes in
    it would let whoever holds a pairing code forge or hide a row in the owner's audit output."""
    hostile = "ok\x1b[31mRED\x1b[0m\r\nfake row\x00"
    minted = db.lens_mint_token(conn, label=hostile)
    stored = str(db.one(conn, "SELECT label FROM lens_tokens WHERE id=?", (minted["id"],))["label"])
    assert stored == "ok[31mRED[0mfake row"
    assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in stored)
    message = str(db.one(conn, "SELECT message FROM events WHERE source='lens' ORDER BY id DESC")["message"])
    assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in message)
    # A label made only of control characters still gets a usable name rather than an empty cell.
    assert db.lens_mint_token(conn, label="\r\n\x00")["label"] == "phone"


# -------------------------------------------------------------------- pairing codes


def test_pairing_code_shape(conn: sqlite3.Connection) -> None:
    code = db.lens_new_pairing_code(conn)
    assert len(code) == db.LENS_PAIRING_LENGTH == 8
    assert set(code) <= set(db.LENS_PAIRING_ALPHABET)
    assert not (set(code) & set("01OIL"))  # nothing anybody can mistype
    # Stored only as a hash, like the tokens.
    stored = db.settings_with_prefix(conn, PAIRING_PREFIX)
    assert list(stored) == [PAIRING_PREFIX + hashlib.sha256(code.encode()).hexdigest()]
    assert all(code not in key and code not in value for key, value in stored.items())


def test_pairing_code_is_single_use(conn: sqlite3.Connection) -> None:
    code = db.lens_new_pairing_code(conn)
    assert db.lens_consume_pairing_code(conn, code) is True
    assert db.lens_consume_pairing_code(conn, code) is False
    assert db.settings_with_prefix(conn, PAIRING_PREFIX) == {}


def test_pairing_code_is_forgiving_about_typing(conn: sqlite3.Connection) -> None:
    code = db.lens_new_pairing_code(conn)
    typed = f" {code[:4].lower()}-{code[4:].lower()} "
    assert db.lens_consume_pairing_code(conn, typed) is True


def test_wrong_pairing_code_is_refused(conn: sqlite3.Connection) -> None:
    db.lens_new_pairing_code(conn)
    for wrong in (None, "", "ZZZZZZZZ", "22222222", "x" * 200):
        assert db.lens_consume_pairing_code(conn, wrong) is False
    assert len(db.settings_with_prefix(conn, PAIRING_PREFIX)) == 1  # a miss does not consume


def test_expired_pairing_code_is_refused_and_swept(conn: sqlite3.Connection) -> None:
    code = db.lens_new_pairing_code(conn)
    key = next(iter(db.settings_with_prefix(conn, PAIRING_PREFIX)))
    state = json.loads(db.get_setting(conn, key))
    db.set_setting(conn, key, {**state, "expires_at": "2020-01-01T00:00:00Z"})
    assert db.lens_consume_pairing_code(conn, code) is False
    assert db.settings_with_prefix(conn, PAIRING_PREFIX) == {}  # swept on the way past


def test_minting_a_new_code_retires_the_old_one(conn: sqlite3.Connection) -> None:
    first = db.lens_new_pairing_code(conn)
    second = db.lens_new_pairing_code(conn)
    assert first != second
    assert db.lens_consume_pairing_code(conn, first) is False
    assert db.lens_consume_pairing_code(conn, second) is True


def test_default_pairing_ttl_is_five_minutes(conn: sqlite3.Connection) -> None:
    assert db.LENS_PAIRING_TTL_SECONDS == 300
    db.lens_new_pairing_code(conn)
    state = json.loads(next(iter(db.settings_with_prefix(conn, PAIRING_PREFIX).values())))
    created = dt.datetime.fromisoformat(state["created_at"].replace("Z", "+00:00"))
    expires = dt.datetime.fromisoformat(state["expires_at"].replace("Z", "+00:00"))
    assert 290 <= (expires - created).total_seconds() <= 310


# ---------------------------------------------------------------------- rate limit


def test_claim_rate_limit(conn: sqlite3.Connection) -> None:
    """B4: ten attempts an hour per source, then an hour of refusal and an events row."""
    for attempt in range(db.LENS_CLAIM_LIMIT):
        allowed, retry_after = db.lens_claim_attempt(conn, PHONE_IP)
        assert allowed is True and retry_after == 0, f"attempt {attempt + 1} should be allowed"
    allowed, retry_after = db.lens_claim_attempt(conn, PHONE_IP)
    assert allowed is False and retry_after == db.LENS_CLAIM_WINDOW_SECONDS
    allowed, retry_after = db.lens_claim_attempt(conn, PHONE_IP)
    assert allowed is False and 0 < retry_after <= db.LENS_CLAIM_WINDOW_SECONDS
    events = db.query(conn, "SELECT * FROM events WHERE source = 'lens' AND level = 'warning'")
    assert len(events) == 1 and "pairing attempts" in str(events[0]["message"])


def test_claim_rate_limit_is_per_source(conn: sqlite3.Connection) -> None:
    for _ in range(db.LENS_CLAIM_LIMIT + 1):
        db.lens_claim_attempt(conn, PHONE_IP)
    assert db.lens_claim_attempt(conn, PHONE_IP)[0] is False
    assert db.lens_claim_attempt(conn, "192.168.10.43")[0] is True
    assert db.lens_claim_attempt(conn, None)[0] is True  # an unknown source is its own bucket


def test_claim_counter_stores_no_address(conn: sqlite3.Connection) -> None:
    db.lens_claim_attempt(conn, PHONE_IP)
    stored = db.settings_with_prefix(conn, "lens.claim.")
    assert len(stored) == 1
    assert all(PHONE_IP not in key and PHONE_IP not in value for key, value in stored.items())


def test_successful_claim_resets_the_counter(conn: sqlite3.Connection) -> None:
    for _ in range(3):
        db.lens_claim_attempt(conn, PHONE_IP)
    db.lens_claim_reset(conn, PHONE_IP)
    assert db.settings_with_prefix(conn, "lens.claim.") == {}
    for _ in range(db.LENS_CLAIM_LIMIT):
        assert db.lens_claim_attempt(conn, PHONE_IP)[0] is True


def test_claim_window_rolls_over(conn: sqlite3.Connection) -> None:
    for _ in range(db.LENS_CLAIM_LIMIT):
        db.lens_claim_attempt(conn, PHONE_IP)
    key = next(iter(db.settings_with_prefix(conn, "lens.claim.")))
    state = json.loads(db.get_setting(conn, key))
    db.set_setting(conn, key, {**state, "window_start": "2020-01-01T00:00:00Z"})
    assert db.lens_claim_attempt(conn, PHONE_IP)[0] is True  # a new hour, a new allowance


def test_claim_counters_are_purged_by_housekeeping(cfg: config.Config, conn: sqlite3.Connection) -> None:
    db.lens_claim_attempt(conn, PHONE_IP)
    key = next(iter(db.settings_with_prefix(conn, "lens.claim.")))
    assert db.lens_purge_claim_counters(conn) == 0  # still current
    db.set_setting(conn, key, {"window_start": "2020-01-01T00:00:00Z", "count": 1, "blocked_until": ""})
    assert cli.housekeeping(cfg, conn)["lens_claim_counters"] == 1
    assert db.settings_with_prefix(conn, "lens.claim.") == {}


# ---------------------------------------------------------------------------- TLS


@needs_cryptography
def test_certificate_is_parseable_and_covers_every_host(data_dir: Path) -> None:
    cert, key = tls.ensure_cert([LAN_IP, "homesoc-pc"])
    assert cert.is_file() and key.is_file()
    assert cert.parent == data_dir / "tls"
    info = tls.cert_info(cert)
    assert set(info["sans"]) == {LAN_IP, "homesoc-pc", "localhost", "127.0.0.1", "::1"}
    assert info["days_left"] > 800
    assert info["fingerprint"] == tls.cert_fingerprint_sha256(cert)
    assert info["not_before"] < info["not_after"]
    assert "Home SOC" in info["subject"]


@needs_cryptography
def test_certificate_is_loadable_by_the_ssl_module(data_dir: Path) -> None:
    """The proof that Flask can actually serve it: the stdlib accepts the pair."""
    import ssl

    cert, key = tls.ensure_cert([LAN_IP])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))  # raises if the pair does not match
    # A client can pin it, which is what the phone effectively does after the warning.
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(str(cert))
    assert client.cert_store_stats()["x509"] == 1

    # Regenerating replaces both halves: the previous key no longer opens the new cert.
    stale_key = key.with_name("previous-key.pem")
    stale_key.write_bytes(key.read_bytes())
    tls.ensure_cert([LAN_IP], force=True)
    with pytest.raises(ssl.SSLError):
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(cert), str(stale_key))
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(cert), str(key))


@needs_cryptography
def test_wildcard_bind_addresses_are_not_put_in_the_certificate(data_dir: Path) -> None:
    names, addresses = tls.normalise_hosts(["0.0.0.0", "::", LAN_IP, "", None, "HomeSOC-PC"])
    assert "0.0.0.0" not in addresses and "::" not in addresses
    assert names == ["homesoc-pc", "localhost"] and LAN_IP in addresses
    cert, _key = tls.ensure_cert(["0.0.0.0", LAN_IP])
    assert "0.0.0.0" not in tls.cert_info(cert)["sans"]


@needs_cryptography
def test_ensure_cert_is_idempotent(data_dir: Path) -> None:
    cert, key = tls.ensure_cert([LAN_IP])
    first = cert.read_bytes(), key.read_bytes()
    tls.ensure_cert([LAN_IP])
    assert (cert.read_bytes(), key.read_bytes()) == first
    tls.ensure_cert([LAN_IP], force=True)
    assert cert.read_bytes() != first[0]


@needs_cryptography
def test_ensure_cert_regenerates_when_a_host_is_missing(data_dir: Path) -> None:
    cert, _key = tls.ensure_cert([LAN_IP])
    before = cert.read_bytes()
    tls.ensure_cert([LAN_IP, "192.168.10.9"])
    assert cert.read_bytes() != before
    assert "192.168.10.9" in tls.cert_info(cert)["sans"]


@needs_cryptography
def test_ensure_cert_renews_a_certificate_that_is_about_to_expire(data_dir: Path) -> None:
    cert, _key = tls.ensure_cert([LAN_IP], days=1)
    assert tls.cert_info(cert)["days_left"] <= tls.RENEW_WITHIN_DAYS
    before = cert.read_bytes()
    tls.ensure_cert([LAN_IP])  # no force: the expiry alone triggers it
    assert cert.read_bytes() != before
    assert tls.cert_info(cert)["days_left"] > tls.RENEW_WITHIN_DAYS


@needs_cryptography
def test_fingerprint_needs_no_optional_package(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cert, _key = tls.ensure_cert([LAN_IP])
    expected = hashlib.sha256(tls.certificate_der(cert)).hexdigest().upper()
    monkeypatch.setitem(sys.modules, "cryptography", None)
    assert tls.available() is False
    fingerprint = tls.cert_fingerprint_sha256(cert)
    assert fingerprint.replace(":", "") == expected
    assert len(fingerprint.split(":")) == 32 and fingerprint.isupper()


def test_missing_cryptography_raises_tls_unavailable_with_a_useful_message(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B11: simulate the package being absent by patching the import."""
    monkeypatch.setitem(sys.modules, "cryptography", None)
    with pytest.raises(tls.TlsUnavailable) as excinfo:
        tls.ensure_cert([LAN_IP])
    message = str(excinfo.value)
    assert "pip install cryptography" in message
    assert "Tailscale" in message and "docs/LENS_SETUP.md" in message
    with pytest.raises(tls.TlsUnavailable):
        tls.cert_info(tls.cert_paths()[0])


@needs_cryptography
def test_describe_never_raises(data_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tls.describe()
    assert missing["exists"] is False and missing["note"]
    cert, _key = tls.ensure_cert([LAN_IP])
    present = tls.describe()
    assert present["exists"] is True and present["fingerprint"] and present["days_left"] > 0
    cert.write_text("not a certificate at all", encoding="utf-8")
    broken = tls.describe()
    assert broken["exists"] is True and "cannot be read" in broken["note"]
    monkeypatch.setitem(sys.modules, "cryptography", None)
    assert tls.describe()["cryptography"] is False


@needs_cryptography
def test_private_key_is_not_world_readable(data_dir: Path) -> None:
    _cert, key = tls.ensure_cert([LAN_IP])
    mode = key.stat().st_mode & 0o777
    # POSIX enforces this; Windows reports 0o666 and inherits the data directory's ACL.
    assert mode & 0o077 == 0 or sys.platform == "win32"
    assert b"PRIVATE KEY" in key.read_bytes()
    assert b"PRIVATE KEY" not in _cert.read_bytes()


def test_certificate_der_rejects_rubbish(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("hello", encoding="utf-8")
    with pytest.raises(ValueError):
        tls.certificate_der(bad)
    bad.write_text("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", encoding="utf-8")
    with pytest.raises(ValueError):
        tls.certificate_der(bad)


def test_homesoc_still_imports_without_cryptography(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole point of the optional extra: nothing else may depend on it."""
    monkeypatch.setitem(sys.modules, "cryptography", None)
    import importlib

    for module in ("homesoc.db", "homesoc.config", "homesoc.cli", "homesoc.web.tls",
                   "homesoc.web.qr", "homesoc.web.app"):
        assert importlib.reload(importlib.import_module(module)) is not None


# ---------------------------------------------------------------------------- CLI


def _args(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


def _ctx(cfg: config.Config, conn: sqlite3.Connection, **kwargs) -> cli.Context:
    return cli.Context(_args(**kwargs), cfg, conn)


def test_parser_accepts_the_lens_commands() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["lens", "pair", "--host", LAN_IP, "--port", "8443", "--invert"])
    assert (args.command, args.lens_command, args.host, args.port, args.invert) == \
        ("lens", "pair", LAN_IP, 8443, True)
    assert parser.parse_args(["lens", "tokens"]).lens_command == "tokens"
    assert parser.parse_args(["lens", "revoke", "3"]).id == 3
    assert parser.parse_args(["lens", "revoke", "--all"]).all is True
    assert parser.parse_args(["lens", "cert", "--regenerate", "--hosts", "a,b"]).hosts == "a,b"
    assert parser.parse_args(["serve", "--tls"]).tls is True
    assert parser.parse_args(["run", "--tls"]).tls is True
    assert parser.parse_args(["run"]).tls is False


def test_lens_without_an_action_is_a_usage_error(data_dir: Path) -> None:
    assert cli.main(["lens"]) == cli.EXIT_USAGE


def test_pair_url_keeps_the_code_out_of_the_query_string(cfg: config.Config) -> None:
    """B10: no device data - and no secret - in a URL the server ever sees."""
    url = cli.lens_pair_url(cfg, "ABCD2345", host=LAN_IP, port=8443)
    assert url == f"https://{LAN_IP}:8443/lens/claim#c=ABCD2345"
    path, _, fragment = url.partition("#")
    assert "?" not in path and "ABCD2345" not in path and fragment == "c=ABCD2345"


def test_lens_hosts_and_display_host(cfg: config.Config) -> None:
    exposed = config.with_overrides(cfg, {"web.host": "0.0.0.0"})
    hosts = cli.lens_hosts(exposed)
    assert "0.0.0.0" not in hosts and hosts, "the wildcard is not a name a certificate can carry"
    assert cli.lens_display_host(exposed) not in cli.WILDCARD_HOSTS
    assert cli.lens_display_host(cfg, host=LAN_IP) == LAN_IP
    assert cli.lens_hosts(cfg, host=LAN_IP)[0] == LAN_IP


def test_dashboard_url_scheme_follows_tls(cfg: config.Config) -> None:
    assert cli.dashboard_url(cfg, "127.0.0.1", 8787).startswith("http://")
    assert cli.dashboard_url(cfg, "127.0.0.1", 8443, tls=True).startswith("https://")


def test_qr_ascii_is_scannable_text(cfg: config.Config) -> None:
    from homesoc.web import qr

    url = cli.lens_pair_url(cfg, "ABCD2345", host=LAN_IP, port=8443)
    rendered = cli.qr_ascii(url)
    assert rendered and rendered.count("\n") > 20
    size = qr.encode(url).size
    assert len(rendered.splitlines()) == size + 4  # default quiet zone of 2
    inverted = cli.qr_ascii(url, invert=True)
    assert inverted and inverted != rendered


def test_pair_refuses_while_lens_is_off(cfg: config.Config, conn: sqlite3.Connection, capsys) -> None:
    ctx = _ctx(cfg, conn, host=None, port=None, invert=False)
    assert cli.cmd_lens_pair(ctx) == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert "switched off" in out and "enabled = true" in out
    assert db.settings_with_prefix(conn, PAIRING_PREFIX) == {}, "no code is minted on the refusal path"


def test_pair_refuses_a_loopback_binding(cfg: config.Config, conn: sqlite3.Connection, capsys) -> None:
    enabled = config.with_overrides(cfg, {"lens.enabled": True, "web.host": "127.0.0.1"})
    assert cli.cmd_lens_pair(_ctx(enabled, conn, host=None, port=None, invert=False)) == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert "only this machine can reach" in out and '0.0.0.0' in out


def test_recorded_bind_prefers_where_the_server_actually_listens(
    cfg: config.Config, conn: sqlite3.Connection
) -> None:
    """``serve --host/--port`` beats config.toml, and the CLI must read it the same way
    :func:`homesoc.web.app.effective_bind` does — otherwise the two halves of the product
    disagree about whether a phone can reach this machine."""
    loopback = config.with_overrides(cfg, {"web.host": "127.0.0.1", "web.port": 8787})
    assert cli.recorded_bind(conn, loopback) == ("127.0.0.1", 8787), "no key: fall back to config"
    cli.record_bind_state(conn, "0.0.0.0", 8443)
    assert cli.recorded_bind(conn, loopback) == ("0.0.0.0", 8443)
    assert cli.recorded_bind(None, loopback) == ("127.0.0.1", 8787), "no connection: config only"
    db.set_setting(conn, cli.BIND_SETTING, "nonsense-without-a-port")
    assert cli.recorded_bind(conn, loopback) == ("127.0.0.1", 8787), "a junk value is ignored"


@needs_cryptography
def test_pair_uses_the_recorded_bind_not_stale_config(
    cfg: config.Config, conn: sqlite3.Connection, capsys
) -> None:
    """Regression: `serve --tls --host 0.0.0.0 --port 8443` (SPEC B3's own invocation) left
    config.toml saying 127.0.0.1, so `lens pair` refused — "web.host is 127.0.0.1" — while
    /lens/pair in the browser minted a code against the very same running server."""
    enabled = config.with_overrides(cfg, {"lens.enabled": True, "web.host": "127.0.0.1", "web.port": 8787})
    assert cli.cmd_lens_pair(_ctx(enabled, conn, host=None, port=None, invert=False)) == cli.EXIT_ERROR
    assert "only this machine can reach" in capsys.readouterr().out
    cli.record_bind_state(conn, "0.0.0.0", 8443)
    assert cli.cmd_lens_pair(_ctx(enabled, conn, host=None, port=None, invert=False)) == cli.EXIT_OK
    out = capsys.readouterr().out
    link = next(line for line in out.splitlines() if "/lens/claim#c=" in line)
    assert ":8443/lens/claim#c=" in link
    assert "0.0.0.0" not in link, "the wildcard is not an address a phone can dial"


@needs_cryptography
def test_pair_prints_everything_the_phone_needs(cfg: config.Config, conn: sqlite3.Connection, capsys) -> None:
    enabled = config.with_overrides(cfg, {"lens.enabled": True, "web.host": "0.0.0.0", "web.port": 8443})
    assert cli.cmd_lens_pair(_ctx(enabled, conn, host=LAN_IP, port=8443, invert=False)) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert f"https://{LAN_IP}:8443/lens/claim#c=" in out
    assert "single use, valid 5 minutes" in out
    assert "Certificate SHA-256:" in out
    assert tls.cert_fingerprint_sha256(tls.cert_paths()[0]) in out
    assert "read-only" in out  # allow_actions is false
    # The code on screen is the one the database will accept, exactly once.
    code = next(line.split(":", 1)[1].split("(")[0].strip()
                for line in out.splitlines() if line.startswith("Pairing code:"))
    assert db.lens_consume_pairing_code(conn, code) is True
    assert db.lens_consume_pairing_code(conn, code) is False


def test_pair_reports_a_missing_optional_package_instead_of_crashing(
    cfg: config.Config, conn: sqlite3.Connection, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "cryptography", None)
    enabled = config.with_overrides(cfg, {"lens.enabled": True, "web.host": "0.0.0.0"})
    assert cli.cmd_lens_pair(_ctx(enabled, conn, host=LAN_IP, port=8443, invert=False)) == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert "pip install cryptography" in out
    assert db.settings_with_prefix(conn, PAIRING_PREFIX) == {}


def test_tokens_command(cfg: config.Config, conn: sqlite3.Connection, capsys) -> None:
    assert cli.cmd_lens_tokens(_ctx(cfg, conn)) == cli.EXIT_OK
    assert "no phones paired" in capsys.readouterr().out
    minted = db.lens_mint_token(conn, label="Hallway phone", scopes="read,act")
    db.lens_verify_token(conn, minted["token"], ip=PHONE_IP)
    revoked = db.lens_mint_token(conn, label="Old phone")
    db.lens_revoke_token(conn, revoked["id"])
    assert cli.cmd_lens_tokens(_ctx(cfg, conn)) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "Hallway phone" in out and "read,act" in out and "active" in out
    assert "Old phone" in out and "revoked" in out
    assert PHONE_IP in out
    assert minted["token"] not in out, "the secret is never shown twice"
    assert "1 active of a maximum of 10" in out


def test_revoke_command(cfg: config.Config, conn: sqlite3.Connection, capsys) -> None:
    minted = db.lens_mint_token(conn, label="phone")
    assert cli.cmd_lens_revoke(_ctx(cfg, conn, id=minted["id"], all=False)) == cli.EXIT_OK
    assert cli.cmd_lens_revoke(_ctx(cfg, conn, id=minted["id"], all=False)) == cli.EXIT_ERROR
    assert cli.cmd_lens_revoke(_ctx(cfg, conn, id=None, all=False)) == cli.EXIT_USAGE
    db.lens_mint_token(conn, label="another")
    db.lens_new_pairing_code(conn)
    assert cli.cmd_lens_revoke(_ctx(cfg, conn, id=None, all=True)) == cli.EXIT_OK
    assert db.lens_active_tokens(conn) == []
    assert db.settings_with_prefix(conn, PAIRING_PREFIX) == {}, "revoke --all also kills pending codes"
    assert "revoked" in capsys.readouterr().out


@needs_cryptography
def test_cert_command(cfg: config.Config, conn: sqlite3.Connection, capsys) -> None:
    assert cli.cmd_lens_cert(_ctx(cfg, conn, regenerate=False, hosts=None)) == cli.EXIT_ERROR
    assert "No certificate yet" in capsys.readouterr().out
    ctx = _ctx(cfg, conn, regenerate=True, hosts=f"{LAN_IP},homesoc-pc")
    assert cli.cmd_lens_cert(ctx) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "fingerprint (SHA-256):" in out and LAN_IP in out and "days left" in out
    assert cli.cmd_lens_cert(_ctx(cfg, conn, regenerate=False, hosts=None)) == cli.EXIT_OK
    assert tls.cert_fingerprint_sha256(tls.cert_paths()[0]) in capsys.readouterr().out


def test_cert_command_without_cryptography(
    cfg: config.Config, conn: sqlite3.Connection, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "cryptography", None)
    assert cli.cmd_lens_cert(_ctx(cfg, conn, regenerate=True, hosts=None)) == cli.EXIT_ERROR
    assert "pip install cryptography" in capsys.readouterr().out


def test_soc_lens_001_fires_only_for_lens_on_the_lan_without_tls(
    cfg: config.Config, conn: sqlite3.Connection
) -> None:
    """B10, and it must not contradict SOC-SYS-003: one is about no password, this one
    about the whole conversation crossing the Wi-Fi in clear text."""
    def ids(c: config.Config) -> set[str]:
        return {d.finding_id for d in cli.soc_health_drafts(c, conn, None)}

    from homesoc.findings import catalog

    spec = catalog.get("SOC-LENS-001")
    # B10's last bullet: the finding must not contradict itself. With the shipped default
    # (require_https = true) nothing crosses the network at all, because Lens refuses to serve
    # plain HTTP off this machine — so the description says which case is which rather than
    # asserting the worse one as fact, and its own last fix step no longer argues with it.
    assert "While lens.require_https is true" in spec.rationale
    assert "unusable until you start with --tls" in spec.rationale
    assert "If you turn require_https off" in spec.rationale

    assert "SOC-LENS-001" not in ids(cfg)  # lens off, loopback only
    lan = config.with_overrides(cfg, {"lens.enabled": True, "web.host": "0.0.0.0", "web.token": "x"})
    assert "SOC-LENS-001" in ids(lan)
    assert "SOC-SYS-003" not in ids(lan), "a token is set, so the other finding stays quiet"
    assert "SOC-LENS-001" not in ids(config.with_overrides(lan, {"web.host": "127.0.0.1"}))
    assert "SOC-LENS-001" not in ids(config.with_overrides(lan, {"lens.enabled": False}))

    # Starting with --tls records it, and the finding goes away on the next health pass.
    cli.record_tls_state(conn, True)
    assert cli.tls_last_used(conn) is True
    assert "SOC-LENS-001" not in ids(lan)
    cli.record_tls_state(conn, False)
    assert "SOC-LENS-001" in ids(lan)
    # The marker is not a configuration key, so it never leaks into the [lens] section.
    assert config.is_config_key(cli.TLS_SETTING) is False
    assert config.load(conn).lens.enabled is False

    draft = next(d for d in cli.soc_health_drafts(lan, conn, None) if d.finding_id == "SOC-LENS-001")
    assert draft.subject == "host" and draft.evidence["tls"] is False
    # Recorded because it decides which half of the description applies.
    assert draft.evidence["require_https"] is True
    relaxed = next(d for d in cli.soc_health_drafts(
        config.with_overrides(lan, {"lens.require_https": False}), conn, None)
        if d.finding_id == "SOC-LENS-001")
    assert relaxed.evidence["require_https"] is False


def test_serve_with_tls_reports_a_missing_package_rather_than_starting(
    cfg: config.Config, conn: sqlite3.Connection, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "cryptography", None)
    rt = cli.Runtime(config.with_overrides(cfg, {"web.host": "0.0.0.0"}), conn)
    assert cli._serve_forever(rt, "0.0.0.0", 0, tls=True) == cli.EXIT_ERROR
    assert "pip install cryptography" in capsys.readouterr().out
