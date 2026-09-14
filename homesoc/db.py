"""SQLite access layer and the complete schema for every package.

One connection is shared by the scheduler thread, the DNS server threads and
Flask request threads, so **every** statement — read or write — goes through
the helpers here under a module-level ``RLock``.

Reads are not exempt, and this is the part that is easy to get wrong. WAL lets
separate *connections* read during a write, but this process has one connection,
and ``sqlite3`` keeps statement state on the connection object. Two threads
calling ``conn.execute`` concurrently do not politely queue: they tread on each
other's cursors. That showed up as ``InterfaceError('no more rows available')``
and ``('bad parameter or other API misuse')`` and, far worse, as :func:`one`
returning ``None`` for a row that plainly exists — a silent wrong answer rather
than a crash. A stress harness of eight threads over 120 trials went from ~160
failures to zero once reads took the lock.

So do not "optimise" the lock out of :func:`query`/:func:`one`. If read
throughput ever genuinely matters, give each thread its own connection instead.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import sqlite3
import threading
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from homesoc import paths
from homesoc.util import json_dumps, utcnow_iso
from homesoc.util import parse_iso as util_parse_iso
from homesoc.util import to_iso as util_to_iso

logger = logging.getLogger(__name__)

_WRITE_LOCK = threading.RLock()

SCHEMA_VERSION = 4

# Complete schema (spec §4). Column order and names are normative — other packages
# write INSERTs against them. Keep DDL idempotent so init_schema can run at every start.
SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feeds (
    name          TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    kind          TEXT NOT NULL,
    etag          TEXT,
    last_modified TEXT,
    last_checked  TEXT,
    last_updated  TEXT,
    status        TEXT NOT NULL DEFAULT 'never',
    bytes         INTEGER,
    entries       INTEGER,
    error         TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS devices (
    id                INTEGER PRIMARY KEY,
    mac               TEXT UNIQUE,
    ip                TEXT,
    hostname          TEXT,
    vendor            TEXT,
    kind              TEXT,
    nickname          TEXT,
    trusted           INTEGER NOT NULL DEFAULT 0,
    notes             TEXT,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    online            INTEGER NOT NULL DEFAULT 1,
    last_service_scan TEXT,
    mdns_services     TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS device_sightings (
    id        INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    ip        TEXT NOT NULL,
    seen_at   TEXT NOT NULL,
    method    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sightings_device_seen ON device_sightings(device_id, seen_at);

CREATE TABLE IF NOT EXISTS services (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    state      TEXT NOT NULL,
    name       TEXT,
    product    TEXT,
    version    TEXT,
    extrainfo  TEXT,
    cpe        TEXT,
    tunnel     TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE(device_id, port, proto)
);

CREATE TABLE IF NOT EXISTS vulns (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    service_id  INTEGER REFERENCES services(id),
    cve         TEXT NOT NULL,
    source      TEXT NOT NULL,
    kev         INTEGER NOT NULL DEFAULT 0,
    cvss        REAL,
    epss        REAL,
    title       TEXT,
    published   TEXT,
    matched_on  TEXT NOT NULL,
    remediation TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(device_id, cve, matched_on)
);

CREATE TABLE IF NOT EXISTS host_checks (
    check_id    TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    value       TEXT,
    expected    TEXT,
    checked_at  TEXT NOT NULL,
    needs_admin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS software (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL,
    version   TEXT,
    available TEXT,
    source    TEXT NOT NULL,
    publisher TEXT,
    seen_at   TEXT NOT NULL,
    UNIQUE(name, source)
);

CREATE TABLE IF NOT EXISTS persistence (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    command    TEXT,
    location   TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    baseline   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(kind, location, name)
);

CREATE TABLE IF NOT EXISTS file_checks (
    sha256     TEXT PRIMARY KEY,
    path       TEXT NOT NULL,
    size       INTEGER,
    first_seen TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    source     TEXT,
    detail     TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    finding_id  TEXT NOT NULL,
    subject     TEXT NOT NULL,
    dedupe_key  TEXT NOT NULL UNIQUE,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT,
    evidence    TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    resolved_at TEXT,
    occurrences INTEGER NOT NULL DEFAULT 1,
    device_id   INTEGER REFERENCES devices(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON findings(status, severity);

CREATE TABLE IF NOT EXISTS finding_events (
    id             INTEGER PRIMARY KEY,
    finding_row_id INTEGER NOT NULL REFERENCES findings(id),
    event          TEXT NOT NULL,
    at             TEXT NOT NULL,
    note           TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,
    summary     TEXT,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    ts      TEXT NOT NULL,
    level   TEXT NOT NULL,
    source  TEXT NOT NULL,
    message TEXT NOT NULL,
    data    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS metrics (
    id    INTEGER PRIMARY KEY,
    ts    TEXT NOT NULL,
    name  TEXT NOT NULL,
    value REAL NOT NULL,
    tags  TEXT
);
CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics(name, ts);

CREATE TABLE IF NOT EXISTS dns_queries (
    id     INTEGER PRIMARY KEY,
    ts     TEXT NOT NULL,
    client TEXT NOT NULL,
    qname  TEXT NOT NULL,
    qtype  TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    ms     REAL
);
CREATE INDEX IF NOT EXISTS idx_dns_queries_ts ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_queries_action_ts ON dns_queries(action, ts);

CREATE TABLE IF NOT EXISTS dns_hourly (
    hour    TEXT NOT NULL,
    client  TEXT NOT NULL,
    total   INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    PRIMARY KEY(hour, client)
);

CREATE TABLE IF NOT EXISTS dns_overrides (
    domain     TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    note       TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reputation (
    domain     TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    malicious  INTEGER NOT NULL DEFAULT 0,
    suspicious INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT NOT NULL,
    raw        TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id      INTEGER PRIMARY KEY,
    ts      TEXT NOT NULL,
    channel TEXT NOT NULL,
    subject TEXT NOT NULL,
    status  TEXT NOT NULL,
    error   TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    name              TEXT PRIMARY KEY,
    last_run          TEXT,
    last_status       TEXT,
    last_duration_sec REAL,
    next_run          TEXT,
    runs              INTEGER NOT NULL DEFAULT 0,
    failures          INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT
);
"""

# Version 2 (SPEC addendum B5): the two tables Lens needs. Both are owned by the web
# package — this module only creates them. A database written by an earlier version of
# Home SOC gains them on the next start with every existing row untouched, which is what
# `tests/test_lens_auth.py::test_v1_database_upgrades_and_keeps_its_rows` proves.
SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS lens_tokens (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'read',
    created_at   TEXT NOT NULL,
    last_seen_at TEXT,
    last_ip      TEXT,
    expires_at   TEXT,
    revoked_at   TEXT
);

CREATE TABLE IF NOT EXISTS lens_tags (
    id           INTEGER PRIMARY KEY,
    code         TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL,
    -- B5: deleting a device leaves the tag behind, unlearned, rather than dangling (or
    -- blocking the delete, which is what a plain REFERENCES would do with foreign keys on).
    device_id    INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    label        TEXT,
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    last_seen_at TEXT,
    scans        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_lens_tags_device ON lens_tags(device_id);
"""

# Version 3 (SPEC addendum C5): dependencies and blast radius. Owned by homesoc/topology/.
#
# ``dep_edges`` is a *cache*, not a record: every row can be recomputed from devices,
# device_sightings, services and dns_queries by ``topology.graph.refresh()``. Deleting the
# table's contents must therefore be harmless — tests/test_topology.py proves it — which is
# why nothing else references it and why it carries its own first_seen/last_seen rather than
# being the authority on when a dependency was first observed.
#
# ``outages`` and ``outage_members`` are the opposite: they are watched history that cannot be
# recomputed once the sightings behind them are purged, so they are written once and never
# rebuilt. ``cycle_seconds`` is part of the row because the honest resolution of "dropped
# together" is one discovery cycle, and that interval changes when the owner edits
# schedule.discovery_minutes — a reader in six months must see the interval that was in force
# then, not today's.
SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS dep_edges (
    id             INTEGER PRIMARY KEY,
    src            TEXT NOT NULL,
    dst            TEXT NOT NULL,
    edge_type      TEXT NOT NULL,
    protocol       TEXT,
    confidence     TEXT NOT NULL,
    evidence       TEXT,
    observed_count INTEGER NOT NULL DEFAULT 0,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    UNIQUE(src, dst, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_dep_edges_src ON dep_edges(src);
CREATE INDEX IF NOT EXISTS idx_dep_edges_dst ON dep_edges(dst);

CREATE TABLE IF NOT EXISTS outages (
    id                INTEGER PRIMARY KEY,
    started_at        TEXT NOT NULL,
    ended_at          TEXT,
    cycle_seconds     INTEGER NOT NULL,
    trigger_device_id INTEGER REFERENCES devices(id),
    trigger_kind      TEXT NOT NULL,
    member_count      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outages_started ON outages(started_at);

CREATE TABLE IF NOT EXISTS outage_members (
    outage_id   INTEGER NOT NULL REFERENCES outages(id),
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    dropped_at  TEXT NOT NULL,
    returned_at TEXT,
    PRIMARY KEY(outage_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_outage_members_device ON outage_members(device_id);
"""

# Version 4: give the outage tables the ON DELETE behaviour they should have shipped with.
#
# ``connect()`` sets PRAGMA foreign_keys=ON, and v3's plain ``REFERENCES devices(id)`` therefore
# *blocks* deleting any device that has ever been in an outage — verified on a migrated v3
# database: DELETE FROM devices WHERE id = 2 raises "FOREIGN KEY constraint failed". Nothing
# deletes devices today, so this is latent; the first "forget this device" feature would meet it
# as a crash. ``lens_tags`` above documents having avoided exactly this trap.
#
# A table rebuild rather than an edit to SCHEMA_V3, because v3 has shipped: a database created
# before this migration exists and has to be brought forward, and a database created after it
# runs v3 then v4 and lands in the same place. The rebuild preserves every row, and rebuilding
# ``outages`` first means ``outage_members``'s own rebuild sees the final parent table.
#
# ``PRAGMA foreign_keys`` cannot be changed inside a transaction, and executescript commits, so
# the legacy_alter_table dance is not needed: the new tables are populated by explicit INSERT
# ... SELECT and the old ones dropped only once the copy is in place.
SCHEMA_V4 = """
PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS outages_v4 (
    id                INTEGER PRIMARY KEY,
    started_at        TEXT NOT NULL,
    ended_at          TEXT,
    cycle_seconds     INTEGER NOT NULL,
    -- The outage is still a fact once the device is gone; it just no longer has a named trigger.
    trigger_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    trigger_kind      TEXT NOT NULL,
    member_count      INTEGER NOT NULL
);
INSERT INTO outages_v4(id, started_at, ended_at, cycle_seconds, trigger_device_id, trigger_kind, member_count)
    SELECT id, started_at, ended_at, cycle_seconds, trigger_device_id, trigger_kind, member_count FROM outages;
DROP TABLE outages;
ALTER TABLE outages_v4 RENAME TO outages;
CREATE INDEX IF NOT EXISTS idx_outages_started ON outages(started_at);

CREATE TABLE IF NOT EXISTS outage_members_v4 (
    outage_id   INTEGER NOT NULL REFERENCES outages(id) ON DELETE CASCADE,
    -- A membership row is *about* a device; with the device gone it says nothing, so it goes too.
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    dropped_at  TEXT NOT NULL,
    returned_at TEXT,
    PRIMARY KEY(outage_id, device_id)
);
INSERT INTO outage_members_v4(outage_id, device_id, dropped_at, returned_at)
    SELECT outage_id, device_id, dropped_at, returned_at FROM outage_members;
DROP TABLE outage_members;
ALTER TABLE outage_members_v4 RENAME TO outage_members;
CREATE INDEX IF NOT EXISTS idx_outage_members_device ON outage_members(device_id);

PRAGMA foreign_keys=ON;
"""

# Ordered list of (version, ddl). Future schema changes append here; init_schema
# applies every version newer than the highest recorded in schema_migrations.
MIGRATIONS: list[tuple[int, str]] = [(1, SCHEMA_V1), (2, SCHEMA_V2), (3, SCHEMA_V3), (4, SCHEMA_V4)]

TABLES: tuple[str, ...] = (
    "schema_migrations", "settings", "feeds", "devices", "device_sightings", "services", "vulns",
    "host_checks", "software", "persistence", "file_checks", "findings", "finding_events", "scans",
    "events", "metrics", "dns_queries", "dns_hourly", "dns_overrides", "reputation", "notifications", "jobs",
    "lens_tokens", "lens_tags",
    "dep_edges", "outages", "outage_members",
)


# ------------------------------------------------------------------ connection


def connect(path: Path | str | None = None, *, init: bool = True) -> sqlite3.Connection:
    """Open (and by default initialise) the database.

    ``check_same_thread=False`` because one connection is shared by all threads.
    ``init`` is on by default (SPEC-GAP: the spec lists init_schema separately;
    auto-initialising costs a few no-op CREATE IF NOT EXISTS and spares every
    package from remembering to call it).
    """
    target = ":memory:" if str(path) == ":memory:" else Path(path) if path else paths.db_path()
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    if target != ":memory:":
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    if init:
        init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create all tables and apply pending migrations; safe to call at every start."""
    with _WRITE_LOCK:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        current = int(row["v"]) if row and row["v"] is not None else 0
        for version, ddl in MIGRATIONS:
            if version <= current:
                continue
            conn.executescript(ddl)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, utcnow_iso()),
            )
            logger.info("applied schema migration %d", version)
        conn.commit()


def schema_version(conn: sqlite3.Connection) -> int:
    row = one(conn, "SELECT MAX(version) AS v FROM schema_migrations")
    return int(row["v"]) if row and row["v"] is not None else 0


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Hold the write lock for a multi-statement unit of work (commit on success, rollback on error)."""
    with _WRITE_LOCK:
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


# ------------------------------------------------------------------ primitives


def write(conn: sqlite3.Connection, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> int:
    """Locked execute + commit; returns ``lastrowid`` (0 for non-INSERT statements)."""
    with _WRITE_LOCK:
        cur = conn.execute(sql, params)
        conn.commit()
        return int(cur.lastrowid or 0)


def writemany(conn: sqlite3.Connection, sql: str, seq: Iterable[Sequence[Any] | dict[str, Any]]) -> None:
    with _WRITE_LOCK:
        conn.executemany(sql, seq)
        conn.commit()


def query(conn: sqlite3.Connection, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
    # Reads take the lock too. One connection is shared by the web threads, the scheduler and the
    # DNS server, and sqlite3's connection-level execute() keeps its statement state on the
    # connection: two threads interleaving there do not merely block, they corrupt each other's
    # cursors. That surfaces as InterfaceError("no more rows available"/"bad parameter or other
    # API misuse") and, worse, as one() returning None for a row that exists. The lock is an
    # RLock, so nesting inside transaction() is fine, and a home-sized query load does not care.
    with _WRITE_LOCK:
        return conn.execute(sql, params).fetchall()


def one(conn: sqlite3.Connection, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Row | None:
    with _WRITE_LOCK:
        return conn.execute(sql, params).fetchone()


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


# -------------------------------------------------------------------- settings


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = one(conn, "SELECT value FROM settings WHERE key = ?", (key,))
    return str(row["value"]) if row is not None else default


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    """Upsert a setting. Non-string values are stored in their canonical text form
    (JSON for containers, ``true``/``false`` for bools) so config.load can coerce them back."""
    write(
        conn,
        "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, _setting_text(value), utcnow_iso()),
    )


def delete_setting(conn: sqlite3.Connection, key: str) -> None:
    write(conn, "DELETE FROM settings WHERE key = ?", (key,))


def settings_with_prefix(conn: sqlite3.Connection, prefix: str) -> dict[str, str]:
    rows = query(conn, "SELECT key, value FROM settings WHERE key LIKE ? ORDER BY key", (prefix + "%",))
    return {str(r["key"]): str(r["value"]) for r in rows}


def _setting_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json_dumps(list(value) if isinstance(value, tuple) else value)
    if value is None:
        return ""
    return str(value)


# ------------------------------------------------------------ events / metrics


def record_event(
    conn: sqlite3.Connection, level: str, source: str, message: str, data: dict | None = None
) -> None:
    write(
        conn,
        "INSERT INTO events(ts, level, source, message, data) VALUES (?, ?, ?, ?, ?)",
        (utcnow_iso(), level.lower(), source, message, json_dumps(data) if data is not None else None),
    )


def record_metric(conn: sqlite3.Connection, name: str, value: float, tags: dict | None = None) -> None:
    write(
        conn,
        "INSERT INTO metrics(ts, name, value, tags) VALUES (?, ?, ?, ?)",
        (utcnow_iso(), name, float(value), json_dumps(tags) if tags else None),
    )


# ----------------------------------------------------------------------- scans


def scan_start(conn: sqlite3.Connection, kind: str) -> int:
    """Open a ``scans`` row; the id is handed to :func:`scan_finish` when the run ends."""
    return write(
        conn,
        "INSERT INTO scans(kind, started_at, status) VALUES (?, ?, 'running')",
        (kind, utcnow_iso()),
    )


def scan_finish(
    conn: sqlite3.Connection,
    scan_id: int,
    status: str,
    summary: dict | None = None,
    error: str | None = None,
) -> None:
    write(
        conn,
        "UPDATE scans SET finished_at = ?, status = ?, summary = ?, error = ? WHERE id = ?",
        (utcnow_iso(), status, json_dumps(summary) if summary is not None else None, error, scan_id),
    )


def abort_stale_scans(conn: sqlite3.Connection) -> int:
    """Close ``running`` scan rows left behind by a killed process, so the dashboard never
    shows a scan that has been "running" since last Tuesday. Called once at start-up,
    before any new scan can legitimately be running."""
    with _WRITE_LOCK:
        cur = conn.execute(
            "UPDATE scans SET status = 'aborted', finished_at = ?, error = COALESCE(error, 'process stopped before the scan finished') "
            "WHERE status = 'running'",
            (utcnow_iso(),),
        )
        conn.commit()
        if cur.rowcount:
            logger.warning("marked %d unfinished scan(s) from a previous run as aborted", cur.rowcount)
        return int(cur.rowcount)


def last_scans(conn: sqlite3.Connection) -> dict[str, str]:
    """Most recent finished timestamp per scan kind, for the overview and ``status``."""
    rows = query(
        conn,
        "SELECT kind, MAX(COALESCE(finished_at, started_at)) AS ts FROM scans "
        "WHERE status != 'running' GROUP BY kind",
    )
    return {str(r["kind"]): str(r["ts"]) for r in rows if r["ts"]}


# ------------------------------------------------------------------ housekeeping


def purge_older_than(conn: sqlite3.Connection, table: str, ts_column: str, cutoff_iso: str) -> int:
    """Delete rows older than ``cutoff_iso``; table/column names are validated against the schema
    because they cannot be bound as parameters."""
    if table not in TABLES:
        raise ValueError(f"unknown table {table!r}")
    if not ts_column.replace("_", "").isalnum():
        raise ValueError(f"bad column {ts_column!r}")
    with _WRITE_LOCK:
        cur = conn.execute(f"DELETE FROM {table} WHERE {ts_column} < ?", (cutoff_iso,))
        conn.commit()
        return int(cur.rowcount)


# -------------------------------------------------------------------------- Lens
#
# Pairing and token primitives for Lens (SPEC addendum B4/B10). They live here rather
# than in the web package because the web package is built in three parallel pieces and
# all of them need these: L1 mints from the CLI, L2 verifies on every API call, L3 hands
# the token to the phone. Import them as ``from homesoc import db`` and call
# ``db.lens_mint_token(...)`` — there is no other home for shared state than the module
# that owns the tables.
#
# The security rules of B10 are enforced here, not by the callers:
#   * a token is 32 bytes from ``secrets.token_urlsafe`` and is returned exactly once;
#   * only its SHA-256 is stored, and comparison is ``secrets.compare_digest``;
#   * expiry, revocation and the ``max_tokens`` ceiling are checked on every use;
#   * pairing codes are single-use, short-lived, stored as hashes, and rate-limited.

#: Entropy of a paired-phone token, in bytes, before url-safe base64 expansion.
LENS_TOKEN_BYTES = 32
#: Scopes a token may carry. ``act`` additionally requires ``lens.allow_actions``.
LENS_SCOPES: tuple[str, ...] = ("read", "act")
#: Pairing codes: 8 characters from an alphabet with no 0/O or 1/I/L to mistype,
#: ~39 bits of entropy, which the claim rate limit keeps far out of guessing range.
LENS_PAIRING_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
LENS_PAIRING_LENGTH = 8
LENS_PAIRING_TTL_SECONDS = 300
#: Claim attempts allowed per source address, and the lock-out that follows (B4).
LENS_CLAIM_LIMIT = 10
LENS_CLAIM_WINDOW_SECONDS = 3600

#: Control characters are stripped from every phone-supplied label before it is stored,
#: logged or printed (see lens_mint_token). Same class lens.normalise_code refuses.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_LENS_PAIRING_PREFIX = "lens.pairing."
_LENS_CLAIM_PREFIX = "lens.claim."
_LENS_CODE_STRIP = str.maketrans("", "", " \t-_")


class LensError(RuntimeError):
    """A Lens token or pairing operation was refused."""


class LensTokenLimit(LensError):
    """``lens.max_tokens`` phones are already paired."""


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _iso_in(seconds: float) -> str:
    return util_to_iso(datetime.now(timezone.utc) + timedelta(seconds=seconds))


def lens_normalise_scopes(scopes: str | Iterable[str] | None) -> str:
    """Canonical ``read``/``read,act`` text. Unknown scopes are dropped, ``read`` is implied."""
    if scopes is None:
        parts: list[str] = []
    elif isinstance(scopes, str):
        parts = [p.strip().lower() for p in scopes.replace(" ", ",").split(",")]
    else:
        parts = [str(p).strip().lower() for p in scopes]
    kept = [s for s in LENS_SCOPES if s in parts]
    if "read" not in kept:
        kept.insert(0, "read")
    return ",".join(kept)


def lens_has_scope(scopes: str | None, scope: str) -> bool:
    return scope in lens_normalise_scopes(scopes).split(",")


def _lens_token_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Row as a dict without ``token_hash`` — nothing that verifies a token leaves this module."""
    data = dict(row)
    data.pop("token_hash", None)
    data["scopes"] = lens_normalise_scopes(data.get("scopes"))
    data["active"] = not data.get("revoked_at") and not _lens_expired(data.get("expires_at"))
    return data


def _lens_expired(expires_at: Any) -> bool:
    return bool(expires_at) and str(expires_at) <= utcnow_iso()


def lens_active_tokens(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Paired phones that could authenticate right now."""
    rows = query(
        conn,
        "SELECT * FROM lens_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) "
        "ORDER BY id",
        (utcnow_iso(),),
    )
    return [_lens_token_row(r) for r in rows]


def lens_list_tokens(conn: sqlite3.Connection, *, include_revoked: bool = True) -> list[dict[str, Any]]:
    """Every paired phone for the ``lens tokens`` command and the pairing page."""
    sql = "SELECT * FROM lens_tokens"
    if not include_revoked:
        sql += " WHERE revoked_at IS NULL"
    return [_lens_token_row(r) for r in query(conn, sql + " ORDER BY id")]


def lens_mint_token(
    conn: sqlite3.Connection,
    *,
    label: str,
    scopes: str | Iterable[str] = "read",
    ttl_days: int = 90,
    max_tokens: int = 10,
) -> dict[str, Any]:
    """Create a paired-phone token.

    Returns the stored row **plus a ``token`` key holding the secret**, which is the only
    time it exists anywhere: the database keeps nothing but its SHA-256. ``ttl_days`` of 0
    means the token never expires. Raises :class:`LensTokenLimit` once ``max_tokens``
    phones are already paired, so a stolen pairing code cannot mint an unbounded number.
    """
    # The label arrives in the /api/lens/claim body, so it is attacker-controlled the moment a
    # pairing code leaks. It is stored, written into an events row, and printed by
    # `python -m homesoc lens tokens` in a fixed-width table — so CR/LF and ANSI escapes in it
    # would let the holder of a pairing code forge or hide a row in the very listing the owner
    # reads to decide what to revoke. Strip control characters, exactly as lens.normalise_code
    # does for the other hostile string on this surface.
    clean_label = (_CONTROL_CHARS.sub("", str(label or "")).strip() or "phone")[:64].strip() or "phone"
    limit = max(1, int(max_tokens))
    active = lens_active_tokens(conn)
    if len(active) >= limit:
        raise LensTokenLimit(
            f"{len(active)} of {limit} Lens tokens are already paired; revoke one "
            f"(python -m homesoc lens revoke <id>) or raise lens.max_tokens"
        )
    token = secrets.token_urlsafe(LENS_TOKEN_BYTES)
    expires_at = _iso_in(int(ttl_days) * 86400) if int(ttl_days) > 0 else None
    row_id = write(
        conn,
        "INSERT INTO lens_tokens(token_hash, label, scopes, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (_sha256_hex(token), clean_label, lens_normalise_scopes(scopes), utcnow_iso(), expires_at),
    )
    record_event(conn, "info", "lens", f"paired a new device: {clean_label}",
                 {"token_id": row_id, "scopes": lens_normalise_scopes(scopes), "expires_at": expires_at})
    stored = one(conn, "SELECT * FROM lens_tokens WHERE id = ?", (row_id,))
    out = _lens_token_row(stored) if stored is not None else {"id": row_id}
    out["token"] = token
    return out


def lens_verify_token(
    conn: sqlite3.Connection, token: str | None, *, ip: str | None = None, touch: bool = True
) -> dict[str, Any] | None:
    """Return the token's row when it is valid, otherwise ``None``.

    Valid means: it exists, it has not been revoked and it has not expired. The presented
    value is hashed and compared with :func:`secrets.compare_digest`, so neither the
    lookup nor the comparison leaks the stored secret through timing. On success
    ``last_seen_at``/``last_ip`` are refreshed (B4) unless ``touch`` is false.
    """
    presented = str(token or "").strip()
    if not presented or len(presented) > 512:
        return None
    digest = _sha256_hex(presented)
    row = one(conn, "SELECT * FROM lens_tokens WHERE token_hash = ?", (digest,))
    if row is None or not secrets.compare_digest(str(row["token_hash"]), digest):
        return None
    if row["revoked_at"] or _lens_expired(row["expires_at"]):
        return None
    if touch:
        write(
            conn,
            "UPDATE lens_tokens SET last_seen_at = ?, last_ip = ? WHERE id = ?",
            (utcnow_iso(), (str(ip)[:45] if ip else row["last_ip"]), int(row["id"])),
        )
        row = one(conn, "SELECT * FROM lens_tokens WHERE id = ?", (int(row["id"]),)) or row
    return _lens_token_row(row)


def lens_revoke_token(conn: sqlite3.Connection, token_id: int) -> bool:
    """Revoke one paired phone. Returns False when the id is unknown or already revoked."""
    with _WRITE_LOCK:
        cur = conn.execute(
            "UPDATE lens_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (utcnow_iso(), int(token_id)),
        )
        conn.commit()
        changed = int(cur.rowcount)
    if changed:
        record_event(conn, "info", "lens", f"revoked Lens token {int(token_id)}", {"token_id": int(token_id)})
    return bool(changed)


def lens_revoke_all_tokens(conn: sqlite3.Connection) -> int:
    """Revoke every paired phone; returns how many were still active."""
    with _WRITE_LOCK:
        cur = conn.execute(
            "UPDATE lens_tokens SET revoked_at = ? WHERE revoked_at IS NULL", (utcnow_iso(),)
        )
        conn.commit()
        changed = int(cur.rowcount)
    if changed:
        record_event(conn, "warning", "lens", f"revoked all {changed} Lens token(s)", {"count": changed})
    return changed


# ------------------------------------------------------------ pairing codes


def lens_new_pairing_code(conn: sqlite3.Connection, *, ttl_seconds: int = LENS_PAIRING_TTL_SECONDS) -> str:
    """Mint a single-use pairing code, returned once and stored only as a hash.

    Minting first clears any earlier code: the pairing page shows one code at a time, and
    a code left on a screen someone walked away from should not still work.
    """
    lens_clear_pairing_codes(conn)
    code = "".join(secrets.choice(LENS_PAIRING_ALPHABET) for _ in range(LENS_PAIRING_LENGTH))
    set_setting(
        conn,
        _LENS_PAIRING_PREFIX + _sha256_hex(code),
        {"created_at": utcnow_iso(), "expires_at": _iso_in(max(1, int(ttl_seconds)))},
    )
    return code


def lens_normalise_pairing_code(code: str | None) -> str:
    """Accept what a person can type: spaces, dashes and lower case all work."""
    return str(code or "").translate(_LENS_CODE_STRIP).strip().upper()[:32]


def lens_consume_pairing_code(conn: sqlite3.Connection, code: str | None) -> bool:
    """Spend a pairing code. True exactly once per code, and never after it expires."""
    presented = lens_normalise_pairing_code(code)
    if not presented:
        return False
    digest = _sha256_hex(presented)
    now = utcnow_iso()
    matched = False
    for key, raw in settings_with_prefix(conn, _LENS_PAIRING_PREFIX).items():
        stored = key[len(_LENS_PAIRING_PREFIX):]
        state = _loads_dict(raw)
        if str(state.get("expires_at", "")) <= now:
            delete_setting(conn, key)
            continue
        if secrets.compare_digest(stored, digest):
            delete_setting(conn, key)
            matched = True
    return matched


def lens_clear_pairing_codes(conn: sqlite3.Connection) -> int:
    """Invalidate every outstanding pairing code (B10: also when ``lens.enabled`` goes false)."""
    keys = list(settings_with_prefix(conn, _LENS_PAIRING_PREFIX))
    for key in keys:
        delete_setting(conn, key)
    return len(keys)


# ------------------------------------------------------------ claim rate limit


def lens_claim_attempt(
    conn: sqlite3.Connection,
    ip: str | None,
    *,
    limit: int = LENS_CLAIM_LIMIT,
    window_seconds: int = LENS_CLAIM_WINDOW_SECONDS,
) -> tuple[bool, int]:
    """Count one ``/api/lens/claim`` attempt from ``ip``.

    Returns ``(allowed, retry_after_seconds)``. The first ``limit`` attempts in a window
    are allowed; the next one locks that address out for a further window and writes an
    ``events`` row (B4). The counter is keyed on a hash of the address so the settings
    table does not accumulate a list of who tried.
    """
    source = str(ip or "unknown")[:45]
    key = _LENS_CLAIM_PREFIX + _sha256_hex(source)[:16]
    now = datetime.now(timezone.utc)
    now_iso = util_to_iso(now)
    state = _loads_dict(get_setting(conn, key, "") or "")
    blocked_until = str(state.get("blocked_until") or "")
    if blocked_until > now_iso:
        return False, _seconds_until(blocked_until, now)
    window_start = str(state.get("window_start") or "")
    count = int(state.get("count") or 0)
    if not window_start or _seconds_until(window_start, now) < -window_seconds:
        window_start, count = now_iso, 0
    count += 1
    if count > max(1, int(limit)):
        until = util_to_iso(now + timedelta(seconds=window_seconds))
        set_setting(conn, key, {"window_start": window_start, "count": count, "blocked_until": until})
        record_event(conn, "warning", "lens",
                     "too many Lens pairing attempts; refusing this source for an hour",
                     {"attempts": count, "limit": int(limit), "blocked_until": until, "source": source})
        return False, int(window_seconds)
    set_setting(conn, key, {"window_start": window_start, "count": count, "blocked_until": ""})
    return True, 0


def lens_claim_reset(conn: sqlite3.Connection, ip: str | None) -> None:
    """Forget one address's attempt counter — called after a successful claim."""
    delete_setting(conn, _LENS_CLAIM_PREFIX + _sha256_hex(str(ip or "unknown")[:45])[:16])


def lens_purge_claim_counters(conn: sqlite3.Connection, *, older_than_seconds: int = 2 * LENS_CLAIM_WINDOW_SECONDS) -> int:
    """Drop rate-limit counters nobody is counting any more (housekeeping)."""
    cutoff = util_to_iso(datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds))
    removed = 0
    for key, raw in settings_with_prefix(conn, _LENS_CLAIM_PREFIX).items():
        state = _loads_dict(raw)
        newest = max(str(state.get("window_start") or ""), str(state.get("blocked_until") or ""))
        if newest < cutoff:
            delete_setting(conn, key)
            removed += 1
    return removed


def _seconds_until(iso: str, now: datetime) -> int:
    parsed = util_parse_iso(iso)
    if parsed is None:
        return 0
    return int((parsed - now).total_seconds())


def _loads_dict(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in TABLES:
        row = one(conn, f"SELECT COUNT(*) AS n FROM {table}")
        counts[table] = int(row["n"]) if row else 0
    return counts


__all__ = [
    "SCHEMA_VERSION",
    "MIGRATIONS",
    "TABLES",
    "connect",
    "init_schema",
    "schema_version",
    "transaction",
    "write",
    "writemany",
    "query",
    "one",
    "rows_to_dicts",
    "get_setting",
    "set_setting",
    "delete_setting",
    "settings_with_prefix",
    "record_event",
    "record_metric",
    "scan_start",
    "scan_finish",
    "abort_stale_scans",
    "last_scans",
    "purge_older_than",
    "table_counts",
    # Lens (SPEC addendum B4/B10) — the import path for L2 and L3 is homesoc.db.
    "LensError",
    "LensTokenLimit",
    "LENS_TOKEN_BYTES",
    "LENS_SCOPES",
    "LENS_PAIRING_ALPHABET",
    "LENS_PAIRING_LENGTH",
    "LENS_PAIRING_TTL_SECONDS",
    "LENS_CLAIM_LIMIT",
    "LENS_CLAIM_WINDOW_SECONDS",
    "lens_normalise_scopes",
    "lens_has_scope",
    "lens_mint_token",
    "lens_verify_token",
    "lens_list_tokens",
    "lens_active_tokens",
    "lens_revoke_token",
    "lens_revoke_all_tokens",
    "lens_new_pairing_code",
    "lens_normalise_pairing_code",
    "lens_consume_pairing_code",
    "lens_clear_pairing_codes",
    "lens_claim_attempt",
    "lens_claim_reset",
    "lens_purge_claim_counters",
]
