"""SQLite access layer and the complete schema for every package.

One connection is shared by the scheduler thread, the DNS server threads and
Flask request threads. SQLite serialises statements on a connection, but
``execute`` + ``commit`` pairs are not atomic across threads, so every write
goes through :func:`write`/:func:`writemany` under a module-level lock. Reads
are lock-free (WAL mode lets them proceed while a write is in flight).
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from homesoc import paths
from homesoc.util import json_dumps, utcnow_iso

logger = logging.getLogger(__name__)

_WRITE_LOCK = threading.RLock()

SCHEMA_VERSION = 1

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

# Ordered list of (version, ddl). Future schema changes append here; init_schema
# applies every version newer than the highest recorded in schema_migrations.
MIGRATIONS: list[tuple[int, str]] = [(1, SCHEMA_V1)]

TABLES: tuple[str, ...] = (
    "schema_migrations", "settings", "feeds", "devices", "device_sightings", "services", "vulns",
    "host_checks", "software", "persistence", "file_checks", "findings", "finding_events", "scans",
    "events", "metrics", "dns_queries", "dns_hourly", "dns_overrides", "reputation", "notifications", "jobs",
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
    return conn.execute(sql, params).fetchall()


def one(conn: sqlite3.Connection, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Row | None:
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
]
