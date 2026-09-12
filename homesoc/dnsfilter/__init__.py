"""Home SOC DNS filter — an embedded LAN resolver that blocks ads, trackers and malware domains.

Package layout (SPEC §12):

* ``server``     — ``DnsServer`` (UDP + TCP listeners, per-query pipeline, health findings)
* ``policy``     — ``Policy`` / ``Decision`` (overrides, never-block, blocklists, reputation)
* ``cache``      — TTL-respecting LRU answer cache
* ``upstream``   — UDP → TCP → DoH forwarding with health tracking
* ``querylog``   — batched query log, hourly rollup, retention, dashboard aggregates
* ``reputation`` — VirusTotal / URLhaus lookups with a persisted daily budget and async worker

The small DB/config helpers below live here (not in a private module) because every submodule needs
them and the package must keep working while the core package (``homesoc.db``/``homesoc.config``)
is still being built by another work package. When ``homesoc.db`` is importable its locked
``write``/``query`` helpers are used so all writers share one lock; otherwise a package-local lock
guards the connection.
"""
from __future__ import annotations

import datetime as _dt
import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

try:  # core package may not exist yet during parallel builds
    from homesoc import db as _core_db  # type: ignore
except Exception:  # pragma: no cover - exercised only when core is absent
    _core_db = None

_local_lock = threading.RLock()


def utcnow_iso() -> str:
    """UTC ISO-8601 with a trailing ``Z`` — same shape ``homesoc.util.utcnow_iso`` is specified to use."""
    try:
        from homesoc.util import utcnow_iso as _u  # type: ignore

        return _u()
    except Exception:
        return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db_write(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> int:
    """Locked execute+commit returning ``lastrowid``; mirrors ``homesoc.db.write``."""
    if _core_db is not None and hasattr(_core_db, "write"):
        return int(_core_db.write(conn, sql, tuple(params)) or 0)
    with _local_lock:
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return int(cur.lastrowid or 0)


def db_writemany(conn: sqlite3.Connection, sql: str, seq: Iterable[Iterable[Any]]) -> None:
    rows = [tuple(r) for r in seq]
    if not rows:
        return
    if _core_db is not None and hasattr(_core_db, "writemany"):
        _core_db.writemany(conn, sql, rows)
        return
    with _local_lock:
        conn.executemany(sql, rows)
        conn.commit()


def db_query(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    if _core_db is not None and hasattr(_core_db, "query"):
        return list(_core_db.query(conn, sql, tuple(params)))
    with _local_lock:
        cur = conn.execute(sql, tuple(params))
        rows = cur.fetchall()
    return list(rows)


def db_one(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
    rows = db_query(conn, sql, params)
    return rows[0] if rows else None


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    if _core_db is not None and hasattr(_core_db, "get_setting"):
        return _core_db.get_setting(conn, key, default)
    try:
        row = db_one(conn, "SELECT value FROM settings WHERE key = ?", (key,))
    except sqlite3.OperationalError:
        return default
    return str(row[0]) if row is not None else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    if _core_db is not None and hasattr(_core_db, "set_setting"):
        _core_db.set_setting(conn, key, value)
        return
    db_write(
        conn,
        "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, str(value), utcnow_iso()),
    )


def record_event(conn: sqlite3.Connection, level: str, source: str, message: str, data: dict | None = None) -> None:
    """Best-effort event record; never raises (the resolver must keep answering)."""
    try:
        if _core_db is not None and hasattr(_core_db, "record_event"):
            _core_db.record_event(conn, level, source, message, data)
    except Exception:  # pragma: no cover
        logger.debug("record_event failed", exc_info=True)


def record_metric(conn: sqlite3.Connection, name: str, value: float, tags: dict | None = None) -> None:
    try:
        if _core_db is not None and hasattr(_core_db, "record_metric"):
            _core_db.record_metric(conn, name, value, tags)
    except Exception:  # pragma: no cover
        logger.debug("record_metric failed", exc_info=True)


def cfg_get(cfg: Any, section: str, key: str, default: Any = None) -> Any:
    """Read ``cfg.<section>.<key>`` from a dataclass, namespace or nested mapping.

    Tests and early integration may hand us plain namespaces/dicts instead of ``homesoc.config.Config``;
    treating all of them alike keeps the resolver independent of the config package's exact shape.
    """
    sec: Any = None
    if isinstance(cfg, Mapping):
        sec = cfg.get(section)
    else:
        sec = getattr(cfg, section, None)
    if sec is None:
        return default
    if isinstance(sec, Mapping):
        return sec.get(key, default)
    return getattr(sec, key, default)


@dataclass
class _LocalDraft:
    """Stand-in for ``homesoc.models.FindingDraft`` while the core package is absent (same fields)."""

    finding_id: str
    subject: str
    evidence: dict = field(default_factory=dict)
    detail: str | None = None
    severity: str | None = None
    device_id: int | None = None


def make_draft(
    finding_id: str,
    subject: str,
    evidence: dict | None = None,
    detail: str | None = None,
    severity: str | None = None,
) -> Any:
    """Build a ``FindingDraft`` (real one when models is importable) — never raises."""
    ev = dict(evidence or {})
    try:
        from homesoc.models import FindingDraft  # type: ignore

        return FindingDraft(finding_id=finding_id, subject=subject, evidence=ev, detail=detail, severity=severity)
    except Exception:
        return _LocalDraft(finding_id=finding_id, subject=subject, evidence=ev, detail=detail, severity=severity)


def apply_findings(conn: sqlite3.Connection, drafts: list, source: str, *, scope: str | None = None) -> Any:
    """Hand drafts to ``homesoc.findings.engine.apply`` when importable; otherwise log and drop.

    Lazy + guarded because dnsfilter must run (and its tests must pass) before the findings package
    lands, and because a findings-engine bug must never take the resolver down.
    """
    if not drafts and scope is None:
        return None
    try:
        from homesoc.findings import engine  # type: ignore
    except Exception:
        logger.debug("findings engine unavailable; %d DNS draft(s) not persisted", len(drafts))
        return None
    try:
        return engine.apply(conn, list(drafts), source, scope=scope)
    except Exception:
        logger.exception("findings.engine.apply failed for source %s", source)
        return None


from .server import DnsServer  # noqa: E402  (helpers above must exist before submodules import)

__all__ = [
    "DnsServer",
    "apply_findings",
    "make_draft",
    "cfg_get",
    "db_one",
    "db_query",
    "db_write",
    "db_writemany",
    "get_setting",
    "record_event",
    "record_metric",
    "set_setting",
    "utcnow_iso",
]
