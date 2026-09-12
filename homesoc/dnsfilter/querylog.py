"""Query log: batched inserts, hourly rollup, retention and dashboard aggregates (SPEC §12).

Why batch: a busy LAN produces tens of queries per second and SQLite commits are expensive on a
laptop disk; buffering for 2 s / 500 rows keeps the resolver's answer latency independent of disk
speed. The hourly ``dns_hourly`` rollup lets the dashboard chart weeks of history after raw rows
have been purged.
"""
from __future__ import annotations

import datetime as dt
import logging
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass

from homesoc.dnsfilter import db_query, db_write, db_writemany, utcnow_iso

logger = logging.getLogger(__name__)

FLUSH_INTERVAL = 2.0
BATCH_SIZE = 500
ACTIONS = ("allow", "block", "cache", "error")

# Only the dnsfilter-owned tables (SPEC §4); identical to core's schema so both are idempotent.
SCHEMA = (
    "CREATE TABLE IF NOT EXISTS dns_queries(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, client TEXT NOT NULL,"
    " qname TEXT NOT NULL, qtype TEXT NOT NULL, action TEXT NOT NULL, reason TEXT, ms REAL)",
    "CREATE INDEX IF NOT EXISTS idx_dns_queries_ts ON dns_queries(ts)",
    "CREATE INDEX IF NOT EXISTS idx_dns_queries_action_ts ON dns_queries(action, ts)",
    "CREATE TABLE IF NOT EXISTS dns_hourly(hour TEXT NOT NULL, client TEXT NOT NULL, total INTEGER NOT NULL,"
    " blocked INTEGER NOT NULL, PRIMARY KEY(hour, client))",
    "CREATE TABLE IF NOT EXISTS dns_overrides(domain TEXT PRIMARY KEY, action TEXT NOT NULL, note TEXT,"
    " created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS reputation(domain TEXT PRIMARY KEY, source TEXT NOT NULL, verdict TEXT NOT NULL,"
    " malicious INTEGER NOT NULL DEFAULT 0, suspicious INTEGER NOT NULL DEFAULT 0, checked_at TEXT NOT NULL, raw TEXT)",
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the dnsfilter-owned tables if core's ``init_schema`` has not run yet (idempotent)."""
    for stmt in SCHEMA:
        db_write(conn, stmt)


@dataclass(frozen=True)
class QueryRecord:
    ts: str
    client: str
    qname: str
    qtype: str
    action: str
    reason: str | None
    ms: float | None


def hour_key(ts: str) -> str:
    """``2026-09-04T12:34:56Z`` → ``2026-09-04T12:00``.

    # SPEC-GAP: the spec leaves the ``dns_hourly.hour`` format open; a truncated ISO string sorts
    # correctly as text and is what the dashboard's per-hour chart needs.
    """
    return ts[:13] + ":00"


def _cutoff_iso(hours: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


class QueryLog:
    """In-memory queue flushed to ``dns_queries`` every 2 s or 500 rows by a daemon thread."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        enabled: bool = True,
        flush_interval: float = FLUSH_INTERVAL,
        batch_size: int = BATCH_SIZE,
    ) -> None:
        self.conn = conn
        self.enabled = enabled
        self.flush_interval = flush_interval
        self.batch_size = batch_size
        self._queue: deque[QueryRecord] = deque()
        self._recent: deque[float] = deque()  # monotonic timestamps for qps_1m (kept even when logging is off)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.total = 0
        self.dropped = 0

    # ---- lifecycle ------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="dns-querylog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        t = self._thread
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=5)
        self._thread = None
        self.flush()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.flush_interval)
            self._wake.clear()
            try:
                self.flush()
            except Exception:
                logger.exception("query log flush failed")

    # ---- recording ------------------------------------------------------------------------
    def record(
        self,
        client: str,
        qname: str,
        qtype: str,
        action: str,
        reason: str | None = None,
        ms: float | None = None,
        *,
        ts: str | None = None,
    ) -> None:
        now = time.monotonic()
        with self._lock:
            self._recent.append(now)
            self._trim_recent(now)
            self.total += 1
            if not self.enabled:
                return
            if len(self._queue) >= self.batch_size * 20:  # disk stalled: drop rather than eat memory
                self.dropped += 1
                return
            self._queue.append(
                QueryRecord(ts or utcnow_iso(), client, qname, qtype, action, reason, None if ms is None else round(ms, 2))
            )
            wake = len(self._queue) >= self.batch_size
        if wake:
            self._wake.set()

    def _trim_recent(self, now: float) -> None:
        while self._recent and now - self._recent[0] > 60.0:
            self._recent.popleft()

    def qps_1m(self) -> float:
        with self._lock:
            self._trim_recent(time.monotonic())
            return round(len(self._recent) / 60.0, 3)

    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    def flush(self) -> int:
        with self._lock:
            if not self._queue:
                return 0
            rows = list(self._queue)
            self._queue.clear()
        try:
            db_writemany(
                self.conn,
                "INSERT INTO dns_queries(ts, client, qname, qtype, action, reason, ms) VALUES (?,?,?,?,?,?,?)",
                [(r.ts, r.client, r.qname, r.qtype, r.action, r.reason, r.ms) for r in rows],
            )
        except sqlite3.Error:
            logger.exception("query log insert failed; %d rows lost", len(rows))
            self.dropped += len(rows)
            return 0
        return len(rows)


# ---- maintenance (scheduler job ``dns_rollup``) ---------------------------------------------------
def rollup(conn: sqlite3.Connection, *, hours_back: int = 48) -> int:
    """Recompute ``dns_hourly`` from raw rows for the last ``hours_back`` hours; returns rows written.

    Re-aggregating a window (instead of only the previous hour) makes the job idempotent and
    self-healing after a missed run or a crash mid-hour.
    """
    since = _cutoff_iso(hours_back)
    rows = db_query(
        conn,
        "SELECT substr(ts, 1, 13) || ':00' AS hour, client, COUNT(*) AS total,"
        " SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked"
        " FROM dns_queries WHERE ts >= ? GROUP BY hour, client",
        (since,),
    )
    db_writemany(
        conn,
        "INSERT INTO dns_hourly(hour, client, total, blocked) VALUES (?,?,?,?)"
        " ON CONFLICT(hour, client) DO UPDATE SET total = excluded.total, blocked = excluded.blocked",
        [(r["hour"], r["client"], int(r["total"]), int(r["blocked"])) for r in rows],
    )
    return len(rows)


def purge(conn: sqlite3.Connection, retention_days: int) -> int:
    """Delete raw rows older than the retention window (hourly rollups are kept 4x longer)."""
    days = max(1, int(retention_days))
    raw_cutoff = _cutoff_iso(days * 24)
    hourly_cutoff = hour_key(_cutoff_iso(days * 24 * 4))
    before = db_query(conn, "SELECT COUNT(*) AS n FROM dns_queries WHERE ts < ?", (raw_cutoff,))
    n = int(before[0]["n"]) if before else 0
    db_write(conn, "DELETE FROM dns_queries WHERE ts < ?", (raw_cutoff,))
    db_write(conn, "DELETE FROM dns_hourly WHERE hour < ?", (hourly_cutoff,))
    return n


def maintenance(cfg, conn: sqlite3.Connection) -> dict:
    """One call for the scheduler's ``dns_rollup`` job: rollup + purge."""
    from homesoc.dnsfilter import cfg_get

    days = int(cfg_get(cfg, "dns", "log_retention_days", 14) or 14)
    written = rollup(conn)
    purged = purge(conn, days)
    return {"rollup_rows": written, "purged": purged}


# ---- aggregates for the dashboard ---------------------------------------------------------------
def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    out = []
    for r in rows:
        try:
            out.append(dict(r))
        except (TypeError, ValueError):  # plain tuples when row_factory is unset
            out.append({str(i): v for i, v in enumerate(r)})
    return out


def top_blocked(conn: sqlite3.Connection, hours: float = 24, limit: int = 20) -> list[dict]:
    rows = db_query(
        conn,
        "SELECT qname AS domain, COUNT(*) AS count, MAX(reason) AS reason FROM dns_queries"
        " WHERE action = 'block' AND ts >= ? GROUP BY qname ORDER BY count DESC, qname LIMIT ?",
        (_cutoff_iso(hours), int(limit)),
    )
    return _rows_to_dicts(rows)


def top_clients(conn: sqlite3.Connection, hours: float = 24, limit: int = 20) -> list[dict]:
    rows = db_query(
        conn,
        "SELECT client, COUNT(*) AS total, SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked"
        " FROM dns_queries WHERE ts >= ? GROUP BY client ORDER BY total DESC, client LIMIT ?",
        (_cutoff_iso(hours), int(limit)),
    )
    return _rows_to_dicts(rows)


def recent(
    conn: sqlite3.Connection,
    limit: int = 100,
    client: str | None = None,
    action: str | None = None,
) -> list[dict]:
    sql = "SELECT id, ts, client, qname, qtype, action, reason, ms FROM dns_queries"
    clauses: list[str] = []
    params: list = []
    if client:
        clauses.append("client = ?")
        params.append(client)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 5000)))
    return _rows_to_dicts(db_query(conn, sql, params))


def series(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    """Per-hour ``{hour, total, blocked}`` for the last ``hours`` hours, zero-filled.

    Live raw rows win for hours still inside the retention window; ``dns_hourly`` fills older hours.
    """
    hours = max(1, int(hours))
    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - dt.timedelta(hours=hours - 1)
    start_key = start.strftime("%Y-%m-%dT%H:00")
    buckets: dict[str, dict] = {}
    for i in range(hours):
        h = (start + dt.timedelta(hours=i)).strftime("%Y-%m-%dT%H:00")
        buckets[h] = {"hour": h, "total": 0, "blocked": 0}
    for r in db_query(
        conn,
        "SELECT hour, SUM(total) AS total, SUM(blocked) AS blocked FROM dns_hourly WHERE hour >= ? GROUP BY hour",
        (start_key,),
    ):
        b = buckets.get(r["hour"])
        if b is not None:
            b["total"], b["blocked"] = int(r["total"] or 0), int(r["blocked"] or 0)
    for r in db_query(
        conn,
        "SELECT substr(ts, 1, 13) || ':00' AS hour, COUNT(*) AS total,"
        " SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked"
        " FROM dns_queries WHERE ts >= ? GROUP BY hour",
        (start.strftime("%Y-%m-%dT%H:%M:%SZ"),),
    ):
        b = buckets.get(r["hour"])
        if b is not None:
            b["total"], b["blocked"] = int(r["total"] or 0), int(r["blocked"] or 0)
    return list(buckets.values())


def summary(conn: sqlite3.Connection, hours: float = 24) -> dict:
    """``{total, blocked, clients}`` for the window — the numbers on the overview cards."""
    row = db_query(
        conn,
        "SELECT COUNT(*) AS total, SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked,"
        " COUNT(DISTINCT client) AS clients FROM dns_queries WHERE ts >= ?",
        (_cutoff_iso(hours),),
    )
    r = row[0] if row else None
    return {
        "total": int(r["total"] or 0) if r else 0,
        "blocked": int(r["blocked"] or 0) if r else 0,
        "clients": int(r["clients"] or 0) if r else 0,
    }


def distinct_clients(conn: sqlite3.Connection, hours: float = 24) -> int:
    return summary(conn, hours)["clients"]
