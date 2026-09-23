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

from homesoc.dnsfilter import db_query, db_write, db_writemany, record_event, utcnow_iso

logger = logging.getLogger(__name__)

FLUSH_INTERVAL = 2.0
BATCH_SIZE = 500
ACTIONS = ("allow", "block", "cache", "error")
# Logging budgets. Every answered query used to become a row, so one LAN device at its rate limit
# could write ~10 GB a day and make every dashboard aggregate (which runs under the shared DB lock)
# slower by the hour. Queries over budget are still answered and still counted in qps; they are just
# not written. A busy household device averages well under 1 query a second.
LOG_BUDGET_PER_CLIENT = 600       # rows per client per minute
LOG_BUDGET_TOTAL = 30000          # rows per minute across all clients (forged sources each get a budget)
LOG_BUDGET_MAX_CLIENTS = 4096     # budget table bound; beyond it new sources are not logged that minute
# Inventory devices (``clients.KnownClients``) are budgeted outside the two shared pools above: forged
# source addresses can fill the table or the total, but never stop a real device's lookups being
# logged. Each known device still has its own LOG_BUDGET_PER_CLIENT.
OVERFLOW_EVENT_SECONDS = 3600.0   # at most one "forged sources flooded the query log" event per hour
OVERFLOW_SAMPLE = 8               # source addresses quoted in that event
MAX_QNAME_LOG = 255              # a wire name is at most 255 octets; dnslib's escaped text can be longer
MAX_LOG_ROWS = 2_000_000          # hard cap on dns_queries, oldest rows evicted first
ROW_CAP_CHECK_SECONDS = 300.0
ROW_CAP_CHUNK = 50_000            # delete in slices so no single statement holds the DB lock for long
BUDGET_EVENTS_PER_HOUR = 20       # "client X exceeded its log budget" events, per client at most hourly

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
        client_budget: int = LOG_BUDGET_PER_CLIENT,
        total_budget: int = LOG_BUDGET_TOTAL,
        max_rows: int = MAX_LOG_ROWS,
        known=None,
    ) -> None:
        self.conn = conn
        self.known = known  # ``client in known`` → an inventory device with its own reserved budget
        self.enabled = enabled
        self.flush_interval = flush_interval
        self.batch_size = batch_size
        self.client_budget = max(1, int(client_budget))
        self.total_budget = max(1, int(total_budget))
        self.max_rows = max(1, int(max_rows))
        self._queue: deque[QueryRecord] = deque()
        # [second, count] pairs for qps_1m (kept even when logging is off); at most 61 entries however
        # fast queries arrive, unlike one timestamp per query.
        self._recent: deque[list[int]] = deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._budget_minute: int | None = None
        self._budget_used: dict[str, int] = {}
        self._budget_total = 0
        self._known_used: dict[str, int] = {}           # inventory devices: rows this minute, outside the pools
        self._over_budget: dict[str, int] = {}          # client -> rows not logged, reported by flush()
        self._budget_events: dict[str, float] = {}      # client -> monotonic time of its last event
        self._overflow_rows = 0                         # rows refused because the source table was full
        self._overflow_sample: list[str] = []
        self._overflow_event_at: float | None = None
        self.overflowed = 0
        # Addresses quoted by the last overflow (kept after the event so the resolver's health check
        # can put them in NET-DNS-007's evidence even when the hourly event was not written).
        self.last_overflow_sample: list[str] = []
        self._last_cap_check = time.monotonic()
        self.total = 0
        self.dropped = 0
        self.suppressed = 0

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
            if time.monotonic() - self._last_cap_check >= ROW_CAP_CHECK_SECONDS:
                self._last_cap_check = time.monotonic()
                try:
                    enforce_row_cap(self.conn, self.max_rows)
                except Exception:
                    logger.exception("query log row cap failed")

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
            sec = int(now)
            if self._recent and self._recent[-1][0] == sec:
                self._recent[-1][1] += 1
            else:
                self._recent.append([sec, 1])
            self._trim_recent(now)
            self.total += 1
            if not self.enabled:
                return
            if not self._within_budget(client, now):
                self.suppressed += 1
                return
            if len(self._queue) >= self.batch_size * 20:  # disk stalled: drop rather than eat memory
                self.dropped += 1
                return
            self._queue.append(
                QueryRecord(ts or utcnow_iso(), str(client)[:64], str(qname)[:MAX_QNAME_LOG], str(qtype)[:16], action,
                            None if reason is None else str(reason)[:200], None if ms is None else round(ms, 2))
            )
            wake = len(self._queue) >= self.batch_size
        if wake:
            self._wake.set()

    def _within_budget(self, client: str, now: float) -> bool:
        """Per-client and total rows-per-minute budget (caller holds the lock)."""
        minute = int(now // 60)
        if minute != self._budget_minute:
            self._budget_minute = minute
            self._budget_used.clear()
            self._known_used.clear()
            self._budget_total = 0
        known = self.known
        if known is not None and client in known:
            # A real device: its own budget, never drawn from the table or the total that forged
            # sources can exhaust (the known set is bounded by the inventory, not by packets).
            used = self._known_used.get(client, 0)
            if used >= self.client_budget:
                self._over_budget[client] = self._over_budget.get(client, 0) + 1
                return False
            self._known_used[client] = used + 1
            return True
        used = self._budget_used.get(client)
        if used is None and len(self._budget_used) >= LOG_BUDGET_MAX_CLIENTS:
            # Only reachable with thousands of source addresses in one minute, i.e. forged ones.
            # Counted and reported (see _report_overflow) instead of vanishing without a trace.
            self._overflow_rows += 1
            self.overflowed += 1
            if len(self._overflow_sample) < OVERFLOW_SAMPLE:
                self._overflow_sample.append(str(client)[:64])
            return False
        used = used or 0
        if used >= self.client_budget or self._budget_total >= self.total_budget:
            if len(self._over_budget) < LOG_BUDGET_MAX_CLIENTS or client in self._over_budget:
                self._over_budget[client] = self._over_budget.get(client, 0) + 1
            return False
        self._budget_used[client] = used + 1
        self._budget_total += 1
        return True

    def _trim_recent(self, now: float) -> None:
        while self._recent and now - self._recent[0][0] > 60.0:
            self._recent.popleft()

    def qps_1m(self) -> float:
        with self._lock:
            self._trim_recent(time.monotonic())
            return round(sum(n for _, n in self._recent) / 60.0, 3)

    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    def _report_over_budget(self) -> None:
        """One event per noisy client per hour (at most ``BUDGET_EVENTS_PER_HOUR`` in total), written
        from the flush thread so the resolver's answer path never waits on the DB lock."""
        with self._lock:
            over, self._over_budget = self._over_budget, {}
            overflow, sample = self._overflow_rows, self._overflow_sample
            self._overflow_rows, self._overflow_sample = 0, []
        now = time.monotonic()
        if overflow:
            if sample:
                self.last_overflow_sample = list(sample)
            self._report_overflow(overflow, sample, now)
        if not over:
            return
        for c in [c for c, t in self._budget_events.items() if now - t >= 3600]:
            del self._budget_events[c]
        for client, n in sorted(over.items(), key=lambda kv: -kv[1]):
            if client in self._budget_events or len(self._budget_events) >= BUDGET_EVENTS_PER_HOUR:
                continue
            self._budget_events[client] = now
            record_event(
                self.conn, "warning", "dns",
                f"{client} sent more DNS queries than the query log keeps ({self.client_budget}/min); "
                f"{n} were answered but not logged",
                {"client": client, "not_logged": n, "budget_per_minute": self.client_budget},
            )

    def _report_overflow(self, rows: int, sample: list[str], now: float) -> None:
        """One event per hour when the per-minute source table overflowed. That needs thousands of
        distinct source addresses within a minute, which a home network only produces when someone
        is forging them — typically to push other devices' lookups out of this log."""
        if self._overflow_event_at is not None and now - self._overflow_event_at < OVERFLOW_EVENT_SECONDS:
            return
        self._overflow_event_at = now
        record_event(
            self.conn, "warning", "dns",
            f"The DNS query log was offered more than {LOG_BUDGET_MAX_CLIENTS} different source addresses in one "
            f"minute; {rows} queries from addresses outside the device inventory were answered but not logged. "
            "A home network does not have that many devices: something on the LAN is probably forging source "
            "addresses. Lookups by devices in the inventory are still logged.",
            {"not_logged": rows, "sources_per_minute_limit": LOG_BUDGET_MAX_CLIENTS, "sample_sources": sample},
        )

    def flush(self) -> int:
        try:
            self._report_over_budget()
        except Exception:
            logger.debug("could not report query-log budget overruns", exc_info=True)
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


def enforce_row_cap(conn: sqlite3.Connection, max_rows: int = MAX_LOG_ROWS, *, chunk: int = ROW_CAP_CHUNK) -> int:
    """Evict the oldest ``dns_queries`` rows beyond ``max_rows``; returns how many were deleted.

    Retention alone is time-based, so a flood could still fill the disk within the window. ``id`` is
    the rowid and only grows, so ``id <= MAX(id) - max_rows`` is the oldest excess (a gap-free
    upper bound), and deleting it in ``chunk``-sized id ranges keeps each statement short.
    """
    max_rows = max(1, int(max_rows))
    row = db_query(conn, "SELECT MIN(id) AS lo, MAX(id) AS hi FROM dns_queries")
    if not row or row[0]["hi"] is None:
        return 0
    lo, cutoff = int(row[0]["lo"]), int(row[0]["hi"]) - max_rows
    if lo > cutoff:
        return 0
    n_row = db_query(conn, "SELECT COUNT(*) AS n FROM dns_queries WHERE id <= ?", (cutoff,))
    n = int(n_row[0]["n"]) if n_row else 0
    while lo <= cutoff:
        upto = min(cutoff, lo + max(1, int(chunk)) - 1)
        db_write(conn, "DELETE FROM dns_queries WHERE id BETWEEN ? AND ?", (lo, upto))
        lo = upto + 1
    if n:
        logger.warning("DNS query log over %d rows; evicted the %d oldest", max_rows, n)
    return n


def maintenance(cfg, conn: sqlite3.Connection) -> dict:
    """One call for the scheduler's ``dns_rollup`` job: rollup + purge (+ the row cap)."""
    from homesoc.dnsfilter import cfg_get

    days = int(cfg_get(cfg, "dns", "log_retention_days", 14) or 14)
    written = rollup(conn)
    purged = purge(conn, days)
    try:
        enforce_row_cap(conn)
    except sqlite3.Error:
        logger.exception("query log row cap failed")
    try:
        # The reputation table gains a row per newly seen domain from any (forgeable) source; this
        # is its retention, run on the same hourly job.
        from homesoc.dnsfilter.reputation import prune_reputation

        prune_reputation(conn)
    except sqlite3.Error:
        logger.exception("reputation table prune failed")
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
