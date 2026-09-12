"""Activity feed: one reverse-chronological stream of everything the agent saw and did.

Spec Addendum A2. Every table that records "something happened" contributes ``FeedItem``s
here (findings lifecycle, device inventory, scans, feed updates, DNS decisions, Defender
detections, notifications, system events); :func:`build_feed` heap-merges them in Python
rather than UNION-ing unbounded scans, so each source query is bounded by ``limit + offset``
and uses the indexed timestamp column.

Titles and details are **plain text** — they carry device hostnames, domains and process
names straight from the network, so they are never HTML and every consumer (Jinja, RSS,
the CLI) escapes them for its own medium.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any, Callable, Iterable

from homesoc.web import api

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- kinds

# (kind, label, icon, default severity). ``icon`` is an ascii token the template maps to a glyph.
KIND_TABLE: tuple[tuple[str, str, str], ...] = (
    ("finding_new", "New finding", "finding"),
    ("finding_reopened", "Reopened finding", "finding"),
    ("finding_resolved", "Remediated", "resolved"),
    ("finding_auto_resolved", "Fixed and verified", "resolved"),
    ("finding_ack", "Acknowledged", "finding"),
    ("finding_suppressed", "Suppressed", "finding"),
    ("device_new", "New device", "device"),
    ("device_offline", "Device offline", "device"),
    ("scan", "Scan", "scan"),
    ("feed_update", "Feed update", "feed"),
    ("dns_block", "DNS blocked", "dns"),
    ("dns_threat", "Malicious domain blocked", "threat"),
    ("av_threat", "Defender detection", "threat"),
    ("notification", "Notification", "notify"),
    ("system", "System", "system"),
)
KINDS: tuple[str, ...] = tuple(k for k, _, _ in KIND_TABLE)
ICON_BY_KIND: dict[str, str] = {k: icon for k, _, icon in KIND_TABLE}
LABEL_BY_KIND: dict[str, str] = {k: label for k, label, _ in KIND_TABLE}

# finding_events.event -> (feed kind, title prefix)
_FINDING_EVENTS: dict[str, tuple[str, str]] = {
    # findings.engine writes "opened" for a newly created finding; the addendum's table calls the
    # same event "created". Accept every spelling so the feed's headline kind is never empty.
    "opened": ("finding_new", "New finding"),
    "created": ("finding_new", "New finding"),
    "new": ("finding_new", "New finding"),
    "reopened": ("finding_reopened", "Reopened"),
    "resolved": ("finding_resolved", "Remediated"),
    "auto_resolved": ("finding_auto_resolved", "Fixed and verified"),
    "acknowledged": ("finding_ack", "Acknowledged"),
    "suppressed": ("finding_suppressed", "Suppressed"),
}

# Blocklists whose hits mean "malware/phishing", not "advertising"; a block from one of these
# is worth a medium severity row in the feed even when it is not a per-query threat verdict.
THREAT_LISTS: frozenset[str] = frozenset(
    {"urlhaus", "threatfox", "openphish", "phishing_army", "feodo", "feodo_ips", "spamhaus_drop", "urlhaus_filter"}
)

# Two-label public suffixes common enough to matter for "registrable domain" grouping. A full
# public-suffix list would be a dependency (and a feed); these cover the everyday cases.
_SECOND_LEVEL: frozenset[str] = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "gob"})

SEVERITY_RANK: dict[str, int] = {sev: i for i, sev in enumerate(api.SEVERITIES)}

MAX_LIMIT = 500
MAX_OFFSET = 20000


@dataclass(frozen=True)
class FeedItem:
    """One thing that happened. ``title``/``detail`` are plain text, never HTML."""

    ts: str  # UTC ISO-8601, "...Z"
    kind: str
    severity: str  # critical|high|medium|low|info
    title: str
    detail: str = ""
    link: str | None = None
    icon: str = "system"
    ref: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- helpers


def feed_kinds() -> list[dict]:
    """Filter-UI descriptor for every kind the feed can produce."""
    return [{"kind": k, "label": label, "icon": icon} for k, label, icon in KIND_TABLE]


def _iso(value: Any) -> str | None:
    """Normalise any stored timestamp to ``YYYY-MM-DDTHH:MM:SSZ`` so the merge orders correctly."""
    dt = api.parse_ts(value)
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _bare(value: Any) -> str | None:
    """Bare ``YYYY-MM-DDTHH:MM:SS`` bound, which compares correctly against both the 'Z' and
    the '+00:00' spellings other packages write."""
    dt = api.parse_ts(value)
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S")


def _until_bound(value: Any) -> str | None:
    """Exclusive upper bound one second past ``until`` so an item exactly at ``until`` is kept
    whichever timestamp spelling it uses."""
    dt = api.parse_ts(value)
    return None if dt is None else (dt + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S")


def registrable_domain(name: Any) -> str:
    """Best-effort eTLD+1 used to group DNS blocks (``a.b.doubleclick.net`` -> ``doubleclick.net``)."""
    host = str(name or "").strip().lower().rstrip(".")
    if not host:
        return ""
    labels = [p for p in host.split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if labels[-2] in _SECOND_LEVEL and len(labels[-1]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return ""
    seconds = int(seconds)
    if seconds >= 3600:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    if seconds >= 60:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds}s"


def _open_for(first_seen: Any, resolved_at: Any) -> str:
    start, end = api.parse_ts(first_seen), api.parse_ts(resolved_at)
    if start is None or end is None:
        return ""
    hours = (end - start).total_seconds() / 3600.0
    if hours < 1:
        return f"open {max(1, int(hours * 60))} min"
    if hours < 48:
        return f"open {hours:.0f} h"
    return f"open {hours / 24:.0f} days"


def _sev(value: Any, default: str = "info") -> str:
    sev = str(value or "").lower()
    return sev if sev in SEVERITY_RANK else default


@dataclass(frozen=True)
class _Query:
    since: str | None
    until: str | None
    kinds: frozenset[str] | None
    cap: int
    severities: frozenset[str] | None = None

    def wants(self, *kinds: str) -> bool:
        return self.kinds is None or any(k in self.kinds for k in kinds)

    def window(self, column: str = "ts") -> tuple[str, list]:
        """SQL fragment + params restricting ``column`` to the requested window."""
        parts, params = [], []
        if self.since:
            parts.append(f"{column}>=?")
            params.append(self.since)
        if self.until:
            parts.append(f"{column}<?")
            params.append(self.until)
        return (" AND " + " AND ".join(parts) if parts else ""), params


# --------------------------------------------------------------------------- sources


def _findings_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    if not q.wants(*(k for k, _ in _FINDING_EVENTS.values())):
        return []
    where, params = q.window("e.at")
    if q.kinds is not None:
        # Push the kind filter into SQL. Without it the LIMIT below is spent on event rows that
        # the caller filtered out, so a filtered page returns a handful of rows instead of a full one.
        events = sorted(name for name, (kind, _) in _FINDING_EVENTS.items() if kind in q.kinds)
        if not events:
            return []
        where += " AND lower(e.event) IN (" + ",".join("?" for _ in events) + ")"
        params = params + events
    if q.severities is not None:
        # Same reason again: severity is a column for "new"/"reopened" rows (every other event
        # renders as info), so filtering here means a severity-filtered page comes back full.
        sev = sorted(q.severities)
        own = sorted(n for n, (kind, _) in _FINDING_EVENTS.items()
                     if kind in ("finding_new", "finding_reopened"))
        rest = sorted(n for n, (kind, _) in _FINDING_EVENTS.items()
                      if kind not in ("finding_new", "finding_reopened"))
        clauses: list[str] = []
        extra: list[Any] = []
        if own:
            marks_e = ",".join("?" for _ in own)
            marks_s = ",".join("?" for _ in sev)
            # an unrecognised severity renders as "info" in _sev(), so keep those rows too
            tail = " OR lower(COALESCE(f.severity,'')) NOT IN ('critical','high','medium','low','info')"                 if "info" in q.severities else ""
            clauses.append(f"(lower(e.event) IN ({marks_e}) AND (lower(f.severity) IN ({marks_s}){tail}))")
            extra += own + sev
        if rest and "info" in q.severities:
            clauses.append("lower(e.event) IN (" + ",".join("?" for _ in rest) + ")")
            extra += rest
        if not clauses:
            return []
        where += " AND (" + " OR ".join(clauses) + ")"
        params = params + extra
    data = api.rows(
        conn,
        "SELECT e.id AS event_id, e.event, e.at, e.note, f.id AS row_id, f.finding_id, f.title, f.severity, "
        "f.subject, f.detail, f.first_seen, f.resolved_at, f.device_id, "
        "COALESCE(d.nickname, d.hostname, d.ip, d.mac) AS device_name "
        "FROM finding_events e JOIN findings f ON f.id=e.finding_row_id "
        "LEFT JOIN devices d ON d.id=f.device_id "
        f"WHERE 1=1{where} ORDER BY e.at DESC, e.id DESC LIMIT ?",
        params + [q.cap],
    )
    out: list[FeedItem] = []
    for r in data:
        mapped = _FINDING_EVENTS.get(str(r.get("event") or "").lower())
        if mapped is None:
            continue
        kind, prefix = mapped
        if not q.wants(kind):
            continue
        ts = _iso(r.get("at"))
        if ts is None:
            continue
        severity = _sev(r.get("severity")) if kind in ("finding_new", "finding_reopened") else "info"
        title = f"{prefix}: {r.get('title') or r.get('finding_id')}"
        if kind in ("finding_resolved", "finding_auto_resolved"):
            span = _open_for(r.get("first_seen"), r.get("at"))
            if span:
                title += f" ({span})"
        bits = [b for b in (r.get("device_name"), r.get("note")) if b]
        detail = " · ".join(str(b) for b in bits) or str(r.get("detail") or "")
        out.append(
            FeedItem(
                ts=ts,
                kind=kind,
                severity=severity,
                title=title,
                detail=detail[:400],
                link=f"/findings?focus={int(r['row_id'])}",
                icon=ICON_BY_KIND[kind],
                ref={
                    "finding_row_id": int(r["row_id"]),
                    "finding_id": r.get("finding_id"),
                    "device_id": r.get("device_id"),
                    "subject": r.get("subject"),
                },
            )
        )
    return out


def _devices_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    out: list[FeedItem] = []
    if q.wants("device_new"):
        where, params = q.window("first_seen")
        for r in api.rows(
            conn,
            "SELECT id, ip, mac, vendor, COALESCE(nickname, hostname, ip, mac) AS name, first_seen "
            f"FROM devices WHERE 1=1{where} ORDER BY first_seen DESC LIMIT ?",
            params + [q.cap],
        ):
            ts = _iso(r.get("first_seen"))
            if ts is None:
                continue
            where_bits = ", ".join(str(b) for b in (r.get("ip"), r.get("vendor")) if b)
            out.append(
                FeedItem(
                    ts=ts,
                    kind="device_new",
                    severity="medium",
                    title=f"New device joined the network: {r.get('name') or 'unknown'}"
                    + (f" ({where_bits})" if where_bits else ""),
                    detail=f"MAC {r.get('mac')}" if r.get("mac") else "",
                    link=f"/devices/{int(r['id'])}",
                    icon="device",
                    ref={"device_id": int(r["id"]), "ip": r.get("ip"), "mac": r.get("mac")},
                )
            )
    if q.wants("device_offline"):
        where, params = q.window("last_seen")
        for r in api.rows(
            conn,
            "SELECT id, ip, COALESCE(nickname, hostname, ip, mac) AS name, last_seen "
            f"FROM devices WHERE online=0{where} ORDER BY last_seen DESC LIMIT ?",
            params + [q.cap],
        ):
            ts = _iso(r.get("last_seen"))
            if ts is None:
                continue
            out.append(
                FeedItem(
                    ts=ts,
                    kind="device_offline",
                    severity="info",
                    title=f"Device went offline: {r.get('name') or 'unknown'}",
                    detail=f"last seen at {r.get('ip')}" if r.get("ip") else "",
                    link=f"/devices/{int(r['id'])}",
                    icon="device",
                    ref={"device_id": int(r["id"]), "ip": r.get("ip")},
                )
            )
    return out


def _scan_summary_words(summary: Any) -> str:
    """'20 devices, 6 services, 27 findings' from whatever the scanner put in scans.summary."""
    data = api.loads(summary, None)
    if not isinstance(data, dict):
        return str(summary or "")[:200]
    words = []
    for key, value in list(data.items())[:6]:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        words.append(f"{value:,} {str(key).replace('_', ' ')}" if value == int(value) else f"{value} {key}")
    return ", ".join(words)


def _scans_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    if not q.wants("scan"):
        return []
    where, params = q.window("COALESCE(finished_at, started_at)")
    data = api.rows(
        conn,
        "SELECT id, kind, started_at, finished_at, status, summary, error FROM scans "
        f"WHERE finished_at IS NOT NULL{where} ORDER BY COALESCE(finished_at, started_at) DESC LIMIT ?",
        params + [q.cap],
    )
    out: list[FeedItem] = []
    for r in data:
        ts = _iso(r.get("finished_at")) or _iso(r.get("started_at"))
        if ts is None:
            continue
        start, end = api.parse_ts(r.get("started_at")), api.parse_ts(r.get("finished_at"))
        took = _duration((end - start).total_seconds()) if start and end else ""
        status = str(r.get("status") or "").lower()
        kind_name = str(r.get("kind") or "scan")
        if status == "error":
            title = f"{kind_name.capitalize()} scan failed"
            detail = str(r.get("error") or "")[:300]
            severity = "medium"
        else:
            words = _scan_summary_words(r.get("summary"))
            title = f"{kind_name.capitalize()} scan finished" + (f": {words}" if words else "")
            if took:
                title += f" ({took})"
            detail = ""
            severity = "info"
        out.append(
            FeedItem(ts=ts, kind="scan", severity=severity, title=title, detail=detail, link="/scans", icon="scan",
                     ref={"scan_id": int(r["id"]), "kind": kind_name, "status": status})
        )
    return out


def _feed_update_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    if not q.wants("feed_update"):
        return []
    where, params = q.window("ts")
    data = api.rows(
        conn,
        "SELECT id, ts, message, data FROM events WHERE source='feeds' AND lower(level) NOT IN ('warning','error')"
        f"{where} ORDER BY ts DESC, id DESC LIMIT ?",
        params + [q.cap],
    )
    out: list[FeedItem] = []
    for r in data:
        ts = _iso(r.get("ts"))
        if ts is None:
            continue
        payload = api.loads(r.get("data"), {}) or {}
        name = str(payload.get("feed") or "") if isinstance(payload, dict) else ""
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if name:
            title = f"Blocklist updated: {name}"
            if isinstance(entries, (int, float)):
                title += f" ({int(entries):,} entries)"
        else:
            title = str(r.get("message") or "Feed updated")
        out.append(
            FeedItem(ts=ts, kind="feed_update", severity="info", title=title[:300],
                     detail="" if name else "", link="/telemetry", icon="feed",
                     ref={"feed": name or None, "entries": entries})
        )
    return out


def _dns_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    out: list[FeedItem] = []
    if q.wants("dns_threat"):
        where, params = q.window("ts")
        for r in api.rows(
            conn,
            # Addendum A2.1 describes these reasons as `threat:...` / `reputation:...`, but
            # dnsfilter/policy.py writes the bare string "reputation" (Decision("block",
            # "reputation", s)) and never writes a `threat:` prefix at all. Matching only the
            # prefixed spellings made dns_threat a kind that could never fire in production, so a
            # reputation block showed up as a plain dns_block. Accept both spellings.
            "SELECT id, ts, client, qname, reason FROM dns_queries WHERE action='block' AND "
            f"(reason LIKE 'threat:%' OR reason = 'reputation' OR reason LIKE 'reputation:%')"
            f"{where} ORDER BY ts DESC, id DESC LIMIT ?",
            params + [q.cap],
        ):
            ts = _iso(r.get("ts"))
            if ts is None:
                continue
            out.append(
                FeedItem(
                    ts=ts,
                    kind="dns_threat",
                    severity="high",
                    title=f"Blocked a known-malicious domain: {r.get('qname')} requested by {r.get('client')}",
                    detail=str(r.get("reason") or ""),
                    link=f"/dns?client={r.get('client') or ''}&q={r.get('qname') or ''}",
                    icon="threat",
                    ref={"client": r.get("client"), "domain": r.get("qname"), "reason": r.get("reason")},
                )
            )
    if q.wants("dns_block"):
        where, params = q.window("ts")
        # Grouped in SQL by (client, qname, hour) to bound the row count, then re-grouped in
        # Python by registrable domain, which SQLite cannot compute.
        grouped = api.rows(
            conn,
            "SELECT client, qname, substr(ts,1,13) AS hour, count(*) AS hits, max(ts) AS ts, max(reason) AS reason "
            "FROM dns_queries WHERE action='block' AND "
            # Must stay the exact complement of the dns_threat filter above, or a reputation block
            # is reported twice (once as a threat, once as an ordinary ad block) or not at all.
            f"(reason IS NULL OR (reason NOT LIKE 'threat:%' AND reason <> 'reputation' "
            f"AND reason NOT LIKE 'reputation:%')){where} "
            "GROUP BY client, qname, hour ORDER BY ts DESC LIMIT ?",
            params + [max(q.cap * 4, 200)],
        )
        buckets: dict[tuple[str, str, str], dict] = {}
        for r in grouped:
            domain = registrable_domain(r.get("qname"))
            key = (str(r.get("client") or ""), domain, str(r.get("hour") or ""))
            b = buckets.setdefault(key, {"hits": 0, "ts": "", "reason": None, "names": set()})
            b["hits"] += int(r.get("hits") or 0)
            ts = _iso(r.get("ts")) or ""
            if ts > b["ts"]:
                b["ts"] = ts
            if r.get("reason") and not b["reason"]:
                b["reason"] = r.get("reason")
            b["names"].add(str(r.get("qname") or ""))
        for (client, domain, hour), b in buckets.items():
            if not b["ts"]:
                continue
            reason = str(b["reason"] or "")
            severity = "medium" if any(t in reason.lower() for t in THREAT_LISTS) else "info"
            names = sorted(b["names"])
            detail = f"list: {reason}" if reason else ""
            if len(names) > 1:
                detail = (detail + " · " if detail else "") + f"{len(names)} names, e.g. {names[0]}"
            out.append(
                FeedItem(
                    ts=b["ts"],
                    kind="dns_block",
                    severity=severity,
                    title=f"Blocked {_plural(b['hits'], 'request')} to {domain or 'a domain'} from {client}",
                    detail=detail,
                    link=f"/dns?client={client}&q={domain}",
                    icon="dns",
                    ref={"client": client, "domain": domain, "hour": hour, "hits": b["hits"]},
                )
            )
    return out


def _events_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    """Defender detections and everything else that logged a warning or an error."""
    if not q.wants("av_threat", "system"):
        return []
    where, params = q.window("ts")
    # Push the source split into SQL for the same reason as in _findings_source: asking for only
    # one of the two kinds must not spend the LIMIT on rows that are then dropped.
    if q.kinds is not None and not q.wants("system"):
        where += " AND lower(source)='defender'"
    elif q.kinds is not None and not q.wants("av_threat"):
        where += " AND lower(source)<>'defender'"
    data = api.rows(
        conn,
        "SELECT id, ts, level, source, message, data FROM events "
        f"WHERE lower(level) IN ('warning','warn','error','critical'){where} ORDER BY ts DESC, id DESC LIMIT ?",
        params + [q.cap],
    )
    out: list[FeedItem] = []
    for r in data:
        ts = _iso(r.get("ts"))
        if ts is None:
            continue
        source = str(r.get("source") or "")
        level = str(r.get("level") or "").lower()
        is_av = source.lower() == "defender"
        kind = "av_threat" if is_av else "system"
        if not q.wants(kind):
            continue
        severity = "high" if (is_av or level in ("error", "critical")) else "medium"
        message = str(r.get("message") or "")
        title = f"Microsoft Defender: {message}" if is_av else message
        out.append(
            FeedItem(ts=ts, kind=kind, severity=severity, title=title[:300],
                     detail=("" if is_av else f"source: {source}"),
                     link="/host" if is_av else "/telemetry", icon="threat" if is_av else "system",
                     ref={"event_id": int(r["id"]), "source": source, "level": level})
        )
    return out


def _notifications_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    if not q.wants("notification"):
        return []
    where, params = q.window("ts")
    data = api.rows(
        conn,
        f"SELECT id, ts, channel, subject, status, error FROM notifications WHERE 1=1{where} "
        "ORDER BY ts DESC, id DESC LIMIT ?",
        params + [q.cap],
    )
    out: list[FeedItem] = []
    for r in data:
        ts = _iso(r.get("ts"))
        if ts is None:
            continue
        status = str(r.get("status") or "")
        ok = status.lower() in ("ok", "sent", "success", "1", "true")
        title = (
            f"Alert sent to {r.get('channel')}: {r.get('subject')}"
            if ok
            else f"Alert to {r.get('channel')} failed: {r.get('subject')}"
        )
        out.append(
            FeedItem(ts=ts, kind="notification", severity="info" if ok else "medium", title=title[:300],
                     detail=str(r.get("error") or "")[:300], link="/settings", icon="notify",
                     ref={"notification_id": int(r["id"]), "channel": r.get("channel"), "status": status})
        )
    return out


_SOURCES: tuple[Callable[[sqlite3.Connection, _Query], list[FeedItem]], ...] = (
    _findings_source,
    _devices_source,
    _scans_source,
    _feed_update_source,
    _dns_source,
    _events_source,
    _notifications_source,
)


# --------------------------------------------------------------------------- collapsing runs

# A finding that flaps (acknowledged, reopened, acknowledged, reopened...) or a scan that runs
# every ten minutes produces a wall of identical rows that buries everything else. Rows sharing a
# (kind, title) are folded into one as long as each is within COLLAPSE_GAP_SECONDS of the previous
# member of that run and the whole run stays inside COLLAPSE_SPAN_SECONDS. Both bounds matter: the
# gap is what makes it a "run" rather than a monthly recurrence, and the span stops a steady
# trickle from folding a year of history into a single line.
COLLAPSE_GAP_SECONDS = 3600
COLLAPSE_SPAN_SECONDS = 24 * 3600

#: Most members carried in ``ref["collapsed"]``; ``ref["count"]`` is always the true total.
COLLAPSE_MEMBER_CAP = 50


def _repeat_note(count: int, oldest: str, newest: str) -> str:
    """Plain-text sentence describing a collapsed run, for the detail line / RSS / the CLI."""
    start, end = api.parse_ts(oldest), api.parse_ts(newest)
    if start is None or end is None:
        return f"Repeated {count} times."
    if start.date() == end.date():
        return f"Repeated {count} times between {start:%H:%M} and {end:%H:%M} UTC on {start:%Y-%m-%d}."
    return f"Repeated {count} times between {start:%Y-%m-%d %H:%M} and {end:%Y-%m-%d %H:%M} UTC."


def collapse_runs(
    items: list[FeedItem],
    *,
    gap_seconds: int = COLLAPSE_GAP_SECONDS,
    span_seconds: int = COLLAPSE_SPAN_SECONDS,
) -> list[FeedItem]:
    """Fold runs of the same ``(kind, title)`` into one row each, newest-first order preserved.

    ``items`` must already be sorted newest first. A collapsed row keeps the newest member's
    text and link and gains ``ref["count"]`` (how many events it stands for), ``ref["from"]`` /
    ``ref["to"]`` (the time range) and ``ref["collapsed"]`` — one ``{"ts", "link"}`` entry per
    member, newest first, so the page's "show all" toggle and ``/api/feed`` can still reach every
    individual event even when they point at different findings. Rows that stand alone are
    returned untouched — no ``count`` key, so "is this collapsed?" is just ``ref.get("count")``.

    ``count`` counts the members present in ``items``. Each feed source is deliberately bounded
    (Addendum A2.1: no unbounded scans), so a very small ``limit`` can under-report a long run —
    the count is "how many of the events fetched for this page were identical", never an
    all-time total. The page's default limit of 200 makes that distinction academic in practice.
    """
    if gap_seconds <= 0 or len(items) < 2:
        return list(items)

    # ``runs`` keeps output order (a run's head is its newest member, and the input is newest
    # first, so the heads stay strictly descending); ``newest_run`` finds the run a row may join.
    runs: list[list[FeedItem]] = []
    newest_run: dict[tuple[str, str], list[FeedItem]] = {}

    for item in items:
        key = (item.kind, item.title)
        run = newest_run.get(key)
        if run is not None:
            gap = _seconds_between(item.ts, run[-1].ts)
            span = _seconds_between(item.ts, run[0].ts)
            if gap is not None and span is not None and gap <= gap_seconds and span <= span_seconds:
                run.append(item)
                continue
        run = [item]
        runs.append(run)
        newest_run[key] = run

    out: list[FeedItem] = []
    for members in runs:
        if len(members) == 1:
            out.append(members[0])
            continue
        newest, oldest = members[0], members[-1]
        note = _repeat_note(len(members), oldest.ts, newest.ts)
        base = newest.detail.strip()
        if base and base[-1] not in ".!?":
            base += "."
        ref = dict(newest.ref)
        ref["count"] = len(members)
        ref["from"] = oldest.ts
        ref["to"] = newest.ts
        ref["collapsed"] = [
            {"ts": m.ts, "link": m.link} if m.link else {"ts": m.ts}
            for m in members[:COLLAPSE_MEMBER_CAP]
        ]
        out.append(
            FeedItem(
                ts=newest.ts,
                kind=newest.kind,
                severity=min((m.severity for m in members), key=lambda s: SEVERITY_RANK.get(s, 9)),
                title=newest.title,
                detail=f"{base} {note}" if base else note,
                link=newest.link,
                icon=newest.icon,
                ref=ref,
            )
        )
    return out


def _seconds_between(older: str, newer: str) -> float | None:
    a, b = api.parse_ts(older), api.parse_ts(newer)
    return None if a is None or b is None else abs((b - a).total_seconds())


# --------------------------------------------------------------------------- merge


def _matches(item: FeedItem, severities: frozenset[str] | None, needle: str | None) -> bool:
    if severities is not None and item.severity not in severities:
        return False
    if needle:
        haystack = f"{item.title}\n{item.detail}\n{item.kind}".lower()
        if needle not in haystack:
            return False
    return True


def build_feed(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    until: str | None = None,
    kinds: Iterable[str] | None = None,
    severities: Iterable[str] | None = None,
    q: str | None = None,
    limit: int = 200,
    offset: int = 0,
    collapse: bool = True,
) -> tuple[list[FeedItem], int]:
    """Merge every source into one ``ts``-descending stream.

    Returns ``(items, total_matching)``. ``total_matching`` counts the merged candidate window,
    which each source bounds at ``limit + offset + 1`` rows — enough to paginate correctly and to
    say "N more", without ever scanning a whole table. The extra row is the sentinel that keeps
    "Load more" visible when a single source fills the whole page.

    ``collapse`` (the default) folds runs of the same ``(kind, title)`` into one row each — see
    :func:`collapse_runs`. It happens before ``offset``/``limit`` are applied, so pages stay
    consistent and ``total`` counts rows as displayed. Every individual event survives inside the
    collapsed row's ``ref``; pass ``collapse=False`` for the raw event stream.
    """
    limit = max(1, min(int(limit or 1), MAX_LIMIT))
    offset = max(0, min(int(offset or 0), MAX_OFFSET))
    kind_set = frozenset(k for k in (kinds or ()) if k in KINDS) or None
    sev_set = frozenset(s for s in (severities or ()) if s in SEVERITY_RANK) or None
    needle = (q or "").strip().lower()[:200] or None
    query = _Query(since=_bare(since), until=_until_bound(until), kinds=kind_set,
                   cap=limit + offset + 1, severities=sev_set)

    items: list[FeedItem] = []
    for source in _SOURCES:
        try:
            items.extend(source(conn, query))
        except Exception:  # one broken table must never take the feed down
            logger.exception("feed source %s failed", getattr(source, "__name__", source))
    items = [i for i in items if _matches(i, sev_set, needle)]
    items.sort(key=lambda i: (i.ts, SEVERITY_RANK.get(i.severity, 9) * -1, i.kind), reverse=True)
    if collapse:
        items = collapse_runs(items)
    return items[offset : offset + limit], len(items)


def feed_counts(conn: sqlite3.Connection, hours: int = 24) -> dict[str, int]:
    """kind -> count over the last ``hours``, for the header chips.

    Counts individual events, not collapsed rows: "12 findings changed today" is the honest
    number for a chip, even when the timeline shows them as two lines.
    """
    hours = max(1, min(int(hours or 24), 24 * 365))
    items, _ = build_feed(conn, since=api.cutoff_iso(hours), limit=MAX_LIMIT, collapse=False)
    counts = {kind: 0 for kind in KINDS}
    for item in items:
        counts[item.kind] = counts.get(item.kind, 0) + 1
    return counts


def newest_ts(items: list[FeedItem]) -> str | None:
    return items[0].ts if items else None
