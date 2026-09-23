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

    @property
    def device_label(self) -> str | None:
        """The device this item is about, by name ("Ellie's iPhone", "Unnamed camera").

        Carried in ``ref`` so the item's top-level JSON shape (which feed readers and the API
        contract pin) is unchanged; ``None`` for network-wide items (scans, list updates).
        """
        value = self.ref.get("device_label") if isinstance(self.ref, dict) else None
        return str(value) if value else None


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
class DeviceFilter:
    """Restrict the feed to one device, *in SQL*.

    Filtering the merged stream in Python instead cannot work: every source is bounded by its
    own ``LIMIT cap``, so on a busy network the cap is spent on other devices' rows and the one
    being asked about is starved out of its own history. Only the three sources whose rows carry
    a device identity can honour this; the rest (scans, blocklist updates, notifications, system
    events) are network-wide and are simply skipped, which is exactly what a caller filtering in
    Python was already dropping.
    """

    device_id: int
    ip: str = ""
    mac: str = ""


@dataclass(frozen=True)
class _Query:
    since: str | None
    until: str | None
    kinds: frozenset[str] | None
    cap: int
    severities: frozenset[str] | None = None
    device: DeviceFilter | None = None

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
    if q.device is not None:
        where += " AND f.device_id=?"
        params = params + [q.device.device_id]
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
        "COALESCE(d.nickname, d.hostname, d.ip, d.mac) AS device_name, d.ip AS device_ip, "
        "d.nickname AS device_nickname, d.hostname AS device_hostname, d.kind AS device_kind "
        "FROM finding_events e JOIN findings f ON f.id=e.finding_row_id "
        "LEFT JOIN devices d ON d.id=f.device_id "
        f"WHERE 1=1{where} ORDER BY e.at DESC, e.id DESC LIMIT ?",
        params + [q.cap],
    )
    api.label_subject_rows(conn, data)  # device_label: "Unnamed camera", "This computer (Home PC)"
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
        bits = [b for b in (r.get("device_label"), r.get("note")) if b]
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
                    "device_label": r.get("device_label"),
                    "link_device_id": r.get("link_device_id"),
                },
            )
        )
    return out


def _devices_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    out: list[FeedItem] = []
    if q.wants("device_new"):
        where, params = q.window("first_seen")
        if q.device is not None:
            where += " AND id=?"
            params = params + [q.device.device_id]
        for r in api.rows(
            conn,
            "SELECT id, ip, mac, vendor, nickname, hostname, kind, first_seen "
            f"FROM devices WHERE 1=1{where} ORDER BY first_seen DESC LIMIT ?",
            params + [q.cap],
        ):
            ts = _iso(r.get("first_seen"))
            if ts is None:
                continue
            # Name first, then the address and maker: "Unnamed camera (192.168.1.142, Acme)", not
            # the IP twice as "192.168.1.142 (192.168.1.142)" for a device with no name.
            label = api.device_label(r)
            where_bits = ", ".join(str(b) for b in (r.get("ip"), r.get("vendor")) if b)
            out.append(
                FeedItem(
                    ts=ts,
                    kind="device_new",
                    severity="medium",
                    title=f"New device joined the network: {label}"
                    + (f" ({where_bits})" if where_bits else ""),
                    detail=f"MAC {r.get('mac')}" if r.get("mac") else "",
                    link=f"/devices/{int(r['id'])}",
                    icon="device",
                    ref={"device_id": int(r["id"]), "ip": r.get("ip"), "mac": r.get("mac"), "device_label": label},
                )
            )
    if q.wants("device_offline"):
        where, params = q.window("last_seen")
        if q.device is not None:
            where += " AND id=?"
            params = params + [q.device.device_id]
        for r in api.rows(
            conn,
            "SELECT id, ip, mac, nickname, hostname, kind, last_seen "
            f"FROM devices WHERE online=0{where} ORDER BY last_seen DESC LIMIT ?",
            params + [q.cap],
        ):
            ts = _iso(r.get("last_seen"))
            if ts is None:
                continue
            label = api.device_label(r)
            out.append(
                FeedItem(
                    ts=ts,
                    kind="device_offline",
                    severity="info",
                    title=f"Device went offline: {label}",
                    detail=f"last seen at {r.get('ip')}" if r.get("ip") else "",
                    link=f"/devices/{int(r['id'])}",
                    icon="device",
                    ref={"device_id": int(r["id"]), "ip": r.get("ip"), "device_label": label},
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
    if not q.wants("scan") or q.device is not None:
        return []  # a scan is network-wide; it belongs to no single device
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
    if not q.wants("feed_update") or q.device is not None:
        return []  # blocklist updates are network-wide
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
    if q.device is not None and not q.device.ip:
        return []  # DNS rows are keyed on the client address; with none there is nothing to match
    client_where = " AND client=?" if q.device is not None else ""
    client_param: list[Any] = [q.device.ip] if q.device is not None else []
    threats: list[dict] = []
    grouped: list[dict] = []
    if q.wants("dns_threat"):
        where, params = q.window("ts")
        where += client_where
        params = params + client_param
        threats = api.rows(
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
        )
    if q.wants("dns_block"):
        where, params = q.window("ts")
        where += client_where
        params = params + client_param
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

    # Clients are addresses; say whose address each one is. One lookup for the whole page.
    names = api.device_labels_by_ip(conn, [r.get("client") for r in threats + grouped])

    def who(client: Any) -> tuple[str, str | None, int | None]:
        """("Ellie's iPhone's address (192.168.1.32)", label, device_id); the bare address when unknown.

        A query's source address is the sender's word: any device on the network can send one
        from another's address. So the title says whose address it came from, never that the
        named device asked for it.
        """
        ip = str(client or "")
        hit = names.get(ip)
        if hit is None:
            return ip or "an unknown device", ("Unnamed device" if ip else None), None
        return api.address_of(hit["device_label"], ip), hit["device_label"], hit["device_id"]

    def with_note(detail: str, label: str | None, device_id: int | None) -> str:
        if device_id is None:
            return detail
        return (detail + " · " if detail else "") + api.ADDRESS_MATCH_NOTE

    for r in threats:
        ts = _iso(r.get("ts"))
        if ts is None:
            continue
        shown, label, device_id = who(r.get("client"))
        out.append(
            FeedItem(
                ts=ts,
                kind="dns_threat",
                severity="high",
                title=f"Blocked a known-malicious domain: {r.get('qname')} requested from {shown}",
                detail=with_note(_block_reason_words(str(r.get("reason") or "")), label, device_id),
                link=f"/dns?client={r.get('client') or ''}&q={r.get('qname') or ''}",
                icon="threat",
                ref={"client": r.get("client"), "domain": r.get("qname"), "reason": r.get("reason"),
                     "device_label": label, "device_id": device_id},
            )
        )
    if grouped:
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
            qnames = sorted(b["names"])
            detail = _block_reason_words(reason)
            if len(qnames) > 1:
                detail = (detail + " · " if detail else "") + f"{len(qnames)} names, e.g. {qnames[0]}"
            shown, label, device_id = who(client)
            out.append(
                FeedItem(
                    ts=b["ts"],
                    kind="dns_block",
                    severity=severity,
                    title=f"Blocked {_plural(b['hits'], 'request')} to {domain or 'a domain'} from {shown}",
                    detail=with_note(detail, label, device_id),
                    link=f"/dns?client={client}&q={domain}",
                    icon="dns",
                    ref={"client": client, "domain": domain, "hour": hour, "hits": b["hits"],
                         "device_label": label, "device_id": device_id},
                )
            )
    return out


def _events_source(conn: sqlite3.Connection, q: _Query) -> list[FeedItem]:
    """Defender detections and everything else that logged a warning or an error."""
    if not q.wants("av_threat", "system") or q.device is not None:
        # events rows carry no device identity (their ref is {event_id, source, level}), so a
        # device-filtered feed can never match one
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
    if not q.wants("notification") or q.device is not None:
        return []  # a notification is about the home, not about one device
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
    device: DeviceFilter | None = None,
) -> tuple[list[FeedItem], int]:
    """Merge every source into one ``ts``-descending stream.

    Returns ``(items, total_matching)``. ``total_matching`` counts the merged candidate window,
    which each source bounds at ``limit + offset + 1`` rows — enough to paginate correctly and to
    say "N more", without ever scanning a whole table. The extra row is the sentinel that keeps
    "Load more" visible when a single source fills the whole page.

    ``device`` narrows every source that can express it to one device *in SQL*, so a device's own
    history is never starved out by the rest of the network's traffic inside the cap.

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
                   cap=limit + offset + 1, severities=sev_set, device=device)

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


# --------------------------------------------------------------------------- plain language

#: kind -> the chip's words for someone who does not read "finding_ack". The technical label in
#: KIND_TABLE stays; this sits beside it.
PLAIN_LABEL_BY_KIND: dict[str, str] = {
    "finding_new": "New problems found",
    "finding_reopened": "Problems that came back",
    "finding_resolved": "Marked fixed",
    "finding_auto_resolved": "Fixed and re-checked",
    "finding_ack": "Marked as seen",
    "finding_suppressed": "Ignored",
    "device_new": "New devices",
    "device_offline": "Devices that went offline",
    "scan": "Checks run",
    "feed_update": "Threat lists updated",
    "dns_block": "Websites blocked",
    "dns_threat": "Dangerous websites blocked",
    "av_threat": "Antivirus detections",
    "notification": "Alerts sent",
    "system": "Home SOC messages",
}
#: The same words for a count of one ("1 Home SOC message", not "1 Home SOC messages").
PLAIN_LABEL_ONE_BY_KIND: dict[str, str] = {
    "finding_new": "New problem found",
    "finding_reopened": "Problem that came back",
    "finding_resolved": "Marked fixed",
    "finding_auto_resolved": "Fixed and re-checked",
    "finding_ack": "Marked as seen",
    "finding_suppressed": "Ignored",
    "device_new": "New device",
    "device_offline": "Device that went offline",
    "scan": "Check run",
    "feed_update": "Threat list updated",
    "dns_block": "Website blocked",
    "dns_threat": "Dangerous website blocked",
    "av_threat": "Antivirus detection",
    "notification": "Alert sent",
    "system": "Home SOC message",
}


def _block_reason_words(reason: str) -> str:
    """Why a look-up was refused, in words, with the technical reason kept beside it."""
    reason = (reason or "").strip()
    if not reason:
        return ""
    if reason.startswith("list:"):
        name = reason[5:]
        kind = "a threat list" if name in THREAT_LISTS else "a blocklist"
        return f"On {kind} ({reason})"
    if reason.startswith("override"):
        return f"You chose to always block it ({reason})"
    if reason == "reputation":
        return "Security services flagged it as dangerous (reputation)"
    return f"Reason: {reason}"


def feed_chips(counts: dict[str, int] | None) -> list[dict]:
    """The header chips as data: ``[{kind, label, plain_label, count, zero, icon}]`` in table order.

    ``zero`` flags a chip the page should hide (or render with ``.quiet-badge``): a row of "0 New
    finding · 0 Defender detection" chips is noise on a quiet day, not information.
    """
    counts = counts or {}
    out = []
    for kind, label, icon in KIND_TABLE:
        try:
            n = max(0, int(counts.get(kind, 0) or 0))
        except (TypeError, ValueError):
            n = 0
        words = PLAIN_LABEL_ONE_BY_KIND if n == 1 else PLAIN_LABEL_BY_KIND
        out.append({"kind": kind, "label": label, "plain_label": words.get(kind, PLAIN_LABEL_BY_KIND.get(kind, label)),
                    "count": n, "zero": n == 0, "icon": icon})
    return out


def _window_words(hours: int | None) -> str:
    if not hours:
        return "so far"
    if hours == 1:
        return "in the last hour"
    if hours % 24 == 0 and hours >= 48:
        return f"in the last {hours // 24} days"
    return f"in the last {hours} hours"


def _ever_ran(conn: sqlite3.Connection) -> bool:
    """Has Home SOC ever recorded anything at all? Cheap EXISTS probes, no table scans."""
    for table in ("scans", "findings", "devices", "events"):
        if api.scalar(conn, f"SELECT EXISTS(SELECT 1 FROM {table})", default=0):
            return True
    return False


def feed_empty_state(
    conn: sqlite3.Connection,
    total: int,
    *,
    window_hours: int | None = 24,
    filtered: bool = False,
    cfg: Any = None,
) -> dict:
    """Why the Activity page is empty, so it can say so honestly.

    ``reason`` is one of:

    * ``None`` — the window has items; nothing to explain;
    * ``"never_run"`` — Home SOC has not recorded anything yet;
    * ``"filtered"`` — the filters exclude everything in the window;
    * ``"not_checking"`` — the window is empty *and* the last network check is stale, so the quiet
      may only mean Home SOC is not looking (a quiet screen must not read as a safe one);
    * ``"quiet"`` — checks are running and simply nothing happened: normal.

    Also returns ``message`` (one plain sentence), ``last_activity`` (newest item of any age, ISO,
    or ``None``) with ``last_activity_text`` ("3 days ago"), and ``suggest_window`` — the next wider
    window key of the page ("7d", "30d", "all") or ``None``.
    """
    try:
        count = int(total or 0)
    except (TypeError, ValueError):
        count = 0
    hours = int(window_hours) if window_hours else None
    suggest = "7d" if hours and hours < 24 * 7 else "30d" if hours and hours < 24 * 30 else "all" if hours else None
    out: dict[str, Any] = {"empty": count == 0, "reason": None, "message": None, "last_activity": None,
                           "last_activity_text": None, "suggest_window": None, "window_hours": hours}
    if count:
        return out
    within = _window_words(hours)
    if not _ever_ran(conn):
        out.update(reason="never_run",
                   message="Nothing has happened yet: Home SOC hasn't run any checks. This page fills up as checks run.")
        return out
    newest, _ = build_feed(conn, limit=1, collapse=False)
    if newest:
        out["last_activity"] = newest[0].ts
        dt = api.parse_ts(newest[0].ts)
        if dt is not None:
            seconds = max(0, int((api.utcnow() - dt).total_seconds()))
            out["last_activity_text"] = "just now" if seconds < 60 else f"{api.span_words(seconds)} ago"
    out["suggest_window"] = suggest
    if filtered:
        out.update(reason="filtered", message=f"Nothing matches these filters {within}.")
        return out
    stale = api.staleness(conn, cfg)
    if stale.get("stale") or stale.get("never"):
        since = f"for {stale['age']}" if stale.get("age") else "yet"
        out.update(
            reason="not_checking",
            message=(f"Nothing new {within}, but Home SOC hasn't checked your network {since}, "
                     "so this may just mean it isn't looking."),
        )
        return out
    out.update(reason="quiet", message=f"Nothing new {within} — that is normal on a quiet day.")
    return out
