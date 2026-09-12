"""Read-model and JSON API for the Home SOC dashboard (SPEC section 15).

Everything reads straight from the SPEC section 4 tables with SQL written here, so the
dashboard renders even when the packages that own those tables have not run (or do not
exist yet). Writes are deliberately few and go through the owning package when it can be
imported; each fallback is marked with a SPEC-GAP comment.
"""

from __future__ import annotations

import importlib
import json
import logging
import platform
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request

logger = logging.getLogger(__name__)

bp = Blueprint("api", __name__, url_prefix="/api")

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
STATUSES: tuple[str, ...] = ("open", "acknowledged", "resolved", "suppressed")
SCORE_PENALTY: dict[str, int] = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
SCAN_KINDS: tuple[str, ...] = ("quick", "full", "host", "exposure", "feeds", "files")
BLOCKLIST_KINDS: tuple[str, ...] = ("hosts", "domains", "adblock", "ip")
JOB_COLUMNS: tuple[str, ...] = ("last_run", "last_status", "last_duration_sec", "next_run", "runs", "failures", "last_error")

# Finding-ID prefix -> category, used when findings.catalog is not importable and for the
# category filter on /findings. Mirrors the groupings of SPEC section 9.
CATEGORY_BY_PREFIX: dict[str, str] = {
    "WIN-DEF": "defender",
    "WIN-FW": "firewall",
    "WIN-UPD": "updates",
    "WIN-ACC": "accounts",
    "WIN-NET": "host-network",
    "WIN-SYS": "system",
    "WIN-PER": "persistence",
    "AV-FILE": "files",
    "POSIX": "posix",
    "NET-DEV": "devices",
    "NET-SVC": "services",
    "NET-VUL": "vulns",
    "NET-WAN": "wan",
    "NET-RTR": "router",
    "NET-WIFI": "wifi",
    "NET-DNS": "dns",
    "SOC": "soc",
}

# Editable settings (SPEC section 15: web, network.exclude, scan, dns, notify, schedule).
# type: str | int | float | bool | list | secret. Secrets are never echoed back.
EDITABLE_SETTINGS: list[tuple[str, str]] = [
    ("web.host", "str"),
    ("web.port", "int"),
    ("web.token", "secret"),
    ("web.refresh_seconds", "int"),
    ("network.exclude", "list"),
    ("scan.use_nmap", "bool"),
    ("scan.nmap_top_ports", "int"),
    ("scan.nmap_timing", "str"),
    ("scan.version_detection", "bool"),
    ("scan.gentle_top_ports", "int"),
    ("scan.per_host_timeout_sec", "int"),
    ("scan.max_parallel_hosts", "int"),
    ("scan.scan_gateway", "bool"),
    ("dns.enabled", "bool"),
    ("dns.listen", "str"),
    ("dns.port", "int"),
    ("dns.upstreams", "list"),
    ("dns.doh_upstream", "str"),
    ("dns.block_mode", "str"),
    ("dns.cache_max_entries", "int"),
    ("dns.lists", "list"),
    ("dns.log_queries", "bool"),
    ("dns.log_retention_days", "int"),
    ("dns.virustotal_api_key", "secret"),
    ("dns.virustotal_daily_budget", "int"),
    ("dns.urlhaus_auth_key", "secret"),
    ("dns.reputation_min_malicious_votes", "int"),
    ("dns.reputation_ttl_hours", "int"),
    ("notify.min_severity", "str"),
    ("notify.ntfy_url", "secret"),
    ("notify.discord_webhook", "secret"),
    ("notify.webhook_url", "secret"),
    ("notify.windows_toast", "bool"),
    ("notify.digest_hour", "int"),
    ("schedule.discovery_minutes", "int"),
    ("schedule.services_hours", "int"),
    ("schedule.host_hours", "int"),
    ("schedule.exposure_hours", "int"),
    ("schedule.feeds_hours", "int"),
]


@dataclass
class WebContext:
    """Everything the request handlers need, stored on ``app.extensions['homesoc']``."""

    cfg: Any
    conn: sqlite3.Connection
    scheduler: Any = None
    dns_server: Any = None
    token: str = ""


def ctx() -> WebContext:
    return current_app.extensions["homesoc"]


# --------------------------------------------------------------------------- helpers


def cfg_get(cfg: Any, dotted: str, default: Any = None) -> Any:
    """Walk ``cfg`` by dotted key across dataclasses, namespaces or dicts.

    The Config dataclass is owned by another package; reading it structurally keeps this
    module working against a stub in tests and against the real thing in production.
    """
    cur = cfg
    for part in dotted.split("."):
        if cur is None:
            return default
        cur = cur.get(part) if isinstance(cur, dict) else getattr(cur, part, None)
    return default if cur is None else cur


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """Same ``YYYY-MM-DDTHH:MM:SSZ`` form as util.utcnow_iso so rows written here sort with everyone else's."""
    return utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def cutoff_iso(hours: float) -> str:
    """Timestamp lower bound as a bare prefix so ``ts >= cutoff`` works for both 'Z' and
    '+00:00' suffixed ISO strings."""
    return (utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")


def parse_ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def age_hours(value: Any) -> float | None:
    dt = parse_ts(value)
    return None if dt is None else round((utcnow() - dt).total_seconds() / 3600, 2)


def loads(value: Any, default: Any = None) -> Any:
    """Parse a JSON column defensively: the content is produced by other packages (and
    for evidence, ultimately by scanned devices), so never let it break a page."""
    if value in (None, ""):
        return default
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:
        return default


_write_lock = threading.Lock()


def _core_db() -> Any | None:
    try:
        return importlib.import_module("homesoc.db")
    except ImportError:
        return None


def rows(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> list[dict]:
    """Run a SELECT and return plain dicts. A missing table just means that package has
    not run yet, so log it and render the page empty instead of failing."""
    try:
        cur = conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except sqlite3.OperationalError as exc:
        logger.warning("query failed (%s): %s", exc, " ".join(sql.split())[:90])
        return []


def one(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> dict | None:
    result = rows(conn, sql, params)
    return result[0] if result else None


def scalar(conn: sqlite3.Connection, sql: str, params: tuple | list = (), default: Any = 0) -> Any:
    row = one(conn, sql, params)
    if not row:
        return default
    value = next(iter(row.values()))
    return default if value is None else value


def write(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> int:
    """Locked write. Uses core's ``db.write`` (which owns the module-level lock) when it
    exists so dashboard writes serialise with scanner writes."""
    dbmod = _core_db()
    if dbmod is not None and hasattr(dbmod, "write"):
        return int(dbmod.write(conn, sql, params) or 0)
    with _write_lock:  # SPEC-GAP: core db missing -> local lock is the best we can do
        cur = conn.execute(sql, params)
        conn.commit()
        return int(cur.lastrowid or 0)


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = one(conn, "SELECT value FROM settings WHERE key=?", (key,))
    return default if row is None else row["value"]


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    dbmod = _core_db()
    if dbmod is not None and hasattr(dbmod, "set_setting"):
        dbmod.set_setting(conn, key, value)
        return
    # SPEC-GAP: core db not importable -> direct upsert with the same semantics.
    write(
        conn,
        "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, now_iso()),
    )


def _bool(value: Any) -> bool:
    return bool(value) and str(value).lower() not in ("0", "false", "no", "")


# --------------------------------------------------------------------------- findings


def finding_counts(conn: sqlite3.Connection) -> dict[str, dict[str, int]]:
    counts = {status: {sev: 0 for sev in SEVERITIES} for status in STATUSES}
    for r in rows(conn, "SELECT status, severity, count(*) AS n FROM findings GROUP BY status, severity"):
        counts.setdefault(r["status"], {sev: 0 for sev in SEVERITIES})
        counts[r["status"]][r["severity"]] = counts[r["status"]].get(r["severity"], 0) + int(r["n"])
    return counts


def _findings_score() -> Any | None:
    """``homesoc.findings.score`` when it is installed, else ``None``.

    findings owns the scoring formula (SPEC section 10). The dashboard must show *its* number,
    or the score card and the "what is costing you points" list underneath it would disagree.
    """
    try:
        return importlib.import_module("homesoc.findings.score")
    except ImportError:
        return None


def _local_security_score(conn: sqlite3.Connection) -> int:
    """SPEC section 10 formula from SQL — the fallback when findings.score is not installed."""
    score = 100
    for sev, n in finding_counts(conn)["open"].items():
        score -= SCORE_PENALTY.get(sev, 0) * n
    return max(0, score)


def security_score(conn: sqlite3.Connection) -> int:
    fn = getattr(_findings_score(), "security_score", None)
    if callable(fn):
        try:
            return max(0, min(100, int(fn(conn))))
        except Exception:  # a scoring bug must not blank the dashboard
            logger.warning("findings.score.security_score failed; using the local formula", exc_info=True)
    return _local_security_score(conn)


def grade(score: int) -> str:
    fn = getattr(_findings_score(), "grade", None)
    if callable(fn):
        try:
            letter = str(fn(int(score)) or "").strip().upper()[:1]
            if letter in ("A", "B", "C", "D", "F"):
                return letter
        except Exception:
            logger.warning("findings.score.grade failed; using the local bands", exc_info=True)
    # SPEC-GAP: thresholds not given; classic 90/80/70/60 bands.
    for floor, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= floor:
            return letter
    return "F"


def score_trend(conn: sqlite3.Connection, days: int = 30) -> list[list]:
    data = rows(
        conn,
        "SELECT substr(ts,1,10) AS d, avg(value) AS v FROM metrics WHERE name='score' AND ts>=? "
        "GROUP BY d ORDER BY d",
        (cutoff_iso(days * 24),),
    )
    return [[r["d"], round(float(r["v"]), 1)] for r in data]


# --------------------------------------------------------------------------- score breakdown

# How many rows the "what is costing you points" list shows by default. Six fits the score
# card without scrolling and is enough to see the shape of the problem.
SCORE_BREAKDOWN_LIMIT = 6


def _sev_rank(severity: Any) -> int:
    sev = str(severity or "").lower()
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


# Words a de-templated catalog title must not end on ("Last cumulative update was" reads worse
# than the concrete title it came from).
_DANGLING_WORDS: frozenset[str] = frozenset(
    {"a", "an", "and", "are", "as", "at", "by", "for", "from", "has", "have", "in", "is", "of", "on", "or", "the", "to", "was", "were", "with"}
)


def _generic_title(catalog_title: Any) -> str:
    """A catalog title with its ``{placeholders}`` cut off, or '' when nothing readable is left.

    ``"New device on the network: {ip} ({vendor})"`` -> ``"New device on the network"``. Used
    when one catalog ID is open on many subjects, where no single subject's wording is fair.
    """
    head = str(catalog_title or "").split("{", 1)[0].strip()
    head = head.rstrip(" \t–—-:;,(").strip()
    words = head.split()
    while words and words[-1].lower() in _DANGLING_WORDS:
        words.pop()
    head = " ".join(words)
    return head if len(head) >= 8 else ""


def _open_finding_facts(conn: sqlite3.Connection) -> dict[str, dict]:
    """finding_id -> {title, severity, count, penalty} over the currently *open* findings.

    One catalog ID can be open on several subjects (``NET-SVC-001`` on three devices) and, in
    principle, at different severities, so counts and penalties are summed and the worst
    severity wins. A single open finding keeps its own concrete title ("Telnet is open on
    192.168.1.74"); several share the catalog's generic one.
    """
    facts: dict[str, dict] = {}
    data = rows(
        conn,
        "SELECT finding_id, severity, count(*) AS n, min(title) AS title FROM findings "
        "WHERE status='open' GROUP BY finding_id, severity",
    )
    for r in data:
        fid = str(r["finding_id"] or "").strip()
        if not fid:
            continue
        sev = str(r["severity"] or "info").lower()
        n = max(0, int(r["n"] or 0))
        f = facts.setdefault(fid, {"finding_id": fid, "title": None, "severity": "info", "count": 0, "penalty": 0})
        f["count"] += n
        f["penalty"] += SCORE_PENALTY.get(sev, 0) * n
        if f["title"] is None or _sev_rank(sev) < _sev_rank(f["severity"]):
            f["severity"] = sev
            f["title"] = r["title"]
    for fid, f in facts.items():
        generic = _generic_title(getattr(catalog_spec(fid), "title", None))
        if f["count"] > 1 and generic:
            f["title"] = generic
        f["title"] = str(f["title"] or generic or fid)
    return facts


def _score_breakdown_from_findings(conn: sqlite3.Connection) -> list[dict] | None:
    """``homesoc.findings.score.score_breakdown`` when that package ships it, else ``None``.

    findings owns the scoring formula, so its numbers win whenever they are available; this
    module is only allowed to guess when they are not.
    """
    fn = getattr(_findings_score(), "score_breakdown", None)
    if not callable(fn):
        return None
    try:
        result = fn(conn)
    except Exception:  # a breakdown must never take the dashboard down
        logger.warning("findings.score.score_breakdown failed; using the local fallback", exc_info=True)
        return None
    if not isinstance(result, (list, tuple)):
        return None
    return [r for r in result if isinstance(r, dict)]


def score_breakdown(conn: sqlite3.Connection, limit: int = SCORE_BREAKDOWN_LIMIT) -> list[dict]:
    """Which open findings are costing the most points, most expensive first.

    Rows are ``{finding_id, title, count, penalty, gain, severity, category}`` — the fields
    findings.score produces plus what the dashboard needs to colour and link the row. ``gain``
    is how far the score would rise if every finding of that type were cleared: findings.score
    reports it as ``score_gain`` when its curve is non-linear, otherwise it equals ``penalty``.
    Only findings that actually cost points appear, so an all-``info`` database yields ``[]``.
    """
    limit = max(1, min(int(limit or 1), 50))
    facts = _open_finding_facts(conn)
    raw = _score_breakdown_from_findings(conn)
    if raw is None:
        raw = list(facts.values())

    out: list[dict] = []
    for item in raw:
        fid = str(item.get("finding_id") or "").strip()
        if not fid:
            continue
        known = facts.get(fid, {})
        try:
            penalty = int(round(float(item.get("penalty") or 0)))
            count = int(item.get("count") or known.get("count") or 0)
        except (TypeError, ValueError):
            continue
        if penalty <= 0:
            continue
        try:
            gain = int(round(float(item["score_gain"]))) if item.get("score_gain") is not None else penalty
        except (TypeError, ValueError):
            gain = penalty
        # A supplied title wins unless it still carries "{placeholders}" from the catalog.
        supplied = str(item.get("title") or "").strip()
        title = supplied if supplied and "{" not in supplied else str(known.get("title") or supplied or fid)
        out.append(
            {
                "finding_id": fid,
                "title": title,
                "count": max(0, count),
                "penalty": penalty,
                "gain": max(0, gain),
                "severity": str(item.get("severity") or known.get("severity") or "info").lower(),
                "category": category_for(fid),
            }
        )
    out.sort(key=lambda r: (-r["penalty"], -r["count"], r["finding_id"]))
    return out[:limit]


def category_for(finding_id: str) -> str:
    spec = catalog_spec(finding_id)
    cat = getattr(spec, "category", None) if spec is not None else None
    if cat:
        return str(cat)
    for prefix, cat in CATEGORY_BY_PREFIX.items():
        if finding_id.startswith(prefix):
            return cat
    return "other"


def catalog_spec(finding_id: str) -> Any | None:
    try:
        catalog = importlib.import_module("homesoc.findings.catalog")
    except ImportError:
        return None
    table = getattr(catalog, "CATALOG", None) or {}
    return table.get(finding_id)


def catalog_remediation(finding_id: str, evidence: dict, subject: str = "") -> list[str]:
    """Remediation steps with this finding's own evidence interpolated.

    28 of the 88 catalog entries phrase a step around a `{path}` / `{ip}` / `{profile}`
    placeholder, so handing the raw templates to the dashboard shows the user
    "right-click '{path}' > Delete". ``catalog.render_remediation`` fills them in;
    the raw list is only the fallback when the findings package is unavailable.
    """
    try:
        catalog = importlib.import_module("homesoc.findings.catalog")
        steps = catalog.render_remediation(finding_id, evidence, subject)
    except Exception:  # noqa: BLE001 - the dashboard must render even if the catalog is broken
        steps = []
    if steps:
        return list(steps)
    spec = catalog_spec(finding_id)
    return list(getattr(spec, "remediation", None) or [])


def _decorate_finding(f: dict) -> dict:
    spec = catalog_spec(f["finding_id"])
    evidence = loads(f.get("evidence"), {})
    f["evidence"] = evidence
    f["evidence_pretty"] = json.dumps(evidence, indent=2, sort_keys=True, default=str) if evidence else ""
    f["category"] = category_for(f["finding_id"])
    f["remediation"] = catalog_remediation(f["finding_id"], evidence, str(f.get("subject") or ""))
    f["refs"] = list(getattr(spec, "refs", None) or [])
    f["rationale"] = getattr(spec, "rationale", None) or ""
    return f


def findings_list(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    category: str | None = None,
    device_id: int | None = None,
    limit: int = 500,
) -> list[dict]:
    where, params = ["1=1"], []
    if status in STATUSES:
        where.append("f.status=?")
        params.append(status)
    if severity in SEVERITIES:
        where.append("f.severity=?")
        params.append(severity)
    if q:
        like = f"%{q}%"
        where.append("(f.title LIKE ? OR f.subject LIKE ? OR f.detail LIKE ? OR f.finding_id LIKE ?)")
        params += [like, like, like, like]
    if device_id is not None:
        where.append("f.device_id=?")
        params.append(device_id)
    order = "CASE f.severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " ELSE 9 END"
    data = rows(
        conn,
        "SELECT f.*, d.ip AS device_ip, COALESCE(d.nickname, d.hostname, d.ip) AS device_name "
        f"FROM findings f LEFT JOIN devices d ON d.id=f.device_id WHERE {' AND '.join(where)} "
        f"ORDER BY {order}, f.last_seen DESC LIMIT ?",
        params + [max(1, min(int(limit), 5000))],
    )
    out = [_decorate_finding(f) for f in data]
    if category:
        out = [f for f in out if f["category"] == category]
    return out


def set_finding_status(conn: sqlite3.Connection, row_id: int, status: str, note: str | None = None) -> bool:
    if status not in STATUSES:
        raise ValueError("invalid status")
    if one(conn, "SELECT id FROM findings WHERE id=?", (row_id,)) is None:
        return False
    try:
        engine = importlib.import_module("homesoc.findings.engine")
    except ImportError:
        engine = None
    if engine is not None and hasattr(engine, "set_status"):
        engine.set_status(conn, row_id, status, note)
        return True
    # SPEC-GAP: findings.engine not importable -> apply the lifecycle change directly.
    now = now_iso()
    resolved_at = now if status == "resolved" else None
    write(conn, "UPDATE findings SET status=?, resolved_at=? WHERE id=?", (status, resolved_at, row_id))
    write(
        conn,
        "INSERT INTO finding_events(finding_row_id, event, at, note) VALUES(?,?,?,?)",
        (row_id, status, now, note),
    )
    return True


# --------------------------------------------------------------------------- devices


def _device_row(d: dict) -> dict:
    d["online"] = _bool(d.get("online"))
    d["trusted"] = _bool(d.get("trusted"))
    d["display_name"] = d.get("nickname") or d.get("hostname") or d.get("ip") or d.get("mac")
    d["mdns_services"] = loads(d.get("mdns_services"), [])
    return d


def devices_list(conn: sqlite3.Connection) -> list[dict]:
    data = rows(
        conn,
        "SELECT d.*, "
        "(SELECT count(*) FROM services s WHERE s.device_id=d.id AND s.state='open') AS open_ports, "
        "(SELECT count(*) FROM findings f WHERE f.status='open' AND "
        " (f.device_id=d.id OR f.subject=('device:'||d.mac) OR f.subject LIKE ('device:'||d.mac||':%'))) AS open_findings "
        "FROM devices d ORDER BY d.online DESC, d.last_seen DESC",
    )
    return [_device_row(d) for d in data]


def device_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {
        "online": int(scalar(conn, "SELECT count(*) FROM devices WHERE online=1")),
        "total": int(scalar(conn, "SELECT count(*) FROM devices")),
    }


def device_detail(conn: sqlite3.Connection, device_id: int) -> dict | None:
    d = one(conn, "SELECT * FROM devices WHERE id=?", (device_id,))
    if d is None:
        return None
    _device_row(d)
    d["services"] = rows(
        conn,
        "SELECT * FROM services WHERE device_id=? ORDER BY CASE state WHEN 'open' THEN 0 ELSE 1 END, port",
        (device_id,),
    )
    d["vulns"] = vulns_list(conn, device_id=device_id)
    d["findings"] = findings_list(conn, device_id=device_id, limit=200)
    week = cutoff_iso(7 * 24)
    d["sightings"] = rows(
        conn,
        "SELECT ip, seen_at, method FROM device_sightings WHERE device_id=? AND seen_at>=? "
        "ORDER BY seen_at DESC LIMIT 500",
        (device_id, week),
    )
    per_day = {
        r["d"]: int(r["n"])
        for r in rows(
            conn,
            "SELECT substr(seen_at,1,10) AS d, count(*) AS n FROM device_sightings "
            "WHERE device_id=? AND seen_at>=? GROUP BY d",
            (device_id, week),
        )
    }
    today = utcnow().date()
    d["presence"] = [
        {"date": (today - timedelta(days=i)).isoformat(), "count": per_day.get((today - timedelta(days=i)).isoformat(), 0)}
        for i in range(6, -1, -1)
    ]
    return d


def update_device(conn: sqlite3.Connection, device_id: int, payload: dict) -> bool:
    """Nickname/notes/trusted are the user's annotations; the dashboard is their only
    editor, so it writes the three columns directly (SPEC-GAP: devices is owned by
    discovery, which never touches these columns)."""
    if one(conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
        return False
    sets, params = [], []
    if "nickname" in payload:
        sets.append("nickname=?")
        params.append((str(payload.get("nickname") or "")[:80]) or None)
    if "notes" in payload:
        sets.append("notes=?")
        params.append((str(payload.get("notes") or "")[:2000]) or None)
    trusted: bool | None = None
    if "trusted" in payload:
        trusted = _bool(payload.get("trusted"))
        sets.append("trusted=?")
        params.append(1 if trusted else 0)
    if not sets:
        return True
    params.append(device_id)
    write(conn, f"UPDATE devices SET {', '.join(sets)} WHERE id=?", params)
    if trusted:
        _resolve_new_device_findings(conn, device_id)
    return True


def _resolve_new_device_findings(conn: sqlite3.Connection, device_id: int) -> None:
    """Marking a device trusted answers the "new device" question; close the open NET-DEV-001 row
    (through the findings engine so the event trail stays intact)."""
    rows_ = rows(conn, "SELECT id FROM findings WHERE finding_id='NET-DEV-001' AND device_id=? AND status IN ('open','acknowledged')", (device_id,))
    if not rows_:
        return
    try:
        engine = importlib.import_module("homesoc.findings.engine")
    except ImportError:
        engine = None
    for r in rows_:
        try:
            if engine is not None:
                engine.set_status(conn, int(r["id"]), "resolved", note="device marked trusted")
            else:  # SPEC-GAP: engine absent -> direct update so the dashboard still behaves
                write(conn, "UPDATE findings SET status='resolved', resolved_at=? WHERE id=?", (now_iso(), int(r["id"])))
        except Exception:
            logger.exception("could not resolve NET-DEV-001 for device %s", device_id)


# --------------------------------------------------------------------------- vulns


def vulns_list(
    conn: sqlite3.Connection,
    *,
    kev: bool | None = None,
    q: str | None = None,
    device_id: int | None = None,
    min_cvss: float | None = None,
    limit: int = 1000,
) -> list[dict]:
    where, params = ["1=1"], []
    if kev:
        where.append("v.kev=1")
    if device_id is not None:
        where.append("v.device_id=?")
        params.append(device_id)
    if min_cvss is not None:
        where.append("COALESCE(v.cvss,0)>=?")
        params.append(float(min_cvss))
    if q:
        like = f"%{q}%"
        where.append("(v.cve LIKE ? OR v.title LIKE ? OR d.ip LIKE ? OR s.product LIKE ?)")
        params += [like, like, like, like]
    data = rows(
        conn,
        "SELECT v.*, d.ip AS device_ip, d.mac AS device_mac, "
        "COALESCE(d.nickname, d.hostname, d.ip) AS device_name, "
        "s.port, s.proto, s.name AS service_name, s.product, s.version AS service_version "
        "FROM vulns v LEFT JOIN devices d ON d.id=v.device_id LEFT JOIN services s ON s.id=v.service_id "
        f"WHERE {' AND '.join(where)} ORDER BY v.kev DESC, COALESCE(v.cvss,0) DESC, v.first_seen DESC LIMIT ?",
        params + [max(1, min(int(limit), 5000))],
    )
    for v in data:
        v["kev"] = _bool(v.get("kev"))
        v["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{v['cve']}"
        v["kev_url"] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + str(v["cve"])
    return data


# --------------------------------------------------------------------------- host


def host_data(conn: sqlite3.Connection) -> dict:
    checks = rows(conn, "SELECT * FROM host_checks ORDER BY check_id")
    for c in checks:
        c["needs_admin"] = _bool(c.get("needs_admin"))
        c["group"] = category_for(c["check_id"])
    defender = loads(get_setting(conn, "defender.status_json"), {}) or {}
    # SPEC-GAP: the spec only names defender.status_json; threats are taken from an optional
    # defender.threats_json key plus the open WIN-DEF-011 findings, whichever exists.
    threats = loads(get_setting(conn, "defender.threats_json"), []) or []
    if not threats:
        threats = [
            {"name": f["title"], "detail": f.get("detail"), "seen": f["last_seen"], "evidence": f["evidence"]}
            for f in findings_list(conn, status="open", limit=100)
            if f["finding_id"] == "WIN-DEF-011"
        ]
    software = rows(
        conn,
        "SELECT * FROM software WHERE available IS NOT NULL AND available<>'' AND "
        "(version IS NULL OR available<>version) ORDER BY name",
    )
    persistence = rows(conn, "SELECT * FROM persistence ORDER BY baseline ASC, last_seen DESC")
    for p in persistence:
        p["baseline"] = _bool(p.get("baseline"))
    # SPEC-GAP: no table holds pending Windows updates / listeners. scanners.updates keeps its
    # probe JSON under updates.status_json ({pending, hotfix, history}) and scanners.host_* the
    # posture probe under host.posture_json ({listeners: [{port, address, pid, process}], hotfix}).
    updates_json = loads(get_setting(conn, "updates.status_json"), {}) or {}
    posture_json = loads(get_setting(conn, "host.posture_json"), {}) or {}
    if not isinstance(updates_json, dict):
        updates_json = {}
    if not isinstance(posture_json, dict):
        posture_json = {}
    pending = _as_list(updates_json.get("pending")) or loads(get_setting(conn, "updates.pending_json"), []) or []
    listeners = _as_list(posture_json.get("listeners")) or loads(get_setting(conn, "host.listeners_json"), []) or []
    if not listeners:
        listeners = [
            {"port": c["check_id"], "value": c.get("value"), "status": c["status"]}
            for c in checks
            if c["check_id"].startswith(("WIN-NET-006", "POSIX-NET-001"))
        ]
    updates = {
        "pending": pending,
        "checks": [c for c in checks if c["check_id"].startswith(("WIN-UPD", "POSIX-UPD"))],
        "last_hotfix": _last_hotfix(updates_json.get("hotfix"), posture_json.get("hotfix"))
        or get_setting(conn, "updates.last_hotfix"),
    }
    defender_summary = {
        "status": defender,
        "signature_age_days": defender.get("AntivirusSignatureAge") or defender.get("signature_age_days"),
        "last_quick_scan": defender.get("QuickScanEndTime") or defender.get("last_quick_scan"),
        "last_full_scan": defender.get("FullScanEndTime") or defender.get("last_full_scan"),
        "threats": threats,
        "checked_at": get_setting(conn, "defender.checked_at"),
    }
    return {
        "checks": checks,
        "defender": defender_summary,
        "updates": updates,
        "software": software,
        "persistence": persistence,
        "listeners": listeners,
        "platform": platform.system(),
    }


def _as_list(value: Any) -> list:
    """Probe sections are a list on success and an error string on failure; only lists are data."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _last_hotfix(*sections: Any) -> str | None:
    """'KB5060842 (2026-07-16)' from whichever probe (updates.ps1 or posture.ps1) reported a hotfix."""
    for section in sections:
        if not isinstance(section, dict):
            continue
        hotfix_id = section.get("id") or section.get("last_id")
        installed = section.get("installed") or section.get("last_installed")
        if hotfix_id or installed:
            return f"{hotfix_id or 'hotfix'} ({installed})" if installed else str(hotfix_id)
    return None


# Defender actions shell out to MpCmdRun.exe: a quick scan takes minutes and a signature update
# took up to 15 minutes inline, which pinned a Flask worker and let a second click start a second
# MpCmdRun. Both are fire-and-forget now: one guarded worker thread per action, de-duplicated by
# ``_defender_jobs``, with the outcome kept for ``GET /api/defender/status`` to poll.
DEFENDER_ACTIONS: dict[str, tuple[str, ...]] = {
    "quick-scan": ("trigger_quick_scan", "quick_scan"),
    "update": ("trigger_signature_update", "update_signatures"),
}
_DEFENDER_RUNNING_PROBE: dict[str, str] = {"quick-scan": "quick_scan_running", "update": "update_running"}
# The scanner runs MpCmdRun on its own thread and publishes the real outcome here. When these
# exist they are authoritative: our trigger call returns as soon as the child is LAUNCHED, so a
# web-side "finished" stamp would otherwise claim success milliseconds into a minutes-long update.
_DEFENDER_STATUS_PROBE: dict[str, str] = {"quick-scan": "quick_scan_status", "update": "update_status"}
_defender_lock = threading.Lock()
_defender_jobs: dict[str, dict] = {}


def _defender_module() -> Any | None:
    try:
        return importlib.import_module("homesoc.scanners.defender")
    except ImportError:
        return None


def _defender_probe(action: str, which: dict[str, str]) -> Any | None:
    defender = _defender_module()
    if defender is None:
        return None
    probe = getattr(defender, which[action], None)
    return probe if callable(probe) else None


def _defender_worker(cfg: Any, action: str, func: Any) -> None:
    ok, error = False, None
    try:
        ok = bool(func(cfg))
    except Exception as exc:  # the action shells out; never let it kill the thread silently
        logger.exception("defender action %s failed", action)
        error = str(exc)[:200]
    if error is None and _defender_probe(action, _DEFENDER_STATUS_PROBE) is not None:
        # The trigger only LAUNCHED MpCmdRun. The scanner owns the outcome from here, so leave
        # this job open and let defender_status() read the real state instead of stamping "done".
        with _defender_lock:
            _defender_jobs.setdefault(action, {})["handed_off"] = True
        return
    with _defender_lock:
        job = _defender_jobs.setdefault(action, {})
        job.update({"running": False, "finished_at": now_iso(), "ok": ok, "error": error})


def defender_action(cfg: Any, action: str) -> dict:
    """Start ``action`` in the background and return immediately (HTTP 202).

    Returns ``ok=False`` only when the integration is missing; a click while the same action is
    already running is a success ("already running"), not an error, so the UI stays idempotent.
    """
    names = DEFENDER_ACTIONS.get(action)
    if names is None:
        return {"ok": False, "error": "unknown action"}
    defender = _defender_module()
    func = next((getattr(defender, n) for n in names if defender is not None and hasattr(defender, n)), None)
    if func is None:
        logger.warning("defender action %s unavailable", action)
        return {"ok": False, "error": "defender integration unavailable"}
    # A handed-off job stays flagged running until the scanner says otherwise, so ask the scanner
    # before refusing a second click -- otherwise the button dead-ends after the first update.
    still_running = None
    running_probe = _defender_probe(action, _DEFENDER_RUNNING_PROBE)
    if running_probe is not None:
        try:
            still_running = bool(running_probe())
        except Exception:
            logger.exception("defender %s probe failed", action)
    with _defender_lock:
        job = _defender_jobs.get(action)
        busy = bool(job and job.get("running")) if still_running is None else still_running
        if busy:
            return {"ok": True, "action": action, "status": "already running",
                    "started_at": (job or {}).get("started_at")}
        started = now_iso()
        _defender_jobs[action] = {"running": True, "started_at": started, "finished_at": None, "ok": None, "error": None}
    thread = threading.Thread(
        target=_defender_worker, args=(cfg, action, func), name=f"homesoc-defender-{action}", daemon=True
    )
    thread.start()
    return {"ok": True, "action": action, "status": "started", "started_at": started}


def defender_status() -> dict:
    """State of both background actions, for the UI to poll after a 202."""
    defender = _defender_module()
    out: dict[str, Any] = {"available": defender is not None, "actions": {}}
    with _defender_lock:
        jobs = {k: dict(v) for k, v in _defender_jobs.items()}
    for action in DEFENDER_ACTIONS:
        job = jobs.get(action) or {"running": False, "started_at": None, "finished_at": None, "ok": None, "error": None}
        handed_off = bool(job.pop("handed_off", False))
        state = None
        status_probe = _defender_probe(action, _DEFENDER_STATUS_PROBE)
        if status_probe is not None:
            try:  # the scanner owns the real process and the real outcome
                state = status_probe()
            except Exception:
                logger.exception("defender %s status probe failed", action)
        if isinstance(state, dict):
            job.update({
                "running": bool(state.get("running")),
                "started_at": state.get("started_at") or job.get("started_at"),
                "finished_at": state.get("finished_at"),
                "ok": state.get("ok"),
                "error": (state.get("message") or None) if state.get("ok") is False else job.get("error"),
                "rc": state.get("rc"),
                "message": state.get("message") or "",
            })
        else:
            running_probe = _defender_probe(action, _DEFENDER_RUNNING_PROBE)
            if running_probe is not None:
                try:
                    job["running"] = bool(running_probe()) or bool(job.get("running"))
                except Exception:
                    logger.exception("defender %s probe failed", action)
            elif handed_off:  # no way to observe the child; do not claim it finished
                job["running"] = True
        out["actions"][action] = job
    return out


# --------------------------------------------------------------------------- dns


def dns_running(c: WebContext) -> bool:
    if c.dns_server is None:
        return False
    flag = getattr(c.dns_server, "running", None)
    if callable(flag):
        try:
            return bool(flag())
        except Exception:
            return False
    return True if flag is None else bool(flag)


def dns_summary(c: WebContext) -> dict:
    conn = c.conn
    since = cutoff_iso(24)
    agg = one(
        conn,
        "SELECT count(*) AS total, sum(action='block') AS blocked, sum(action='cache') AS cached, "
        "count(DISTINCT client) AS clients, avg(ms) AS avg_ms FROM dns_queries WHERE ts>=?",
        (since,),
    ) or {}
    total = int(agg.get("total") or 0)
    blocked = int(agg.get("blocked") or 0)
    today = utcnow().strftime("%Y-%m-%d")
    budget_used = int(str(get_setting(conn, f"vt.budget.{today}", "0") or "0").split(".")[0] or 0)
    return {
        "total24h": total,
        "blocked24h": blocked,
        "blocked_pct": round(100.0 * blocked / total, 1) if total else 0.0,
        "cached24h": int(agg.get("cached") or 0),
        "clients24h": int(agg.get("clients") or 0),
        "avg_ms": round(float(agg.get("avg_ms") or 0.0), 1),
        "running": dns_running(c),
        "enabled": _bool(cfg_get(c.cfg, "dns.enabled", False)),
        "listen": str(cfg_get(c.cfg, "dns.listen", "0.0.0.0")),
        "port": int(cfg_get(c.cfg, "dns.port", 53) or 53),
        "upstreams": list(cfg_get(c.cfg, "dns.upstreams", []) or []),
        "block_mode": str(cfg_get(c.cfg, "dns.block_mode", "null")),
        "overrides": int(scalar(conn, "SELECT count(*) FROM dns_overrides")),
        "reputation_entries": int(scalar(conn, "SELECT count(*) FROM reputation")),
        "vt_budget": {
            "date": today,
            "used": budget_used,
            "limit": int(cfg_get(c.cfg, "dns.virustotal_daily_budget", 400) or 0),
            "key_set": bool(cfg_get(c.cfg, "dns.virustotal_api_key", "")),
        },
    }


def dns_series(conn: sqlite3.Connection, hours: int = 24) -> list[dict]:
    """Per-hour totals straight from dns_queries so the current (not yet rolled-up) hour is
    included; missing hours are zero-filled so charts always show the full window."""
    hours = max(1, min(int(hours), 24 * 14))
    data = rows(
        conn,
        "SELECT substr(ts,1,13) AS hour, count(*) AS total, sum(action='block') AS blocked "
        "FROM dns_queries WHERE ts>=? GROUP BY hour ORDER BY hour",
        (cutoff_iso(hours),),
    )
    by_hour = {r["hour"]: r for r in data}
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    out = []
    for i in range(hours - 1, -1, -1):
        key = (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H")
        r = by_hour.get(key, {})
        out.append({"hour": key, "total": int(r.get("total") or 0), "blocked": int(r.get("blocked") or 0)})
    return out


def dns_top(conn: sqlite3.Connection, kind: str = "blocked", hours: int = 24, limit: int = 20) -> list[dict]:
    since = cutoff_iso(max(1, min(int(hours), 24 * 30)))
    limit = max(1, min(int(limit), 200))
    if kind == "clients":
        return rows(
            conn,
            "SELECT client, count(*) AS total, sum(action='block') AS blocked FROM dns_queries "
            "WHERE ts>=? GROUP BY client ORDER BY total DESC LIMIT ?",
            (since, limit),
        )
    return rows(
        conn,
        "SELECT qname AS domain, count(*) AS hits, max(reason) AS reason, count(DISTINCT client) AS clients "
        "FROM dns_queries WHERE ts>=? AND action='block' GROUP BY qname ORDER BY hits DESC LIMIT ?",
        (since, limit),
    )


def dns_log(conn: sqlite3.Connection, limit: int = 100, client: str | None = None, action: str | None = None) -> list[dict]:
    where, params = ["1=1"], []
    if client:
        where.append("client=?")
        params.append(client)
    if action in ("allow", "block", "cache", "error"):
        where.append("action=?")
        params.append(action)
    params.append(max(1, min(int(limit), 1000)))
    return rows(
        conn,
        f"SELECT * FROM dns_queries WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
        params,
    )


def dns_lists(c: WebContext) -> list[dict]:
    active = {str(n) for n in (cfg_get(c.cfg, "dns.lists", []) or [])}
    placeholders = ",".join("?" for _ in BLOCKLIST_KINDS)
    data = rows(
        c.conn,
        f"SELECT name, kind, url, status, entries, bytes, last_updated, last_checked, enabled, error "
        f"FROM feeds WHERE kind IN ({placeholders}) ORDER BY name",
        BLOCKLIST_KINDS,
    )
    for r in data:
        r["enabled"] = _bool(r.get("enabled"))
        r["active"] = r["name"] in active
        r["age_hours"] = age_hours(r.get("last_updated"))
    return data


def dns_overrides(conn: sqlite3.Connection) -> list[dict]:
    return rows(conn, "SELECT * FROM dns_overrides ORDER BY created_at DESC")


def normalise_domain(value: Any) -> str | None:
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or any(ch in domain for ch in " /\\\t\n\r'\";"):
        return None
    if not all(label and len(label) <= 63 for label in domain.split(".")):
        return None
    return domain


def dns_override_set(conn: sqlite3.Connection, domain: Any, action: Any, note: Any = None) -> dict:
    name = normalise_domain(domain)
    if name is None:
        return {"ok": False, "error": "invalid domain"}
    if action not in ("allow", "deny"):
        return {"ok": False, "error": "action must be allow or deny"}
    write(
        conn,
        "INSERT INTO dns_overrides(domain, action, note, created_at) VALUES(?,?,?,?) "
        "ON CONFLICT(domain) DO UPDATE SET action=excluded.action, note=excluded.note, created_at=excluded.created_at",
        (name, action, (str(note or "")[:200]) or None, now_iso()),
    )
    return {"ok": True, "domain": name, "action": action}


def dns_override_delete(conn: sqlite3.Connection, domain: Any) -> dict:
    name = normalise_domain(domain)
    if name is None:
        return {"ok": False, "error": "invalid domain"}
    write(conn, "DELETE FROM dns_overrides WHERE domain=?", (name,))
    return {"ok": True, "domain": name}


def dns_reputation(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    data = rows(
        conn,
        "SELECT domain, source, verdict, malicious, suspicious, checked_at FROM reputation "
        "ORDER BY CASE verdict WHEN 'malicious' THEN 0 WHEN 'suspicious' THEN 1 ELSE 2 END, checked_at DESC LIMIT ?",
        (max(1, min(int(limit), 2000)),),
    )
    return data


# --------------------------------------------------------------------------- telemetry


def _series_key(name: str, tags: Any) -> str:
    """One chart per metric name *and* tag set, so job.duration becomes one series per job."""
    tags = loads(tags, {}) if isinstance(tags, str) else (tags or {})
    if isinstance(tags, dict) and tags:
        return name + " · " + "/".join(str(v) for _, v in sorted(tags.items()))
    return name


def telemetry_metrics(conn: sqlite3.Connection, name: str | None = None, hours: int = 24 * 7) -> dict:
    hours = max(1, min(int(hours), 24 * 90))
    where, params = ["ts>=?"], [cutoff_iso(hours)]
    if name:
        where.append("name=?")
        params.append(name)
    data = rows(
        conn,
        f"SELECT ts, name, value, tags FROM metrics WHERE {' AND '.join(where)} ORDER BY name, ts LIMIT 50000",
        params,
    )
    series: dict[str, list[list]] = {}
    for r in data:
        series.setdefault(_series_key(r["name"], r.get("tags")), []).append([r["ts"], float(r["value"])])
    return {"hours": hours, "names": sorted(series), "series": series}


def telemetry_jobs(c: WebContext) -> list[dict]:
    data = rows(c.conn, "SELECT * FROM jobs ORDER BY name")
    if c.scheduler is not None and hasattr(c.scheduler, "status"):
        try:
            live = {str(j.get("name")): j for j in (c.scheduler.status() or []) if isinstance(j, dict)}
        except Exception:  # a scheduler bug must not take the page down
            logger.exception("scheduler.status() failed")
            live = {}
        known = {r["name"] for r in data}
        for r in data:
            r.update({k: v for k, v in live.get(r["name"], {}).items() if v is not None})
        data.extend(dict(v) for k, v in live.items() if k not in known)
    for r in data:
        # Jobs the scheduler knows but has never run have no table row yet; give them the
        # table's columns so templates can treat every job alike.
        for col in JOB_COLUMNS:
            r.setdefault(col, None)
        r["runs"] = int(r.get("runs") or 0)
        r["failures"] = int(r.get("failures") or 0)
        r["last_age_hours"] = age_hours(r.get("last_run"))
    return data


def telemetry_events(conn: sqlite3.Connection, level: str | None = None, limit: int = 100) -> list[dict]:
    where, params = ["1=1"], []
    if level:
        where.append("upper(level)=?")
        params.append(level.upper())
    params.append(max(1, min(int(limit), 2000)))
    data = rows(conn, f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?", params)
    for r in data:
        r["data"] = loads(r.get("data"), None)
    return data


def scans_list(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    data = rows(conn, "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 2000)),))
    for r in data:
        r["summary"] = loads(r.get("summary"), r.get("summary"))
        start, end = parse_ts(r.get("started_at")), parse_ts(r.get("finished_at"))
        r["duration_sec"] = round((end - start).total_seconds(), 1) if start and end else None
    return data


def feeds_list(conn: sqlite3.Connection) -> list[dict]:
    data = rows(
        conn,
        "SELECT name, kind, status, last_checked, last_updated, entries, bytes, enabled, error FROM feeds ORDER BY name",
    )
    for r in data:
        r["enabled"] = _bool(r.get("enabled"))
        r["age_hours"] = age_hours(r.get("last_updated"))
    return data


def last_scans(conn: sqlite3.Connection) -> dict[str, str]:
    data = rows(conn, "SELECT kind, started_at FROM scans WHERE id IN (SELECT max(id) FROM scans GROUP BY kind)")
    return {r["kind"]: r["started_at"] for r in data}


# --------------------------------------------------------------------------- summary


def summary(c: WebContext) -> dict:
    conn = c.conn
    score = security_score(conn)
    dns = dns_summary(c)
    return {
        "generated_at": now_iso(),
        "name": str(cfg_get(c.cfg, "general.name", "Home SOC")),
        "refresh_seconds": int(cfg_get(c.cfg, "web.refresh_seconds", 15) or 15),
        "score": score,
        "grade": grade(score),
        "trend": score_trend(conn),
        "score_breakdown": score_breakdown(conn),
        "counts": finding_counts(conn),
        "devices": device_counts(conn),
        "dns": {k: dns[k] for k in ("total24h", "blocked24h", "clients24h", "running", "blocked_pct", "enabled")},
        "jobs": telemetry_jobs(c),
        "feeds": feeds_list(conn),
        "last_scans": last_scans(conn),
        "events": telemetry_events(conn, limit=20),
        "scheduler": c.scheduler is not None,
    }


# --------------------------------------------------------------------------- scans

_running_lock = threading.Lock()
_running: set[str] = set()

# Fallback steps when no scheduler is wired in: (scan kind, module, callable, kwargs).
_HOST_MODULE = "homesoc.scanners.host_windows" if platform.system() == "Windows" else "homesoc.scanners.host_posix"
SCAN_STEPS: dict[str, list[tuple[str, str, str, dict]]] = {
    "quick": [("discovery", "homesoc.scanners.discovery", "run", {}), ("services", "homesoc.scanners.ports", "run", {"quick": True})],
    "full": [
        ("discovery", "homesoc.scanners.discovery", "run", {}),
        ("services", "homesoc.scanners.ports", "run", {}),
        ("vulns", "homesoc.vulns.matcher", "match_services", {}),
    ],
    "host": [("host", _HOST_MODULE, "run", {})],
    "exposure": [("exposure", "homesoc.scanners.exposure", "run", {})],
    "feeds": [("feeds", "homesoc.feeds.updater", "update", {})],
    "files": [("files", "homesoc.scanners.files", "run", {})],
}
# Scheduler job names per kind. cli.build_jobs registers manual-only "quick" and "full" jobs
# (discovery + quick services + vulns + wifi, and every step) so one run_now covers the whole scan.
SCAN_JOBS: dict[str, list[str]] = {
    "quick": ["quick"],
    "full": ["full"],
    "host": ["host"],
    "exposure": ["exposure"],
    "feeds": ["feeds"],
    "files": ["files"],
}


def _apply_findings(conn: sqlite3.Connection, result: Any, source: str) -> None:
    drafts = getattr(result, "findings", None)
    if not drafts:
        return
    try:
        engine = importlib.import_module("homesoc.findings.engine")
        engine.apply(conn, drafts, source)
    except Exception:
        logger.exception("findings.apply failed for %s", source)


def _run_steps(c: WebContext, kind: str) -> None:
    """Background fallback runner: records a scans row per step (SPEC-GAP: scans is core's
    table, but without a scheduler nobody else would) and applies findings if possible."""
    conn = c.conn
    try:
        for scan_kind, module_name, func_name, kwargs in SCAN_STEPS.get(kind, []):
            started = now_iso()
            row_id = write(conn, "INSERT INTO scans(kind, started_at, status) VALUES(?,?,?)", (scan_kind, started, "running"))
            status, error, summary_json = "ok", None, None
            try:
                mod = importlib.import_module(module_name)
                result = getattr(mod, func_name)(c.cfg, conn, **kwargs)
                _apply_findings(conn, result, scan_kind)
                err = getattr(result, "error", None)
                if err:
                    status, error = "error", str(err)[:500]
                summ = getattr(result, "summary", result if isinstance(result, dict) else None)
                summary_json = json.dumps(summ, default=str)[:4000] if summ is not None else None
            except Exception as exc:
                logger.exception("scan step %s failed", scan_kind)
                status, error = "error", str(exc)[:500]
            write(
                conn,
                "UPDATE scans SET finished_at=?, status=?, summary=?, error=? WHERE id=?",
                (now_iso(), status, summary_json, error, row_id),
            )
    finally:
        with _running_lock:
            _running.discard(kind)


def trigger_scan(c: WebContext, kind: str) -> dict:
    if kind not in SCAN_KINDS:
        return {"ok": False, "error": "kind must be one of " + ", ".join(SCAN_KINDS)}
    if c.scheduler is not None and hasattr(c.scheduler, "run_now"):
        started = [job for job in SCAN_JOBS[kind] if _safe_run_now(c.scheduler, job)]
        return {"ok": bool(started), "kind": kind, "mode": "scheduler", "jobs": started}
    with _running_lock:
        if kind in _running:
            return {"ok": False, "kind": kind, "error": "already running"}
        _running.add(kind)
    threading.Thread(target=_run_steps, args=(c, kind), name=f"homesoc-scan-{kind}", daemon=True).start()
    return {"ok": True, "kind": kind, "mode": "thread", "jobs": [s[0] for s in SCAN_STEPS[kind]]}


def _safe_run_now(scheduler: Any, job: str) -> bool:
    try:
        return bool(scheduler.run_now(job))
    except Exception:
        logger.exception("scheduler.run_now(%s) failed", job)
        return False


def _run_device_scan(c: WebContext, device_id: int) -> None:
    """Thread fallback when no scheduler is wired in (``serve``-less test setups)."""
    key = f"device:{device_id}"
    try:
        mod = importlib.import_module("homesoc.scanners.ports")
        # SPEC-GAP: the scanner interface has no per-device entry point; ports.scan_device is it.
        func = getattr(mod, "scan_device", None)
        if func is None:
            logger.warning("ports.scan_device unavailable; device %s not scanned", device_id)
            return
        result = func(c.cfg, c.conn, device_id)
        _apply_findings(c.conn, result, "services")
    except Exception:
        logger.exception("device scan %s failed", device_id)
    finally:
        with _running_lock:
            _running.discard(key)


def trigger_device_scan(c: WebContext, device_id: int) -> dict:
    if one(c.conn, "SELECT id FROM devices WHERE id=?", (device_id,)) is None:
        return {"ok": False, "error": "no such device"}
    # Preferred path: queue the id for the scheduler's manual-only ``device_scan`` job so it is
    # serialised with the scheduled service scan and can never race it in the services table.
    if c.scheduler is not None and hasattr(c.scheduler, "run_now") and "device_scan" in getattr(c.scheduler, "jobs", {}):
        try:
            cli = importlib.import_module("homesoc.cli")
            cli.queue_device_scan(device_id)
        except Exception:
            logger.exception("could not queue device scan %s", device_id)
            return {"ok": False, "error": "could not queue the scan"}
        _safe_run_now(c.scheduler, "device_scan")  # False = already queued/running; the id is in the queue anyway
        return {"ok": True, "device_id": device_id, "mode": "scheduler"}
    key = f"device:{device_id}"
    with _running_lock:
        if key in _running:
            return {"ok": False, "error": "already running"}
        _running.add(key)
    threading.Thread(target=_run_device_scan, args=(c, device_id), name=f"homesoc-{key}", daemon=True).start()
    return {"ok": True, "device_id": device_id, "mode": "thread"}


# --------------------------------------------------------------------------- settings


def _encode_setting(kind: str, value: Any) -> str:
    """Overrides are stored as strings (db.set_setting). SPEC-GAP: encoding is not specified;
    bools as true/false, lists as a JSON array, everything else str()."""
    if kind == "bool":
        return "true" if _bool(value) else "false"
    if kind == "list":
        if isinstance(value, str):
            value = [v.strip() for v in value.replace("\n", ",").split(",") if v.strip()]
        return json.dumps([str(v) for v in (value or [])])
    if kind == "int":
        return str(int(value))
    if kind == "float":
        return str(float(value))
    return str(value if value is not None else "")


def _display_value(kind: str, value: Any) -> Any:
    if kind == "list":
        parsed = loads(value, None) if isinstance(value, str) and value.startswith("[") else value
        if isinstance(parsed, (list, tuple)):
            return ", ".join(str(v) for v in parsed)
        return str(parsed or "")
    if kind == "bool":
        return _bool(value)
    return "" if value is None else value


def settings_get(c: WebContext) -> list[dict]:
    out = []
    for key, kind in EDITABLE_SETTINGS:
        override = get_setting(c.conn, key)
        raw = override if override is not None else cfg_get(c.cfg, key, "")
        item = {"key": key, "section": key.split(".")[0], "type": kind, "source": "override" if override is not None else "config"}
        if kind == "secret":
            item["value"] = ""
            item["set"] = bool(raw)
        else:
            item["value"] = _display_value(kind, raw)
        out.append(item)
    return out


def settings_post(c: WebContext, payload: dict) -> dict:
    allowed = dict(EDITABLE_SETTINGS)
    saved, errors = [], {}
    for key, value in (payload or {}).items():
        kind = allowed.get(str(key))
        if kind is None:
            errors[str(key)] = "not editable"
            continue
        if kind == "secret" and not value:
            continue  # blank secret field means "keep what is there"
        try:
            set_setting(c.conn, str(key), _encode_setting(kind, value))
            saved.append(str(key))
        except (TypeError, ValueError):
            errors[str(key)] = f"expected {kind}"
    return {"ok": not errors, "saved": saved, "errors": errors, "restart_required": bool(saved)}


def notify_test(c: WebContext) -> dict:
    try:
        channels = importlib.import_module("homesoc.notify.channels")
    except ImportError:
        return {"ok": False, "error": "notify package unavailable"}
    try:
        result = channels.test_channels(c.cfg, c.conn)
    except Exception as exc:
        logger.exception("test_channels failed")
        return {"ok": False, "error": str(exc)[:200]}
    return {"ok": True, "channels": result}


def export_data(c: WebContext, full: bool = False) -> dict:
    conn = c.conn
    data = {
        "generated_at": now_iso(),
        "version": "0.1.0",
        "findings": findings_list(conn, limit=5000),
        "devices": devices_list(conn),
        "vulns": vulns_list(conn, limit=5000),
    }
    if full:
        # Support bundle: everything useful for a bug report, minus secrets.
        data.update(
            {
                "platform": {"system": platform.system(), "release": platform.release(), "python": platform.python_version()},
                "settings": [s for s in settings_get(c)],
                "jobs": telemetry_jobs(c),
                "feeds": feeds_list(conn),
                "scans": scans_list(conn, 100),
                "events": telemetry_events(conn, limit=300),
                "host": host_data(conn),
                "dns": dns_summary(c),
            }
        )
    return data


# --------------------------------------------------------------------------- routes


def _int_arg(name: str, default: int, lo: int = 1, hi: int = 100000) -> int:
    try:
        return max(lo, min(int(request.args.get(name, default)), hi))
    except (TypeError, ValueError):
        return default


def _payload() -> dict:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _status(result: dict, ok_code: int = 200) -> tuple[Response, int]:
    if result.get("ok", True):
        return jsonify(result), ok_code
    code = 404 if "no such" in str(result.get("error", "")) else 400
    return jsonify(result), code


@bp.get("/summary")
def api_summary():
    return jsonify(summary(ctx()))


@bp.get("/findings")
def api_findings():
    return jsonify(
        findings_list(
            ctx().conn,
            status=request.args.get("status") or None,
            severity=request.args.get("severity") or None,
            q=(request.args.get("q") or "").strip()[:200] or None,
            category=request.args.get("category") or None,
            limit=_int_arg("limit", 500, 1, 5000),
        )
    )


@bp.post("/findings/<int:row_id>/status")
def api_finding_status(row_id: int):
    body = _payload()
    status = str(body.get("status", ""))
    if status not in STATUSES:
        return jsonify({"ok": False, "error": "status must be one of " + ", ".join(STATUSES)}), 400
    note = (str(body.get("note") or "")[:500]) or None
    if not set_finding_status(ctx().conn, row_id, status, note):
        return jsonify({"ok": False, "error": "no such finding"}), 404
    return jsonify({"ok": True, "id": row_id, "status": status})


@bp.get("/devices")
def api_devices():
    return jsonify(devices_list(ctx().conn))


@bp.get("/devices/<int:device_id>")
def api_device(device_id: int):
    d = device_detail(ctx().conn, device_id)
    if d is None:
        return jsonify({"ok": False, "error": "no such device"}), 404
    return jsonify(d)


@bp.post("/devices/<int:device_id>")
def api_device_update(device_id: int):
    if not update_device(ctx().conn, device_id, _payload()):
        return jsonify({"ok": False, "error": "no such device"}), 404
    return jsonify({"ok": True, "id": device_id})


@bp.post("/devices/<int:device_id>/scan")
def api_device_scan(device_id: int):
    return _status(trigger_device_scan(ctx(), device_id), 202)


@bp.get("/vulns")
def api_vulns():
    min_cvss = request.args.get("min_cvss")
    try:
        min_cvss_f = float(min_cvss) if min_cvss else None
    except ValueError:
        min_cvss_f = None
    device = request.args.get("device_id")
    return jsonify(
        vulns_list(
            ctx().conn,
            kev=_bool(request.args.get("kev")),
            q=(request.args.get("q") or "").strip()[:200] or None,
            device_id=int(device) if device and device.isdigit() else None,
            min_cvss=min_cvss_f,
        )
    )


@bp.get("/host")
def api_host():
    return jsonify(host_data(ctx().conn))


@bp.post("/defender/quick-scan")
def api_defender_quick_scan():
    result = defender_action(ctx().cfg, "quick-scan")
    return (jsonify(result), 202) if result["ok"] else (jsonify(result), 503)


@bp.post("/defender/update")
def api_defender_update():
    result = defender_action(ctx().cfg, "update")
    return (jsonify(result), 202) if result["ok"] else (jsonify(result), 503)


@bp.get("/defender/status")
def api_defender_status():
    """Poll target for the two fire-and-forget actions above."""
    return jsonify(defender_status())


@bp.get("/dns/summary")
def api_dns_summary():
    return jsonify(dns_summary(ctx()))


@bp.get("/dns/series")
def api_dns_series():
    return jsonify(dns_series(ctx().conn, _int_arg("hours", 24, 1, 24 * 14)))


@bp.get("/dns/top")
def api_dns_top():
    kind = request.args.get("kind", "blocked")
    return jsonify(dns_top(ctx().conn, "clients" if kind == "clients" else "blocked", _int_arg("hours", 24, 1, 24 * 30), _int_arg("limit", 20, 1, 200)))


@bp.get("/dns/log")
def api_dns_log():
    return jsonify(
        dns_log(
            ctx().conn,
            _int_arg("limit", 100, 1, 1000),
            (request.args.get("client") or "").strip()[:64] or None,
            request.args.get("action") or None,
        )
    )


@bp.get("/dns/lists")
def api_dns_lists():
    return jsonify(dns_lists(ctx()))


@bp.post("/dns/override")
def api_dns_override():
    body = _payload()
    return _status(dns_override_set(ctx().conn, body.get("domain"), body.get("action"), body.get("note")))


@bp.delete("/dns/override/<domain>")
def api_dns_override_delete(domain: str):
    return _status(dns_override_delete(ctx().conn, domain))


@bp.get("/dns/overrides")
def api_dns_overrides():
    return jsonify(dns_overrides(ctx().conn))


@bp.get("/dns/reputation")
def api_dns_reputation():
    return jsonify(dns_reputation(ctx().conn, _int_arg("limit", 200, 1, 2000)))


@bp.get("/telemetry/metrics")
def api_telemetry_metrics():
    return jsonify(telemetry_metrics(ctx().conn, (request.args.get("name") or "").strip()[:100] or None, _int_arg("hours", 24 * 7, 1, 24 * 90)))


@bp.get("/telemetry/jobs")
def api_telemetry_jobs():
    return jsonify(telemetry_jobs(ctx()))


@bp.get("/telemetry/events")
def api_telemetry_events():
    return jsonify(telemetry_events(ctx().conn, (request.args.get("level") or "").strip()[:16] or None, _int_arg("limit", 100, 1, 2000)))


@bp.get("/scans")
def api_scans():
    return jsonify(scans_list(ctx().conn, _int_arg("limit", 200, 1, 2000)))


@bp.post("/scan")
def api_scan():
    body = _payload()
    kind = str(body.get("kind") or request.args.get("kind") or "")
    result = trigger_scan(ctx(), kind)
    if not result.get("ok"):
        return jsonify(result), 409 if result.get("error") == "already running" else 400
    return jsonify(result), 202


@bp.get("/settings")
def api_settings_get():
    return jsonify(settings_get(ctx()))


@bp.post("/settings")
def api_settings_post():
    result = settings_post(ctx(), _payload())
    return jsonify(result), (200 if result["ok"] else 400)


@bp.post("/notify/test")
def api_notify_test():
    result = notify_test(ctx())
    return jsonify(result), (200 if result["ok"] else 503)


@bp.get("/export")
def api_export():
    full = _bool(request.args.get("full")) or _bool(request.args.get("bundle"))
    body = json.dumps(export_data(ctx(), full), indent=2, default=str)
    name = "homesoc-support-bundle.json" if full else "homesoc-export.json"
    return Response(body, mimetype="application/json", headers={"Content-Disposition": f'attachment; filename="{name}"'})
