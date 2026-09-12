"""Remediation summary: what has been found, what has been fixed, what is still outstanding.

Spec Addendum A3. :func:`build_summary` is the single read model behind the ``/summary`` page,
``/api/summary/report`` and the Markdown/JSON exports, so the dashboard and a report mailed to
somebody else can never disagree.

Every value is derived from the SPEC section 4 tables with SQL written here; a package that has
not run yet simply contributes zeros. The function must return the complete key set on an empty
database and must never raise — a report that blows up is worse than a report full of zeros.
"""

from __future__ import annotations

import importlib
import logging
import sqlite3
from typing import Any

from homesoc.web import api

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

# findings.subject prefixes -> the subject buckets the report groups by.
SUBJECT_TYPES: tuple[str, ...] = ("host", "device", "wan", "dns", "soc")

# Scan kinds whose freshness the coverage section reports.
COVERAGE_SCANS: tuple[str, ...] = ("discovery", "services", "host", "exposure", "files")

# A blocklist older than this has stopped protecting anybody.
FEED_STALE_HOURS = 72


# --------------------------------------------------------------------------- helpers


def _pct(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile; no numpy, and correct for the tiny samples a home network yields."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 2)
    idx = max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))
    return round(ordered[idx], 2)


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    value = ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2
    return round(value, 2)


def _hours_between(start: Any, end: Any) -> float | None:
    a, b = api.parse_ts(start), api.parse_ts(end)
    if a is None or b is None:
        return None
    return round(max(0.0, (b - a).total_seconds() / 3600.0), 2)


def subject_type(subject: Any) -> str:
    head = str(subject or "").split(":", 1)[0].strip().lower()
    return head if head in SUBJECT_TYPES else "soc"


def _catalog() -> Any | None:
    try:
        return importlib.import_module("homesoc.findings.catalog")
    except ImportError:
        return None


def remediation_steps(finding_id: str, evidence: Any = None, subject: str = "") -> list[str]:
    """Numbered steps from the catalog with evidence interpolated where the catalog supports it."""
    catalog = _catalog()
    if catalog is not None and hasattr(catalog, "render_remediation"):
        try:
            steps = catalog.render_remediation(finding_id, evidence if isinstance(evidence, dict) else {}, subject)
            if steps:
                return [str(s) for s in steps]
        except Exception:  # a template bug in the catalog must not empty the worklist
            logger.exception("render_remediation failed for %s", finding_id)
    spec = api.catalog_spec(finding_id)
    return [str(s) for s in (getattr(spec, "remediation", None) or [])]


def _refs(finding_id: str) -> list[str]:
    spec = api.catalog_spec(finding_id)
    return [str(r) for r in (getattr(spec, "refs", None) or [])]


# --------------------------------------------------------------------------- sections


def _totals(conn: sqlite3.Connection, cutoff: str) -> tuple[dict, dict[str, int]]:
    by_status = {s: 0 for s in api.STATUSES}
    for r in api.rows(conn, "SELECT status, count(*) AS n FROM findings GROUP BY status"):
        by_status[str(r["status"])] = by_status.get(str(r["status"]), 0) + int(r["n"] or 0)
    found_all_time = int(api.scalar(conn, "SELECT count(*) FROM findings"))
    open_n, resolved_n = by_status.get("open", 0), by_status.get("resolved", 0)
    totals = {
        "found_all_time": found_all_time,
        "open": open_n,
        "acknowledged": by_status.get("acknowledged", 0),
        "resolved": resolved_n,
        "suppressed": by_status.get("suppressed", 0),
        "remediation_rate": _pct(resolved_n, resolved_n + open_n),
        "found_in_window": int(api.scalar(conn, "SELECT count(*) FROM findings WHERE first_seen>=?", (cutoff,))),
        "resolved_in_window": int(
            api.scalar(conn, "SELECT count(*) FROM findings WHERE resolved_at IS NOT NULL AND resolved_at>=?", (cutoff,))
        ),
    }
    return totals, by_status


def _by_severity(conn: sqlite3.Connection) -> dict[str, dict[str, int]]:
    counts = api.finding_counts(conn)
    return {status: {sev: int(counts.get(status, {}).get(sev, 0)) for sev in api.SEVERITIES} for status in api.STATUSES}


def _grouped(conn: sqlite3.Connection, key: str) -> list[dict]:
    """found/open/resolved per category or per subject type, computed in Python because both
    groupings need the findings catalog, which SQLite cannot see."""
    buckets: dict[str, dict[str, int]] = {}
    for r in api.rows(conn, "SELECT finding_id, subject, status, count(*) AS n FROM findings GROUP BY finding_id, subject, status"):
        name = api.category_for(str(r["finding_id"])) if key == "category" else subject_type(r["subject"])
        b = buckets.setdefault(name, {"found": 0, "open": 0, "acknowledged": 0, "resolved": 0, "suppressed": 0})
        n = int(r["n"] or 0)
        b["found"] += n
        status = str(r["status"] or "")
        if status in b:
            b[status] += n
    label = "category" if key == "category" else "subject_type"
    out = [{label: name, **{k: v for k, v in vals.items()}} for name, vals in buckets.items()]
    out.sort(key=lambda d: (-d["open"], -d["found"], str(d[label])))
    return out


def _how_resolved(conn: sqlite3.Connection, row_ids: list[int]) -> dict[int, str]:
    """`auto` when the newest lifecycle event for the finding is ``auto_resolved`` — the agent
    re-scanned and the problem was gone, which is the strongest evidence a fix worked."""
    if not row_ids:
        return {}
    out: dict[int, str] = {}
    chunk = 400
    for start in range(0, len(row_ids), chunk):
        ids = row_ids[start : start + chunk]
        placeholders = ",".join("?" for _ in ids)
        for r in api.rows(
            conn,
            f"SELECT finding_row_id, event FROM finding_events WHERE finding_row_id IN ({placeholders}) "
            "AND id IN (SELECT max(id) FROM finding_events GROUP BY finding_row_id)",
            ids,
        ):
            out[int(r["finding_row_id"])] = "auto" if str(r["event"]) == "auto_resolved" else "manual"
    return out


def _remediated(conn: sqlite3.Connection, cutoff: str, limit: int = 500) -> list[dict]:
    data = api.rows(
        conn,
        "SELECT f.id, f.finding_id, f.title, f.severity, f.subject, f.first_seen, f.resolved_at, f.occurrences, "
        "COALESCE(d.nickname, d.hostname, d.ip, d.mac) AS device_name "
        "FROM findings f LEFT JOIN devices d ON d.id=f.device_id "
        "WHERE f.status='resolved' AND f.resolved_at IS NOT NULL AND f.resolved_at>=? "
        "ORDER BY f.resolved_at DESC LIMIT ?",
        (cutoff, limit),
    )
    how = _how_resolved(conn, [int(r["id"]) for r in data])
    out = []
    for r in data:
        out.append(
            {
                "finding_id": r["finding_id"],
                "row_id": int(r["id"]),
                "title": r["title"],
                "severity": r["severity"],
                "subject": r["subject"],
                "device_name": r.get("device_name"),
                "first_seen": r["first_seen"],
                "resolved_at": r["resolved_at"],
                "hours_open": _hours_between(r["first_seen"], r["resolved_at"]),
                "how": how.get(int(r["id"]), "manual"),
                "occurrences": int(r.get("occurrences") or 1),
            }
        )
    return out


def _open_worklist(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    order = "CASE f.severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(api.SEVERITIES)) + " ELSE 9 END"
    data = api.rows(
        conn,
        "SELECT f.id, f.finding_id, f.title, f.severity, f.subject, f.detail, f.evidence, f.first_seen, "
        "f.occurrences, f.device_id, COALESCE(d.nickname, d.hostname, d.ip, d.mac) AS device_name "
        "FROM findings f LEFT JOIN devices d ON d.id=f.device_id WHERE f.status='open' "
        f"ORDER BY {order}, f.first_seen ASC LIMIT ?",
        (limit,),
    )
    out = []
    for r in data:
        evidence = api.loads(r.get("evidence"), {})
        age = _hours_between(r["first_seen"], api.now_iso())
        out.append(
            {
                "finding_id": r["finding_id"],
                "row_id": int(r["id"]),
                "title": r["title"],
                "severity": r["severity"],
                "subject": r["subject"],
                "detail": r.get("detail") or "",
                "device_id": r.get("device_id"),
                "device_name": r.get("device_name"),
                "first_seen": r["first_seen"],
                "age_days": round((age or 0.0) / 24.0, 1),
                "occurrences": int(r.get("occurrences") or 1),
                "category": api.category_for(str(r["finding_id"])),
                "remediation": remediation_steps(str(r["finding_id"]), evidence, str(r["subject"])),
                "refs": _refs(str(r["finding_id"])),
            }
        )
    return out


def _time_to_remediate(remediated: list[dict]) -> dict:
    timed = [r for r in remediated if isinstance(r.get("hours_open"), (int, float))]
    hours = [float(r["hours_open"]) for r in timed]
    fastest = min(timed, key=lambda r: r["hours_open"], default=None)
    slowest = max(timed, key=lambda r: r["hours_open"], default=None)

    def trim(r: dict | None) -> dict | None:
        return None if r is None else {k: r[k] for k in ("finding_id", "title", "severity", "hours_open")}

    return {
        "median_hours": _median(hours),
        "p90_hours": _percentile(hours, 0.9),
        "count": len(hours),
        "fastest": trim(fastest),
        "slowest": trim(slowest),
    }


def _top_devices(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    data = api.rows(
        conn,
        "SELECT d.id, COALESCE(d.nickname, d.hostname, d.ip, d.mac) AS name, d.ip, "
        "sum(CASE WHEN f.status='open' THEN 1 ELSE 0 END) AS open_n, "
        "sum(CASE WHEN f.status='resolved' THEN 1 ELSE 0 END) AS resolved_n "
        "FROM devices d JOIN findings f ON f.device_id=d.id GROUP BY d.id "
        "ORDER BY open_n DESC, resolved_n DESC LIMIT ?",
        (limit,),
    )
    return [
        {"device_id": int(r["id"]), "name": r.get("name"), "ip": r.get("ip"),
         "open": int(r.get("open_n") or 0), "resolved": int(r.get("resolved_n") or 0)}
        for r in data
    ]


def _coverage(conn: sqlite3.Connection) -> dict:
    last = api.last_scans(conn)
    feeds = api.feeds_list(conn)
    stale = [
        f["name"]
        for f in feeds
        if not f.get("last_updated") or (f.get("age_hours") is not None and f["age_hours"] > FEED_STALE_HOURS)
    ]
    since = api.cutoff_iso(24)
    dns_agg = api.one(
        conn,
        "SELECT count(*) AS total, sum(action='block') AS blocked, count(DISTINCT client) AS clients "
        "FROM dns_queries WHERE ts>=?",
        (since,),
    ) or {}
    total = int(dns_agg.get("total") or 0)
    blocked = int(dns_agg.get("blocked") or 0)
    return {
        "devices_total": int(api.scalar(conn, "SELECT count(*) FROM devices")),
        "devices_online": int(api.scalar(conn, "SELECT count(*) FROM devices WHERE online=1")),
        "services_seen": int(api.scalar(conn, "SELECT count(*) FROM services WHERE state='open'")),
        "cves_matched": int(api.scalar(conn, "SELECT count(*) FROM vulns")),
        "kev_matches": int(api.scalar(conn, "SELECT count(*) FROM vulns WHERE kev=1")),
        "last_scans": {kind: last.get(kind) for kind in COVERAGE_SCANS},
        "feeds_current": sum(1 for f in feeds if f["name"] not in stale),
        "feeds_total": len(feeds),
        "feeds_stale": stale,
        "dns": {
            # The report only has the database, not cfg; a stored override wins, otherwise
            # "did the resolver actually answer anything" is the honest answer.
            "enabled": api._bool(api.get_setting(conn, "dns.enabled", "")) or total > 0,
            "queries_24h": total,
            "blocked_24h": blocked,
            "block_rate": _pct(blocked, total),
            "clients_24h": int(dns_agg.get("clients") or 0),
        },
    }


def _defender(conn: sqlite3.Connection, cutoff: str) -> dict:
    status = api.loads(api.get_setting(conn, "defender.status_json"), {}) or {}
    if not isinstance(status, dict):
        status = {}
    threats = int(
        api.scalar(
            conn,
            "SELECT count(*) FROM events WHERE source='defender' AND lower(level) IN ('warning','error') AND ts>=?",
            (cutoff,),
        )
    )
    return {
        "available": bool(status),
        "av_enabled": bool(status.get("AntivirusEnabled", status.get("av_enabled", False))),
        "rtp": bool(status.get("RealTimeProtectionEnabled", status.get("rtp", False))),
        "signature_age_days": status.get("AntivirusSignatureAge", status.get("signature_age_days")),
        "last_quick_scan": status.get("QuickScanEndTime") or status.get("last_quick_scan"),
        "last_full_scan": status.get("FullScanEndTime") or status.get("last_full_scan"),
        "threats_30d": threats,
    }


def _notes(conn: sqlite3.Connection) -> list[str]:
    """"Not checked" explanations, so a clean report is never mistaken for a complete one."""
    notes: list[str] = []
    for r in api.rows(conn, "SELECT check_id FROM host_checks WHERE needs_admin=1 ORDER BY check_id"):
        spec = api.catalog_spec(str(r["check_id"]))
        title = getattr(spec, "title", None) or str(r["check_id"])
        # Catalog titles are phrased as the failure ("BitLocker / device encryption is off"), so
        # splicing one into "X could not be checked" asserts the very thing we could not determine.
        # Quote it as the question instead: this report is exportable and must not invent verdicts.
        notes.append(
            f"Not checked without administrator rights ({r['check_id']}): "
            f'"{title}" is neither confirmed nor ruled out.'
        )
    stale = [f["name"] for f in api.feeds_list(conn) if (f.get("age_hours") or 0) > FEED_STALE_HOURS]
    if stale:
        notes.append("These definition feeds are stale, so matches may be missing: " + ", ".join(sorted(stale)))
    if not api.scalar(conn, "SELECT count(*) FROM scans"):
        notes.append("No scan has run yet — every count below is zero because nothing has been looked at.")
    return notes


# --------------------------------------------------------------------------- public API


def build_summary(conn: sqlite3.Connection, *, days: int = 30) -> dict:
    """Everything found and everything remediated, in one dict (Addendum A3.1)."""
    days = max(1, min(int(days or 30), 3650))
    cutoff = api.cutoff_iso(days * 24)
    score = api.security_score(conn)
    totals, _ = _totals(conn, cutoff)
    remediated = _remediated(conn, cutoff)
    return {
        "generated_at": api.now_iso(),
        "window_days": days,
        "score": {"current": score, "grade": api.grade(score), "trend": api.score_trend(conn, days)},
        "totals": totals,
        "by_severity": _by_severity(conn),
        "by_category": _grouped(conn, "category"),
        "by_subject": _grouped(conn, "subject"),
        "time_to_remediate": _time_to_remediate(remediated),
        "remediated": remediated,
        "open_worklist": _open_worklist(conn),
        "top_devices": _top_devices(conn),
        "coverage": _coverage(conn),
        "defender": _defender(conn, cutoff),
        "notes": _notes(conn),
    }


def remediation_report_json(conn: sqlite3.Connection, *, days: int = 30) -> dict:
    data = build_summary(conn, days=days)
    data["schema_version"] = SCHEMA_VERSION
    return data


# --------------------------------------------------------------------------- markdown


def _md_escape(value: Any) -> str:
    """Keep table pipes and line breaks from breaking the document; the report is plain text,
    so nothing else needs escaping."""
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _md_table(headers: list[str], rows_: list[list[Any]]) -> list[str]:
    if not rows_:
        return ["_None._", ""]
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out += ["| " + " | ".join(_md_escape(c) for c in row) + " |" for row in rows_]
    out.append("")
    return out


def _hours_words(hours: Any) -> str:
    if not isinstance(hours, (int, float)):
        return "—"
    if hours < 1:
        return f"{int(hours * 60)} min"
    if hours < 48:
        return f"{hours:.1f} h"
    return f"{hours / 24:.1f} days"


def remediation_report_markdown(conn: sqlite3.Connection, *, days: int = 30) -> str:
    """A standalone document: readable by somebody who has never seen the dashboard."""
    s = build_summary(conn, days=days)
    t, cov, dfn = s["totals"], s["coverage"], s["defender"]
    lines: list[str] = []
    lines.append("# Home SOC — security report")
    lines.append("")
    lines.append(f"Generated {s['generated_at']} · window: last {s['window_days']} days")
    lines.append("")
    lines.append(
        f"Home SOC has found **{t['found_all_time']}** issues on this network and host; "
        f"**{t['resolved']}** are fixed, **{t['open']}** still need attention "
        f"({t['acknowledged']} acknowledged, {t['suppressed']} suppressed). "
        f"The current security score is **{s['score']['current']}/100 (grade {s['score']['grade']})** and the "
        f"remediation rate is **{round(t['remediation_rate'] * 100)}%**."
    )
    lines.append("")
    ttr = s["time_to_remediate"]
    if ttr["median_hours"] is not None:
        lines.append(
            f"Of the {t['resolved_in_window']} issues fixed in this window, the median time to fix was "
            f"{_hours_words(ttr['median_hours'])} and the slowest 10% took {_hours_words(ttr['p90_hours'])} or more."
        )
        lines.append("")

    lines.append("## Found vs remediated, by severity")
    lines.append("")
    lines += _md_table(
        ["Severity", "Open", "Acknowledged", "Resolved", "Suppressed"],
        [
            [sev.capitalize()] + [s["by_severity"][st][sev] for st in ("open", "acknowledged", "resolved", "suppressed")]
            for sev in api.SEVERITIES
        ],
    )

    lines.append("## By category")
    lines.append("")
    lines += _md_table(
        ["Category", "Found", "Open", "Resolved"],
        [[c["category"], c["found"], c["open"], c["resolved"]] for c in s["by_category"]],
    )

    lines.append(f"## Remediated (last {s['window_days']} days)")
    lines.append("")
    lines += _md_table(
        ["Finding", "Severity", "Where", "Opened", "Fixed", "Time open", "How"],
        [
            [
                r["title"],
                r["severity"],
                r.get("device_name") or r["subject"],
                r["first_seen"],
                r["resolved_at"],
                _hours_words(r["hours_open"]),
                "verified by rescan" if r["how"] == "auto" else "marked fixed",
            ]
            for r in s["remediated"]
        ],
    )

    lines.append("## Still open — what to do next")
    lines.append("")
    if not s["open_worklist"]:
        lines.append("_Nothing is open. Everything Home SOC found has been fixed, acknowledged or suppressed._")
        lines.append("")
    for i, item in enumerate(s["open_worklist"], start=1):
        where = item.get("device_name") or item["subject"]
        lines.append(f"### {i}. [{item['severity'].upper()}] {item['title']}")
        lines.append("")
        lines.append(
            f"- Affects: {where}  \n- Finding ID: `{item['finding_id']}`  \n"
            f"- Open for {item['age_days']} days · seen {item['occurrences']}×"
        )
        if item["detail"]:
            lines.append("")
            lines.append(str(item["detail"]))
        if item["remediation"]:
            lines.append("")
            lines.append("**How to fix it**")
            lines.append("")
            for n, step in enumerate(item["remediation"], start=1):
                lines.append(f"{n}. {step}")
        if item["refs"]:
            lines.append("")
            lines.append("References: " + ", ".join(f"<{r}>" for r in item["refs"]))
        lines.append("")

    lines.append("## Coverage — what was actually checked")
    lines.append("")
    lines += _md_table(
        ["What", "Value"],
        [
            ["Devices known", f"{cov['devices_total']} ({cov['devices_online']} online)"],
            ["Open service ports seen", cov["services_seen"]],
            ["CVEs matched", f"{cov['cves_matched']} ({cov['kev_matches']} in CISA KEV)"],
            ["Definition feeds current", f"{cov['feeds_current']} / {cov['feeds_total']}"],
            ["Stale feeds", ", ".join(cov["feeds_stale"]) or "none"],
            [
                "DNS filtering (24 h)",
                f"{cov['dns']['queries_24h']} queries, {cov['dns']['blocked_24h']} blocked "
                f"({round(cov['dns']['block_rate'] * 100)}%), {cov['dns']['clients_24h']} clients",
            ],
            [
                "Microsoft Defender",
                (
                    f"antivirus {'on' if dfn['av_enabled'] else 'off'}, real-time protection "
                    f"{'on' if dfn['rtp'] else 'off'}, signatures {dfn['signature_age_days']} day(s) old, "
                    f"{dfn['threats_30d']} detection(s) in window"
                )
                if dfn["available"]
                else "not available (no status recorded)",
            ],
        ],
    )
    lines.append("### Last scan of each kind")
    lines.append("")
    lines += _md_table(
        ["Scan", "Last run"],
        [[kind, cov["last_scans"].get(kind) or "never"] for kind in COVERAGE_SCANS],
    )

    if s["notes"]:
        lines.append("## Not checked")
        lines.append("")
        for note in s["notes"]:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Generated by Home SOC, a self-hosted home security agent. Nothing in this report left your machine.")
    lines.append("")
    return "\n".join(lines)
