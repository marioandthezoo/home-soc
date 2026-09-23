"""Security score: one number a home user can watch go up.

The v1 formula (100 minus 25/10/4/1 per open critical/high/medium/low, floor 0) was measured
against a real installation and found useless: 70 open findings — mostly 22 "new device" rows and
18 "outdated app" rows — drove it straight to 0/F, where it stayed no matter what the user fixed.
A number that every real home pins to the floor carries no information. This module replaces it.

FORMULA
-------
1. **Only unfixed findings count, and not all of them equally.** Each finding row is a *slot* whose
   weight is its severity weight times a status factor::

       severity weight   critical 30 · high 12 · medium 5 · low 1.5 · info 0
       status factor     open 1.0 · acknowledged 0.25 · suppressed 0 · resolved 0

   ``acknowledged`` means "I have seen this and chosen to live with it for now" — the risk is still
   real, so it still costs something, but a quarter of the price. ``suppressed`` ("this is not a
   problem here, stop telling me") and ``resolved`` cost nothing.

2. **Diminishing returns per finding type.** 26 separate "outdated app" findings are one problem,
   not 26. Within a single ``finding_id`` the slots are sorted worst-first and each successive one
   is discounted by half::

       penalty(id) = w0 + w1/2 + w2/4 + w3/8 + ...      capped at 2 x w0

   So the first occurrence costs full price, the second half, the third a quarter, and a whole pile
   of the same problem can never cost more than twice a single one. One outdated app costs 1.5
   points; twenty-six cost 3.

3. **The total penalty is converted to a score by halving, not subtracting**::

       score = 100 x 0.5 ** (total_penalty / 60)

   The score therefore never sticks at 0 and *always* moves when the user fixes something: every 60
   points of penalty removed doubles what is left. This is the property the old formula lacked.

4. **Critical findings still tank the score**, through explicit ceilings rather than arithmetic:
   one open critical (a KEV match, a port open to the internet, antivirus switched off) caps the
   score at 34 — an F whatever else is clean; two or more cap it at 20. Any open *high* finding
   caps it at 79, so an A means "nothing high or critical is open".

Grades: A >= 80, B >= 65, C >= 50, D >= 35, F below. Calibrated against real data: a tidy home with
a couple of medium and a handful of low hygiene items scores 86-92 (A); the author's machine, with
7 open high findings, 22 unbaselined devices and 18 outdated apps, scores 36 (D) and gains 12
points the moment the outdated high-risk apps are updated.

``score_breakdown(conn)`` explains the number: one row per finding type, worst first, with the
penalty it contributes and the score points the user would get back by clearing it.
"""
from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

#: Cost of the *first* occurrence of a finding type, by severity.
WEIGHTS: dict[str, float] = {"critical": 30.0, "high": 12.0, "medium": 5.0, "low": 1.5, "info": 0.0}

#: How much of that cost each lifecycle status still carries.
STATUS_FACTORS: dict[str, float] = {"open": 1.0, "acknowledged": 0.25, "suppressed": 0.0, "resolved": 0.0}

#: Statuses that reach the score at all (the SQL filter and STATUS_FACTORS must agree).
COUNTED_STATUSES: tuple[str, ...] = ("open", "acknowledged")

#: Each repeat of the same finding_id costs this fraction of the one before it.
REPEAT_DECAY = 0.5
#: Ceiling on one finding type, as a multiple of its first occurrence: 1/(1-REPEAT_DECAY).
REPEAT_CAP = 1.0 / (1.0 - REPEAT_DECAY)

#: Penalty points that halve the score.
HALF_LIFE = 60.0

#: Letter bands, highest first.
GRADE_BANDS: tuple[tuple[int, str], ...] = ((80, "A"), (65, "B"), (50, "C"), (35, "D"))

#: An open critical is an F; two or more is a hard F. An open high forbids an A.
CEILING_ONE_CRITICAL = 34
CEILING_MANY_CRITICAL = 20
CEILING_ANY_HIGH = 79

_MAX_SLOTS = 512  # guard: past this the geometric tail is far below float precision anyway

try:  # pragma: no cover - exercised only when P1 is present
    from homesoc.db import query as _query
except ImportError:  # pragma: no cover

    def _query(conn: sqlite3.Connection, sql: str, params=()) -> list[sqlite3.Row]:
        return list(conn.execute(sql, tuple(params)).fetchall())

try:  # pragma: no cover
    from homesoc.findings import catalog as _catalog
except ImportError:  # pragma: no cover
    _catalog = None  # type: ignore[assignment]


# --------------------------------------------------------------------------- the maths


def slot_weight(severity: str, status: str) -> float:
    """Points one finding row is worth before the repeat discount."""
    return WEIGHTS.get(str(severity), 0.0) * STATUS_FACTORS.get(str(status), 0.0)


def group_penalty(slots: list[tuple[float, int]]) -> float:
    """Penalty for one finding_id. ``slots`` is [(weight, how many rows have it), ...].

    Worst-first, each successive row costs REPEAT_DECAY times the previous one. A run of ``n``
    identical weights starting at position ``i`` sums in closed form, so 500 identical findings
    cost the same as the arithmetic says without building a 500-element list.
    """
    ordered = sorted(((w, n) for w, n in slots if w > 0 and n > 0), key=lambda s: -s[0])
    if not ordered:
        return 0.0
    total = 0.0
    index = 0
    for weight, count in ordered:
        if index >= _MAX_SLOTS:
            break
        run = REPEAT_DECAY ** index * (1.0 - REPEAT_DECAY ** count) / (1.0 - REPEAT_DECAY)
        total += weight * run
        index += count
    return min(total, REPEAT_CAP * ordered[0][0])


def score_from_penalty(penalty: float, *, open_critical: int = 0, open_high: int = 0) -> int:
    """Halving curve plus the critical/high ceilings; always 0..100."""
    value = 100.0 * (REPEAT_DECAY ** (max(0.0, penalty) / HALF_LIFE))
    if open_critical >= 2:
        value = min(value, float(CEILING_MANY_CRITICAL))
    elif open_critical == 1:
        value = min(value, float(CEILING_ONE_CRITICAL))
    elif open_high > 0:
        value = min(value, float(CEILING_ANY_HIGH))
    return int(round(max(0.0, min(100.0, value))))


# --------------------------------------------------------------------------- reading the database


def _counted_rows(conn: sqlite3.Connection) -> list[dict] | None:
    """(finding_id, severity, status, n) for everything that still counts; None if no table yet."""
    placeholders = ",".join("?" for _ in COUNTED_STATUSES)
    try:
        rows = _query(
            conn,
            f"SELECT finding_id, severity, status, COUNT(*) AS n FROM findings "
            f"WHERE status IN ({placeholders}) GROUP BY finding_id, severity, status",
            COUNTED_STATUSES,
        )
    except sqlite3.OperationalError:
        logger.warning("findings table missing; reporting score 100")
        return None
    return [
        {"finding_id": str(r["finding_id"]), "severity": str(r["severity"]),
         "status": str(r["status"]), "n": int(r["n"])}
        for r in rows
    ]


def _grouped(rows: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["finding_id"], []).append(row)
    return groups


def _open_counts(rows: list[dict]) -> tuple[int, int]:
    """(open criticals, open highs) — what the ceilings key off."""
    crit = sum(r["n"] for r in rows if r["status"] == "open" and r["severity"] == "critical")
    high = sum(r["n"] for r in rows if r["status"] == "open" and r["severity"] == "high")
    return crit, high


def _penalties(groups: dict[str, list[dict]]) -> dict[str, float]:
    return {
        fid: group_penalty([(slot_weight(r["severity"], r["status"]), r["n"]) for r in rows])
        for fid, rows in groups.items()
    }


def security_score(conn: sqlite3.Connection) -> int:
    """0-100. See the module docstring for the formula."""
    rows = _counted_rows(conn)
    if rows is None:
        return 100
    if not rows:
        return 100
    penalty = sum(_penalties(_grouped(rows)).values())
    crit, high = _open_counts(rows)
    return score_from_penalty(penalty, open_critical=crit, open_high=high)


def grade(score: int) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


# --------------------------------------------------------------------------- explaining the number

# A possessive goes with its placeholder ("from {name}'s address" -> "from address", not "from 's").
_PLACEHOLDER = re.compile(r"\{[^{}]*\}(?:'s\b)?")
_PARENTHETICAL = re.compile(r"\s*\([^()]*\{[^{}]*\}[^()]*\)")
_TRAILING_JUNK = re.compile(r"[\s:,;\-–—]+$")
_DANGLING_WORD = re.compile(r"\s+(on|for|in|at|to|of|from|with|by)$", re.IGNORECASE)


def generic_title(finding_id: str, fallback: str = "") -> str:
    """The catalog title with its per-instance details removed.

    A breakdown row covers many findings at once, so "Outdated app: Firefox 141 (available 143)"
    would name one arbitrary app; this turns the catalog template into "Outdated app".
    """
    spec = _catalog.get(finding_id) if _catalog is not None else None
    template = getattr(spec, "title", None) or fallback
    if not template:
        return finding_id
    text = _PARENTHETICAL.sub("", str(template))
    text = _PLACEHOLDER.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = _TRAILING_JUNK.sub("", text)
    text = _DANGLING_WORD.sub("", text)
    text = _TRAILING_JUNK.sub("", text).strip()
    return text or (fallback or finding_id)


def _sample_titles(conn: sqlite3.Connection) -> dict[str, str]:
    """One concrete title per finding_id — used verbatim when a type has a single finding."""
    placeholders = ",".join("?" for _ in COUNTED_STATUSES)
    try:
        rows = _query(
            conn,
            f"SELECT finding_id, title FROM findings WHERE status IN ({placeholders}) "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC",
            COUNTED_STATUSES,
        )
    except sqlite3.OperationalError:
        return {}
    out: dict[str, str] = {}
    for row in rows:
        out.setdefault(str(row["finding_id"]), str(row["title"] or ""))
    return out


def _group_title(conn: sqlite3.Connection, finding_id: str, count: int, sample: str) -> str:
    """:func:`generic_title`, except that a WIN-PER-* group holding changed entries says so: a
    familiar autostart entry whose command was swapped must not be summed up as "new"."""
    generic = generic_title(finding_id, sample)
    if not finding_id.startswith("WIN-PER-") or _catalog is None:
        return generic
    placeholders = ",".join("?" for _ in COUNTED_STATUSES)
    try:
        found = _query(conn, f"SELECT count(*) AS n FROM findings WHERE finding_id=? AND status IN ({placeholders}) "
                             "AND json_extract(evidence, '$.change') = 'modified'", (finding_id, *COUNTED_STATUSES))
        changed = int(found[0]["n"] or 0) if found else 0
    except sqlite3.Error:
        return generic
    if not changed:
        return generic
    spec = _catalog.spec_for(finding_id, {"change": "modified"}) if hasattr(_catalog, "spec_for") else None
    changed_title = generic_title(finding_id, "")
    if spec is not None:
        text = _PARENTHETICAL.sub("", str(spec.title))
        text = re.sub(r"\s+", " ", _PLACEHOLDER.sub("", text)).strip()
        changed_title = _TRAILING_JUNK.sub("", _DANGLING_WORD.sub("", _TRAILING_JUNK.sub("", text))).strip() or generic
    return changed_title if changed >= count else f"{generic} or changed ({changed} changed)"


def _worst_severity(rows: list[dict]) -> str:
    order = ("critical", "high", "medium", "low", "info")
    present = [r["severity"] for r in rows if r["severity"] in order]
    return min(present, key=order.index) if present else "info"


def score_breakdown(conn: sqlite3.Connection) -> list[dict]:
    """"What is costing you the most points", worst first.

    One entry per finding type::

        {"finding_id": "WIN-UPD-004", "title": "Outdated high-risk app", "count": 5,
         "penalty": 23.2, "score_gain": 12, "severity": "high", "open": 5, "acknowledged": 0}

    ``penalty`` is the raw contribution to the total; ``score_gain`` is what the score would
    actually rise by if every finding of that type were fixed — the number the dashboard should
    show, because the curve is not linear and clearing the last open critical lifts a ceiling too.
    """
    rows = _counted_rows(conn)
    if not rows:
        return []
    groups = _grouped(rows)
    penalties = _penalties(groups)
    total = sum(penalties.values())
    crit, high = _open_counts(rows)
    current = score_from_penalty(total, open_critical=crit, open_high=high)
    titles = _sample_titles(conn)

    out: list[dict] = []
    for finding_id, group in groups.items():
        penalty = penalties[finding_id]
        n_open = sum(r["n"] for r in group if r["status"] == "open")
        n_ack = sum(r["n"] for r in group if r["status"] == "acknowledged")
        without_crit, without_high = _open_counts([r for r in rows if r["finding_id"] != finding_id])
        gain = score_from_penalty(total - penalty, open_critical=without_crit, open_high=without_high) - current
        sample = titles.get(finding_id, "")
        count = n_open + n_ack
        out.append({
            "finding_id": finding_id,
            "title": sample if (count == 1 and sample) else _group_title(conn, finding_id, count, sample),
            "count": count,
            "penalty": round(penalty, 1),
            "score_gain": max(0, gain),
            "severity": _worst_severity(group),
            "open": n_open,
            "acknowledged": n_ack,
        })
    out.sort(key=lambda d: (-d["penalty"], -d["count"], d["finding_id"]))
    return out


def score_detail(conn: sqlite3.Connection) -> dict:
    """Everything a dashboard or the summary page needs in one call."""
    rows = _counted_rows(conn) or []
    penalty = sum(_penalties(_grouped(rows)).values())
    crit, high = _open_counts(rows)
    value = score_from_penalty(penalty, open_critical=crit, open_high=high) if rows else 100
    return {
        "score": value,
        "grade": grade(value),
        "penalty": round(penalty, 1),
        "open_critical": crit,
        "open_high": high,
        "breakdown": score_breakdown(conn),
    }


# --------------------------------------------------------------------------- history


def trend(conn: sqlite3.Connection, days: int = 30) -> list[list]:
    """[[YYYY-MM-DD, score], ...] oldest first, one point per day (the day's last sample)."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%S")
    try:
        rows = _query(conn, "SELECT ts, value FROM metrics WHERE name='score' AND ts>=? ORDER BY ts", (cutoff,))
    except sqlite3.OperationalError:
        return []
    per_day: dict[str, int] = {}
    for row in rows:
        day = str(row["ts"])[:10]
        per_day[day] = int(round(float(row["value"])))
    return [[day, per_day[day]] for day in sorted(per_day)]


def record_score(conn: sqlite3.Connection) -> int:
    """Helper for the hourly 'score' scheduler job; uses db.record_metric when P1 is present."""
    value = security_score(conn)
    try:
        from homesoc.db import record_metric

        record_metric(conn, "score", float(value))
    except ImportError:  # pragma: no cover
        from datetime import datetime as _dt

        ts = _dt.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        conn.execute("INSERT INTO metrics(ts, name, value, tags) VALUES (?, 'score', ?, NULL)", (ts, float(value)))
        conn.commit()
    return value
