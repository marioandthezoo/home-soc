"""Findings engine: turns scanner drafts into durable rows with a lifecycle.

Scanners are stateless and re-emit the same finding on every run; this module owns the memory:
the same finding is one row that accumulates occurrences, a fixed problem resolves itself when it
stops being reported, and a user's acknowledge/suppress decision survives rescans.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from homesoc.findings import catalog

logger = logging.getLogger(__name__)

STATUSES: tuple[str, ...] = ("open", "acknowledged", "resolved", "suppressed")
SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# --- core helpers (P1) with local fallbacks so this package tests standalone -------------------
try:  # pragma: no cover - exercised only when P1 is present
    from homesoc.db import one as _one
    from homesoc.db import query as _query
    from homesoc.db import write as _write
except ImportError:  # pragma: no cover
    _lock = threading.Lock()

    def _write(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> int:
        with _lock:
            cur = conn.execute(sql, tuple(params))
            conn.commit()
            return int(cur.lastrowid or 0)

    def _query(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return list(conn.execute(sql, tuple(params)).fetchall())

    def _one(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        return conn.execute(sql, tuple(params)).fetchone()

try:  # pragma: no cover
    from homesoc.util import utcnow_iso as _now
except ImportError:  # pragma: no cover

    def _now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


#: The "new device on the network" finding — the one a first discovery raises for every device the
#: household already owns, and the one the baseline operation below exists to clear.
NEW_DEVICE_FINDING_ID = "NET-DEV-001"
BASELINE_NOTE = "accepted as part of the baseline inventory"
TRUST_NOTE = "device marked trusted"


@dataclass
class ApplyResult:
    new: list[dict] = field(default_factory=list)
    reopened: list[dict] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    updated: int = 0


@dataclass
class BaselineResult:
    """What ``baseline_devices`` did (or, with ``dry_run``, would have done)."""

    devices_total: int = 0
    trusted: list[dict] = field(default_factory=list)        # devices this run marked trusted
    already_trusted: list[dict] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)       # NET-DEV-001 rows closed
    dry_run: bool = False


def dedupe_key(draft: Any) -> str:
    """Identity of a finding: id + subject, plus evidence['key'] when a subject can carry several
    distinct instances (one threat name, one CVE, one autostart entry)."""
    key = f"{draft.finding_id}|{draft.subject}"
    evidence = getattr(draft, "evidence", None) or {}
    extra = evidence.get("key") if isinstance(evidence, dict) else None
    if extra not in (None, ""):
        key += f"|{extra}"
    return key


# A lone surrogate cannot be encoded as UTF-8, so SQLite refuses the whole INSERT and the finding
# is lost. Title and detail are cleaned by the catalog; the subject and the dedupe key (which can
# carry evidence['key'], sometimes device text) are cleaned here, of that one character class only.
_LONE_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _storable(text: Any) -> str:
    return _LONE_SURROGATE.sub("?", str(text))


def _row_to_dict(row: sqlite3.Row | None) -> dict:
    if row is None:
        return {}
    d = dict(row) if not isinstance(row, dict) else dict(row)
    raw = d.get("evidence")
    if isinstance(raw, str):
        try:
            d["evidence"] = json.loads(raw)
        except ValueError:
            d["evidence"] = {"raw": raw}
    elif raw is None:
        d["evidence"] = {}
    spec = catalog.get(d.get("finding_id", ""))
    d["category"] = spec.category if spec else "unknown"
    d["rationale"] = (catalog.render_why(d.get("finding_id", ""), d["evidence"], d.get("subject", "")) or spec.rationale) if spec else ""
    d["refs"] = list(spec.refs) if spec else []
    d["remediation"] = catalog.render_remediation(d.get("finding_id", ""), d["evidence"], d.get("subject", ""))
    return d


def _fetch(conn: sqlite3.Connection, row_id: int) -> dict:
    return _row_to_dict(_one(conn, "SELECT * FROM findings WHERE id=?", (row_id,)))


def _event(conn: sqlite3.Connection, row_id: int, event: str, note: str | None = None) -> None:
    _write(
        conn,
        "INSERT INTO finding_events(finding_row_id, event, at, note) VALUES (?,?,?,?)",
        (row_id, event, _now(), note),
    )


def _evidence_json(draft: Any) -> str:
    evidence = getattr(draft, "evidence", None) or {}
    try:
        return json.dumps(evidence, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return json.dumps({"raw": str(evidence)})


def apply(conn: sqlite3.Connection, drafts: list[Any], source: str, *,
          scope: str | Iterable[str] | None = None) -> ApplyResult:
    """Upsert drafts by dedupe_key and, within scope, auto-resolve what this source stopped reporting.

    ``scope`` may be one prefix or several (SPEC-GAP: a service scan knows exactly which devices it
    finished, so it passes one ``device:<mac>`` per completed device instead of a blanket ``device:``).
    A scope ending in ":" is a raw prefix; any other scope matches the subject itself and its
    ``<scope>:...`` children, so ``ip:10.0.0.5`` never swallows ``ip:10.0.0.50``.
    """
    result = ApplyResult()
    now = _now()
    seen: set[str] = set()
    for draft in drafts:
        key = _storable(dedupe_key(draft))
        if key in seen:
            # SPEC-GAP: a scanner emitting the same key twice in one run counts once; first draft wins.
            continue
        seen.add(key)
        _apply_one(conn, draft, key, source, now, result)

    scopes = [scope] if isinstance(scope, str) else list(scope or [])
    for one_scope in scopes:
        _auto_resolve(conn, source, one_scope, seen, now, result)
    logger.info(
        "findings.apply source=%s scope=%s new=%d reopened=%d resolved=%d updated=%d",
        source, scope, len(result.new), len(result.reopened), len(result.resolved), result.updated,
    )
    return result


def _apply_one(conn: sqlite3.Connection, draft: Any, key: str, source: str, now: str, result: ApplyResult) -> None:
    title, detail = catalog.render(draft)
    severity = catalog.severity_for(draft)
    evidence = _evidence_json(draft)
    device_id = getattr(draft, "device_id", None)
    existing = _one(conn, "SELECT id, status FROM findings WHERE dedupe_key=?", (key,))

    if existing is None:
        row_id = _write(
            conn,
            "INSERT INTO findings(finding_id, subject, dedupe_key, severity, title, detail, evidence, status, "
            "source, first_seen, last_seen, occurrences, device_id) VALUES (?,?,?,?,?,?,?,'open',?,?,?,1,?)",
            (draft.finding_id, _storable(draft.subject), key, severity, title, detail, evidence, source, now, now, device_id),
        )
        _event(conn, row_id, "opened")
        result.new.append(_fetch(conn, row_id))
        return

    row_id, status = int(existing["id"]), str(existing["status"])
    reopen = status == "resolved"
    # A row the engine auto-resolved from "acknowledged" comes back acknowledged: a device that was
    # merely asleep for one scan must not discard the user's decision.
    restored = _previous_status_if_auto_resolved(conn, row_id) if reopen else None
    new_status = restored or "open"
    _write(
        conn,
        "UPDATE findings SET last_seen=?, occurrences=occurrences+1, evidence=?, title=?, detail=?, severity=?, "
        "source=?, device_id=COALESCE(?, device_id), status=CASE WHEN status='resolved' THEN ? ELSE status END, "
        "resolved_at=CASE WHEN status='resolved' THEN NULL ELSE resolved_at END WHERE id=?",
        (now, evidence, title, detail, severity, source, device_id, new_status, row_id),
    )
    if reopen:
        _event(conn, row_id, "reopened", f"restored {restored}" if restored else None)
        result.reopened.append(_fetch(conn, row_id))
    else:
        # open/acknowledged refresh silently; suppressed stays suppressed but keeps a live last_seen.
        result.updated += 1


_AUTO_NOTE_PREFIX = "was:"


def _previous_status_if_auto_resolved(conn: sqlite3.Connection, row_id: int) -> str | None:
    last = _one(conn, "SELECT event, note FROM finding_events WHERE finding_row_id=? ORDER BY id DESC LIMIT 1", (row_id,))
    if last is None or str(last["event"]) != "auto_resolved":
        return None
    note = str(last["note"] or "")
    if note.startswith(_AUTO_NOTE_PREFIX) and note[len(_AUTO_NOTE_PREFIX):] == "acknowledged":
        return "acknowledged"
    return None


def _auto_resolve(conn, source: str, scope: str, seen: set[str], now: str, result: ApplyResult) -> None:
    # substr() instead of LIKE so '%' or '_' in a subject cannot widen the match.
    if scope.endswith(":"):
        where, params = "substr(subject,1,?)=?", [len(scope), scope]
    else:
        child = scope + ":"
        where, params = "(subject=? OR substr(subject,1,?)=?)", [scope, len(child), child]
    rows = _query(
        conn,
        f"SELECT id, dedupe_key, status FROM findings WHERE source=? AND {where} AND status IN ('open','acknowledged')",
        [source, *params],
    )
    # SPEC-GAP: suppressed findings are left alone on auto-resolve (a user decision should not be undone by a rescan).
    for row in rows:
        if row["dedupe_key"] in seen:
            continue
        _write(conn, "UPDATE findings SET status='resolved', resolved_at=? WHERE id=?", (now, row["id"]))
        _event(conn, int(row["id"]), "auto_resolved", f"{_AUTO_NOTE_PREFIX}{row['status']}")
        result.resolved.append(_fetch(conn, int(row["id"])))


def set_status(conn: sqlite3.Connection, row_id: int, status: str, note: str | None = None) -> None:
    """User-driven transition; 'open' from the dashboard is a manual reopen."""
    if status not in STATUSES:
        raise ValueError(f"invalid status {status!r}")
    if _one(conn, "SELECT 1 FROM findings WHERE id=?", (row_id,)) is None:
        raise KeyError(f"finding row {row_id} does not exist")
    now = _now()
    resolved_at = now if status == "resolved" else None
    _write(conn, "UPDATE findings SET status=?, resolved_at=? WHERE id=?", (status, resolved_at, row_id))
    _event(conn, row_id, "reopened" if status == "open" else status, note)


def list_findings(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    severity: str | None = None,
    subject_prefix: str | None = None,
    limit: int = 500,
) -> list[dict]:
    sql = "SELECT * FROM findings WHERE 1=1"
    params: list[Any] = []
    if status:
        sql += " AND status=?"
        params.append(status)
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if subject_prefix:
        sql += " AND substr(subject,1,?)=?"
        params.extend([len(subject_prefix), subject_prefix])
    sql += (
        " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,"
        " last_seen DESC LIMIT ?"
    )
    params.append(int(limit))
    return [_row_to_dict(r) for r in _query(conn, sql, params)]


def counts(conn: sqlite3.Connection) -> dict:
    """Every status x severity cell is present (zero-filled) so the dashboard never KeyErrors."""
    out: dict[str, dict[str, int]] = {s: {sev: 0 for sev in SEVERITY_RANK} for s in STATUSES}
    for row in _query(conn, "SELECT status, severity, COUNT(*) AS n FROM findings GROUP BY status, severity"):
        out.setdefault(row["status"], {sev: 0 for sev in SEVERITY_RANK})[row["severity"]] = int(row["n"])
    return out


def events(conn: sqlite3.Connection, row_id: int, limit: int = 50) -> list[dict]:
    rows = _query(
        conn,
        "SELECT id, event, at, note FROM finding_events WHERE finding_row_id=? ORDER BY id DESC LIMIT ?",
        (row_id, int(limit)),
    )
    return [dict(r) for r in rows]


# --------------------------------------------------------------- baseline / trusted devices
#
# The first discovery on a network that already has 23 devices raises 23 "new device" findings:
# the user is told their own television is an intruder, the dashboard is unreadable and the score
# is wrecked. Fresh installs mark that first sweep as a baseline, but an install that already ran
# has no way back. These helpers are that way back, and the web layer can offer them as a button.
#
# SPEC-GAP: `devices` is owned by scanners.discovery (spec section 4) and findings may not import
# scanners (section 18), so the trusted flag is written here directly — one column the scanner
# never sets, exactly as the dashboard already does when the user ticks "Trusted".


def _device_row(conn: sqlite3.Connection, device_id: int) -> dict | None:
    row = _one(conn, "SELECT id, mac, ip, hostname, nickname, vendor, trusted FROM devices WHERE id=?", (device_id,))
    return dict(row) if row is not None else None


def device_label(device: dict) -> str:
    """What to call a device in a summary line: the friendliest name it has."""
    for key in ("nickname", "hostname", "ip", "mac"):
        value = device.get(key)
        if value:
            return str(value)
    return f"device {device.get('id')}"


def new_device_findings(conn: sqlite3.Connection, device_id: int | None = None) -> list[dict]:
    """Unfinished NET-DEV-001 rows, for one device or for every device."""
    sql = ("SELECT * FROM findings WHERE finding_id=? AND status IN ('open','acknowledged')")
    params: list[Any] = [NEW_DEVICE_FINDING_ID]
    if device_id is not None:
        device = _device_row(conn, int(device_id))
        # Match the row's device_id, and also its subject, so a finding written before the device
        # row existed (or by an older version that left device_id NULL) is still found.
        sql += " AND (device_id=? OR subject=?)"
        params.extend([int(device_id), f"device:{device['mac']}" if device else ""])
    return [_row_to_dict(r) for r in _query(conn, sql + " ORDER BY id", params)]


def accept_new_device_findings(conn: sqlite3.Connection, device_id: int | None = None, *,
                               note: str = BASELINE_NOTE, dry_run: bool = False) -> list[dict]:
    """Resolve the outstanding "new device" findings — the user says "yes, that one is mine".

    Goes through ``set_status`` so every closed row keeps an event trail explaining *why* it
    closed, instead of silently vanishing from the dashboard.
    """
    rows = new_device_findings(conn, device_id)
    if dry_run:
        return rows
    closed: list[dict] = []
    for row in rows:
        try:
            set_status(conn, int(row["id"]), "resolved", note=note)
        except (KeyError, ValueError, sqlite3.Error):
            logger.exception("could not resolve %s row %s", NEW_DEVICE_FINDING_ID, row.get("id"))
            continue
        closed.append(_fetch(conn, int(row["id"])))
    return closed


def trust_device(conn: sqlite3.Connection, device_id: int, trusted: bool = True, *,
                 note: str = TRUST_NOTE) -> list[dict]:
    """Set (or clear) a device's trusted flag; trusting answers its "new device" question.

    Returns the findings that were resolved as a result, so a caller can report them.
    """
    if _device_row(conn, int(device_id)) is None:
        raise KeyError(f"device {device_id} does not exist")
    _write(conn, "UPDATE devices SET trusted=? WHERE id=?", (1 if trusted else 0, int(device_id)))
    if not trusted:
        return []
    return accept_new_device_findings(conn, int(device_id), note=note)


def baseline_devices(conn: sqlite3.Connection, *, trust_all: bool = True,
                     dry_run: bool = False, note: str = BASELINE_NOTE) -> BaselineResult:
    """Accept every device currently in the inventory as "already mine".

    Marks them trusted (unless ``trust_all=False``) and resolves their outstanding NET-DEV-001
    findings with a clear event, so from then on only genuinely new devices raise an alert.
    ``dry_run`` reports exactly what would change and writes nothing.
    """
    devices = [dict(r) for r in _query(
        conn, "SELECT id, mac, ip, hostname, nickname, vendor, trusted FROM devices ORDER BY id")]
    result = BaselineResult(devices_total=len(devices), dry_run=bool(dry_run))

    for device in devices:
        if bool(device.get("trusted")):
            result.already_trusted.append(device)
        elif trust_all:
            if not dry_run:
                _write(conn, "UPDATE devices SET trusted=1 WHERE id=?", (int(device["id"]),))
            result.trusted.append(device)

    # Every unfinished NET-DEV-001 row, including any whose device row has since been removed.
    result.resolved = accept_new_device_findings(conn, None, note=note, dry_run=dry_run)
    logger.info("findings.baseline devices=%d trusted=%d resolved=%d dry_run=%s",
                result.devices_total, len(result.trusted), len(result.resolved), dry_run)
    return result
