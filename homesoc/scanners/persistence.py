"""Autostart / persistence inventory with baselining (SPEC 6.9).

``ps/persistence.ps1`` lists Run/RunOnce values, Startup-folder items, non-Microsoft scheduled tasks
and Auto-start services with non-Windows binaries. The first run stores everything as baseline;
later runs insert newcomers with ``baseline=0`` and emit WIN-PER-001/002/003 for them.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import ScanResult
from homesoc.scanners.host_windows import PS_DIR, Collector, as_list, cfg_get, is_denied, run_ps_json, write_checks  # noqa: F401 - re-exported helpers
from homesoc.util import age_seconds, is_windows, json_dumps, utcnow_iso

if TYPE_CHECKING:  # pragma: no cover
    from homesoc.config import Config

logger = logging.getLogger(__name__)

PERSISTENCE_TIMEOUT_SEC = 180
# SPEC-GAP: how long a non-baseline entry keeps re-emitting its finding is unspecified. Seven days
# keeps the alert visible across several scheduler runs without reopening findings forever.
REEMIT_WINDOW_SEC = 7 * 86400

KINDS = ("run_key", "startup_folder", "scheduled_task", "service")
FINDING_FOR_KIND = {
    "run_key": "WIN-PER-001",
    "startup_folder": "WIN-PER-001",
    "scheduled_task": "WIN-PER-002",
    "service": "WIN-PER-003",
}
CHECK_FOR_FINDING = {
    "WIN-PER-001": ("no new autostart entries", ("run_key", "startup_folder")),
    "WIN-PER-002": ("no new scheduled tasks", ("scheduled_task",)),
    "WIN-PER-003": ("no new services", ("service",)),
}


@dataclass(frozen=True)
class Entry:
    kind: str
    name: str
    location: str
    command: str | None
    extra: dict[str, Any]

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.kind, self.location, self.name)


# --------------------------------------------------------------------------- collection


def collect(cfg: Config | None = None) -> dict[str, Any]:
    """Raw probe JSON, or ``{"error": ...}``."""
    if not is_windows():
        return {"error": "not windows"}
    res = run_ps_json(PS_DIR / "persistence.ps1", timeout=PERSISTENCE_TIMEOUT_SEC)
    if res.data is None:
        return {"error": res.error or "no data"}
    return res.data


def normalize(raw: dict[str, Any]) -> list[Entry]:
    """Flatten the four probe sections into Entry records keyed by (kind, location, name)."""
    out: list[Entry] = []
    for r in as_list(raw.get("run_keys")):
        if isinstance(r, dict) and r.get("name"):
            out.append(Entry("run_key", str(r["name"]), str(r.get("key") or r.get("hive") or "Run"), _text(r.get("command")), {"hive": r.get("hive")}))
    for s in as_list(raw.get("startup")):
        if isinstance(s, dict) and s.get("name"):
            cmd = " ".join(x for x in (_text(s.get("target")), _text(s.get("arguments"))) if x) or None
            out.append(Entry("startup_folder", str(s["name"]), str(s.get("folder") or s.get("scope") or "Startup"), cmd, {"scope": s.get("scope"), "modified": s.get("modified")}))
    for t in as_list(raw.get("tasks")):
        if isinstance(t, dict) and t.get("name"):
            out.append(Entry("scheduled_task", str(t["name"]), str(t.get("path") or "\\"), _text(t.get("command")), {"author": t.get("author"), "state": t.get("state"), "run_level": t.get("run_level"), "user": t.get("user")}))
    for s in as_list(raw.get("services")):
        if isinstance(s, dict) and s.get("name"):
            out.append(Entry("service", str(s["name"]), "services", _text(s.get("path")), {"display": s.get("display"), "state": s.get("state"), "start_mode": s.get("start_mode"), "account": s.get("account"), "source": s.get("source")}))
    # De-duplicate on the unique key so a probe glitch cannot violate the table constraint.
    seen: set[tuple[str, str, str]] = set()
    unique: list[Entry] = []
    for e in out:
        if e.key not in seen:
            seen.add(e.key)
            unique.append(e)
    return unique


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:2000] if text else None


# --------------------------------------------------------------------------- reconcile


@dataclass
class Reconciled:
    new: list[Entry]
    known: int
    baseline_run: bool
    reemit: list[dict[str, Any]]  # rows still un-baselined and inside the re-emit window


def reconcile(conn: Any, entries: list[Entry], *, baseline_enabled: bool = True) -> Reconciled:
    """Persist entries and work out which are new relative to the stored inventory.

    The very first run (empty table) is the baseline: everything is stored with ``baseline=1`` and
    nothing is reported. When alerting is disabled via config every run behaves like a baseline.
    """
    now = utcnow_iso()
    existing_count = db.one(conn, "SELECT COUNT(*) AS n FROM persistence")
    first_run = int(existing_count["n"] if existing_count else 0) == 0
    baseline_run = first_run or not baseline_enabled
    known_keys = {(r["kind"], r["location"], r["name"]) for r in db.query(conn, "SELECT kind, location, name FROM persistence")}

    new: list[Entry] = []
    inserts: list[tuple] = []
    updates: list[tuple] = []
    for e in entries:
        if e.key in known_keys:
            updates.append((e.command, now, e.kind, e.location, e.name))
        else:
            inserts.append((e.kind, e.name, e.command, e.location, now, now, 1 if baseline_run else 0))
            if not baseline_run:
                new.append(e)
    if inserts:
        db.writemany(conn, "INSERT OR IGNORE INTO persistence(kind, name, command, location, first_seen, last_seen, baseline) VALUES (?, ?, ?, ?, ?, ?, ?)", inserts)
    if updates:
        db.writemany(conn, "UPDATE persistence SET command = ?, last_seen = ? WHERE kind = ? AND location = ? AND name = ?", updates)
    if first_run and inserts:
        db.set_setting(conn, "persistence.baseline_at", now)

    reemit: list[dict[str, Any]] = []
    if not baseline_run:
        present = {e.key for e in entries}
        for r in db.query(conn, "SELECT kind, name, location, command, first_seen FROM persistence WHERE baseline = 0"):
            key = (r["kind"], r["location"], r["name"])
            age = age_seconds(r["first_seen"])
            if key in present and age is not None and age <= REEMIT_WINDOW_SEC:
                reemit.append(dict(r))
    return Reconciled(new=new, known=len(updates), baseline_run=baseline_run, reemit=reemit)


def promote_to_baseline(conn: Any) -> int:
    """Accept every current entry as known (used by the dashboard's "mark all as known")."""
    return db.write(conn, "UPDATE persistence SET baseline = 1 WHERE baseline = 0") or 0


# --------------------------------------------------------------------------- findings


def build_findings(reemit_rows: list[dict[str, Any]], errors: dict[str, Any], c: Collector, entries_by_key: dict[tuple[str, str, str], Entry] | None = None) -> None:
    """WIN-PER-* checks (one row per ID) and one finding per new entry (dedupe key = kind:location:name)."""
    entries_by_key = entries_by_key or {}
    grouped: dict[str, list[dict[str, Any]]] = {fid: [] for fid in CHECK_FOR_FINDING}
    for r in reemit_rows:
        fid = FINDING_FOR_KIND.get(str(r.get("kind")))
        if fid:
            grouped[fid].append(r)
    denied_sections = {k for k, v in (errors or {}).items() if is_denied(v)}
    for fid, (expected, kinds) in CHECK_FOR_FINDING.items():
        rows = grouped[fid]
        section_denied = ("tasks" in denied_sections and "scheduled_task" in kinds) or ("services" in denied_sections and "service" in kinds)
        if rows:
            c.check(fid, "fail", f"{len(rows)} new: " + ", ".join(str(r.get("name")) for r in rows[:8]) + (" ..." if len(rows) > 8 else ""), expected)
            for r in rows:
                entry = entries_by_key.get((r["kind"], r["location"], r["name"]))
                ev = {"kind": r["kind"], "name": r["name"], "location": r["location"], "command": r.get("command"), "first_seen": r.get("first_seen")}
                if entry:
                    ev.update({k: v for k, v in entry.extra.items() if v not in (None, "")})
                c.finding(fid, ev, key=f"{r['kind']}:{r['location']}:{r['name']}", detail=f"{r['kind']} '{r['name']}' -> {r.get('command') or '?'}")
        elif section_denied:
            c.denied(fid, expected)
        else:
            c.ok(fid, "none", expected)


# --------------------------------------------------------------------------- scanner entry point


def run(cfg: Config, conn: Any, *, quick: bool = False, progress: Callable[[str], None] | None = None) -> ScanResult:
    """Scanner interface (SPEC 6): inventory autostarts, baseline on first run, alert on newcomers."""
    started = time.monotonic()
    notify = progress or (lambda _msg: None)
    if not is_windows():
        return ScanResult("host", [], {"skipped": "not windows"}, error="persistence scanner runs on Windows only")

    notify("persistence: enumerating autostart entries")
    raw = collect(cfg)
    if raw.get("error"):
        db.record_event(conn, "warning", "persistence", f"persistence probe failed: {raw['error']}")
        return ScanResult("host", [], {"duration_sec": round(time.monotonic() - started, 2)}, error=str(raw["error"]))

    entries = normalize(raw)
    errors = raw.get("errors") if isinstance(raw.get("errors"), dict) else {}
    if not entries and errors:
        # Every section failed: do not create an empty baseline that would flag everything next time.
        return ScanResult("host", [], {"duration_sec": round(time.monotonic() - started, 2), "errors": errors}, error="persistence probe returned no entries")

    rec = reconcile(conn, entries, baseline_enabled=bool(cfg_get(cfg, "host.persistence_baseline", True)))
    c = Collector()
    build_findings(rec.reemit, errors, c, {e.key: e for e in entries})
    write_checks(conn, c.checks)
    db.set_setting(conn, "persistence.checked_at", utcnow_iso())
    db.set_setting(conn, "persistence.errors_json", json_dumps(errors))
    summary = c.summary()
    summary.update({
        "duration_sec": round(time.monotonic() - started, 2),
        "entries": len(entries),
        "new": len(rec.new),
        "known": rec.known,
        "baseline_run": rec.baseline_run,
        "by_kind": {k: sum(1 for e in entries if e.kind == k) for k in KINDS},
        "findings": len(c.findings),
    })
    notify(f"persistence: {len(entries)} entries, {len(rec.new)} new" + (" (baseline stored)" if rec.baseline_run else ""))
    return ScanResult("host", c.findings, summary, error="; ".join(f"{k}: {v}" for k, v in errors.items()) or None)


__all__ = [
    "Entry",
    "FINDING_FOR_KIND",
    "KINDS",
    "Reconciled",
    "build_findings",
    "collect",
    "normalize",
    "promote_to_baseline",
    "reconcile",
    "run",
]
