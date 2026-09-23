"""Autostart / persistence inventory with baselining (SPEC 6.9).

``ps/persistence.ps1`` lists Run/RunOnce values, Startup-folder items, scheduled tasks outside the
``\\Microsoft\\`` task folder and Auto-start services. The first run stores everything as baseline;
later runs insert newcomers with ``baseline=0`` and emit WIN-PER-001/002/003 for them.

Security properties (second security round):

- An entry is identified by (kind, location, name), but its *command* is compared too. A known entry
  whose command changes (a repointed Run value, a task whose action was swapped) is treated as a
  possible hijack until the owner accepts it: it goes back to ``baseline=0`` and is reported under its
  own dedupe key (``...:changed:<digest>``), with the previous command kept in the evidence.
- Every un-reviewed entry that is still present keeps being re-emitted. There is no time window after
  which a live, never-accepted entry silently turns into "resolved".
- Which services count as "part of Windows" is decided here from facts the probe reports (parsed
  executable, Authenticode signer, the Windows folder), not by a string prefix. See
  :func:`is_windows_service`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import ntpath
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import ScanResult
from homesoc.scanners.host_windows import PS_DIR, Collector, as_list, cfg_get, is_denied, run_ps_json, write_checks  # noqa: F401 - re-exported helpers
from homesoc.util import is_windows, json_dumps, utcnow_iso

if TYPE_CHECKING:  # pragma: no cover
    from homesoc.config import Config

logger = logging.getLogger(__name__)

PERSISTENCE_TIMEOUT_SEC = 180
# An un-baselined entry is re-emitted for as long as it is present and not accepted. A time window
# here would let the findings engine auto-resolve a live, never-reviewed autostart entry. The engine
# only notifies on new/reopened findings, so re-emitting does not re-notify.

#: settings key holding ``{entry_id: {"previous": <command before the change>, "accepted": <was that
#: command baselined>, "changed_at": iso}}`` for entries whose command changed and that the owner has
#: not accepted yet.
CHANGES_SETTING = "persistence.changes_json"

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
    windir = raw.get("windir")
    for s in as_list(raw.get("services")):
        if isinstance(s, dict) and s.get("name") and not is_windows_service(s, windir):
            out.append(Entry("service", str(s["name"]), "services", _text(s.get("path")), {"display": s.get("display"), "state": s.get("state"), "start_mode": s.get("start_mode"), "account": s.get("account"), "source": s.get("source")}))
    # De-duplicate on the unique key so a probe glitch cannot violate the table constraint.
    seen: set[tuple[str, str, str]] = set()
    unique: list[Entry] = []
    for e in out:
        if e.key not in seen:
            seen.add(e.key)
            unique.append(e)
    return unique


# --------------------------------------------------------------------------- Windows services

#: Folders under %SystemRoot% that a standard user can write to (or that hold user-controlled data).
#: A binary there is not "part of Windows" even though its path starts with the Windows folder.
_WRITABLE_WINDIR_SUBDIRS = (
    "temp", "tasks", "tracing", "debug", "registration\\crmlog", "pla", "servicestate",
    "system32\\tasks", "system32\\tasks_migrated", "system32\\spool", "system32\\com\\dmp",
    "system32\\fxstmp", "system32\\microsoft\\crypto", "system32\\logfiles",
    "syswow64\\tasks", "syswow64\\com\\dmp", "syswow64\\fxstmp",
)
#: Signed Windows binaries that run whatever their arguments name. As a service binary they are
#: never "just Windows", whatever the arguments are.
LOLBINS = frozenset({
    "rundll32.exe", "regsvr32.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "msiexec.exe", "msbuild.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "certutil.exe", "bitsadmin.exe", "forfiles.exe", "conhost.exe",
    "schtasks.exe", "sc.exe", "wmic.exe", "cmstp.exe", "odbcconf.exe", "pcalua.exe", "hh.exe",
    "bash.exe", "wsl.exe", "curl.exe", "esentutl.exe", "msdt.exe", "control.exe", "explorer.exe",
    "presentationhost.exe", "ieexec.exe", "dnscmd.exe", "msxsl.exe", "ftp.exe", "wsreset.exe",
    "scriptrunner.exe", "syncappvpublishingserver.exe", "appvlp.exe", "cdb.exe", "dotnet.exe",
    "node.exe", "python.exe", "pythonw.exe", "java.exe", "javaw.exe",
})
_MICROSOFT_SIGNER = "o=microsoft corporation"
# A drive-letter or UNC path inside an argument string (stops at quotes, commas, separators).
_ABS_PATH_RE = re.compile(r"""(?i)(?:\b[a-z]:[\\/]|\\\\|//)[^\s"',;|]*""")


def split_command(command: str | None) -> tuple[str, str]:
    """``(executable, arguments)`` of a Windows command line: quoted, or up to the first whitespace."""
    text = (command or "").strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        if end == -1:
            return text[1:], ""
        return text[1:end], text[end + 1:].strip()
    exe, _, args = text.partition(" ")
    return exe, args.strip()


def _norm_path(path: str) -> str:
    path = (path or "").strip().strip('"')
    return ntpath.normpath(path).casefold() if path else ""


def _in_trusted_windir(path_norm: str, windir_norm: str) -> bool:
    """True when ``path_norm`` sits inside the Windows folder *and* outside its user-writable parts."""
    if not path_norm or not windir_norm or not path_norm.startswith(windir_norm + "\\"):
        return False
    rel = path_norm[len(windir_norm) + 1:]
    return not any(rel == d or rel.startswith(d + "\\") for d in _WRITABLE_WINDIR_SUBDIRS)


def is_windows_service(service: dict[str, Any], windir: str | None) -> bool:
    """True only for an Auto-start service that is demonstrably a Windows (or WHQL driver) component.

    Every condition below must hold. So a path that merely *starts with* the Windows folder name
    (``C:\\WindowsUpdate\\x.exe``), a user-writable folder under it (``C:\\Windows\\Temp``), a
    Microsoft-signed script host with attacker arguments (``rundll32.exe C:\\Users\\x\\evil.dll,Run``)
    or an unsigned binary dropped into System32 is still inventoried:

    - the probe reported the service from WMI, together with the Windows folder;
    - the executable (quoted or unquoted) normalises to a path inside the Windows folder, after a path
      separator, and outside the user-writable subfolders;
    - the probe saw a *valid* Authenticode signature issued to Microsoft Corporation on that same
      executable (Windows itself, and WHQL-signed driver services in DriverStore);
    - the executable is not a known living-off-the-land binary;
    - the arguments name no path outside the trusted part of the Windows folder, no parent-directory
      hop, no URL and no unexpanded environment variable.

    Anything missing (an older probe, a failed signature check) means "not Windows": the service is
    listed and baselined rather than hidden.
    """
    if not isinstance(service, dict) or service.get("source") != "wmi":
        return False
    windir_norm = _norm_path(str(windir or ""))
    if not windir_norm or windir_norm.startswith("\\\\"):
        return False
    exe, args = split_command(_text(service.get("path")))
    exe_norm = _norm_path(exe)
    if not _in_trusted_windir(exe_norm, windir_norm):
        return False
    if _norm_path(str(service.get("exe") or "")) != exe_norm:
        return False  # the signature the probe checked belongs to some other file
    if _MICROSOFT_SIGNER not in str(service.get("signer") or "").casefold():
        return False
    if ntpath.basename(exe_norm) in LOLBINS:
        return False
    if "%" in args or "://" in args or ".." in args:
        return False
    return all(_in_trusted_windir(_norm_path(m.group(0)), windir_norm) for m in _ABS_PATH_RE.finditer(args))


# --------------------------------------------------------------------------- command comparison

_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)+")


def command_fingerprint(command: str | None) -> str:
    """Comparable form of a command line.

    The executable is case-folded and version-number folders are collapsed (auto-updaters move
    ``app-1.0.9003\\x.exe`` to ``app-1.0.9004\\x.exe``; whoever can write that folder could replace
    the binary in place anyway). Arguments are compared exactly apart from surrounding and repeated
    whitespace, so a changed server address or script path is a change. A UNC executable is kept
    verbatim so a changed host is seen.
    """
    exe, args = split_command(command)
    exe_norm = exe.strip().casefold()
    if not exe_norm.startswith(("\\\\", "//")):
        exe_norm = _VERSION_TOKEN_RE.sub("#", exe_norm)
    return exe_norm + "\x00" + " ".join(args.split())


def command_digest(command: str | None) -> str:
    """Short, stable digest of :func:`command_fingerprint` for use in a dedupe key."""
    return hashlib.sha1(command_fingerprint(command).encode("utf-8", "replace"), usedforsecurity=False).hexdigest()[:12]


def _entry_id(kind: str, location: str, name: str) -> str:
    return json.dumps([kind, location, name], ensure_ascii=False)


def _load_changes(conn: Any) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(db.get_setting(conn, CHANGES_SETTING, "{}") or "{}")
    except (TypeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def _save_changes(conn: Any, changes: dict[str, dict[str, Any]]) -> None:
    db.set_setting(conn, CHANGES_SETTING, json_dumps(changes))


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
    reemit: list[dict[str, Any]]  # rows still un-baselined (new or changed) and still present
    changed: list[Entry] = field(default_factory=list)  # known entries whose command changed this run


def reconcile(conn: Any, entries: list[Entry], *, baseline_enabled: bool = True) -> Reconciled:
    """Persist entries and work out which are new or changed relative to the stored inventory.

    The very first run (empty table) is the baseline: everything is stored with ``baseline=1`` and
    nothing is reported. When alerting is disabled via config every run behaves like a baseline.

    A known entry whose command changed (compared with :func:`command_fingerprint`) is set back to
    ``baseline=0`` with ``first_seen`` reset, and the command it had before is remembered under
    :data:`CHANGES_SETTING` so the finding can show both. A probe that could not read a command
    (``None``) never counts as a change and never erases the stored command.
    """
    now = utcnow_iso()
    existing_count = db.one(conn, "SELECT COUNT(*) AS n FROM persistence")
    first_run = int(existing_count["n"] if existing_count else 0) == 0
    baseline_run = first_run or not baseline_enabled
    known_rows = {
        (r["kind"], r["location"], r["name"]): dict(r)
        for r in db.query(conn, "SELECT kind, location, name, command, baseline FROM persistence")
    }
    changes = _load_changes(conn)
    changes_dirty = False

    new: list[Entry] = []
    changed: list[Entry] = []
    inserts: list[tuple] = []
    updates: list[tuple] = []
    rearms: list[tuple] = []
    restores: list[tuple] = []
    known = 0
    for e in entries:
        row = known_rows.get(e.key)
        if row is None:
            inserts.append((e.kind, e.name, e.command, e.location, now, now, 1 if baseline_run else 0))
            if not baseline_run:
                new.append(e)
            continue
        known += 1
        old = row.get("command")
        eid = _entry_id(*e.key)
        prior = changes.get(eid)
        if e.command is None:
            updates.append((old, now, e.kind, e.location, e.name))
        elif not baseline_run and old is not None and command_fingerprint(e.command) != command_fingerprint(old):
            if prior and prior.get("accepted") and command_fingerprint(e.command) == command_fingerprint(prior.get("previous")):
                # Changed back to the command the owner had accepted: the entry is known again.
                del changes[eid]
                changes_dirty = True
                restores.append((e.command, now, e.kind, e.location, e.name))
                continue
            # Keep the command from before the *first* unaccepted change: that is what the owner knew.
            changes[eid] = {
                "previous": prior.get("previous") if prior else old,
                "accepted": bool(prior.get("accepted")) if prior else bool(row.get("baseline")),
                "changed_at": now,
            }
            changes_dirty = True
            rearms.append((e.command, now, now, e.kind, e.location, e.name))
            changed.append(e)
        else:
            updates.append((e.command, now, e.kind, e.location, e.name))
    if inserts:
        db.writemany(conn, "INSERT OR IGNORE INTO persistence(kind, name, command, location, first_seen, last_seen, baseline) VALUES (?, ?, ?, ?, ?, ?, ?)", inserts)
    if updates:
        db.writemany(conn, "UPDATE persistence SET command = ?, last_seen = ? WHERE kind = ? AND location = ? AND name = ?", updates)
    if rearms:
        db.writemany(conn, "UPDATE persistence SET command = ?, last_seen = ?, first_seen = ?, baseline = 0 WHERE kind = ? AND location = ? AND name = ?", rearms)
    if restores:
        db.writemany(conn, "UPDATE persistence SET command = ?, last_seen = ?, baseline = 1 WHERE kind = ? AND location = ? AND name = ?", restores)
    if first_run and inserts:
        db.set_setting(conn, "persistence.baseline_at", now)

    pending = {
        (r["kind"], r["location"], r["name"]): dict(r)
        for r in db.query(conn, "SELECT kind, name, location, command, first_seen FROM persistence WHERE baseline = 0")
    }
    # Forget change records for entries that were accepted (baseline=1) or no longer exist.
    live_ids = {_entry_id(*k) for k in pending}
    for eid in [k for k in changes if k not in live_ids]:
        del changes[eid]
        changes_dirty = True
    if changes_dirty:
        _save_changes(conn, changes)

    reemit: list[dict[str, Any]] = []
    if not baseline_run:
        present = {e.key for e in entries}
        for key, r in pending.items():
            if key not in present:
                continue
            info = changes.get(_entry_id(*key))
            if info:
                r.update({"change": "modified", "previous_command": info.get("previous"), "changed_at": info.get("changed_at")})
            reemit.append(r)
    return Reconciled(new=new, known=known, baseline_run=baseline_run, reemit=reemit, changed=changed)


def promote_to_baseline(conn: Any) -> int:
    """Accept every current entry, changed commands included, as known ("mark all as known")."""
    n = db.write(conn, "UPDATE persistence SET baseline = 1 WHERE baseline = 0") or 0
    _save_changes(conn, {})
    return n


def accept_entry(conn: Any, kind: str, location: str, name: str) -> bool:
    """Accept one entry and its current command as known. True when a pending entry was accepted."""
    row = db.one(conn, "SELECT baseline FROM persistence WHERE kind = ? AND location = ? AND name = ?", (kind, location, name))
    if row is None:
        return False
    db.write(conn, "UPDATE persistence SET baseline = 1 WHERE kind = ? AND location = ? AND name = ?", (kind, location, name))
    changes = _load_changes(conn)
    if changes.pop(_entry_id(kind, location, name), None) is not None:
        _save_changes(conn, changes)
    return not row["baseline"]


# --------------------------------------------------------------------------- findings


def build_findings(reemit_rows: list[dict[str, Any]], errors: dict[str, Any], c: Collector, entries_by_key: dict[tuple[str, str, str], Entry] | None = None) -> None:
    """WIN-PER-* checks (one row per ID) and one finding per pending entry.

    Dedupe key: ``kind:location:name`` for a new entry, and
    ``kind:location:name:changed:<digest of the new command>`` for a known entry whose command
    changed. A hijack therefore opens (and notifies) a fresh finding even when the entry's earlier
    finding was acknowledged or suppressed, and every further change opens another one.
    """
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
            names = [str(r.get("name")) + (" (changed)" if r.get("change") == "modified" else "") for r in rows[:8]]
            c.check(fid, "fail", f"{len(rows)} new: " + ", ".join(names) + (" ..." if len(rows) > 8 else ""), expected)
            for r in rows:
                entry = entries_by_key.get((r["kind"], r["location"], r["name"]))
                ev = {"kind": r["kind"], "name": r["name"], "location": r["location"], "command": r.get("command"), "first_seen": r.get("first_seen")}
                if entry:
                    ev.update({k: v for k, v in entry.extra.items() if v not in (None, "")})
                key = f"{r['kind']}:{r['location']}:{r['name']}"
                detail = f"{r['kind']} '{r['name']}' -> {r.get('command') or '?'}"
                if r.get("change") == "modified":
                    ev.update({"change": "modified", "previous_command": r.get("previous_command"), "changed_at": r.get("changed_at")})
                    key += f":changed:{command_digest(r.get('command'))}"
                    detail = f"{r['kind']} '{r['name']}' changed: {r.get('previous_command') or '?'} -> {r.get('command') or '?'}"
                c.finding(fid, ev, key=key, detail=detail)
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
        "changed": len(rec.changed),
        "known": rec.known,
        "baseline_run": rec.baseline_run,
        "by_kind": {k: sum(1 for e in entries if e.kind == k) for k in KINDS},
        "findings": len(c.findings),
    })
    notify(f"persistence: {len(entries)} entries, {len(rec.new)} new, {len(rec.changed)} changed" + (" (baseline stored)" if rec.baseline_run else ""))
    return ScanResult("host", c.findings, summary, error="; ".join(f"{k}: {v}" for k, v in errors.items()) or None)


__all__ = [
    "CHANGES_SETTING",
    "Entry",
    "FINDING_FOR_KIND",
    "KINDS",
    "LOLBINS",
    "Reconciled",
    "accept_entry",
    "build_findings",
    "collect",
    "command_digest",
    "command_fingerprint",
    "is_windows_service",
    "normalize",
    "promote_to_baseline",
    "reconcile",
    "run",
    "split_command",
]
