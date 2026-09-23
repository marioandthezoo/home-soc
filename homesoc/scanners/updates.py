"""Pending OS updates and outdated applications (SPEC 6.7).

Windows: ``ps/updates.ps1`` (Windows Update COM search + hotfix/history) and ``winget upgrade``
parsed from its fixed-width table into ``software`` rows. POSIX: apt / brew / softwareupdate
counts. The winget parser is pure so the fixture in ``tests/fixtures/posture/winget_upgrade.txt``
covers spinner lines, the ``< 17.14.37`` version quirk and the trailing summary line.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import ScanResult
from homesoc.scanners.host_windows import PS_DIR, Collector, as_list, is_denied, run_ps_json, write_checks
from homesoc.util import is_elevated, is_macos, is_windows, json_dumps, parse_iso, run_cmd, utcnow_iso, which

if TYPE_CHECKING:  # pragma: no cover
    from homesoc.config import Config

logger = logging.getLogger(__name__)

UPDATES_TIMEOUT_SEC = 240
WINGET_TIMEOUT_SEC = 180
POSIX_TIMEOUT_SEC = 120
CUMULATIVE_MAX_DAYS = 45
MAX_TITLES_IN_EVIDENCE = 15

# SPEC 8: an outdated app matching one of these is WIN-UPD-004 (high) instead of WIN-UPD-003 (low).
HIGH_RISK_APPS = (
    "java", "adobe", "chrome", "firefox", "edge", "zoom", "vlc", "7-zip", "winrar", "putty",
    "openvpn", "notepad++", "teamviewer", "anydesk", "filezilla", "python",
)
_HIGH_RISK_PATTERNS = [re.compile(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9+])") for t in HIGH_RISK_APPS]
_ESCALATE_TITLE = re.compile(r"security|cumulative", re.IGNORECASE)
_SPINNER = re.compile(r"^[\s\-\\|/█▒░.]*$")
_WINGET_COLUMNS = ("Name", "Id", "Version", "Available", "Source")


# --------------------------------------------------------------------------- helpers


def days_since(value: Any, now: datetime | None = None) -> int | None:
    dt = parse_iso(value)
    if dt is None:
        return None
    ref = now or datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    return max(0, int((ref - dt).total_seconds() // 86400))


def is_high_risk(name: str, package_id: str | None = None) -> bool:
    hay = f"{name or ''} {package_id or ''}".lower().replace(".", " ")
    return any(p.search(hay) for p in _HIGH_RISK_PATTERNS)


# --------------------------------------------------------------------------- winget


def winget_exe() -> str | None:
    # winget is found on the user's PATH or in %LOCALAPPDATA%\Microsoft\WindowsApps, both of which
    # the user can write without admin rights. Running whatever sits there from an elevated Home SOC
    # would hand a non-admin program administrator rights, so an elevated process never runs it.
    if is_elevated():
        return None
    found = which("winget")
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA")
    if is_windows() and local:
        cand = Path(local) / "Microsoft" / "WindowsApps" / "winget.exe"
        if cand.is_file():
            return str(cand)
    return None


def winget_upgrades() -> tuple[list[dict[str, str]], str | None]:
    """Run ``winget upgrade`` non-interactively; returns (rows, error)."""
    exe = winget_exe()
    if exe is None:
        return [], "winget not found"
    rc, out, err = run_cmd(
        [exe, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"],
        timeout=WINGET_TIMEOUT_SEC,
    )
    rows = parse_winget_upgrade(out)
    if rc != 0 and not rows:
        return [], f"winget rc={rc}: {(err or out).strip()[-200:]}"
    return rows, None


def parse_winget_upgrade(text: str) -> list[dict[str, str]]:
    """Parse the fixed-width ``winget upgrade`` table(s).

    Column offsets come from the header line, because winget pads columns to the widest value and
    the widths change every run. Progress spinner fragments, the dashed rule and the trailing
    "N upgrades available." line are skipped; a second table ("require explicit targeting") is
    parsed the same way. Rows whose Id slice contains whitespace (wide Unicode names shift the
    columns) fall back to a 2+-space split.
    """
    rows: list[dict[str, str]] = []
    offsets: list[tuple[str, int]] | None = None
    expect_rule = False
    for raw in text.splitlines():
        line = raw.split("\r")[-1].rstrip()
        if not line.strip():
            offsets = None
            continue
        header = _header_offsets(line)
        if header:
            offsets = header
            expect_rule = True
            continue
        if expect_rule:
            expect_rule = False
            if set(line.strip()) <= {"-"}:
                continue
        if offsets is None or _SPINNER.match(line) or _is_footer(line):
            continue
        row = _slice_row(line, offsets)
        if row:
            rows.append(row)
    return rows


def _header_offsets(line: str) -> list[tuple[str, int]] | None:
    if not line.lstrip().startswith("Name") or " Id" not in line or "Version" not in line:
        return None
    pos = 0
    out: list[tuple[str, int]] = []
    for col in _WINGET_COLUMNS:
        idx = line.find(col, pos)
        if idx < 0:
            if col in ("Name", "Id", "Version"):
                return None
            continue
        out.append((col, idx))
        pos = idx + len(col)
    return out


def _is_footer(line: str) -> bool:
    s = line.strip().lower()
    return bool(re.match(r"^\d+ (upgrades?|packages?) available", s)) or s.startswith(("the following packages", "no installed package", "failed", "no applicable"))


def _slice_row(line: str, offsets: list[tuple[str, int]]) -> dict[str, str] | None:
    parts: dict[str, str] = {}
    for i, (col, start) in enumerate(offsets):
        end = offsets[i + 1][1] if i + 1 < len(offsets) else len(line)
        parts[col.lower()] = line[start:end].strip()
    if not parts.get("name") or not parts.get("id") or re.search(r"\s", parts["id"]):
        # Wide glyphs threw the columns off: split on runs of 2+ spaces instead.
        chunks = re.split(r"\s{2,}", line.strip())
        if len(chunks) < 3:
            return None
        parts = {"name": chunks[0], "id": chunks[1], "version": chunks[2], "available": chunks[3] if len(chunks) > 3 else "", "source": chunks[4] if len(chunks) > 4 else ""}
        if re.search(r"\s", parts["id"]):
            return None
    return {
        "name": parts.get("name", ""),
        "id": parts.get("id", ""),
        "version": parts.get("version", ""),
        "available": parts.get("available", ""),
        "source": parts.get("source", "") or "winget",
    }


_UPSERT_SOFTWARE_SQL = (
    "INSERT INTO software(name, version, available, source, publisher, seen_at) VALUES (?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(name, source) DO UPDATE SET version = excluded.version, available = excluded.available, "
    "publisher = excluded.publisher, seen_at = excluded.seen_at"
)


def write_software(conn: Any, rows: list[dict[str, str]], source: str) -> int:
    """Upsert software rows; entries no longer reported by the package manager are removed."""
    now = utcnow_iso()
    # SPEC-GAP: the software table has no column for the winget package Id, which is what
    # "winget upgrade --id" needs; it is stored in ``publisher`` (its first segment IS the publisher).
    params = [(r["name"], r.get("version") or None, r.get("available") or None, source, r.get("id") or r.get("publisher") or None, now) for r in rows if r.get("name")]
    if params:
        db.writemany(conn, _UPSERT_SOFTWARE_SQL, params)
    db.write(conn, "DELETE FROM software WHERE source = ? AND seen_at < ?", (source, now))
    return len(params)


def software_findings(rows: list[dict[str, str]], c: Collector) -> None:
    """WIN-UPD-003 per outdated app, WIN-UPD-004 (high) when it is on the high-risk list."""
    risky: list[dict[str, str]] = []
    plain: list[dict[str, str]] = []
    for r in rows:
        (risky if is_high_risk(r.get("name", ""), r.get("id")) else plain).append(r)
    for cid, group, expected in (("WIN-UPD-003", plain, "no outdated apps"), ("WIN-UPD-004", risky, "no outdated high-risk apps")):
        if group:
            c.check(cid, "fail", ", ".join(f"{r['name']} {r.get('version') or '?'} -> {r.get('available') or '?'}" for r in group[:12]) + (" ..." if len(group) > 12 else ""), expected)
            for r in group:
                c.finding(cid, {"name": r.get("name"), "id": r.get("id"), "version": r.get("version"), "available": r.get("available"), "source": r.get("source")}, key=r.get("id") or r.get("name"), detail=f"{r.get('name')}: {r.get('version')} -> {r.get('available')}")
        else:
            c.ok(cid, "none", expected)


# --------------------------------------------------------------------------- windows update


def windows_update_findings(data: dict[str, Any], c: Collector, *, now: datetime | None = None) -> None:
    """WIN-UPD-001 (pending) and WIN-UPD-002 (cumulative age) from the updates.ps1 JSON."""
    err = data.get("pending_error")
    if err:
        if is_denied(err):
            c.denied("WIN-UPD-001", "no pending updates")
        else:
            c.unknown("WIN-UPD-001", "no pending updates", str(err)[:200])
    else:
        pending = [p for p in as_list(data.get("pending")) if isinstance(p, dict)]
        # Defender intelligence updates arrive daily and are installed automatically; they do not
        # make the machine "behind on updates".
        real = [p for p in pending if not _is_defender_intel(p)]
        if real:
            titles = [str(p.get("title")) for p in real]
            important = any(_ESCALATE_TITLE.search(t) for t in titles)
            c.fail(
                "WIN-UPD-001",
                f"{len(real)} pending" + (" (security/cumulative)" if important else ""),
                "no pending updates",
                {"count": len(real), "titles": titles[:MAX_TITLES_IN_EVIDENCE], "kbs": [p.get("kb") for p in real if p.get("kb")][:MAX_TITLES_IN_EVIDENCE], "important": important, "ignored_defender_intel": len(pending) - len(real)},
                severity="high" if important else None,
            )
        else:
            c.ok("WIN-UPD-001", "none" + (f" ({len(pending)} Defender intelligence update(s) pending)" if pending else ""), "no pending updates")

    history = data.get("history") if isinstance(data.get("history"), dict) else {}
    hotfix = data.get("hotfix") if isinstance(data.get("hotfix"), dict) else {}
    last = history.get("last_cumulative_date") or hotfix.get("last_installed")
    source = "windows update history" if history.get("last_cumulative_date") else "hotfix"
    days = days_since(last, now)
    expected = f"cumulative update within {CUMULATIVE_MAX_DAYS} days"
    if days is None:
        if is_denied(hotfix.get("error")) or is_denied(history.get("error")):
            c.denied("WIN-UPD-002", expected)
        else:
            c.unknown("WIN-UPD-002", expected, "no install date available")
    elif days > CUMULATIVE_MAX_DAYS:
        c.fail("WIN-UPD-002", f"{days} days ago ({str(last)[:10]})", expected, {"last": last, "days": days, "title": history.get("last_cumulative_title") or hotfix.get("last_id"), "source": source, "build": (data.get("os") or {}).get("build") if isinstance(data.get("os"), dict) else None})
    else:
        c.ok("WIN-UPD-002", f"{days} days ago ({str(last)[:10]})", expected)


def _is_defender_intel(update: dict[str, Any]) -> bool:
    title = str(update.get("title") or "").lower()
    return "security intelligence update" in title or "antimalware platform" in title


# --------------------------------------------------------------------------- posix


def posix_pending() -> dict[str, Any]:
    """Count upgradable packages with whichever manager exists; never raises."""
    if which("apt"):
        rc, out, err = run_cmd(["apt", "list", "--upgradable"], timeout=POSIX_TIMEOUT_SEC)
        pkgs = []
        for line in out.splitlines():
            m = re.match(r"^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]", line)
            if m:
                pkgs.append({"name": m.group(1), "version": m.group(3), "available": m.group(2)})
        return {"manager": "apt", "count": len(pkgs), "packages": pkgs, "error": None if rc == 0 else err.strip()[-200:]}
    if which("brew"):
        rc, out, err = run_cmd(["brew", "outdated", "--verbose"], timeout=POSIX_TIMEOUT_SEC)
        pkgs = []
        for line in out.splitlines():
            m = re.match(r"^(\S+)\s+\(([^)]+)\)\s+<\s+(\S+)", line.strip())
            if m:
                pkgs.append({"name": m.group(1), "version": m.group(2), "available": m.group(3)})
            elif line.strip():
                pkgs.append({"name": line.split()[0], "version": None, "available": None})
        return {"manager": "brew", "count": len(pkgs), "packages": pkgs, "error": None if rc == 0 else err.strip()[-200:]}
    if is_macos() and which("softwareupdate"):
        rc, out, err = run_cmd(["softwareupdate", "-l"], timeout=POSIX_TIMEOUT_SEC)
        pkgs = [{"name": line.strip().lstrip("* ").split(":", 1)[-1].strip() or line.strip(), "version": None, "available": None} for line in out.splitlines() if line.strip().startswith("*")]
        return {"manager": "softwareupdate", "count": len(pkgs), "packages": pkgs, "error": None if rc == 0 else err.strip()[-200:]}
    return {"manager": None, "count": 0, "packages": [], "error": "no supported package manager"}


def _run_posix(cfg: Any, conn: Any, notify: Callable[[str], None], started: float) -> ScanResult:
    notify("updates: querying package manager")
    info = posix_pending()
    c = Collector()
    if info["manager"] is None:
        c.unknown("POSIX-UPD-001", "no pending updates", info.get("error"))
    elif info["count"] > 0:
        c.fail("POSIX-UPD-001", f"{info['count']} pending ({info['manager']})", "no pending updates", {"count": info["count"], "manager": info["manager"], "packages": [p["name"] for p in info["packages"][:MAX_TITLES_IN_EVIDENCE]]})
    else:
        c.ok("POSIX-UPD-001", f"none ({info['manager']})", "no pending updates")
    if info["manager"] in ("apt", "brew"):
        write_software(conn, [{"name": p["name"], "version": p.get("version"), "available": p.get("available"), "id": None} for p in info["packages"]], info["manager"])
    write_checks(conn, c.checks)
    db.set_setting(conn, "updates.status_json", json_dumps(info))
    summary = c.summary()
    summary.update({"duration_sec": round(time.monotonic() - started, 2), "manager": info["manager"], "pending": info["count"], "findings": len(c.findings)})
    return ScanResult("host", c.findings, summary, error=info.get("error") if info["manager"] is None else None)


# --------------------------------------------------------------------------- scanner entry point


def run(cfg: Config, conn: Any, *, quick: bool = False, progress: Callable[[str], None] | None = None) -> ScanResult:
    """Scanner interface (SPEC 6): pending updates + outdated apps -> host_checks, software, drafts."""
    started = time.monotonic()
    notify = progress or (lambda _msg: None)
    if not is_windows():
        return _run_posix(cfg, conn, notify, started)

    c = Collector()
    errors: list[str] = []
    data: dict[str, Any] = {}
    # The COM search alone is ~25 s; a quick scan skips it and keeps the previous WIN-UPD-001/002 rows.
    if not quick:
        notify("updates: searching Windows Update (this takes ~30 s)")
        res = run_ps_json(PS_DIR / "updates.ps1", timeout=UPDATES_TIMEOUT_SEC)
        if res.data is None:
            errors.append(res.error or "updates probe failed")
            c.unknown("WIN-UPD-001", "no pending updates", res.error)
            c.unknown("WIN-UPD-002", f"cumulative update within {CUMULATIVE_MAX_DAYS} days", res.error)
        else:
            data = res.data
            windows_update_findings(data, c)
            db.set_setting(conn, "updates.status_json", json_dumps(data))

    notify("updates: listing winget upgrades")
    rows, werr = winget_upgrades()
    if werr:
        errors.append(werr)
        c.unknown("WIN-UPD-003", "no outdated apps", werr)
        c.unknown("WIN-UPD-004", "no outdated high-risk apps", werr)
    else:
        write_software(conn, rows, "winget")
        software_findings(rows, c)
    db.set_setting(conn, "updates.checked_at", utcnow_iso())

    write_checks(conn, c.checks)
    summary = c.summary()
    summary.update({
        "duration_sec": round(time.monotonic() - started, 2),
        "pending_updates": len(as_list(data.get("pending"))) if data else None,
        "outdated_apps": len(rows),
        "findings": len(c.findings),
        "quick": quick,
    })
    notify(f"updates: {summary['pending_updates']} pending, {len(rows)} outdated apps")
    return ScanResult("host", c.findings, summary, error="; ".join(errors) if errors else None)


__all__ = [
    "CUMULATIVE_MAX_DAYS",
    "HIGH_RISK_APPS",
    "days_since",
    "is_high_risk",
    "parse_winget_upgrade",
    "posix_pending",
    "run",
    "software_findings",
    "windows_update_findings",
    "winget_upgrades",
    "write_software",
]
