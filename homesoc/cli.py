"""Command-line interface and the wiring between all packages.

This is the only module that knows about every other package. Everything it
needs from them is imported lazily inside functions and guarded, because the
packages are developed in parallel: a missing scanner must degrade to a logged
"not available" and a skipped job, never to a crashed dashboard.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import logging
import logging.handlers
import re
import secrets
import signal
import sqlite3
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homesoc import __version__, config, db, paths, util
from homesoc.config import Config
from homesoc.models import SEVERITIES, FindingDraft, ScanResult, severity_rank
from homesoc.scheduler import Job, Scheduler

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

# Scan step names accepted by `scan --only` and the "full" job, in execution order:
# vulns needs fresh services, everything else is independent.
# SPEC addendum C6 adds "topology": it reads what discovery and the DNS filter already wrote,
# so it comes after them and costs no network traffic of its own.
SCAN_STEPS: tuple[str, ...] = ("discovery", "services", "vulns", "topology", "host", "exposure", "wifi", "files")
# What a "quick" scan covers: what changed on the LAN plus a cheap host check.
QUICK_STEPS: tuple[str, ...] = ("discovery", "services", "vulns", "wifi")

MODULES = {
    "feeds_update": ("homesoc.feeds.updater", "update"),
    "feeds_registry": ("homesoc.feeds.registry", None),
    "discovery": ("homesoc.scanners.discovery", "run"),
    "ports": ("homesoc.scanners.ports", "run"),
    "exposure": ("homesoc.scanners.exposure", "run"),
    "wifi": ("homesoc.scanners.wifi", "run"),
    "host_windows": ("homesoc.scanners.host_windows", "run"),
    "host_posix": ("homesoc.scanners.host_posix", "run"),
    "defender": ("homesoc.scanners.defender", "run"),
    "updates": ("homesoc.scanners.updates", "run"),
    "persistence": ("homesoc.scanners.persistence", "run"),
    "files": ("homesoc.scanners.files", "run"),
    "match_services": ("homesoc.vulns.matcher", "match_services"),
    "topology": ("homesoc.topology", "run"),
    "topology_graph": ("homesoc.topology.graph", None),
    "apply": ("homesoc.findings.engine", "apply"),
    "list_findings": ("homesoc.findings.engine", "list_findings"),
    "counts": ("homesoc.findings.engine", "counts"),
    "security_score": ("homesoc.findings.score", "security_score"),
    "score_breakdown": ("homesoc.findings.score", "score_breakdown"),
    "baseline_devices": ("homesoc.findings.engine", "baseline_devices"),
    "notify_new_findings": ("homesoc.notify.channels", "notify_new_findings"),
    "DnsServer": ("homesoc.dnsfilter.server", "DnsServer"),
    "create_app": ("homesoc.web.app", "create_app"),
    # helpers beyond the spec's wiring list, still guarded the same way
    "send": ("homesoc.notify.channels", "send"),
    "querylog": ("homesoc.dnsfilter.querylog", None),
    "Policy": ("homesoc.dnsfilter.policy", "Policy"),
    "defender_module": ("homesoc.scanners.defender", None),
}

_UNAVAILABLE: set[str] = set()

#: SPEC addendum C6: the topology job's default interval, in hours. A literal rather than an
#: import of homesoc.topology, so a missing package degrades to a skipped job like every other.
TOPOLOGY_JOB_HOURS = 6

#: How many devices/finding types the plain-text commands list before summarising the rest.
BASELINE_LIST_LIMIT = 20
SCORE_BREAKDOWN_LIMIT = 5


def _lazy(name: str) -> Any:
    """Import one of the MODULES entries on demand; None (with one clear log line) when missing."""
    module_name, attr = MODULES[name]
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # ImportError, or a sibling package mid-edit raising at import
        if module_name not in _UNAVAILABLE:
            _UNAVAILABLE.add(module_name)
            logger.warning("%s is not available (%s: %s); features that need it are skipped",
                           module_name, type(exc).__name__, exc)
        return None
    if attr is None:
        return module
    obj = getattr(module, attr, None)
    if obj is None:
        logger.warning("%s has no attribute %r; feature skipped", module_name, attr)
    return obj


# ----------------------------------------------------------------- logging


class _StderrHandler(logging.StreamHandler):
    """Resolves ``sys.stderr`` at emit time, so a stream swapped (and later closed) by
    pytest's capture or a console redirect never leaves the root logger writing to a dead file."""

    def __init__(self) -> None:
        super().__init__(sys.stderr)

    @property
    def stream(self):  # type: ignore[override]
        return sys.stderr

    @stream.setter
    def stream(self, value) -> None:
        pass


class _TerminalSafeFormatter(logging.Formatter):
    r"""Log lines quote hostnames, banners and UPnP fields that LAN devices choose; show their
    control characters as ``\xNN`` so a device cannot drive the console (or whoever tails the log)."""

    #: Line breaks inside the *message* itself: a device-supplied value containing one would
    #: otherwise start what looks like a fresh, genuine log line.
    _MESSAGE_BREAKS = {"\n": "\\n", "\u2028": "\\u2028", "\u2029": "\\u2029", "\x85": "\\x85"}

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802 - logging API name
        text = util.terminal_safe(super().formatMessage(record))
        for raw, shown in self._MESSAGE_BREAKS.items():
            text = text.replace(raw, shown)
        return text

    def format(self, record: logging.LogRecord) -> str:
        # formatMessage (above) has made the message one line; tracebacks appended after it keep
        # their line breaks, with any other control characters still made visible.
        return util.terminal_safe(super().format(record))


def setup_logging(level: str = "INFO", *, log_file: Path | None = None) -> None:
    """stderr + rotating file (5 x 2 MB). Re-entrant so tests and `main()` can call it repeatedly."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_homesoc", False):
            root.removeHandler(handler)
            handler.close()
    fmt = _TerminalSafeFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    stream = _StderrHandler()
    stream.setFormatter(fmt)
    stream._homesoc = True  # type: ignore[attr-defined]
    root.addHandler(stream)
    target = log_file or paths.logs_dir() / "homesoc.log"
    try:
        rotating = logging.handlers.RotatingFileHandler(target, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
        rotating.setFormatter(fmt)
        rotating._homesoc = True  # type: ignore[attr-defined]
        root.addHandler(rotating)
        # Existing installs wrote these 0644; the log names devices, addresses and DNS activity.
        for log in Path(target).parent.glob(Path(target).name + "*"):
            paths.restrict_path(log, paths.PRIVATE_FILE_MODE)
    except OSError as exc:
        logger.warning("cannot open log file %s: %s", target, exc)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for noisy in ("werkzeug", "urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def emit(text: str = "") -> None:
    """Console output for the user (the CLI *is* the UI here; library code logs instead).

    A stock Windows console is code page 437/850, so an em dash in a report or a feed title
    would otherwise end the command in a UnicodeEncodeError traceback. Text that the console
    cannot represent is degraded, never fatal — ``report --out`` still writes real UTF-8.

    Findings titles and hostnames carry banners and mDNS names that LAN devices choose, so
    terminal control characters are shown as visible escapes rather than written raw.
    """
    line = util.terminal_safe(text) + "\n"
    stream = sys.stdout
    try:
        stream.write(line)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "utf-8"
        stream.write(line.encode(encoding, "replace").decode(encoding, "replace"))
    try:
        stream.flush()
    except (ValueError, OSError):  # stream closed by a pipe that went away (e.g. `| head`)
        pass


# ------------------------------------------------------------ scan pipeline

ScannerCall = Callable[[], ScanResult]


def _progress_logger(kind: str) -> Callable[[str], None]:
    def progress(message: str) -> None:
        logger.info("[%s] %s", kind, message)

    return progress


def effective_scope(result: ScanResult, scope: str | None) -> str | list[str] | None:
    """Only a *complete, successful* run may auto-resolve what it did not report.

    A scanner that failed, timed out, scanned nothing (laptop on VPN, Wi-Fi not up yet) or
    reports ``summary["partial"]`` returns no scope, so "it went away" is never concluded from
    "we did not look". A scanner that knows exactly what it covered lists it in
    ``summary["scopes"]`` (ports.run: one ``device:<mac>`` per fully scanned device).
    """
    if result.error:
        return None
    summary = result.summary if isinstance(result.summary, dict) else {}
    if summary.get("partial"):
        return None
    scopes = summary.get("scopes")
    if isinstance(scopes, list):
        return [str(s) for s in scopes]
    if "targets" in summary and not summary.get("targets"):
        return None
    if "hosts_scanned" in summary and not summary.get("hosts_scanned"):
        return None
    return scope


def apply_findings(cfg: Config, conn: sqlite3.Connection, result: ScanResult, source: str,
                   scope: str | None, drafts: list[FindingDraft] | None = None) -> dict[str, int]:
    """Persist a scanner's drafts through the findings engine and notify about new ones."""
    counts = {"new": 0, "reopened": 0, "resolved": 0, "updated": 0}
    apply = _lazy("apply")
    if apply is None:
        return counts
    try:
        applied = apply(conn, list(result.findings if drafts is None else drafts), source,
                        scope=effective_scope(result, scope))
    except Exception:
        logger.exception("findings.engine.apply failed for source %s", source)
        return counts
    new = list(getattr(applied, "new", []) or [])
    counts.update(
        new=len(new),
        reopened=len(getattr(applied, "reopened", []) or []),
        resolved=len(getattr(applied, "resolved", []) or []),
        updated=int(getattr(applied, "updated", 0) or 0),
    )
    if new:
        notify = _lazy("notify_new_findings")
        if notify is not None:
            try:
                notify(cfg, conn, new)
            except Exception:
                logger.exception("notification for %d new findings failed", len(new))
    return counts


def _call_scanner(name: str, cfg: Config, conn: sqlite3.Connection, *, quick: bool,
                  progress: Callable[[str], None]) -> ScannerCall | None:
    run = _lazy(name)
    if run is None:
        return None
    if name == "match_services":
        return lambda: run(cfg, conn)
    return lambda: run(cfg, conn, quick=quick, progress=progress)


Route = Callable[[ScanResult], list[tuple[str, list[FindingDraft], str | None]]]


def run_step(cfg: Config, conn: sqlite3.Connection, kind: str,
             parts: list[tuple[str, ScannerCall | None, str | None] | tuple[str, ScannerCall | None, str | None, Route]]) -> dict[str, Any]:
    """Run the scanners that make up one scan kind, apply their findings, record one `scans` row.

    ``parts`` are ``(source, callable, scope[, route])``; a None callable means the package is not
    available yet and the part is recorded as skipped instead of failing the whole step. A ``route``
    splits one result into several ``(source, drafts, scope)`` groups (discovery uses it so
    NET-DEV-003 lives under its own source/scope and can auto-resolve).
    """
    scan_id = db.scan_start(conn, kind)
    summary: dict[str, Any] = {}
    errors: list[str] = []
    ran = 0
    for part in parts:
        source, call, scope = part[0], part[1], part[2]
        route: Route | None = part[3] if len(part) > 3 else None  # type: ignore[misc]
        if call is None:
            summary[source] = {"skipped": "module unavailable"}
            continue
        started = time.time()
        try:
            result = call()
        except Exception as exc:  # scanners promise not to raise; belt and braces
            logger.exception("scanner %s crashed", source)
            summary[source] = {"error": f"{type(exc).__name__}: {exc}"}
            errors.append(f"{source}: {type(exc).__name__}: {exc}")
            continue
        ran += 1
        if not isinstance(result, ScanResult):
            summary[source] = {"error": "scanner returned no ScanResult"}
            errors.append(f"{source}: bad result type {type(result).__name__}")
            continue
        if route is None:
            counts = apply_findings(cfg, conn, result, source, scope)
        else:
            counts = {"new": 0, "reopened": 0, "resolved": 0, "updated": 0}
            for group_source, group_drafts, group_scope in route(result):
                for key, value in apply_findings(cfg, conn, result, group_source, group_scope, drafts=group_drafts).items():
                    counts[key] += value
        part_summary = dict(result.summary or {})
        part_summary["findings"] = counts
        part_summary.setdefault("duration_sec", round(time.time() - started, 2))
        if result.error:
            part_summary["error"] = result.error
            errors.append(f"{source}: {result.error}")
        summary[source] = part_summary
    if not errors:
        status = "ok" if ran else "skipped"
    elif ran and len(errors) < len(parts):
        status = "partial"
    else:
        status = "error"
    db.scan_finish(conn, scan_id, status, summary, "; ".join(errors) or None)
    return {"kind": kind, "status": status, "summary": summary, "errors": errors}


OFFLINE_DEVICE_FINDINGS = frozenset({"NET-DEV-003"})


def _route_discovery(result: ScanResult) -> list[tuple[str, list[FindingDraft], str | None]]:
    """New-device findings keep no scope (they must survive the device going offline; the user
    acks them). NET-DEV-003 "trusted device offline 30 days" gets its own source and scope so it
    resolves the moment the device is seen again."""
    offline = [d for d in result.findings if d.finding_id in OFFLINE_DEVICE_FINDINGS]
    rest = [d for d in result.findings if d.finding_id not in OFFLINE_DEVICE_FINDINGS]
    return [("discovery", rest, None), ("discovery_offline", offline, "device:")]


def scan_discovery(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    call = _call_scanner("discovery", cfg, conn, quick=quick, progress=_progress_logger("discovery"))
    return run_step(cfg, conn, "discovery", [("discovery", call, None, _route_discovery)])


def scan_services(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    call = _call_scanner("ports", cfg, conn, quick=quick, progress=_progress_logger("services"))
    # ports.run reports summary["scopes"] = the devices it scanned completely; effective_scope()
    # uses that instead of this blanket prefix, so findings on devices that were asleep, timed
    # out or not selected (quick scan) are never auto-resolved.
    return run_step(cfg, conn, "services", [("services", call, None if quick else "device:")])


def scan_vulns(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    call = _call_scanner("match_services", cfg, conn, quick=quick, progress=_progress_logger("vulns"))
    # SPEC-GAP: scans.kind gains "vulns" and "wifi" so each step has its own history row.
    return run_step(cfg, conn, "vulns", [("vulns", call, "device:")])


def scan_host(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    progress = _progress_logger("host")
    parts: list[tuple[str, ScannerCall | None, str | None]] = []
    if cfg.host.posture:
        posture = "host_windows" if util.is_windows() else "host_posix"
        parts.append(("host", _call_scanner(posture, cfg, conn, quick=quick, progress=progress), "host"))
    if util.is_windows():
        parts.append(("defender", _call_scanner("defender", cfg, conn, quick=quick, progress=progress), "host"))
    parts.append(("updates", _call_scanner("updates", cfg, conn, quick=quick, progress=progress), "host"))
    if util.is_windows():
        parts.append(("persistence", _call_scanner("persistence", cfg, conn, quick=quick, progress=progress), "host"))
    return run_step(cfg, conn, "host", parts)


def scan_exposure(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    call = _call_scanner("exposure", cfg, conn, quick=quick, progress=_progress_logger("exposure"))
    return run_step(cfg, conn, "exposure", [("exposure", call, "wan")])


def scan_wifi(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    call = _call_scanner("wifi", cfg, conn, quick=quick, progress=_progress_logger("wifi"))
    # wifi.py emits subject "wifi"; the scope must match it or NET-WIFI-* could never auto-resolve.
    return run_step(cfg, conn, "wifi", [("wifi", call, "wifi")])


def scan_files(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    if not cfg.host.files_check:
        return {"kind": "files", "status": "disabled", "summary": {}, "errors": []}
    call = _call_scanner("files", cfg, conn, quick=quick, progress=_progress_logger("files"))
    return run_step(cfg, conn, "files", [("files", call, None)])


def scan_topology(cfg: Config, conn: sqlite3.Connection, *, quick: bool = False) -> dict[str, Any]:
    """SPEC addendum C6. Scope "device:" so a NET-DEP finding auto-resolves the moment the
    dependency it describes stops being true — the device stopped being load-bearing, or the
    endpoint it could never reach started answering."""
    call = _call_scanner("topology", cfg, conn, quick=quick, progress=_progress_logger("topology"))
    return run_step(cfg, conn, "topology", [("topology", call, "device:")])


SCAN_FUNCS: dict[str, Callable[..., dict[str, Any]]] = {
    "discovery": scan_discovery,
    "services": scan_services,
    "vulns": scan_vulns,
    "topology": scan_topology,
    "host": scan_host,
    "exposure": scan_exposure,
    "wifi": scan_wifi,
    "files": scan_files,
}


def run_scan(cfg: Config, conn: sqlite3.Connection, steps: tuple[str, ...] | list[str], *,
             quick: bool = False, on_step: Callable[[str, dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Run several steps in canonical order and record a `scans` row of kind `full` around them."""
    ordered = [s for s in SCAN_STEPS if s in steps]
    scan_id = db.scan_start(conn, "full")
    results: dict[str, Any] = {}
    for step in ordered:
        results[step] = SCAN_FUNCS[step](cfg, conn, quick=quick)
        if on_step:
            on_step(step, results[step])
    failed = [s for s, r in results.items() if r["status"] == "error"]
    status = "ok" if not failed else ("partial" if len(failed) < len(results) else "error")
    db.scan_finish(conn, scan_id, status, {s: r["status"] for s, r in results.items()},
                   "; ".join(f"{s}: {'; '.join(results[s]['errors'])}" for s in failed) or None)
    return {"kind": "full", "status": status, "steps": results}


def run_feeds(cfg: Config, conn: sqlite3.Connection, names: list[str] | None = None,
              force: bool = False) -> dict[str, str]:
    update = _lazy("feeds_update")
    if update is None:
        return {}
    scan_id = db.scan_start(conn, "feeds")
    try:
        statuses = dict(update(cfg, conn, names=names, force=force, progress=_progress_logger("feeds")) or {})
    except Exception as exc:
        logger.exception("feed update failed")
        db.scan_finish(conn, scan_id, "error", None, f"{type(exc).__name__}: {exc}")
        raise
    errors = sorted(n for n, s in statuses.items() if s == "error")
    tally = {s: sum(1 for v in statuses.values() if v == s) for s in sorted(set(statuses.values()))}
    status = "ok" if not errors else ("partial" if len(errors) < len(statuses) else "error")
    db.scan_finish(conn, scan_id, status, {"statuses": statuses, "tally": tally},
                   ("failed: " + ", ".join(errors)) if errors else None)
    return statuses


# ------------------------------------------------------------- SOC health


def soc_health_drafts(cfg: Config, conn: sqlite3.Connection, scheduler: Scheduler | None) -> list[FindingDraft]:
    """SOC-SYS-001/003/004 and SOC-FEED-001/002 — health of Home SOC itself, computed here
    because the scheduler and feeds table are core-owned and no scanner sees them."""
    drafts: list[FindingDraft] = []
    if cfg.scan.use_nmap and util.which("nmap") is None:
        # The only emitter of SOC-SYS-001 (ports.run just logs), so one source owns the row.
        drafts.append(FindingDraft("SOC-SYS-001", "host", {"hint": "install nmap or set scan.use_nmap=false", "method": "python"}))
    # Where the dashboard really listens, not what config.toml says: `serve --host 0.0.0.0` in
    # one terminal and `scan` in another must not clear the finding the server just earned.
    bound_host, bound_port = recorded_bind(conn, cfg)
    web = dataclasses.replace(cfg.web, host=bound_host, port=bound_port)
    if web.exposed and not web.token:
        drafts.append(FindingDraft("SOC-SYS-003", "host", {"host": web.host, "port": web.port}))
    # SPEC addendum B10: Lens on the LAN without TLS. This complements SOC-SYS-003 rather
    # than repeating it — that one is about there being no password, this one about the
    # whole conversation (and the paired-phone token) crossing the Wi-Fi in clear text.
    if cfg.lens.insecure_on_lan(web, tls=tls_last_used(conn)):
        drafts.append(FindingDraft("SOC-LENS-001", "host", {
            "host": web.host, "port": web.port, "tls": False,
            # Recorded because it decides which half of the finding's description applies:
            # true means Lens refuses to serve phones at all, false means it serves them in clear.
            "require_https": bool(cfg.lens.require_https),
            "hint": "python -m homesoc lens cert --regenerate, then run with --tls",
        }))
    if scheduler is not None:
        for job in scheduler.failing_jobs():
            drafts.append(FindingDraft("SOC-SYS-004", f"job:{job['name']}", {
                "key": job["name"], "job": job["name"], "failures": job["consecutive_failures"],
                "consecutive_failures": job["consecutive_failures"],
                "last_error": job["last_error"], "last_run": job["last_run"],
            }))
    cutoff = util.iso_ago(hours=48)
    try:
        rows = db.query(conn, "SELECT name, status, last_checked, last_updated, error FROM feeds WHERE enabled = 1")
    except sqlite3.Error:
        rows = []
    for row in rows:
        name = str(row["name"])
        last_updated = row["last_updated"]
        never_fresh = last_updated is None or str(last_updated) < cutoff
        # "Failing > 48 h" = no successful fetch (200 or 304) for 48 h. A feed that never succeeded
        # counts from its first error (settings feeds.error_since.<name>), so an offline first
        # start does not raise fourteen findings within the hour.
        since = _feed_error_since(conn, name)
        long_failing = since is not None and since < cutoff
        hours = _hours_since(last_updated if last_updated is not None else since)
        if row["status"] == "error" and never_fresh and row["last_checked"] and (last_updated is not None or long_failing):
            drafts.append(FindingDraft("SOC-FEED-001", f"feed:{name}", {
                "key": name, "name": name, "error": row["error"], "last_updated": last_updated,
                "error_since": since, "hours": hours,
            }))
        if name == "kev" and row["last_checked"] and never_fresh and (last_updated is not None or long_failing):
            drafts.append(FindingDraft("SOC-FEED-002", "feed:kev", {"last_updated": last_updated, "hours": hours}))
    return drafts


def _feed_error_since(conn: sqlite3.Connection, name: str) -> str | None:
    """When the feed's current run of failures started; the updater keeps it in ``settings``."""
    try:
        return db.get_setting(conn, f"feeds.error_since.{name}")
    except sqlite3.Error:
        return None


def _hours_since(value: str | None) -> int | str:
    secs = util.age_seconds(value)
    return int(secs // 3600) if secs is not None else "never"


def apply_soc_health(cfg: Config, conn: sqlite3.Connection, scheduler: Scheduler | None) -> dict[str, int]:
    drafts = soc_health_drafts(cfg, conn, scheduler)
    totals = {"new": 0, "reopened": 0, "resolved": 0, "updated": 0}
    for scope in ("host", "job:", "feed:"):
        subset = [d for d in drafts if d.subject.startswith(scope)]
        counts = apply_findings(cfg, conn, ScanResult("soc", subset, {}), "soc", scope)
        for key in totals:
            totals[key] += counts.get(key, 0)
    return totals


# ------------------------------------------------------------------ jobs


def build_jobs(cfg: Config, conn: sqlite3.Connection,
               scheduler_ref: Callable[[], Scheduler | None] | None = None, *,
               manual_only: bool = False) -> list[Job]:
    """The timetable from spec §13. ``scheduler_ref`` lets the score job inspect job health
    (SOC-SYS-004) even though the scheduler is created after its jobs.

    ``manual_only`` keeps every job but drops the timetable (used by ``serve``: the
    dashboard's Run buttons still work through run_now, nothing runs on its own).
    """
    hours = lambda h: int(h * 3600)  # noqa: E731

    def job_feeds() -> None:
        if cfg.feeds.enabled:
            run_feeds(cfg, conn)

    def job_score() -> None:
        score = _lazy("security_score")
        if score is not None:
            db.record_metric(conn, "score", float(score(conn)))
        apply_soc_health(cfg, conn, scheduler_ref() if scheduler_ref else None)

    def job_dns_rollup() -> None:
        dns_rollup(cfg, conn)

    def job_housekeeping() -> None:
        housekeeping(cfg, conn)

    def job_dns_retry() -> None:
        # SPEC-GAP: a transient port-53 conflict at boot (ICS/HNS, a previous instance still
        # shutting down) must self-heal; the resolver is retried until it binds.
        sched = scheduler_ref() if scheduler_ref else None
        rt = getattr(sched, "runtime", None) if sched is not None else None
        if rt is not None and cfg.dns.enabled:
            rt.retry_dns()

    def job_digest() -> None:
        send_digest(cfg, conn)

    def job_host() -> None:
        scan_host(cfg, conn)
        scan_wifi(cfg, conn)  # SPEC-GAP: no wifi job in §13; it rides along with host.

    jobs = [
        Job("feeds", hours(cfg.schedule.feeds_hours), job_feeds, description="Update threat-intel feeds and blocklists"),
        Job("discovery", cfg.schedule.discovery_minutes * 60, lambda: scan_discovery(cfg, conn),
            description="Discover LAN devices (ARP + TCP sweep)"),
        Job("services", hours(cfg.schedule.services_hours), lambda: scan_services(cfg, conn, quick=False),
            description="Service scan of online devices"),
        Job("vulns", hours(cfg.schedule.services_hours), lambda: scan_vulns(cfg, conn),
            description="Match services against KEV / NVD / EPSS"),
        # SPEC addendum C6: after discovery (and after services, so the providers a device offers
        # are known the first time the graph is built rather than six hours later).
        Job("topology", hours(TOPOLOGY_JOB_HOURS), lambda: scan_topology(cfg, conn),
            description="Dependency map, outage history and blast radius"),
        Job("host", hours(cfg.schedule.host_hours), job_host, description="Host posture, Defender, updates, persistence, Wi-Fi"),
        Job("exposure", hours(cfg.schedule.exposure_hours), lambda: scan_exposure(cfg, conn),
            description="WAN exposure: public IP, InternetDB, UPnP", budget_sec=10 * 60),
        Job("files", hours(24), lambda: scan_files(cfg, conn), description="Hash and look up new downloads"),
        Job("dns_rollup", hours(1), job_dns_rollup, description="DNS query log rollup and retention"),
        Job("score", hours(1), job_score, description="Record security score and SOC health"),
        # SPEC-GAP: §13 has no retention job, but metrics/events/sightings grow without bound.
        Job("housekeeping", hours(24), job_housekeeping, description="Purge old telemetry rows and checkpoint the database"),
        Job("dns_retry", 5 * 60, job_dns_retry, run_at_start=False, description="Re-bind the DNS resolver after a port conflict"),
        # Manual-only entries so the dashboard's buttons map onto scheduler.run_now().
        Job("quick", 0, lambda: run_scan(cfg, conn, QUICK_STEPS, quick=True), description="Quick scan"),
        Job("full", 0, lambda: run_scan(cfg, conn, SCAN_STEPS), description="Full scan", budget_sec=3 * 3600),
        Job("device_scan", 0, lambda: run_device_scan(cfg, conn), description="Service scan of one device (dashboard)"),
    ]
    if 0 <= cfg.notify.digest_hour <= 23:
        jobs.append(Job("digest", hours(24), job_digest, run_at_start=False, at_hour=cfg.notify.digest_hour,
                        description="Daily digest notification"))
    if manual_only:
        jobs = [Job(j.name, 0, j.func, run_at_start=False, at_hour=None, description=j.description,
                    budget_sec=j.budget_sec) for j in jobs]
    return jobs


def dns_rollup(cfg: Config, conn: sqlite3.Connection) -> None:
    """Hourly DNS housekeeping: querylog.maintenance (rollup + retention purge) plus the
    dns.qps metric, derived here from dns_queries because the query log has no metric hook."""
    querylog = _lazy("querylog")
    if querylog is not None:
        try:
            querylog.maintenance(cfg, conn)
        except Exception:
            logger.exception("dns querylog maintenance failed")
    row = db.one(conn, "SELECT COUNT(*) AS n FROM dns_queries WHERE ts >= ?", (util.iso_ago(hours=1),))
    total = int(row["n"]) if row else 0
    if total or cfg.dns.enabled:
        db.record_metric(conn, "dns.qps", round(total / 3600.0, 4))


# Retention per table (days). SPEC-GAP: the spec only defines retention for dns_queries.
RETENTION_DAYS: dict[str, int] = {
    "metrics": 90, "events": 30, "device_sightings": 30, "notifications": 90, "scans": 90, "finding_events": 90,
}


def housekeeping(cfg: Config, conn: sqlite3.Connection) -> dict[str, int]:
    """Purge rows nobody will look at again and give the WAL file back to the OS.

    Sightings keep the latest row per device (the Devices page needs "last seen"), and finding
    events only go once their finding has been resolved for the retention period.
    """
    purged: dict[str, int] = {}
    for table in ("metrics", "events", "notifications", "scans"):
        column = "started_at" if table == "scans" else "ts"
        try:
            purged[table] = db.purge_older_than(conn, table, column, util.iso_ago(days=RETENTION_DAYS[table]))
        except (sqlite3.Error, ValueError):
            logger.exception("housekeeping: purge of %s failed", table)
    try:
        with db.transaction(conn):
            cur = conn.execute(
                "DELETE FROM device_sightings WHERE seen_at < ? AND id NOT IN "
                "(SELECT MAX(id) FROM device_sightings GROUP BY device_id)",
                (util.iso_ago(days=RETENTION_DAYS["device_sightings"]),),
            )
            purged["device_sightings"] = int(cur.rowcount)
        with db.transaction(conn):
            cur = conn.execute(
                "DELETE FROM finding_events WHERE at < ? AND finding_row_id IN "
                "(SELECT id FROM findings WHERE status = 'resolved' AND resolved_at < ?)",
                (util.iso_ago(days=RETENTION_DAYS["finding_events"]), util.iso_ago(days=RETENTION_DAYS["finding_events"])),
            )
            purged["finding_events"] = int(cur.rowcount)
    except sqlite3.Error:
        logger.exception("housekeeping: purge failed")
    try:
        # Lens pairing rate-limit counters nobody is counting any more (SPEC addendum B4).
        purged["lens_claim_counters"] = db.lens_purge_claim_counters(conn)
    except sqlite3.Error:
        logger.exception("housekeeping: purge of Lens rate-limit counters failed")
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error as exc:
        logger.debug("wal_checkpoint skipped: %s", exc)
    total = sum(purged.values())
    if total:
        db.record_event(conn, "info", "cli", f"housekeeping purged {total} rows", purged)
    return purged


_DEVICE_SCAN_QUEUE: list[int] = []
_DEVICE_SCAN_LOCK = threading.Lock()


def queue_device_scan(device_id: int) -> bool:
    """Remember which device the dashboard asked for; the ``device_scan`` job drains the queue.
    Returns False when that device is already waiting."""
    with _DEVICE_SCAN_LOCK:
        if device_id in _DEVICE_SCAN_QUEUE:
            return False
        _DEVICE_SCAN_QUEUE.append(int(device_id))
        return True


def run_device_scan(cfg: Config, conn: sqlite3.Connection) -> dict[str, Any]:
    """Scheduler job body for "Scan this device now": serialised with every other job, so it can
    never overlap the scheduled service scan on the same device."""
    with _DEVICE_SCAN_LOCK:
        ids = list(_DEVICE_SCAN_QUEUE)
        _DEVICE_SCAN_QUEUE.clear()
    if not ids:
        return {"kind": "services", "status": "skipped", "summary": {}, "errors": []}
    ports = importlib.import_module("homesoc.scanners.ports")
    parts: list = []
    for device_id in ids:
        def call(device_id: int = device_id) -> ScanResult:
            return ports.scan_device(cfg, conn, device_id, progress=_progress_logger("services"))

        parts.append(("services", call, None))
    result = run_step(cfg, conn, "services", parts)
    scan_vulns(cfg, conn)
    return result


def send_digest(cfg: Config, conn: sqlite3.Connection) -> None:
    counts_fn = _lazy("counts")
    counts = counts_fn(conn) if counts_fn else fallback_counts(conn)
    open_counts = counts.get("open", {}) if isinstance(counts, dict) else {}
    top = list_findings_safe(conn, status="open", limit=5)
    score = _lazy("security_score")
    subject = f"{cfg.general.name} daily digest"
    if score is not None:
        subject += f" — score {score(conn)}"
    try:
        channels = importlib.import_module("homesoc.notify.channels")
        # Titles and subjects carry LAN-chosen text (hostnames, banners, UPnP descriptions), and
        # rows stored before the catalog flattened them still hold CR/LF, U+2028 and bidi
        # controls. The finding lines come from the notify package's own formatter, the one place
        # that sanitises them, never from a hand-built f-string here: a raw newline forged a
        # "[CRITICAL] ..." line in Discord, ntfy and the webhook. `findings` gives the webhook
        # the slimmed (also sanitised) list.
        body = "Open findings: " + ", ".join(f"{s} {open_counts.get(s, 0)}" for s in SEVERITIES)
        if top:
            body += "\n" + channels.format_findings_body(top)
        channels.send(cfg, conn, subject, body, severity="info", findings=top)
    except Exception:
        logger.exception("digest could not be sent")


# ----------------------------------------------------------- read helpers


def list_findings_safe(conn: sqlite3.Connection, *, status: str | None = None, severity: str | None = None,
                       limit: int = 500) -> list[dict[str, Any]]:
    """findings.engine.list_findings when present, else a direct query — so `status`,
    `findings` and `export` work before that package lands."""
    list_findings = _lazy("list_findings")
    if list_findings is not None:
        try:
            return [dict(f) for f in list_findings(conn, status=status, severity=severity, limit=limit)]
        except Exception:
            logger.exception("findings.engine.list_findings failed; using direct query")
    sql = "SELECT * FROM findings WHERE 1=1"
    params: list[Any] = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    sql += " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)
    rows = db.rows_to_dicts(db.query(conn, sql, params))
    rows.sort(key=lambda r: severity_rank(r.get("severity")))
    return rows


def fallback_counts(conn: sqlite3.Connection) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for row in db.query(conn, "SELECT status, severity, COUNT(*) AS n FROM findings GROUP BY status, severity"):
        out.setdefault(str(row["status"]), {})[str(row["severity"])] = int(row["n"])
    return out


#: Mirrors homesoc.findings.score (see that module's docstring for the reasoning). Duplicated on
#: purpose: this is the formula the CLI uses when the findings package is not importable, so it
#: cannot import the constants it is standing in for. Keep the two in step.
FALLBACK_WEIGHTS = {"critical": 30.0, "high": 12.0, "medium": 5.0, "low": 1.5, "info": 0.0}
FALLBACK_STATUS_FACTORS = {"open": 1.0, "acknowledged": 0.25}
FALLBACK_DECAY = 0.5
FALLBACK_HALF_LIFE = 60.0
GRADE_BANDS: tuple[tuple[int, str], ...] = ((80, "A"), (65, "B"), (50, "C"), (35, "D"))


def fallback_score(conn: sqlite3.Connection) -> int:
    """Same formula as findings.score.security_score, for use before that module exists.

    Diminishing returns per finding type, a quarter price for acknowledged findings, a halving
    curve instead of a subtraction, and hard ceilings when something critical or high is open.
    """
    groups: dict[str, list[float]] = {}
    open_critical = open_high = 0
    rows = db.query(
        conn,
        "SELECT finding_id, severity, status, COUNT(*) AS n FROM findings "
        "WHERE status IN ('open','acknowledged') GROUP BY finding_id, severity, status",
    )
    for row in rows:
        severity, status, n = str(row["severity"]), str(row["status"]), int(row["n"])
        weight = FALLBACK_WEIGHTS.get(severity, 0.0) * FALLBACK_STATUS_FACTORS.get(status, 0.0)
        if weight > 0 and n > 0:
            groups.setdefault(str(row["finding_id"]), []).extend([weight] * min(n, 64))
        if status == "open" and severity == "critical":
            open_critical += n
        elif status == "open" and severity == "high":
            open_high += n
    penalty = 0.0
    for weights in groups.values():
        weights.sort(reverse=True)
        penalty += sum(w * FALLBACK_DECAY ** i for i, w in enumerate(weights))
    value = 100.0 * (FALLBACK_DECAY ** (penalty / FALLBACK_HALF_LIFE))
    if open_critical >= 2:
        value = min(value, 20.0)
    elif open_critical == 1:
        value = min(value, 34.0)
    elif open_high:
        value = min(value, 79.0)
    return int(round(max(0.0, min(100.0, value))))


def _score_breakdown_safe(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """findings.score.score_breakdown, or [] when that package is not importable."""
    breakdown = _lazy("score_breakdown")
    if breakdown is None:
        return []
    try:
        return [dict(row) for row in breakdown(conn)]
    except Exception:
        logger.exception("score_breakdown failed")
        return []


def score_breakdown_lines(conn: sqlite3.Connection, limit: int = SCORE_BREAKDOWN_LIMIT) -> list[str]:
    """"Costing you the most" lines for `status`; empty when the breakdown is unavailable."""
    rows = [r for r in _score_breakdown_safe(conn) if r.get("penalty", 0)]
    if not rows:
        return []
    lines = ["costing the most points:"]
    for row in rows[:limit]:
        title = str(row.get("title") or row["finding_id"])
        if len(title) > 44:
            title = title[:41] + "..."
        count = f" x{row['count']}" if int(row.get("count", 1)) > 1 else ""
        lines.append(f"  {str(row['finding_id']):13} {title:44}{count:5} "
                     f"fixing it: +{int(row.get('score_gain', 0))}")
    return lines


def current_score(conn: sqlite3.Connection) -> int:
    score = _lazy("security_score")
    if score is not None:
        try:
            return int(score(conn))
        except Exception:
            logger.exception("security_score failed; using fallback")
    return fallback_score(conn)


def grade(score: int) -> str:
    """Letter for a score; delegates so the CLI can never disagree with the dashboard."""
    score_module = _lazy("security_score")
    if score_module is not None:
        try:
            from homesoc.findings.score import grade as _grade

            return _grade(int(score))
        except Exception:  # pragma: no cover - the fallback bands below are the same numbers
            logger.exception("findings.score.grade failed; using the built-in bands")
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


# --------------------------------------------------------------- runtime


@dataclass
class Runtime:
    """Everything `run` keeps alive: scheduler, optional resolver, Flask app."""

    cfg: Config
    conn: sqlite3.Connection
    scheduler: Scheduler | None = None
    dns_server: Any = None

    def start(self, *, with_scheduler: bool = True, with_dns: bool | None = None,
              manual_only: bool = False) -> None:
        db.abort_stale_scans(self.conn)
        if with_scheduler:
            holder: list[Scheduler | None] = [None]
            jobs = build_jobs(self.cfg, self.conn, lambda: holder[0], manual_only=manual_only)
            self.scheduler = Scheduler(self.cfg, self.conn, jobs)
            self.scheduler.runtime = self  # type: ignore[attr-defined]  # lets the dns_retry job reach start_dns
            holder[0] = self.scheduler
            self.scheduler.start()
        if with_dns if with_dns is not None else self.cfg.dns.enabled:
            self.start_dns()

    def start_dns(self) -> bool:
        """Bind the resolver; False (and the server's NET-DNS-002) when the port is taken."""
        dns_cls = _lazy("DnsServer")
        if dns_cls is None:
            return False
        try:
            if self.dns_server is None:
                self.dns_server = dns_cls(self.cfg, self.conn)
            ok = bool(self.dns_server.start())
        except Exception:
            logger.exception("DNS server failed to start; continuing without it")
            self.dns_server = None
            return False
        if not ok:
            logger.error("DNS filter could not bind %s:%d: %s", self.cfg.dns.listen, self.cfg.dns.port,
                         getattr(self.dns_server, "last_error", "unknown error"))
            return False
        logger.info("DNS filter listening on %s:%d", self.cfg.dns.listen, self.cfg.dns.port)
        return True

    def retry_dns(self) -> bool:
        """Periodic job: re-bind if the resolver is enabled but not running."""
        if self.dns_server is not None and getattr(self.dns_server, "running", False):
            return True
        return self.start_dns()

    def stop(self) -> None:
        if self.scheduler is not None:
            self.scheduler.stop()
        if self.dns_server is not None:
            try:
                self.dns_server.stop()
            except Exception:
                logger.exception("DNS server stop failed")
        db.record_event(self.conn, "info", "cli", "Home SOC stopped")


#: Seconds a new HTTPS connection gets to finish its TLS handshake. It runs in the connection's
#: own thread, so a peer that connects and says nothing only ever ties up itself.
TLS_HANDSHAKE_TIMEOUT = 10.0
#: Seconds a connection may sit silent (between keep-alive requests, or mid-request) before it
#: is closed, so stalled clients cannot hold threads forever. Handler run time does not count.
CONNECTION_IDLE_TIMEOUT = 120.0


def build_tls_context(cert: Path | str, key: Path | str) -> Any:
    """Server-side TLS context: TLS 1.2 or newer, with the Lens certificate."""
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    return context


def make_dashboard_server(app: Any, host: str, port: int, *, ssl_context: Any = None) -> Any:
    """The threaded Werkzeug server the dashboard and Lens run on, made safe to face the LAN.

    Werkzeug's own ``ssl_context`` support wraps the *listening* socket, so the TLS handshake of
    every new connection runs inside ``accept()`` on the single serving thread, with no timeout:
    one device that opens a TCP connection and never sends a ClientHello froze the dashboard and
    every paired phone for as long as it liked. Here the listener stays a plain socket, each
    accepted connection is wrapped with ``do_handshake_on_connect=False``, and the handshake runs
    in that connection's worker thread under TLS_HANDSHAKE_TIMEOUT. Every connection, plain or
    TLS, then gets CONNECTION_IDLE_TIMEOUT.
    """
    import ssl

    from werkzeug.serving import ThreadedWSGIServer, WSGIRequestHandler

    class _RequestHandler(WSGIRequestHandler):
        def log_error(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            if format.startswith("Request timed out"):  # an idle keep-alive closed: routine
                logger.debug("closed idle connection from %s", self.client_address[0])
                return
            super().log_error(format, *args)

    class _DashboardServer(ThreadedWSGIServer):
        def get_request(self) -> tuple[Any, Any]:
            sock, address = self.socket.accept()
            if self.ssl_context is not None:
                sock = self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            return sock, address

        def finish_request(self, request: Any, client_address: Any) -> None:
            if isinstance(request, ssl.SSLSocket):
                request.settimeout(TLS_HANDSHAKE_TIMEOUT)
                try:
                    request.do_handshake()
                except (OSError, ValueError) as exc:  # timeout, reset, not TLS, bad version
                    logger.debug("TLS handshake with %s failed: %s", client_address[0], exc)
                    return
            request.settimeout(CONNECTION_IDLE_TIMEOUT)
            super().finish_request(request, client_address)

    server = _DashboardServer(host, port, app, _RequestHandler)
    server.ssl_context = ssl_context  # read by the request handler for the URL scheme
    return server


#: Overrides an intruder on an open dashboard would plant (Settings page): where the house's DNS
#: goes, which blocklists apply, where alerts go, who is scanned, and the dashboard's own
#: bind and credential. Finding one when the policy has to generate a token means the
#: dashboard may already have been used by someone else.
TAMPER_SIGNAL_KEYS: tuple[str, ...] = (
    "web.", "notify.", "dns.upstreams", "dns.doh_upstream", "dns.lists", "dns.listen", "dns.enabled",
    "network.exclude",
)


def _tamper_signals(cfg: Config, conn: sqlite3.Connection) -> list[str]:
    """Reasons to believe an exposed, token-less dashboard was already used by someone else."""
    reasons: list[str] = []
    try:
        previous = str(db.get_setting(conn, BIND_SETTING, "") or "")
    except sqlite3.Error:
        previous = ""
    if previous and ":" in previous and not config.is_loopback_host(previous.rpartition(":")[0]):
        reasons.append(f"it was last started listening on {previous}")
    try:
        paired = len(db.lens_active_tokens(conn))
    except sqlite3.Error:
        paired = 0
    if paired:
        reasons.append(f"{paired} Lens phone token(s) are active")
    try:
        stored = config.overrides(conn)
    except sqlite3.Error:
        stored = {}
    planted = sorted(k for k in stored if k.startswith(TAMPER_SIGNAL_KEYS))
    if planted:
        reasons.append("Settings-page overrides exist for " + ", ".join(planted))
    return reasons


def enforce_bind_policy(cfg: Config, conn: sqlite3.Connection, host: str | None = None) -> Config | None:
    """The LAN exposure policy, applied before anything is built from ``cfg``.

    Loopback: ``cfg`` unchanged, whatever the token (only this machine can connect).
    Exposed with no token: a random token is generated, stored as the ``web.token`` override so
    it survives restarts (the database is owner-only), and the returned Config carries it, so
    the scheduler, SOC health and the dashboard all see the same credential. There is no "no
    token on the LAN" setting: the documented alternative is loopback plus Tailscale Serve.
    Exposed with a short token: None after saying exactly what to change (callers exit
    EXIT_USAGE), because a hand-picked PIN falls to the rate-limited guesser within a day.
    """
    bind = host if host is not None else cfg.web.host
    web = dataclasses.replace(cfg.web, host=bind)
    problem = config.lan_bind_problem(web)
    if problem is None:
        return cfg
    if problem == "weak-token":
        emit(f"Refusing to listen on {bind or 'every interface'}: web.token is only {len(web.token)} characters, "
             "and anyone on the network could guess it.")
        emit(f"Use a random token of at least {config.MIN_TOKEN_LENGTH} characters, for example the output of")
        emit('  python -c "import secrets; print(secrets.token_urlsafe(24))"')
        emit(f"in [web] token of {paths.config_path()}, then remove any Settings-page value with")
        emit("  python -m homesoc config unset web.token")
        emit("Or remove web.token from both places and Home SOC generates a strong one itself, or keep the")
        emit("dashboard on 127.0.0.1 (see docs/LENS_SETUP.md for the Tailscale route).")
        logger.error("refused to bind the dashboard to %s: web.token is shorter than %d characters",
                     bind, config.MIN_TOKEN_LENGTH)
        return None
    # problem == "no-token"
    reasons = _tamper_signals(cfg, conn)
    token = secrets.token_urlsafe(32)
    try:
        config.set_override(conn, "web.token", token)
        stored = True
    except (sqlite3.Error, ValueError):
        logger.exception("could not store the generated web.token; it lasts until this process stops")
        stored = False
    emit(f"This dashboard is reachable from your network ({bind or 'every interface'}) and had no web.token,")
    emit("so Home SOC generated one" + (" and saved it in its database." if stored else " for this run only."))
    emit("Every device, this one included, now needs it: use the Dashboard link printed below once and")
    emit("the browser remembers it. To choose your own token instead, set [web] token (16+ characters)")
    emit(f"in {paths.config_path()} and run: python -m homesoc config unset web.token")
    if reasons:
        emit("")
        emit("WARNING: this dashboard may already have been open to the network without a password:")
        for reason in reasons:
            emit(f"  - {reason}")
        emit("Anyone on the network could have changed settings or paired a phone. Review and clean up:")
        emit("  python -m homesoc lens revoke --all")
        emit("  python -m homesoc config overrides      (then: config unset <key> for anything you did not set)")
    logger.warning("dashboard exposed on %s without web.token: generated one%s", bind,
                   " (possible prior use by others: " + "; ".join(reasons) + ")" if reasons else "")
    try:
        db.record_event(conn, "warning", "cli", "generated web.token for a LAN-facing dashboard",
                        {"host": bind, "stored": stored, "signals": reasons})
    except sqlite3.Error:
        pass
    return config.with_overrides(cfg, {"web.token": token})


def _serve_forever(rt: Runtime, host: str, port: int, *, tls: bool = False) -> int:
    create_app = _lazy("create_app")
    if create_app is None:
        emit("The web package is not available; cannot start the dashboard.")
        return EXIT_ERROR
    ssl_context: Any = None
    if tls:
        try:
            cert, key = ensure_lens_cert(rt.cfg, host=host)
            ssl_context = build_tls_context(cert, key)
        except Exception as exc:  # TlsUnavailable, OSError/SSLError, or a missing web package
            emit(str(exc))
            return EXIT_ERROR
        fingerprint = lens_cert_fingerprint(cert)
        logger.info("HTTPS enabled with %s (SHA-256 %s)", cert, fingerprint or "unknown")
        emit(f"Certificate: {cert}")
        emit(f"  SHA-256 fingerprint: {fingerprint or 'unavailable'}")
        emit("  Self-signed: the phone warns once, then remembers. Check the fingerprint matches.")
    # Last line of the LAN exposure policy: whatever the caller did (or forgot), nothing listens
    # beyond loopback without a strong token. cmd_serve/cmd_run have already run
    # enforce_bind_policy, so reaching this means a new caller skipped it.
    problem = config.lan_bind_problem(dataclasses.replace(rt.cfg.web, host=host))
    if problem is not None:
        emit(f"Refusing to start the dashboard on {host or 'every interface'}: "
             + ("web.token is empty" if problem == "no-token" else "web.token is too short")
             + ", so anyone on the network could use it. Set a random token of at least "
             f"{config.MIN_TOKEN_LENGTH} characters, or listen on 127.0.0.1.")
        logger.error("refused to bind the dashboard to %s (%s)", host, problem)
        return EXIT_USAGE
    record_tls_state(rt.conn, tls)
    record_bind_state(rt.conn, host, port)
    app = create_app(rt.cfg, rt.conn, scheduler=rt.scheduler, dns_server=rt.dns_server)
    emit(f"Dashboard: {dashboard_url(rt.cfg, host, port, tls=tls)}  (Ctrl-C to stop)")
    try:
        server = make_dashboard_server(app, host, port, ssl_context=ssl_context)
    except (OSError, SystemExit) as exc:  # Werkzeug reports a failed bind as SystemExit(1)
        logger.error("cannot bind dashboard on %s:%d: %s", host, port, exc)
        return EXIT_ERROR
    server.serve_forever()  # returns on Ctrl-C / SIGTERM and closes the socket itself
    return EXIT_OK


def dashboard_url(cfg: Config, host: str | None = None, port: int | None = None, *,
                  tls: bool = False) -> str:
    """The one link the user needs: /login?token=... when a token is set, so the browser gets the
    cookie once and the token never has to be typed."""
    host = host or cfg.web.host
    port = port or cfg.web.port
    shown = util.default_interface_ip() if host in ("0.0.0.0", "::") else host
    base = f"{'https' if tls else 'http'}://{shown}:{port}"
    return f"{base}/login?token={cfg.web.token}" if cfg.web.token else f"{base}/"


# ------------------------------------------------------------------- lens
#
# Transport and pairing helpers shared by `serve --tls`, `run --tls` and the `lens`
# commands. The certificate and QR code live in the web package (homesoc.web.tls and
# homesoc.web.qr); the tokens live in homesoc.db as lens_* helpers.

#: Addresses that mean "every interface" to a socket and nothing to a certificate or a URL.
WILDCARD_HOSTS: tuple[str, ...] = ("0.0.0.0", "::", "[::]")


def _web_module(name: str) -> Any:
    """Import ``homesoc.web.<name>`` on demand, or None with one clear log line."""
    try:
        return importlib.import_module(f"homesoc.web.{name}")
    except Exception as exc:
        logger.warning("homesoc.web.%s is not available (%s: %s)", name, type(exc).__name__, exc)
        return None


def lens_hosts(cfg: Config, host: str | None = None) -> list[str]:
    """Every name and address the phone might use to reach this machine.

    These become the certificate's subjectAltNames, so a browser accepts the URL whether
    the owner typed the LAN address, the hostname or ``localhost``.
    """
    hosts: list[str] = []
    for candidate in (host or cfg.web.host, util.default_interface_ip(), util.local_hostname()):
        value = str(candidate or "").strip()
        if value and value not in WILDCARD_HOSTS and value not in hosts:
            hosts.append(value)
    name = util.local_hostname()
    if name and f"{name}.local" not in hosts:
        hosts.append(f"{name}.local")
    return hosts


def lens_display_host(cfg: Config, host: str | None = None) -> str:
    """The address to put in a link: the bind address, or this machine's LAN address for 0.0.0.0."""
    value = str(host or cfg.web.host or "").strip()
    return util.default_interface_ip() if value in WILDCARD_HOSTS or not value else value


def ensure_lens_cert(cfg: Config, *, host: str | None = None, force: bool = False,
                     hosts: list[str] | None = None) -> tuple[Path, Path]:
    """Certificate and key for ``--tls``, generated on first use.

    Raises with an actionable message when the web package or ``cryptography`` is absent —
    the caller prints it verbatim.
    """
    tls = _web_module("tls")
    if tls is None:
        raise RuntimeError("homesoc.web.tls is not available in this install; reinstall Home SOC.")
    return tls.ensure_cert(hosts if hosts is not None else lens_hosts(cfg, host), force=force)


def lens_cert_fingerprint(cert: Path | str) -> str:
    """SHA-256 fingerprint of a certificate, or "" when it cannot be read."""
    tls = _web_module("tls")
    if tls is None:
        return ""
    try:
        return str(tls.cert_fingerprint_sha256(cert))
    except (OSError, ValueError) as exc:
        logger.warning("cannot fingerprint %s: %s", cert, exc)
        return ""


def lens_pair_url(cfg: Config, code: str, *, host: str | None = None, port: int | None = None,
                  scheme: str = "https") -> str:
    """``https://<lan-host>:<port>/lens/claim#c=<code>`` (SPEC B4).

    The code sits in the fragment, which browsers never send to the server and no proxy or
    log ever sees; the claim page reads it with JavaScript and POSTs it.
    """
    return (f"{scheme}://{lens_display_host(cfg, host)}:{int(port or cfg.web.port)}"
            f"/lens/claim#c={code}")


#: Settings key recording whether the dashboard was last started with ``--tls``. A scan
#: run from a second terminal has no other way to know, and "never started with TLS" is
#: the safe reading when the key is absent.
TLS_SETTING = "lens.tls"

#: Settings key recording the address the dashboard was last actually bound to, as
#: ``host:port``. ``serve --host/--port`` override ``config.toml``, so config alone cannot
#: answer "can a phone reach this?" — see :func:`homesoc.web.app.effective_bind`. Absence
#: means "fall back to config", which is how this behaved before the key existed.
BIND_SETTING = "lens.bind"


def record_tls_state(conn: sqlite3.Connection, enabled: bool) -> None:
    try:
        db.set_setting(conn, TLS_SETTING, bool(enabled))
    except sqlite3.Error:
        logger.debug("could not record the TLS state", exc_info=True)


def record_bind_state(conn: sqlite3.Connection, host: str, port: int) -> None:
    """Remember where the server is really listening, for /lens/pair's preflight."""
    try:
        db.set_setting(conn, BIND_SETTING, f"{host}:{int(port)}")
    except (sqlite3.Error, TypeError, ValueError):
        logger.debug("could not record the bind address", exc_info=True)


def tls_last_used(conn: sqlite3.Connection) -> bool:
    try:
        return str(db.get_setting(conn, TLS_SETTING, "") or "").lower() == "true"
    except sqlite3.Error:
        return False


def recorded_bind(conn: sqlite3.Connection | None, cfg: Config) -> tuple[str, int]:
    """Where the server is really listening: the recorded bind, else config.

    The CLI half of :func:`homesoc.web.app.effective_bind`, and it has to agree with it.
    ``serve --tls --host 0.0.0.0 --port 8443`` is the invocation SPEC B3 documents, and it
    overrides ``config.toml`` for the life of that process — so reading ``web.host`` alone
    made ``lens pair`` refuse ("web.host is 127.0.0.1") against a server the phone can
    already reach, while ``/lens/pair`` in the browser minted a code quite happily.
    Absence of the key means "fall back to config", which is how this read before it existed.
    """
    host = str(cfg.web.host or "127.0.0.1")
    port = int(cfg.web.port or 8787)
    if conn is None:
        return host, port
    try:
        raw = str(db.get_setting(conn, BIND_SETTING, "") or "")
    except sqlite3.Error:
        return host, port
    if raw and ":" in raw:
        bound_host, _, bound_port = raw.rpartition(":")
        if bound_host:
            host = bound_host
        if bound_port.isdigit():
            port = int(bound_port)
    return host, port


def qr_ascii(payload: str, *, invert: bool = False, quiet_zone: int = 2) -> str | None:
    """The payload as a terminal QR code, or None when the encoder is unavailable.

    Block characters are used when the console can encode them and ``#`` when it cannot
    (a stock Windows console is code page 850); a code made of replacement characters
    would be unscannable, which is worse than a plain warning.
    """
    qr = _web_module("qr")
    if qr is None:
        return None
    dark, light = ("  ", "██") if invert else ("██", "  ")
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "".join((dark, light)).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        dark, light = ("  ", "##") if invert else ("##", "  ")
    try:
        return str(qr.encode(payload).to_ascii(quiet_zone=quiet_zone, dark=dark, light=light))
    except Exception as exc:
        logger.warning("could not render the pairing QR: %s", exc)
        return None


def _install_signal_handlers() -> None:
    def _raise_interrupt(signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _raise_interrupt)
        except (ValueError, OSError):  # not main thread / unsupported on this platform
            pass


# -------------------------------------------------------------- commands


@dataclass
class Context:
    args: argparse.Namespace
    cfg: Config
    conn: sqlite3.Connection


def cmd_init(ctx: Context) -> int:
    data = paths.data_dir()
    paths.feeds_dir()
    paths.logs_dir()
    cfg_path = paths.config_path()
    if cfg_path.exists():
        emit(f"config: {cfg_path} (kept)")
    else:
        # SPEC-GAP: the example ships with an empty token; a real install gets a random one so the
        # dashboard is never usable by a page that DNS-rebinds to 127.0.0.1:8787 (Host validation
        # is the first line, the token the second). The login link is printed by `run`.
        token = secrets.token_urlsafe(24)
        text = config.EXAMPLE_TOML.replace('token = ""', f'token = "{token}"', 1)
        util.atomic_write_text(cfg_path, text)
        ctx.cfg = config.with_overrides(ctx.cfg, {"web.token": token})
        emit(f"config: {cfg_path} (created from example with a random web.token - edit it to taste)")
    db.init_schema(ctx.conn)
    emit(f"database: {paths.db_path()} (schema v{db.schema_version(ctx.conn)})")
    db.record_event(ctx.conn, "info", "cli", "initialised", {"data_dir": str(data), "version": __version__})
    if not ctx.args.no_feeds:
        emit("downloading first feeds (oui, kev) ...")
        try:
            statuses = run_feeds(ctx.cfg, ctx.conn, ["oui", "kev"])
        except Exception as exc:
            emit(f"feed update failed: {exc} (run 'python -m homesoc update' later)")
            statuses = {}
        for name, status in sorted(statuses.items()):
            emit(f"  {name}: {status}")
        if not statuses:
            emit("  (feeds package not available yet — skipped)")
    emit("")
    emit(f"Next: python -m homesoc run   (dashboard at {dashboard_url(ctx.cfg)})")
    return EXIT_OK


def cmd_update(ctx: Context) -> int:
    names = [n.strip() for n in ctx.args.feeds.split(",") if n.strip()] if ctx.args.feeds else None
    if _lazy("feeds_update") is None:
        emit("feeds package not available")
        return EXIT_ERROR
    try:
        statuses = run_feeds(ctx.cfg, ctx.conn, names, force=ctx.args.force)
    except Exception as exc:
        emit(f"feed update failed: {exc}")
        return EXIT_ERROR
    for name, status in sorted(statuses.items()):
        emit(f"{name:16} {status}")
    return EXIT_ERROR if statuses and all(s == "error" for s in statuses.values()) else EXIT_OK


def cmd_scan(ctx: Context) -> int:
    if ctx.args.only:
        steps = tuple(s.strip() for s in ctx.args.only.split(",") if s.strip())
        unknown = [s for s in steps if s not in SCAN_STEPS]
        if unknown:
            emit(f"unknown scan step(s): {', '.join(unknown)}; choose from {', '.join(SCAN_STEPS)}")
            return EXIT_USAGE
    else:
        steps = QUICK_STEPS if ctx.args.quick else SCAN_STEPS

    def report(step: str, result: dict[str, Any]) -> None:
        emit(f"{step:10} {result['status']}")
        for source, part in result.get("summary", {}).items():
            findings = part.get("findings") if isinstance(part, dict) else None
            detail = {k: v for k, v in part.items() if k not in ("findings",)} if isinstance(part, dict) else part
            emit(f"  {source}: {json.dumps(detail, default=str)}" + (f" findings={findings}" if findings else ""))

    db.abort_stale_scans(ctx.conn)
    result = run_scan(ctx.cfg, ctx.conn, steps, quick=ctx.args.quick, on_step=report)
    apply_soc_health(ctx.cfg, ctx.conn, None)
    emit(f"score: {current_score(ctx.conn)}")
    return EXIT_OK if result["status"] != "error" else EXIT_ERROR


def cmd_serve(ctx: Context) -> int:
    overrides: dict[str, Any] = {}
    if ctx.args.host:
        overrides["web.host"] = ctx.args.host
    if ctx.args.port:
        overrides["web.port"] = ctx.args.port
    cfg = config.with_overrides(ctx.cfg, overrides) if overrides else ctx.cfg
    # Before Runtime: the scheduler, SOC health and create_app must all see the final token.
    checked = enforce_bind_policy(cfg, ctx.conn)
    if checked is None:
        return EXIT_USAGE
    cfg = checked
    rt = Runtime(cfg, ctx.conn)
    # SPEC-GAP: "dashboard only" still needs a worker behind the Run buttons, so the scheduler
    # starts with every job manual-only (no timetable: nothing runs unless asked for).
    rt.start(with_scheduler=True, with_dns=False, manual_only=True)
    _install_signal_handlers()
    try:
        return _serve_forever(rt, cfg.web.host, cfg.web.port, tls=bool(getattr(ctx.args, "tls", False)))
    except KeyboardInterrupt:
        return EXIT_OK
    finally:
        rt.stop()


def cmd_dns(ctx: Context) -> int:
    overrides: dict[str, Any] = {"dns.enabled": True}
    if ctx.args.port:
        overrides["dns.port"] = ctx.args.port
    cfg = config.with_overrides(ctx.cfg, overrides)
    rt = Runtime(cfg, ctx.conn)
    if not rt.start_dns():
        emit("DNS server could not be started: " + str(getattr(rt.dns_server, "last_error", None) or "see log"))
        return EXIT_ERROR
    emit(f"DNS filter listening on {cfg.dns.listen}:{cfg.dns.port}  (Ctrl-C to stop)")
    _install_signal_handlers()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        return EXIT_OK
    finally:
        rt.stop()


def cmd_run(ctx: Context) -> int:
    # Before Runtime: the scheduler, SOC health and create_app must all see the final token.
    cfg = enforce_bind_policy(ctx.cfg, ctx.conn)
    if cfg is None:
        return EXIT_USAGE
    ctx.cfg = cfg
    rt = Runtime(cfg, ctx.conn)
    _install_signal_handlers()
    db.record_event(ctx.conn, "info", "cli", "Home SOC started", {"version": __version__, "platform": util.platform_name()})
    rt.start()
    try:
        return _serve_forever(rt, cfg.web.host, cfg.web.port,
                              tls=bool(getattr(ctx.args, "tls", False)))
    except KeyboardInterrupt:
        return EXIT_OK
    finally:
        rt.stop()


def cmd_status(ctx: Context) -> int:
    conn = ctx.conn
    score = current_score(conn)
    counts_fn = _lazy("counts")
    counts = counts_fn(conn) if counts_fn else fallback_counts(conn)
    open_counts = counts.get("open", {}) if isinstance(counts, dict) else {}
    emit(f"{ctx.cfg.general.name} {__version__}  data={paths.data_dir()}  config={ctx.cfg.source_path or '(defaults)'}")
    emit(f"score: {score} ({grade(score)})   open findings: " +
         ", ".join(f"{s} {open_counts.get(s, 0)}" for s in SEVERITIES))
    for line in score_breakdown_lines(conn):
        emit(line)
    devices = db.one(conn, "SELECT COUNT(*) AS total, SUM(online) AS online FROM devices")
    emit(f"devices: {int(devices['online'] or 0)} online / {int(devices['total'] or 0)} total")
    last = db.last_scans(conn)
    emit("last scans: " + (", ".join(f"{k} {util.human_age(v)}" for k, v in sorted(last.items())) or "none"))
    emit("")
    emit(f"{'feed':16} {'status':13} {'updated':12} {'entries':>8}  error")
    for row in db.query(conn, "SELECT * FROM feeds ORDER BY name"):
        emit(f"{row['name']:16} {row['status']:13} {util.human_age(row['last_updated']):12} "
             f"{row['entries'] if row['entries'] is not None else '-':>8}  {row['error'] or ''}")
    emit("")
    emit(f"{'job':12} {'last run':12} {'status':8} {'secs':>7} {'next run':20} {'runs':>5} {'fail':>5}")
    for row in db.query(conn, "SELECT * FROM jobs ORDER BY name"):
        emit(f"{row['name']:12} {util.human_age(row['last_run']):12} {row['last_status'] or '-':8} "
             f"{row['last_duration_sec'] if row['last_duration_sec'] is not None else '-':>7} "
             f"{row['next_run'] or '-':20} {row['runs']:>5} {row['failures']:>5}")
    return EXIT_OK


def cmd_findings(ctx: Context) -> int:
    rows = list_findings_safe(ctx.conn, status=ctx.args.status, severity=ctx.args.severity, limit=ctx.args.limit)
    if not rows:
        emit("no findings")
        return EXIT_OK
    emit(f"{'severity':9} {'id':13} {'status':12} {'last seen':11} {'subject':28} title")
    for f in rows:
        subject = str(f.get("subject", ""))[:28]
        emit(f"{str(f.get('severity')):9} {str(f.get('finding_id')):13} {str(f.get('status')):12} "
             f"{util.human_age(f.get('last_seen')):11} {subject:28} {f.get('title') or ''}")
    return EXIT_OK


def cmd_baseline(ctx: Context) -> int:
    """Accept the devices already on the network so only genuinely new ones raise an alert."""
    conn = ctx.conn
    baseline = _lazy("baseline_devices")
    if baseline is None:
        emit("baseline needs homesoc.findings.engine, which is not available here.")
        return EXIT_ERROR
    dry_run = bool(getattr(ctx.args, "dry_run", False))
    before = current_score(conn)
    try:
        result = baseline(conn, trust_all=True, dry_run=dry_run)
    except Exception:
        logger.exception("baseline failed")
        emit("baseline failed; see the log for details.")
        return EXIT_ERROR

    verb = "would trust" if dry_run else "trusted"
    closed = "would close" if dry_run else "closed"
    emit(f"devices known: {result.devices_total}")
    emit(f"{verb}: {len(result.trusted)}   already trusted: {len(result.already_trusted)}")
    for device in result.trusted[:BASELINE_LIST_LIMIT]:
        label = device.get("nickname") or device.get("hostname") or device.get("ip") or device.get("mac")
        emit(f"  {str(device.get('ip') or '-'):15} {str(device.get('mac') or '-'):18} {label}")
    if len(result.trusted) > BASELINE_LIST_LIMIT:
        emit(f"  ... and {len(result.trusted) - BASELINE_LIST_LIMIT} more")
    emit(f"{closed}: {len(result.resolved)} 'new device' findings (NET-DEV-001)")

    if dry_run:
        emit("")
        emit("dry run: nothing was written. Run `python -m homesoc baseline` to apply it.")
        return EXIT_OK

    db.record_event(
        conn, "info", "baseline",
        f"Baseline accepted: {len(result.trusted)} devices trusted, {len(result.resolved)} new-device findings closed",
        {"devices_total": result.devices_total, "trusted": len(result.trusted),
         "resolved": len(result.resolved)},
    )
    after = current_score(conn)
    emit("")
    emit(f"score: {before} ({grade(before)}) -> {after} ({grade(after)})")
    emit("From now on only a device that was not in this list is reported as new.")
    return EXIT_OK


def cmd_export(ctx: Context) -> int:
    conn = ctx.conn
    report = {
        "generated_at": util.utcnow_iso(),
        "version": __version__,
        "host": util.local_hostname(),
        "score": current_score(conn),
        "score_breakdown": _score_breakdown_safe(conn),
        "counts": (_lazy("counts") or fallback_counts)(conn),
        "findings": list_findings_safe(conn, limit=100000),
        "devices": db.rows_to_dicts(db.query(conn, "SELECT * FROM devices ORDER BY id")),
        "vulns": db.rows_to_dicts(db.query(conn, "SELECT * FROM vulns ORDER BY id")),
    }
    out = Path(ctx.args.out)
    util.atomic_write_text(out, json.dumps(report, indent=2, default=str))
    emit(f"wrote {out} ({len(report['findings'])} findings, {len(report['devices'])} devices, {len(report['vulns'])} vulns)")
    return EXIT_OK


def _web_helper(module: str, func: str) -> Any:
    """Import ``homesoc.web.<module>.<func>`` on demand.

    Separate from :func:`_lazy` on purpose: the web package is edited in parallel with this one,
    so a missing module, a syntax error mid-edit or a renamed function must all produce the same
    clear "not available" message rather than an import-time crash of the whole CLI.
    """
    try:
        mod = importlib.import_module(f"homesoc.web.{module}")
    except Exception as exc:
        logger.info("homesoc.web.%s is not available (%s: %s)", module, type(exc).__name__, exc)
        return None
    helper = getattr(mod, func, None)
    if helper is None:
        logger.warning("homesoc.web.%s has no attribute %r", module, func)
    return helper


# Accepted by `feed --since`: "30m", "24h", "7d", "2w" — or a plain ISO-8601 timestamp.
_SINCE_RE = re.compile(r"^(\d+)\s*([mhdw])$", re.IGNORECASE)
_SINCE_HOURS: dict[str, float] = {"m": 1 / 60.0, "h": 1.0, "d": 24.0, "w": 168.0}


def parse_since(value: str | None) -> str | None:
    """Turn ``--since`` into a UTC ISO timestamp. Raises ValueError on anything else."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    match = _SINCE_RE.match(text)
    if match:
        amount = int(match.group(1))
        return util.iso_ago(hours=amount * _SINCE_HOURS[match.group(2).lower()])
    parsed = util.parse_iso(text)
    if parsed is not None:
        return util.to_iso(parsed)
    raise ValueError(f"cannot read --since {value!r}; use 30m, 24h, 7d, 2w or an ISO timestamp")


def cmd_report(ctx: Context) -> int:
    """Addendum A4: the remediation summary as Markdown or JSON, dashboard-free."""
    fmt = ctx.args.format
    func = "remediation_report_json" if fmt == "json" else "remediation_report_markdown"
    build = _web_helper("summary", func)
    if build is None:
        emit(f"The report generator (homesoc.web.summary.{func}) is not available in this install; "
             "reinstall or update the web package, then try again.")
        return EXIT_ERROR
    days = max(1, int(ctx.args.days))
    try:
        produced = build(ctx.conn, days=days)
        text = json.dumps(produced, indent=2, default=str) if fmt == "json" else str(produced)
    except Exception as exc:
        logger.exception("report generation failed")
        emit(f"report generation failed: {type(exc).__name__}: {exc}")
        return EXIT_ERROR
    if ctx.args.out:
        out = Path(ctx.args.out)
        util.atomic_write_text(out, text if text.endswith("\n") else text + "\n")
        emit(f"wrote {out}  ({fmt}, {days}-day window, {len(text)} bytes)")
    else:
        emit(text)
    return EXIT_OK


def cmd_feed(ctx: Context) -> int:
    """Addendum A4: the activity feed as plain text, for the terminal."""
    build_feed = _web_helper("feed", "build_feed")
    if build_feed is None:
        emit("The activity feed (homesoc.web.feed.build_feed) is not available in this install; "
             "reinstall or update the web package, then try again.")
        return EXIT_ERROR
    try:
        since = parse_since(ctx.args.since)
    except ValueError as exc:
        emit(str(exc))
        return EXIT_USAGE
    kinds = {k.strip() for k in ctx.args.kinds.split(",") if k.strip()} if ctx.args.kinds else None
    limit = max(1, int(ctx.args.limit))
    try:
        produced = build_feed(ctx.conn, since=since, kinds=kinds, limit=limit)
    except Exception as exc:
        logger.exception("activity feed failed")
        emit(f"activity feed failed: {type(exc).__name__}: {exc}")
        return EXIT_ERROR
    items, total = produced if isinstance(produced, tuple) else (produced, None)
    items = list(items or [])
    if not items:
        emit("no activity yet" + (f" since {since}" if since else "") + " (the feed fills as scans run)")
        return EXIT_OK
    for item in items:
        get = (lambda key: item.get(key)) if isinstance(item, dict) else (lambda key: getattr(item, key, None))
        ts = str(get("ts") or "")
        emit(f"{ts:20} {str(get('severity') or ''):8} {str(get('kind') or ''):20} {str(get('title') or '')}")
        detail = str(get("detail") or "").strip()
        if detail:
            emit(f"{'':20} {'':8} {'':20} {detail}")
    if total is not None and int(total) > len(items):
        emit(f"... {int(total) - len(items)} older item(s) not shown (raise --limit)")
    return EXIT_OK


# ------------------------------------------------------- blast radius (addendum C)


def resolve_device(conn: sqlite3.Connection, needle: str) -> tuple[int | None, list[dict[str, Any]]]:
    """Find one device by IP, MAC or name.

    Returns ``(device_id, candidates)``: an id when exactly one device matches, otherwise None
    and the list of candidates so the caller can print them. Matching is deliberately ordered —
    an address is unambiguous, a name is not — and a name only falls back to a substring match
    when nothing matched it exactly, so "iPhone" asks which one rather than picking.
    """
    text = str(needle or "").strip()
    if not text:
        return None, []
    rows = db.rows_to_dicts(db.query(
        conn, "SELECT id, mac, ip, hostname, nickname, kind, online FROM devices ORDER BY id"))
    mac = text.lower().replace("-", ":")
    lowered = text.lower()
    for test in (
        lambda r: str(r["ip"] or "") == text,
        lambda r: str(r["mac"] or "").lower() == mac,
        lambda r: str(r["nickname"] or "").lower() == lowered,
        lambda r: str(r["hostname"] or "").lower() == lowered,
        lambda r: lowered in f"{r['nickname'] or ''} {r['hostname'] or ''}".lower(),
    ):
        matches = [r for r in rows if test(r)]
        if len(matches) == 1:
            return int(matches[0]["id"]), matches
        if len(matches) > 1:
            return None, matches
    return None, []


def cmd_blast(ctx: Context) -> int:
    """`python -m homesoc blast <device>` — what the house loses if this device fails."""
    graph = _lazy("topology_graph")
    if graph is None:
        emit("The dependency map (homesoc.topology) is not available in this install; "
             "reinstall or update Home SOC, then try again.")
        return EXIT_ERROR
    needle = str(getattr(ctx.args, "device", "") or "")
    device_id, candidates = resolve_device(ctx.conn, needle)
    if device_id is None:
        if candidates:
            emit(f"{len(candidates)} devices match {needle!r}; name one of these exactly, or use its IP:")
            for row in candidates[:BASELINE_LIST_LIMIT]:
                emit(f"  {str(row['ip'] or ''):15} {str(row['mac'] or ''):18} "
                     f"{str(row['nickname'] or row['hostname'] or '')}")
            return EXIT_USAGE
        emit(f"no device matches {needle!r} (try an IP, a MAC, or a nickname from: python -m homesoc status)")
        return EXIT_ERROR

    hours = int(getattr(ctx.cfg, "topology", None).hours) if getattr(ctx.cfg, "topology", None) else 168
    try:
        blast = graph.blast_radius(ctx.conn, device_id, hours=hours)
    except Exception as exc:
        logger.exception("blast radius failed")
        emit(f"could not work out the blast radius: {type(exc).__name__}: {exc}")
        return EXIT_ERROR
    if not blast:
        emit(f"no device with id {device_id}")
        return EXIT_ERROR

    device = blast["device"]
    emit(f"{device['label']}   {device['ip'] or ''}  {device['mac'] or ''}"
         f"{'' if device['online'] else '   (currently offline)'}")
    emit("")
    for line in _wrap(blast["headline"], 88):
        emit(line)
    emit("")
    _emit_blast_list("Goes offline", blast["offline"])
    _emit_blast_list("Keeps working, but degraded", blast["degraded"])
    if blast["services_lost"]:
        emit("Services lost")
        for item in blast["services_lost"]:
            emit(f"  - {item}")
        emit("")
    unaffected = blast["unaffected"]
    if unaffected:
        names = ", ".join(str(d["label"]) for d in unaffected[:8])
        more = f", and {len(unaffected) - 8} more" if len(unaffected) > 8 else ""
        emit(f"Unaffected ({len(unaffected)}): {names}{more}")
        emit("")
    emit(f"Confidence: {blast['confidence']}")
    if blast.get("evidence"):
        for line in _wrap(str(blast["evidence"]), 88):
            emit(f"  {line}")
    else:
        emit("  Nothing like this has been recorded yet, so this is worked out from the shape of the")
        emit("  network rather than from an outage Home SOC has watched happen.")
    if blast.get("resolution"):
        for line in _wrap(str(blast["resolution"]), 88):
            emit(f"  {line}")
    emit("")
    emit("  Home SOC cannot see traffic between devices - it has no packet visibility. These links")
    emit("  are what it has observed or can reasonably infer.")
    return EXIT_OK


def _emit_blast_list(title: str, items: list[dict[str, Any]]) -> None:
    if not items:
        return
    emit(f"{title} ({len(items)})")
    for item in items:
        emit(f"  - {item['label']}: {item.get('why') or ''}".rstrip(": "))
    emit("")


def _wrap(text: str, width: int) -> list[str]:
    words = str(text or "").split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]


def cmd_defender(ctx: Context) -> int:
    defender = _lazy("defender_module")
    if defender is None:
        emit("defender module not available")
        return EXIT_ERROR
    if ctx.args.quick_scan:
        ok = bool(defender.trigger_quick_scan(ctx.cfg))
        emit("quick scan started" if ok else "quick scan could not be started")
    else:
        ok = bool(defender.update_signatures(ctx.cfg))
        emit("signature update started" if ok else "signature update failed")
    return EXIT_OK if ok else EXIT_ERROR


# ------------------------------------------------------------ lens commands


def cmd_lens(ctx: Context) -> int:
    """Dispatch ``lens pair|tokens|revoke|cert`` (SPEC addendum B3)."""
    handlers: dict[str, Callable[[Context], int]] = {
        "pair": cmd_lens_pair,
        "tokens": cmd_lens_tokens,
        "revoke": cmd_lens_revoke,
        "cert": cmd_lens_cert,
    }
    action = str(getattr(ctx.args, "lens_command", "") or "")
    handler = handlers.get(action)
    if handler is None:  # argparse enforces this; belt and braces
        emit("usage: python -m homesoc lens {pair|tokens|revoke|cert}")
        return EXIT_USAGE
    return handler(ctx)


def cmd_lens_pair(ctx: Context) -> int:
    """Print the pairing URL, the QR code and the certificate fingerprint.

    Refuses before it can produce something that works, and says exactly what to change:
    a pairing code is only useful if Lens is switched on and reachable from the phone.
    """
    cfg = ctx.cfg
    if not cfg.lens.enabled:
        emit("Lens is switched off, so a pairing code would not work.")
        emit("  Turn it on:  set [lens] enabled = true in " + str(paths.config_path()))
        emit("               (or use the Settings page), then run this again.")
        return EXIT_ERROR

    bound_host, bound_port = recorded_bind(ctx.conn, cfg)
    host = getattr(ctx.args, "host", None) or bound_host
    port = int(getattr(ctx.args, "port", None) or bound_port)
    problems: list[str] = []
    if host in ("127.0.0.1", "localhost", "::1"):
        problems.append(
            f"web.host is {host}, which only this machine can reach. Set web.host = \"0.0.0.0\" "
            "(and keep web.token set) so the phone can connect."
        )

    tls = _web_module("tls")
    cert_path = None
    fingerprint = ""
    if tls is None:
        problems.append("homesoc.web.tls is missing from this install; reinstall Home SOC.")
    else:
        try:
            cert_path, _key = ensure_lens_cert(cfg, host=host)
            fingerprint = lens_cert_fingerprint(cert_path)
        except Exception as exc:
            problems.append(str(exc))
    if problems:
        emit("Lens cannot be paired yet:")
        for problem in problems:
            emit("")
            for line in str(problem).splitlines():
                emit("  " + line)
        return EXIT_ERROR

    code = db.lens_new_pairing_code(ctx.conn)
    url = lens_pair_url(cfg, code, host=host, port=port)
    emit(f"Pairing code: {code}   (single use, valid {db.LENS_PAIRING_TTL_SECONDS // 60} minutes)")
    emit(f"Open on the phone: {url}")
    emit("")
    rendered = qr_ascii(url, invert=bool(getattr(ctx.args, "invert", False)))
    if rendered:
        emit(rendered)
    else:
        emit("(the QR encoder is unavailable; type the link above instead)")
    emit("")
    emit(f"Certificate SHA-256: {fingerprint or 'unavailable'}")
    emit("The phone will warn that the certificate is not trusted. That is expected for a")
    emit("self-signed certificate: check the fingerprint above matches the one the browser")
    emit("shows, then continue. docs/LENS_SETUP.md also covers the Tailscale route, which")
    emit("needs no warning at all.")
    if not cfg.lens.allow_actions:
        emit("")
        emit("The paired phone will be read-only (lens.allow_actions is false).")
    emit("")
    emit(f"Serve it with: python -m homesoc run --tls   (listening on {host}:{port})")
    return EXIT_OK


def cmd_lens_tokens(ctx: Context) -> int:
    rows = db.lens_list_tokens(ctx.conn)
    if not rows:
        emit("no phones paired (run: python -m homesoc lens pair)")
        return EXIT_OK
    emit(f"{'id':>4} {'label':20} {'scopes':10} {'state':9} {'created':12} {'last seen':12} last ip")
    for row in rows:
        if row["revoked_at"]:
            state = "revoked"
        elif not row["active"]:
            state = "expired"
        else:
            state = "active"
        emit(f"{int(row['id']):>4} {str(row['label'])[:20]:20} {str(row['scopes']):10} {state:9} "
             f"{util.human_age(row['created_at']):12} {util.human_age(row['last_seen_at']):12} "
             f"{row['last_ip'] or '-'}")
    active = sum(1 for r in rows if r["active"])
    emit("")
    emit(f"{active} active of a maximum of {ctx.cfg.lens.token_ceiling} (lens.max_tokens)")
    return EXIT_OK


def cmd_lens_revoke(ctx: Context) -> int:
    if getattr(ctx.args, "all", False):
        count = db.lens_revoke_all_tokens(ctx.conn)
        db.lens_clear_pairing_codes(ctx.conn)
        emit(f"revoked {count} token(s); every paired phone must pair again")
        return EXIT_OK
    token_id = getattr(ctx.args, "id", None)
    if token_id is None:
        emit("usage: python -m homesoc lens revoke <id> | --all   (ids from: lens tokens)")
        return EXIT_USAGE
    if db.lens_revoke_token(ctx.conn, int(token_id)):
        emit(f"token {int(token_id)} revoked")
        return EXIT_OK
    emit(f"no active token with id {int(token_id)} (see: python -m homesoc lens tokens)")
    return EXIT_ERROR


def cmd_lens_cert(ctx: Context) -> int:
    tls = _web_module("tls")
    if tls is None:
        emit("homesoc.web.tls is not available in this install; reinstall Home SOC.")
        return EXIT_ERROR
    hosts = [h.strip() for h in str(getattr(ctx.args, "hosts", "") or "").split(",") if h.strip()]
    if getattr(ctx.args, "regenerate", False):
        try:
            cert, key = ensure_lens_cert(ctx.cfg, force=True, hosts=hosts or lens_hosts(ctx.cfg))
        except Exception as exc:
            for line in str(exc).splitlines():
                emit(line)
            return EXIT_ERROR
        emit(f"wrote {cert}")
        emit(f"wrote {key}   (keep this file to yourself)")
    elif hosts:
        emit("--hosts only applies together with --regenerate; showing the current certificate.")
    info = tls.describe()
    emit(f"certificate: {info['path']}")
    if not info["exists"]:
        for line in str(info["note"]).splitlines():
            emit("  " + line)
        return EXIT_ERROR
    emit(f"  fingerprint (SHA-256): {info.get('fingerprint') or 'unavailable'}")
    if "subject" in info:
        emit(f"  subject:  {info['subject']}")
        emit(f"  covers:   {', '.join(info['sans']) or '(none!)'}")
        emit(f"  valid:    {info['not_before']} .. {info['not_after']}  ({info['days_left']} days left)")
    if info["note"]:
        emit("")
        for line in str(info["note"]).splitlines():
            emit("  " + line)
    return EXIT_OK


def cmd_dns_test(ctx: Context) -> int:
    domain = ctx.args.domain.strip().rstrip(".").lower()
    policy_cls = _lazy("Policy")
    if policy_cls is None:
        emit("policy: unavailable (dnsfilter package missing)")
    else:
        try:
            decision = policy_cls.load(ctx.cfg, ctx.conn).decide(domain, "A", "127.0.0.1")
            emit(f"policy: {getattr(decision, 'action', decision)}  reason: {getattr(decision, 'reason', '')}")
        except Exception as exc:
            emit(f"policy: error ({type(exc).__name__}: {exc})")
    upstream = ctx.cfg.dns.upstreams[0] if ctx.cfg.dns.upstreams else "1.1.1.2"
    try:
        from dnslib import DNSRecord

        raw = DNSRecord.question(domain, "A").send(upstream, 53, timeout=3)
        answer = DNSRecord.parse(raw)
        rrs = [str(rr.rdata) for rr in answer.rr] or ["(no answer)"]
        emit(f"upstream {upstream}: rcode={answer.header.get_rcode()} " + ", ".join(rrs))
    except Exception as exc:
        emit(f"upstream {upstream}: error {exc}")
        return EXIT_ERROR
    return EXIT_OK


def cmd_config(ctx: Context) -> int:
    """``config overrides`` lists the Settings-page overrides; ``config unset KEY`` removes one so
    config.toml (or the default) applies again. Needed to rotate a leaked secret that was once
    entered on the Settings page: while the override exists, editing config.toml changes nothing."""
    action = str(getattr(ctx.args, "config_command", "") or "")
    stored = config.overrides(ctx.conn)
    if action == "overrides":
        if not stored:
            emit("no Settings-page overrides: config.toml (and the defaults) apply as written")
            return EXIT_OK
        for key in sorted(stored):
            shown = "***" if key in config.SECRET_KEYS else stored[key]
            emit(f"{key:34} {shown}")
        emit("")
        emit("Remove one with: python -m homesoc config unset <key>")
        return EXIT_OK
    if action == "unset":
        keys = list(getattr(ctx.args, "keys", None) or [])
        if getattr(ctx.args, "all", False):
            keys = sorted(stored)
        if not keys:
            emit("usage: python -m homesoc config unset <key> [<key> ...] | --all")
            return EXIT_USAGE
        status = EXIT_OK
        for key in keys:
            if key not in stored:
                emit(f"{key}: no override stored (nothing to do)")
                continue
            config.clear_override(ctx.conn, key)
            emit(f"{key}: override removed; config.toml applies after a restart")
            if key == "web.token":
                try:
                    from homesoc.web import api as webapi

                    count = webapi.sessions_revoke_all(ctx.conn)
                    emit(f"  signed out {count} browser session(s) opened with the old token")
                except Exception as exc:  # the override is gone either way
                    emit(f"  could not revoke browser sessions: {exc}")
                    status = EXIT_ERROR
        db.record_event(ctx.conn, "info", "cli", "config overrides cleared", {"keys": keys})
        return status
    emit("usage: python -m homesoc config {overrides|unset}")
    return EXIT_USAGE


COMMANDS: dict[str, Callable[[Context], int]] = {
    "init": cmd_init,
    "update": cmd_update,
    "scan": cmd_scan,
    "serve": cmd_serve,
    "dns": cmd_dns,
    "run": cmd_run,
    "status": cmd_status,
    "findings": cmd_findings,
    "baseline": cmd_baseline,
    "export": cmd_export,
    "report": cmd_report,
    "feed": cmd_feed,
    "defender": cmd_defender,
    "dns-test": cmd_dns_test,
    "lens": cmd_lens,
    "config": cmd_config,
    "blast": cmd_blast,
}


# ---------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="homesoc", description="Home SOC - home network security operations center")
    parser.add_argument("--version", action="version", version=f"homesoc {__version__}")
    parser.add_argument("--config", metavar="PATH", help="config.toml to use (default: HOMESOC_CONFIG or ./config.toml)")
    parser.add_argument("--data", metavar="DIR", help="data directory (default: HOMESOC_DATA or ./data)")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), help="override general.log_level")
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    p = sub.add_parser("init", help="create data dir, config.toml, schema and fetch the first feeds")
    p.add_argument("--no-feeds", action="store_true", help="skip the first feed download")

    p = sub.add_parser("update", help="update definition feeds")
    p.add_argument("--feeds", metavar="a,b", help="comma-separated feed names (default: all enabled)")
    p.add_argument("--force", action="store_true", help="ignore ETag/age and re-download")

    p = sub.add_parser("scan", help="run scans now")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="discovery + quick service scan + vulns + wifi")
    # SPEC-GAP: the spec only names --quick (a bare `scan` is already full); --full is accepted as
    # an explicit synonym because the dashboard and docs talk about "quick" and "full" scans.
    mode.add_argument("--full", action="store_true", help="every step (the default when --quick is absent)")
    p.add_argument("--only", metavar="a,b", help="comma-separated steps: " + ",".join(SCAN_STEPS))

    p = sub.add_parser("serve", help="dashboard only")
    p.add_argument("--host", metavar="H")
    p.add_argument("--port", metavar="P", type=int)
    p.add_argument("--tls", action="store_true",
                   help="serve over HTTPS with the self-signed Lens certificate (needed for the phone camera)")

    p = sub.add_parser("dns", help="DNS resolver only (foreground)")
    p.add_argument("--port", metavar="P", type=int)

    p = sub.add_parser("run", help="dashboard + scheduler + resolver (normal mode)")
    p.add_argument("--tls", action="store_true", help="serve over HTTPS (see: lens cert)")

    sub.add_parser("status", help="score, counts, last scans, feeds, jobs")

    p = sub.add_parser("findings", help="list findings")
    p.add_argument("--status", choices=("open", "acknowledged", "resolved", "suppressed"))
    p.add_argument("--severity", choices=SEVERITIES)
    p.add_argument("--limit", type=int, default=500)

    p = sub.add_parser("baseline", help="accept the devices you already own: trust them and close their "
                                        "'new device' findings")
    # SPEC-GAP: --trust-all is the default behaviour, named as a flag so the intent can be stated
    # explicitly (the same way `scan --full` spells out what a bare `scan` already does).
    p.add_argument("--trust-all", action="store_true",
                   help="explicit synonym for the default: tick 'Trusted' on every known device")
    p.add_argument("--dry-run", action="store_true", help="show what would change and write nothing")

    p = sub.add_parser("export", help="export findings, devices and vulns as JSON")
    p.add_argument("--out", metavar="FILE", default="report.json")

    # Addendum A4. Both work with the dashboard stopped.
    p = sub.add_parser("report", help="remediation summary: what was found and what is fixed")
    p.add_argument("--days", metavar="N", type=int, default=30, help="window in days (default 30)")
    p.add_argument("--format", choices=("md", "json"), default="md", help="output format (default md)")
    p.add_argument("--out", metavar="PATH", help="write to a file instead of stdout")

    p = sub.add_parser("feed", help="plain-text activity feed for the terminal")
    p.add_argument("--limit", metavar="N", type=int, default=50, help="how many items (default 50)")
    p.add_argument("--kinds", metavar="a,b", help="comma-separated feed kinds (see the /feed page)")
    p.add_argument("--since", metavar="AGE", help="30m, 24h, 7d, 2w or an ISO timestamp")

    p = sub.add_parser("defender", help="Windows Defender actions")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--quick-scan", action="store_true")
    group.add_argument("--update", action="store_true")

    p = sub.add_parser("dns-test", help="show the policy decision and upstream answer for a domain")
    p.add_argument("domain")

    # SPEC addendum C6.
    p = sub.add_parser("blast", help="what stops working if a device fails")
    p.add_argument("device", metavar="DEVICE", help="an IP, a MAC, or a nickname/hostname")

    # Lens (SPEC addendum B3). A sub-group rather than four top-level commands, so
    # `homesoc lens` alone prints the four things you can do with it.
    p = sub.add_parser("lens", help="pair a phone with Lens, list or revoke tokens, manage the certificate")
    lens_sub = p.add_subparsers(dest="lens_command", metavar="action")
    lens_sub.required = True

    q = lens_sub.add_parser("pair", help="print the pairing URL and QR code for a phone")
    q.add_argument("--host", metavar="H", help="address to put in the link (default: web.host)")
    q.add_argument("--port", metavar="P", type=int, help="port to put in the link (default: web.port)")
    q.add_argument("--invert", action="store_true",
                   help="swap dark and light modules (for a terminal with a dark background)")

    lens_sub.add_parser("tokens", help="list paired phones")

    q = lens_sub.add_parser("revoke", help="revoke one paired phone, or all of them")
    q.add_argument("id", nargs="?", type=int, help="token id from 'lens tokens'")
    q.add_argument("--all", action="store_true", help="revoke every paired phone")

    p = sub.add_parser("config", help="list or remove Settings-page overrides of config.toml")
    config_sub = p.add_subparsers(dest="config_command", metavar="action")
    config_sub.required = True
    config_sub.add_parser("overrides", help="list the values saved on the Settings page (secrets masked)")
    q = config_sub.add_parser("unset", help="remove Settings-page overrides so config.toml applies again")
    q.add_argument("keys", nargs="*", metavar="KEY", help="dotted key, e.g. web.token or notify.discord_webhook")
    q.add_argument("--all", action="store_true", help="remove every override")

    q = lens_sub.add_parser("cert", help="show or regenerate the HTTPS certificate")
    q.add_argument("--regenerate", action="store_true", help="replace the certificate even if it is still valid")
    q.add_argument("--hosts", metavar="a,b", help="names/addresses to cover (default: this machine's)")
    return parser


def _private_umask() -> None:
    """POSIX: every file Home SOC creates (database, WAL, logs, feeds, backups) is owner-only.

    Only ever adds bits to the mask, so a stricter umask the owner already chose is kept."""
    import os

    if os.name == "nt":
        return
    previous = os.umask(0o077)
    os.umask(previous | 0o077)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed usage/help
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    if args.data:
        import os

        os.environ[paths.ENV_DATA] = args.data
    if args.config:
        import os

        os.environ[paths.ENV_CONFIG] = args.config
    _private_umask()
    setup_logging(args.log_level or "INFO")
    try:
        conn = db.connect()
        cfg = config.load(conn)
        if not args.log_level:
            logging.getLogger().setLevel(getattr(logging, cfg.general.log_level.upper(), logging.INFO))
        return COMMANDS[args.command](Context(args, cfg, conn))
    except KeyboardInterrupt:
        return EXIT_OK
    except Exception:
        logger.exception("command %s failed", args.command)
        return EXIT_ERROR


__all__ = [
    "EXIT_OK", "EXIT_ERROR", "EXIT_USAGE", "SCAN_STEPS", "QUICK_STEPS", "MODULES",
    "setup_logging", "effective_scope", "apply_findings", "run_step", "run_scan", "run_feeds",
    "scan_discovery", "scan_services", "scan_vulns", "scan_host", "scan_exposure", "scan_wifi", "scan_files",
    "soc_health_drafts", "apply_soc_health", "build_jobs", "dns_rollup", "housekeeping", "send_digest",
    "queue_device_scan", "run_device_scan", "dashboard_url", "parse_since", "RETENTION_DAYS",
    "list_findings_safe", "fallback_counts", "fallback_score", "current_score", "grade", "GRADE_BANDS",
    "score_breakdown_lines", "cmd_baseline",
    # Dependencies and blast radius (SPEC addendum C)
    "scan_topology", "TOPOLOGY_JOB_HOURS", "resolve_device", "cmd_blast",
    "BASELINE_LIST_LIMIT", "SCORE_BREAKDOWN_LIMIT",
    # Lens (SPEC addendum B3)
    "WILDCARD_HOSTS", "TLS_SETTING", "BIND_SETTING", "recorded_bind", "lens_hosts", "lens_display_host",
    "ensure_lens_cert",
    "lens_cert_fingerprint", "lens_pair_url", "qr_ascii", "record_tls_state", "tls_last_used",
    "record_bind_state", "enforce_bind_policy", "TAMPER_SIGNAL_KEYS",
    "cmd_lens", "cmd_lens_pair", "cmd_lens_tokens", "cmd_lens_revoke", "cmd_lens_cert",
    "Runtime", "Context", "build_parser", "main",
]
