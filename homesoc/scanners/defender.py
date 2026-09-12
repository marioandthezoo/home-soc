"""Microsoft Defender integration (SPEC 6.6).

``status``/``threats`` wrap ``ps/defender.ps1``; ``trigger_quick_scan``/``update_signatures`` drive
``MpCmdRun.exe``. The WIN-DEF-* rules live here in ``evaluate_status``/``evaluate_threats`` so the
posture scanner (which carries the same Defender subset) and this scanner agree on every verdict.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import FindingDraft, HostCheck, ScanResult
from homesoc.scanners.host_windows import (
    PS_DIR,
    Collector,
    as_list,
    cfg_get,
    is_denied,
    is_error,
    run_ps_json,
    to_int,
    truthy,
    write_checks,
)
from homesoc.util import is_windows, json_dumps, parse_iso, run_cmd, utcnow_iso, which

if TYPE_CHECKING:  # pragma: no cover
    from homesoc.config import Config

logger = logging.getLogger(__name__)

STATUS_TIMEOUT_SEC = 120
THREATS_TIMEOUT_SEC = 120
QUICK_SCAN_TIMEOUT_SEC = 3600
SIGNATURE_UPDATE_TIMEOUT_SEC = 300
SIGNATURE_MAX_AGE_DAYS = 3
FULL_SCAN_MAX_AGE_DAYS = 30
NEVER_SCANNED = 4294967295  # Get-MpComputerStatus reports uint32 max when a scan never ran

THREAT_EVENT_IDS = (1006, 1007, 1116, 1117, 1118, 1119, 5001, 5010, 5012)
PROTECTION_CHANGE_EVENT_IDS = {5001, 5010, 5012}
# The subset of THREAT_EVENT_IDS that really reports malware (the rest are protection changes).
MALWARE_EVENT_IDS = {1006, 1007, 1116, 1117, 1118, 1119}

STATUS_CHECK_IDS = (
    "WIN-DEF-001", "WIN-DEF-002", "WIN-DEF-003", "WIN-DEF-004", "WIN-DEF-005", "WIN-DEF-006",
    "WIN-DEF-007", "WIN-DEF-008", "WIN-DEF-009", "WIN-DEF-010", "WIN-DEF-012", "WIN-DEF-014",
)

_SCAN_LOCK = threading.Lock()
_SCAN_THREAD: threading.Thread | None = None
_UPDATE_LOCK = threading.Lock()
_UPDATE_THREAD: threading.Thread | None = None

# --------------------------------------------------------------------------- probes


def status(cfg: Config | None = None) -> dict[str, Any]:
    """Get-MpComputerStatus + Get-MpPreference subset; ``{"error": ...}`` when unavailable."""
    if not is_windows():
        return {"error": "not windows"}
    res = run_ps_json(PS_DIR / "defender.ps1", timeout=STATUS_TIMEOUT_SEC, args=["-Action", "status"])
    if res.data is None:
        return {"error": res.error or "no data"}
    return res.data


def _threats_raw(cfg: Config | None = None, days: int = 30) -> dict[str, Any]:
    """Raw ``-Action threats`` probe output: ``{detections, events, activity, errors}``."""
    if not is_windows():
        return {}
    res = run_ps_json(PS_DIR / "defender.ps1", timeout=THREATS_TIMEOUT_SEC, args=["-Action", "threats", "-Days", str(int(days))])
    if res.data is None:
        logger.warning("defender threats probe failed: %s", res.error)
        return {}
    return res.data


def threats(cfg: Config | None = None, days: int = 30) -> list[dict[str, Any]]:
    """Detections plus Defender/Operational events (last ``days``), newest first, normalised."""
    return normalize_threats(_threats_raw(cfg, days))


def normalize_activity(raw: dict[str, Any]) -> dict[str, Any]:
    """Scan / signature-update history from the Defender/Operational log, for the AV panel.

    Get-MpThreatDetection is empty on a healthy machine and the malware event IDs never fire, so
    without this the AV panel has nothing to show and the user cannot tell a working Defender from
    a silent one. These events (scan started/finished, signature updated, update failed) are the
    proof that it is alive, and a failed-update timestamp is a real AV-health signal.
    """
    act = raw.get("activity") if isinstance(raw.get("activity"), dict) else {}
    out: dict[str, Any] = {
        "last_scan_started": act.get("last_scan_started"),
        "last_scan_finished": act.get("last_scan_finished"),
        "last_scan_type": act.get("last_scan_type"),
        "last_scan_cancelled": act.get("last_scan_cancelled"),
        "last_signature_update": act.get("last_signature_update"),
        "last_signature_version": act.get("last_signature_version"),
        "last_signature_failure": act.get("last_signature_failure"),
        "last_signature_failure_reason": (str(act.get("last_signature_failure_reason") or "") or None),
        "config_changes": to_int(act.get("config_changes"), 0) or 0,
        "scans": to_int(act.get("scans"), 0) or 0,
        "signature_updates": to_int(act.get("signature_updates"), 0) or 0,
        "days": to_int(raw.get("days"), 30) or 30,
    }
    errors = raw.get("errors")
    out["errors"] = errors if isinstance(errors, dict) else {}
    return out


def normalize_threats(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten detections + events into one list of threat dicts, one per (name, path).

    A single detection produces several events (1116 detected, 1117 action taken, ...); collapsing
    them keeps WIN-DEF-011 at one finding per actual threat while the evidence keeps the latest state.
    """
    out: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for d in as_list(raw.get("detections")):
        if not isinstance(d, dict):
            continue
        item = {
            "kind": "threat",
            "source": "detection",
            "threat_name": d.get("threat_name") or f"ThreatID {d.get('threat_id')}",
            "threat_id": d.get("threat_id"),
            "path": d.get("path") or "",
            "severity": d.get("severity"),
            "action": "success" if truthy(d.get("action_success")) else ("failed" if d.get("action_success") is not None else None),
            "detected_at": d.get("detected_at"),
            "process": d.get("process"),
            "user": d.get("user"),
            "event_id": None,
        }
        _merge_threat(out, order, item)
    for e in as_list(raw.get("events")):
        if not isinstance(e, dict):
            continue
        eid = to_int(e.get("event_id"))
        # Classify by event ID, not by "anything that is not a protection change": the probe may
        # grow new IDs, and mislabelling a housekeeping event as a threat would raise a false
        # WIN-DEF-011. An unknown ID only counts as a threat when it names one.
        if eid in MALWARE_EVENT_IDS or (eid not in PROTECTION_CHANGE_EVENT_IDS and e.get("threat_name")):
            kind = "threat"
        else:
            kind = "protection_change"
        item = {
            "kind": kind,
            "source": "event",
            "threat_name": e.get("threat_name") or (f"Defender event {eid}" if kind == "protection_change" else "unknown threat"),
            "threat_id": None,
            "path": e.get("path") or "",
            "severity": e.get("severity"),
            "action": e.get("action"),
            "detected_at": e.get("time"),
            "process": e.get("process"),
            "user": e.get("user"),
            "event_id": eid,
            "message": (e.get("message") or "")[:300],
        }
        _merge_threat(out, order, item)
    return [out[k] for k in order]


def _merge_threat(out: dict[str, dict[str, Any]], order: list[str], item: dict[str, Any]) -> None:
    if item["kind"] == "protection_change":
        key = f"pc|{item['event_id']}|{item['detected_at']}"
    else:
        key = f"t|{str(item['threat_name']).lower()}|{str(item['path']).lower()}"
    item["key"] = hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]
    existing = out.get(key)
    if existing is None:
        out[key] = item
        order.append(key)
        return
    # Keep the newest timestamp/action, but never lose a real threat name or path.
    item_dt = parse_iso(item.get("detected_at"))
    existing_dt = parse_iso(existing.get("detected_at"))
    if item_dt is not None and (existing_dt is None or item_dt > existing_dt):
        for k in ("detected_at", "action", "event_id", "source", "message"):
            if item.get(k) is not None:
                existing[k] = item[k]
    for k in ("severity", "process", "user", "threat_id"):
        if not existing.get(k) and item.get(k):
            existing[k] = item[k]


# --------------------------------------------------------------------------- MpCmdRun actions


def mpcmdrun_path(status_info: dict[str, Any] | None = None) -> Path | None:
    """Locate MpCmdRun.exe: Program Files stub first, then the newest Platform folder."""
    if not is_windows():
        return None
    candidates: list[Path] = []
    pf = os.environ.get("ProgramFiles")
    if pf:
        candidates.append(Path(pf) / "Windows Defender" / "MpCmdRun.exe")
    if status_info and status_info.get("platform_dir"):
        candidates.append(Path(str(status_info["platform_dir"])) / "MpCmdRun.exe")
    pd = os.environ.get("ProgramData")
    if pd:
        base = Path(pd) / "Microsoft" / "Windows Defender" / "Platform"
        try:
            if base.is_dir():
                wanted = str((status_info or {}).get("AMProductVersion") or "")
                dirs = sorted((d for d in base.iterdir() if d.is_dir()), key=lambda d: d.name, reverse=True)
                dirs.sort(key=lambda d: 0 if wanted and d.name.startswith(wanted) else 1)
                candidates.extend(d / "MpCmdRun.exe" for d in dirs)
        except OSError:
            pass
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def _run_mpcmdrun(args: list[str], timeout: float) -> tuple[int, str, str]:
    exe = mpcmdrun_path()
    if exe is None:
        return 127, "", "MpCmdRun.exe not found"
    return run_cmd([str(exe), *args], timeout=timeout)


def _blank_action_state() -> dict[str, Any]:
    return {"running": False, "started_at": None, "finished_at": None, "ok": None, "rc": None,
            "message": "", "duration_sec": None}


# Last outcome of each MpCmdRun action, so the dashboard can poll instead of holding a request
# open for the length of a scan or an update. Guarded by the matching lock.
_SCAN_STATE: dict[str, Any] = _blank_action_state()
_UPDATE_STATE: dict[str, Any] = _blank_action_state()


def _start_action(name: str, argv: list[str], timeout: float, lock: threading.Lock,
                  thread_ref: str, state: dict[str, Any]) -> bool:
    """Launch one MpCmdRun action on a guarded daemon thread; True when running (new or already).

    The thread is the whole point: ``-SignatureUpdate`` can take minutes and ``-Scan`` far longer,
    and a synchronous call would hold the Flask worker (and the browser fetch) open for all of it,
    with every retry click stacking another MpCmdRun process. ``run_cmd`` still carries a hard
    timeout so a wedged child is reaped rather than leaked.
    """
    global _SCAN_THREAD, _UPDATE_THREAD
    if mpcmdrun_path() is None:
        logger.warning("%s requested but MpCmdRun.exe was not found", name)
        state.update(_blank_action_state(), message="MpCmdRun.exe not found", ok=False)
        return False
    with lock:
        current = _SCAN_THREAD if thread_ref == "scan" else _UPDATE_THREAD
        if current is not None and current.is_alive():
            logger.info("%s already running", name)
            return True
        started = time.monotonic()
        state.update(_blank_action_state(), running=True, started_at=utcnow_iso())

        def _worker() -> None:
            rc, out, err = -1, "", ""
            try:
                rc, out, err = _run_mpcmdrun(argv, timeout)
            except Exception as exc:  # noqa: BLE001 - a daemon thread must never die silently
                logger.exception("%s crashed", name)
                err = str(exc)
            finally:
                message = (err or out).strip()[-300:]
                state.update(running=False, finished_at=utcnow_iso(), ok=rc == 0, rc=rc,
                             message=message, duration_sec=round(time.monotonic() - started, 1))
                level = logger.info if rc == 0 else logger.warning
                level("defender %s finished rc=%s %s", name, rc, message)

        thread = threading.Thread(target=_worker, name=f"defender-{thread_ref}", daemon=True)
        if thread_ref == "scan":
            _SCAN_THREAD = thread
        else:
            _UPDATE_THREAD = thread
        thread.start()
    return True


def trigger_quick_scan(cfg: Config | None = None) -> bool:
    """Start ``MpCmdRun -Scan -ScanType 1`` in the background; True when launched or already running."""
    return _start_action("quick scan", ["-Scan", "-ScanType", "1"], QUICK_SCAN_TIMEOUT_SEC,
                         _SCAN_LOCK, "scan", _SCAN_STATE)


def trigger_signature_update(cfg: Config | None = None) -> bool:
    """Start ``MpCmdRun -SignatureUpdate`` in the background; True when launched or already running.

    This is what the dashboard's "Update signatures" button must call: the synchronous
    :func:`update_signatures` blocks for as long as the download takes.
    """
    return _start_action("signature update", ["-SignatureUpdate"], SIGNATURE_UPDATE_TIMEOUT_SEC,
                         _UPDATE_LOCK, "update", _UPDATE_STATE)


def quick_scan_running() -> bool:
    return _SCAN_THREAD is not None and _SCAN_THREAD.is_alive()


def update_running() -> bool:
    return _UPDATE_THREAD is not None and _UPDATE_THREAD.is_alive()


def quick_scan_status() -> dict[str, Any]:
    """Pollable state of the background quick scan (see :func:`update_status`)."""
    return dict(_SCAN_STATE, running=quick_scan_running(), available=mpcmdrun_path() is not None)


def update_status() -> dict[str, Any]:
    """Pollable state of the background signature update.

    ``{"running", "available", "started_at", "finished_at", "ok", "rc", "message", "duration_sec"}``
    — ``running`` while MpCmdRun is alive, then ``ok``/``message`` describe the last attempt, so the
    /host page can fire the POST and poll this instead of waiting on the request.
    """
    return dict(_UPDATE_STATE, running=update_running(), available=mpcmdrun_path() is not None)


def update_signatures(cfg: Config | None = None) -> bool:
    """``MpCmdRun -SignatureUpdate`` run to completion (CLI ``defender --update``); True on rc 0.

    Synchronous by design for the CLI, which has a terminal to wait in. Anything serving a request
    must use :func:`trigger_signature_update` instead.
    """
    started = time.monotonic()
    rc, out, err = _run_mpcmdrun(["-SignatureUpdate"], SIGNATURE_UPDATE_TIMEOUT_SEC)
    message = (err or out).strip()[-300:]
    _UPDATE_STATE.update(running=False, started_at=_UPDATE_STATE.get("started_at") or utcnow_iso(),
                         finished_at=utcnow_iso(), ok=rc == 0, rc=rc, message=message,
                         duration_sec=round(time.monotonic() - started, 1))
    if rc != 0:
        logger.warning("signature update failed rc=%s: %s", rc, message)
    return rc == 0


def clamscan_available() -> bool:
    """Optional ClamAV presence (not required, never invoked automatically)."""
    return which("clamscan") is not None


# --------------------------------------------------------------------------- evaluation


def evaluate_status(st: dict[str, Any], c: Collector | None = None) -> tuple[list[HostCheck], list[FindingDraft]]:
    """WIN-DEF-001..010/012/014 (+013 when the status carries the Smart App Control state)."""
    c = c or Collector()
    if st.get("error") or is_denied(st) or is_error(st):
        err = st.get("error") if isinstance(st, dict) else st
        for cid in STATUS_CHECK_IDS:
            if is_denied(err):
                c.denied(cid, "Microsoft Defender readable")
            else:
                c.unknown(cid, "Microsoft Defender readable", str(err)[:200])
        return c.checks, c.findings

    av_on = truthy(st.get("AntivirusEnabled"))
    svc_on = truthy(st.get("AMServiceEnabled"))
    if av_on is False or svc_on is False:
        c.fail("WIN-DEF-001", "disabled", "antivirus enabled", {"AntivirusEnabled": av_on, "AMServiceEnabled": svc_on, "AMRunningMode": st.get("AMRunningMode")})
    elif av_on is None:
        c.unknown("WIN-DEF-001", "antivirus enabled")
    else:
        c.ok("WIN-DEF-001", "enabled", "antivirus enabled")

    rtp = truthy(st.get("RealTimeProtectionEnabled"))
    if rtp is False or truthy(st.get("DisableRealtimeMonitoring")) is True:
        c.fail("WIN-DEF-002", "off", "real-time protection on", {"RealTimeProtectionEnabled": rtp, "DisableRealtimeMonitoring": truthy(st.get("DisableRealtimeMonitoring"))})
    elif rtp is None:
        c.unknown("WIN-DEF-002", "real-time protection on")
    else:
        c.ok("WIN-DEF-002", "on", "real-time protection on")

    age = to_int(st.get("AntivirusSignatureAge"))
    if age is None:
        c.unknown("WIN-DEF-003", f"signatures <= {SIGNATURE_MAX_AGE_DAYS} days old")
    elif age > SIGNATURE_MAX_AGE_DAYS:
        c.fail("WIN-DEF-003", f"{age} days", f"<= {SIGNATURE_MAX_AGE_DAYS} days", {"age_days": age, "last_updated": st.get("AntivirusSignatureLastUpdated"), "version": st.get("AntivirusSignatureVersion")})
    else:
        c.ok("WIN-DEF-003", f"{age} days (v{st.get('AntivirusSignatureVersion') or '?'})", f"<= {SIGNATURE_MAX_AGE_DAYS} days")

    _flag(c, "WIN-DEF-004", truthy(st.get("IsTamperProtected")), "tamper protection on", "IsTamperProtected", st)

    maps = to_int(st.get("MAPSReporting"))
    if maps is None:
        c.unknown("WIN-DEF-005", "cloud-delivered protection on")
    elif maps == 0:
        c.fail("WIN-DEF-005", "off (MAPSReporting=0)", "MAPSReporting=2", {"MAPSReporting": maps})
    else:
        c.ok("WIN-DEF-005", "basic" if maps == 1 else "advanced", "MAPSReporting=2")

    _tri_state(c, "WIN-DEF-006", to_int(st.get("PUAProtection")), "PUAProtection", "PUA protection on")

    full = to_int(st.get("FullScanAge"))
    if full is None:
        c.unknown("WIN-DEF-007", f"full scan within {FULL_SCAN_MAX_AGE_DAYS} days")
    elif full >= NEVER_SCANNED or full > FULL_SCAN_MAX_AGE_DAYS:
        c.fail("WIN-DEF-007", "never" if full >= NEVER_SCANNED else f"{full} days ago", f"within {FULL_SCAN_MAX_AGE_DAYS} days", {"full_scan_age_days": None if full >= NEVER_SCANNED else full, "quick_scan_age_days": to_int(st.get("QuickScanAge")), "last_full_scan": st.get("FullScanEndTime")})
    else:
        c.ok("WIN-DEF-007", f"{full} days ago", f"within {FULL_SCAN_MAX_AGE_DAYS} days")

    _tri_state(c, "WIN-DEF-008", to_int(st.get("EnableControlledFolderAccess")), "EnableControlledFolderAccess", "controlled folder access on")
    _tri_state(c, "WIN-DEF-009", to_int(st.get("EnableNetworkProtection")), "EnableNetworkProtection", "network protection on")

    ids = [str(i) for i in as_list(st.get("AttackSurfaceReductionRules_Ids")) if i]
    actions = [to_int(a) for a in as_list(st.get("AttackSurfaceReductionRules_Actions"))]
    active = [i for i, a in zip(ids, actions + [1] * (len(ids) - len(actions))) if a not in (0, None)]
    if "AttackSurfaceReductionRules_Ids" not in st:
        c.unknown("WIN-DEF-010", "ASR rules configured")
    elif not active:
        c.fail("WIN-DEF-010", "none configured" if not ids else f"{len(ids)} rules, none enforcing", "at least one ASR rule in block/warn mode", {"rules": ids, "actions": actions})
    else:
        c.ok("WIN-DEF-010", f"{len(active)} rules active", "at least one ASR rule in block/warn mode")

    mode = str(st.get("AMRunningMode") or "")
    healthy_modes = ("normal", "passive mode", "passive", "sxs passive mode", "edr block mode")
    if svc_on is None:
        c.unknown("WIN-DEF-012", "AM service running")
    elif svc_on is False or (mode and mode.lower() not in healthy_modes):
        state = "service disabled" if svc_on is False else f"running mode {mode or 'unknown'}"
        c.fail("WIN-DEF-012", f"AMServiceEnabled={svc_on} mode={mode or '?'}", "AM service running in Normal mode", {"state": state, "AMServiceEnabled": svc_on, "AMRunningMode": mode, "engine": st.get("AMEngineVersion"), "platform": st.get("AMProductVersion")})
    else:
        c.ok("WIN-DEF-012", f"running ({mode or 'Normal'}) engine {st.get('AMEngineVersion') or '?'}", "AM service running in Normal mode")

    if "smart_app_control" in st:
        sac = to_int(st.get("smart_app_control"))
        if sac in (1, 2):
            c.ok("WIN-DEF-013", "on" if sac == 1 else "evaluation", "Smart App Control on")
        else:
            c.fail("WIN-DEF-013", "off" if sac == 0 else "unknown", "Smart App Control on", {"VerifiedAndReputablePolicyState": sac})

    consent = to_int(st.get("SubmitSamplesConsent"))
    level = to_int(st.get("CloudBlockLevel"))
    if consent is None and level is None:
        c.unknown("WIN-DEF-014", "sample submission on, cloud block level >= High")
    elif consent == 2 or (level is not None and level == 0):
        c.fail("WIN-DEF-014", f"SubmitSamplesConsent={consent} CloudBlockLevel={level}", "SubmitSamplesConsent!=2, CloudBlockLevel>=2", {"SubmitSamplesConsent": consent, "CloudBlockLevel": level})
    else:
        c.ok("WIN-DEF-014", f"SubmitSamplesConsent={consent} CloudBlockLevel={level}", "SubmitSamplesConsent!=2, CloudBlockLevel>=2")
    return c.checks, c.findings


def _flag(c: Collector, cid: str, value: bool | None, expected: str, field: str, st: dict[str, Any]) -> None:
    if value is None:
        c.unknown(cid, expected)
    elif value:
        c.ok(cid, "on", expected)
    else:
        c.fail(cid, "off", expected, {field: False})


def _tri_state(c: Collector, cid: str, value: int | None, field: str, expected: str) -> None:
    """Defender preferences use 0=off, 1=on, 2=audit; audit is a warn, not a pass."""
    if value is None:
        c.unknown(cid, expected)
    elif value == 0:
        c.fail(cid, "off", expected, {field: 0})
    elif value == 2:
        c.warn(cid, "audit mode", expected, {field: 2})
    else:
        c.ok(cid, "on", expected)


def evaluate_threats(items: list[dict[str, Any]], c: Collector | None = None) -> tuple[HostCheck, list[FindingDraft]]:
    """WIN-DEF-011: one finding per threat seen in the last 30 days (protection changes are evidence only)."""
    c = c or Collector()
    real = [t for t in items if t.get("kind") == "threat"]
    changes = [t for t in items if t.get("kind") == "protection_change"]
    if real:
        hc = c.check("WIN-DEF-011", "fail", f"{len(real)} threat(s) in last 30 days", "no threats detected")
        for t in real:
            ev = {k: t.get(k) for k in ("threat_name", "path", "severity", "action", "detected_at", "process", "user", "source", "event_id", "threat_id") if t.get(k) is not None}
            c.finding("WIN-DEF-011", ev, key=t.get("key"), detail=f"{t.get('threat_name')} at {t.get('path') or 'unknown path'}")
    else:
        hc = c.check("WIN-DEF-011", "pass", "none" + (f" ({len(changes)} protection change events)" if changes else ""), "no threats detected")
    return hc, c.findings


# --------------------------------------------------------------------------- scanner entry point


def run(cfg: Config, conn: Any, *, quick: bool = False, progress: Callable[[str], None] | None = None) -> ScanResult:
    """Scanner interface (SPEC 6): status + threats -> host_checks rows, WIN-DEF-* drafts, settings JSON."""
    started = time.monotonic()
    notify = progress or (lambda _msg: None)
    if not is_windows():
        return ScanResult("host", [], {"skipped": "not windows"}, error="defender scanner runs on Windows only")

    notify("defender: reading status")
    st = status(cfg)
    c = Collector()
    evaluate_status(st, c)
    items: list[dict[str, Any]] = []
    activity: dict[str, Any] = {}
    if not st.get("error"):
        notify("defender: reading detections and events")
        raw = _threats_raw(cfg, days=30)
        items = normalize_threats(raw)
        activity = normalize_activity(raw)
    evaluate_threats(items, c)

    write_checks(conn, c.checks)
    if st.get("error"):
        # Keep the last good status so the AV panel does not go blank on one failed probe;
        # defender.status_error + defender.checked_at say how fresh the displayed data is.
        db.set_setting(conn, "defender.status_error", str(st.get("error"))[:300])
    else:
        db.set_setting(conn, "defender.status_json", json_dumps(st))
        db.set_setting(conn, "defender.status_error", "")
        db.set_setting(conn, "defender.threats_json", json_dumps(items))
        db.set_setting(conn, "defender.activity_json", json_dumps(activity))
    db.set_setting(conn, "defender.checked_at", utcnow_iso())
    summary = c.summary()
    summary.update({
        "duration_sec": round(time.monotonic() - started, 2),
        "threats": len([t for t in items if t.get("kind") == "threat"]),
        "protection_changes": len([t for t in items if t.get("kind") == "protection_change"]),
        "signature_age_days": to_int(st.get("AntivirusSignatureAge")),
        "last_signature_update": activity.get("last_signature_update"),
        "last_scan_finished": activity.get("last_scan_finished"),
        "mpcmdrun": str(mpcmdrun_path(st) or ""),
        "clamscan": clamscan_available(),
        "findings": len(c.findings),
    })
    error = str(st.get("error")) if st.get("error") else None
    return ScanResult("host", c.findings, summary, error=error)


__all__ = [
    "MALWARE_EVENT_IDS",
    "NEVER_SCANNED",
    "PROTECTION_CHANGE_EVENT_IDS",
    "STATUS_CHECK_IDS",
    "THREAT_EVENT_IDS",
    "clamscan_available",
    "evaluate_status",
    "evaluate_threats",
    "mpcmdrun_path",
    "normalize_activity",
    "normalize_threats",
    "quick_scan_running",
    "quick_scan_status",
    "run",
    "status",
    "threats",
    "trigger_quick_scan",
    "trigger_signature_update",
    "update_running",
    "update_signatures",
    "update_status",
]
