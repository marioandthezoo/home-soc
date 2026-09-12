"""Windows host posture scanner (SPEC 6.5) plus the helpers shared by the other host scanners.

One PowerShell probe (``ps/posture.ps1``) collects everything in ~15 s; this module turns that
JSON into ``host_checks`` rows and finding drafts. Evaluation is pure (``evaluate()``) so the
fixture in ``tests/fixtures/posture/win_nonadmin.json`` exercises every rule offline.

Shared helpers used by defender/updates/persistence/host_posix:
``run_ps_json``, ``write_checks``, ``as_list``, ``is_denied``, ``truthy``, ``Collector``.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import FindingDraft, HostCheck, ScanResult
from homesoc.util import is_windows, json_dumps, run_cmd, safe_json_loads, utcnow_iso, which

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps import-time coupling minimal
    from homesoc.config import Config

logger = logging.getLogger(__name__)

PS_DIR = Path(__file__).resolve().parent / "ps"
ACCESS_DENIED = "ACCESS_DENIED"
POSTURE_TIMEOUT_SEC = 240
HOST_SUBJECT = "host"

# Ports Windows always has open on the LAN (SPEC 9, WIN-NET-006) — not "unusual".
_EXPECTED_LISTENER_PORTS = {135, 139, 445, 5040, 5357, 7680}
_LOOPBACK_PREFIXES = ("127.", "::1")

# --------------------------------------------------------------------------- shared helpers


def cfg_get(cfg: Any, dotted: str, default: Any = None) -> Any:
    """Read ``section.key`` from a Config (or any nested object/dict) without raising.

    Scanners are exercised with partial configs in tests and with the frozen dataclasses at
    runtime; tolerating both keeps the scanner code free of ``hasattr`` noise.
    """
    node = cfg
    for part in dotted.split("."):
        if node is None:
            return default
        if isinstance(node, dict):
            node = node.get(part)
        else:
            node = getattr(node, part, None)
    return default if node is None else node


def as_list(value: Any) -> list:
    """PowerShell unrolls single-element arrays into scalars; undo that consistently."""
    if value is None or is_denied(value) or is_error(value):
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_denied(value: Any) -> bool:
    return isinstance(value, str) and value == ACCESS_DENIED


def is_error(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("ERROR:")


def truthy(value: Any) -> bool | None:
    """Normalise PowerShell booleans that arrive as bool, int, or "True"/"False" strings."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in ("true", "1", "yes", "on", "enabled"):
        return True
    if text in ("false", "0", "no", "off", "disabled", ""):
        return False
    return None


def to_int(value: Any, default: int | None = None) -> int | None:
    if value is None or isinstance(value, bool):
        return default if value is None else int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class PsResult:
    data: dict[str, Any] | None
    error: str | None = None
    returncode: int | None = None
    duration_sec: float = 0.0


def powershell_exe() -> str | None:
    """Windows PowerShell 5.1 first: the Defender/NetSecurity modules are guaranteed there."""
    return which("powershell") or which("pwsh")


def run_ps_json(script: Path, *, timeout: float, args: Iterable[str] = ()) -> PsResult:
    """Run one of our ``ps/*.ps1`` probes and parse the single JSON object it prints.

    Every probe is invoked the same way (-NoProfile -NonInteractive -ExecutionPolicy Bypass -File)
    so a machine with a restrictive execution policy or a chatty profile still works.
    """
    exe = powershell_exe()
    if exe is None:
        return PsResult(None, error="powershell not found on PATH")
    if not script.is_file():
        return PsResult(None, error=f"probe script missing: {script}")
    argv = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script), *args]
    started = time.monotonic()
    rc, out, err = run_cmd(argv, timeout=timeout)
    duration = time.monotonic() - started
    data = extract_json(out)
    if data is None:
        tail = (err or out or "").strip().splitlines()
        detail = tail[-1][:300] if tail else "no output"
        logger.warning("probe %s produced no JSON (rc=%s): %s", script.name, rc, detail)
        return PsResult(None, error=f"{script.name}: rc={rc}: {detail}", returncode=rc, duration_sec=duration)
    return PsResult(data, returncode=rc, duration_sec=duration)


def extract_json(text: str | None) -> dict[str, Any] | None:
    """Find the JSON object in stdout even if a module printed a warning line before it."""
    if not text:
        return None
    parsed = safe_json_loads(text)
    if isinstance(parsed, dict):
        return parsed
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    parsed = safe_json_loads(text[start : end + 1])
    return parsed if isinstance(parsed, dict) else None


_UPSERT_CHECK_SQL = (
    "INSERT INTO host_checks(check_id, status, value, expected, checked_at, needs_admin) "
    "VALUES (?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(check_id) DO UPDATE SET status = excluded.status, value = excluded.value, "
    "expected = excluded.expected, checked_at = excluded.checked_at, needs_admin = excluded.needs_admin"
)


def write_checks(conn: Any, checks: Iterable[HostCheck]) -> int:
    """Upsert ``host_checks`` rows (check_id is the PK, so one row per check ID)."""
    now = utcnow_iso()
    rows = [
        (c.check_id, c.status, _clip(c.value), _clip(c.expected), now, 1 if c.needs_admin else 0)
        for c in checks
    ]
    if rows:
        db.writemany(conn, _UPSERT_CHECK_SQL, rows)
    return len(rows)


def _clip(value: str | None, limit: int = 2000) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


class Collector:
    """Accumulates checks and findings so each rule is one short call.

    A ``fail``/``warn`` produces both the ``host_checks`` row and the finding draft; the
    catalog supplies title/remediation so drafts only carry evidence (and a severity only
    when the rule overrides the catalog default, e.g. RDP without NLA).
    """

    def __init__(self, subject: str = HOST_SUBJECT) -> None:
        self.subject = subject
        self.checks: list[HostCheck] = []
        self.findings: list[FindingDraft] = []
        self.skipped: list[str] = []

    def check(self, check_id: str, status: str, value: Any = None, expected: str | None = None, *, needs_admin: bool = False) -> HostCheck:
        hc = HostCheck(check_id, status, _stringify(value), expected, needs_admin)
        self.checks.append(hc)
        if status == "needs_admin":
            self.skipped.append(check_id)
        return hc

    def ok(self, check_id: str, value: Any = None, expected: str | None = None) -> None:
        self.check(check_id, "pass", value, expected)

    def denied(self, check_id: str, expected: str | None = None, value: Any = "requires administrator") -> None:
        self.check(check_id, "needs_admin", value, expected, needs_admin=True)

    def unknown(self, check_id: str, expected: str | None = None, value: Any = None) -> None:
        self.check(check_id, "unknown", value, expected)

    def fail(self, check_id: str, value: Any, expected: str | None, evidence: dict | None = None, *, severity: str | None = None, key: str | None = None, detail: str | None = None, status: str = "fail") -> None:
        self.check(check_id, status, value, expected)
        self.finding(check_id, evidence, severity=severity, key=key, detail=detail)

    def warn(self, check_id: str, value: Any, expected: str | None, evidence: dict | None = None, **kw: Any) -> None:
        self.fail(check_id, value, expected, evidence, status="warn", **kw)

    def finding(self, finding_id: str, evidence: dict | None = None, *, severity: str | None = None, key: str | None = None, detail: str | None = None) -> FindingDraft:
        ev = dict(evidence or {})
        if key is not None:
            ev["key"] = str(key)
        draft = FindingDraft(finding_id=finding_id, subject=self.subject, evidence=ev, detail=detail, severity=severity)
        self.findings.append(draft)
        return draft

    def gate(self, check_id: str, value: Any, expected: str | None = None) -> bool:
        """Handle the two non-answers (ACCESS_DENIED / ERROR:) in one place; True when usable."""
        if is_denied(value):
            self.denied(check_id, expected)
            return False
        if is_error(value):
            self.unknown(check_id, expected, value[:200])
            return False
        return True

    def summary(self) -> dict[str, int]:
        counts = {"total": len(self.checks), "pass": 0, "fail": 0, "warn": 0, "needs_admin": 0, "unknown": 0}
        for c in self.checks:
            counts[c.status] = counts.get(c.status, 0) + 1
        return counts


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json_dumps(value)


# --------------------------------------------------------------------------- evaluation


class SkippedChecks(list):
    """The list of check IDs a non-elevated run could not answer.

    It has to be two things at once: structured data for the dashboard and the JSON evidence
    blob (``["WIN-SYS-002", ...]``), and readable text for the catalog title, which interpolates
    ``{skipped}``. A plain list would render as a Python repr inside the finding title, so the
    string conversions are overridden while the value stays a real sequence of IDs.
    """

    __slots__ = ()

    def __str__(self) -> str:
        return ", ".join(self) if self else "nothing"

    def __format__(self, spec: str) -> str:
        return format(str(self), spec)


def evaluate(posture: dict[str, Any], cfg: Any = None, *, last_cumulative: str | None = None) -> tuple[list[HostCheck], list[FindingDraft], dict[str, Any]]:
    """Map the posture JSON to every WIN-* check the probe can answer (pure, offline-testable).

    ``last_cumulative`` is the Windows-Update-history install date that ``updates.py`` recorded on
    an earlier run; when it is newer than the newest installed hotfix it wins for WIN-UPD-002 so
    the two scanners can never publish opposite verdicts for the same finding (see ``_eval_hotfix``).
    """
    c = Collector()
    is_admin = bool(truthy(posture.get("is_admin")))

    _eval_defender(c, posture.get("defender"))
    _eval_firewall(c, posture.get("firewall"))
    _eval_accounts(c, posture)
    _eval_network(c, posture, cfg)
    _eval_system(c, posture, is_admin)
    _eval_hotfix(c, posture.get("hotfix"), last_cumulative)

    if not is_admin:
        # SPEC 6.5: informational finding listing what a non-elevated run could not verify.
        # {project_root} is plain text; {skipped} is a SkippedChecks list that renders as text.
        c.finding("SOC-SYS-002", {
            "is_admin": False,
            "skipped": SkippedChecks(sorted(c.skipped)),
            "skipped_ids": sorted(c.skipped),
            "project_root": _project_root_text(),
            "user": _redact_user(posture),
        })
    summary = c.summary()
    summary["is_admin"] = is_admin
    return c.checks, c.findings, summary


def _project_root_text() -> str:
    try:
        from homesoc.paths import project_root

        return str(project_root())
    except Exception:
        return "<the Home SOC folder>"


def _redact_user(posture: dict[str, Any]) -> str | None:
    admins = posture.get("admins")
    if isinstance(admins, dict):
        user = admins.get("current_user")
        return str(user) if user else None
    return None


def _eval_defender(c: Collector, section: Any) -> None:
    from homesoc.scanners import defender  # lazy: defender imports our helpers at module level

    if not isinstance(section, dict):
        for cid in defender.STATUS_CHECK_IDS:
            if is_denied(section):
                c.denied(cid, "Microsoft Defender readable")
            else:
                c.unknown(cid, "Microsoft Defender readable", section if isinstance(section, str) else "no data")
        return
    defender.evaluate_status(section, c)
    threats = defender.normalize_threats({"detections": as_list(section.get("threats")), "events": []})
    defender.evaluate_threats(threats, c)


def _eval_firewall(c: Collector, section: Any) -> None:
    exp = "all profiles enabled"
    if not c.gate("WIN-FW-001", section, exp):
        c.check("WIN-FW-002", "needs_admin" if is_denied(section) else "unknown", None, "default inbound Block", needs_admin=is_denied(section))
        return
    profiles = [p for p in as_list(section) if isinstance(p, dict)]
    if not profiles:
        c.unknown("WIN-FW-001", exp, "no profiles reported")
        c.unknown("WIN-FW-002", "default inbound Block", "no profiles reported")
        return
    disabled = [str(p.get("name")) for p in profiles if truthy(p.get("enabled")) is False]
    if disabled:
        c.check("WIN-FW-001", "fail", "disabled: " + ", ".join(disabled), exp)
        for name in disabled:  # per-profile findings (SPEC 9)
            c.finding("WIN-FW-001", {"profile": name}, key=name)
    else:
        c.ok("WIN-FW-001", "enabled: " + ", ".join(str(p.get("name")) for p in profiles), exp)
    # "NotConfigured" means the built-in default (Block) applies; only an explicit Allow is a hole.
    allow = [str(p.get("name")) for p in profiles if _inbound_allows(p.get("default_inbound")) and truthy(p.get("enabled")) is not False]
    if allow:
        c.fail("WIN-FW-002", "inbound Allow: " + ", ".join(allow), "default inbound Block", {"profile": ", ".join(allow), "profiles": allow})
    else:
        c.ok("WIN-FW-002", "Block", "default inbound Block")


def _inbound_allows(value: Any) -> bool:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value) == 2  # NetSecurity enum: NotConfigured=0, Allow=2, Block=4
    return str(value or "").strip().lower() == "allow"


def _eval_accounts(c: Collector, posture: dict[str, Any]) -> None:
    admins = posture.get("admins")
    if c.gate("WIN-ACC-001", admins, "daily account is a standard user"):
        if isinstance(admins, dict) and truthy(admins.get("current_is_admin_member")):
            members = [m.get("name") for m in as_list(admins.get("members")) if isinstance(m, dict)]
            c.fail("WIN-ACC-001", f"{admins.get('current_user')} is in Administrators", "standard user", {"user": admins.get("current_user"), "administrators": members})
        elif isinstance(admins, dict):
            c.ok("WIN-ACC-001", f"{admins.get('current_user')} is a standard user", "standard user")
        else:
            c.unknown("WIN-ACC-001", "standard user")

    builtin = posture.get("builtin_admin")
    if c.gate("WIN-ACC-002", builtin, "built-in Administrator disabled"):
        if isinstance(builtin, dict) and truthy(builtin.get("enabled")):
            c.fail("WIN-ACC-002", "enabled", "disabled", {"name": builtin.get("name"), "last_logon": builtin.get("last_logon")})
        elif isinstance(builtin, dict):
            c.ok("WIN-ACC-002", "disabled", "disabled")
        else:
            c.unknown("WIN-ACC-002", "disabled", "account not found")

    guest = posture.get("guest")
    if c.gate("WIN-ACC-003", guest, "Guest disabled"):
        if isinstance(guest, dict) and truthy(guest.get("enabled")):
            c.fail("WIN-ACC-003", "enabled", "disabled", {"name": guest.get("name")})
        elif isinstance(guest, dict):
            c.ok("WIN-ACC-003", "disabled", "disabled")
        else:
            c.unknown("WIN-ACC-003", "disabled", "account not found")

    auto = posture.get("autologon") if isinstance(posture.get("autologon"), dict) else {}
    if str(auto.get("AutoAdminLogon", "")).strip() == "1":
        c.fail("WIN-ACC-004", "AutoAdminLogon=1", "AutoAdminLogon=0", {"user": auto.get("DefaultUserName"), "password_stored": bool(truthy(auto.get("has_default_password")))})
    else:
        c.ok("WIN-ACC-004", "off", "AutoAdminLogon=0")

    uac = posture.get("uac") if isinstance(posture.get("uac"), dict) else {}
    lua = to_int(uac.get("EnableLUA"), 1)
    cpba = to_int(uac.get("ConsentPromptBehaviorAdmin"), 5)
    if lua == 0 or cpba == 0:
        c.fail("WIN-ACC-005", f"EnableLUA={lua} ConsentPromptBehaviorAdmin={cpba}", "EnableLUA=1, ConsentPromptBehaviorAdmin>=2", {"EnableLUA": lua, "ConsentPromptBehaviorAdmin": cpba})
    else:
        c.ok("WIN-ACC-005", f"EnableLUA={lua} ConsentPromptBehaviorAdmin={cpba}", "EnableLUA=1, ConsentPromptBehaviorAdmin>=2")


def _eval_network(c: Collector, posture: dict[str, Any], cfg: Any) -> None:
    smb = posture.get("smb")
    if c.gate("WIN-NET-001", smb, "SMBv1 disabled"):
        if isinstance(smb, dict) and truthy(smb.get("EnableSMB1Protocol")):
            c.fail("WIN-NET-001", "SMBv1 enabled", "disabled", {"EnableSMB1Protocol": True})
        elif isinstance(smb, dict):
            c.ok("WIN-NET-001", "disabled", "disabled")
        else:
            c.unknown("WIN-NET-001", "disabled")
    if c.gate("WIN-NET-003", smb, "RequireSecuritySignature=true"):
        if isinstance(smb, dict) and truthy(smb.get("RequireSecuritySignature")) is False:
            c.fail("WIN-NET-003", "signing not required", "required", {"RequireSecuritySignature": False, "EnableSecuritySignature": truthy(smb.get("EnableSecuritySignature"))})
        elif isinstance(smb, dict):
            c.ok("WIN-NET-003", "required", "required")
        else:
            c.unknown("WIN-NET-003", "required")

    rdp = posture.get("rdp") if isinstance(posture.get("rdp"), dict) else {}
    deny = to_int(rdp.get("fDenyTSConnections"), 1)
    nla = to_int(rdp.get("UserAuthentication"), 1)
    if deny == 0:
        sev = "high" if nla == 0 else None
        c.fail("WIN-NET-002", f"RDP enabled, NLA={'off' if nla == 0 else 'on'}", "RDP disabled", {"fDenyTSConnections": deny, "nla": nla != 0}, severity=sev)
    else:
        c.ok("WIN-NET-002", "disabled", "RDP disabled")

    llmnr = posture.get("llmnr") if isinstance(posture.get("llmnr"), dict) else {}
    mc = to_int(llmnr.get("EnableMulticast"))
    if mc == 0:
        c.ok("WIN-NET-004", "EnableMulticast=0", "EnableMulticast=0")
    else:
        c.fail("WIN-NET-004", "policy unset (LLMNR on by default)" if mc is None else f"EnableMulticast={mc}", "EnableMulticast=0", {"EnableMulticast": mc})

    listeners = [l for l in as_list(posture.get("listeners")) if isinstance(l, dict)]
    ports = {to_int(l.get("port")) for l in listeners}
    winrm = posture.get("winrm") if isinstance(posture.get("winrm"), dict) else {}
    rreg = posture.get("remote_registry") if isinstance(posture.get("remote_registry"), dict) else {}
    exposed = []
    if 5985 in ports or 5986 in ports or str(winrm.get("status", "")).lower() == "running":
        exposed.append("WinRM")
    if str(rreg.get("status", "")).lower() == "running":
        exposed.append("Remote Registry")
    if exposed:
        listening = sorted(p for p in (5985, 5986) if p in ports)
        c.fail("WIN-NET-005", ", ".join(exposed), "WinRM and Remote Registry stopped",
               {"port": ", ".join(str(p) for p in listening) or ", ".join(exposed), "services": exposed, "winrm": winrm, "remote_registry": rreg})
    else:
        c.ok("WIN-NET-005", "WinRM/Remote Registry not running", "WinRM and Remote Registry stopped")

    if is_denied(posture.get("listeners")):
        c.denied("WIN-NET-006", "no unexpected LAN listeners")
    else:
        unusual = unusual_listeners(listeners, cfg)
        if unusual:
            c.check("WIN-NET-006", "fail", ", ".join(f"{u['port']}/{u.get('process') or '?'}" for u in unusual), "no unexpected LAN listeners")
            for u in unusual:
                c.finding("WIN-NET-006", u, key=str(u["port"]))
        else:
            c.ok("WIN-NET-006", f"{len(listeners)} listeners, all expected", "no unexpected LAN listeners")


def unusual_listeners(listeners: list[dict[str, Any]], cfg: Any = None) -> list[dict[str, Any]]:
    """TCP listeners reachable from the LAN that are not baseline Windows or Home SOC ports."""
    excluded = set(_EXPECTED_LISTENER_PORTS)
    excluded.add(to_int(cfg_get(cfg, "web.port", 8787), 8787) or 8787)
    excluded.add(to_int(cfg_get(cfg, "dns.port", 53), 53) or 53)
    seen: dict[int, dict[str, Any]] = {}
    for l in listeners:
        port = to_int(l.get("port"))
        addr = str(l.get("address") or "")
        if port is None or port in excluded or 49000 <= port <= 49999:
            continue
        if addr.startswith(_LOOPBACK_PREFIXES):
            continue
        seen.setdefault(port, {"port": port, "address": addr, "process": l.get("process"), "pid": l.get("pid")})
    return [seen[p] for p in sorted(seen)]


def _eval_system(c: Collector, posture: dict[str, Any], is_admin: bool) -> None:
    # Secure Boot: the registry mirror is readable without elevation, so prefer it over ACCESS_DENIED.
    sb = posture.get("secure_boot")
    sb_reg = to_int(posture.get("secure_boot_registry"))
    sb_state = truthy(sb) if not (is_denied(sb) or is_error(sb)) else (sb_reg == 1 if sb_reg is not None else None)
    if sb_state is None:
        c.gate("WIN-SYS-001", sb if isinstance(sb, str) else ACCESS_DENIED, "Secure Boot on")
    elif sb_state:
        c.ok("WIN-SYS-001", "on" + ("" if not is_denied(sb) else " (registry)"), "Secure Boot on")
    else:
        c.fail("WIN-SYS-001", "off", "Secure Boot on", {"secure_boot": sb, "registry": sb_reg})

    bl = posture.get("bitlocker")
    if c.gate("WIN-SYS-002", bl, "OS volume encrypted"):
        vols = [v for v in as_list(bl) if isinstance(v, dict)]
        unprotected = [v for v in vols if str(v.get("protection", "")).lower() not in ("on", "1")]
        if not vols:
            c.unknown("WIN-SYS-002", "OS volume encrypted", "no volumes reported")
        elif unprotected:
            c.fail("WIN-SYS-002", "off: " + ", ".join(str(v.get("mount")) for v in unprotected), "OS volume encrypted", {"volumes": vols})
        else:
            c.ok("WIN-SYS-002", "on: " + ", ".join(str(v.get("mount")) for v in vols), "OS volume encrypted")

    dg = posture.get("device_guard")
    if c.gate("WIN-SYS-003", dg, "VBS running with HVCI"):
        dg = dg if isinstance(dg, dict) else {}
        vbs = to_int(dg.get("VirtualizationBasedSecurityStatus"), 0)
        running = [to_int(x) for x in as_list(dg.get("SecurityServicesRunning"))]
        hvci = 2 in running
        if vbs == 2 and hvci:
            c.ok("WIN-SYS-003", "VBS running, HVCI running", "VBS running with HVCI")
        else:
            c.fail("WIN-SYS-003", f"VBS status={vbs}, HVCI={'running' if hvci else 'not running'}", "VBS running with HVCI", {"vbs_status": vbs, "services_running": running})

    lsa = posture.get("lsa") if isinstance(posture.get("lsa"), dict) else {}
    ppl = to_int(lsa.get("RunAsPPL"))
    if ppl in (1, 2):
        c.ok("WIN-SYS-004", f"RunAsPPL={ppl}", "RunAsPPL=1 or 2")
    else:
        c.fail("WIN-SYS-004", "RunAsPPL unset" if ppl is None else f"RunAsPPL={ppl}", "RunAsPPL=1 or 2", {"RunAsPPL": ppl})

    ps2 = posture.get("ps_v2") if isinstance(posture.get("ps_v2"), dict) else {}
    state = ps2.get("state")
    if c.gate("WIN-SYS-005", state, "PowerShell v2 feature disabled"):
        text = str(state or "").lower()
        if text.startswith("enabled"):
            c.fail("WIN-SYS-005", "enabled", "disabled", {"state": state})
        elif text.startswith("disabled") or text == "notpresent":
            c.ok("WIN-SYS-005", "disabled", "disabled")
        else:
            c.unknown("WIN-SYS-005", "disabled", state)

    ss = posture.get("smartscreen") if isinstance(posture.get("smartscreen"), dict) else {}
    explorer = str(ss.get("SmartScreenEnabled") or "").strip().lower()
    policy = to_int(ss.get("policy_EnableSmartScreen"))
    if explorer == "off" or policy == 0:
        c.fail("WIN-SYS-006", f"SmartScreenEnabled={ss.get('SmartScreenEnabled')} policy={policy}", "SmartScreen on", {"SmartScreenEnabled": ss.get("SmartScreenEnabled"), "policy_EnableSmartScreen": policy})
    else:
        c.ok("WIN-SYS-006", ss.get("SmartScreenEnabled") or "default (on)", "SmartScreen on")

    lock = posture.get("screen_lock") if isinstance(posture.get("screen_lock"), dict) else {}
    inactivity = to_int(lock.get("InactivityTimeoutSecs"), 0) or 0
    saver_on = str(lock.get("ScreenSaveActive") or "").strip() == "1"
    saver_secure = str(lock.get("ScreenSaverIsSecure") or "").strip() == "1"
    saver_timeout = to_int(lock.get("ScreenSaveTimeOut"), 0) or 0
    if inactivity > 0 or (saver_on and saver_secure and saver_timeout > 0):
        c.ok("WIN-SYS-007", f"inactivity={inactivity}s saver={saver_timeout}s secure={saver_secure}", "automatic lock configured")
    else:
        c.fail("WIN-SYS-007", "no lock timeout", "automatic lock configured", {"InactivityTimeoutSecs": inactivity, "ScreenSaveActive": saver_on, "ScreenSaverIsSecure": saver_secure, "ScreenSaveTimeOut": saver_timeout, "display_off_ac_sec": lock.get("display_off_ac_sec")})

    tpm = posture.get("tpm")
    pnp = [d for d in as_list(posture.get("tpm_pnp")) if isinstance(d, dict)]
    if c.gate("WIN-SYS-008", tpm, "TPM present and ready"):
        tpm = tpm if isinstance(tpm, dict) else {}
        present = truthy(tpm.get("present"))
        ready = truthy(tpm.get("ready"))
        enabled = truthy(tpm.get("enabled"))
        if present and (ready or enabled):
            c.ok("WIN-SYS-008", f"present, enabled={enabled}, spec={tpm.get('spec')}", "TPM present and ready")
        else:
            c.fail("WIN-SYS-008", "absent" if not present else "not ready", "TPM present and ready", {"tpm": tpm, "pnp": pnp})
    elif pnp:
        # Readiness needs admin, but the PnP class proves the chip exists — record that in the value.
        c.checks[-1].value = "present per PnP (" + str(pnp[0].get("name")) + "); readiness requires administrator"

    sac = posture.get("smart_app_control") if isinstance(posture.get("smart_app_control"), dict) else {}
    sac_state = to_int(sac.get("VerifiedAndReputablePolicyState"))
    if sac_state in (1, 2):
        c.ok("WIN-DEF-013", "on" if sac_state == 1 else "evaluation", "Smart App Control on")
    else:
        c.fail("WIN-DEF-013", "off" if sac_state == 0 else "unknown", "Smart App Control on", {"VerifiedAndReputablePolicyState": sac_state})


def _eval_hotfix(c: Collector, hotfix: Any, last_cumulative: str | None = None) -> None:
    """WIN-UPD-002 from Get-HotFix, reconciled with the Windows Update history date.

    updates.py evaluates the same finding from the WU history, which sees enablement/feature
    updates that Get-HotFix does not list. Both scanners emit subject ``host``, so they share one
    dedupe key: if they ever disagreed the row would be re-labelled every scan and could never
    auto-resolve. ``last_cumulative`` (persisted by updates.py, replayed by ``run()``) is therefore
    preferred whenever it is the newer of the two dates, which makes the verdicts identical.
    A failing check emits its finding here as well, so every fail/warn row has one (SPEC 6.5).
    """
    from homesoc.scanners.updates import CUMULATIVE_MAX_DAYS, days_since

    if not c.gate("WIN-UPD-002", hotfix, f"cumulative update within {CUMULATIVE_MAX_DAYS} days"):
        return
    hotfix = hotfix if isinstance(hotfix, dict) else {}
    last = hotfix.get("last_installed")
    source = "hotfix"
    hotfix_days = days_since(last)
    history_days = days_since(last_cumulative)
    if history_days is not None and (hotfix_days is None or history_days < hotfix_days):
        last, source, days = last_cumulative, "windows update history", history_days
    else:
        days = hotfix_days
    # Value/evidence wording matches updates.windows_update_findings exactly: both scanners write
    # this one host_checks row and this one finding, so differing text would churn on every scan.
    expected = f"cumulative update within {CUMULATIVE_MAX_DAYS} days"
    if days is None:
        c.unknown("WIN-UPD-002", expected, "no install date available")
    elif days > CUMULATIVE_MAX_DAYS:
        c.fail(
            "WIN-UPD-002",
            f"{days} days ago ({str(last)[:10]})",
            expected,
            {"last": last, "days": days, "title": hotfix.get("last_id"), "source": source},
        )
    else:
        c.ok("WIN-UPD-002", f"{days} days ago ({str(last)[:10]})", expected)


def _last_cumulative_date(conn: Any) -> str | None:
    """Windows Update history date recorded by ``updates.py`` (read-only; None when absent)."""
    try:
        raw = db.get_setting(conn, "updates.status_json")
        data = safe_json_loads(raw) if raw else None
        history = data.get("history") if isinstance(data, dict) else None
        value = history.get("last_cumulative_date") if isinstance(history, dict) else None
        return str(value) if value else None
    except Exception:  # noqa: BLE001 - a missing/garbled setting must never fail the posture scan
        logger.debug("could not read updates.status_json for WIN-UPD-002", exc_info=True)
        return None


# --------------------------------------------------------------------------- scanner entry point


def run(cfg: Config, conn: Any, *, quick: bool = False, progress: Callable[[str], None] | None = None) -> ScanResult:
    """Scanner interface (SPEC 6): run the posture probe, persist checks, return drafts."""
    started = time.monotonic()
    notify = progress or (lambda _msg: None)
    if not is_windows():
        return ScanResult("host", [], {"skipped": "not windows"}, error="host_windows runs on Windows only")
    if not cfg_get(cfg, "host.posture", True):
        return ScanResult("host", [], {"skipped": "host.posture disabled"})

    notify("host: running posture probe")
    res = run_ps_json(PS_DIR / "posture.ps1", timeout=POSTURE_TIMEOUT_SEC)
    if res.data is None:
        db.record_event(conn, "warning", "host", f"posture probe failed: {res.error}")
        return ScanResult("host", [], {"duration_sec": round(time.monotonic() - started, 2)}, error=res.error)

    checks, findings, summary = evaluate(res.data, cfg, last_cumulative=_last_cumulative_date(conn))
    write_checks(conn, checks)
    # SPEC-GAP: the /host page needs the raw listeners and Wi-Fi/DNS facts; the spec only defines
    # host_checks rows, so the whole probe result is kept under a settings key for the web layer.
    db.set_setting(conn, "host.posture_json", json_dumps(res.data))
    db.set_setting(conn, "host.posture_at", utcnow_iso())
    db.record_metric(conn, "host.checks_fail", float(summary.get("fail", 0)))
    summary.update({"duration_sec": round(time.monotonic() - started, 2), "probe_sec": res.data.get("elapsed_sec"), "findings": len(findings)})
    notify(f"host: {summary['fail']} failing checks, {summary['needs_admin']} need admin")
    return ScanResult("host", findings, summary)


__all__ = [
    "ACCESS_DENIED",
    "PS_DIR",
    "Collector",
    "PsResult",
    "SkippedChecks",
    "as_list",
    "cfg_get",
    "evaluate",
    "extract_json",
    "is_denied",
    "is_error",
    "powershell_exe",
    "run",
    "run_ps_json",
    "to_int",
    "truthy",
    "unusual_listeners",
    "write_checks",
]
