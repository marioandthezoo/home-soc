"""Linux / macOS host posture (SPEC 6.5, second half): small but real.

Firewall (ufw / pf / macOS ALF), pending updates (via ``updates.posix_pending``), sshd
PermitRootLogin, disk encryption heuristics (FileVault / LUKS), and LAN-reachable listeners.
Everything is best-effort without root: a check that needs privileges reports ``needs_admin``.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import ScanResult
from homesoc.scanners.host_windows import Collector, cfg_get, to_int, write_checks
from homesoc.util import is_linux, is_macos, is_windows, json_dumps, run_cmd, utcnow_iso, which

if TYPE_CHECKING:  # pragma: no cover
    from homesoc.config import Config

logger = logging.getLogger(__name__)

CMD_TIMEOUT_SEC = 20
# Ports that are normal on a workstation (ssh, DNS, CUPS, mDNS) plus Home SOC's own.
_EXPECTED_PORTS = {22, 53, 631, 5353}
_LOOPBACK = ("127.", "::1", "localhost")


# --------------------------------------------------------------------------- probes


def firewall_state() -> tuple[str, str]:
    """('active'|'inactive'|'unknown'|'needs_admin', detail)."""
    if is_linux():
        conf = Path("/etc/ufw/ufw.conf")
        if conf.is_file():
            try:
                text = conf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            m = re.search(r"^ENABLED\s*=\s*(\w+)", text, re.MULTILINE)
            if m:
                return ("active" if m.group(1).lower() == "yes" else "inactive"), f"ufw.conf ENABLED={m.group(1)}"
        if which("ufw"):
            rc, out, err = run_cmd(["ufw", "status"], timeout=CMD_TIMEOUT_SEC)
            if rc == 0 and "Status:" in out:
                return ("active" if "Status: active" in out else "inactive"), out.strip().splitlines()[0]
            if "root" in (err + out):
                return "needs_admin", "ufw status requires root"
        for unit in ("firewalld", "nftables", "ufw"):
            if which("systemctl"):
                rc, out, _ = run_cmd(["systemctl", "is-active", unit], timeout=CMD_TIMEOUT_SEC)
                if rc == 0 and out.strip() == "active":
                    return "active", f"{unit} active"
        return "unknown", "no ufw/firewalld/nftables state readable"
    if is_macos():
        rc, out, _ = run_cmd(["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"], timeout=CMD_TIMEOUT_SEC)
        if rc == 0 and out.strip().isdigit():
            state = int(out.strip())
            return ("active" if state > 0 else "inactive"), f"ALF globalstate={state}"
        sf = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        rc, out, _ = run_cmd([sf, "--getglobalstate"], timeout=CMD_TIMEOUT_SEC)
        if rc == 0:
            return ("active" if "enabled" in out.lower() else "inactive"), out.strip()
        rc, out, err = run_cmd(["pfctl", "-s", "info"], timeout=CMD_TIMEOUT_SEC)
        if rc == 0:
            return ("active" if "Status: Enabled" in out else "inactive"), "pf"
        if "permission" in (err or "").lower():
            return "needs_admin", "pfctl requires root"
    return "unknown", "unsupported platform"


def sshd_root_login() -> tuple[str | None, str]:
    """PermitRootLogin effective value from sshd_config (default since OpenSSH 7 is prohibit-password)."""
    cfg = Path("/etc/ssh/sshd_config")
    if not cfg.is_file():
        return None, "no sshd_config"
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"unreadable: {exc}"
    value = "prohibit-password"
    for line in text.splitlines():
        m = re.match(r"^\s*PermitRootLogin\s+(\S+)", line, re.IGNORECASE)
        if m:
            value = m.group(1).lower()
    return value, "sshd_config"


def disk_encrypted() -> tuple[bool | None, str]:
    if is_macos():
        rc, out, _ = run_cmd(["fdesetup", "status"], timeout=CMD_TIMEOUT_SEC)
        if rc == 0:
            return ("FileVault is On" in out), out.strip()
        return None, "fdesetup unavailable"
    if is_linux():
        if which("lsblk"):
            rc, out, _ = run_cmd(["lsblk", "-rno", "TYPE"], timeout=CMD_TIMEOUT_SEC)
            if rc == 0:
                return ("crypt" in out.split()), "lsblk TYPE"
        try:
            mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None, "no /proc/mounts"
        return ("/dev/mapper/" in mounts), "/proc/mounts"
    return None, "unsupported platform"


def listeners() -> list[dict[str, Any]]:
    """TCP listeners as ``{port, address, process}``; empty when no tool is available."""
    out_rows: list[dict[str, Any]] = []
    if which("ss"):
        rc, out, _ = run_cmd(["ss", "-ltnHp"], timeout=CMD_TIMEOUT_SEC)
        if rc != 0:
            rc, out, _ = run_cmd(["ss", "-ltnH"], timeout=CMD_TIMEOUT_SEC)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            addr, _, port = local.rpartition(":")
            proc = None
            m = re.search(r'users:\(\("([^"]+)"', line)
            if m:
                proc = m.group(1)
            if port.isdigit():
                out_rows.append({"port": int(port), "address": addr.strip("[]"), "process": proc})
        return out_rows
    if which("lsof"):
        rc, out, _ = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=CMD_TIMEOUT_SEC)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            addr, _, port = parts[8].rpartition(":")
            if port.isdigit():
                out_rows.append({"port": int(port), "address": addr.strip("[]"), "process": parts[0]})
        return out_rows
    if which("netstat"):
        rc, out, _ = run_cmd(["netstat", "-an"], timeout=CMD_TIMEOUT_SEC)
        for line in out.splitlines():
            if "LISTEN" not in line:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3].replace(".", ":") if is_macos() else parts[3]
            addr, _, port = local.rpartition(":")
            if port.isdigit():
                out_rows.append({"port": int(port), "address": addr, "process": None})
    return out_rows


def unusual_listeners(rows: list[dict[str, Any]], cfg: Any = None) -> list[dict[str, Any]]:
    excluded = set(_EXPECTED_PORTS)
    excluded.add(to_int(cfg_get(cfg, "web.port", 8787), 8787) or 8787)
    excluded.add(to_int(cfg_get(cfg, "dns.port", 53), 53) or 53)
    seen: dict[int, dict[str, Any]] = {}
    for r in rows:
        port = to_int(r.get("port"))
        addr = str(r.get("address") or "")
        if port is None or port in excluded or addr.startswith(_LOOPBACK):
            continue
        seen.setdefault(port, r)
    return [seen[p] for p in sorted(seen)]


# --------------------------------------------------------------------------- evaluation


def evaluate(facts: dict[str, Any], cfg: Any = None) -> Collector:
    """Pure mapping of collected facts to POSIX-* checks/findings (unit-testable without a shell)."""
    c = Collector()
    fw_state, fw_detail = facts.get("firewall", ("unknown", ""))
    if fw_state == "active":
        c.ok("POSIX-FW-001", fw_detail, "firewall active")
    elif fw_state == "inactive":
        c.fail("POSIX-FW-001", fw_detail, "firewall active", {"detail": fw_detail})
    elif fw_state == "needs_admin":
        c.denied("POSIX-FW-001", "firewall active")
    else:
        c.unknown("POSIX-FW-001", "firewall active", fw_detail)

    root_login, ssh_detail = facts.get("sshd", (None, ""))
    if root_login is None:
        c.unknown("POSIX-SSH-001", "PermitRootLogin no", ssh_detail)
    elif root_login == "yes":
        c.fail("POSIX-SSH-001", "PermitRootLogin yes", "PermitRootLogin no", {"PermitRootLogin": root_login})
    else:
        c.ok("POSIX-SSH-001", f"PermitRootLogin {root_login}", "PermitRootLogin no")

    enc, enc_detail = facts.get("encryption", (None, ""))
    if enc is None:
        c.unknown("POSIX-ENC-001", "disk encrypted", enc_detail)
    elif enc:
        c.ok("POSIX-ENC-001", enc_detail, "disk encrypted")
    else:
        c.fail("POSIX-ENC-001", "not encrypted", "disk encrypted", {"detail": enc_detail})

    rows = facts.get("listeners") or []
    unusual = unusual_listeners(rows, cfg)
    if unusual:
        c.check("POSIX-NET-001", "fail", ", ".join(f"{u['port']}/{u.get('process') or '?'}" for u in unusual), "no unexpected listeners")
        for u in unusual:
            c.finding("POSIX-NET-001", u, key=str(u["port"]))
    else:
        c.ok("POSIX-NET-001", f"{len(rows)} listeners, all expected", "no unexpected listeners")
    return c


# --------------------------------------------------------------------------- scanner entry point


def run(cfg: Config, conn: Any, *, quick: bool = False, progress: Callable[[str], None] | None = None) -> ScanResult:
    """Scanner interface (SPEC 6) for Linux/macOS hosts."""
    started = time.monotonic()
    notify = progress or (lambda _msg: None)
    if is_windows():
        return ScanResult("host", [], {"skipped": "windows"}, error="host_posix runs on Linux/macOS only")
    if not cfg_get(cfg, "host.posture", True):
        return ScanResult("host", [], {"skipped": "host.posture disabled"})

    notify("host: collecting posture facts")
    facts = {"firewall": firewall_state(), "sshd": sshd_root_login(), "encryption": disk_encrypted(), "listeners": listeners()}
    c = evaluate(facts, cfg)

    # Pending updates are NOT collected here: cli.scan_host runs scanners.updates as its own step
    # on every platform. Calling it from here too ran the package-manager query twice per scan and
    # published POSIX-UPD-001 under two different sources with one dedupe key, so each run
    # re-labelled the row and neither source could ever auto-resolve it.
    write_checks(conn, c.checks)
    db.set_setting(conn, "host.posture_json", json_dumps({"listeners": facts["listeners"], "firewall": facts["firewall"], "sshd": facts["sshd"], "encryption": facts["encryption"]}))
    db.set_setting(conn, "host.posture_at", utcnow_iso())
    summary = c.summary()
    summary.update({"duration_sec": round(time.monotonic() - started, 2), "findings": len(c.findings)})
    return ScanResult("host", c.findings, summary)


__all__ = ["disk_encrypted", "evaluate", "firewall_state", "listeners", "run", "sshd_root_login", "unusual_listeners"]
