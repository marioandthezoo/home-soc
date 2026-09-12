"""Scanner modules for Home SOC.

Every scanner exposes the same entry point (SPEC section 6)::

    run(cfg, conn, *, quick=False, progress=None) -> ScanResult

Submodules are deliberately not imported here: several of them shell out to
platform tools (PowerShell, nmap, netsh) and the CLI wires each scanner with an
explicit ``from homesoc.scanners import <name>``.  Importing this package must
never have side effects or platform requirements.

The handful of helpers below are shared by the network scanners so each one
does not re-invent "run a command with a timeout and never raise".
"""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "discovery", "ports", "nmap_xml", "services", "exposure", "mdns_ssdp", "wifi",
    "host_windows", "host_posix", "defender", "updates", "persistence", "files",
    "IS_WINDOWS", "IS_MAC", "IS_LINUX", "cfg_get", "run_command", "powershell", "CommandResult",
]

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Hidden console windows for child processes when running from a shortcut.
_CREATION_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0


def cfg_get(cfg: Any, dotted: str, default: Any = None) -> Any:
    """Read ``cfg.section.key`` tolerating dataclasses, namespaces and plain dicts.

    Scanners are exercised in tests with lightweight config stand-ins, and a
    missing key should fall back to the documented default rather than crash
    a scan.
    """
    cur = cfg
    for part in dotted.split("."):
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
    return default if cur is None else cur


@dataclass
class CommandResult:
    rc: int | None
    out: str
    err: str
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out and not self.missing


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # Windows console tools (netsh, arp) emit the OEM/ANSI code page.
        return raw.decode("mbcs" if IS_WINDOWS else "latin-1", errors="replace")


def run_command(args: Sequence[str], timeout: float, *, input_text: str | None = None) -> CommandResult:
    """Run a fixed argv (never a shell string) with a hard timeout; never raises.

    The argv is always built from constants plus validated values (IPs,
    integers), so there is no path for user-controlled strings to reach a shell.
    """
    try:
        proc = subprocess.run(
            list(args),
            capture_output=True,
            timeout=timeout,
            input=input_text.encode("utf-8") if input_text is not None else None,
            creationflags=_CREATION_FLAGS,
            shell=False,
        )
    except FileNotFoundError:
        return CommandResult(None, "", f"{args[0]}: not found", missing=True)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(None, _decode(exc.stdout), _decode(exc.stderr), timed_out=True)
    except (OSError, ValueError) as exc:
        return CommandResult(None, "", str(exc), missing=True)
    return CommandResult(proc.returncode, _decode(proc.stdout), _decode(proc.stderr))


def powershell(script: str, timeout: float = 30.0) -> CommandResult:
    """Run a fixed PowerShell snippet (Windows only) and return its stdout."""
    if not IS_WINDOWS:
        return CommandResult(None, "", "powershell: not available on this platform", missing=True)
    return run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout,
    )
