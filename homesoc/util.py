"""Small cross-platform helpers used by every package.

Nothing here touches the database or the config; that keeps the module safe to
import from anywhere (including the DNS hot path) without circular imports.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Exit codes run_cmd uses for "the command never really ran" situations, chosen to
# match the shell conventions so log lines read naturally.
RC_NOT_FOUND = 127
RC_TIMEOUT = 124

# --------------------------------------------------------------------------- time


def utcnow_iso() -> str:
    """Current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``.

    Whole seconds and a fixed ``Z`` suffix keep every stored timestamp the same
    width, so plain string comparison in SQL orders them correctly.
    """
    return to_iso(datetime.now(timezone.utc))


def to_iso(dt: datetime) -> str:
    """Format any datetime in the canonical storage form (naive values are taken as UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str | datetime | None) -> datetime | None:
    """Parse ISO-8601 text into an aware UTC datetime; ``None`` for empty or garbage.

    Accepts the canonical ``Z`` form, ``+00:00`` offsets, naive strings (assumed
    UTC), a bare date, and a space instead of ``T`` — feeds and PowerShell output
    all produce slightly different flavours.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def human_age(value: str | datetime | None, now: datetime | None = None) -> str:
    """Compact relative age for tables ("3 h ago"); ``never`` when there is no timestamp."""
    dt = parse_iso(value)
    if dt is None:
        return "never"
    ref = now.astimezone(timezone.utc) if now and now.tzinfo else (now.replace(tzinfo=timezone.utc) if now else datetime.now(timezone.utc))
    seconds = (ref - dt).total_seconds()
    if seconds < 0:
        return "in " + _duration_words(-seconds)
    if seconds < 45:
        return "just now"
    return _duration_words(seconds) + " ago"


def _duration_words(seconds: float) -> str:
    if seconds < 3600:
        return f"{max(1, int(seconds // 60))} min"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h"
    return f"{int(seconds // 86400)} d"


def age_seconds(value: str | datetime | None) -> float | None:
    dt = parse_iso(value)
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds()


def iso_ago(**delta: float) -> str:
    """ISO timestamp for "now minus <timedelta kwargs>" — handy in retention queries."""
    return to_iso(datetime.now(timezone.utc) - timedelta(**delta))


# ---------------------------------------------------------------------- processes


def run_cmd(
    args: Sequence[str],
    timeout: float,
    cwd: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> tuple[int, str, str]:
    """Run a command without a shell and always come back with ``(rc, stdout, stderr)``.

    A missing binary or a timeout is an *expected* failure for a scanner, so both
    are reported through the return code (127 / 124) rather than raised — callers
    then decide whether that is a finding or just a skipped check.
    """
    argv = [str(a) for a in args]
    if not argv:
        raise ValueError("run_cmd needs at least the program name")
    kwargs: dict[str, Any] = {}
    if is_windows():
        # Hide the console window that PowerShell/netsh would otherwise flash open.
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
            input=input_text,
            shell=False,
            **kwargs,
        )
    except FileNotFoundError:
        return RC_NOT_FOUND, "", f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired as exc:
        out = _as_text(exc.stdout)
        err = _as_text(exc.stderr)
        return RC_TIMEOUT, out, (err + "\n" if err else "") + f"timeout after {timeout}s"
    except OSError as exc:  # permission denied, bad executable format, ...
        return RC_NOT_FOUND, "", f"cannot run {argv[0]}: {exc}"
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def which(name: str) -> str | None:
    """``shutil.which`` with the Windows Program Files fallback for nmap."""
    found = shutil.which(name)
    if found:
        return found
    if is_windows() and name.lower() in ("nmap", "nmap.exe"):
        for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
            if base and (Path(base) / "Nmap" / "nmap.exe").is_file():
                return str(Path(base) / "Nmap" / "nmap.exe")
    return None


# -------------------------------------------------------------------------- json


def safe_json_loads(text: str | bytes | None, default: Any = None) -> Any:
    """Parse JSON from untrusted text; return ``default`` instead of raising."""
    if text is None:
        return default
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    # PowerShell (and some feeds) prepend a UTF-8 BOM.
    text = text.strip().lstrip("\ufeff")
    if not text:
        return default
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return default


def json_dumps(obj: Any) -> str:
    """Compact, deterministic JSON for TEXT columns; unserialisable values become strings."""
    return json.dumps(obj, default=str, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------- platform


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def platform_name() -> str:
    return f"{platform.system()} {platform.release()}"


def local_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "localhost"


# ----------------------------------------------------------------------- network


def default_interface_ip() -> str:
    """IPv4 address of the interface that routes to the internet.

    Connecting a UDP socket sends no packets; the kernel just picks the source
    address it *would* use, which is exactly the LAN address we want to scan from.
    """
    for probe in ("1.1.1.1", "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.connect((probe, 53))
                ip = sock.getsockname()[0]
                if ip and not ip.startswith("0."):
                    return ip
        except OSError:
            continue
    try:
        ip = socket.gethostbyname(local_hostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def default_cidr() -> str:
    """The /24 containing the default interface — what ``network.cidr = "auto"`` means."""
    ip = default_interface_ip()
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return "192.168.1.0/24"


def default_gateway() -> str:
    """IPv4 default gateway, read from the OS routing table without admin rights."""
    gw: str | None = None
    if is_windows():
        gw = _gateway_windows()
    elif is_linux():
        gw = _gateway_linux()
    elif is_macos():
        gw = _gateway_macos()
    if gw and _is_ipv4(gw):
        return gw
    # Last resort: the conventional first host of the local /24.
    net = ipaddress.ip_network(default_cidr(), strict=False)
    return str(next(net.hosts()))


def _is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _gateway_windows() -> str | None:
    rc, out, _ = run_cmd(["route", "print", "-4", "0.0.0.0"], timeout=8)
    if rc != 0:
        return None
    best: tuple[int, str] | None = None
    for line in out.splitlines():
        parts = line.split()
        # "0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>"
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0" and _is_ipv4(parts[2]):
            try:
                metric = int(parts[4])
            except ValueError:
                metric = 9999
            if best is None or metric < best[0]:
                best = (metric, parts[2])
    return best[1] if best else None


def _gateway_linux() -> str | None:
    rc, out, _ = run_cmd(["ip", "-j", "route", "show", "default"], timeout=5)
    if rc == 0:
        routes = safe_json_loads(out, [])
        if isinstance(routes, list):
            for route in routes:
                if isinstance(route, dict) and route.get("gateway"):
                    return str(route["gateway"])
    rc, out, _ = run_cmd(["ip", "route", "show", "default"], timeout=5)
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    return None


def _gateway_macos() -> str | None:
    rc, out, _ = run_cmd(["route", "-n", "get", "default"], timeout=5)
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            return line.split(":", 1)[1].strip()
    return None


# -------------------------------------------------------------------------- files


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Write via a temp file + replace so a crash never leaves a half-written file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


__all__ = [
    "RC_NOT_FOUND",
    "RC_TIMEOUT",
    "utcnow_iso",
    "to_iso",
    "parse_iso",
    "human_age",
    "age_seconds",
    "iso_ago",
    "run_cmd",
    "which",
    "safe_json_loads",
    "json_dumps",
    "is_windows",
    "is_macos",
    "is_linux",
    "platform_name",
    "local_hostname",
    "default_interface_ip",
    "default_cidr",
    "default_gateway",
    "atomic_write_text",
]
