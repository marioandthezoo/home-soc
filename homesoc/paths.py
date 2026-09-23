"""Filesystem locations for Home SOC.

Every function re-reads the environment on each call (no caching) so tests can
point ``HOMESOC_DATA`` / ``HOMESOC_CONFIG`` at a temporary directory and the
rest of the code base picks it up without restarts.
"""

from __future__ import annotations

import logging
import os
import re
import stat
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

ENV_DATA = "HOMESOC_DATA"
ENV_CONFIG = "HOMESOC_CONFIG"

#: The data folder holds the device map, the DNS query history and every secret entered on the
#: Settings page, so it is owner-only on POSIX, like config.toml (mkstemp) and the TLS key.
PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600

#: What makes an existing folder recognisably a Home SOC data folder. Permissions are only ever
#: tightened on one of these (or on an empty folder), never on an arbitrary directory someone
#: pointed HOMESOC_DATA at, such as a home directory or a drive root.
_DATA_MARKERS: tuple[str, ...] = ("homesoc.db", "feeds", "logs", "tls")

# Folders already tightened by this process: data_dir() runs on hot paths, and the Windows ACL
# change starts two processes, so each folder is handled once per start (a restart re-applies it).
_SECURED: set[str] = set()
_SECURED_LOCK = threading.Lock()

_SID_RE = re.compile(r"S-1-[0-9-]+")
# Well-known SIDs that keep access on Windows: LocalSystem and BUILTIN\Administrators.
_WINDOWS_KEEP_SIDS: tuple[str, ...] = ("S-1-5-18", "S-1-5-32-544")


def project_root() -> Path:
    """Folder containing ``pyproject.toml``, found by walking up from this file.

    Falls back to the package's parent directory when the project is installed
    as a wheel (no ``pyproject.toml`` on disk) so ``data/`` still lands
    somewhere predictable.
    """
    here = Path(__file__).resolve()
    for candidate in (here.parent, *here.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return here.parent.parent


def data_dir() -> Path:
    """Runtime data folder (``HOMESOC_DATA`` or ``<root>/data``), created on demand, owner-only."""
    raw = os.environ.get(ENV_DATA, "").strip()
    path = Path(raw).expanduser() if raw else project_root() / "data"
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    _secure_data_dir(path)
    return path


def feeds_dir() -> Path:
    path = data_dir() / "feeds"
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    return path


def logs_dir() -> Path:
    path = data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    restrict_path(path, PRIVATE_DIR_MODE)
    return path


# ------------------------------------------------------------------ permissions


def restrict_path(path: Path | str, mode: int = PRIVATE_FILE_MODE) -> bool:
    """POSIX: drop group/other access from ``path`` (an existing install made it 0644/0755).

    Only ever removes bits, never adds any, and never touches a file owned by someone else.
    True when the path is now private (or on Windows, where the folder ACL does the job).
    """
    if os.name == "nt":
        return True
    target = Path(path)
    try:
        st = target.stat()
    except OSError:
        return False
    current = stat.S_IMODE(st.st_mode)
    if not current & 0o077:
        return True
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        logger.warning("%s is owned by another account and readable by other users; "
                       "fix its permissions by hand (chmod %o)", target, mode)
        return False
    try:
        os.chmod(target, current & mode)
    except OSError as exc:
        logger.warning("cannot restrict permissions of %s: %s", target, exc)
        return False
    return True


def _looks_like_data_dir(path: Path) -> bool:
    try:
        entries = {child.name for child in path.iterdir()}
    except OSError:
        return False
    return not entries or any(marker in entries for marker in _DATA_MARKERS)


def _secure_data_dir(path: Path) -> None:
    """Make the data folder private to this account, once per process and folder."""
    key = str(path)
    with _SECURED_LOCK:
        if key in _SECURED:
            return
        _SECURED.add(key)
    if not _looks_like_data_dir(path):
        logger.warning("HOMESOC_DATA %s already holds other files; leaving its permissions alone. "
                       "Point it at a folder of its own so Home SOC can make it private.", path)
        return
    if os.name == "nt":
        _restrict_windows_acl(path)
    else:
        restrict_path(path, PRIVATE_DIR_MODE)


def _inside_user_profile(path: Path) -> bool:
    profile = os.environ.get("USERPROFILE", "").strip()
    if not profile:
        return False
    try:
        path.resolve().relative_to(Path(profile).resolve())
    except (ValueError, OSError):
        return False
    return True


def _current_user_sid() -> str | None:
    from homesoc import util  # local: util must stay importable without paths and vice versa

    whoami = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "whoami.exe"
    rc, out, _err = util.run_cmd([str(whoami), "/user", "/fo", "csv", "/nh"], timeout=15)
    if rc != 0:
        return None
    sids = _SID_RE.findall(out)
    return sids[-1] if sids else None


def _restrict_windows_acl(path: Path) -> bool:
    r"""Windows: a folder under the user profile is already private to that user. One elsewhere
    (``C:\HomeSOC-data``, what the elevated-autostart guidance leads to) inherits
    ``Authenticated Users: Modify`` from the drive root, which would let every local account read
    the secrets and plant settings or Lens tokens that the (possibly elevated) process trusts.
    Replace the inherited ACL with this account, SYSTEM and Administrators only."""
    resolved = path.resolve()
    if _inside_user_profile(path) or resolved == Path(resolved.anchor):
        return True
    sid = _current_user_sid()
    if not sid:
        logger.warning("cannot determine the current account's SID; the permissions of %s are unchanged", path)
        return False
    from homesoc import util

    icacls = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe"
    grants: list[str] = []
    for principal in (sid, *_WINDOWS_KEEP_SIDS):
        grants += ["/grant:r", f"*{principal}:(OI)(CI)F"]
    rc, _out, err = util.run_cmd([str(icacls), str(path), "/inheritance:r", *grants], timeout=60)
    if rc != 0:
        logger.warning("could not make %s private to this account (icacls rc=%d): %s", path, rc, err.strip())
        return False
    logger.info("restricted %s to this account, SYSTEM and Administrators", path)
    return True


def db_path() -> Path:
    return data_dir() / "homesoc.db"


def config_path() -> Path:
    """User config file (``HOMESOC_CONFIG`` or ``<root>/config.toml``); may not exist yet."""
    raw = os.environ.get(ENV_CONFIG, "").strip()
    return Path(raw).expanduser() if raw else project_root() / "config.toml"
