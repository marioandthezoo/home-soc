r"""Start Home SOC for the ELEVATED logon task (``make-autostart.ps1 -Mode task -Elevated``).

The task registers exactly this command and nothing else::

    <root>\.venv\Scripts\pythonw.exe -I -S "<root>\scripts\run-elevated.py" run

Why a separate starter: Task Scheduler gives a logon task the user's environment block, and that
block includes ``HKCU\Environment``, which the (non-admin) user - or malware running as the user -
can write without a UAC prompt. Before this starter, the elevated task ran ``pythonw.exe -m
homesoc run`` and so honoured, with administrator rights:

* ``PYTHONPATH`` / ``PYTHONHOME`` / ``PYTHONSTARTUP`` - a ``sitecustomize.py`` in a folder named
  by ``PYTHONPATH`` ran as administrator at the next logon (reproduced);
* ``PATH`` - Home SOC resolves ``nmap`` and ``winget`` through ``PATH``, and the per-user
  ``PATH`` holds user-writable folders such as ``%LOCALAPPDATA%\Microsoft\WindowsApps``;
* ``ProgramFiles`` / ``ProgramData`` / ``SystemRoot`` - Home SOC builds the paths of
  ``MpCmdRun.exe``, ``nmap.exe``, ``whoami.exe`` and ``icacls.exe`` from them;
* ``PSModulePath`` - the PowerShell that Home SOC starts autoloads modules from it.

This starter removes the whole class instead of chasing variables one by one:

1. ``-I`` (isolated) makes the interpreter ignore every ``PYTHON*`` variable and the user
   site-packages; ``-S`` stops ``site`` from importing anything before step 2.
2. It checks that every import path lies inside the base interpreter or the venv - the two trees
   ``make-autostart.ps1`` verified as administrator-only - and refuses otherwise (this catches,
   for example, a ``PythonPath`` registry entry). Only then does it run ``site.main()``.
3. It REPLACES the environment with one built from machine-wide sources only (``HKLM``, the
   account's token) and a fixed system ``PATH``. The only values taken from the inherited
   environment are ``HOMESOC_DATA`` and ``HOMESOC_CONFIG``, which name data, not code.
4. It runs ``homesoc`` from the Home SOC root, which ``make-autostart.ps1`` also verified.

Nothing here writes anywhere. ``pythonw`` has no console, so a refusal is visible as the task's
"Last Run Result" in Task Scheduler (2: not started isolated, 3: untrusted import path, 4: not
Windows or the machine environment is unreadable).
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable, Mapping

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Inherited variables that are passed through: they select the data folder and the config file,
#: both of which the owner is expected to control (the documented elevated setup keeps the data
#: under the owner's profile). Everything else comes from machine-wide sources.
PASSTHROUGH = ("HOMESOC_DATA", "HOMESOC_CONFIG")

#: Variables never placed in the clean environment even if a machine-wide value exists. The
#: per-user folders are left out on purpose: nothing Home SOC needs lives there, and what can be
#: found there (the WindowsApps aliases, user site-packages) is writable by the unelevated user.
DROPPED = ("APPDATA", "LOCALAPPDATA", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
           "PYTHONSAFEPATH", "PYTHONEXECUTABLE", "PYTHONPLATLIBDIR", "PYTHONINSPECT")

EXIT_NOT_ISOLATED = 2
EXIT_UNTRUSTED_PATH = 3
EXIT_NO_MACHINE_ENV = 4

_VAR_RE = re.compile(r"%([^%]+)%")


# ----------------------------------------------------------------------------- pure helpers


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def is_within(path: str, roots: Iterable[str]) -> bool:
    """True when ``path`` is one of ``roots`` or lies below one of them."""
    if not path:
        return False  # "" means the current directory: never trusted implicitly
    target = _norm(path)
    for root in roots:
        if not root:
            continue
        base = _norm(root)
        try:
            if os.path.commonpath([target, base]) == base:
                return True
        except ValueError:  # different drives
            continue
    return False


def untrusted_import_paths(entries: Iterable[str], roots: Iterable[str]) -> list[str]:
    """``sys.path`` entries outside the verified trees (for example a registry PythonPath)."""
    roots = list(roots)
    return [e for e in entries if not is_within(e, roots)]


def expand(value: str, env: Mapping[str, str]) -> str:
    """Expand ``%VAR%`` against ``env`` only - never against the (untrusted) process environment,
    which is what ``os.path.expandvars`` and ``winreg.ExpandEnvironmentStrings`` would use."""
    upper = {k.upper(): v for k, v in env.items()}

    def repl(m: re.Match[str]) -> str:
        return upper.get(m.group(1).upper(), m.group(0))

    return _VAR_RE.sub(repl, value)


def system_path(system_root: str) -> str:
    """The fixed PATH of the elevated process: Windows' own folders and nothing else.

    Every program Home SOC starts by bare name on Windows (powershell, netsh, netstat, route, arp)
    lives here; nmap is found through its Program Files fallback."""
    return ";".join([
        os.path.join(system_root, "System32"),
        system_root,
        os.path.join(system_root, "System32", "Wbem"),
        os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0"),
    ])


def clean_environment(inherited: Mapping[str, str], machine: Mapping[str, str], *,
                      profile: str | None, username: str | None, computername: str | None) -> dict[str, str]:
    """Build the elevated process environment.

    ``machine`` holds values read from HKLM (already expanded); ``inherited`` is the environment
    the task was given, of which only :data:`PASSTHROUGH` is used."""
    env: dict[str, str] = {}
    for key, value in machine.items():
        if key.upper() in DROPPED or key.upper().startswith("PYTHON"):
            continue
        env[key] = value
    system_root = env.get("SystemRoot") or env.get("windir")
    if not system_root:
        raise RuntimeError("machine environment has no SystemRoot")
    env["SystemRoot"] = system_root
    env["windir"] = system_root
    env["Path"] = system_path(system_root)
    if profile:
        env["USERPROFILE"] = profile
        drive, tail = os.path.splitdrive(profile)
        if drive:
            env["HOMEDRIVE"], env["HOMEPATH"] = drive, tail or "\\"
    if username:
        env["USERNAME"] = username
    if computername:
        env["COMPUTERNAME"] = computername
    upper_inherited = {k.upper(): v for k, v in inherited.items()}
    for key in PASSTHROUGH:
        value = upper_inherited.get(key)
        if value:
            env[key] = value
    # Drop case-insensitive duplicates of Path / SystemRoot that a machine value may have spelled
    # differently: Windows environment names are case-insensitive, the first one would win.
    result: dict[str, str] = {}
    seen: set[str] = set()
    for key in ("Path", "SystemRoot", "windir", *env.keys()):
        if key.upper() in seen or key not in env:
            continue
        seen.add(key.upper())
        result[key] = env[key]
    return result


# ------------------------------------------------------------------- Windows machine sources


def machine_environment() -> dict[str, str]:  # pragma: no cover - exercised on Windows only
    """Machine-wide variables from HKLM, expanded against machine values only."""
    import winreg

    def read(key_path: str, names: Iterable[str] | None = None) -> dict[str, tuple[str, int]]:
        out: dict[str, tuple[str, int]] = {}
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            if names is None:
                i = 0
                while True:
                    try:
                        name, value, kind = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    if isinstance(value, str):
                        out[name] = (value, kind)
            else:
                for name in names:
                    try:
                        value, kind = winreg.QueryValueEx(key, name)
                    except OSError:
                        continue
                    if isinstance(value, str):
                        out[name] = (value, kind)
        return out

    seed: dict[str, str] = {}
    nt = read(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", ["SystemRoot"])
    if "SystemRoot" not in nt:
        raise RuntimeError("HKLM has no SystemRoot")
    system_root = nt["SystemRoot"][0]
    seed["SystemRoot"] = system_root
    seed["SystemDrive"] = os.path.splitdrive(system_root)[0]
    folders = {
        "ProgramFiles": "ProgramFilesDir",
        "ProgramFiles(x86)": "ProgramFilesDir (x86)",
        "ProgramW6432": "ProgramW6432Dir",
        "CommonProgramFiles": "CommonFilesDir",
        "CommonProgramFiles(x86)": "CommonFilesDir (x86)",
        "CommonProgramW6432": "CommonW6432Dir",
    }
    cv = read(r"SOFTWARE\Microsoft\Windows\CurrentVersion", folders.values())
    for var, name in folders.items():
        if name in cv:
            seed[var] = expand(cv[name][0], seed)
    profiles = read(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", ["ProgramData", "Public"])
    if "ProgramData" in profiles:
        seed["ProgramData"] = seed["ALLUSERSPROFILE"] = expand(profiles["ProgramData"][0], seed)
    if "Public" in profiles:
        seed["PUBLIC"] = expand(profiles["Public"][0], seed)

    session = read(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
    env = dict(seed)
    for _ in range(2):  # a value may reference another Session Manager value
        for name, (value, kind) in session.items():
            env[name] = expand(value, env) if kind == winreg.REG_EXPAND_SZ else value
    env.update(seed)  # the seeded folders win over any same-named Session Manager value
    return env


def _token_profile_dir() -> str | None:  # pragma: no cover - Windows only
    """The account's profile folder, from its token (HKLM ProfileList), not from USERPROFILE."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    userenv.GetUserProfileDirectoryW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        return None
    try:
        size = wintypes.DWORD(0)
        userenv.GetUserProfileDirectoryW(token, None, ctypes.byref(size))
        if not size.value:
            return None
        buf = ctypes.create_unicode_buffer(size.value)
        if not userenv.GetUserProfileDirectoryW(token, buf, ctypes.byref(size)):
            return None
        return buf.value or None
    finally:
        kernel32.CloseHandle(token)


def _api_string(dll: str, func: str) -> str | None:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    fn = getattr(ctypes.WinDLL(dll, use_last_error=True), func)
    fn.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    size = wintypes.DWORD(257)
    buf = ctypes.create_unicode_buffer(size.value)
    if not fn(buf, ctypes.byref(size)):
        return None
    return buf.value or None


# ---------------------------------------------------------------------------------- main


def _say(message: str) -> None:
    if sys.stderr is not None:  # None under pythonw
        print(f"[Home SOC] {message}", file=sys.stderr)


def trusted_roots() -> list[str]:
    return [sys.base_prefix, sys.base_exec_prefix, sys.prefix, sys.exec_prefix]


def main(argv: list[str]) -> int:
    if os.name != "nt":
        _say("run-elevated.py is only for the Windows elevated logon task")
        return EXIT_NO_MACHINE_ENV
    if not (sys.flags.isolated and sys.flags.no_site):
        _say("refusing to start: run-elevated.py must be started with -I -S (see make-autostart.ps1)")
        return EXIT_NOT_ISOLATED
    roots = trusted_roots()
    bad = untrusted_import_paths(sys.path, roots)
    if bad:
        _say(f"refusing to start: import path outside the verified interpreter/venv: {bad}")
        return EXIT_UNTRUSTED_PATH

    import site

    site.main()  # adds the venv site-packages; every folder it reads is inside ``roots``
    bad = untrusted_import_paths(sys.path, roots)
    if bad:
        _say(f"refusing to start: site added an import path outside the verified trees: {bad}")
        return EXIT_UNTRUSTED_PATH

    try:
        machine = machine_environment()
        clean = clean_environment(os.environ, machine, profile=_token_profile_dir(),
                                  username=_api_string("advapi32", "GetUserNameW"),
                                  computername=_api_string("kernel32", "GetComputerNameW"))
    except (OSError, RuntimeError) as exc:
        _say(f"refusing to start: cannot build the machine environment ({exc})")
        return EXIT_NO_MACHINE_ENV
    os.environ.clear()  # also clears the process block, so child processes inherit only ``clean``
    os.environ.update(clean)

    os.chdir(ROOT)
    sys.path.insert(0, ROOT)
    import runpy

    sys.argv = ["homesoc", *argv]
    runpy.run_module("homesoc", run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
