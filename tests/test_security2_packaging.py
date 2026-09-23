r"""Security round two, packaging: the ELEVATED logon task of scripts/make-autostart.ps1.

Finding (host-scripts lens, medium): ``make-autostart.ps1 -Mode task -Elevated`` refused unless the
Home SOC tree was administrator-only, then registered ``.venv\Scripts\pythonw.exe -m homesoc run``
with ``-RunLevel Highest``. But a logon task gets the user's environment block, which includes
``HKCU\Environment`` - writable by the user (and by malware running as the user) without a UAC
prompt. ``PYTHONPATH`` pointing at a folder with a ``sitecustomize.py`` therefore ran code as
administrator at the next logon (reproduced). ``PATH``, ``ProgramFiles``, ``SystemRoot`` and
``PSModulePath`` steer which executables and PowerShell modules Home SOC runs. The check also never
looked at the base interpreter named by ``pyvenv.cfg`` ("home"), which the .venv launcher actually
runs; a per-user python.org install there is user-writable.

The fix:
* the elevated task runs ``pythonw.exe -I -S scripts\run-elevated.py run``; the starter verifies the
  import path, then replaces the environment with machine-wide values before starting Home SOC;
* make-autostart.ps1 applies the admin-only test to the pyvenv.cfg "home" folder too.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STARTER = ROOT / "scripts" / "run-elevated.py"
AUTOSTART = ROOT / "scripts" / "make-autostart.ps1"

windows_only = pytest.mark.skipif(os.name != "nt", reason="the elevated logon task is Windows-only")


def _load_starter():
    spec = importlib.util.spec_from_file_location("run_elevated", STARTER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _poisoned_env(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """The environment an attacker controls through HKCU\\Environment, plus the PoC marker path."""
    evil = tmp_path / "evil"
    evil.mkdir()
    marker = tmp_path / "pwned.txt"
    (evil / "sitecustomize.py").write_text(
        f"open({str(marker)!r}, 'w').write('sitecustomize ran')\n", encoding="utf-8")
    env = dict(os.environ)
    env.update({
        "PYTHONPATH": str(evil),
        "PYTHONSTARTUP": str(evil / "sitecustomize.py"),
        "PATH": str(evil) + os.pathsep + env.get("PATH", ""),
        "ProgramFiles": str(evil),
        "ProgramData": str(evil),
        "windir": str(evil),
        "PSModulePath": str(evil),
        "LOCALAPPDATA": str(evil),
        "HOMESOC_DATA": str(tmp_path / "data"),
    })
    return env, marker


# ------------------------------------------------------------------ the exploit, end to end


@windows_only
def test_pythonpath_sitecustomize_no_longer_runs_in_the_task_process(tmp_path):
    env, marker = _poisoned_env(tmp_path)
    # Before the fix: the task command, reproduced. The injected code runs.
    before = subprocess.run([sys.executable, "-m", "homesoc", "--version"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=120)
    assert marker.exists(), "precondition: PYTHONPATH injection works against the old command"
    marker.unlink()
    assert before.returncode == 0

    # After the fix: the command make-autostart.ps1 now registers for -Elevated.
    after = subprocess.run([sys.executable, "-I", "-S", str(STARTER), "--version"], cwd=tmp_path, env=env,
                           capture_output=True, text=True, timeout=120)
    assert not marker.exists(), "sitecustomize from PYTHONPATH ran inside the elevated starter"
    assert after.returncode == 0, after.stderr
    assert "homesoc" in (after.stdout + after.stderr).lower()


@windows_only
def test_starter_refuses_to_run_without_isolated_mode(tmp_path):
    env, _marker = _poisoned_env(tmp_path)
    proc = subprocess.run([sys.executable, str(STARTER), "--version"], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2
    assert "-I -S" in proc.stderr


_HARNESS = textwrap.dedent(r"""
    import importlib.util, json, os, runpy, sys
    out, starter, extra = sys.argv[1], sys.argv[2], sys.argv[3]
    if extra:
        sys.path.append(extra)          # stands in for a registry PythonPath entry
    spec = importlib.util.spec_from_file_location("run_elevated", starter)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    def fake_run_module(name, run_name=None, alter_sys=False):
        json.dump({"module": name, "argv": sys.argv, "env": dict(os.environ), "cwd": os.getcwd(),
                   "path0": sys.path[0], "path": sys.path}, open(out, "w"))
    runpy.run_module = fake_run_module
    rc = m.main(["run"])
    if rc:
        json.dump({"rc": rc}, open(out, "w"))
""")


def _run_harness(tmp_path: Path, env: dict[str, str], extra_path: str = "") -> dict:
    out = tmp_path / "result.json"
    proc = subprocess.run([sys.executable, "-I", "-S", "-c", _HARNESS, str(out), str(STARTER), extra_path],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(out.read_text(encoding="utf-8"))


@windows_only
def test_starter_replaces_the_user_controlled_environment(tmp_path):
    env, marker = _poisoned_env(tmp_path)
    evil = str(tmp_path / "evil").lower()
    result = _run_harness(tmp_path, env)
    assert not marker.exists()
    assert result["module"] == "homesoc" and result["argv"] == ["homesoc", "run"]
    child = {k.upper(): v for k, v in result["env"].items()}

    for key, value in child.items():
        assert evil not in value.lower(), f"{key} still carries the user-controlled value {value!r}"
    assert not [k for k in child if k.startswith("PYTHON")]
    assert "LOCALAPPDATA" not in child and "APPDATA" not in child

    system_root = child["SYSTEMROOT"]
    assert child["WINDIR"] == system_root
    for entry in child["PATH"].split(";"):
        assert entry.lower().startswith(system_root.lower()), f"PATH entry outside Windows: {entry}"
    assert child["PROGRAMFILES"].lower() != evil
    assert Path(child["PROGRAMFILES"]).is_dir()
    assert Path(child["USERPROFILE"]).is_dir()

    # The documented data override still works; code runs from the verified root.
    assert child["HOMESOC_DATA"] == str(tmp_path / "data")
    assert Path(result["cwd"]).resolve() == ROOT
    assert Path(result["path0"]).resolve() == ROOT


@windows_only
def test_starter_refuses_an_import_path_outside_the_verified_trees(tmp_path):
    env, _marker = _poisoned_env(tmp_path)
    result = _run_harness(tmp_path, env, extra_path=str(tmp_path / "evil"))
    assert result == {"rc": 3}


# ------------------------------------------------------------------- pure helper behaviour


def test_untrusted_import_paths_is_a_real_containment_check():
    m = _load_starter()
    base = str(Path(os.sep, "py", "Python314").resolve()) if os.name != "nt" else r"C:\Python314"
    entries = [os.path.join(base, "Lib"), base, base + "evil", "", os.path.join(os.sep, "evil")]
    assert m.untrusted_import_paths(entries, [base]) == [base + "evil", "", os.path.join(os.sep, "evil")]


def test_expand_never_reads_the_process_environment(monkeypatch):
    m = _load_starter()
    monkeypatch.setenv("windir", "EVIL")
    monkeypatch.setenv("HOMESOC_TEST_ONLY", "EVIL")
    assert m.expand(r"%SystemRoot%\x;%windir%\y;%HOMESOC_TEST_ONLY%", {"SystemRoot": r"C:\Windows"}) == (
        r"C:\Windows\x;%windir%\y;%HOMESOC_TEST_ONLY%")


def test_clean_environment_takes_only_data_selectors_from_the_inherited_block():
    m = _load_starter()
    machine = {"SystemRoot": r"C:\Windows", "Path": r"C:\Tools;C:\Windows\System32",
               "PSModulePath": r"C:\Program Files\WindowsPowerShell\Modules", "PYTHONPATH": r"C:\x",
               "ProgramFiles": r"C:\Program Files", "TEMP": r"C:\Windows\TEMP"}
    inherited = {"PYTHONPATH": r"C:\evil", "Path": r"C:\evil", "PSModulePath": r"C:\evil",
                 "ProgramFiles": r"C:\evil", "LOCALAPPDATA": r"C:\evil", "homesoc_data": r"D:\data",
                 "HOMESOC_CONFIG": r"D:\cfg.toml", "HOMESOC_OTHER": r"C:\evil"}
    env = m.clean_environment(inherited, machine, profile=r"C:\Users\me", username="me", computername="PC")
    assert not any("evil" in v for v in env.values())
    assert env["Path"] == m.system_path(r"C:\Windows")
    assert "C:\\Tools" not in env["Path"]
    assert "PYTHONPATH" not in env
    assert env["PSModulePath"] == machine["PSModulePath"]
    assert env["HOMESOC_DATA"] == r"D:\data" and env["HOMESOC_CONFIG"] == r"D:\cfg.toml"
    assert "HOMESOC_OTHER" not in env
    assert env["USERPROFILE"] == r"C:\Users\me"
    if os.name == "nt":
        assert env["HOMEDRIVE"] == "C:" and env["HOMEPATH"] == r"\Users\me"
    assert len({k.upper() for k in env}) == len(env), "case-insensitive duplicate names"


# --------------------------------------------------------------------- make-autostart.ps1


def _powershell() -> str | None:
    return shutil.which("powershell") or shutil.which("pwsh")


def _fake_install(tmp_path: Path, home_line: str | None) -> Path:
    root = tmp_path / "Home_SOC"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(AUTOSTART, root / "scripts" / "make-autostart.ps1")
    shutil.copy2(STARTER, root / "scripts" / "run-elevated.py")
    (root / ".venv" / "Scripts").mkdir(parents=True)
    (root / ".venv" / "Scripts" / "pythonw.exe").write_bytes(b"")
    cfg = "include-system-site-packages = false\nversion = 3.14.6\n"
    if home_line is not None:
        cfg = home_line + "\n" + cfg
    (root / ".venv" / "pyvenv.cfg").write_text(cfg, encoding="utf-8")
    return root


def _check_only(root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                           str(root / "scripts" / "make-autostart.ps1"), "-Mode", "task", "-CheckOnly", *extra],
                          capture_output=True, text=True, timeout=300)


@windows_only
def test_elevated_check_covers_a_user_writable_base_interpreter(tmp_path):
    if not _powershell():
        pytest.skip("no PowerShell")
    user_python = tmp_path / "LocalAppData" / "Programs" / "Python" / "Python314"
    user_python.mkdir(parents=True)
    (user_python / "python.exe").write_bytes(b"")
    root = _fake_install(tmp_path, f"home = {user_python}")
    proc = _check_only(root, "-Elevated")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert f"checking the base interpreter the .venv runs: {user_python}" in out
    # A standard user can replace that folder (its parent grants them full control): refused.
    base_lines = [l.strip() for l in out.splitlines() if l.strip().startswith("[base interpreter]")]
    assert any(l.startswith(f"[base interpreter] {user_python.parent}  ->  ") for l in base_lines), out


@windows_only
def test_elevated_check_fails_closed_without_a_venv_home(tmp_path):
    if not _powershell():
        pytest.skip("no PowerShell")
    root = _fake_install(tmp_path, None)
    proc = _check_only(root, "-Elevated")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "[base interpreter] cannot read an existing 'home' folder" in out


@windows_only
def test_limited_task_command_is_unchanged(tmp_path):
    if not _powershell():
        pytest.skip("no PowerShell")
    root = _fake_install(tmp_path, "home = C:\\Python314")
    proc = _check_only(root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "run level would be: Limited" in proc.stdout
    assert proc.stdout.strip().endswith("pythonw.exe -m homesoc run")


def test_elevated_task_command_uses_the_isolated_starter():
    text = AUTOSTART.read_text(encoding="utf-8")
    assert "$argument = '-I -S \"{0}\" run' -f $elevatedStarter" in text
    # The elevated branch must reach Register-ScheduledTask with that argument, not "-m homesoc".
    elevated_block = text.split("if ($Elevated) {", 1)[1].split("\nif ($CheckOnly)", 1)[0]
    assert '$runLevel = "Highest"' in elevated_block
    assert elevated_block.index('$runLevel = "Highest"') < elevated_block.index("-I -S")
    assert "Test-TreeIsAdminOnly -Path $baseDir" in elevated_block
