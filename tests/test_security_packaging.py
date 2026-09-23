"""Security regression tests for packaging: the dependency lock and the scripts that install it.

Finding (feeds-supply-chain lens, low): pytest - a dev tool with an advisory (PYSEC-2026-1845,
fixed in 9.0.3) - was in requirements.txt, so every production .venv got it; transitive
dependencies (urllib3, werkzeug, jinja2 ...) were unpinned and not hash-locked, so a first
install took whatever PyPI served that day; and because run.bat / run.sh only reinstall when
requirements.txt's hash changes, an existing .venv never received a transitive security fix.

The fix makes requirements.txt a fully pinned, hash-locked lock file (pip included), installs it
with --require-hashes everywhere, and keeps pytest in the [dev] extra only. These tests encode
each part so a regression (someone re-adding an unpinned line, dropping --require-hashes from a
launcher, or putting pytest back) fails the suite.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements.txt"
PYPROJECT = ROOT / "pyproject.toml"

# Every script that installs dependencies into a venv.
INSTALLERS = [
    ROOT / "run.bat",
    ROOT / "run.sh",
    ROOT / "scripts" / "install.ps1",
    ROOT / "scripts" / "install.sh",
]

# Transitive closure of flask==3.1.3 / requests==2.34.2 / dnslib==0.9.26 (SECURITY.md section 6).
EXPECTED_TRANSITIVE = {
    "werkzeug", "jinja2", "markupsafe", "itsdangerous", "click", "blinker",
    "urllib3", "certifi", "idna", "charset-normalizer",
}

_REQ_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*(?P<version>[0-9][^\s;\\]*)")
_HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]+)")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_lines(text: str) -> list[str]:
    """requirements.txt lines with comments dropped and backslash continuations joined."""
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        line = line.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            out.append(buf.strip())
        buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


def _parse_lock() -> dict[str, tuple[str, list[str], str]]:
    """{normalised name: (version, [sha256 hashes], logical line)}; fails on any unpinned line."""
    entries: dict[str, tuple[str, list[str], str]] = {}
    for line in _logical_lines(LOCK.read_text(encoding="utf-8")):
        m = _REQ_RE.match(line)
        assert m, f"requirements.txt line is not an exact `name==version` pin: {line!r}"
        entries[_norm(m.group("name"))] = (m.group("version"), _HASH_RE.findall(line), line)
    return entries


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:3])


def test_pytest_is_not_installed_into_production_venvs():
    # Before the fix: `pytest==8.*` under "# dev" in requirements.txt.
    assert "pytest" not in _parse_lock()
    assert not re.search(r"^\s*pytest\b", LOCK.read_text(encoding="utf-8"), re.MULTILINE | re.IGNORECASE)


def test_every_locked_requirement_is_exactly_pinned_and_hashed():
    entries = _parse_lock()
    assert entries, "requirements.txt has no requirements"
    for name, (version, hashes, line) in entries.items():
        assert hashes, f"{name}=={version} has no --hash; --require-hashes would reject the whole install"
        for h in hashes:
            assert len(h) == 64, f"{name}: malformed sha256 {h!r}"
        assert not re.search(r"(?<![=!<>~])(>=|<=|~=|!=|>|<)", line.split("--hash", 1)[0].split(";", 1)[0]), (
            f"{name}: range specifier in a lock file: {line!r}")


def test_lock_no_longer_depends_on_index_url_or_editable_lines():
    text = LOCK.read_text(encoding="utf-8")
    for bad in ("--index-url", "--extra-index-url", "-i ", "--trusted-host", "-e ", "--editable", "--find-links"):
        for line in _logical_lines(text):
            assert not line.startswith(bad), f"lock file must not redirect or loosen the install: {line!r}"


def test_lock_covers_the_transitive_closure():
    # Before the fix only flask/requests/dnslib were pinned; urllib3 & co. floated.
    locked = set(_parse_lock())
    missing = EXPECTED_TRANSITIVE - locked
    assert not missing, f"transitive dependencies not locked: {sorted(missing)}"


def test_lock_agrees_with_pyproject_direct_pins():
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    entries = _parse_lock()
    for dep in data["project"]["dependencies"]:
        m = _REQ_RE.match(dep)
        assert m, f"pyproject dependency is not an exact pin: {dep!r}"
        name = _norm(m.group("name"))
        assert name in entries, f"{name} is in pyproject but not in the lock"
        assert entries[name][0] == m.group("version"), (
            f"{name}: pyproject pins {m.group('version')}, lock pins {entries[name][0]}")


def test_lock_upgrades_pip_past_pysec_2026_3721():
    entries = _parse_lock()
    assert "pip" in entries, "pip is not locked, so the venv keeps the bundled (vulnerable) pip"
    assert _version_tuple(entries["pip"][0]) >= (26, 2, 0)


def test_dev_extra_requires_fixed_pytest():
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    dev = [d for d in data["project"]["optional-dependencies"]["dev"] if _norm(d).startswith("pytest")]
    assert dev, "pytest missing from the [dev] extra"
    m = re.search(r">=\s*([0-9][0-9.]*)", dev[0])
    assert m, f"pytest dev requirement has no lower bound: {dev[0]!r}"
    assert _version_tuple(m.group(1)) >= (9, 0, 3), f"pytest lower bound predates PYSEC-2026-1845 fix: {dev[0]!r}"


@pytest.mark.parametrize("script", INSTALLERS, ids=lambda p: p.name)
def test_every_installer_enforces_hashes(script: Path):
    text = script.read_text(encoding="utf-8")
    installs = [l for l in text.splitlines()
                if re.search(r"-m\s+pip\s+install\b", l) and not l.lstrip().startswith(("#", "rem ", "REM "))]
    assert installs, f"{script.name}: no pip install line found"
    for line in installs:
        assert "requirements.txt" in line, f"{script.name}: installs something other than the lock: {line!r}"
        assert "--require-hashes" in line, f"{script.name}: pip install without --require-hashes: {line!r}"
        assert "--no-deps" not in line and "--index-url" not in line and "--trusted-host" not in line


@pytest.mark.parametrize("script", [ROOT / "run.bat", ROOT / "run.sh"], ids=lambda p: p.name)
def test_launcher_reinstall_stamp_is_the_lock_hash(script: Path):
    # A lock bump must change the stamp, or existing .venvs never receive the fix.
    text = script.read_text(encoding="utf-8")
    hash_lines = [l for l in text.splitlines() if "REQHASH" in l and re.search(r"certutil -hashfile|sha256sum |shasum -a 256", l)]
    assert hash_lines, f"{script.name}: no reinstall stamp"
    for line in hash_lines:
        assert "requirements.txt" in line, f"{script.name}: stamp not derived from the lock: {line!r}"
