"""Shared pytest fixtures for every Home SOC package.

Every test gets an isolated data directory (``HOMESOC_DATA``) and a config path
that does not exist (``HOMESOC_CONFIG``), so tests never touch the developer's
real ``data/`` or ``config.toml``. ``live`` tests are skipped unless ``--live``.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from homesoc import config as _config  # noqa: E402
from homesoc import db as _db  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--live", action="store_true", default=False, help="run tests marked 'live' (real network)")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: touches the real network/feeds; skipped unless --live is given")
    config.addinivalue_line("markers", "slow: offline but spawns interpreters/subprocesses; deselect with -m 'not slow'")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--live"):
        return
    skip = pytest.mark.skip(reason="live test; pass --live to run")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _reset_homesoc_logging():
    """Drop handlers that cli.setup_logging() attached, so a test that ran the CLI never leaves
    a rotating file open in a temp dir (or a stale stream) for the tests that follow."""
    yield
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_homesoc", False):
            root.removeHandler(handler)
            handler.close()


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Temporary HOMESOC_DATA (and a non-existent HOMESOC_CONFIG so defaults apply)."""
    data = tmp_path / "data"
    monkeypatch.setenv("HOMESOC_DATA", str(data))
    monkeypatch.setenv("HOMESOC_CONFIG", str(tmp_path / "config.toml"))
    return data


@pytest.fixture
def conn(data_dir: Path):
    """Schema-initialised SQLite connection at the temporary db_path()."""
    connection = _db.connect()
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def memory_conn():
    """In-memory database with the full schema, for tests that never involve paths."""
    connection = _db.connect(":memory:")
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def cfg(conn) -> _config.Config:
    """Default configuration (no config.toml, no overrides)."""
    return _config.load(conn)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
