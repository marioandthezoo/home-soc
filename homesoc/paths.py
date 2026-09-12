"""Filesystem locations for Home SOC.

Every function re-reads the environment on each call (no caching) so tests can
point ``HOMESOC_DATA`` / ``HOMESOC_CONFIG`` at a temporary directory and the
rest of the code base picks it up without restarts.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_DATA = "HOMESOC_DATA"
ENV_CONFIG = "HOMESOC_CONFIG"


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
    """Runtime data folder (``HOMESOC_DATA`` or ``<root>/data``), created on demand."""
    raw = os.environ.get(ENV_DATA, "").strip()
    path = Path(raw).expanduser() if raw else project_root() / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def feeds_dir() -> Path:
    path = data_dir() / "feeds"
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    path = data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "homesoc.db"


def config_path() -> Path:
    """User config file (``HOMESOC_CONFIG`` or ``<root>/config.toml``); may not exist yet."""
    raw = os.environ.get(ENV_CONFIG, "").strip()
    return Path(raw).expanduser() if raw else project_root() / "config.toml"
