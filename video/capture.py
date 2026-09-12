"""Capture stage of the Home SOC walkthrough video.

Owns a throwaway dashboard process (``python -m homesoc serve --port 8899`` against
``video/demo_data``), drives it with Playwright + the *installed* Google Chrome, and writes
everything the compositor needs to draw frames:

``video/build/shots/slide_<name>.png``
    One per slide function in :mod:`slides`, 3200x1800.

``video/build/shots/<scene-id>_<n>.png``
    One per *visual state* a scene passes through, 3200x1800 (1600x900 CSS at 2x), in the
    order they appear on screen. State ``0`` is the scene's opening shot. Later states are
    declared three ways, which ``script.py`` deliberately overlaps: extra ``PageSequence``
    members (``ats[i]`` says when member *i* takes over), ``Click(then_shot=...)``, and
    ``Scroll(to_y=...)``. A sequence member and the ``Scroll``/``Click`` that reaches it are
    the same state and are captured once — see :func:`plan_states`.

``video/build/geometry.json``
    ``{scene_id: {selector: [x, y, w, h]}}`` — the rectangle of every selector the script
    points the cursor at, in the 1600x900 CSS coordinate space of the state that was on
    screen when the action fires. Keys are the selector strings exactly as written in
    ``script.py`` (``"css=#chart-gauge"``), so the compositor can look them up directly.

``video/build/shots_manifest.json``
    Per-scene list of the captured states, in order, with the page/scroll each came from.

Nothing here writes to the real ``data/`` directory or ``config.toml``. The dashboard runs
with ``HOMESOC_DATA``/``HOMESOC_CONFIG`` pointing at a generated, token-free config under
``build/`` and at ``build/demo_data_run`` — a throwaway copy of ``video/demo_data`` made at
the start of every run. The copy matters: the script clicks *Acknowledge* on a finding and
ticks filter boxes for real, so the dashboard writes to its database. Serving a copy keeps
``video/demo_data`` exactly as ``seed_demo.py`` left it and makes re-runs identical.

Usage::

    python video/capture.py                    # slides + every scene
    python video/capture.py --only 06-findings
    python video/capture.py --slides-only
    python video/capture.py --headed           # watch it work
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import ExitStack, suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final

HERE: Final[Path] = Path(__file__).resolve().parent
PROJECT_ROOT: Final[Path] = HERE.parent
if str(HERE) not in sys.path:  # so `python video/capture.py` finds script.py / slides.py
    sys.path.insert(0, str(HERE))

BUILD: Final[Path] = HERE / "build"
SHOTS_DIR: Final[Path] = BUILD / "shots"
DEMO_DATA: Final[Path] = HERE / "demo_data"
GEOMETRY_PATH: Final[Path] = BUILD / "geometry.json"
MANIFEST_PATH: Final[Path] = BUILD / "shots_manifest.json"
DASHBOARD_LOG: Final[Path] = BUILD / "dashboard.log"
DEMO_CONFIG: Final[Path] = BUILD / "demo_config.toml"
#: Throwaway copy of demo_data that the dashboard is allowed to write to.
WORK_DATA: Final[Path] = BUILD / "demo_data_run"

PORT: Final[int] = 8899
BASE_URL: Final[str] = f"http://127.0.0.1:{PORT}"
VIEWPORT_W: Final[int] = 1600
VIEWPORT_H: Final[int] = 900
SCALE: Final[int] = 2
SHOT_W: Final[int] = VIEWPORT_W * SCALE
SHOT_H: Final[int] = VIEWPORT_H * SCALE

READY_TIMEOUT: Final[float] = 60.0
READY_INTERVAL: Final[float] = 0.25
NAV_TIMEOUT_MS: Final[int] = 30_000
IDLE_TIMEOUT_MS: Final[int] = 15_000
CHART_TIMEOUT_MS: Final[int] = 15_000
SETTLE_MS: Final[int] = 350
STOP_GRACE: Final[float] = 8.0

logger = logging.getLogger("homesoc.video.capture")


class CaptureError(RuntimeError):
    """Anything that stops the capture, always naming the scene and selector at fault."""


# --------------------------------------------------------------------------- injected assets

#: Kills every source of between-run jitter that is not the data itself.
FREEZE_CSS: Final[str] = """
*, *::before, *::after {
  animation: none !important;
  transition: none !important;
  animation-duration: 0s !important;
  transition-duration: 0s !important;
  caret-color: transparent !important;
  scroll-behavior: auto !important;
}
html { scrollbar-width: none !important; }
::-webkit-scrollbar { width: 0 !important; height: 0 !important; }
*:focus, *:focus-visible { outline: none !important; }
"""

#: Pins the one string the dashboard rewrites from the wall clock every refresh tick.
FREEZE_JS: Final[str] = """
(frozenLabel) => {
  const pin = () => {
    const el = document.getElementById('last-refresh');
    if (el && el.textContent !== frozenLabel) el.textContent = frozenLabel;
  };
  pin();
  if (!window.__homesocPinned) {
    window.__homesocPinned = true;
    const obs = new MutationObserver(pin);
    const el = document.getElementById('last-refresh');
    if (el) obs.observe(el, { childList: true, characterData: true, subtree: true });
  }
  return true;
}
"""

#: The demo dashboard is started with `homesoc serve`, and `cmd_serve` deliberately passes
#: ``with_dns=False`` — "dashboard only" never binds the resolver, whatever the config says.
#: (`homesoc run`, which is what run.bat launches, does start it.) The consequence in the video
#: was that every page reported the resolver STOPPED while the narration described a house
#: resolving through it, and while the same pages showed twenty-four hours of query log, hourly
#: bars and 774 blocks that only a running resolver could have produced. That contradiction is an
#: artefact of the capture harness, not of the product, so the three places the page reports it
#: are set to what a `run.bat` instance shows. Nothing else about the resolver is touched: the
#: traffic, the block rate and the reputation cache all come from the seeded database.
#: It re-applies on a timer because app.js rewrites the sidebar dot from /api/summary every
#: refresh tick.
RESOLVER_RUNNING_JS: Final[str] = """
() => {
  const fix = () => {
    const dot = document.getElementById('dot-dns');
    if (dot && dot.className !== 'dot on') dot.className = 'dot on';
    const state = document.getElementById('chip-dns-state');
    if (state && state.textContent !== 'running') state.textContent = 'running';
    document.querySelectorAll('span.badge-off').forEach(el => {
      const text = (el.textContent || '').trim();
      if (text === 'stopped' || text === 'enabled, not running') {
        el.className = 'badge badge-ok';
        el.textContent = 'running';
      }
    });
  };
  fix();
  if (!window.__homesocResolver) {
    window.__homesocResolver = setInterval(fix, 250);
  }
  return true;
}
"""

#: The /feed "Kinds" box showed four whole rows and then a fifth sliced horizontally through
#: the middle of its letters — the first thing the eye lands on for the whole Activity feed
#: scene, and it reads as a rendering fault. Measured in Chrome: `<select multiple size=4>`
#: with this stylesheet is 86 px tall, its rows are 18 px, and its first row starts 7 px in
#: (1 px border + 6 px padding). 7 + 4x18 = 79, so the 6 px of bottom padding is where the
#: fifth row leaks through: the box height is already right, the padding is not part of the
#: clip. Drop the bottom padding and pin the height to whole rows measured off the option
#: boxes themselves, rather than trusting `size` or a computed row height.
WHOLE_ROWS_JS: Final[str] = """
() => {
  document.querySelectorAll('select[multiple]').forEach(el => {
    const n = el.options.length;
    if (n < 3 || el.dataset.homesocRows) return;
    const shown = Math.min(Math.max(1, el.size || 4), n);
    if (n <= shown) { el.dataset.homesocRows = '1'; return; }
    const box = el.getBoundingClientRect();
    const first = el.options[0].getBoundingClientRect();
    const second = el.options[1].getBoundingClientRect();
    const row = second.top - first.top;
    if (!(row > 1)) return;
    const lead = first.top - box.top;                       // border + top padding
    const style = getComputedStyle(el);
    const border = parseFloat(style.borderBottomWidth) || 0;
    el.style.paddingBottom = '0px';
    el.style.overflowY = 'hidden';
    el.style.height = Math.round(lead + row * shown + border) + 'px';
    el.dataset.homesocRows = '1';
  });
  return true;
}
"""

#: Every `.chart` container that is actually laid out must have been filled by charts.js
#: (an <svg>, or the `.chart-empty` placeholder) before the shot is worth taking.
CHARTS_READY_JS: Final[str] = """
() => {
  const nodes = Array.from(document.querySelectorAll('.chart'));
  if (!nodes.length) return true;
  return nodes.every(n => n.offsetParent === null || n.children.length > 0);
}
"""


# --------------------------------------------------------------------------- script model


@dataclass
class State:
    """One captured page (or slide) state within a scene."""

    scene_id: str
    index: int
    kind: str  # "slide" | "page"
    path: str  # url path, or the slide name
    scroll: int = 0
    png: Path | None = None
    produced_by: str = "shot"

    @property
    def filename(self) -> str:
        return f"{self.scene_id}_{self.index}.png"

    def as_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "kind": self.kind,
            "path": self.path,
            "scroll": self.scroll,
            "png": self.png.as_posix() if self.png else None,
            "produced_by": self.produced_by,
        }


def _attr(obj: object, *names: str, default: Any = None) -> Any:
    """First present attribute out of ``names`` - the script's dataclasses are duck-typed."""
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


def _kind_of(obj: object) -> str:
    return type(obj).__name__


def is_slide(shot: object) -> bool:
    return _kind_of(shot) == "Slide" or (hasattr(shot, "html_fn") and not hasattr(shot, "path"))


def is_page(shot: object) -> bool:
    return _kind_of(shot) == "Page" or hasattr(shot, "path") or hasattr(shot, "url")


def is_sequence(shot: object) -> bool:
    return _kind_of(shot) == "PageSequence" or hasattr(shot, "shots") or hasattr(shot, "pages")


def sequence_items(shot: object) -> list[Any]:
    items = _attr(shot, "shots", "pages", "items", "states", default=None)
    if items is None and isinstance(shot, (list, tuple)):
        items = list(shot)
    return list(items or [])


def slide_name(shot: object, scene_id: str) -> str:
    name = _attr(shot, "html_fn", "name", "slide", "fn")
    if not name:
        raise CaptureError(f"{scene_id}: Slide shot has no html_fn/name attribute ({shot!r})")
    return str(name)


def page_path(shot: object, scene_id: str) -> str:
    path = _attr(shot, "path", "url", "route")
    if not path:
        raise CaptureError(f"{scene_id}: Page shot has no path/url attribute ({shot!r})")
    path = str(path)
    return path if path.startswith("/") else "/" + path


def page_scroll(shot: object) -> int:
    return int(_attr(shot, "scroll", "scroll_y", "y", default=0) or 0)


_XY_RE = re.compile(r"^xy\s*=\s*\(?\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\)?$", re.I)


def parse_xy(target: str) -> tuple[float, float] | None:
    """``"xy=(120, 340)"`` -> ``(120.0, 340.0)``; ``None`` when it is a selector."""
    match = _XY_RE.match(target.strip())
    if not match:
        return None
    return float(match.group(1)), float(match.group(2))


def _offscreen(rect: list[float]) -> str:
    """``""`` when the rect is fully inside the viewport, else which way it overflows."""
    x, y, w, h = rect
    sides = []
    if y + h <= 0 or y >= VIEWPORT_H:
        sides.append("below" if y >= VIEWPORT_H else "above")
    if x + w <= 0 or x >= VIEWPORT_W:
        sides.append("right of" if x >= VIEWPORT_W else "left of")
    return " and ".join(sides)


def action_selector(action: object) -> str | None:
    """The selector string an action points at, exactly as written in the script."""
    kind = _kind_of(action)
    if kind == "Move":
        return _attr(action, "to", "target", "sel", "selector")
    if kind == "Highlight":
        return _attr(action, "sel", "selector", "to", "target")
    return _attr(action, "sel", "selector") if kind not in {"Click", "Scroll", "Zoom"} else None


def action_at(action: object) -> float:
    try:
        return float(_attr(action, "at", "t", default=0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


# --------------------------------------------------------------------------- dashboard


DEMO_CONFIG_TOML: Final[str] = """\
# Generated by video/capture.py — the demo dashboard's config. Never the user's config.toml.
[general]
name = "Home SOC"
log_level = "WARNING"

[web]
host = "127.0.0.1"
port = {port}
token = ""
refresh_seconds = 15

[dns]
enabled = true

[feeds]
enabled = false

[notify]
windows_toast = false
"""


def make_working_copy(source: Path) -> Path:
    """Copy the seeded demo data into ``build/`` and serve the dashboard from *that*.

    The script clicks Acknowledge on a finding and toggles filters for real, so the
    dashboard writes to its database. Running against a throwaway copy keeps
    ``video/demo_data/`` exactly as ``seed_demo.py`` left it and makes re-runs identical.
    """
    db = source / "homesoc.db"
    if not db.is_file():
        raise CaptureError(
            f"demo database {db} does not exist - run `python video/seed_demo.py` first."
        )
    dest = WORK_DATA
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    # The whole tree, -wal/-shm included: seed_demo.py may have left committed pages in the
    # write-ahead log, and copying the .db alone would silently lose them.
    shutil.copytree(source, dest, dirs_exist_ok=True)
    _checkpoint(dest / "homesoc.db")
    logger.info("serving a working copy of %s from %s", source, dest)
    return dest


def _checkpoint(db: Path) -> None:
    """Fold the copied write-ahead log into the database file, then drop it."""
    try:
        conn = sqlite3.connect(db, timeout=10)
    except sqlite3.Error as exc:
        raise CaptureError(f"the demo database {db} could not be opened: {exc}") from exc
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
    except sqlite3.Error as exc:
        logger.warning("could not checkpoint %s: %s", db, exc)
    finally:
        conn.close()
    for suffix in ("-wal", "-shm"):
        (db.parent / f"{db.name}{suffix}").unlink(missing_ok=True)


@dataclass
class Dashboard:
    """The demo dashboard subprocess. Always stopped, including on Ctrl-C."""

    data_dir: Path
    port: int = PORT
    proc: subprocess.Popen[bytes] | None = None
    _log: Any = None

    def __enter__(self) -> Dashboard:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _write_config(self) -> Path:
        DEMO_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        DEMO_CONFIG.write_text(DEMO_CONFIG_TOML.format(port=self.port), encoding="utf-8")
        return DEMO_CONFIG

    def start(self) -> None:
        db = self.data_dir / "homesoc.db"
        if not db.is_file():
            raise CaptureError(f"demo database {db} does not exist")
        config = self._write_config()
        env = dict(os.environ)
        env["HOMESOC_DATA"] = str(self.data_dir)
        env["HOMESOC_CONFIG"] = str(config)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        cmd = [
            sys.executable, "-m", "homesoc",
            "--data", str(self.data_dir),
            "--config", str(config),
            "serve", "--host", "127.0.0.1", "--port", str(self.port),
        ]
        DASHBOARD_LOG.parent.mkdir(parents=True, exist_ok=True)
        self._log = DASHBOARD_LOG.open("wb")
        logger.info("starting dashboard: %s", " ".join(cmd))
        self.proc = subprocess.Popen(
            cmd, cwd=str(PROJECT_ROOT), env=env,
            stdout=self._log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        last: str = "no response yet"
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise CaptureError(
                    f"dashboard exited with code {self.proc.returncode} before it was ready.\n"
                    f"Its output is in {DASHBOARD_LOG}:\n{self._tail_log()}"
                )
            try:
                with urllib.request.urlopen(f"{BASE_URL}/", timeout=3) as resp:
                    if resp.status == 200:
                        logger.info("dashboard ready on %s", BASE_URL)
                        return
                    last = f"HTTP {resp.status}"
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    raise CaptureError(
                        f"the demo dashboard demands a token - {DEMO_CONFIG} should set "
                        "web.token = \"\". Delete build/demo_config.toml and re-run."
                    ) from exc
                last = f"HTTP {exc.code}"
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last = f"{type(exc).__name__}: {exc}"
            time.sleep(READY_INTERVAL)
        raise CaptureError(
            f"dashboard did not answer on {BASE_URL} within {READY_TIMEOUT:.0f}s ({last}).\n"
            f"Its output is in {DASHBOARD_LOG}:\n{self._tail_log()}"
        )

    def _tail_log(self, lines: int = 25) -> str:
        with suppress(OSError):
            if self._log is not None:
                self._log.flush()
            text = DASHBOARD_LOG.read_text(encoding="utf-8", errors="replace")
            return "\n".join(text.splitlines()[-lines:])
        return "(no log)"

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            logger.info("stopping dashboard (pid %s)", proc.pid)
            with suppress(OSError):
                proc.terminate()
            try:
                proc.wait(timeout=STOP_GRACE)
            except subprocess.TimeoutExpired:
                logger.warning("dashboard ignored terminate; killing pid %s", proc.pid)
                with suppress(OSError):
                    proc.kill()
                with suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=STOP_GRACE)
        if self._log is not None:
            with suppress(OSError):
                self._log.close()
            self._log = None


# --------------------------------------------------------------------------- browser


class Capturer:
    """Drives one Chrome page through the scene script."""

    def __init__(self, page: Any, *, frozen_label: str) -> None:
        self.page = page
        self.frozen_label = frozen_label
        self.current_path: str | None = None

    # -- page plumbing -------------------------------------------------

    def goto(self, path: str) -> None:
        url = BASE_URL + path
        logger.debug("navigate %s", url)
        response = self.page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        if response is not None and response.status >= 400:
            raise CaptureError(f"{url} returned HTTP {response.status}")
        self.current_path = path
        self.settle()

    def settle(self) -> None:
        """Wait until the page is quiet, charts are drawn and the clock text is pinned."""
        with suppress(Exception):
            self.page.wait_for_load_state("networkidle", timeout=IDLE_TIMEOUT_MS)
        with suppress(Exception):
            self.page.evaluate("() => document.fonts && document.fonts.ready")
        try:
            self.page.wait_for_function(CHARTS_READY_JS, timeout=CHART_TIMEOUT_MS)
        except Exception as exc:  # noqa: BLE001 - a chartless page is fine, a stuck one is not
            logger.warning("charts did not finish rendering on %s: %s", self.current_path, exc)
        self._freeze()
        with suppress(Exception):
            self.page.evaluate(FREEZE_JS, self.frozen_label)
        with suppress(Exception):
            self.page.evaluate(RESOLVER_RUNNING_JS)
        with suppress(Exception):
            self.page.evaluate(WHOLE_ROWS_JS)
        self.page.wait_for_timeout(SETTLE_MS)

    def scroll_to(self, y: int) -> None:
        self.page.evaluate("(y) => window.scrollTo(0, y)", int(y))
        self.page.wait_for_timeout(200)
        actual = int(self.page.evaluate("() => Math.round(window.scrollY)"))
        if abs(actual - int(y)) > 4:
            logger.warning(
                "requested scroll %s on %s but the page stopped at %s (document is shorter)",
                y, self.current_path, actual,
            )
        self.page.wait_for_timeout(150)

    def shoot(self, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.page.screenshot(path=str(dest), full_page=False, animations="disabled", caret="hide")
        return dest

    def set_content(self, html: str) -> None:
        self.page.set_content(html, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        with suppress(Exception):
            self.page.wait_for_load_state("networkidle", timeout=IDLE_TIMEOUT_MS)
        with suppress(Exception):
            self.page.evaluate("() => document.fonts && document.fonts.ready")
        self._freeze()
        self.page.wait_for_timeout(SETTLE_MS)

    def _freeze(self) -> None:
        """Inject the anti-jitter CSS once per document (re-settles must not stack it)."""
        already = False
        with suppress(Exception):
            already = bool(self.page.evaluate("() => !!document.getElementById('homesoc-freeze')"))
        if already:
            return
        with suppress(Exception):
            self.page.add_style_tag(content=FREEZE_CSS)
        with suppress(Exception):
            self.page.evaluate(
                "() => { const s = document.querySelector('style:last-of-type');"
                " if (s) s.id = 'homesoc-freeze'; }"
            )

    # -- geometry ------------------------------------------------------

    def rect(self, selector: str, *, scene_id: str) -> list[float]:
        """Viewport rect ``[x, y, w, h]`` in the 1600x900 CSS space, or a clear failure."""
        try:
            locator = self.page.locator(selector)
            count = locator.count()
        except Exception as exc:  # noqa: BLE001 - a malformed selector must name its scene
            raise CaptureError(
                f"{scene_id}: selector {selector!r} is not a valid Playwright selector "
                f"({type(exc).__name__}: {exc})"
            ) from exc
        if count == 0:
            raise CaptureError(
                f"{scene_id}: selector {selector!r} matched nothing on {self.current_path!r}. "
                "Fix the selector in video/script.py - capture.py never guesses coordinates."
            )
        if count > 1:
            logger.warning(
                "%s: selector %r matched %d elements on %s; using the first",
                scene_id, selector, count, self.current_path,
            )
        box = locator.first.bounding_box()
        if not box:
            raise CaptureError(
                f"{scene_id}: selector {selector!r} matched an element with no box on "
                f"{self.current_path!r} (it is display:none or has zero size)."
            )
        return [
            round(float(box["x"]), 2),
            round(float(box["y"]), 2),
            round(float(box["width"]), 2),
            round(float(box["height"]), 2),
        ]

    def click_at(self, x: float, y: float, *, scene_id: str) -> None:
        if not (0 <= x <= VIEWPORT_W and 0 <= y <= VIEWPORT_H):
            raise CaptureError(
                f"{scene_id}: click point ({x:.0f}, {y:.0f}) is outside the "
                f"{VIEWPORT_W}x{VIEWPORT_H} viewport - the element needs a scroll state first."
            )
        self.page.mouse.move(x, y)
        self.page.wait_for_timeout(60)
        self.page.mouse.click(x, y)


# --------------------------------------------------------------------------- slides


def load_slides() -> dict[str, Any]:
    """``{name: callable_or_html}`` from ``video/slides.py``."""
    try:
        import slides  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CaptureError(
            f"cannot import {HERE / 'slides.py'} - slide HTML must exist before capture ({exc})"
        ) from exc
    registry = getattr(slides, "SLIDES", None)
    if isinstance(registry, dict) and registry:
        return dict(registry)
    found = {
        name[len("slide_"):] if name.startswith("slide_") else name: getattr(slides, name)
        for name in dir(slides)
        if name.startswith("slide_") and callable(getattr(slides, name))
    }
    if found:
        return found
    raise CaptureError(
        f"{HERE / 'slides.py'} exposes neither a SLIDES dict nor any slide_* functions"
    )


def slide_html(registry: dict[str, Any], name: str, *, scene_id: str = "-") -> str:
    entry = registry.get(name)
    if entry is None:
        for key in (f"slide_{name}", name.replace("-", "_"), name.replace("_", "-")):
            if key in registry:
                entry = registry[key]
                break
    if entry is None:
        raise CaptureError(
            f"{scene_id}: slides.py has no slide named {name!r}. "
            f"Available: {', '.join(sorted(registry)) or '(none)'}"
        )
    try:
        html = entry() if callable(entry) else entry
    except Exception as exc:  # noqa: BLE001 - a broken slide must name itself
        raise CaptureError(
            f"{scene_id}: slides.{name} raised {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(html, str) or "<" not in html:
        raise CaptureError(f"{scene_id}: slide {name!r} did not return HTML (got {type(html).__name__})")
    return html


def capture_slides(cap: Capturer, registry: dict[str, Any], names: list[str] | None = None) -> dict[str, Path]:
    wanted = names if names is not None else sorted(registry)
    out: dict[str, Path] = {}
    for i, name in enumerate(wanted, start=1):
        dest = SHOTS_DIR / f"slide_{name}.png"
        cap.set_content(slide_html(registry, name))
        cap.shoot(dest)
        out[name] = dest
        print(f"  [slide {i}/{len(wanted)}] {name:<22} -> {dest.name}", flush=True)
    return out


# --------------------------------------------------------------------------- scenes


@dataclass
class SceneResult:
    scene_id: str
    states: list[State] = field(default_factory=list)
    geometry: dict[str, list[float]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def load_scenes() -> list[Any]:
    try:
        import script  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CaptureError(
            f"cannot import {HERE / 'script.py'} - the scene script must exist before capture ({exc})"
        ) from exc
    scenes = getattr(script, "SCENES", None)
    if not scenes:
        raise CaptureError(f"{HERE / 'script.py'} defines no non-empty SCENES list")
    return list(scenes)


@dataclass(frozen=True)
class Target:
    """What is on screen for one state: a slide, or a dashboard page at a scroll offset."""

    kind: str  # "slide" | "page"
    ref: str  # slide name, or url path
    scroll: int = 0


@dataclass
class Planned:
    """A state on the scene's fractional timeline, before it has been captured."""

    at: float
    target: Target
    produced_by: str


#: Two declarations of the same state closer together than this are the same state — a
#: PageSequence member and the Scroll/Click that moves to it are written a beat apart.
MERGE_WINDOW: Final[float] = 0.10


def _target_of(shot: object, scene_id: str, *, current_path: str | None) -> Target:
    if is_slide(shot):
        return Target("slide", slide_name(shot, scene_id))
    if is_sequence(shot):
        items = sequence_items(shot)
        if not items:
            raise CaptureError(f"{scene_id}: nested PageSequence is empty")
        return _target_of(items[0], scene_id, current_path=current_path)
    if is_page(shot):
        return Target("page", page_path(shot, scene_id), page_scroll(shot))
    raise CaptureError(f"{scene_id}: unrecognised shot {shot!r} ({_kind_of(shot)})")


@dataclass(frozen=True)
class _ScrollTo:
    to_y: int


def plan_states(scene: Any) -> list[Planned]:
    """The ordered states a scene passes through, on its 0..1 narration timeline.

    Three things declare a state, and they overlap on purpose:

    * every member of a ``PageSequence`` (``ats[i]`` says when member *i* takes over),
    * every ``Click`` — ``then_shot`` is the state the real click produces,
    * every ``Scroll`` — the same page at the new offset.

    ``script.py``'s convention is that a scene's scroll offsets are *declared* in its
    ``PageSequence`` **and** reached by a matching ``Scroll`` action, so the two
    declarations of one state are merged here rather than captured twice.
    """
    scene_id = str(getattr(scene, "id", "") or "scene")
    shot = getattr(scene, "shot", None)
    if shot is None:
        raise CaptureError(f"{scene_id}: scene has no shot")

    members = sequence_items(shot) if is_sequence(shot) else [shot]
    if not members:
        raise CaptureError(f"{scene_id}: PageSequence is empty")
    ats = list(_attr(shot, "ats", default=()) or ())

    declared: list[tuple[float, object, str]] = []
    for i, member in enumerate(members[1:], start=1):
        if len(ats) == len(members):
            frac = float(ats[i])
        else:
            frac = i / len(members)
        declared.append((frac, member, "sequence"))

    for action in sorted(getattr(scene, "actions", None) or [], key=action_at):
        kind = _kind_of(action)
        if kind == "Click":
            then_shot = _attr(action, "then_shot", "then", "after")
            if then_shot is None:
                continue
            declared.append((action_at(action), then_shot, "click"))
        elif kind == "Scroll":
            to_y = int(_attr(action, "to_y", "y", "scroll", default=0) or 0)
            declared.append((action_at(action), _ScrollTo(to_y), "scroll"))

    declared.sort(key=lambda entry: entry[0])

    first = _target_of(members[0], scene_id, current_path=None)
    plan = [Planned(0.0, first, "shot")]
    current = first
    for frac, payload, produced_by in declared:
        if isinstance(payload, _ScrollTo):
            if current.kind != "page":
                raise CaptureError(
                    f"{scene_id}: Scroll at {frac:.2f} has no page on screen to scroll "
                    f"(the shot at that point is the slide {current.ref!r})"
                )
            target = Target("page", current.ref, payload.to_y)
        else:
            target = _target_of(payload, scene_id, current_path=current.ref)
        previous = plan[-1]
        if target == previous.target and frac - previous.at <= MERGE_WINDOW:
            previous.produced_by = f"{previous.produced_by}+{produced_by}"
            continue
        plan.append(Planned(frac, target, produced_by))
        current = target
    return plan


def capture_scene(cap: Capturer, scene: Any, registry: dict[str, Any]) -> SceneResult:
    """Capture every state a scene passes through and resolve every selector it names.

    States and actions are walked together in ``at`` order, so a selector that only exists
    after a click (``findings.html``'s ``tr.detail-row`` is ``hidden`` until its row is
    clicked) is measured on the state that is actually on screen when the cursor gets there.
    """
    scene_id = str(getattr(scene, "id", "") or "scene")
    result = SceneResult(scene_id=scene_id)
    plan = plan_states(scene)

    # Actions first at equal `at`: a Click must fire before the state it produces lands.
    timeline: list[tuple[float, int, str, Any]] = [
        (p.at, 1, "state", p) for p in plan
    ] + [
        (action_at(a), 0, "action", a) for a in (getattr(scene, "actions", None) or [])
    ]
    timeline.sort(key=lambda entry: (entry[0], entry[1]))

    index = -1
    cursor: tuple[float, float] | None = None

    for _frac, _prio, kind, payload in timeline:
        if kind == "state":
            index += 1
            state = _realise(cap, scene_id, payload, index, registry)
            state.png = cap.shoot(SHOTS_DIR / state.filename)
            result.states.append(state)
            where = state.path if state.kind == "page" else f"slide:{state.path}"
            scroll = f" @{state.scroll}" if state.scroll else ""
            print(
                f"  [{scene_id}] state {state.index} at {payload.at:.2f} {where}{scroll} "
                f"({state.produced_by}) -> {state.png.name}",
                flush=True,
            )
            continue

        action = payload
        action_kind = _kind_of(action)
        selector = action_selector(action)

        if selector:
            xy = parse_xy(str(selector))
            if xy is not None:
                cursor = xy
            else:
                rect = cap.rect(str(selector), scene_id=scene_id)
                previous = result.geometry.get(str(selector))
                if previous is not None and previous != rect:
                    logger.warning(
                        "%s: selector %r resolves to %s here but %s earlier in the scene; "
                        "geometry.json keeps the last value",
                        scene_id, selector, rect, previous,
                    )
                result.geometry[str(selector)] = rect
                off = _offscreen(rect)
                if off:
                    warning = (
                        f"{scene_id}: {action_kind} target {selector!r} sits {off} the "
                        f"{VIEWPORT_W}x{VIEWPORT_H} viewport at rect {rect} - the cursor "
                        "would be drawn outside the frame. Give the scene a scroll state "
                        "that brings the element on screen."
                    )
                    logger.warning("%s", warning)
                    result.warnings.append(warning)
                if action_kind in {"Move", "Click"}:
                    cursor = (rect[0] + rect[2] / 2, rect[1] + rect[3] / 2)

        if action_kind == "Click":
            if cursor is None:
                raise CaptureError(
                    f"{scene_id}: Click at {action_at(action):.2f} has no preceding Move, so "
                    "nothing is under the cursor to click. Add a Move action before it."
                )
            cap.click_at(cursor[0], cursor[1], scene_id=scene_id)
            cap.page.wait_for_timeout(350)

        elif action_kind == "Zoom":
            rect_spec = _attr(action, "to_rect", "rect")
            if rect_spec is None or len(list(rect_spec)) != 4:
                raise CaptureError(f"{scene_id}: Zoom needs a 4-tuple to_rect, got {rect_spec!r}")

        elif action_kind in {"Move", "Highlight"}:
            if not selector:
                raise CaptureError(f"{scene_id}: {action_kind} has no selector ({action!r})")

        elif action_kind != "Scroll":
            logger.warning("%s: ignoring unknown action type %s (%r)", scene_id, action_kind, action)

    return result


def _realise(
    cap: Capturer, scene_id: str, planned: Planned, index: int, registry: dict[str, Any]
) -> State:
    """Put ``planned.target`` on screen, without disturbing state a click just produced."""
    target = planned.target
    if target.kind == "slide":
        cap.set_content(slide_html(registry, target.ref, scene_id=scene_id))
        cap.current_path = None
        return State(scene_id, index, "slide", target.ref, produced_by=planned.produced_by)

    landed = _current_path(cap) if cap.current_path is not None else None
    if landed != target.ref:
        if planned.produced_by.startswith("click") and landed is not None:
            logger.warning(
                "%s: the click landed on %r but the script's then_shot says %r; "
                "navigating explicitly so the after-state is the declared one",
                scene_id, landed, target.ref,
            )
        cap.goto(target.ref)
    else:
        # Same URL: a click that expanded a row or toggled a filter in place. Re-navigating
        # would throw that state away, so only re-settle.
        cap.current_path = landed
        cap.settle()
    cap.scroll_to(target.scroll)
    return State(scene_id, index, "page", target.ref, target.scroll, produced_by=planned.produced_by)


def _current_path(cap: Capturer) -> str:
    url = str(cap.page.url or "")
    if url.startswith(BASE_URL):
        return url[len(BASE_URL):] or "/"
    return url


# --------------------------------------------------------------------------- driver


def capture(
    *,
    data_dir: Path = DEMO_DATA,
    only: str | None = None,
    slides_only: bool = False,
    no_slides: bool = False,
    headed: bool = False,
) -> tuple[dict[str, SceneResult], dict[str, Path]]:
    from playwright.sync_api import sync_playwright

    scenes = [] if slides_only else load_scenes()
    if only:
        wanted = {s.strip() for s in only.split(",") if s.strip()}
        known = {str(getattr(s, "id", "")) for s in scenes}
        unknown = wanted - known
        if unknown:
            raise CaptureError(f"--only names unknown scene ids: {', '.join(sorted(unknown))}")
        scenes = [s for s in scenes if str(getattr(s, "id", "")) in wanted]

    registry = load_slides()
    slide_names: list[str] | None = None
    if no_slides:
        slide_names = []
    elif only and not slides_only:
        slide_names = sorted({
            slide_name(sh, str(getattr(s, "id", "")))
            for s in scenes
            for sh in _all_shots(s)
            if is_slide(sh)
        })

    SHOTS_DIR.mkdir(parents=True, exist_ok=True)
    # Truncated to the minute: relative "3h ago" text stays honest against the seeded data,
    # but the seconds hand can never differ between two runs of the same capture.
    now = datetime.now().replace(second=0, microsecond=0)
    frozen_label = "updated " + now.strftime("%I:%M:%S %p").lstrip("0")

    results: dict[str, SceneResult] = {}
    slide_pngs: dict[str, Path] = {}
    needs_dashboard = any(not is_slide(sh) for s in scenes for sh in _all_shots(s))

    with ExitStack() as stack:
        dashboard = (
            stack.enter_context(Dashboard(data_dir=make_working_copy(data_dir)))
            if needs_dashboard else None
        )
        p = stack.enter_context(sync_playwright())
        browser = None
        try:
            browser = p.chromium.launch(channel="chrome", headless=not headed)
            context = browser.new_context(
                viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
                device_scale_factor=SCALE,
                color_scheme="dark",
                reduced_motion="reduce",
                base_url=BASE_URL,
            )
            context.set_default_timeout(NAV_TIMEOUT_MS)
            with suppress(Exception):
                context.clock.set_fixed_time(now)
            _strip_csp(context)
            page = context.new_page()
            cap = Capturer(page, frozen_label=frozen_label)

            if not no_slides:
                slide_pngs = capture_slides(cap, registry, slide_names)

            for i, scene in enumerate(scenes, start=1):
                scene_id = str(getattr(scene, "id", f"scene-{i:02d}"))
                started = time.monotonic()
                results[scene_id] = capture_scene(cap, scene, registry)
                print(
                    f"  [{i:02d}/{len(scenes)}] {scene_id:<22} "
                    f"{len(results[scene_id].states)} state(s), "
                    f"{len(results[scene_id].geometry)} selector(s), "
                    f"{time.monotonic() - started:.1f}s",
                    flush=True,
                )
        finally:
            if browser is not None:
                with suppress(Exception):
                    browser.close()
            if dashboard is not None:
                dashboard.stop()

    _write_outputs(results, slide_pngs)
    return results, slide_pngs


def _all_shots(scene: Any) -> list[Any]:
    shots: list[Any] = []
    shot = getattr(scene, "shot", None)
    if shot is not None:
        shots.extend(sequence_items(shot) if is_sequence(shot) else [shot])
    for action in getattr(scene, "actions", None) or []:
        then_shot = _attr(action, "then_shot", "then", "after")
        if then_shot is not None:
            shots.append(then_shot)
    return shots


def _strip_csp(context: Any) -> None:
    """Drop the dashboard's ``default-src 'self'`` header so injected CSS actually applies.

    Only affects the throwaway capture browser; the product's headers are untouched.
    """

    def handler(route: Any) -> None:
        try:
            response = route.fetch()
            headers = {
                k: v for k, v in response.headers.items()
                if k.lower() != "content-security-policy"
            }
            route.fulfill(response=response, headers=headers)
        except Exception:  # noqa: BLE001 - never let a routing hiccup kill the capture
            with suppress(Exception):
                route.continue_()

    context.route("**/*", handler)


def _write_outputs(results: dict[str, SceneResult], slide_pngs: dict[str, Path]) -> None:
    BUILD.mkdir(parents=True, exist_ok=True)

    geometry = {sid: res.geometry for sid, res in results.items()}
    if GEOMETRY_PATH.is_file():  # keep scenes captured in earlier --only runs
        with suppress(Exception):
            existing = json.loads(GEOMETRY_PATH.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                geometry = {**existing, **geometry}
    GEOMETRY_PATH.write_text(json.dumps(geometry, indent=2) + "\n", encoding="utf-8")

    manifest: dict[str, Any] = {
        "viewport": [VIEWPORT_W, VIEWPORT_H],
        "device_scale_factor": SCALE,
        "shot_size": [SHOT_W, SHOT_H],
        "slides": {name: path.as_posix() for name, path in sorted(slide_pngs.items())},
        "scenes": {sid: [s.as_json() for s in res.states] for sid, res in results.items()},
        "warnings": {sid: res.warnings for sid, res in results.items() if res.warnings},
    }
    if MANIFEST_PATH.is_file():
        with suppress(Exception):
            existing = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                manifest["slides"] = {**existing.get("slides", {}), **manifest["slides"]}
                manifest["scenes"] = {**existing.get("scenes", {}), **manifest["scenes"]}
                # A partial run re-states only the scenes it touched, so a scene it did not
                # touch keeps whatever the last full run said about it.
                merged_warnings = dict(existing.get("warnings", {}))
                for sid in results:
                    merged_warnings.pop(sid, None)
                merged_warnings.update(manifest["warnings"])
                manifest["warnings"] = merged_warnings
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"\n  {GEOMETRY_PATH}")
    print(f"  {MANIFEST_PATH}")
    print(f"  {SHOTS_DIR}  ({len(list(SHOTS_DIR.glob('*.png')))} png)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture the Home SOC dashboard for the walkthrough video.")
    parser.add_argument("--only", metavar="ID[,ID]", help="only capture these scene ids")
    parser.add_argument("--slides-only", action="store_true", help="render the slides and stop")
    parser.add_argument("--no-slides", action="store_true", help="skip the slides, capture pages only")
    parser.add_argument("--headed", action="store_true", help="show the browser window")
    parser.add_argument("--data", metavar="DIR", default=str(DEMO_DATA), help="demo data directory")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    data_dir = Path(args.data).expanduser().resolve()
    print(f"capture: data={data_dir} port={PORT} viewport={VIEWPORT_W}x{VIEWPORT_H}@{SCALE}x")
    try:
        capture(
            data_dir=data_dir,
            only=args.only,
            slides_only=args.slides_only,
            no_slides=args.no_slides,
            headed=args.headed,
        )
    except CaptureError as exc:
        print(f"\ncapture: FAILED\n{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ncapture: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
