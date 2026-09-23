"""Capture stage of the Home SOC walkthrough video.

Owns a throwaway dashboard process (``homesoc serve --tls --port 8899`` against
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

Lens, and why the dashboard is now served over TLS
--------------------------------------------------
CONTRACT_V2 adds an act about Lens, the phone app. Browsers hand out ``getUserMedia`` only
in a secure context, and Lens refuses to serve a phone over plain HTTP, so the demo
dashboard is started with ``--tls`` and everything — desktop pages included — is captured
from ``https://127.0.0.1:8899``. The certificate is self-signed, which is the product's
documented path, and both browser contexts are created with ``ignore_https_errors``.

Three new shot kinds come from ``script.py`` and are handled here:

``Phone(path="/lens", state=..., scroll=...)``
    A 390x844 @3x phone screen, captured by :mod:`phone` in its own mobile context and
    saved at 1170x2532. Tap targets are resolved in the 390x844 space and land in
    ``geometry.json`` under the phone scene's id, exactly like cursor targets.

``PhonePair(scene_png=..., phone_state=...)``
    Scene 18: the illustrated scene from ``scene_render.py`` beside the phone. Only the
    phone half is captured here; the manifest records where the scene still lives.

``Tap`` / ``PhoneScroll``
    Phone choreography. A ``Tap``'s target is resolved on the phone state that is on
    screen when it fires; ``PhoneScroll`` scrolls the card's own body, not the document.

Two substitutions, both stated out loud
---------------------------------------
1. **The decoder** (CONTRACT_V2 V3). Desktop Chrome on Windows has no ``BarcodeDetector``,
   so for scene 18 this module starts ``video/decode_sidecar.py`` (zxing-cpp), launches
   Chrome with ``--use-file-for-fake-video-capture`` pointed at the Y4M that
   ``video/scene_render.py`` drew, and injects a ``BarcodeDetector`` shim that hands the
   frame to the sidecar and returns the real decoded value. The pixels are genuinely
   decoded; only the decoder sits beside the browser instead of inside it. If the shim
   does not produce the camera's sticker token, capture **fails** — the narration calls it
   a scan, so it has to be one, and quietly falling back to the manual picker would make
   the video lie.

2. **The machine's identity**. ``cli.lens_hosts`` builds the TLS certificate's subject and
   subjectAltNames out of ``socket.gethostname()`` and the real LAN address, and
   ``/lens/pair`` prints both, along with a pairing URL built from them. That would put the
   author's real hostname and LAN address on screen, which CONTRACT_V2 V5 forbids. The
   demo dashboard is therefore launched through ``build/serve_demo.py``, a generated
   wrapper that rebinds ``util.local_hostname``/``util.default_interface_ip`` to the
   fiction the rest of the video already uses (``home-pc``, ``192.168.1.20`` — the address
   seed_demo.py gives HOME-PC in the inventory) and records
   the bind address the documented invocation produces (``192.168.1.20:8443``, from
   ``serve --tls --host 0.0.0.0 --port 8443``). The socket still listens on loopback only,
   so nothing is exposed. Nothing under ``homesoc/`` is modified; the wrapper lives in
   ``build/`` and exists for the length of one capture. The precedent is the resolver fix
   below: where the capture harness contradicts what a real ``run.bat`` instance shows,
   the harness is what gets corrected.

Nothing here writes to the real ``data/`` directory or ``config.toml``. The dashboard runs
with ``HOMESOC_DATA``/``HOMESOC_CONFIG`` pointing at a generated, token-free config under
``build/`` and at ``build/demo_data_run`` — a throwaway copy of ``video/demo_data`` made at
the start of every run. The copy matters: the script clicks *Acknowledge* on a finding and
ticks filter boxes for real, so the dashboard writes to its database. Serving a copy keeps
``video/demo_data`` exactly as ``seed_demo.py`` left it and makes re-runs identical.

Usage::

    python video/capture.py                    # slides + every scene
    python video/capture.py --only 06-findings
    python video/capture.py --only 18-lens-scan   # the scan rig, end to end
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
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import ExitStack, closing, suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Final

HERE: Final[Path] = Path(__file__).resolve().parent
PROJECT_ROOT: Final[Path] = HERE.parent
if str(HERE) not in sys.path:  # so `python video/capture.py` finds script.py / slides.py
    sys.path.insert(0, str(HERE))

BUILD_ROOT: Final[Path] = HERE / "build"
DEMO_DATA: Final[Path] = HERE / "demo_data"

# Everything below is per film and is (re)bound by :func:`configure` - the everyday film
# captures into build/everyday/, the technical cut into build/ as it always has. The defaults
# are the everyday film's, so importing this module without configuring it is still coherent.
BUILD: Path = BUILD_ROOT / "everyday"
SHOTS_DIR: Path = BUILD / "shots"
GEOMETRY_PATH: Path = BUILD / "geometry.json"
MANIFEST_PATH: Path = BUILD / "shots_manifest.json"
DASHBOARD_LOG: Path = BUILD / "dashboard.log"
DEMO_CONFIG: Path = BUILD / "demo_config.toml"
#: Throwaway copy of demo_data that the dashboard is allowed to write to.
WORK_DATA: Path = BUILD / "demo_data_run"
#: Generated wrapper that starts the dashboard with a fictional machine identity.
SERVE_LAUNCHER: Path = BUILD / "serve_demo.py"
SIDECAR_LOG: Path = BUILD / "decode_sidecar.log"
#: The film's scene script and slide modules, and the colour scheme the browser reports.
SCRIPT_MODULE: str = "script_everyday"
SLIDES_MODULE: str = "slides_everyday"
#: "light" is the dashboard's Stone & Sage day theme. The redesigned style.css follows
#: prefers-color-scheme, so a "dark" browser is shown the cocoa Dusk theme instead.
COLOR_SCHEME: str = "light"
FILM_NAME: str = "everyday"
#: Blur the film script's ``REDACTIONS`` (the unbranded router, real brand domains on Blocking)
#: on every page it settles. A film rule, so ``shoot_docs.py`` switches it off for the docs.
REDACT: bool = True


def configure(film: Any) -> None:
    """Point every per-film path and module at ``film`` (a ``narrate.Film``)."""
    global BUILD, SHOTS_DIR, GEOMETRY_PATH, MANIFEST_PATH, DASHBOARD_LOG, DEMO_CONFIG
    global WORK_DATA, SERVE_LAUNCHER, SIDECAR_LOG, PHONE_DIR
    global SCRIPT_MODULE, SLIDES_MODULE, COLOR_SCHEME, FILM_NAME
    BUILD = Path(film.build)
    SHOTS_DIR = BUILD / "shots"
    GEOMETRY_PATH = BUILD / "geometry.json"
    MANIFEST_PATH = BUILD / "shots_manifest.json"
    DASHBOARD_LOG = BUILD / "dashboard.log"
    DEMO_CONFIG = BUILD / "demo_config.toml"
    WORK_DATA = BUILD / "demo_data_run"
    SERVE_LAUNCHER = BUILD / "serve_demo.py"
    SIDECAR_LOG = BUILD / "decode_sidecar.log"
    PHONE_DIR = SHOTS_DIR
    SCRIPT_MODULE = str(film.script_module)
    SLIDES_MODULE = str(film.slides_module)
    COLOR_SCHEME = str(film.color_scheme)
    FILM_NAME = str(film.name)
    # scene_render.py draws a different object for each film (the everyday film's small white
    # box, the technical cut's navy bullet camera) and reads which one from here at import.
    import os  # noqa: PLC0415

    os.environ["HOMESOC_VIDEO_FILM"] = FILM_NAME


def _import(name: str) -> Any:
    import importlib

    return importlib.import_module(name)


def _pick_port(preferred: int, *, tries: int = 24) -> int:
    """``preferred`` if loopback is free there, else the next free port above it.

    A fixed port is a liability on a machine that is doing more than one thing: a stale
    ``homesoc serve`` left on 8899 by something else answered the readiness probe over
    *plain HTTP*, and this module's TLS probe failed with ``WRONG_VERSION_NUMBER`` sixty
    seconds later with nothing useful to say. Picking a free one costs a bind and a close.
    """
    for candidate in range(preferred, preferred + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", candidate))
            except OSError:
                continue
        if candidate != preferred:
            # `logger` is defined below this block, so ask for it by name.
            logging.getLogger("homesoc.video.capture").warning(
                "port %d is busy; using %d instead", preferred, candidate
            )
        return candidate
    return preferred


PORT: Final[int] = _pick_port(8899)
#: Lens needs a secure context, so the whole capture — desktop pages included — is https.
BASE_URL: Final[str] = f"https://127.0.0.1:{PORT}"

#: The fiction the rest of the video already tells, extended to the machine itself so no
#: frame can show the author's hostname or LAN address. See the module docstring.
#:
#: These must agree with the machine seed_demo.py puts in the inventory, because the video
#: shows both: /lens/pair prints this address, and /devices lists every address in the
#: household two scenes earlier. seed_demo.py's device 2 is hostname HOME-PC, nickname
#: "Home PC", notes "The machine Home SOC itself runs on", at 192.168.1.20. An earlier take
#: used 192.168.1.50 here, which in that same inventory is device 12, the Epson printer — so
#: scene 16 announced that Home SOC was serving from the printer. Re-check against the
#: devices table if the seed's addressing ever changes.
DEMO_HOSTNAME: Final[str] = "home-pc"
DEMO_LAN_IP: Final[str] = "192.168.1.20"
DEMO_LAN_PORT: Final[int] = 8443

#: The phone this capture pairs with itself, so ``/lens`` renders as a paired phone.
LENS_TOKEN_LABEL: Final[str] = "Pixel in the hallway"

#: The scan rig (CONTRACT_V2 V3). Owned by other packages; this module starts them.
SCENE_RENDER_SCRIPT: Final[Path] = HERE / "scene_render.py"
SIDECAR_SCRIPT: Final[Path] = HERE / "decode_sidecar.py"
SIDECAR_PORT: Final[int] = _pick_port(max(8901, PORT + 1))
#: Scenes whose narration calls the identification a *scan*, so it has to be a real one.
SCAN_SCENES: Final[frozenset[str]] = frozenset({"18-lens-scan"})
#: Where the phone screens land, next to the desktop shots (rebound by configure()).
PHONE_DIR: Path = BUILD / "shots"

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


#: The demo certificate is self-signed on purpose — that is the path SPEC B3 documents and
#: scene 16 explains. Nothing here is a trust decision: it is this machine dialling itself.
_TLS_CTX: Final[ssl.SSLContext] = ssl._create_unverified_context()


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

/* Long reference URLs.
   In a browser you scroll a clipped URL, or hover it, or click it. In a video it just sits
   there chopped: the finding detail in scene 6 parked
   "...CSI_BEST_PRACTICES_FOR_SECURING_YOUR_H" against the right edge of the remediation
   panel, with no ellipsis and no wrap, for sixteen seconds. Wrapping is what the page
   would do at a narrower width anyway - nothing is hidden and nothing is invented. */
.detail a, .detail li, .refs a, .refs li {
  overflow-wrap: anywhere !important;
  word-break: break-word !important;
}

/* NOT fixed here, on purpose: the empty band inside "Fix these first" and "Last scans".
   It is not a min-height the video may quietly drop - those are `.card-fill` cards in a
   `.grid`, so CSS grid stretches them to their taller neighbour and `.push-down` pins the
   footnote to the bottom of the stretched box. Overriding either would be the video
   redrawing the product's layout to flatter it, and seeding more finding types to fill the
   card would move every figure the narration speaks. It is the page's own behaviour on a
   small network, and it stays. */
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

#: Web blocking is REALLY running in the film. `homesoc serve` ("dashboard only") never starts
#: the resolver - `cmd_serve` passes ``with_dns=False`` - so a plain serve reports "Web blocking
#: is switched on but not running" next to twenty-four hours of blocked look-ups. The v2 cut
#: papered over that with a script that rewrote the three indicators to "running"; that script
#: is gone. Instead the capture launcher (``build/serve_demo.py``) starts the product's own
#: embedded resolver - ``Runtime.start_dns()``, exactly what `homesoc run` does - bound to
#: 127.0.0.1 on a free high port (never 53, never the LAN), and :func:`verify_blocking_running`
#: refuses to capture unless the dashboard, the Home banner, the sidebar chip and the Blocking
#: page all say so on their own. Nothing queries the resolver during a capture, so the query
#: log, the hourly bars and the block counts are still exactly what the seed wrote.
DNS_PORT_PREFERRED: Final[int] = 53530


def _pick_dns_port(preferred: int, *, tries: int = 40) -> int:
    """A loopback port free for both UDP and TCP, at or above ``preferred``."""
    for candidate in range(preferred, preferred + tries):
        try:
            with (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
                  socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp):
                udp.bind(("127.0.0.1", candidate))
                tcp.bind(("127.0.0.1", candidate))
        except OSError:
            continue
        return candidate
    raise RuntimeError(f"no free loopback port for the demo resolver in {preferred}-{preferred + tries}")


DNS_PORT: Final[int] = _pick_dns_port(DNS_PORT_PREFERRED)

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
    kind: str  # "slide" | "page" | "phone" | "phone_pair"
    path: str  # url path, or the slide name
    scroll: int = 0
    png: Path | None = None
    produced_by: str = "shot"
    #: Phone states only — everything the compositor needs to frame and caption one.
    phone: dict[str, Any] | None = None

    @property
    def filename(self) -> str:
        return f"{self.scene_id}_{self.index}.png"

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "index": self.index,
            "kind": self.kind,
            "path": self.path,
            "scroll": self.scroll,
            "png": self.png.as_posix() if self.png else None,
            "produced_by": self.produced_by,
        }
        if self.phone is not None:
            out["phone"] = self.phone
        return out


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


def is_phone(shot: object) -> bool:
    """``Phone(path="/lens", state="scan"|"card"|"picker"|"unknown", scroll=0)``."""
    return _kind_of(shot) == "Phone" or (
        hasattr(shot, "state") and hasattr(shot, "path") and not hasattr(shot, "scene_png")
    )


def is_phone_pair(shot: object) -> bool:
    """``PhonePair(scene_png=..., phone_state=...)`` — the illustrated scene plus a phone."""
    return _kind_of(shot) == "PhonePair" or hasattr(shot, "phone_state") or hasattr(shot, "scene_png")


def is_page(shot: object) -> bool:
    if is_phone(shot) or is_phone_pair(shot):
        return False
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


def phone_path(shot: object) -> str:
    path = str(_attr(shot, "path", "url", "route", default="/lens") or "/lens")
    return path if path.startswith("/") else "/" + path


def phone_state(shot: object, scene_id: str) -> str:
    """The screen a phone shot wants, normalised and checked against :data:`phone.STATES`."""
    state = str(_attr(shot, "state", "phone_state", "screen", default="") or "").strip().lower()
    if not state:
        raise CaptureError(f"{scene_id}: phone shot {shot!r} declares no state")
    if state not in _phone().STATES:
        raise CaptureError(
            f"{scene_id}: unknown phone state {state!r}; expected one of "
            f"{', '.join(_phone().STATES)}"
        )
    return state


def pair_scene_png(shot: object) -> str:
    """The illustrated still ``scene_render.py`` drew, as declared by a ``PhonePair``."""
    return str(_attr(shot, "scene_png", "scene", "still", default="") or "")


def _phone() -> Any:
    """``video/phone.py``, imported late so ``--slides-only`` never needs Pillow's phone kit."""
    try:
        import phone  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CaptureError(
            f"cannot import {HERE / 'phone.py'} - the phone rig must exist before capture ({exc})"
        ) from exc
    return phone


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


#: Actions that move nothing and point at nothing, so have no selector to resolve.
_TARGETLESS: Final[frozenset[str]] = frozenset({"Click", "Scroll", "Zoom", "PhoneScroll"})


def action_selector(action: object) -> str | None:
    """The selector string an action points at, exactly as written in the script.

    ``Tap`` carries its target in ``xy``, which may be a literal ``(x, y)`` in the phone's
    390x844 space rather than a string; normalising it to ``"xy=(x, y)"`` here means the
    compositor reads one spelling out of ``geometry.json`` whatever the script wrote.
    """
    kind = _kind_of(action)
    if kind == "Move":
        return _attr(action, "to", "target", "sel", "selector")
    if kind == "Highlight":
        return _attr(action, "sel", "selector", "to", "target")
    if kind == "Tap":
        target = _attr(action, "xy", "to", "sel", "selector", "target")
        if isinstance(target, (tuple, list)) and len(target) == 2:
            return f"xy=({target[0]}, {target[1]})"
        return target
    return _attr(action, "sel", "selector") if kind not in _TARGETLESS else None


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

# The real resolver, on loopback and a free high port (see DNS_PORT_PREFERRED).
[dns]
enabled = true
listen = "127.0.0.1"
port = {dns_port}

[feeds]
enabled = false

[notify]
windows_toast = false

# Lens is off by default in the product (SPEC B10) and has to be turned on deliberately.
# The video turns it on for the demo database only; `act` stays off, so the phone in the
# video is strictly read-only.
[lens]
{lens}
"""

#: The Lens policy the video is captured under, in one place. ``config.load`` merges the
#: ``settings`` table *over* config.toml, so writing only the file is not enough: a stale
#: ``lens.allow_actions`` row left in the seeded database would silently win and put action
#: buttons on the phone card. Both are written from this dict, so they cannot disagree.
DEMO_LENS: Final[dict[str, Any]] = {
    "enabled": True,
    "require_https": True,
    "tag_learning": True,
    "allow_actions": False,
    "token_ttl_days": 90,
    "max_tokens": 12,
}


def _toml_value(value: Any) -> str:
    return "true" if value is True else "false" if value is False else str(value)


def apply_lens_settings(data_dir: Path) -> None:
    """Pin ``lens.*`` in the working copy's settings table to :data:`DEMO_LENS`.

    Also clears any outstanding pairing code the seed left behind: they are single-use and
    five minutes old, so the only thing a stale one can do is make ``/lens/pair`` render a
    QR that has already expired.
    """
    db_path = data_dir / "homesoc.db"
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    conn = sqlite3.connect(db_path, timeout=15)
    try:
        conn.execute("DELETE FROM settings WHERE key LIKE 'lens.pairing.%'")
        for key, value in DEMO_LENS.items():
            conn.execute(
                "INSERT OR REPLACE INTO settings(key, value, updated_at) VALUES (?, ?, ?)",
                (f"lens.{key}", _toml_value(value).lower(), now),
            )
        conn.commit()
    except sqlite3.Error as exc:
        raise CaptureError(f"could not set the demo Lens policy in {db_path}: {exc}") from exc
    finally:
        conn.close()

def apply_dns_settings(data_dir: Path) -> None:
    """Pin the working copy's resolver to 127.0.0.1:``DNS_PORT``.

    The seed saves ``dns.listen = 0.0.0.0`` and ``dns.port = 53`` in the settings table (what a
    household's Settings page would hold), and the settings table wins over any config file.
    Left alone, the capture's resolver would try to answer the author's whole LAN on port 53.
    Only the working copy is changed; ``video/demo_data`` is never written.
    """
    db_path = data_dir / "homesoc.db"
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    conn = sqlite3.connect(db_path, timeout=15)
    try:
        for key, value in (("dns.enabled", "true"), ("dns.listen", "127.0.0.1"),
                           ("dns.port", str(DNS_PORT))):
            conn.execute(
                "INSERT OR REPLACE INTO settings(key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, now),
            )
        # The harness's own plumbing: the seed saved web.port 8787 and a toast preference, the
        # capture serves on PORT with toasts off, and the dashboard logs a *warning* that
        # "Settings-page values are overriding config.toml" when the two disagree - which then
        # heads the "What happened" feed in every shot of it. Only rows that already exist are
        # brought into line; nothing a viewer is told about is changed.
        for key, value in (("web.port", str(PORT)), ("notify.windows_toast", "false")):
            conn.execute("UPDATE settings SET value = ?, updated_at = ? WHERE key = ?",
                         (value, now, key))
        conn.commit()
    except sqlite3.Error as exc:
        raise CaptureError(f"could not point the demo resolver at 127.0.0.1:{DNS_PORT}: {exc}") from exc
    finally:
        conn.close()


def sync_blocklist_mtimes(data_dir: Path) -> None:
    """Give every feed file the age the seeded ``feeds`` table says it has.

    The running resolver judges a blocklist's age by its file's modification time
    (NET-DNS-003 fires past three days). The files in ``video/demo_data/feeds`` carry whatever
    date they were downloaded on, which is not the fiction the database tells; the database is
    the authority, so the copy's files are dated to match it. If the seed itself is old, the
    resolver will say so - truthfully - and :func:`report_resolver_findings` prints it.
    """
    db_path = data_dir / "homesoc.db"
    feeds = data_dir / "feeds"
    if not feeds.is_dir():
        return
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        try:
            rows = conn.execute("SELECT name, last_updated FROM feeds").fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("could not read the feeds table to date the blocklists: %s", exc)
        return
    for name, stamp in rows:
        if not stamp:
            continue
        try:
            when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        for path in feeds.glob(f"{name}.*"):
            if path.suffix == ".sha256" or not path.is_file():
                continue
            with suppress(OSError):
                os.utime(path, (when, when))


def open_findings(data_dir: Path) -> dict[str, tuple[str, str]]:
    """``{dedupe_key: (finding_id, severity)}`` of every open finding in the working copy."""
    try:
        conn = sqlite3.connect(f"file:{data_dir / 'homesoc.db'}?mode=ro", uri=True, timeout=10)
        try:
            rows = conn.execute(
                "SELECT dedupe_key, finding_id, severity FROM findings WHERE status = 'open'"
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    return {str(k): (str(f), str(s)) for k, f, s in rows}


#: The wrapper the demo dashboard is started through. It patches nothing in the installed
#: product — it rebinds two lookups *in its own process* before the CLI runs, so the
#: certificate, the pairing URL and every "this machine" string in the dashboard describe
#: the fictional household instead of the author's PC. See the module docstring.
SERVE_LAUNCHER_PY: Final[str] = '''\
"""Generated by video/capture.py. Do not edit; do not ship. One capture's lifetime.

Starts the demo dashboard with a fictional machine identity so no frame of the video can
show the author's real hostname or LAN address (CONTRACT_V2 V5). The socket still binds
loopback only — the recorded bind address is the one the documented invocation
(`serve --tls --host 0.0.0.0 --port 8443`) produces, which is what /lens/pair is for.
"""
import sys

sys.path.insert(0, {project!r})

from homesoc import util

util.local_hostname = lambda: {hostname!r}
util.default_interface_ip = lambda: {lan_ip!r}

from homesoc import cli

_record = cli.record_bind_state
cli.record_bind_state = lambda conn, host, port: _record(conn, {lan_ip!r}, {lan_port!r})

# Web blocking, for real. `serve` is "dashboard only" and passes with_dns=False; the film needs
# the resolver running the way `homesoc run` runs it, so Runtime.start is asked for it here -
# the product's own Runtime.start_dns() binds the product's own DnsServer, on the loopback
# address and high port the demo config names. The scheduler stays manual-only (serve's
# choice), so nothing is ever scanned. If the resolver cannot bind, the capture stops: the
# film does not get to show "running" unless something is running.
_start = cli.Runtime.start


def _start_with_resolver(self, *, with_scheduler=True, with_dns=None, manual_only=False):
    _start(self, with_scheduler=with_scheduler, with_dns=True, manual_only=manual_only)
    server = self.dns_server
    if server is None or not getattr(server, "running", False):
        error = getattr(server, "last_error", None) or "see the log above"
        sys.stderr.write(f"capture: the web-blocking resolver did not start: {{error}}\\n")
        sys.stderr.flush()
        raise SystemExit(3)
    print(f"capture: web-blocking resolver running on {{server.listen}}:{{server.port}}", flush=True)


cli.Runtime.start = _start_with_resolver

sys.exit(cli.main(sys.argv[1:]))
'''


def write_serve_launcher() -> Path:
    SERVE_LAUNCHER.parent.mkdir(parents=True, exist_ok=True)
    SERVE_LAUNCHER.write_text(
        SERVE_LAUNCHER_PY.format(
            project=str(PROJECT_ROOT), hostname=DEMO_HOSTNAME,
            lan_ip=DEMO_LAN_IP, lan_port=DEMO_LAN_PORT,
        ),
        encoding="utf-8",
    )
    return SERVE_LAUNCHER


def mint_lens_token(data_dir: Path, *, label: str = LENS_TOKEN_LABEL) -> str:
    """Pair this capture's phone with the demo database and return the secret.

    ``lens_tokens`` stores only a SHA-256, so the plaintext exists exactly once, at mint
    time — the seed cannot hand one over. This is the same code path ``/api/lens/claim``
    runs; it just skips the pairing code, which no browser is here to scan.
    """
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    previous = os.environ.get("HOMESOC_DATA")
    os.environ["HOMESOC_DATA"] = str(data_dir)
    try:
        from homesoc import db  # imported late: the product is a read-only dependency here

        conn = db.connect()
        try:
            row = db.lens_mint_token(conn, label=label, scopes="read", ttl_days=90, max_tokens=64)
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - without a token /lens renders "not paired"
        raise CaptureError(
            f"could not mint a Lens token in {data_dir}: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        if previous is None:
            os.environ.pop("HOMESOC_DATA", None)
        else:
            os.environ["HOMESOC_DATA"] = previous
    token = str(row.get("token") or "")
    if not token:
        raise CaptureError("lens_mint_token returned no token")
    logger.info("paired a demo phone (%s) with the working copy", label)
    return token


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
    # Any certificate already in demo_data was minted against whatever machine made it, so
    # its subject and SANs carry that machine's real name. Drop it: the launcher's
    # fictional identity regenerates a clean one on the first --tls start.
    shutil.rmtree(dest / "tls", ignore_errors=True)
    apply_lens_settings(dest)
    apply_dns_settings(dest)
    sync_blocklist_mtimes(dest)
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
    tls: bool = True
    proc: subprocess.Popen[bytes] | None = None
    _log: Any = None

    def __enter__(self) -> Dashboard:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _write_config(self) -> Path:
        DEMO_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        lens = "\n".join(f"{key} = {_toml_value(value)}" for key, value in DEMO_LENS.items())
        DEMO_CONFIG.write_text(
            DEMO_CONFIG_TOML.format(port=self.port, lens=lens, dns_port=DNS_PORT), encoding="utf-8"
        )
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
            sys.executable, str(write_serve_launcher()),
            "--data", str(self.data_dir),
            "--config", str(config),
            "serve", "--host", "127.0.0.1", "--port", str(self.port),
        ]
        if self.tls:
            cmd.append("--tls")
        DASHBOARD_LOG.parent.mkdir(parents=True, exist_ok=True)
        self._log = DASHBOARD_LOG.open("wb")
        logger.info("starting dashboard: %s", " ".join(cmd))
        before = open_findings(self.data_dir)
        self.proc = subprocess.Popen(
            cmd, cwd=str(PROJECT_ROOT), env=env,
            stdout=self._log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        try:
            self._wait_ready()
            self._wait_resolver(before)
        except BaseException:
            self.stop()
            raise

    def _summary(self) -> dict[str, Any]:
        with urllib.request.urlopen(f"{BASE_URL}/api/summary", timeout=10, context=_TLS_CTX) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _wait_resolver(self, before: dict[str, tuple[str, str]]) -> None:
        """The dashboard must report the real resolver running, and its first health pass done.

        The resolver checks its own health on its first housekeeping tick (5 s after it binds)
        and files or resolves NET-DNS-00x findings from what it sees. That is part of what a
        running Home SOC shows, so it is allowed to happen - but *before* the first shot, never
        between two scenes, where it would change a number the voice has already spoken.
        """
        deadline = time.monotonic() + 20.0
        running = False
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise CaptureError(
                    f"the dashboard exited ({self.proc.returncode}) - the web-blocking resolver "
                    f"could not start on 127.0.0.1:{DNS_PORT}.\n{self._tail_log()}"
                )
            with suppress(Exception):
                running = bool((self._summary().get("dns") or {}).get("running"))
            if running:
                break
            time.sleep(0.5)
        if not running:
            raise CaptureError(
                "the dashboard does not report web blocking as running, so the film would say "
                f"'switched on but not running'. Its log:\n{self._tail_log()}"
            )
        try:
            if str(PROJECT_ROOT) not in sys.path:
                sys.path.insert(0, str(PROJECT_ROOT))
            from homesoc.dnsfilter import server as dns_server_mod  # noqa: PLC0415

            tick = float(getattr(dns_server_mod, "HOUSEKEEPING_TICK", 5.0))
        except Exception:  # noqa: BLE001 - the product is read, never required to import here
            tick = 5.0
        time.sleep(tick + 2.0)
        after = open_findings(self.data_dir)
        opened = sorted(set(after) - set(before))
        closed = sorted(set(before) - set(after))
        print(f"  web blocking: running on 127.0.0.1:{DNS_PORT} (the product's own resolver)",
              flush=True)
        for key in opened:
            print(f"  NOTE the running resolver opened {after[key][0]} ({after[key][1]}) {key} - "
                  "counts on screen include it", flush=True)
        for key in closed:
            print(f"  NOTE the running resolver resolved {before[key][0]} {key} - counts on "
                  "screen no longer include it", flush=True)

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
                with urllib.request.urlopen(f"{BASE_URL}/", timeout=3, context=_TLS_CTX) as resp:
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


# --------------------------------------------------------------------------- the scan rig


@dataclass(frozen=True)
class DemoCamera:
    """The device the Lens act is about, and the sticker token stuck to it."""

    device_id: int
    ip: str
    name: str
    code: str


def demo_camera(data_dir: Path) -> DemoCamera:
    """Find the camera and its sticker token in the working copy, rather than hard-coding.

    ``seed_demo.py`` mints the sticker tokens, ``scene_render.py`` draws one of them into
    the scene, and this is the one place that has to agree with both. The camera is
    identified the way the script identifies it — the device at ``CAMERA_IP`` — falling
    back to "whatever has Telnet open", which is the only device in the seed that does.
    """
    wanted_ip = ""
    with suppress(Exception):
        wanted_ip = str(getattr(_import(SCRIPT_MODULE), "CAMERA_IP", "") or "")

    db_path = data_dir / "homesoc.db"
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    except sqlite3.Error as exc:
        raise CaptureError(f"cannot read {db_path}: {exc}") from exc
    conn.row_factory = sqlite3.Row
    try:
        row = None
        if wanted_ip:
            row = conn.execute("SELECT * FROM devices WHERE ip = ?", (wanted_ip,)).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT d.* FROM devices d JOIN services s ON s.device_id = d.id "
                "WHERE s.port = 23 ORDER BY d.id LIMIT 1"
            ).fetchone()
        if row is None:
            raise CaptureError(
                "no camera to point Lens at: the seeded database has no device at "
                f"{wanted_ip or '(script.CAMERA_IP unset)'} and none with Telnet open."
            )
        tag = conn.execute(
            "SELECT code FROM lens_tags WHERE device_id = ? AND kind = 'sticker' "
            "ORDER BY id LIMIT 1", (row["id"],),
        ).fetchone()
    finally:
        conn.close()
    if tag is None:
        raise CaptureError(
            f"device {row['id']} ({row['ip']}) has no sticker tag in lens_tags. "
            "video/seed_demo.py must mint one (CONTRACT_V2 V4) before the Lens act can be "
            "captured — the scene render encodes exactly that token."
        )
    name = str(row["nickname"] or row["hostname"] or row["ip"] or "")
    return DemoCamera(int(row["id"]), str(row["ip"] or ""), name, str(tag["code"]))


def _free_port(preferred: int) -> int:
    with closing(socket.socket()) as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def qr_png(payload: str, *, module_px: int = 8, quiet: int = 4) -> bytes:
    """A PNG of ``payload`` as a QR code, drawn with the product's own encoder.

    Used only to prove the decode sidecar works before scene 18 depends on it: if this
    round-trips, the sidecar really is reading pixels.
    """
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from io import BytesIO

    from PIL import Image

    from homesoc.web import qr as qrmod

    matrix = [list(row) for row in qrmod.to_matrix(payload)]
    size = len(matrix)
    side = (size + quiet * 2) * module_px
    img = Image.new("L", (side, side), 255)
    pixels = img.load()
    for y, row in enumerate(matrix):
        for x, cell in enumerate(row):
            if not cell:
                continue
            for dy in range(module_px):
                for dx in range(module_px):
                    pixels[(x + quiet) * module_px + dx, (y + quiet) * module_px + dy] = 0
    buffer = BytesIO()
    img.convert("RGB").save(buffer, format="PNG")
    return buffer.getvalue()


#: Where a loopback decoder might listen. The sidecar is another package's file, so its
#: exact route is discovered rather than assumed — and then proved with a known QR.
_SIDECAR_ROUTES: Final[tuple[str, ...]] = ("/decode", "/", "/api/decode", "/decode.json", "/barcode")


@dataclass
class DecodeSidecar:
    """``video/decode_sidecar.py``: a loopback zxing-cpp decoder, owned and always stopped.

    zxing-cpp is a capture-time tool. It is imported by the sidecar, never by the product,
    and must not appear in ``requirements.txt`` or ``pyproject.toml`` (CONTRACT_V2 V3.3).
    """

    script: Path = SIDECAR_SCRIPT
    port: int = SIDECAR_PORT
    proc: subprocess.Popen[bytes] | None = None
    route: str = ""
    _log: Any = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}{self.route}"

    def __enter__(self) -> DecodeSidecar:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(self) -> None:
        # Absolute, because the sidecar is started with cwd=video/: a relative path would be
        # resolved against that and land on video/video/decode_sidecar.py.
        self.script = Path(self.script).expanduser().resolve()
        if not self.script.is_file():
            raise CaptureError(
                f"{self.script} does not exist. Scene 18 decodes the scene's real pixels with "
                "zxing-cpp in a loopback sidecar (CONTRACT_V2 V3.3); without it there is no "
                "honest way to produce the scan, and faking it is not an option."
            )
        self.port = _free_port(self.port)
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        SIDECAR_LOG.parent.mkdir(parents=True, exist_ok=True)
        self._log = SIDECAR_LOG.open("wb")
        attempts = (
            [sys.executable, str(self.script), "--host", "127.0.0.1", "--port", str(self.port)],
            [sys.executable, str(self.script), "--port", str(self.port)],
            [sys.executable, str(self.script), str(self.port)],
        )
        errors: list[str] = []
        for cmd in attempts:
            logger.info("starting decode sidecar: %s", " ".join(cmd))
            self.proc = subprocess.Popen(
                cmd, cwd=str(HERE), env=env,
                stdout=self._log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            )
            try:
                self._discover()
                return
            except CaptureError as exc:
                errors.append(f"{' '.join(cmd[1:])}: {exc}")
                self._kill()
        raise CaptureError(
            "the decode sidecar never answered with a usable decode.\n  "
            + "\n  ".join(errors)
            + f"\nIts output is in {SIDECAR_LOG}:\n{self._tail()}"
        )

    def _discover(self) -> None:
        """Find the route that decodes a known QR. Readiness and protocol in one check."""
        probe = "hs1:" + "capture-selftest-0001"
        payload = _data_url(qr_png(probe))
        deadline = time.monotonic() + 25.0
        last = "no response"
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise CaptureError(f"it exited with code {self.proc.returncode}")
            for route in _SIDECAR_ROUTES:
                self.route = route
                try:
                    values = [h.get("rawValue") for h in self._post(payload)]
                except Exception as exc:  # noqa: BLE001 - wrong route, not yet up, wrong shape
                    last = f"{route}: {type(exc).__name__}: {exc}"
                    continue
                if probe in values:
                    logger.info("decode sidecar ready on %s (self-test decoded %r)", self.url, probe)
                    return
                last = f"{route}: decoded {values!r}, expected {probe!r}"
            time.sleep(0.4)
        raise CaptureError(last)

    def _post(self, data_url: str) -> list[dict[str, Any]]:
        # Several key spellings in one body, because the sidecar is another package's file
        # and this must work against whichever one it reads.
        body = json.dumps({
            "image": data_url, "data_url": data_url, "dataUrl": data_url,
            "png": data_url, "frame": data_url,
        }).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{self.route}", data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
        return _normalise_decode(json.loads(raw.decode("utf-8")))

    def decode(self, data_url: str) -> dict[str, Any]:
        """The callback the ``BarcodeDetector`` shim reaches through a Playwright binding."""
        try:
            return {"results": self._post(data_url)}
        except Exception as exc:  # noqa: BLE001 - reported through the shim's error bus
            logger.warning("sidecar decode failed: %s: %s", type(exc).__name__, exc)
            return {"results": [], "error": f"{type(exc).__name__}: {exc}"}

    def _tail(self, lines: int = 20) -> str:
        with suppress(OSError):
            if self._log is not None:
                self._log.flush()
            text = SIDECAR_LOG.read_text(encoding="utf-8", errors="replace")
            return "\n".join(text.splitlines()[-lines:])
        return "(no log)"

    def _kill(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            with suppress(OSError):
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with suppress(OSError):
                    proc.kill()

    def stop(self) -> None:
        self._kill()
        if self._log is not None:
            with suppress(OSError):
                self._log.close()
            self._log = None


def _data_url(png: bytes) -> str:
    import base64

    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def _normalise_decode(payload: Any) -> list[dict[str, Any]]:
    """Whatever the sidecar answers -> ``[{rawValue, format, boundingBox}, ...]``."""
    if isinstance(payload, dict):
        for key in ("results", "barcodes", "codes", "decodes", "hits"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            single = payload.get("rawValue") or payload.get("raw_value") or payload.get("text")
            payload = [payload] if single else []
    if not isinstance(payload, list):
        return []
    out: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, str):
            value, box, fmt = item, {}, "qr_code"
        elif isinstance(item, dict):
            value = str(
                item.get("rawValue") or item.get("raw_value") or item.get("text")
                or item.get("value") or ""
            )
            raw_box = item.get("boundingBox") or item.get("bounding_box") or item.get("box") or {}
            box = raw_box if isinstance(raw_box, dict) else {}
            fmt = re.sub(r"[\s-]+", "_", str(item.get("format") or item.get("type") or "qr_code").lower())
        else:
            continue
        if not value:
            continue
        out.append({
            "rawValue": value,
            "format": fmt or "qr_code",
            "boundingBox": {
                "x": float(box.get("x", 0) or 0), "y": float(box.get("y", 0) or 0),
                "width": float(box.get("width", box.get("w", 0)) or 0),
                "height": float(box.get("height", box.get("h", 0)) or 0),
            },
        })
    return out


@dataclass(frozen=True)
class SceneAssets:
    """What ``video/scene_render.py`` produced: the still, and the drifting camera clip."""

    y4m: Path | None
    png: Path | None

    @property
    def usable(self) -> bool:
        return bool(self.y4m and self.y4m.is_file())


#: Module attributes ``scene_render.py`` might expose. Tried in order; the first that
#: yields an existing .y4m wins. It is another package's file, so this asks rather than
#: assumes — and says exactly what it looked for when it finds nothing.
_SCENE_BUILDERS: Final[tuple[str, ...]] = ("ensure_assets", "ensure", "build", "render", "main")
_SCENE_Y4M_ATTRS: Final[tuple[str, ...]] = ("Y4M_PATH", "SCENE_Y4M", "CLIP_PATH", "Y4M", "CLIP")
_SCENE_PNG_ATTRS: Final[tuple[str, ...]] = ("PNG_PATH", "SCENE_PNG", "STILL_PATH", "PNG", "STILL")


def scene_assets(*, y4m: Path | None = None, png: Path | None = None) -> SceneAssets:
    """The fake-camera clip and the illustrated still, built if they are not there yet."""
    if y4m is not None or png is not None:
        return SceneAssets(y4m if y4m and y4m.is_file() else None,
                           png if png and png.is_file() else None)

    found_y4m: Path | None = None
    found_png: Path | None = None
    if SCENE_RENDER_SCRIPT.is_file():
        module: Any = None
        with suppress(Exception):
            import scene_render  # type: ignore[import-not-found]

            module = scene_render
        if module is not None:
            result: Any = None
            for name in _SCENE_BUILDERS:
                fn = getattr(module, name, None)
                if callable(fn):
                    with suppress(Exception):
                        result = fn()
                        break
            if isinstance(result, dict):
                found_y4m = _as_path(result.get("y4m") or result.get("clip"))
                found_png = _as_path(result.get("png") or result.get("still"))
            elif isinstance(result, (str, Path)) and str(result).endswith(".y4m"):
                found_y4m = _as_path(result)
            found_y4m = found_y4m or _first_attr(module, _SCENE_Y4M_ATTRS)
            found_png = found_png or _first_attr(module, _SCENE_PNG_ATTRS)
        else:
            with suppress(Exception):
                subprocess.run([sys.executable, str(SCENE_RENDER_SCRIPT)], cwd=str(HERE),
                               check=False, timeout=180)

    if found_y4m is None:
        # scene_render.py writes into video/build/ whichever film is being captured
        found_y4m = next(iter(sorted(BUILD_ROOT.glob("*.y4m"))), None) or next(
            iter(sorted(BUILD.rglob("*.y4m"))), None)
    if found_png is None:
        found_png = next(iter(sorted(BUILD_ROOT.glob("scene*.png"))), None) or next(
            iter(sorted(BUILD.rglob("scene*.png"))), None)
    return SceneAssets(found_y4m if found_y4m and found_y4m.is_file() else None,
                       found_png if found_png and found_png.is_file() else None)


def resolve_scene_png(name: str, assets: SceneAssets) -> Path | None:
    """Turn a ``PhonePair``'s ``scene_png`` *name* into the file on disk.

    ``script.py`` names the illustration ("shelf", one of ``SCENE_RENDERS``);
    ``scene_render.py`` decides what to call the file. ``compose.py`` needs the path, so
    the translation happens here — the one place that has both.
    """
    name = str(name or "").strip()
    if name:
        direct = _as_path(name)
        if direct is not None:
            return direct
        module: Any = None
        with suppress(Exception):
            import scene_render  # type: ignore[import-not-found]

            module = scene_render
        if module is not None:
            for attr in ("scene_png_for", "png_for", "still_for"):
                fn = getattr(module, attr, None)
                if callable(fn):
                    with suppress(Exception):
                        found = _as_path(fn(name))
                        if found is not None:
                            return found
            registry = getattr(module, "SCENE_RENDERS", None) or getattr(module, "RENDERS", None)
            if isinstance(registry, dict) and name in registry:
                found = _as_path(registry[name])
                if found is not None:
                    return found
        for candidate in (f"scene_{name}.png", f"{name}.png", f"scene_camera_{name}.png"):
            for root in (BUILD, BUILD_ROOT):
                found = _as_path(root / candidate)
                if found is not None:
                    return found
    # One illustration, many names for it: with a single render, the name is decoration.
    return assets.png


def _as_path(value: Any) -> Path | None:
    if not value:
        return None
    path = Path(str(value))
    if not path.is_absolute():
        path = (HERE / path).resolve()
    return path if path.is_file() else None


def _first_attr(module: Any, names: tuple[str, ...]) -> Path | None:
    for name in names:
        path = _as_path(getattr(module, name, None))
        if path is not None:
            return path
    return None


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
            self.page.evaluate(WHOLE_ROWS_JS)
        self.redact()
        self.page.wait_for_timeout(SETTLE_MS)

    def redact(self) -> int:
        """Blur the film's ``REDACTIONS`` on this page (SCRIPT.md capture checklist 2 and 5).

        The film's script module may define ``redaction_js(path)``; its script blurs the
        router's make and model and real brand domains in place, text only, layout untouched.
        It is idempotent, so a second pass that still finds something to blur means the
        first pass missed a match - that fails the capture rather than film it legibly.
        """
        path = self.current_path
        if not path or not REDACT:
            return 0
        try:
            module = _import(SCRIPT_MODULE)
        except ImportError:
            return 0
        make_js = getattr(module, "redaction_js", None)
        if make_js is None:
            return 0
        js = make_js(path)
        if not js:
            return 0
        count = int(self.page.evaluate(js) or 0)
        again = int(self.page.evaluate(js) or 0)
        if again:
            raise CaptureError(
                f"redaction on {path!r} left {again} match(es) legible after its first pass"
            )
        if count:
            logger.info("redacted %d string(s) on %s", count, path)
            print(f"    redacted {count} string(s) on {path}", flush=True)
        return count

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
        self._record_fingerprint(dest)
        return dest

    def _record_fingerprint(self, dest: Path) -> None:
        """Beside a shot of /lens/pair, the Security fingerprint exactly as that page shows it.

        The compositor draws the tablet's side of "check the long code matches" from this file,
        so the code on the drawn tablet is the code in the frame - never typed, never recomputed
        from a certificate a later capture may have regenerated.
        """
        side = dest.with_suffix(".fingerprint.txt")
        side.unlink(missing_ok=True)
        if not (self.current_path or "").startswith("/lens/pair"):
            return
        text = ""
        with suppress(Exception):
            text = str(self.page.evaluate(
                "() => { const f = document.querySelector('.fingerprint');"
                " return f ? f.innerText : ''; }") or "")
        text = " ".join(text.split())
        if text:
            side.write_text(text + "\n", encoding="utf-8")

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


# --------------------------------------------------------------------------- web blocking, on screen

#: What the three places that report web blocking must say before a single shot is taken.
_BLOCKING_STATE_JS: Final[str] = """
() => {
  const text = (document.body && document.body.innerText) || '';
  const chip = document.getElementById('chip-dns');
  const side = document.getElementById('chip-dns-state');
  const theme = getComputedStyle(document.documentElement).colorScheme || '';
  return {
    notRunning: /not running/i.test(text),
    chip: chip ? { off: chip.classList.contains('is-off'), text: chip.innerText.trim() } : null,
    side: side ? side.textContent.trim() : null,
    bodyBg: getComputedStyle(document.body).backgroundColor,
    theme: theme,
    dataTheme: document.documentElement.getAttribute('data-theme') || '',
  };
}
"""


def verify_blocking_running(cap: Capturer) -> None:
    """Refuse to capture unless Home, the Blocking chip and the Blocking page say "running".

    This reads the pages exactly as the film will photograph them - nothing is injected - and
    leaves ``verify_blocking_home.png`` / ``verify_blocking_dns.png`` in the build directory
    to look at.
    """
    problems: list[str] = []
    for path, name in (("/", "home"), ("/dns", "dns")):
        cap.goto(path)
        try:
            cap.page.wait_for_function(
                "() => { const s = document.getElementById('chip-dns-state');"
                " return !s || s.textContent.trim() === 'running'; }",
                timeout=CHART_TIMEOUT_MS,
            )
        except Exception:  # noqa: BLE001 - reported below with what the page actually says
            pass
        state = cap.page.evaluate(_BLOCKING_STATE_JS)
        cap.shoot(BUILD / f"verify_blocking_{name}.png")
        if state.get("notRunning"):
            problems.append(f"{path} says 'not running' somewhere on the page")
        chip = state.get("chip")
        if chip is None or chip.get("off"):
            problems.append(f"{path}: the topbar Blocking chip is {chip!r}")
        if state.get("side") not in (None, "running"):
            problems.append(f"{path}: the sidebar says 'Blocking: {state.get('side')}'")
        if path == "/dns":
            badge = cap.page.locator(".kpi .badge").first
            label = badge.inner_text().strip() if badge.count() else ""
            if label.lower() != "running":
                problems.append(f"/dns: the Blocking page's status badge reads {label!r}")
        print(f"  on screen {path:<5} chip={chip} sidebar={state.get('side')!r} "
              f"theme={state.get('theme') or '?'} body={state.get('bodyBg')}", flush=True)
    if problems:
        raise CaptureError(
            "web blocking does not read as running on screen:\n  " + "\n  ".join(problems)
            + f"\nLook at {BUILD / 'verify_blocking_home.png'} and verify_blocking_dns.png."
        )


# --------------------------------------------------------------------------- slides


def load_slides() -> dict[str, Any]:
    """``{name: callable_or_html}`` from the film's slide module.

    ``video/slides.py`` for the technical cut, ``video/slides_everyday.py`` for the everyday
    film. Both expose ``SLIDES``, so both go through exactly the same path: the HTML is set as
    the page content of the capture browser and screenshotted at 1600x900 @2x.
    """
    try:
        slides = _import(SLIDES_MODULE)
    except ImportError as exc:
        raise CaptureError(
            f"cannot import {SLIDES_MODULE}.py - slide HTML must exist before capture ({exc})"
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
        f"{SLIDES_MODULE}.py exposes neither a SLIDES dict nor any slide_* functions"
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
            f"{scene_id}: {SLIDES_MODULE}.py has no slide named {name!r}. "
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
        script = _import(SCRIPT_MODULE)
    except ImportError as exc:
        raise CaptureError(
            f"cannot import {SCRIPT_MODULE}.py - the scene script must exist before capture ({exc})"
        ) from exc
    scenes = getattr(script, "SCENES", None)
    if not scenes:
        raise CaptureError(f"{SCRIPT_MODULE}.py defines no non-empty SCENES list")
    return list(scenes)


@dataclass(frozen=True)
class Target:
    """What is on screen for one state.

    ``kind`` is ``"slide"`` (a slide name in ``ref``), ``"page"`` (a dashboard path at a
    scroll offset), ``"phone"`` (``/lens`` showing ``state``) or ``"phone_pair"`` (the same
    phone beside the illustrated still named by ``scene``).
    """

    kind: str
    ref: str  # slide name, or url path
    scroll: int = 0
    state: str = ""     # phone screen: scan | card | picker | unknown
    scene: str = ""     # phone_pair: the illustrated still from scene_render.py

    @property
    def is_phone(self) -> bool:
        return self.kind in ("phone", "phone_pair")


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
    if is_phone_pair(shot):
        inner = _attr(shot, "phone", "phone_shot")
        state = (
            phone_state(inner, scene_id) if inner is not None
            else str(_attr(shot, "phone_state", "state", default="scan") or "scan").lower()
        )
        return Target(
            "phone_pair",
            phone_path(inner if inner is not None else shot),
            int(_attr(shot, "scroll", default=0) or 0),
            state,
            pair_scene_png(shot),
        )
    if is_phone(shot):
        return Target("phone", phone_path(shot), page_scroll(shot), phone_state(shot, scene_id))
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
        if kind in ("Click", "Tap"):
            # A Tap with a `then_shot` is the phone's Click: a real press that changes the
            # screen (scene 19 opens the card's Vulnerabilities section with one).
            then_shot = _attr(action, "then_shot", "then", "after")
            if then_shot is None:
                continue
            declared.append((action_at(action), then_shot, kind.lower()))
        elif kind in ("Scroll", "PhoneScroll"):
            to_y = int(_attr(action, "to_y", "y", "scroll", default=0) or 0)
            declared.append((action_at(action), _ScrollTo(to_y),
                             "scroll" if kind == "Scroll" else "phone-scroll"))

    declared.sort(key=lambda entry: entry[0])

    first = _target_of(members[0], scene_id, current_path=None)
    plan = [Planned(0.0, first, "shot")]
    current = first
    for frac, payload, produced_by in declared:
        if isinstance(payload, _ScrollTo):
            if current.kind == "slide":
                raise CaptureError(
                    f"{scene_id}: Scroll at {frac:.2f} has no page on screen to scroll "
                    f"(the shot at that point is the slide {current.ref!r})"
                )
            target = Target(current.kind, current.ref, payload.to_y, current.state, current.scene)
        else:
            target = _target_of(payload, scene_id, current_path=current.ref)
        previous = plan[-1]
        if target == previous.target and frac - previous.at <= MERGE_WINDOW:
            previous.produced_by = f"{previous.produced_by}+{produced_by}"
            if produced_by in ("click", "tap"):
                # Not two declarations of one state: a press changes the screen. Both
                # planners (here and compose.plan_transitions) still merge them, so the
                # scene gets one image — and it is the *after* image, because `then_shot`
                # says explicitly what has to be on screen. The press is therefore visible
                # before the finger arrives, which is a script timing bug, not a capture one.
                logger.warning(
                    "%s: the %s at %.3f produces a state indistinguishable from the one at "
                    "%.3f, so they merge into a single shot and the change appears early. "
                    "Move its `at` more than %.2f after that state (or the state earlier).",
                    scene_id, produced_by, frac, previous.at, MERGE_WINDOW,
                )
            continue
        plan.append(Planned(frac, target, produced_by))
        current = target
    return plan


@dataclass
class PhoneRig:
    """Everything a phone shot needs: a paired token, a camera to point at, a decoder."""

    token: str
    camera: DemoCamera
    data_dir: Path
    assets: SceneAssets
    sidecar: DecodeSidecar | None = None
    clock: datetime | None = None
    #: The driver ``capture()`` is already inside — the sync API cannot be nested, so the
    #: phone's own Chrome (it needs different launch flags) is started from this one.
    playwright: Any = None
    headed: bool = False

    @property
    def decoding(self) -> bool:
        return self.sidecar is not None

    def launch_args(self) -> list[str]:
        """Chrome's fake camera, pointed at the clip ``scene_render.py`` drew."""
        if self.assets.usable:
            return [f"--use-file-for-fake-video-capture={self.assets.y4m}"]
        return []

    def decode(self) -> Callable[[str], Any] | None:
        return self.sidecar.decode if self.sidecar is not None else None


def scene_wants_scan(scene: Any, plan: list[Planned]) -> bool:
    """Does this scene's narration call the identification a scan?

    Three ways to say so, any of which arms the rig and makes a failed decode fatal: the
    scene is one of :data:`SCAN_SCENES`, it uses a ``PhonePair`` (which exists only for
    scene 18), or one of its phone shots asks for ``via="scan"`` explicitly.
    """
    scene_id = str(getattr(scene, "id", "") or "")
    if scene_id in SCAN_SCENES:
        return True
    if any(p.target.kind == "phone_pair" for p in plan):
        return True
    for shot in _all_shots(scene):
        if (is_phone(shot) or is_phone_pair(shot)) and str(_attr(shot, "via", default="")) == "scan":
            return True
    return False


def _forget_tag(db_path: Path, code: str) -> Callable[[], None]:
    """Temporarily un-learn a sticker, and hand back the undo.

    This is how the "new code — which device is this?" sheet is produced honestly: the
    phone decodes the *same real sticker* off the *same real pixels*, but Home SOC has not
    been told about it yet, so ``/api/lens/identify`` genuinely answers "unknown" with a
    genuinely ranked picker. It is the first scan of a new sticker, which is exactly what
    the screen is for.
    """
    conn = sqlite3.connect(db_path, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM lens_tags WHERE code = ?", (code,)).fetchone()
        if row is None:
            conn.close()
            return lambda: None
        saved = dict(row)
        conn.execute("DELETE FROM lens_tags WHERE code = ?", (code,))
        conn.commit()
    finally:
        conn.close()

    def restore() -> None:
        back = sqlite3.connect(db_path, timeout=15)
        try:
            columns = ", ".join(saved)
            marks = ", ".join("?" for _ in saved)
            back.execute(
                f"INSERT OR REPLACE INTO lens_tags({columns}) VALUES ({marks})",
                tuple(saved.values()),
            )
            back.commit()
        finally:
            back.close()

    return restore


def _phone_shots(scene: Any, plan: list[Planned], rig: PhoneRig) -> list[dict[str, Any]]:
    """Turn the phone states of one scene into :func:`phone.capture_phone` shot dicts.

    Selectors are assigned to the state that is on screen when their action fires — the
    same rule the desktop path uses, and the reason a ``Tap`` on the card's Problems
    section is measured on the card rather than on the viewfinder behind it.
    """
    scene_id = str(getattr(scene, "id", "") or "scene")
    wants_scan = scene_wants_scan(scene, plan)
    members = sequence_items(scene.shot) if is_sequence(scene.shot) else [scene.shot]

    shots: list[dict[str, Any]] = []
    member_at = 0
    for index, planned in enumerate(plan):
        # Walk the PageSequence in step with the plan: a member takes over when the plan
        # says "sequence"; a scroll or a click stays on the member already on screen.
        if index and "sequence" in planned.produced_by:
            member_at = min(member_at + 1, len(members) - 1)
        target = planned.target
        if not target.is_phone:
            continue
        # The script's own shot object, when it is the one this state came from, so per-shot
        # overrides (via=, code=, device=, mode=, hold=) work without script.py needing them.
        declared = members[member_at] if member_at < len(members) else None
        if declared is None or not (is_phone(declared) or is_phone_pair(declared)):
            declared = None
        elif _target_of(declared, scene_id, current_path=None).state != target.state:
            declared = None

        state = target.state
        if state in ("card", "unknown"):
            via = str(_attr(declared, "via", default="") or "").lower()
            if not via:
                via = "scan" if (wants_scan and rig.decoding) else "pick"
            if state == "unknown":
                via = "scan"   # the sheet only exists after a decode; there is no other way
        else:
            via = ""           # scan and picker are reached by tapping, not by identifying

        shot: dict[str, Any] = {
            "id": f"{scene_id}_{index}",
            "path": target.ref,
            "state": state,
            "scroll": target.scroll,
            "via": via,
            "mode": str(_attr(declared, "mode", default="pick") or "pick"),
            "hold": bool(_attr(declared, "hold", default=True)),
            "device": str(_attr(declared, "device", default=rig.camera.ip) or rig.camera.ip),
            "selectors": [],
            "taps": [],
        }
        # Where in the illustration the phone is pointed, if the script says. compose.py
        # draws the view cone from it; it is carried through untouched.
        aim = _attr(declared, "aim")
        if isinstance(aim, (tuple, list)) and len(aim) == 2:
            shot["aim"] = [float(aim[0]), float(aim[1])]
        # A burst state: several screenshots of the same screen, so the viewfinder's
        # handheld drift survives into the film instead of being frozen by one PNG.
        burst = int(_attr(declared, "burst", default=0) or 0)
        if burst > 1:
            shot["burst"] = {
                "frames": burst,
                "interval_ms": int(_attr(declared, "burst_ms", default=66) or 66),
            }
        # The moment of recognition: a `scan` screen photographed while its own lookup is in
        # flight, so the green reticle the narration names is actually on screen.
        if bool(_attr(declared, "hit", default=False)):
            shot["hit"] = True
            shot["hit_ms"] = int(_attr(declared, "hit_ms", default=2600) or 2600)
            shot["hold"] = False
        if via == "scan" or shot.get("hit"):
            shot["code"] = str(_attr(declared, "code", default=rig.camera.code) or rig.camera.code)
        if state == "unknown":
            # Forget the sticker for the length of this one screenshot, then put it back.
            holder: dict[str, Callable[[], None]] = {}
            code = shot["code"]
            db_path = rig.data_dir / "homesoc.db"
            shot["before"] = lambda holder=holder, code=code, db_path=db_path: holder.__setitem__(
                "undo", _forget_tag(db_path, code)
            )
            shot["after"] = lambda holder=holder: holder.pop("undo", lambda: None)()
            shot["note"] = "the sticker is un-learned for this shot, so the decode is a first sight"
        shots.append(shot)

    by_index = {int(str(s["id"]).rsplit("_", 1)[1]): s for s in shots}

    # A Tap with a `then_shot` is performed for real, on the shot its press produces: either
    # the state the plan gave it, or — when the two were close enough to merge — the state
    # it was merged into. Pressing before that screenshot is what makes the after-state real
    # (scene 19's Vulnerabilities section is a <details> the finger opens).
    for action in sorted(getattr(scene, "actions", None) or [], key=action_at):
        if _kind_of(action) != "Tap" or _attr(action, "then_shot", "then", "after") is None:
            continue
        target = action_selector(action)
        if not target:
            continue
        produced = _state_index_at(plan, action_at(action), prefer="tap")
        shot = by_index.get(produced)
        if shot is not None and str(target) not in shot["taps"]:
            shot["taps"].append(str(target))

    # Every action's target belongs to the newest state at or before it, so a selector that
    # only exists once a press has opened something is measured on the opened screen.
    for action in sorted(getattr(scene, "actions", None) or [], key=action_at):
        selector = action_selector(action)
        if not selector:
            continue
        shot = by_index.get(_state_index_at(plan, action_at(action)))
        if shot is not None and str(selector) not in shot["selectors"]:
            shot["selectors"].append(str(selector))
    return shots


def _state_index_at(plan: list[Planned], at: float, *, prefer: str = "") -> int | None:
    """Which planned state is on screen at ``at``.

    ``prefer`` names a producer ("tap") whose own state should win when it sits within a
    hair of ``at`` — a press's ``then_shot`` is declared at the press's own moment, and
    floating point should not decide whether it lands on its own state or the previous one.
    """
    current: int | None = None
    for index, planned in enumerate(plan):
        if planned.at > at + 1e-9:
            break
        if prefer and prefer in planned.produced_by and abs(planned.at - at) < 1e-9:
            return index
        current = index
    return current


def _capture_phone_scene(scene: Any, plan: list[Planned], rig: PhoneRig,
                         result: SceneResult) -> dict[int, dict[str, Any]]:
    """Capture every phone state of one scene in a single mobile session."""
    scene_id = str(getattr(scene, "id", "") or "scene")
    phone = _phone()
    shots = _phone_shots(scene, plan, rig)
    if not shots:
        return {}
    wants_scan = scene_wants_scan(scene, plan)
    if wants_scan and not rig.decoding:
        raise CaptureError(
            f"{scene_id} narrates a scan, but the decode rig is not running. "
            "Start video/decode_sidecar.py and render the scene clip with "
            "video/scene_render.py — capture.py will not quietly fall back to the manual "
            "picker and let the voice call it a scan."
        )
    if wants_scan and not rig.assets.usable:
        raise CaptureError(
            f"{scene_id} narrates a scan, but there is no camera clip to scan. "
            "video/scene_render.py must produce the .y4m that Chrome plays back through "
            "--use-file-for-fake-video-capture (CONTRACT_V2 V3.2)."
        )

    try:
        out = _run_phone(phone, shots, rig)
    except phone.PhoneError as exc:
        # One exception type leaves this module, so render.py's caller sees one failure mode.
        raise CaptureError(f"{scene_id}: {exc}") from exc

    by_index = {i: p for i, p in enumerate(plan)}
    captured: dict[int, dict[str, Any]] = {}
    for shot, screen in zip(shots, out["shots"]):
        index = int(str(shot["id"]).rsplit("_", 1)[1])
        screen = dict(screen)
        screen["via"] = shot["via"]
        screen["expected_code"] = shot.get("code")
        screen["clip"] = rig.assets.y4m.as_posix() if rig.assets.usable else None
        if shot.get("taps"):
            screen["taps"] = list(shot["taps"])
        target = by_index[index].target
        if target.kind == "phone_pair":
            still = resolve_scene_png(target.scene, rig.assets)
            if still is None:
                raise CaptureError(
                    f"{scene_id}: state {index} is a PhonePair naming the illustration "
                    f"{target.scene!r}, but scene_render.py produced no still to go beside "
                    "the phone. Run `python video/scene_render.py` and try again."
                )
            screen["scene_png"] = still.as_posix()
        if shot.get("aim") is not None:
            screen["aim"] = shot["aim"]
        captured[index] = screen
    for _shot_id, geometry in (out.get("geometry") or {}).items():
        result.geometry.update(geometry)

    if wants_scan:
        decoded = [s.get("decoded") for s in out["shots"] if s.get("decoded")]
        if rig.camera.code not in decoded:
            raise CaptureError(
                f"{scene_id}: the BarcodeDetector shim never returned the camera's sticker "
                f"token. Expected {rig.camera.code!r}, got {decoded!r}. The scan in this "
                "scene has to be a real decode of the scene's real pixels — check that "
                "video/scene_render.py encoded this token and that the sticker is inside "
                "the frame for long enough."
            )
        print(f"  [{scene_id}] scan rig decoded {rig.camera.code} from the camera feed", flush=True)
    return captured


def _run_phone(phone: Any, shots: list[dict[str, Any]], rig: PhoneRig) -> dict[str, Any]:
    return phone.capture_phone(
        shots[0].get("path") or "/lens",
        token=rig.token,
        shots=shots,
        out_dir=PHONE_DIR,
        base_url=BASE_URL,
        playwright=rig.playwright,
        headless=not rig.headed,
        launch_args=rig.launch_args(),
        decode=rig.decode(),
        clock=rig.clock,
    )


def capture_scene(cap: Capturer, scene: Any, registry: dict[str, Any],
                  rig: PhoneRig | None = None) -> SceneResult:
    """Capture every state a scene passes through and resolve every selector it names.

    States and actions are walked together in ``at`` order, so a selector that only exists
    after a click (``findings.html``'s ``tr.detail-row`` is ``hidden`` until its row is
    clicked) is measured on the state that is actually on screen when the cursor gets there.
    """
    scene_id = str(getattr(scene, "id", "") or "scene")
    result = SceneResult(scene_id=scene_id)
    plan = plan_states(scene)

    # The phone states of a scene are captured together, in one mobile session, before the
    # desktop walk: a card only exists after the scan that opened it, so they cannot be
    # produced one at a time out of order.
    phone_indices = {i for i, p in enumerate(plan) if p.target.is_phone}
    phone_screens: dict[int, dict[str, Any]] = {}
    if phone_indices:
        if rig is None:
            raise CaptureError(
                f"{scene_id} has phone shots but no phone rig was prepared "
                "(no Lens token / no demo camera). This is a capture.py bug."
            )
        phone_screens = _capture_phone_scene(scene, plan, rig, result)

    # Actions first at equal `at`: a Click must fire before the state it produces lands.
    timeline: list[tuple[float, int, str, Any]] = [
        (p.at, 1, "state", p) for p in plan
    ] + [
        (action_at(a), 0, "action", a) for a in (getattr(scene, "actions", None) or [])
    ]
    timeline.sort(key=lambda entry: (entry[0], entry[1]))

    index = -1
    cursor: tuple[float, float] | None = None
    on_phone = False

    for _frac, _prio, kind, payload in timeline:
        if kind == "state":
            index += 1
            on_phone = index in phone_indices
            if on_phone:
                state = _phone_state(scene_id, payload, index, phone_screens)
                result.states.append(state)
                print(
                    f"  [{scene_id}] state {state.index} at {payload.at:.2f} "
                    f"phone:{payload.target.state}"
                    f"{' @' + str(state.scroll) if state.scroll else ''} "
                    f"({state.produced_by}) -> {Path(state.png).name if state.png else '?'}",
                    flush=True,
                )
                continue
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

        if on_phone:
            # Resolved against the phone, in the 390x844 space, by the pass above.
            if selector and str(selector) not in result.geometry and not parse_xy(str(selector)):
                raise CaptureError(
                    f"{scene_id}: {action_kind} target {selector!r} was not resolved on any "
                    "phone state of this scene. Check that its `at` falls inside the state "
                    "it belongs to."
                )
            continue

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


def _phone_state(scene_id: str, planned: Planned, index: int,
                 screens: dict[int, dict[str, Any]]) -> State:
    """Fold one already-captured phone screen back into the scene's state list."""
    screen = screens.get(index)
    if screen is None:
        raise CaptureError(
            f"{scene_id}: phone state {index} ({planned.target.state}) was planned but not "
            "captured - the phone session and the state plan disagree."
        )
    target = planned.target
    phone_meta = dict(screen)
    phone_meta["state"] = target.state
    if target.kind == "phone_pair":
        # The illustrated half is scene_render.py's output; only the phone was shot here.
        # compose.py wants a path it can open, so the script's *name* is resolved to one.
        phone_meta["scene_name"] = target.scene
        resolved = screen.get("scene_png")
        phone_meta["scene_png"] = str(resolved) if resolved else None
    return State(
        scene_id, index, target.kind, target.ref, int(screen.get("scroll") or 0),
        png=Path(str(screen["png"])), produced_by=planned.produced_by, phone=phone_meta,
    )


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
    scenes: list[Any] | None = None,
    scene_y4m: Path | None = None,
    scene_png: Path | None = None,
    sidecar_script: Path = SIDECAR_SCRIPT,
) -> tuple[dict[str, SceneResult], dict[str, Path]]:
    from playwright.sync_api import sync_playwright

    if scenes is None:
        scenes = [] if slides_only else load_scenes()
    elif slides_only:
        scenes = []
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
    phone_scenes = [
        s for s in scenes
        if any(is_phone(sh) or is_phone_pair(sh) for sh in _all_shots(s))
    ]
    # A decoder is needed when a scene calls it a scan, and whenever the unrecognised-code
    # sheet is on the list: that screen only exists after a decode.
    needs_decode = any(
        scene_wants_scan(s, plan_states(s))
        or any(p.target.is_phone and p.target.state == "unknown" for p in plan_states(s))
        for s in phone_scenes
    )

    with ExitStack() as stack:
        work_data = make_working_copy(data_dir) if needs_dashboard else data_dir
        rig: PhoneRig | None = None
        if phone_scenes:
            assets = scene_assets(y4m=scene_y4m, png=scene_png)
            sidecar = None
            if needs_decode:
                sidecar = stack.enter_context(DecodeSidecar(script=sidecar_script))
            rig = PhoneRig(
                token=mint_lens_token(work_data),
                camera=demo_camera(work_data),
                data_dir=work_data,
                assets=assets,
                sidecar=sidecar,
                clock=now,
                headed=headed,
            )
            print(
                f"  phone rig: camera {rig.camera.ip} (device {rig.camera.device_id}), "
                f"sticker {rig.camera.code}, clip "
                f"{rig.assets.y4m.name if rig.assets.usable else 'NONE'}, "
                f"decoder {'on' if rig.decoding else 'off'}",
                flush=True,
            )

        dashboard = (
            stack.enter_context(Dashboard(data_dir=work_data)) if needs_dashboard else None
        )
        p = stack.enter_context(sync_playwright())
        if rig is not None:
            rig.playwright = p
        browser = None
        try:
            browser = p.chromium.launch(channel="chrome", headless=not headed)
            context = browser.new_context(
                viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
                device_scale_factor=SCALE,
                color_scheme=COLOR_SCHEME,
                reduced_motion="reduce",
                ignore_https_errors=True,   # the demo certificate is self-signed by design
                base_url=BASE_URL,
            )
            context.set_default_timeout(NAV_TIMEOUT_MS)
            with suppress(Exception):
                context.clock.set_fixed_time(now)
            _strip_csp(context)
            page = context.new_page()
            cap = Capturer(page, frozen_label=frozen_label)
            if dashboard is not None:
                verify_blocking_running(cap)

            if not no_slides:
                slide_pngs = capture_slides(cap, registry, slide_names)

            for i, scene in enumerate(scenes, start=1):
                scene_id = str(getattr(scene, "id", f"scene-{i:02d}"))
                started = time.monotonic()
                results[scene_id] = capture_scene(cap, scene, registry, rig)
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
        "base_url": BASE_URL,
        "slides": {name: path.as_posix() for name, path in sorted(slide_pngs.items())},
        "scenes": {sid: [s.as_json() for s in res.states] for sid, res in results.items()},
        "warnings": {sid: res.warnings for sid, res in results.items() if res.warnings},
    }
    # The phone half of the geometry: every rect under a phone scene id is in this space,
    # not the 1600x900 one, and every phone PNG is this size. Optional, because a capture
    # that never touched a phone should not need video/phone.py to exist.
    with suppress(CaptureError):
        phone = _phone()
        manifest["phone_viewport"] = [phone.PHONE_W, phone.PHONE_H]
        manifest["phone_device_scale_factor"] = phone.PHONE_SCALE
        manifest["phone_shot_size"] = [phone.SCREEN_W, phone.SCREEN_H]
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
    parser.add_argument("--script", default=None, metavar="FILM",
                        help="which film: everyday (default) | technical")
    parser.add_argument("--only", metavar="ID[,ID]", help="only capture these scene ids")
    parser.add_argument("--slides-only", action="store_true", help="render the slides and stop")
    parser.add_argument("--no-slides", action="store_true", help="skip the slides, capture pages only")
    parser.add_argument("--headed", action="store_true", help="show the browser window")
    parser.add_argument("--data", metavar="DIR", default=str(DEMO_DATA), help="demo data directory")
    parser.add_argument("--scene-y4m", metavar="FILE",
                        help="the fake-camera clip for the scan rig (default: from scene_render.py)")
    parser.add_argument("--scene-png", metavar="FILE",
                        help="the illustrated still that goes beside the phone in scene 18")
    parser.add_argument("--sidecar", metavar="FILE", default=str(SIDECAR_SCRIPT),
                        help="the zxing-cpp decode sidecar to run (capture-time only)")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    data_dir = Path(args.data).expanduser().resolve()
    try:
        from narrate import NarrationError, select_film  # noqa: PLC0415 - sibling module

        configure(select_film(args.script))
    except NarrationError as exc:
        print(f"capture: {exc}", file=sys.stderr)
        return 2
    print(f"capture: film={FILM_NAME} ({SCRIPT_MODULE}.py, {SLIDES_MODULE}.py, {COLOR_SCHEME}) "
          f"build={BUILD}")
    print(f"capture: data={data_dir} port={PORT} resolver=127.0.0.1:{DNS_PORT} "
          f"viewport={VIEWPORT_W}x{VIEWPORT_H}@{SCALE}x")
    try:
        capture(
            data_dir=data_dir,
            only=args.only,
            slides_only=args.slides_only,
            no_slides=args.no_slides,
            headed=args.headed,
            scene_y4m=Path(args.scene_y4m).expanduser().resolve() if args.scene_y4m else None,
            scene_png=Path(args.scene_png).expanduser().resolve() if args.scene_png else None,
            sidecar_script=Path(args.sidecar).expanduser().resolve(),
        )
    except CaptureError as exc:
        print(f"\ncapture: FAILED\n{exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - phone.PhoneError and anything else, one format
        if type(exc).__name__ != "PhoneError":
            raise
        print(f"\ncapture: FAILED\n{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ncapture: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
