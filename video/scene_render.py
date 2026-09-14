"""The illustrated scene the phone "looks at" in scene 18, and the fake camera feed made from it.

CONTRACT_V2 section V3 step 1-2. Desktop Chrome on Windows has no ``BarcodeDetector``, so the
recording machine cannot run Lens's real in-browser decode — but the scan is still produced from
**real pixels**: this module draws a small wall-mounted security camera as flat vector SVG in the
product's palette, sticks a **genuine** QR sticker on its body (encoded by ``homesoc.web.qr`` from
the demo camera's real sticker token), renders it in the installed Chrome, and turns that still
into a Y4M clip Chrome can play back as a webcam with
``--use-file-for-fake-video-capture=<clip>.y4m``.

Nothing here is a photograph, a stock asset or an external file: the wall, the shelf, the camera
and the QR are all drawn from these lines. The one input is the camera's sticker payload, read
from the seeded demo database (and from ``video/build/lens_demo.json`` if that is all there is).

Three numbers govern the composition, and all three come from the product rather than from taste:

* ``static/lens.js`` decodes from a canvas downscaled to **480 px wide** — a factor of 0.375 on a
  1280 px frame — so the QR is drawn large enough to survive that, which is what ``QR_MODULE_PX``
  is about.
* ``static/lens.css`` shows the camera feed with ``object-fit: cover`` in a 390x844 viewport, so a
  1280x720 frame is cropped to its central ~333 px, and the Lens card then rises over the bottom
  two thirds. The sticker has to live inside that column and high in the frame, which is why the
  camera is drawn as a close-up with its label above the middle.
* the frame is 1280x720 because that is exactly what ``lens.js`` asks ``getUserMedia`` for, so
  Chrome's file-backed fake device hands the track through unadapted and uncropped.

Usage::

    python video/scene_render.py          # build (or reuse) the still and the Y4M, and check both
    python video/scene_render.py --force  # rebuild even if the current assets carry this token
    python video/scene_render.py --still-only --out /tmp/look.png   # just look at the drawing
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

VIDEO_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = VIDEO_DIR.parent
if str(PROJECT_ROOT) not in sys.path:  # running the file directly, without an install
    sys.path.insert(0, str(PROJECT_ROOT))

from homesoc.web import qr as qrmod  # noqa: E402

logger = logging.getLogger("scene_render")

BUILD_DIR = VIDEO_DIR / "build"
LENS_JSON = BUILD_DIR / "lens_demo.json"
SCENE_PNG = BUILD_DIR / "scene_camera.png"
SCENE_Y4M = BUILD_DIR / "scene_camera.y4m"

#: The seeded demo database, which is the authority on the camera's sticker payload — the file
#: ``capture.py`` reads it out of too. ``lens_demo.json`` is the fallback for when it is absent.
DEMO_DB = VIDEO_DIR / "demo_data" / "homesoc.db"
CAMERA_IP = "192.168.1.142"

#: Default clip length. Chrome loops the file, and the drift is periodic, so a few seconds is
#: plenty — and Y4M is raw: 1280x720 costs about 1.4 MB a frame.
CLIP_SECONDS = 6.0
CLIP_FPS = 30

#: The resolution ``lens.js`` asks for, so Chrome's file-backed fake device needs no adaptation.
WIDTH = 1280
HEIGHT = 720

#: Extra pixels rendered outside the frame on every side, so the handheld drift always has real
#: scene to move into instead of a black edge. Bigger than the largest possible excursion:
#: 6 px of translation plus ~4 px from rotating a 1336x776 image by 0.3 degrees.
BLEED = 28

#: Device pixels per QR module. ``lens.js`` decodes from a 480 px-wide grab of the 1280 px frame,
#: so this is 2.25 px per module by the time the decoder sees it. Measured, not guessed: the whole
#: chain (render -> drift -> Y4M -> 480 px grab) still decodes at 4 px per module, and every step
#: below that is a cliff — 6 leaves half again as much margin while keeping the sticker small
#: enough that the camera around it is still in shot when lens.css crops the feed to portrait.
QR_MODULE_PX = 6
QR_QUIET_ZONE = 4

# --------------------------------------------------------------------------- palette
# Read from homesoc/web/static/style.css. Kept as literals (like slides.py does) because the
# renderer must produce the same frame whether or not the dashboard is running.

BG = "#0f1117"
PANEL_2 = "#1d2130"
ACCENT = "#3e63dd"
SEV_CRITICAL = "#e5484d"
GLASS = "#0b0f14"
STICKER = "#f6f7fb"
STICKER_LINE = "#dfe2ea"
STICKER_INK = "#1a1d27"
SANS = 'system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'

# The dashboard's dark palette is built for text on a screen; a camera pointed at an object in a
# hallway has to separate that object from the wall behind it. These are the same hues one or two
# steps lighter — the panel/line family stretched into a lit surface rather than a new palette.
SHELL = "#2b3244"
SHELL_DARK = "#232838"
SHELL_EDGE = "#39415a"
SHELL_HI = "#4a5470"
HOOD = "#333b50"

BRAND_MARK = "◉"  # the dashboard sidebar's brand glyph

# --------------------------------------------------------------------------- geometry
#
# All coordinates are in frame pixels (1280x720), 1:1 with the rendered image — the SVG is never
# scaled, so a QR module is exactly QR_MODULE_PX device pixels and stays crisp.

SHELF_TOP = 596.0          # where the shelf surface meets the wall
SHELF_FRONT = 672.0        # bottom of the shelf's front edge

#: The body is a bullet camera seen side-on: a semicircular left cap (the lens end), a long
#: barrel, and a squarer right end where the cable leaves. It hangs off a bracket that stands on
#: the shelf, which is what makes "wall-mounted camera, currently on a shelf" read at a glance.
BODY = (150.0, 95.0, 900.0, 370.0)      # x, y, w, h
CAP_R = BODY[3] / 2.0                   # the left end is a half-circle
LENS_CENTRE = (BODY[0] + CAP_R, BODY[1] + CAP_R)
LENS_R = 150.0                          # housing; the glass is smaller

#: Where the sticker sits, and the most constrained rectangle in the file.
#:
#: * horizontally centred, because lens.css shows the feed ``object-fit: cover`` in a 390x844
#:   viewport — of a 1280 px frame only the middle ~333 px are ever on screen;
#: * high in the frame, because the Lens card rises over the bottom two thirds of the phone, and
#:   a sticker any lower would be behind the card in the very shot that is about recognising it;
#: * centred near 40% of the frame height, which is where lens.css puts the scanning reticle.
STICKER_PAD = 18.0
STICKER_CENTRE = (WIDTH / 2.0, 250.0)
CENTRE_X = WIDTH / 2.0


@dataclass(frozen=True)
class Drift:
    """The handheld wobble. Periods divide the clip exactly, so the loop is seamless."""

    x_px: float = 5.0
    y_px: float = 3.2
    degrees: float = 0.28
    #: Period of each component as a fraction of the clip length (1 = one cycle per clip).
    x_cycles: float = 1.0
    y_cycles: float = 2.0
    rot_cycles: float = 1.0

    def at(self, phase: float) -> tuple[float, float, float]:
        """``phase`` is 0..1 through the clip -> (dx, dy, degrees).

        Sines, not linear ramps: the motion eases in and out of every reversal on its own, which
        is what a hand does, and it returns to exactly where it started so the file loops.
        """
        tau = 2.0 * math.pi
        dx = self.x_px * math.sin(tau * self.x_cycles * phase)
        dy = self.y_px * math.sin(tau * self.y_cycles * phase + math.pi / 3.0)
        rot = self.degrees * math.sin(tau * self.rot_cycles * phase + math.pi / 5.0)
        return dx, dy, rot


class SceneError(RuntimeError):
    """Raised with an explanation a person can act on."""


# --------------------------------------------------------------------------- the sticker token


def sticker_code_from_db(db: Path | None = None, *, ip: str = CAMERA_IP) -> str | None:
    """The camera's sticker payload straight out of the seeded demo database, or ``None``.

    Opened **read-only**: this is the same row ``capture.py`` reads, and nothing in the video
    pipeline may write to a database a dashboard might have open.
    """
    import sqlite3

    # Defaults are resolved here, not in the signature: the module constants are what a caller
    # (or a test) redirects, and a default bound at import time would ignore that.
    db = Path(db) if db is not None else DEMO_DB
    if not db.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=2.0)
    except sqlite3.Error as exc:
        logger.debug("could not open %s read-only: %s", db, exc)
        return None
    try:
        row = conn.execute(
            "SELECT t.code FROM lens_tags t JOIN devices d ON d.id = t.device_id "
            "WHERE t.kind = 'sticker' AND d.ip = ? ORDER BY t.id LIMIT 1", (ip,),
        ).fetchone()
    except sqlite3.Error as exc:  # a pre-Lens database has no lens_tags table
        logger.debug("no sticker tag in %s: %s", db, exc)
        return None
    finally:
        conn.close()
    return str(row[0]) if row else None


def load_sticker_code(path: Path | None = None, *, db: Path | None = None) -> str:
    """The camera's real sticker payload.

    Deliberately not invented here: the QR on the wall has to be the code the demo database
    actually resolves to the camera at 192.168.1.142, or the scan in scene 18 would be theatre.

    The **database wins** over ``lens_demo.json``. Re-seeding mints a fresh random payload, so a
    JSON file left over from an earlier seed is the one way this could silently draw a QR that no
    longer identifies anything — and a stale sticker would fail in the middle of the take.
    """
    path = Path(path) if path is not None else LENS_JSON
    db = Path(db) if db is not None else DEMO_DB
    from_db = sticker_code_from_db(db)
    if from_db:
        return from_db
    if not path.exists():
        raise SceneError(
            f"neither {db} nor {path} holds a sticker token — run "
            "`python video/seed_demo.py --force` first so one is minted for the camera."
        )
    try:
        facts = json.loads(path.read_text(encoding="utf-8"))
        code = str(facts["sticker_code"])
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        raise SceneError(f"{path} is not a usable lens_demo.json: {exc}") from exc
    if not code.startswith("hs1:"):
        raise SceneError(f"{path} holds {code!r}, which is not a Home SOC sticker payload")
    logger.warning("%s has no sticker tag; falling back to %s", db.name, path.name)
    return code


# --------------------------------------------------------------------------- drawing


def _qr_svg(code: str) -> tuple[str, float]:
    """The product's own QR encoder. Returns (markup, side in px).

    The markup is placed later as a nested ``<svg>`` with its own x/y, so the QR keeps its
    one-module-per-``QR_MODULE_PX`` grid untouched — which is the whole reason it survives the
    resampling the handheld drift puts it through.
    """
    encoded = qrmod.encode(code)
    svg = encoded.to_svg(scale=QR_MODULE_PX, quiet_zone=QR_QUIET_ZONE)
    side = float((encoded.size + QR_QUIET_ZONE * 2) * QR_MODULE_PX)
    logger.debug("QR version %d, %d modules, %.0f px", encoded.version, encoded.size, side)
    return svg, side


def _defs() -> str:
    return f"""
  <defs>
    <linearGradient id="wall" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1b2130"/>
      <stop offset="0.55" stop-color="#141926"/>
      <stop offset="1" stop-color="{BG}"/>
    </linearGradient>
    <radialGradient id="pool" cx="0.5" cy="0.40" r="0.66">
      <stop offset="0" stop-color="#2c3550" stop-opacity="0.9"/>
      <stop offset="1" stop-color="#2c3550" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="bodyfill" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{SHELL}"/>
      <stop offset="0.52" stop-color="{SHELL_DARK}"/>
      <stop offset="1" stop-color="{PANEL_2}"/>
    </linearGradient>
    <linearGradient id="hoodfill" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#3d4661"/>
      <stop offset="1" stop-color="{HOOD}"/>
    </linearGradient>
    <linearGradient id="shelftop" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#39415a"/>
      <stop offset="1" stop-color="#232838"/>
    </linearGradient>
    <linearGradient id="shelffront" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{PANEL_2}"/>
      <stop offset="1" stop-color="#101319"/>
    </linearGradient>
    <radialGradient id="glass" cx="0.36" cy="0.30" r="0.80">
      <stop offset="0" stop-color="#232c40"/>
      <stop offset="0.52" stop-color="#0f141d"/>
      <stop offset="1" stop-color="{GLASS}"/>
    </radialGradient>
    <radialGradient id="led" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="{SEV_CRITICAL}" stop-opacity="0.8"/>
      <stop offset="1" stop-color="{SEV_CRITICAL}" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="contact" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#05070a" stop-opacity="0.8"/>
      <stop offset="1" stop-color="#05070a" stop-opacity="0"/>
    </radialGradient>
  </defs>"""


def _background(bleed: float) -> str:
    left = -bleed
    top = -bleed
    full_w = WIDTH + bleed * 2
    full_h = HEIGHT + bleed * 2
    return f"""
  <rect x="{left:g}" y="{top:g}" width="{full_w:g}" height="{full_h:g}" fill="url(#wall)"/>
  <ellipse cx="{CENTRE_X:g}" cy="290" rx="{WIDTH * 0.60:g}" ry="{HEIGHT * 0.56:g}" fill="url(#pool)"/>
  <!-- a picture rail, so the wall reads as a wall rather than as a backdrop -->
  <rect x="{left:g}" y="42" width="{full_w:g}" height="3" fill="{SHELL_EDGE}" opacity="0.45"/>
  <rect x="{left:g}" y="45" width="{full_w:g}" height="2" fill="#0d1017" opacity="0.6"/>
  <!-- the shelf: a lit top surface, a dark front edge, and the wall below it -->
  <rect x="{left:g}" y="{SHELF_TOP:g}" width="{full_w:g}" height="16" fill="url(#shelftop)"/>
  <rect x="{left:g}" y="{SHELF_TOP:g}" width="{full_w:g}" height="2" fill="{SHELL_HI}" opacity="0.7"/>
  <rect x="{left:g}" y="{SHELF_TOP + 16:g}" width="{full_w:g}" height="{SHELF_FRONT - SHELF_TOP - 16:g}"
        fill="url(#shelffront)"/>
  <rect x="{left:g}" y="{SHELF_FRONT:g}" width="{full_w:g}" height="{top + full_h - SHELF_FRONT:g}"
        fill="#0a0d13"/>
  <rect x="{left:g}" y="{SHELF_FRONT:g}" width="{full_w:g}" height="2" fill="#05070a"/>"""


def sticker_box(qr_side: float) -> tuple[float, float, float, float]:
    """x, y, w, h of the printed label: the QR plus its margins and the caption strip."""
    width = qr_side + STICKER_PAD * 2
    height = qr_side + STICKER_PAD * 2 + 22.0
    return (STICKER_CENTRE[0] - width / 2.0, STICKER_CENTRE[1] - height / 2.0, width, height)


def _camera(sticker_svg: str, qr_side: float) -> str:
    bx, by, bw, bh = BODY
    cx, cy = LENS_CENTRE
    sx, sy, sw, sh = sticker_box(qr_side)
    right = bx + bw
    bottom = by + bh
    qr_x = sx + (sw - qr_side) / 2.0
    qr_y = sy + STICKER_PAD
    caption_y = sy + sh - 14.0

    # A bullet body: semicircular lens end on the left, squarer end on the right.
    body_path = (f"M {bx + CAP_R:g} {by:g} H {right - 46:g} a46 46 0 0 1 46 46 "
                 f"V {bottom - 46:g} a46 46 0 0 1 -46 46 H {bx + CAP_R:g} "
                 f"a{CAP_R:g} {CAP_R:g} 0 0 1 0 {-bh:g} Z")
    # The sun hood: the overhang that makes a bullet camera unmistakable, wrapping the lens end.
    hood_outer = CAP_R + 26.0
    hood_path = (f"M {cx - hood_outer:g} {cy:g} "
                 f"A {hood_outer:g} {hood_outer:g} 0 0 1 {cx:g} {cy - hood_outer:g} "
                 f"H {right - 24:g} a24 24 0 0 1 24 24 V {cy - CAP_R + 4:g} H {cx:g} "
                 f"A {CAP_R - 4:g} {CAP_R - 4:g} 0 0 0 {cx - CAP_R + 4:g} {cy:g} Z")

    # The IR ring: eight emitters around the glass, the giveaway that this thing sees in the dark.
    ir = "".join(
        f'<circle cx="{cx + math.cos(math.radians(a)) * (LENS_R - 26):.1f}" '
        f'cy="{cy + math.sin(math.radians(a)) * (LENS_R - 26):.1f}" r="9" '
        f'fill="#171d2a" stroke="{SHELL_EDGE}" stroke-width="2"/>'
        for a in range(0, 360, 45)
    )
    vents = "".join(
        f'<rect x="862" y="{250 + step * 28:g}" width="150" height="10" rx="5" fill="#12161f"/>'
        for step in range(5)
    )
    knuckle_y = bottom + 14.0
    return f"""
  <!-- contact shadow where the bracket meets the shelf -->
  <ellipse cx="720" cy="{SHELF_TOP + 4:g}" rx="230" ry="20" fill="url(#contact)"/>

  <!-- wall bracket: foot plate on the shelf, arm up to a knuckle under the barrel -->
  <rect x="618" y="{SHELF_TOP - 16:g}" width="206" height="20" rx="8" fill="{HOOD}"
        stroke="{SHELL_EDGE}" stroke-width="2"/>
  <circle cx="656" cy="{SHELF_TOP - 6:g}" r="4" fill="#0d1017"/>
  <circle cx="786" cy="{SHELF_TOP - 6:g}" r="4" fill="#0d1017"/>
  <path d="M 686 {SHELF_TOP - 14:g} L 700 {knuckle_y:g} L 754 {knuckle_y:g} L 758 {SHELF_TOP - 14:g} Z"
        fill="{HOOD}" stroke="{SHELL_EDGE}" stroke-width="2"/>
  <circle cx="727" cy="{knuckle_y:g}" r="26" fill="{SHELL}" stroke="{SHELL_EDGE}" stroke-width="2"/>
  <circle cx="727" cy="{knuckle_y:g}" r="9" fill="#12161f"/>

  <!-- cable, running off to the right the way a power lead does -->
  <path d="M {right - 6:g} 392 C {right + 90:g} 392 {right + 120:g} 448 1300 452" fill="none"
        stroke="#0a0d13" stroke-width="13" stroke-linecap="round"/>
  <path d="M {right - 6:g} 392 C {right + 90:g} 392 {right + 120:g} 448 1300 452" fill="none"
        stroke="{HOOD}" stroke-width="6" stroke-linecap="round"/>

  <!-- antenna -->
  <rect x="952" y="8" width="15" height="104" rx="7.5" fill="{HOOD}" stroke="{SHELL_EDGE}"
        stroke-width="2"/>

  <!-- barrel -->
  <path d="{body_path}" fill="url(#bodyfill)" stroke="{SHELL_EDGE}" stroke-width="3"/>
  <path d="M {bx + CAP_R:g} {by + 4:g} H {right - 60:g}" stroke="{SHELL_HI}" stroke-width="3"
        stroke-linecap="round" opacity="0.75"/>
  <path d="M 820 {by + 26:g} V {bottom - 26:g}" stroke="{SHELL_EDGE}" stroke-width="2" opacity="0.8"/>

  <!-- sun hood -->
  <path d="{hood_path}" fill="url(#hoodfill)" stroke="{SHELL_EDGE}" stroke-width="3"/>

  <!-- lens assembly -->
  <circle cx="{cx:g}" cy="{cy:g}" r="{LENS_R:g}" fill="{HOOD}" stroke="{SHELL_EDGE}" stroke-width="3"/>
  <circle cx="{cx:g}" cy="{cy:g}" r="{LENS_R - 12:g}" fill="{SHELL_DARK}" stroke="{SHELL_EDGE}"
          stroke-width="2"/>
  {ir}
  <circle cx="{cx:g}" cy="{cy:g}" r="{LENS_R - 44:g}" fill="#05070a"/>
  <circle cx="{cx:g}" cy="{cy:g}" r="{LENS_R - 50:g}" fill="url(#glass)"/>
  <circle cx="{cx:g}" cy="{cy:g}" r="{LENS_R - 66:g}" fill="none" stroke="{ACCENT}" stroke-width="3"
          opacity="0.5"/>
  <path d="M {cx - 58:g} {cy - 34:g} A 68 68 0 0 1 {cx + 2:g} {cy - 66:g}" fill="none"
        stroke="#ffffff" stroke-width="9" stroke-linecap="round" opacity="0.18"/>
  <circle cx="{cx - 34:g}" cy="{cy - 30:g}" r="9" fill="#ffffff" opacity="0.24"/>

  <!-- vents and the status light -->
  {vents}
  <circle cx="937" cy="170" r="24" fill="url(#led)"/>
  <circle cx="937" cy="170" r="8" fill="{SEV_CRITICAL}"/>

  <!-- the printed sticker: a real QR of the camera's real sticker token -->
  <rect x="{sx + 5:g}" y="{sy + 10:g}" width="{sw:g}" height="{sh:g}" rx="16" fill="#05070a"
        opacity="0.5"/>
  <rect x="{sx:g}" y="{sy:g}" width="{sw:g}" height="{sh:g}" rx="16" fill="{STICKER}"
        stroke="{STICKER_LINE}" stroke-width="2"/>
  {sticker_svg.replace('<svg ', f'<svg x="{qr_x:g}" y="{qr_y:g}" ', 1)}
  <text x="{sx + sw / 2:g}" y="{caption_y:g}" fill="{STICKER_INK}" font-family="{SANS}"
        font-size="15" font-weight="600" letter-spacing="1.6" text-anchor="middle"
        opacity="0.72">{BRAND_MARK} HOME SOC</text>"""


def scene_html(code: str, *, bleed: float = 0.0) -> str:
    """The whole scene as one self-contained document. No external asset, no script, no font file.

    ``bleed`` widens the drawing beyond the frame on every side so a moving crop window never
    runs off the edge of the wall; the coordinate system is untouched, so nothing is rescaled.
    """
    sticker_svg, qr_side = _qr_svg(code)
    sx, sy, sw, sh = sticker_box(qr_side)
    bx, by, bw, bh = BODY
    lens_clear = LENS_CENTRE[0] + LENS_R + 24.0
    if sx < lens_clear or sx + sw > bx + bw - 40 or sy < by + 14 or sy + sh > by + bh - 14:
        raise SceneError(
            f"the {sw:.0f}x{sh:.0f} px sticker for {code!r} does not fit the camera body clear of "
            "the lens — shorten the payload or lower QR_MODULE_PX"
        )
    if sx < 480 or sx + sw > 800:
        raise SceneError(
            f"the sticker spans {sx:.0f}..{sx + sw:.0f} px, outside the ~333 px column lens.css "
            "leaves on screen — it would be cropped off the phone"
        )
    width = WIDTH + bleed * 2
    height = HEIGHT + bleed * 2
    body = _background(bleed) + _camera(sticker_svg, qr_side)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Home SOC — scene</title>
<style>
  html, body {{ margin: 0; padding: 0; background: {BG}; }}
  svg {{ display: block; }}
</style></head>
<body>
<svg xmlns="http://www.w3.org/2000/svg" width="{width:g}" height="{height:g}"
     viewBox="{-bleed:g} {-bleed:g} {width:g} {height:g}" shape-rendering="geometricPrecision">
{_defs()}
{body}
</svg>
</body></html>"""


# --------------------------------------------------------------------------- rendering


def _render_html(html: str, out_png: Path, *, width: int, height: int) -> Path:
    """Rasterise one document in the **installed** Chrome (the bundled download fails here)."""
    from playwright.sync_api import sync_playwright

    out_png.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        try:
            context = browser.new_context(
                viewport={"width": width, "height": height},
                device_scale_factor=1,      # 1:1, so a QR module stays exactly QR_MODULE_PX pixels
                color_scheme="dark",
                reduced_motion="reduce",
            )
            page = context.new_page()
            page.set_content(html, wait_until="load")
            page.screenshot(path=str(out_png), type="png", scale="css")
            context.close()
        finally:
            browser.close()
    return out_png


def render_scene(out_png: Path | None = None, *, code: str | None = None,
                 bleed: float = 0.0) -> Path:
    """Draw the scene and write it to ``out_png`` (1280x720 unless ``bleed`` widens it)."""
    out_png = Path(out_png) if out_png is not None else SCENE_PNG
    code = code or load_sticker_code()
    html = scene_html(code, bleed=bleed)
    path = _render_html(html, Path(out_png),
                        width=int(WIDTH + bleed * 2), height=int(HEIGHT + bleed * 2))
    logger.info("rendered %s (%dx%d) carrying %s", path.name,
                int(WIDTH + bleed * 2), int(HEIGHT + bleed * 2), code)
    return path


# --------------------------------------------------------------------------- the camera feed


def _frames(source: Any, *, seconds: float, fps: int, drift: Drift) -> Iterator[Any]:
    """Crop a moving, slightly rotated window out of the padded still, one frame at a time."""
    from PIL import Image

    total = max(1, int(round(seconds * fps)))
    centre = (source.width / 2.0, source.height / 2.0)
    for index in range(total):
        phase = index / total          # 0..1 exclusive, so frame 0 and frame `total` coincide
        dx, dy, angle = drift.at(phase)
        moved = source.rotate(angle, resample=Image.BICUBIC, center=centre, translate=(dx, dy))
        left = int(round((source.width - WIDTH) / 2.0))
        top = int(round((source.height - HEIGHT) / 2.0))
        yield moved.crop((left, top, left + WIDTH, top + HEIGHT))


def _write_y4m_frame(handle: Any, rgb: Any) -> None:
    """One I420 frame: BT.601 studio-range luma and 2x2-averaged chroma, as C420mpeg2 means."""
    import numpy as np

    arr = np.asarray(rgb, dtype=np.float32)
    r, g, b = arr[..., 0], arr[..., 1], arr[..., 2]
    y = 16.0 + (65.481 * r + 128.553 * g + 24.966 * b) / 255.0
    u = 128.0 + (-37.797 * r - 74.203 * g + 112.0 * b) / 255.0
    v = 128.0 + (112.0 * r - 93.786 * g - 18.214 * b) / 255.0

    def _sub(plane: Any) -> Any:
        return plane.reshape(plane.shape[0] // 2, 2, plane.shape[1] // 2, 2).mean(axis=(1, 3))

    handle.write(b"FRAME\n")
    handle.write(np.clip(y, 0, 255).astype(np.uint8).tobytes())
    handle.write(np.clip(_sub(u), 0, 255).astype(np.uint8).tobytes())
    handle.write(np.clip(_sub(v), 0, 255).astype(np.uint8).tobytes())


def make_camera_clip(out_y4m: Path | None = None, seconds: float = CLIP_SECONDS,
                     fps: int = CLIP_FPS, *,
                     code: str | None = None, drift: Drift = Drift(),
                     still: Path | None = None) -> Path:
    """Write the fake camera feed: the scene with a slow eased handheld drift.

    Chrome loops the file for as long as the page holds the track, and the drift's periods divide
    the clip exactly, so the loop point is invisible. The output is raw Y4M (about 1.4 MB a frame
    at 720p) — it lives in the gitignored ``video/build/``.

    ``still`` optionally receives the flat 1280x720 frame at the same time, which is the image
    scene 18 places beside the phone.
    """
    from PIL import Image

    out_y4m = Path(out_y4m) if out_y4m is not None else SCENE_Y4M
    out_y4m.parent.mkdir(parents=True, exist_ok=True)
    code = code or load_sticker_code()

    padded = out_y4m.with_name(out_y4m.stem + "_bleed.png")
    render_scene(padded, code=code, bleed=BLEED)
    source = Image.open(padded).convert("RGB")
    if source.size != (WIDTH + BLEED * 2, HEIGHT + BLEED * 2):
        raise SceneError(f"the padded still is {source.size}, expected "
                         f"{(WIDTH + BLEED * 2, HEIGHT + BLEED * 2)}")
    if still is not None:
        render_scene(Path(still), code=code)

    total = max(1, int(round(seconds * fps)))
    header = f"YUV4MPEG2 W{WIDTH} H{HEIGHT} F{fps}:1 Ip A1:1 C420mpeg2\n".encode("ascii")
    with out_y4m.open("wb") as handle:
        handle.write(header)
        for index, frame in enumerate(_frames(source, seconds=seconds, fps=fps, drift=drift)):
            _write_y4m_frame(handle, frame)
            if index and index % 60 == 0:
                logger.info("  %d/%d frames", index, total)
    padded.unlink(missing_ok=True)
    logger.info("wrote %s (%d frames, %.1f s at %d fps, %.0f MB)", out_y4m.name, total,
                total / fps, fps, out_y4m.stat().st_size / 1e6)
    return out_y4m


# --------------------------------------------------------------------------- verification


def decode_png(path: Path) -> list[dict[str, Any]]:
    """Decode every barcode in a rendered PNG with zxing-cpp.

    Capture-time only: zxing-cpp is installed with ``pip install --user zxing-cpp`` and must
    never appear in ``requirements.txt`` or ``pyproject.toml`` (CONTRACT_V2 V3).
    """
    try:
        import zxingcpp
    except ImportError as exc:  # pragma: no cover - the machine is documented as having it
        raise SceneError("zxing-cpp is not installed: pip install --user zxing-cpp") from exc
    from PIL import Image

    import numpy as np

    grey = np.asarray(Image.open(path).convert("L"))
    return [
        {"rawValue": hit.text, "format": str(hit.format),
         "position": str(hit.position), "valid": bool(hit.valid)}
        for hit in zxingcpp.read_barcodes(grey)
    ]


def verify_scene(path: Path, expected: str) -> dict[str, Any]:
    """Decode the QR back out of the rendered pixels and insist it is the camera's token."""
    hits = decode_png(Path(path))
    if not hits:
        raise SceneError(f"no barcode decoded out of {path} — the QR is not readable as drawn")
    values = [h["rawValue"] for h in hits]
    if expected not in values:
        raise SceneError(f"{path} decodes to {values!r}, expected {expected!r}")
    return next(h for h in hits if h["rawValue"] == expected)


def probe_clip(path: Path) -> dict[str, Any]:
    """What ffprobe makes of the Y4M — the honest answer to 'is this a video file'."""
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_streams", "-show_format",
         "-of", "json", str(path)],
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        raise SceneError(f"ffprobe rejected {path}: {out.stderr.strip()}")
    data = json.loads(out.stdout)
    stream = (data.get("streams") or [{}])[0]
    fmt = data.get("format") or {}
    return {
        "codec": stream.get("codec_name"),
        "pix_fmt": stream.get("pix_fmt"),
        "width": stream.get("width"),
        "height": stream.get("height"),
        "frames": int(stream.get("nb_read_frames") or stream.get("nb_frames") or 0) or None,
        "avg_frame_rate": stream.get("avg_frame_rate"),
        "duration": float(fmt.get("duration") or stream.get("duration") or 0.0),
        "size": int(fmt.get("size") or 0),
    }


# --------------------------------------------------------------------------- the entry point


def assets_are_current(code: str, *, png: Path | None = None, y4m: Path | None = None) -> bool:
    """Are the built assets for *this* sticker payload?

    Checked by decoding the still rather than by comparing timestamps: re-seeding mints a new
    random payload, and a stale scene would draw a QR that identifies nothing. A wrong file here
    is worse than a slow rebuild, so the test is the same one the video depends on.
    """
    png = Path(png) if png is not None else SCENE_PNG
    y4m = Path(y4m) if y4m is not None else SCENE_Y4M
    if not png.is_file() or not y4m.is_file() or y4m.stat().st_size < 1024:
        return False
    try:
        verify_scene(png, code)
    except SceneError as exc:
        logger.info("rebuilding the scene: %s", exc)
        return False
    return True


def ensure_assets(*, code: str | None = None, seconds: float = CLIP_SECONDS, fps: int = CLIP_FPS,
                  force: bool = False) -> dict[str, Any]:
    """Build the scan rig's two assets if they are missing or stale, and say where they are.

    This is what ``capture.py`` calls (with no arguments) before scene 18. It returns
    ``{"png", "y4m", "code", "rebuilt"}``; ``png`` is the flat still that goes beside the phone,
    ``y4m`` is the feed for ``--use-file-for-fake-video-capture``.
    """
    code = code or load_sticker_code()
    if not force and assets_are_current(code):
        logger.info("scene assets are current for %s", code)
        return {"png": SCENE_PNG, "y4m": SCENE_Y4M, "code": code, "rebuilt": False}
    make_camera_clip(SCENE_Y4M, seconds, fps, code=code, still=SCENE_PNG)
    verify_scene(SCENE_PNG, code)
    return {"png": SCENE_PNG, "y4m": SCENE_Y4M, "code": code, "rebuilt": True}


# --------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=SCENE_PNG, help=f"still (default: {SCENE_PNG})")
    parser.add_argument("--clip-out", type=Path, default=SCENE_Y4M, help=f"default: {SCENE_Y4M}")
    parser.add_argument("--seconds", type=float, default=CLIP_SECONDS)
    parser.add_argument("--fps", type=int, default=CLIP_FPS)
    parser.add_argument("--code", default=None, help="override the sticker payload (testing only)")
    parser.add_argument("--still-only", action="store_true", help="render the PNG, skip the clip")
    parser.add_argument("--force", action="store_true", help="rebuild even if the assets are current")
    parser.add_argument("--no-verify", action="store_true", help="skip the decode check")
    # Accepted and ignored: building the clip is the default, and callers that spell it out
    # (or that were written against an earlier flag set) must keep working.
    parser.add_argument("--clip", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    code = args.code or load_sticker_code()
    print(f"token    {code}")

    if args.still_only:
        still = render_scene(args.out, code=code)
        print(f"scene    {still}")
        if not args.no_verify:
            hit = verify_scene(still, code)
            print(f"decoded  {hit['rawValue']}  ({hit['format']}, position {hit['position']})")
        return 0

    if args.out == SCENE_PNG and args.clip_out == SCENE_Y4M:
        built = ensure_assets(code=code, seconds=args.seconds, fps=args.fps, force=args.force)
        still, clip = built["png"], built["y4m"]
        if not built["rebuilt"]:
            print("cached   the scene already carries this token; nothing to rebuild")
    else:
        clip = make_camera_clip(args.clip_out, args.seconds, args.fps, code=code, still=args.out)
        still = args.out

    print(f"scene    {still}")
    if not args.no_verify:
        hit = verify_scene(still, code)
        print(f"decoded  {hit['rawValue']}  ({hit['format']}, position {hit['position']})")
    info = probe_clip(clip)
    print(f"clip     {clip}")
    print(f"ffprobe  {info['codec']} {info['width']}x{info['height']} {info['pix_fmt']} "
          f"{info['avg_frame_rate']} fps · {info['duration']:.2f} s · {info['size'] / 1e6:.0f} MB")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SceneError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
