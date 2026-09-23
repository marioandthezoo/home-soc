"""Frame compositor for the Home SOC walkthrough video.

Owns the *look* of the video. Given, for one scene:

* the screenshots captured by ``capture.py``,
* the element geometry resolved by ``capture.py``,
* the narration duration measured by ``narrate.py``,
* the action list declared in ``script.py``,

this module generates every frame in memory with Pillow/numpy and pipes them
as raw ``rgb24`` straight into ffmpeg's stdin.  Nothing is ever written to disk
as a PNG except when you explicitly ask for probe frames.

Output format (CONTRACT.md section 5): 1920x1080, 30 fps, H.264 yuv420p, CRF 19.

CONTRACT_V2 adds the Lens act, which brings three new things to this module:

* **phone shots** - a 390x844 Lens screen, captured at ``device_scale_factor=3``
  and composited into a drawn phone body (``video/phone.phone_frame`` when that
  module is importable, otherwise the equivalent drawn here), standing on the
  1920x1080 canvas at roughly two thirds of frame height so the screen text is
  legible at 1080p;
* ``PhonePair`` - the illustrated scene and the phone side by side for scene 18,
  with a dashed view cone from the phone to a target ring on the thing it is
  pointed at, so the relationship reads without narration;
* ``Tap`` and ``PhoneScroll`` - a finger press (a filled circle that expands and
  fades, deliberately *not* the desktop cursor's arrow-and-halo) and a genuine
  translation of the phone's screen content.

--------------------------------------------------------------------------
File conventions this module expects from the other packages
--------------------------------------------------------------------------
``build/shots_manifest.json``  the authority on a scene's *visual states*:
                               ``{"scenes": {id: [{index, kind, path, scroll,
                               png}, ...]}}``, in chronological order.  State 0
                               is the opening shot; each later one is produced
                               by a ``PageSequence`` member, a ``Click``'s
                               ``then_shot``, or a ``Scroll``.
                               ``kind`` is ``"page"``, ``"slide"``, ``"phone"``
                               or ``"phone_pair"``; a ``phone_pair`` row also
                               carries ``scene_png`` (the illustrated scene) and
                               may carry ``aim`` = ``[fx, fy]``, where in that
                               illustration the phone is pointed (fractions of
                               the image, default the middle right).
``build/shots/<scene_id>_<k>.png``   the images the manifest points at; also the
                               glob fallback when there is no manifest.
``build/geometry.json``        ``{scene_id: {"css=<selector>": [x, y, w, h]}}``,
                               *viewport*-relative, in the 1600x900 CSS space.
                               The optional key ``"__fixed__"`` may carry a list
                               of rects for ``position: fixed`` chrome; without
                               it those regions are detected by diffing the two
                               scroll states.
``build/timings.json``         ``{scene_id: {"audio": path, "seconds": float}}``

:func:`plan_transitions` deliberately reimplements ``capture.plan_states``: the
two must agree, because transition *k* here maps onto manifest state *k + 1*.

Shots are captured at ``device_scale_factor=2`` so they arrive as 3200x1800 and
are downscaled exactly once to the 1792x1008 window.  They are never upscaled --
a ``Zoom`` resamples the 3200px original, so up to 1.79x magnification is still
real captured detail.

--------------------------------------------------------------------------
Per-frame pipeline
--------------------------------------------------------------------------
1. page layer      the 1792x1008 shot, or a true scroll (the two scroll states
                   stacked into the document strip they came from, with fixed
                   chrome held still), or a cross-fade of two states
2. camera          Ken Burns crop+resize (Zoom, slide drift)
3. highlight       25% scrim, the target rect punched back to full brightness,
                   accent glow around it
4. window chrome   #0b0f14 canvas, soft drop shadow, 12px rounded corners,
                   hairline border  ->  1920x1080 canvas
5. cursor          arrow + halo (+ click ripple), drawn after the camera at a
                   camera-projected position, so it stays crisp and 34px
6. caption         lower-third pill
7. head dissolve   400ms cross-dissolve from the previous scene's last frame

Most frames take the fast path at step 1 and are a copy of a cached canvas plus
a cursor blit, which is what keeps a ~14,000 frame render inside a few minutes.

Run ``python video/compose.py --selftest`` to render a synthetic 10 second clip
that exercises every effect against fake shots it draws itself, and leaves
probe PNGs in ``build/selftest/probe`` to look at.  ``--selftest-phone`` does the
same for the Lens shots: a phone screen, a ``Tap``, a ``PhoneScroll``, a
``PhonePair`` and the head dissolve, into ``build/selftest/probe_phone``.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Iterable, Mapping, Sequence

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

log = logging.getLogger("homesoc.video.compose")

# --------------------------------------------------------------------------
# Canvas geometry and timing constants
# --------------------------------------------------------------------------

W, H = 1920, 1080
FPS = 30

CSS_W, CSS_H = 1600, 900

#: the "window" the dashboard is letterboxed into, on the 1920x1080 canvas
WIN_X, WIN_Y, WIN_W, WIN_H = 64, 36, 1792, 1008
#: CSS px -> canvas px.  1792/1600 == 1008/900 == 1.12 exactly.
SCALE = WIN_W / CSS_W

BG = (11, 15, 20)  # #0b0f14
BORDER = (44, 52, 68)
ACCENT = (91, 124, 255)
CAPTION_FG = (232, 236, 246)

CORNER_RADIUS = 12
SHADOW_BLUR = 26
SHADOW_DY = 16
SHADOW_ALPHA = 0.62

# These three must match narrate.LEAD_IN / TAIL_PAD / END_ROOM_TONE, because
# narrate.py writes the subtitle timeline from the same numbers.
#: silence before the narration starts in every scene
LEAD_IN = 0.30
#: silence after the narration ends in every scene
TAIL = 0.40
#: Extra room tone appended after the *last* scene. CONTRACT §6 asks for 0.6 s at the very
#: end; TAIL (0.40) plus this is the silence this pipeline *adds*, and edge-tts leaves roughly
#: another third of a second of its own padding after the last word, so 0.60 here measured
#: 1.34 s of dead air on the close slide. 0.25 puts the added room tone at 0.65 s.
END_ROOM_TONE = 0.25

DISSOLVE = 0.40  # scene-to-scene cross dissolve
RIPPLE_SECONDS = 0.45
PRESS_SECONDS = 0.06
AFTER_DELAY = 0.12  # crossfade to the after-state starts this long after the ripple
SWAP_SECONDS = 0.22
CAPTION_FADE = 0.30
#: How long the lower third stays up before fading, in seconds. It used to hold for the
#: whole scene, and at 34 px the pill is ~300 CSS px wide - about 60 px past the sidebar -
#: so on a 65 s scene it sat on top of page content for a minute: it ate the leading "W" of
#: WIN-ACC-005, blanked the hostname cell of the 192.168.1.71 row under a Zoom, and covered
#: the "BY CATEGORY" heading on /summary. A lower third names the shot and leaves; holding
#: one is what broadcast calls a bug, not a caption.
CAPTION_HOLD = 5.6
HIGHLIGHT_FADE = 0.25
DIM_STRENGTH = 0.25
MAX_ZOOM = 1.6
#: Slides get a gentle Ken Burns push so a title card is not dead still. Set
#: this to 1.0 to turn the drift off; it is the most expensive effect in the
#: render (every drifting frame is a full-page resample).
SLIDE_DRIFT = 1.03
#: The drift runs across the *whole* time the slide is on screen, at a constant rate.
#: It used to settle after a fixed 11 s, which is why `ffmpeg -vf freezedetect` found 264 s
#: of bit-identical frames in a 471 s film: the architecture slide sat motionless for 31 s,
#: "What it is" for 19 s, the close for 14 s. Constant rate rather than ease-in-out, because
#: a cubic ease across a 40 s slide has a near-zero derivative at both ends and freezes there
#: anyway. It costs one resample per slide frame - about 8 ms - and nothing else in the
#: render is anywhere near that price.

#: The same treatment, but for a *page* or *phone* state the voice sits on without
#: scrolling. The walkthrough is built out of held screenshots, so a scene where the
#: narration explains one panel for twenty seconds is twenty seconds of bit-identical
#: frames: `freezedetect` found 10.8 s, 9.4 s, 8.5 s and 7.6 s stretches in the previous
#: cut, and the quality bar is 6 s.
#:
#: A slide's single push cannot be borrowed as-is. Its *rate* falls as the hold gets
#: longer - 1.03 spread over 30 s moves the crop box 0.058 px per frame, over 20 s at
#: 1.012 only 0.034 px, and at that speed most of a dark dashboard rounds to the same
#: bytes two frames running and freezes anyway (measured: scene 12 still had an 8.5 s
#: stretch with a whole-hold 1.012 push on it). So a held page drifts at a fixed *speed*
#: instead, in and back out over a short cycle: the excursion stays under one per cent -
#: invisible, and far too small to soften 2x-captured text - while every frame differs
#: from the one before it.
#: Crop-box speed, in page-layer pixels of width per second.
IDLE_DRIFT_RATE = 2.5
#: One in-and-out cycle takes this long, so the push half is half of it. Short enough that
#: the excursion stays tiny at this speed, long enough that nothing reads as movement.
IDLE_DRIFT_CYCLE = 9.0
#: Holds shorter than this are left alone: a beat between scrolls does not need help, and
#: skipping them keeps the resample off most frames.
#:
#: 4.0 was one tenth of a second too generous for the one state in the film whose narration
#: claims motion: scene 18's `hit=True` shot - the real instant of recognition, green reticle,
#: chip reading "identifying…" - is on screen for 3.83 s, so it fell through this test and
#: `freezedetect` reported a 3.7 s bit-identical stretch under the words "Lens reads frames
#: the whole time". Under CONTRACT_V2 V7's 6 s bar, and still the only dead frame in the Lens
#: act. 2.5 catches it and anything else of that length; the ceiling is IDLE_DRIFT_CYCLE, and
#: a 2.5 s cycle at IDLE_DRIFT_RATE is a 0.2 per cent excursion.
IDLE_DRIFT_AFTER = 2.5
#: A Zoom holds at full extent between its push and its pull-back, and that hold is as
#: frozen as any other still - scene 07a's zoom onto the printer's provider node sat dead
#: for 10.8 s. The hold keeps creeping at IDLE_DRIFT_RATE instead, capped at this fraction
#: past the rect the Zoom asked for so a 1.6x push never becomes a 1.7x one.
HOLD_CREEP_MAX = 0.06

CURSOR_HEIGHT = 34.0
HALO_RADIUS = 34
#: the halo is centred on the arrow's body, not on its tip, so the whole
#: pointer sits inside the glow
HALO_OFFSET = (7.0, 14.0)
CURSOR_TILE = 112
CURSOR_HOT = 46  # hotspot offset inside the tile, both axes
SUBPIXEL_STEPS = 4

DEFAULT_CURSOR_START = (1180.0, 760.0)  # CSS space

# --- phone shots (CONTRACT_V2 V2) ------------------------------------------
#: the Lens viewport, in phone CSS pixels; captured at device_scale_factor=3
PHONE_CSS_W, PHONE_CSS_H = 390.0, 844.0
#: Phone *body* height as a fraction of the 1080 px canvas (the drop shadow is not
#: part of the phone). CONTRACT_V2 V5 asks for 55-70% in phone-only scenes, and the
#: top of that range is the only part of it that keeps the Lens screen near 1:1 with
#: its own CSS pixels - 0.70 puts a 390x844 viewport on screen at 0.87x, so 15 px
#: body text lands at 13 px. Anything lower and the phone starts lying about how
#: readable the real thing is.
PHONE_BODY_FRAC = 0.70
#: The pair shot has to fit an illustration beside it, so the phone gives up a little -
#: but only a little. This is the money shot, and the card that rises on it is the densest
#: screen in the film; 0.68 costs the illustration about 2% of its width and buys the card
#: a tenth more type. Still inside the contract's 55-70%.
PHONE_PAIR_BODY_FRAC = 0.68
#: canvas margins for the pair layout
PHONE_MARGIN = 88
PHONE_PAIR_GAP = 56
#: Where the phone is pointed in the illustrated scene, as fractions of the
#: illustration - by default the sticker, which ``scene_render.py`` centres at
#: (WIDTH/2, 250) of its 1280x720 frame. A manifest row overrides it with
#: ``"aim": [fx, fy]``.
PHONE_AIM_DEFAULT = (0.50, 0.35)

#: a finger press: a filled circle that expands and fades
TAP_SECONDS = 0.55
#: Contact radius and final ring radius, **in the phone's own 390x844 CSS pixels**, scaled
#: to the canvas by however big the composited phone is. They used to be canvas constants
#: (18 -> 104 px), which on a 0.83x phone drew a ~200 px near-white disc: the one tap in the
#: Lens act washed out the sheet's drag handle, the "Vulnerabilities 1" header and the top
#: two lines of the CVE text. A fingertip on a 390 px-wide screen is about 40 px across.
TAP_START_R_CSS = 11.0
TAP_MAX_R_CSS = 42.0
TAP_RGB = (226, 236, 255)

_FONT_CANDIDATES = (
    r"C:\Windows\Fonts\seguisb.ttf",
    r"C:\Windows\Fonts\segoeuib.ttf",
    r"C:\Windows\Fonts\calibrib.ttf",
    r"C:\Windows\Fonts\arialbd.ttf",
)
_FONT_REGULAR_CANDIDATES = (
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\calibri.ttf",
    r"C:\Windows\Fonts\arial.ttf",
)


# --------------------------------------------------------------------------
# Small maths helpers
# --------------------------------------------------------------------------


def ease_in_out_cubic(t: float) -> float:
    """Standard ease-in-out cubic on [0, 1]."""
    t = min(1.0, max(0.0, t))
    if t < 0.5:
        return 4.0 * t * t * t
    return 1.0 - ((-2.0 * t + 2.0) ** 3) / 2.0


def ease_out_cubic(t: float) -> float:
    t = min(1.0, max(0.0, t))
    return 1.0 - (1.0 - t) ** 3


def clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else hi if v > hi else v


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def css_to_page(x: float, y: float) -> tuple[float, float]:
    """CSS (1600x900) coordinates -> page-layer (1792x1008) coordinates."""
    return x * SCALE, y * SCALE


# --------------------------------------------------------------------------
# Sprite construction (cursor, ripple, caption, glow) - all cached
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Sprite:
    """An RGBA sprite split into a uint8 colour plane and a float alpha plane."""

    rgb: np.ndarray  # (h, w, 3) uint8
    alpha: np.ndarray  # (h, w, 1) float32 in 0..1

    @property
    def size(self) -> tuple[int, int]:
        return self.alpha.shape[1], self.alpha.shape[0]


def sprite_from_image(im: Image.Image) -> Sprite:
    arr = np.asarray(im.convert("RGBA"), dtype=np.uint8)
    return Sprite(
        rgb=np.ascontiguousarray(arr[:, :, :3]),
        alpha=np.ascontiguousarray(arr[:, :, 3:4].astype(np.float32) / 255.0),
    )


def blit(dst: np.ndarray, sp: Sprite, x: float, y: float, alpha: float = 1.0) -> None:
    """Alpha-composite ``sp`` onto the RGB array ``dst`` with clipping.

    ``x``/``y`` are the top-left of the sprite in ``dst`` coordinates.
    """
    if alpha <= 0.002:
        return
    sh, sw = sp.alpha.shape[:2]
    dx, dy = int(round(x)), int(round(y))
    sx0 = max(0, -dx)
    sy0 = max(0, -dy)
    dx0 = max(0, dx)
    dy0 = max(0, dy)
    cw = min(sw - sx0, dst.shape[1] - dx0)
    ch = min(sh - sy0, dst.shape[0] - dy0)
    if cw <= 0 or ch <= 0:
        return
    a = sp.alpha[sy0 : sy0 + ch, sx0 : sx0 + cw]
    if alpha < 1.0:
        a = a * alpha
    c = sp.rgb[sy0 : sy0 + ch, sx0 : sx0 + cw]
    reg = dst[dy0 : dy0 + ch, dx0 : dx0 + cw]
    np.copyto(reg, (reg * (1.0 - a) + c * a + 0.5).astype(np.uint8))


def _font(size: int, semibold: bool = True) -> ImageFont.FreeTypeFont:
    for path in _FONT_CANDIDATES if semibold else _FONT_REGULAR_CANDIDATES:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    log.warning("no TrueType font found; falling back to the PIL bitmap font")
    return ImageFont.load_default()


_cursor_cache: dict[tuple[float, int, int], Sprite] = {}


def _arrow_polygon(height: float) -> list[tuple[float, float]]:
    """Classic pointer outline with the tip at (0, 0), scaled to ``height``."""
    base = [
        (0.0, 0.0),
        (0.0, 16.0),
        (4.2, 12.4),
        (6.8, 18.6),
        (9.6, 17.4),
        (7.0, 11.4),
        (12.0, 11.4),
    ]
    k = height / 18.6
    return [(px * k, py * k) for px, py in base]


def _halo_layer(radius: float, tile: int, hot: int) -> np.ndarray:
    """Soft translucent accent halo as an (h, w, 4) float32 premultiply-free RGBA."""
    yy, xx = np.mgrid[0:tile, 0:tile].astype(np.float32)
    d = np.hypot(xx - (hot + HALO_OFFSET[0]), yy - (hot + HALO_OFFSET[1]))
    core = np.clip(1.0 - d / (radius * 0.60), 0.0, 1.0) ** 1.1 * 0.26
    outer = np.clip(1.0 - d / radius, 0.0, 1.0) ** 1.35 * 0.34
    a = np.clip(core + outer, 0.0, 0.66)
    layer = np.zeros((tile, tile, 4), dtype=np.float32)
    layer[:, :, 0] = ACCENT[0]
    layer[:, :, 1] = ACCENT[1]
    layer[:, :, 2] = ACCENT[2]
    layer[:, :, 3] = a * 255.0
    return layer


def cursor_sprite(press: float = 0.0, sub_x: int = 0, sub_y: int = 0) -> Sprite:
    """Build (and cache) the cursor sprite.

    ``press`` is 0..1; 1 is the fully pressed state (scaled down).  ``sub_x`` /
    ``sub_y`` are subpixel phases in 1/SUBPIXEL_STEPS of a pixel, which keeps
    slow cursor movement smooth instead of stepping pixel to pixel.
    """
    key = (round(press, 2), sub_x % SUBPIXEL_STEPS, sub_y % SUBPIXEL_STEPS)
    hit = _cursor_cache.get(key)
    if hit is not None:
        return hit

    scale = 1.0 - 0.14 * press
    ss = 4  # supersample factor for the arrow
    tile = CURSOR_TILE
    hot = CURSOR_HOT
    ox = (sub_x % SUBPIXEL_STEPS) / SUBPIXEL_STEPS
    oy = (sub_y % SUBPIXEL_STEPS) / SUBPIXEL_STEPS

    # --- halo (drawn directly at 1x; it is a smooth gradient) ---------------
    out = _halo_layer(HALO_RADIUS * (1.0 - 0.06 * press), tile, hot)

    # --- arrow at 4x, then downsampled --------------------------------------
    poly = _arrow_polygon(CURSOR_HEIGHT * scale)
    big = Image.new("RGBA", (tile * ss, tile * ss), (0, 0, 0, 0))
    dr = ImageDraw.Draw(big)
    pts = [((hot + ox + px) * ss, (hot + oy + py) * ss) for px, py in poly]
    dr.polygon(pts, fill=(255, 255, 255, 255), outline=(9, 12, 17, 255), width=int(1.6 * ss))
    arrow = big.resize((tile, tile), Image.LANCZOS)

    # --- drop shadow from the arrow silhouette ------------------------------
    shadow = Image.new("RGBA", (tile, tile), (0, 0, 0, 0))
    sa = arrow.getchannel("A").filter(ImageFilter.GaussianBlur(3.0))
    shadow.putalpha(sa.point(lambda v: int(v * 0.55)))
    shadow = shadow.transform(
        (tile, tile), Image.AFFINE, (1, 0, -2, 0, 1, -3), resample=Image.BILINEAR
    )

    for layer in (shadow, arrow):
        la = np.asarray(layer, dtype=np.float32)
        a = la[:, :, 3:4] / 255.0
        out[:, :, :3] = la[:, :, :3] * a + out[:, :, :3] * (1.0 - a)
        out[:, :, 3:4] = la[:, :, 3:4] + out[:, :, 3:4] * (1.0 - a)

    sp = Sprite(
        rgb=np.ascontiguousarray(np.clip(out[:, :, :3], 0, 255).astype(np.uint8)),
        alpha=np.ascontiguousarray(np.clip(out[:, :, 3:4] / 255.0, 0.0, 1.0).astype(np.float32)),
    )
    _cursor_cache[key] = sp
    return sp


_RIPPLE_TILE = 224
_ripple_grid: np.ndarray | None = None


def ripple_sprite(t: float) -> Sprite | None:
    """Two expanding, fading rings.  ``t`` is seconds since the click."""
    global _ripple_grid
    if t < 0.0 or t > RIPPLE_SECONDS:
        return None
    if _ripple_grid is None:
        yy, xx = np.mgrid[0:_RIPPLE_TILE, 0:_RIPPLE_TILE].astype(np.float32)
        c = _RIPPLE_TILE / 2.0
        _ripple_grid = np.hypot(xx - c, yy - c)
    d = _ripple_grid

    acc = np.zeros(d.shape, dtype=np.float32)
    for i, delay in enumerate((0.0, 0.13)):
        u = (t - delay) / (RIPPLE_SECONDS - 0.13)
        if u <= 0.0 or u >= 1.0:
            continue
        r = 12.0 + 82.0 * ease_out_cubic(u)
        width = 5.5 - 3.2 * u
        peak = (1.0 - u) ** 1.6 * (1.0 if i == 0 else 0.72)
        acc += np.exp(-(((d - r) / width) ** 2)) * peak
    # a short bright flash right under the pointer at the moment of the click
    u0 = t / 0.18
    if u0 < 1.0:
        acc += np.exp(-((d / 16.0) ** 2)) * (1.0 - u0) * 0.55
    if float(acc.max()) < 0.004:
        return None

    a = np.clip(acc, 0.0, 1.0)[:, :, None]
    rgb = np.empty((_RIPPLE_TILE, _RIPPLE_TILE, 3), dtype=np.uint8)
    rgb[:, :, 0] = 150
    rgb[:, :, 1] = 175
    rgb[:, :, 2] = 255
    return Sprite(rgb=rgb, alpha=np.ascontiguousarray(a.astype(np.float32)))


_caption_cache: dict[str, tuple[Sprite, int, int]] = {}


def caption_sprite(text: str) -> tuple[Sprite, int, int]:
    """Lower-third pill.  Returns (sprite, x, y) on the 1920x1080 canvas."""
    hit = _caption_cache.get(text)
    if hit is not None:
        return hit

    font = _font(34, semibold=True)
    probe = ImageDraw.Draw(Image.new("RGB", (8, 8)))
    box = probe.textbbox((0, 0), text, font=font)
    tw, th = box[2] - box[0], box[3] - box[1]

    pad_x, pad_y = 30, 17
    dot_r = 5
    dot_gap = 15
    pill_w = pad_x * 2 + dot_r * 2 + dot_gap + tw
    pill_h = max(68, th + pad_y * 2 + 10)
    rad = pill_h // 2

    margin = 26  # room for the pill's own shadow
    im = Image.new("RGBA", (pill_w + margin * 2, pill_h + margin * 2), (0, 0, 0, 0))

    shadow = Image.new("RGBA", im.size, (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle(
        (margin, margin + 6, margin + pill_w, margin + pill_h + 6),
        radius=rad,
        fill=(0, 0, 0, 150),
    )
    im.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(12)))

    d = ImageDraw.Draw(im)
    # Opaque, not translucent. The pill lands over the bottom-left of whatever is on
    # screen - the dashboard's sidebar footer, or a slide's own summary strip - and at
    # 88% alpha that text ghosted through it and read as a collision rather than as a
    # lower third. A lower third is meant to cover what is under it.
    # No hairline outline: at this size the 1 px light stroke read as a seam against the dark
    # dashboard rather than as an edge. The blurred shadow above is what separates the pill.
    d.rounded_rectangle(
        (margin, margin, margin + pill_w, margin + pill_h),
        radius=rad,
        fill=(12, 16, 23, 255),
    )
    cy = margin + pill_h / 2
    dx = margin + pad_x
    d.ellipse((dx, cy - dot_r, dx + dot_r * 2, cy + dot_r), fill=(*ACCENT, 255))
    d.text(
        (dx + dot_r * 2 + dot_gap, cy),
        text,
        font=font,
        fill=(*CAPTION_FG, 255),
        anchor="lm",
    )

    sp = sprite_from_image(im)
    x = 80 - margin
    y = H - 84 - pill_h - margin
    _caption_cache[text] = (sp, x, y)
    return sp, x, y


#: The dashboard's own status block, in CSS space: `.sidebar-foot` is pinned to the bottom of
#: a 220 px sticky sidebar with 18 px of padding, and holds four 12 px status lines.
#: The caption pill lands on top of it, and *partly* on top of it is what read as broken -
#: the red DNS dot poking out at the pill's left edge, "ing" surviving to the right of it,
#: "up" clipped underneath. A lower third is meant to cover what is under it, so the band is
#: repainted in the sidebar's own colour first and the pill is drawn onto a clean surface.
_FOOTER_BAND_CSS = (0.0, 776.0, 212.0, 114.0)
#: Somewhere in the sidebar that is always empty on every page: below the last nav link
#: ("Settings" ends around y=480) and well above the footer band.
_SIDEBAR_SAMPLE_CSS = (110.0, 700.0)


def _cover_sidebar_foot(
    canvas: np.ndarray,
    alpha: float,
    cam_rect: tuple[float, float, float, float] | None = None,
) -> None:
    """Repaint the sidebar's status block in its own background colour.

    ``alpha`` follows the caption's own fade, so the status lines dissolve out with the pill
    arriving rather than blinking away a beat before it. ``cam_rect`` moves and scales the
    band with the camera: a Zoom that still has the sidebar in shot slides the footer down
    and to the right, out from behind a pill that is anchored to the canvas, which is
    exactly the overlap this exists to remove. A crop that leaves the sidebar out of frame
    has nothing to cover, and says so by putting the sample point off-canvas.
    """
    if alpha <= 0.004:
        return
    sx, sy = css_to_page(*_SIDEBAR_SAMPLE_CSS)
    x, y, w, h = _FOOTER_BAND_CSS
    px, py = css_to_page(x, y)
    pw, ph = w * SCALE, h * SCALE
    if cam_rect is not None:
        sx, sy = Camera.project((sx, sy), cam_rect)
        px, py = Camera.project((px, py), cam_rect)
        k = WIN_W / cam_rect[2]
        pw, ph = pw * k, ph * k
    if not (0.0 <= sx < WIN_W and 0.0 <= sy < WIN_H):
        return  # the sidebar is not in shot, so neither is its footer
    colour = canvas[int(WIN_Y + sy), int(WIN_X + sx)].astype(np.float32)
    # never paint over the window's rounded bottom-left corner or its border
    # The rounded corner only bites in the last CORNER_RADIUS rows, which y1 already excludes,
    # so the band may run all the way to the window's left edge - and under a camera it has to,
    # or a sliver of the footer survives between the edge and the scrim.
    x0 = max(int(round(WIN_X + px)), WIN_X)
    y0 = max(int(round(WIN_Y + py)), WIN_Y)
    x1 = min(int(round(WIN_X + px + pw)), WIN_X + WIN_W)
    y1 = min(int(round(WIN_Y + py + ph)), WIN_Y + WIN_H - CORNER_RADIUS)
    if x1 <= x0 or y1 <= y0:
        return
    band = canvas[y0:y1, x0:x1]
    if alpha >= 0.996:
        band[:] = colour.astype(np.uint8)
    else:
        band[:] = (band * (1.0 - alpha) + colour * alpha + 0.5).astype(np.uint8)


def glow_sprite(w: int, h: int) -> Sprite:
    """Accent glow for a Highlight, sized for a ``w`` x ``h`` element."""
    pad = 40
    tw, th = int(w) + pad * 2, int(h) + pad * 2
    im = Image.new("RGBA", (tw, th), (0, 0, 0, 0))
    for blur, width, alpha in ((16.0, 16, 110), (6.0, 7, 150)):
        layer = Image.new("RGBA", (tw, th), (0, 0, 0, 0))
        ImageDraw.Draw(layer).rounded_rectangle(
            (pad - 4, pad - 4, pad + w + 4, pad + h + 4),
            radius=14,
            outline=(*ACCENT, alpha),
            width=width,
        )
        im.alpha_composite(layer.filter(ImageFilter.GaussianBlur(blur)))
    ImageDraw.Draw(im).rounded_rectangle(
        (pad - 4, pad - 4, pad + w + 4, pad + h + 4),
        radius=14,
        outline=(*ACCENT, 235),
        width=2,
    )
    return sprite_from_image(im)


_tap_grids: dict[int, np.ndarray] = {}


def tap_tile(scale: float) -> int:
    """Sprite side for a tap drawn at ``scale`` (canvas px per phone CSS px)."""
    return int(2 * math.ceil(TAP_MAX_R_CSS * max(0.05, scale)) + 26)


def tap_sprite(t: float, seconds: float = TAP_SECONDS, scale: float = 1.0) -> Sprite | None:
    """A finger press: a filled disc that expands and fades.  ``t`` is seconds since the tap.

    Deliberately not the desktop click ripple.  That one is two thin expanding
    *rings* drawn under an arrow pointer; this is a solid translucent disc with a
    soft edge and no pointer at all, which is what a touch looks like and what
    tells a viewer that nobody is holding a mouse.

    ``scale`` is canvas pixels per phone CSS pixel, so the circle is a fingertip on
    the screen it is touching rather than a fixed lump of canvas.
    """
    if t < 0.0 or t > seconds:
        return None
    tile = tap_tile(scale)
    d = _tap_grids.get(tile)
    if d is None:
        yy, xx = np.mgrid[0:tile, 0:tile].astype(np.float32)
        c = tile / 2.0
        d = np.hypot(xx - c, yy - c)
        _tap_grids[tile] = d

    r0 = TAP_START_R_CSS * scale
    r1 = TAP_MAX_R_CSS * scale
    shoulder = max(2.0, 5.0 * scale)
    u = t / max(1e-6, seconds)
    r = r0 + (r1 - r0) * ease_out_cubic(u)
    fade = (1.0 - u) ** 1.35

    # the disc: full inside, a soft shoulder at the rim
    disc = np.clip((r - d) / shoulder, 0.0, 1.0) * (0.19 * fade)
    # a brighter rim, so the growth is readable against a busy camera image
    rim = np.exp(-(((d - r) / max(1.6, 3.4 * scale)) ** 2)) * (0.46 * fade)
    # the contact point itself: a small bright dot that fades faster than the disc
    core = np.exp(-((d / max(4.0, 8.0 * scale)) ** 2)) * max(0.0, 1.0 - u * 2.4) * 0.50

    a = np.clip(disc + rim + core, 0.0, 0.66)
    if float(a.max()) < 0.004:
        return None
    rgb = np.empty((tile, tile, 3), dtype=np.uint8)
    rgb[:, :, 0], rgb[:, :, 1], rgb[:, :, 2] = TAP_RGB
    return Sprite(rgb=rgb, alpha=np.ascontiguousarray(a[:, :, None].astype(np.float32)))


# --------------------------------------------------------------------------
# Window chrome
# --------------------------------------------------------------------------

_chrome: dict[str, Any] = {}


def _build_chrome() -> dict[str, Any]:
    """Pre-render everything about the window frame that never changes."""
    if _chrome:
        return _chrome

    canvas = np.empty((H, W, 3), dtype=np.uint8)
    canvas[:, :] = BG

    shadow = Image.new("L", (W, H), 0)
    ImageDraw.Draw(shadow).rounded_rectangle(
        (WIN_X, WIN_Y + SHADOW_DY, WIN_X + WIN_W, WIN_Y + WIN_H + SHADOW_DY),
        radius=CORNER_RADIUS + 6,
        fill=255,
    )
    shadow = shadow.filter(ImageFilter.GaussianBlur(SHADOW_BLUR))
    sa = (np.asarray(shadow, dtype=np.float32) / 255.0 * SHADOW_ALPHA)[:, :, None]
    canvas[:] = (canvas * (1.0 - sa)).astype(np.uint8)

    # corner alpha tiles: page pixels fade out to reveal the canvas behind them
    r = CORNER_RADIUS
    ss = 8
    disc = Image.new("L", (r * 2 * ss, r * 2 * ss), 0)
    ImageDraw.Draw(disc).ellipse((0, 0, r * 2 * ss - 1, r * 2 * ss - 1), fill=255)
    disc = disc.resize((r * 2, r * 2), Image.LANCZOS)
    da = np.asarray(disc, dtype=np.float32) / 255.0
    # The rounded corners reveal the canvas *including its drop shadow*, so keep
    # the real background tiles rather than blending to a flat colour.
    corners = {}
    for name, (oy, ox) in (
        ("tl", (0, 0)),
        ("tr", (0, WIN_W - r)),
        ("bl", (WIN_H - r, 0)),
        ("br", (WIN_H - r, WIN_W - r)),
    ):
        a = {"tl": da[:r, :r], "tr": da[:r, r:], "bl": da[r:, :r], "br": da[r:, r:]}[name]
        corners[name] = (
            a[:, :, None].astype(np.float32),
            canvas[WIN_Y + oy : WIN_Y + oy + r, WIN_X + ox : WIN_X + ox + r].astype(np.float32),
        )

    # hairline border, kept as four thin strips so compositing stays cheap
    pad = 3
    bw, bh = WIN_W + pad * 2, WIN_H + pad * 2
    bim = Image.new("RGBA", (bw, bh), (0, 0, 0, 0))
    ImageDraw.Draw(bim).rounded_rectangle(
        (pad - 1, pad - 1, pad + WIN_W, pad + WIN_H),
        radius=CORNER_RADIUS + 1,
        outline=(*BORDER, 255),
        width=2,
    )
    ImageDraw.Draw(bim).rounded_rectangle(
        (pad, pad, pad + WIN_W - 1, pad + WIN_H - 1),
        radius=CORNER_RADIUS,
        outline=(255, 255, 255, 26),
        width=1,
    )
    strips = []
    t = 8
    for sub, sx, sy in (
        (bim.crop((0, 0, bw, t)), -pad, -pad),
        (bim.crop((0, bh - t, bw, bh)), -pad, WIN_H + pad - t),
        (bim.crop((0, t, t, bh - t)), -pad, -pad + t),
        (bim.crop((bw - t, t, bw, bh - t)), WIN_W + pad - t, -pad + t),
    ):
        strips.append((sprite_from_image(sub), sx, sy))

    _chrome.update(canvas=canvas, corners=corners, strips=strips)
    return _chrome


def compose_canvas(page: np.ndarray) -> np.ndarray:
    """Letterbox a 1792x1008 page layer onto the 1920x1080 window canvas."""
    ch = _build_chrome()
    canvas: np.ndarray = ch["canvas"].copy()
    canvas[WIN_Y : WIN_Y + WIN_H, WIN_X : WIN_X + WIN_W] = page

    r = CORNER_RADIUS
    for name, (oy, ox) in (
        ("tl", (0, 0)),
        ("tr", (0, WIN_W - r)),
        ("bl", (WIN_H - r, 0)),
        ("br", (WIN_H - r, WIN_W - r)),
    ):
        a, under = ch["corners"][name]
        reg = canvas[WIN_Y + oy : WIN_Y + oy + r, WIN_X + ox : WIN_X + ox + r]
        np.copyto(reg, (reg * a + under * (1.0 - a) + 0.5).astype(np.uint8))

    for sp, sx, sy in ch["strips"]:
        blit(canvas, sp, WIN_X + sx, WIN_Y + sy)
    return canvas


# --------------------------------------------------------------------------
# Page layers (the screenshots)
# --------------------------------------------------------------------------


class PageStore:
    """Loads and caches the page layers (and hi-res sources) for one scene."""

    def __init__(self, shots: Sequence[Path], fixed: Sequence[Sequence[float]] = ()) -> None:
        self._shots = list(shots)
        self._pages: dict[int, np.ndarray] = {}
        self._sources: dict[int, Image.Image] = {}
        self._canvases: dict[int, np.ndarray] = {}
        self._dimmed: dict[tuple[int, int], np.ndarray] = {}
        self._fixed_declared = [
            (
                int(r[0] * SCALE),
                int(r[1] * SCALE),
                int(math.ceil(r[2] * SCALE)),
                int(math.ceil(r[3] * SCALE)),
            )
            for r in fixed
        ]
        self._fixed_cache: dict[tuple[int, int], list[tuple[int, int, int, int]]] = {}

    def __len__(self) -> int:
        return len(self._shots)

    def page(self, idx: int) -> np.ndarray:
        idx = min(idx, len(self._shots) - 1)
        hit = self._pages.get(idx)
        if hit is None:
            hit = load_page(self._shots[idx])
            self._pages[idx] = hit
        return hit

    def source(self, idx: int) -> Image.Image:
        """The original 2x screenshot, so a Zoom resamples real detail."""
        idx = min(idx, len(self._shots) - 1)
        hit = self._sources.get(idx)
        if hit is None:
            hit = Image.open(self._shots[idx]).convert("RGB")
            hit.load()
            self._sources[idx] = hit
        return hit

    def fixed_bands(self, a_idx: int, b_idx: int) -> list[tuple[int, int, int, int]]:
        """Regions that do not move when the page scrolls (fixed nav, sticky bar).

        Declared rects from ``geometry.json['__fixed__']`` win; otherwise the
        bands are detected by comparing the two scroll states, because a
        ``position: fixed`` element is pixel-identical in both.
        """
        if self._fixed_declared:
            return self._fixed_declared
        key = (a_idx, b_idx)
        hit = self._fixed_cache.get(key)
        if hit is not None:
            return hit
        hit = detect_fixed_bands(self.page(a_idx), self.page(b_idx))
        self._fixed_cache[key] = hit
        return hit

    def canvas(self, idx: int) -> np.ndarray:
        """Fully composed 1920x1080 canvas for a static shot (the fast path)."""
        idx = min(idx, len(self._shots) - 1)
        hit = self._canvases.get(idx)
        if hit is None:
            hit = compose_canvas(self.page(idx))
            self._canvases[idx] = hit
        return hit

    def dimmed(self, idx: int, step: int, steps: int) -> np.ndarray:
        """Page dimmed by ``step/steps`` of DIM_STRENGTH, cached per step."""
        key = (min(idx, len(self._shots) - 1), step)
        hit = self._dimmed.get(key)
        if hit is None:
            hit = dim_page(self.page(idx), step, steps)
            self._dimmed[key] = hit
        return hit

    def release(self) -> None:
        self._pages.clear()
        self._canvases.clear()
        self._dimmed.clear()
        for im in self._sources.values():
            im.close()
        self._sources.clear()
        self._fixed_cache.clear()


def dim_page(page: np.ndarray, step: int, steps: int) -> np.ndarray:
    f = 1.0 - DIM_STRENGTH * (step / steps)
    lut = np.clip(np.arange(256) * f, 0, 255).astype(np.uint8)
    return lut[page]


class DimCache:
    """Memoises the dim scrim for a page the camera is holding still.

    A Zoom's hold phase returns the same array object frame after frame, so the
    17 ms LUT pass only has to run when the picture or the fade step changes.
    """

    def __init__(self) -> None:
        self._key: tuple[int, int] | None = None
        self._src: np.ndarray | None = None
        self._out: np.ndarray | None = None

    def get(self, page: np.ndarray, step: int, steps: int) -> np.ndarray:
        key = (id(page), step)
        if key == self._key and self._out is not None and self._src is page:
            return self._out
        out = dim_page(page, step, steps)
        self._key, self._src, self._out = key, page, out
        return out


def detect_fixed_bands(
    a: np.ndarray, b: np.ndarray, tol: int = 6
) -> list[tuple[int, int, int, int]]:
    """Find the leading column band and top/bottom row bands common to both shots.

    Used to keep a ``position: fixed`` sidebar or sticky header still while the
    rest of the page scrolls.  Bands are capped at 45% of the axis so a page
    that barely changed cannot be mistaken for one giant fixed element.
    """
    same = np.abs(a.astype(np.int16) - b.astype(np.int16)).max(axis=2) <= tol
    bands: list[tuple[int, int, int, int]] = []

    def has_content(x: int, y: int, w: int, h: int) -> bool:
        """Flat background is identical in both shots too - ignore it."""
        return bool(a[y : y + h, x : x + w].std() > 4.0)

    col_frac = same.mean(axis=0)
    w = 0
    while w < int(WIN_W * 0.45) and col_frac[w] > 0.985:
        w += 1
    if w >= 24 and has_content(0, 0, w, WIN_H):
        bands.append((0, 0, w, WIN_H))
    else:
        w = 0

    row_frac = same[:, w:].mean(axis=1)
    h = 0
    while h < int(WIN_H * 0.40) and row_frac[h] > 0.985:
        h += 1
    if h >= 16 and has_content(w, 0, WIN_W - w, h):
        bands.append((w, 0, WIN_W - w, h))

    hb = 0
    while hb < int(WIN_H * 0.15) and row_frac[WIN_H - 1 - hb] > 0.985:
        hb += 1
    if hb >= 16 and has_content(w, WIN_H - hb, WIN_W - w, hb):
        bands.append((w, WIN_H - hb, WIN_W - w, hb))
    return bands


def load_page(path: Path) -> np.ndarray:
    """Load a shot and fit it to the 1792x1008 page layer.  Never upscales."""
    if not path.exists():
        raise FileNotFoundError(f"missing shot: {path}")
    im = Image.open(path).convert("RGB")
    if im.size == (WIN_W, WIN_H):
        return np.ascontiguousarray(np.asarray(im, dtype=np.uint8))
    if im.width >= WIN_W and im.height >= WIN_H:
        im = im.resize((WIN_W, WIN_H), Image.LANCZOS)
        return np.ascontiguousarray(np.asarray(im, dtype=np.uint8))
    log.warning(
        "shot %s is %dx%d, smaller than the %dx%d window - centring it rather "
        "than upscaling",
        path.name,
        im.width,
        im.height,
        WIN_W,
        WIN_H,
    )
    out = np.empty((WIN_H, WIN_W, 3), dtype=np.uint8)
    out[:, :] = BG
    ox, oy = (WIN_W - im.width) // 2, (WIN_H - im.height) // 2
    out[oy : oy + im.height, ox : ox + im.width] = np.asarray(im, dtype=np.uint8)
    return out


def blend_pages(a: np.ndarray, b: np.ndarray, t: float) -> np.ndarray:
    """Cross-fade two page layers with integer maths (fast enough at 1792x1008)."""
    if t <= 0.001:
        return a
    if t >= 0.999:
        return b
    k = int(round(t * 64))
    return ((a.astype(np.uint16) * (64 - k) + b.astype(np.uint16) * k) >> 6).astype(np.uint8)


def blend_frames(a: np.ndarray, b: np.ndarray, t: float) -> np.ndarray:
    """Cross-fade two full canvases (used for the scene-to-scene dissolve)."""
    if t <= 0.001:
        return a
    if t >= 0.999:
        return b
    k = int(round(t * 64))
    return ((a.astype(np.uint16) * (64 - k) + b.astype(np.uint16) * k) >> 6).astype(np.uint8)


# --------------------------------------------------------------------------
# Phone layers (the Lens shots)
# --------------------------------------------------------------------------

PHONE_KINDS = frozenset({"phone", "phone_pair", "phonepair", "phone-pair"})


def is_phone_kind(kind: str) -> bool:
    return str(kind or "").strip().lower() in PHONE_KINDS


def is_pair_kind(kind: str) -> bool:
    return str(kind or "").strip().lower() in {"phone_pair", "phonepair", "phone-pair"}


_phone_module_cache: list[Any] = []


def phone_module() -> Any | None:
    """``video/phone.py`` if the capture package has landed it, else ``None``.

    The drawn phone body belongs to the capture package (CONTRACT_V2 V2), so it
    is used whenever it is importable.  The fallback below exists so this module
    can be developed and self-tested on its own, and so a missing phone.py is a
    warning rather than a dead pipeline.
    """
    if not _phone_module_cache:
        try:
            import phone as _phone  # type: ignore[import-not-found]

            _phone_module_cache.append(_phone)
        except Exception as exc:  # noqa: BLE001 - any import failure is the same story
            log.info(
                "video/phone.py is not importable (%s: %s) - drawing the phone body here instead",
                type(exc).__name__, exc,
            )
            _phone_module_cache.append(None)
    return _phone_module_cache[0]


def _fallback_phone_frame(screen: Image.Image) -> tuple[Image.Image, tuple[int, int, int, int]]:
    """Draw a phone body around ``screen``.  Returns (RGBA image, screen rect in it).

    Only used when ``video/phone.py`` is not importable.  Everything is drawn
    programmatically at the screen's own resolution (3x), so the one downscale
    to the canvas happens afterwards and the text stays crisp.
    """
    sw, sh = screen.size
    bez = max(6, int(round(sh * 0.0295)))  # uniform bezel
    pad = max(8, int(round(sh * 0.040)))  # room for the drop shadow
    r_out = int(round(sh * 0.082))
    r_in = max(2, r_out - bez)
    w, h = sw + 2 * bez + 2 * pad, sh + 2 * bez + 2 * pad
    body = (pad, pad, pad + sw + 2 * bez, pad + sh + 2 * bez)

    im = Image.new("RGBA", (w, h), (0, 0, 0, 0))

    shadow = Image.new("L", (w, h), 0)
    ImageDraw.Draw(shadow).rounded_rectangle(
        (body[0], body[1] + int(pad * 0.55), body[2], body[3] + int(pad * 0.55)),
        radius=r_out, fill=210,
    )
    shadow = shadow.filter(ImageFilter.GaussianBlur(pad * 0.55))
    im.putalpha(shadow)
    im.paste((0, 0, 0), (0, 0, w, h), shadow)

    draw = ImageDraw.Draw(im)
    draw.rounded_rectangle(body, radius=r_out, fill=(8, 10, 14, 255))
    # rim highlight: a hairline of reflected light around the body
    draw.rounded_rectangle(body, radius=r_out, outline=(120, 132, 156, 150), width=max(2, bez // 10))
    draw.rounded_rectangle(
        (body[0] + bez - 2, body[1] + bez - 2, body[2] - bez + 2, body[3] - bez + 2),
        radius=r_in + 2, outline=(0, 0, 0, 210), width=max(2, bez // 8),
    )

    sx, sy = pad + bez, pad + bez
    mask = Image.new("L", (sw, sh), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, sw - 1, sh - 1), radius=r_in, fill=255)
    im.paste(screen.convert("RGB"), (sx, sy), mask)

    # speaker slot
    slot_w, slot_h = int(sw * 0.20), max(3, int(sh * 0.0075))
    cx = pad + bez + sw // 2
    slot_y = pad + bez // 2 - slot_h // 2
    draw.rounded_rectangle(
        (cx - slot_w // 2, slot_y, cx + slot_w // 2, slot_y + slot_h),
        radius=slot_h, fill=(30, 34, 44, 255),
    )
    return im, (sx, sy, sw, sh)


Rect4 = tuple[float, float, float, float]


def _frame_geometry(framed: Image.Image, screen_size: tuple[int, int]) -> tuple[Rect4, Rect4]:
    """``(body rect, screen rect)`` inside a framed phone drawn by another module.

    The body is the opaque part of the image - a drop shadow is translucent, so a
    threshold removes it, which matters because the shadow is what makes "70% of
    frame height" mean two different things.  Assuming the bezel is the same
    thickness on all four sides - which is what every drawn phone body in this
    project does - the screen height then solves exactly:
    ``body_h - s == body_w - a*s`` for screen aspect ``a``.
    """
    alpha = np.asarray(framed.convert("RGBA"), dtype=np.uint8)[:, :, 3]
    solid = alpha > 190
    rows = np.flatnonzero(solid.any(axis=1))
    cols = np.flatnonzero(solid.any(axis=0))
    if not rows.size or not cols.size:
        whole = (0.0, 0.0, float(framed.width), float(framed.height))
        return whole, whole
    by, bx = float(rows[0]), float(cols[0])
    bh, bw = float(rows[-1] - rows[0] + 1), float(cols[-1] - cols[0] + 1)
    body = (bx, by, bw, bh)
    a = screen_size[0] / screen_size[1]
    s_h = (bh - bw) / (1.0 - a)
    bez = (bh - s_h) / 2.0
    if 0.55 * bh <= s_h <= bh and bez >= 0.0:
        return body, (bx + bez, by + bez, a * s_h, s_h)
    log.warning(
        "could not infer the screen rect inside the phone frame "
        "(body %.0fx%.0f -> screen height %.1f); using the whole body",
        bw, bh, s_h,
    )
    return body, body


def frame_phone(screen: Image.Image, body_height: float) -> tuple[Image.Image, Rect4, Rect4]:
    """Composite a Lens screen into a phone body whose *body* is ``body_height`` px tall.

    Returns ``(RGBA image, screen rect, body rect)``.  ``body_height`` is measured
    on the phone itself, not on the returned image: the frame carries a drop
    shadow, and sizing to the image would quietly make the phone a tenth smaller
    than CONTRACT_V2 V5 asks for, which is a tenth off the screen text too.

    The 3x screen is resampled exactly once - the frame is drawn at the
    screenshot's own resolution, then the finished frame is scaled down in a
    single LANCZOS pass.
    """
    mod = phone_module()
    fn = getattr(mod, "phone_frame", None) if mod is not None else None
    if fn is None:
        natural, _ = _fallback_phone_frame(screen)
        body, screen_rect_f = _frame_geometry(natural, screen.size)
    else:
        natural = fn(screen)
        if not isinstance(natural, Image.Image):
            raise ComposeError(
                f"phone.phone_frame returned {type(natural).__name__}, expected a PIL Image"
            )
        natural = natural.convert("RGBA")
        body, screen_rect_f = _frame_geometry(natural, screen.size)
        rect_fn = getattr(mod, "screen_rect", None)
        if callable(rect_fn):
            try:
                r = tuple(float(v) for v in rect_fn(natural))
                if len(r) == 4 and r[2] > 0 and r[3] > 0:
                    screen_rect_f = r  # type: ignore[assignment]
            except Exception as exc:  # noqa: BLE001
                log.warning("phone.screen_rect failed (%s); inferring it instead", exc)

    k = body_height / max(1.0, body[3])
    framed = natural.resize(
        (max(2, int(round(natural.width * k))), max(2, int(round(natural.height * k)))),
        Image.LANCZOS,
    )
    natural.close()
    return (
        framed,
        tuple(v * k for v in screen_rect_f),  # type: ignore[return-value]
        tuple(v * k for v in body),  # type: ignore[return-value]
    )


def _rounded_mask(w: int, h: int, radius: int) -> np.ndarray:
    m = Image.new("L", (w, h), 0)
    ImageDraw.Draw(m).rounded_rectangle((0, 0, w - 1, h - 1), radius=max(0, radius), fill=255)
    return (np.asarray(m, dtype=np.float32) / 255.0)[:, :, None]


_phone_backdrop_cache: dict[int, np.ndarray] = {}


def phone_backdrop(cx: int) -> np.ndarray:
    """The canvas a phone stands on: the film's background plus one soft accent glow."""
    key = int(cx) // 16
    hit = _phone_backdrop_cache.get(key)
    if hit is not None:
        return hit
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    d = np.hypot((xx - key * 16) / 1.35, (yy - H * 0.52) / 1.0)
    g = (np.clip(1.0 - d / 780.0, 0.0, 1.0) ** 1.8 * 0.20)[:, :, None]
    base = np.empty((H, W, 3), dtype=np.float32)
    base[:, :] = BG
    out = np.clip(base * (1.0 - g) + np.asarray(ACCENT, dtype=np.float32) * g, 0, 255).astype(
        np.uint8
    )
    _phone_backdrop_cache[key] = out
    return out


def scene_card(im: Image.Image, max_w: int, max_h: int) -> tuple[Sprite, int, int, int]:
    """The illustrated scene as a framed card.

    Returns ``(sprite, card_w, card_h, margin)``; the sprite is ``margin`` px
    bigger on every side than the card, because it carries its own drop shadow.
    """
    k = min(max_w / im.width, max_h / im.height)
    cw, ch = max(2, int(im.width * k)), max(2, int(im.height * k))
    card = im.convert("RGB").resize((cw, ch), Image.LANCZOS)
    margin = 30
    out = Image.new("RGBA", (cw + margin * 2, ch + margin * 2), (0, 0, 0, 0))

    shadow = Image.new("L", out.size, 0)
    ImageDraw.Draw(shadow).rounded_rectangle(
        (margin, margin + 12, margin + cw, margin + ch + 12), radius=CORNER_RADIUS + 4, fill=190
    )
    out.putalpha(shadow.filter(ImageFilter.GaussianBlur(16)))
    out.paste((0, 0, 0), (0, 0, *out.size), out.getchannel("A"))

    mask = Image.new("L", (cw, ch), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, cw - 1, ch - 1), radius=CORNER_RADIUS, fill=255)
    out.paste(card, (margin, margin), mask)
    ImageDraw.Draw(out).rounded_rectangle(
        (margin, margin, margin + cw - 1, margin + ch - 1),
        radius=CORNER_RADIUS, outline=(*BORDER, 255), width=2,
    )
    return sprite_from_image(out), cw, ch, margin


def _dashed_line(
    draw: ImageDraw.ImageDraw,
    p0: tuple[float, float],
    p1: tuple[float, float],
    colour: tuple[int, int, int, int],
    width: int = 3,
    dash: float = 16.0,
    gap: float = 12.0,
) -> None:
    length = math.dist(p0, p1)
    if length <= 1.0:
        return
    ux, uy = (p1[0] - p0[0]) / length, (p1[1] - p0[1]) / length
    pos = 0.0
    while pos < length:
        end = min(length, pos + dash)
        draw.line(
            [(p0[0] + ux * pos, p0[1] + uy * pos), (p0[0] + ux * end, p0[1] + uy * end)],
            fill=colour, width=width,
        )
        pos = end + gap


def sight_line_sprite(
    apex: tuple[float, float],
    aim: tuple[float, float],
    spread: float,
    fill_until: float | None = None,
) -> Sprite:
    """The 'this phone is looking at that thing' overlay: a view cone and a target ring.

    ``fill_until`` is the right edge of the illustration: the cone's translucent
    fill is cut off there so it reads as a beam crossing the gap rather than as a
    blue wash over half the picture, while the dashed edges carry on to the target.
    """
    im = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    ax, ay = aim
    top = (ax, ay - spread)
    bottom = (ax, ay + spread)

    cone = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(cone).polygon([apex, top, bottom], fill=(*ACCENT, 30))
    if fill_until is not None:
        edge = int(clamp(fill_until, 0, W))
        fade = np.asarray(cone, dtype=np.uint8).copy()
        ramp = 90
        fade[:, :max(0, edge - ramp), 3] = 0
        if ramp > 0 and edge > 0:
            lo = max(0, edge - ramp)
            grad = np.linspace(0.0, 1.0, edge - lo, dtype=np.float32)[None, :]
            fade[:, lo:edge, 3] = (fade[:, lo:edge, 3] * grad).astype(np.uint8)
        cone = Image.fromarray(fade, "RGBA")
    im.alpha_composite(cone)

    _dashed_line(d, apex, top, (*ACCENT, 170), width=3)
    _dashed_line(d, apex, bottom, (*ACCENT, 170), width=3)

    # Focus brackets, not a bullseye: this lands on the sticker, and the sticker is the
    # thing the shot is about. One faint ring for the eye, four corner ticks for the
    # framing, and nothing at all over the code itself.
    outer = spread
    d.ellipse((ax - outer, ay - outer, ax + outer, ay + outer), outline=(*ACCENT, 95), width=2)
    tick = outer * 0.30
    for sx, sy in ((-1, -1), (1, -1), (-1, 1), (1, 1)):
        cx, cy = ax + sx * outer, ay + sy * outer
        d.line([(cx, cy), (cx - sx * tick, cy)], fill=(*ACCENT, 235), width=3)
        d.line([(cx, cy), (cx, cy - sy * tick)], fill=(*ACCENT, 235), width=3)
    return sprite_from_image(im)


def detect_fixed_rows(
    a: np.ndarray, b: np.ndarray, tol: int = 6, cap_frac: float = 0.70
) -> list[tuple[int, int]]:
    """Leading/trailing row bands identical in both scroll states, as ``(y0, y1)``.

    The phone equivalent of :func:`detect_fixed_bands`.  A ``PhoneScroll`` scrolls
    the Lens card's own body, so the status bar, the viewfinder above the card and
    any pinned footer are pixel-identical in both shots and must not slide with the
    content - which is exactly what these bands hold still.

    ``cap_frac`` is deliberately looser than the desktop's 45%: on a phone the
    viewfinder takes the top third and the card's pinned header another fifth, so
    well over half the screen legitimately does not move.
    """
    h = a.shape[0]
    same = np.abs(a.astype(np.int16) - b.astype(np.int16)).max(axis=2) <= tol
    row_frac = same.mean(axis=1)
    cap = int(h * cap_frac)
    bands: list[tuple[int, int]] = []

    top = 0
    while top < cap and row_frac[top] > 0.985:
        top += 1
    if top >= 8 and float(a[:top].std()) > 4.0:
        bands.append((0, top))

    bot = 0
    while bot < cap and row_frac[h - 1 - bot] > 0.985:
        bot += 1
    if bot >= 8 and float(a[h - bot :].std()) > 4.0:
        bands.append((h - bot, h))
    return bands


class PhoneStore:
    """Builds and caches the composed canvas for every phone state in one scene.

    A scene has a handful of phone states, so everything here is done once per
    state and then reused: framing the 3x screen, the single downscale to the
    canvas, the illustrated scene's card, the view cone, and the finished
    1920x1080 canvas.  Per frame the store only hands back a cached array (or,
    during a ``PhoneScroll``, splices a translated strip into the screen rect).
    """

    def __init__(self, states: Sequence[ShotState], scene_id: str = "?") -> None:
        self._states = list(states)
        self._scene_id = scene_id
        self._entries: dict[int, dict[str, Any]] = {}
        self._strips: dict[tuple[int, int], tuple[np.ndarray, int]] = {}

    # -- construction -------------------------------------------------------

    def _entry(self, idx: int) -> dict[str, Any]:
        idx = min(max(idx, 0), len(self._states) - 1)
        hit = self._entries.get(idx)
        if hit is not None:
            return hit
        st = self._states[idx]
        if not st.png.exists():
            raise FileNotFoundError(f"[{self._scene_id}] missing phone shot: {st.png}")
        with Image.open(st.png) as raw:
            screen = raw.convert("RGB")
            screen.load()

        pair = is_pair_kind(st.kind)
        frac = PHONE_PAIR_BODY_FRAC if pair else PHONE_BODY_FRAC
        framed, rect, body = frame_phone(screen, H * frac)
        screen.close()
        sx, sy = int(round(rect[0])), int(round(rect[1]))
        sw, sh = max(1, int(round(rect[2]))), max(1, int(round(rect[3])))
        bx, by = int(round(body[0])), int(round(body[1]))
        bw, bh = max(1, int(round(body[2]))), max(1, int(round(body[3])))

        # placed by the phone's *body*, so the drop shadow does not shift it
        if pair:
            px = W - PHONE_MARGIN - (bx + bw)
        else:
            px = (W - bw) // 2 - bx
        py = (H - bh) // 2 - by

        canvas = phone_backdrop(int(W * 0.5) if pair else px + bx + bw // 2).copy()
        entry: dict[str, Any] = {
            "sprite": sprite_from_image(framed),
            "framed": framed,
            "pos": (px, py),
            # the screen rect on the 1920x1080 canvas
            "screen": (px + sx, py + sy, sw, sh),
            "body": (px + bx, py + by, bw, bh),
            "radius": int(round(sh * 0.055)),
            "pair": pair,
        }

        if pair:
            scene_png = st.scene_png
            if scene_png is None or not Path(scene_png).exists():
                raise ComposeError(
                    f"[{self._scene_id}] state {idx} is a PhonePair but has no illustrated "
                    f"scene image (looked for {scene_png!r}). capture.py must record it as "
                    f"'scene_png' in shots_manifest.json, or leave it next to the phone shot "
                    f"as <scene>_<n>_scene.png."
                )
            with Image.open(scene_png) as raw_scene:
                illo = raw_scene.convert("RGB")
                illo.load()
            avail_w = (px + bx) - PHONE_PAIR_GAP - PHONE_MARGIN
            avail_h = int(H * 0.72)
            card, cw, ch, margin = scene_card(illo, max(120, avail_w), avail_h)
            illo.close()
            cx0 = PHONE_MARGIN + max(0, (avail_w - cw) // 2)
            cy0 = (H - ch) // 2
            blit(canvas, card, cx0 - margin, cy0 - margin)
            fx, fy = st.aim or PHONE_AIM_DEFAULT
            aim = (cx0 + cw * float(fx), cy0 + ch * float(fy))
            apex = (px + bx, py + by + bh * 0.30)
            blit(
                canvas,
                # the brackets want to sit just outside the sticker, which is about a
                # sixth of the illustration's height in scene_render.py's framing
                sight_line_sprite(apex, aim, spread=min(ch * 0.17, 128.0), fill_until=cx0 + cw),
                0,
                0,
            )

        blit(canvas, entry["sprite"], px, py)
        entry["canvas"] = canvas

        # A burst state: pre-downscale every captured frame's screen once, so playback is
        # one masked paste per output frame. The screen is resampled straight from the 3x
        # screenshot to the composited screen rect, which is what frame_phone does to the
        # first one, so nothing pops between frame 0 and the rest.
        if st.frames:
            mask = _rounded_mask(sw, sh, entry["radius"])
            screens: list[np.ndarray] = []
            for path in st.all_frames:
                with Image.open(path) as raw_frame:
                    small = raw_frame.convert("RGB").resize((sw, sh), Image.LANCZOS)
                    screens.append(np.asarray(small, dtype=np.uint8).copy())
            entry["burst"] = screens
            entry["burst_mask"] = mask
            entry["burst_interval"] = float(st.frame_interval) or (1.0 / 15.0)
            log.info(
                "[%s] state %d plays a %d-frame burst at %.0f ms",
                self._scene_id, idx, len(screens), entry["burst_interval"] * 1000.0,
            )

        self._entries[idx] = entry
        return entry

    # -- what the frame loop asks for ---------------------------------------

    def canvas(self, idx: int) -> np.ndarray:
        return self._entry(idx)["canvas"]

    def has_burst(self, idx: int) -> bool:
        return bool(self._entry(idx).get("burst"))

    def canvas_at(self, idx: int, t: float) -> np.ndarray:
        """The canvas for this state at scene time ``t``.

        Identical to :meth:`canvas` unless the state was captured as a burst, in which case
        the viewfinder plays: the handheld drift that ``scene_render.py`` baked into
        ``build/scene_camera.y4m`` (CONTRACT_V2 V3.2) reaches the finished film here and
        nowhere else. The burst loops, forwards then backwards, so a six-second clip
        sampled for sixteen seconds never jump-cuts back to its first frame.
        """
        entry = self._entry(idx)
        burst: list[np.ndarray] | None = entry.get("burst")
        if not burst:
            return entry["canvas"]
        n = len(burst)
        if n == 1:
            return entry["canvas"]
        step = int(max(0.0, t) / entry["burst_interval"])
        period = 2 * n - 2
        k = step % period
        k = k if k < n else period - k
        canvas = entry["canvas"].copy()
        sx, sy, sw, sh = entry["screen"]
        m = entry["burst_mask"]
        region = canvas[sy : sy + sh, sx : sx + sw]
        np.copyto(region, (region * (1.0 - m) + burst[k] * m + 0.5).astype(np.uint8))
        return canvas

    def css_scale(self, idx: int) -> float:
        """Canvas pixels per phone CSS pixel for this state's composited screen."""
        return float(self._entry(idx)["screen"][2]) / PHONE_CSS_W

    def to_canvas(self, idx: int, css: tuple[float, float]) -> tuple[float, float]:
        """A point in the 390x844 Lens viewport -> a point on the 1920x1080 canvas."""
        sx, sy, sw, sh = self._entry(idx)["screen"]
        x, y = float(css[0]), float(css[1])
        # capture.py may report a tap target in device pixels (3x); treat anything
        # far outside the CSS viewport as such rather than putting the tap off-screen
        if x > PHONE_CSS_W * 1.2 or y > PHONE_CSS_H * 1.2:
            x, y = x / 3.0, y / 3.0
        return (sx + x / PHONE_CSS_W * sw, sy + y / PHONE_CSS_H * sh)

    def _scroll_band(
        self, frm: int, to: int, crop_a: np.ndarray, crop_b: np.ndarray, sh: int
    ) -> tuple[int, int]:
        """Which rows of the composited screen a PhoneScroll is allowed to move.

        Prefer the rect ``phone.py`` measured for the element that actually scrolls. The
        fallback - differencing the two screenshots and calling the identical rows fixed -
        is right on a static page and *wrong* on Lens: the rows above the card are a live
        camera feed, so two captures of the same card at different offsets differ up there
        by a few units of noise, the top band is never detected, and the whole screen gets
        stacked. That is the tear at 11:30 in the v2 cut - the card's headline clipped at a
        hard edge with a band of viewfinder spliced under it and a second drag handle below
        that.
        """
        rect = self._states[frm].scroller or self._states[to].scroller
        if rect is not None:
            sy_screen = self._entry(frm)["screen"][3]
            k = sy_screen / PHONE_CSS_H
            y0 = int(round(rect[1] * k))
            y1 = int(round((rect[1] + rect[3]) * k))
            y0 = max(0, min(sh, y0))
            y1 = max(y0, min(sh, y1))
            if y1 - y0 >= 40:
                return y0, y1
            log.warning(
                "[%s] the declared scroller rect %r is only %d px tall on the composited "
                "screen; falling back to differencing", self._scene_id, rect, y1 - y0,
            )
        y0, y1 = 0, sh
        for band_y0, band_y1 in detect_fixed_rows(crop_a, crop_b):
            if band_y0 == 0:
                y0 = band_y1
            elif band_y1 >= sh:
                y1 = band_y0
        if y1 - y0 < 40:  # nothing sensible left to move
            y0, y1 = 0, sh
        return y0, y1

    def _strip(self, swap: Swap) -> tuple[np.ndarray, int, tuple[int, int]]:
        """The scrolling part of the screen, stacked into the strip it came from.

        Returns ``(strip, dy, (y0, y1))`` where ``y0..y1`` is the band of screen
        rows that actually moves.  Only that band is stacked: a ``PhoneScroll``
        moves the Lens card's body while the viewfinder above it and the card's
        own header stay put, and stacking the whole screen would drag a second
        copy of that header up through the frame.
        """
        key = (swap.frm, swap.to)
        hit = self._strips.get(key)
        if hit is not None:
            return hit  # type: ignore[return-value]
        a = self._entry(swap.frm)
        b = self._entry(swap.to)
        sx, sy, sw, sh = a["screen"]
        dy = int(round(abs(swap.dy_css) * (sh / PHONE_CSS_H)))
        crop_a = a["canvas"][sy : sy + sh, sx : sx + sw]
        bx, by, _bw, _bh = b["screen"]
        crop_b = b["canvas"][by : by + sh, bx : bx + sw]
        if dy <= 0 or crop_a.shape != crop_b.shape:
            out = (np.ascontiguousarray(crop_b), 0, (0, sh))
        else:
            y0, y1 = self._scroll_band(swap.frm, swap.to, crop_a, crop_b, sh)
            band_h = y1 - y0
            if dy >= band_h:
                # No overlap between the two screens: the rows in between were never
                # captured, so there is no strip to translate. Cross-fade instead of
                # scrolling through pixels that do not exist.
                log.info(
                    "[%s] a %.0f px scroll is longer than the %d px it scrolls, so states "
                    "%d->%d cross-fade rather than glide",
                    self._scene_id, abs(swap.dy_css), band_h, swap.frm, swap.to,
                )
                out = (np.ascontiguousarray(crop_b), 0, (y0, y1))
                self._strips[key] = out  # type: ignore[assignment]
                return out  # type: ignore[return-value]
            tall = np.empty((band_h + dy, sw, 3), dtype=np.uint8)
            if swap.dy_css > 0:  # scrolling down: A on top, B below
                tall[:band_h] = crop_a[y0:y1]
                tall[dy:] = crop_b[y0:y1]
            else:
                tall[:band_h] = crop_b[y0:y1]
                tall[dy:] = crop_a[y0:y1]
            out = (tall, dy, (y0, y1))
        self._strips[key] = out  # type: ignore[assignment]
        return out  # type: ignore[return-value]

    def scroll_canvas(self, swap: Swap, progress: float) -> np.ndarray:
        """A mid-``PhoneScroll`` canvas: the screen content translated inside the bezel."""
        a = self._entry(swap.frm)
        sx, sy, sw, sh = a["screen"]
        strip, dy, (y0, y1) = self._strip(swap)
        if dy <= 0:
            # No captured strip between these two offsets, so this is a cut, not a glide. It
            # used to dissolve across the whole PhoneScroll — 1.8 s on scene 19's travel past
            # six findings — which put two complete card bodies on screen at 50/50 for about
            # 0.8 s: "Problems" and "Exposed" superimposed on one baseline, the count pill
            # reading a blend of 6 and 4, a LOW and a HIGH badge stacked at the same y. Text
            # dissolved through text is unreadable, and it landed exactly under the sentence
            # naming the section. Hold each end still and put the dissolve in the middle, at
            # the same 400 ms the film uses between scenes — the same treatment the desktop
            # non-overlapping scroll already gets through CUT_DISSOLVE_HOLD.
            return blend_frames(
                a["canvas"], self.canvas(swap.to),
                ease_in_out_cubic(_cut_progress(swap, progress)),
            )
        u = ease_in_out_cubic(progress)
        off = int(round(dy * u)) if swap.dy_css > 0 else int(round(dy * (1.0 - u)))
        window = strip[off : off + (y1 - y0)]
        canvas = a["canvas"].copy()
        # the screen has rounded corners, so the moving content is composited
        # through the same rounded mask rather than pasted as a square
        m = _rounded_mask(sw, sh, a["radius"])[y0:y1]
        region = canvas[sy + y0 : sy + y1, sx : sx + sw]
        np.copyto(region, (region * (1.0 - m) + window * m + 0.5).astype(np.uint8))
        return canvas

    def release(self) -> None:
        for entry in self._entries.values():
            im = entry.get("framed")
            if isinstance(im, Image.Image):
                im.close()
        self._entries.clear()
        self._strips.clear()


# --------------------------------------------------------------------------
# The scene plan: actions -> a timeline the frame loop can evaluate
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MoveSeg:
    t0: float
    t1: float
    p0: tuple[float, float]
    p1: tuple[float, float]


@dataclass(frozen=True)
class ClickEvt:
    t: float


@dataclass(frozen=True)
class TapEvt:
    """A finger press on the phone screen, in the 390x844 Lens viewport."""

    t: float
    css: tuple[float, float]
    seconds: float = TAP_SECONDS


@dataclass(frozen=True)
class Swap:
    """A change of visual state: a cross-fade, or an animated scroll."""

    t0: float
    t1: float
    frm: int
    to: int
    kind: str  # "fade" | "scroll"
    dy_css: float = 0.0


@dataclass(frozen=True)
class HighlightEvt:
    t0: float
    t1: float
    rect: tuple[float, float, float, float]  # page-layer pixels


@dataclass(frozen=True)
class CameraEvt:
    t0: float
    t1: float
    hold_until: float
    t_out: float
    rect: tuple[float, float, float, float]  # page-layer pixels
    #: True for a real Zoom (resample from the 2x source); False for slide drift
    hires: bool = True
    #: A Zoom eases in and out of its push. A slide drift runs at a constant rate: an
    #: ease-in-out spread over a 40 s slide has a near-zero derivative at both ends, which
    #: is exactly the dead-still opening and closing seconds this drift exists to remove.
    linear: bool = False


@dataclass(frozen=True)
class ShotState:
    """One visual state of a scene, as recorded in ``build/shots_manifest.json``."""

    png: Path
    scroll: float = 0.0
    kind: str = "page"  # "page" | "slide" | "phone" | "phone_pair"
    path: str = ""
    #: the Lens screen state ("scan", "card", "picker", "unknown") - phone shots only
    state: str = ""
    #: the illustrated scene that stands beside the phone - ``phone_pair`` only
    scene_png: Path | None = None
    #: where in that illustration the phone is pointed, as fractions of the image
    aim: tuple[float, float] | None = None
    #: Viewport rect (390x844 CSS) of the element a PhoneScroll moves, when it is not the
    #: window. Measured by phone.py; the compositor uses it instead of guessing which rows
    #: are fixed by differencing two screenshots - which cannot work when the rows above the
    #: scroller are a live camera feed.
    scroller: tuple[float, float, float, float] | None = None
    #: Frames after the first, for a state captured as a burst, in order.
    frames: tuple[Path, ...] = ()
    #: Seconds between those frames, as captured.
    frame_interval: float = 0.0

    @property
    def is_phone(self) -> bool:
        return is_phone_kind(self.kind)

    @property
    def all_frames(self) -> tuple[Path, ...]:
        return (self.png, *self.frames)


@dataclass
class ScenePlan:
    scene_id: str
    duration: float
    n_frames: int
    states: list[ShotState]
    caption: str | None = None
    moves: list[MoveSeg] = field(default_factory=list)
    clicks: list[ClickEvt] = field(default_factory=list)
    taps: list[TapEvt] = field(default_factory=list)
    swaps: list[Swap] = field(default_factory=list)
    highlights: list[HighlightEvt] = field(default_factory=list)
    cameras: list[CameraEvt] = field(default_factory=list)
    cursor_start: tuple[float, float] = DEFAULT_CURSOR_START
    cursor_end: tuple[float, float] = DEFAULT_CURSOR_START
    show_cursor: bool = False
    #: Indices of the states that are slides. The cursor is a dashboard prop: it has nothing
    #: to point at on a title card, and leaving it parked over the headline of the "Day to
    #: day" slide read as a position carried over from the previous scene rather than as a
    #: gesture. Every scene whose actions start on a slide and finish on a page hits this.
    slide_states: frozenset[int] = frozenset()
    #: Indices of the states that carry the dashboard sidebar (every ``/`` page, but not
    #: ``/lens/*``, which has none). Only these get the caption's footer repaint.
    sidebar_states: frozenset[int] = frozenset()
    #: Indices of the states that are phone shots (``Phone`` or ``PhonePair``). These are
    #: composed by :class:`PhoneStore` instead of the window-chrome path, and the desktop
    #: cursor never appears over them: a phone is touched, not pointed at.
    phone_states: frozenset[int] = frozenset()
    #: CSS-space rects of position:fixed chrome, from geometry["__fixed__"]
    fixed: list[list[float]] = field(default_factory=list)
    #: Earliest time the lower-third pill may be drawn. A slide already carries its own
    #: title and fills the frame to its own edges - a pill in the bottom-left corner
    #: lands on the slide's own footer strip and reads as a collision, not a label. So
    #: the caption waits until a dashboard page is on screen; ``inf`` on an all-slide
    #: scene means it is never drawn at all.
    caption_from: float = 0.0

    @property
    def shots(self) -> list[Path]:
        return [s.png for s in self.states]


class ComposeError(RuntimeError):
    """The compositor could not produce a scene."""


class GeometryError(ComposeError):
    """A selector used by an action was not resolved by capture.py."""


_XY_RE = re.compile(r"^xy=\(?\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)?$")


def resolve_target(
    spec: Any,
    geom: Mapping[str, Any],
    scene_id: str,
    strict: bool = True,
) -> tuple[float, float, float, float]:
    """Resolve an action target to a CSS-space rect (x, y, w, h)."""
    if spec is None:
        raise GeometryError(f"[{scene_id}] action has no target")
    if isinstance(spec, (tuple, list)) and len(spec) in (2, 4):
        v = [float(n) for n in spec]
        return (v[0], v[1], 0.0, 0.0) if len(v) == 2 else (v[0], v[1], v[2], v[3])
    s = str(spec).strip()
    m = _XY_RE.match(s)
    if m:
        return (float(m.group(1)), float(m.group(2)), 0.0, 0.0)
    # capture.py keys geometry.json by the *raw* action string ("css=#chart-gauge"),
    # so try that first and fall back to the bare selector.
    sel = s[4:].strip() if s.startswith("css=") else s
    rect = geom.get(s)
    if rect is None:
        rect = geom.get(sel)
    if rect is None:
        msg = (
            f"[{scene_id}] selector {sel!r} is not in geometry.json - "
            f"capture.py must resolve every selector an action uses"
        )
        if strict:
            raise GeometryError(msg)
        log.warning("%s (falling back to the centre of the viewport)", msg)
        return (CSS_W / 2 - 120, CSS_H / 2 - 30, 240.0, 60.0)
    v = [float(n) for n in rect]
    return (v[0], v[1], v[2], v[3])


def _centre(rect: tuple[float, float, float, float]) -> tuple[float, float]:
    x, y, w, h = rect
    return (x + w / 2.0, y + h / 2.0)


def _kind(action: Any) -> str:
    return type(action).__name__.lower()


def _attr(action: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        if hasattr(action, n):
            v = getattr(action, n)
            if v is not None:
                return v
    return default


def _rect4(value: Any) -> tuple[float, float, float, float] | None:
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return None
    try:
        x, y, w, h = (float(v) for v in value)
    except (TypeError, ValueError):
        return None
    return (x, y, w, h) if w > 0 and h > 0 else None


def _frames_of(meta: Mapping[str, Any], build: Path) -> tuple[Path, ...]:
    """The extra burst frames of one state, as paths that exist."""
    raw = meta.get("frames")
    if not isinstance(raw, (list, tuple)):
        return ()
    out: list[Path] = []
    for item in raw:
        p = Path(str(item))
        if not p.is_absolute():
            p = build / "shots" / p.name
        if p.exists():
            out.append(p)
        else:
            log.warning("burst frame %s is in the manifest but not on disk; skipping", p)
    return tuple(out)


def load_states(build: Path, scene_id: str, scene: Any = None) -> list[ShotState]:
    """Read a scene's visual states from ``build/shots_manifest.json``.

    Falls back to globbing ``build/shots/<scene_id>_*.png`` when the manifest is
    missing, so the compositor still runs against a hand-made fixture.
    """
    manifest = build / "shots_manifest.json"
    if manifest.exists():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        rows = (data.get("scenes") or {}).get(scene_id)
        if rows:
            out: list[ShotState] = []
            for row in sorted(rows, key=lambda r: int(r.get("index", 0))):
                png = Path(row["png"])
                if not png.is_absolute():
                    png = build / "shots" / png.name
                kind = str(row.get("kind") or "page")
                # capture.py nests everything about a phone shot under "phone"
                meta = row.get("phone")
                merged: dict[str, Any] = dict(row)
                if isinstance(meta, Mapping):
                    merged.update(meta)
                out.append(
                    ShotState(
                        png=png,
                        scroll=float(merged.get("scroll") or 0.0),
                        kind=kind,
                        path=str(row.get("path") or ""),
                        state=str(merged.get("state") or merged.get("lens_state") or ""),
                        scene_png=_scene_png_for(merged, png) if is_pair_kind(kind) else None,
                        aim=_aim_of(merged),
                        scroller=_rect4(merged.get("scroller")),
                        frames=_frames_of(merged, build),
                        frame_interval=float(merged.get("frame_interval") or 0.0),
                    )
                )
            return _reconcile_phone_states(out, scene, scene_id)
        log.warning("shots_manifest.json has no entry for %s; globbing instead", scene_id)

    shots_dir = build / "shots"
    found = sorted(
        shots_dir.glob(f"{scene_id}_*.png"),
        key=lambda p: int(re.sub(r"\D", "", p.stem.rsplit("_", 1)[-1]) or 0),
    )
    if not found:
        raise FileNotFoundError(
            f"[{scene_id}] no shots in {shots_dir} - run capture.py first "
            f"(expected {scene_id}_0.png ...)"
        )
    members = _seq_members(getattr(scene, "shot", None)) if scene is not None else []
    out = []
    for i, png in enumerate(found):
        member = members[i] if i < len(members) else None
        kind = _shot_kind(member)
        out.append(
            ShotState(
                png=png,
                scroll=float(getattr(member, "scroll", 0) or 0),
                kind=kind,
                path=str(getattr(member, "path", "") or ""),
                state=str(getattr(member, "state", "") or getattr(member, "phone_state", "") or ""),
                scene_png=_scene_png_for({}, png) if is_pair_kind(kind) else None,
                aim=_aim_of(member),
            )
        )
    return out


def _reconcile_phone_states(
    states: list[ShotState], scene: Any, scene_id: str
) -> list[ShotState]:
    """Let the script fill in what an older manifest does not say about phone shots.

    ``capture.py`` is the authority on the images; the script is the authority on
    what kind of thing each one *is*.  When the two line up one-for-one and the
    script says a state is a ``Phone`` or a ``PhonePair``, that wins over a
    manifest row still labelled ``page`` - otherwise a phone screen would be
    letterboxed into the desktop window frame and look like a mistake.
    """
    members = _seq_members(getattr(scene, "shot", None)) if scene is not None else []
    if not members or len(members) != len(states):
        return states
    if not any(is_phone_kind(_shot_kind(m)) for m in members):
        return states
    out: list[ShotState] = []
    for st, member in zip(states, members):
        kind = _shot_kind(member)
        if not is_phone_kind(kind) or is_phone_kind(st.kind):
            out.append(st)
            continue
        log.info(
            "[%s] the manifest calls state %s %r but script.py declares a %s - "
            "composing it as a phone shot", scene_id, st.png.name, st.kind,
            type(member).__name__,
        )
        scene_png = None
        if is_pair_kind(kind):
            raw = getattr(member, "scene_png", None)
            if raw:
                candidate = Path(str(raw))
                scene_png = candidate if candidate.exists() else _scene_png_for({}, st.png)
            else:
                scene_png = _scene_png_for({}, st.png)
        out.append(
            ShotState(
                png=st.png,
                scroll=float(getattr(member, "scroll", 0) or 0),
                kind=kind,
                path=str(getattr(member, "path", "") or st.path),
                state=str(
                    getattr(member, "state", "") or getattr(member, "phone_state", "") or ""
                ),
                scene_png=scene_png,
                aim=_aim_of(member),
            )
        )
    return out


#: how a shot's class name maps onto a manifest ``kind``
_SHOT_KINDS = {
    "Slide": "slide",
    "Phone": "phone",
    "PhonePair": "phone_pair",
    "PhoneShot": "phone",
}


def _shot_kind(shot: Any) -> str:
    return _SHOT_KINDS.get(type(shot).__name__, "page")


def _scene_png_for(row: Mapping[str, Any], png: Path) -> Path | None:
    """The illustrated scene beside a PhonePair's phone.

    The manifest row wins; otherwise the convention is the phone shot's own name
    with ``_scene`` appended, which is what a hand-made fixture can produce too.
    """
    for key in ("scene_png", "scene", "png2", "background"):
        raw = row.get(key)
        if raw:
            candidate = Path(str(raw))
            if not candidate.is_absolute():
                candidate = png.parent / candidate.name
            return candidate
    guess = png.with_name(f"{png.stem}_scene{png.suffix}")
    return guess if guess.exists() else None


def _aim_of(source: Any) -> tuple[float, float] | None:
    raw = source.get("aim") if isinstance(source, Mapping) else getattr(source, "aim", None)
    if isinstance(raw, (list, tuple)) and len(raw) == 2:
        try:
            return (float(raw[0]), float(raw[1]))
        except (TypeError, ValueError):
            return None
    return None


def _seq_members(shot: Any) -> list[Any]:
    """Flatten a Shot into the list of states it declares, in order."""
    if type(shot).__name__ in {"PageSequence", "ShotSequence"}:
        return list(getattr(shot, "shots", ()) or ())
    return [shot] if shot is not None else []


#: mirrors capture.MERGE_WINDOW - a Click and the PageSequence member it produces
#: are two declarations of one state, not two states
MERGE_WINDOW = 0.10


@dataclass
class Transition:
    """One declared visual state, on the 0..1 narration timeline."""

    frac: float
    produced_by: str
    key: tuple[str, str, int]
    to_y: float | None = None


def _target_key(shot: Any, current_path: str | None) -> tuple[str, str, int]:
    """Mirror of ``capture._target_of``, as a hashable key."""
    name = type(shot).__name__
    if name == "Slide":
        return ("slide", str(getattr(shot, "html_fn", "") or ""), 0)
    if name in {"PageSequence", "ShotSequence"}:
        items = _seq_members(shot)
        return _target_key(items[0], current_path) if items else ("page", "/", 0)
    if name == "PhonePair":
        # mirrors capture.Target("phone_pair", path, scroll, state, scene)
        inner = getattr(shot, "phone", None) or getattr(shot, "phone_shot", None)
        state = (
            getattr(inner, "state", "") if inner is not None
            else getattr(shot, "phone_state", "") or getattr(shot, "state", "") or "scan"
        )
        return (
            "phone_pair",
            f"{getattr(shot, 'path', '') or '/lens'}|{state}|"
            f"{getattr(shot, 'scene_png', '') or ''}",
            int(getattr(shot, "scroll", 0) or 0),
        )
    if name in {"Phone", "PhoneShot"}:
        return (
            "phone",
            f"{getattr(shot, 'path', '') or '/lens'}|{getattr(shot, 'state', '') or ''}",
            int(getattr(shot, "scroll", 0) or 0),
        )
    return (
        "page",
        str(getattr(shot, "path", None) or current_path or "/"),
        int(getattr(shot, "scroll", 0) or 0),
    )


def plan_transitions(scene: Any) -> list[Transition]:
    """The state changes a scene goes through, in the same order capture.py records them.

    This deliberately reimplements ``capture.plan_states``: the two must agree,
    because transition *k* here maps onto ``states[k + 1]`` from the manifest.
    """
    shot = getattr(scene, "shot", None)
    members = _seq_members(shot)
    if not members:
        return []
    ats = list(getattr(shot, "ats", ()) or []) if type(shot).__name__ == "PageSequence" else []

    declared: list[tuple[float, Any, str]] = []
    for i, member in enumerate(members[1:], start=1):
        frac = float(ats[i]) if len(ats) == len(members) else i / len(members)
        declared.append((frac, member, "sequence"))
    for action in sorted(
        list(getattr(scene, "actions", []) or []), key=lambda a: float(_attr(a, "at", default=0.0))
    ):
        kind = _kind(action)
        at = float(_attr(action, "at", default=0.0))
        if kind in {"click", "tap"}:
            then_shot = _attr(action, "then_shot", "then", "after")
            if then_shot is not None:
                declared.append((at, then_shot, kind))
        elif kind in {"scroll", "phonescroll"}:
            declared.append(
                (at, ("__scroll__", float(_attr(action, "to_y", "y", default=0) or 0)), "scroll")
            )
    declared.sort(key=lambda e: e[0])

    first = _target_key(members[0], None)
    plan = [Transition(0.0, "shot", first)]
    current = first
    for frac, payload, produced_by in declared:
        if isinstance(payload, tuple) and payload and payload[0] == "__scroll__":
            # a Scroll (or PhoneScroll) keeps whatever is on screen and moves it
            key = (current[0] if current[0] != "slide" else "page", current[1], int(payload[1]))
            to_y: float | None = float(payload[1])
        else:
            key = _target_key(payload, current[1])
            to_y = float(key[2]) if key[0] in {"page", "phone"} else None
        previous = plan[-1]
        if key == previous.key and frac - previous.frac <= MERGE_WINDOW:
            previous.produced_by += f"+{produced_by}"
            if produced_by == "scroll":
                previous.to_y = to_y
            continue
        plan.append(Transition(frac, produced_by, key, to_y if produced_by == "scroll" else None))
        current = key
    return plan[1:]


def build_plan(
    scene: Any,
    states: Sequence[ShotState],
    narration_seconds: float,
    geom: Mapping[str, Any],
    cursor_start: tuple[float, float] = DEFAULT_CURSOR_START,
    strict: bool = True,
    extra_tail: float = 0.0,
) -> ScenePlan:
    """Turn a ``script.Scene`` (duck-typed) into a concrete, timed plan.

    Action ``at`` values are fractions of the *narration* duration; the clip is
    longer than the narration by ``LEAD_IN`` at the head and ``TAIL`` at the
    tail, so an action at fraction ``f`` fires at ``LEAD_IN + f * narration``.

    Visual state changes come from three places and are merged in time order:
    a ``PageSequence``'s declared ``ats``, every ``Click``'s ``then_shot``, and
    every ``Scroll``.  Transition *k* moves to ``states[k + 1]``, matching the
    order ``capture.py`` records in ``shots_manifest.json``.
    """
    scene_id = str(getattr(scene, "id", "scene"))
    narration = max(0.1, narration_seconds)
    duration = LEAD_IN + narration + TAIL + extra_tail
    n_frames = max(1, int(round(duration * FPS)))
    if not states:
        raise FileNotFoundError(f"[{scene_id}] no shots to compose")

    shot = getattr(scene, "shot", None)
    plan = ScenePlan(
        scene_id=scene_id,
        duration=n_frames / FPS,
        n_frames=n_frames,
        states=list(states),
        caption=getattr(scene, "caption", None),
        cursor_start=cursor_start,
        fixed=[[float(v) for v in r] for r in (geom.get("__fixed__") or [])],
    )

    def at_time(action: Any, default: float = 0.2) -> float:
        return LEAD_IN + float(_attr(action, "at", default=default)) * narration

    actions = sorted(
        list(getattr(scene, "actions", []) or []),
        key=lambda a: float(_attr(a, "at", default=0.0)),
    )

    # ---- cursor choreography and per-element effects ------------------------
    pos = cursor_start
    click_times: list[float] = []
    scrolls: list[tuple[float, float, float]] = []  # (to_y, t, seconds)

    for action in actions:
        kind = _kind(action)
        t = at_time(action)

        if kind == "move":
            dest = _point(action, "to", "target", "sel", geom=geom, scene_id=scene_id, strict=strict)
            secs = float(_attr(action, "seconds", default=0.0) or 0.0)
            if secs <= 0.0:
                secs = clamp(0.34 + math.dist(dest, pos) / 1500.0, 0.34, 1.15)
            plan.moves.append(MoveSeg(t, t + secs, pos, dest))
            pos = dest
            plan.show_cursor = True

        elif kind == "click":
            target = _attr(action, "to", "target", "sel", "selector")
            if target is not None:
                dest = _point(action, "to", "target", "sel", geom=geom, scene_id=scene_id, strict=strict)
                if math.dist(dest, pos) > 2.0:
                    secs = clamp(0.34 + math.dist(dest, pos) / 1500.0, 0.34, 1.15)
                    plan.moves.append(MoveSeg(t - secs - 0.12, t - 0.12, pos, dest))
                    pos = dest
            plan.clicks.append(ClickEvt(t))
            click_times.append(t)
            plan.show_cursor = True

        elif kind in {"scroll", "phonescroll"}:
            scrolls.append(
                (
                    float(_attr(action, "to_y", "y", default=0.0) or 0.0),
                    t,
                    float(_attr(action, "seconds", default=1.2) or 1.2),
                )
            )

        elif kind == "tap":
            plan.taps.append(
                TapEvt(
                    t,
                    _tap_point(action, geom=geom, scene_id=scene_id, strict=strict),
                    max(0.18, float(_attr(action, "seconds", default=TAP_SECONDS) or TAP_SECONDS)),
                )
            )

        elif kind == "highlight":
            rect = resolve_target(
                _attr(action, "sel", "to", "target", "selector"), geom, scene_id, strict
            )
            rect = _clamp_css_rect(rect, scene_id, _attr(action, "sel", "to", default="?"))
            secs = float(_attr(action, "seconds", default=2.0) or 2.0)
            px, py = css_to_page(rect[0], rect[1])
            pw, ph = max(rect[2], 60.0) * SCALE, max(rect[3], 24.0) * SCALE
            plan.highlights.append(HighlightEvt(t, t + secs, (px, py, pw, ph)))

        elif kind == "zoom":
            rect_spec = _attr(action, "to_rect", "rect", "to")
            if isinstance(rect_spec, (tuple, list)) and len(rect_spec) == 4:
                rc = tuple(float(v) for v in rect_spec)
            else:
                rc = resolve_target(rect_spec, geom, scene_id, strict)
            secs = float(_attr(action, "seconds", default=1.5) or 1.5)
            px, py = css_to_page(rc[0], rc[1])
            # push in, sit on it for a beat, ease back out - so the rest of the
            # scene is framed normally again. If the push starts too late to
            # come back out, hold to the end and let the scene dissolve cover it.
            t1 = t + secs
            hold = max(1.0, secs)
            if t1 + hold + secs <= plan.duration - 0.15:
                hold_until, t_out = t1 + hold, t1 + hold + secs
            elif t1 + 0.4 <= plan.duration:
                hold_until = max(t1, plan.duration - secs)
                t_out = plan.duration
            else:
                hold_until = t_out = plan.duration
            plan.cameras.append(
                CameraEvt(
                    t0=t,
                    t1=min(t1, plan.duration),
                    hold_until=hold_until,
                    t_out=t_out,
                    rect=(px, py, rc[2] * SCALE, rc[3] * SCALE),
                    hires=True,
                )
            )

        else:
            log.warning("[%s] ignoring unknown action %s", scene_id, type(action).__name__)

    plan.cursor_end = pos

    # ---- quality bar: the cursor must have arrived before the ripple fires ---
    for click in plan.clicks:
        arrived = [m for m in plan.moves if m.t1 <= click.t + 1e-6]
        moving = [m for m in plan.moves if m.t0 < click.t < m.t1]
        if moving:
            log.warning(
                "[%s] the click at %.2fs fires while the cursor is still gliding "
                "(the move lands at %.2fs) - give the Move more lead time in script.py",
                scene_id, click.t, moving[0].t1,
            )
        elif not arrived:
            log.warning(
                "[%s] the click at %.2fs has no Move before it, so the ripple lands "
                "wherever the previous scene left the cursor",
                scene_id, click.t,
            )

    # ---- visual state transitions -------------------------------------------
    transitions = plan_transitions(scene)
    wanted = len(states) - 1
    if len(transitions) != wanted:
        log.warning(
            "[%s] the script declares %d state change(s) but capture recorded %d "
            "- composing the first %d",
            scene_id, len(transitions), wanted, min(len(transitions), wanted),
        )
    for k in range(min(len(transitions), wanted)):
        tr = transitions[k]
        a, b = states[k], states[k + 1]
        t0 = LEAD_IN + tr.frac * narration
        is_scroll = "scroll" in tr.produced_by and a.path == b.path and a.kind == b.kind
        if "click" in tr.produced_by:
            # cause before effect: the after-state starts 120 ms into the ripple
            t0 += AFTER_DELAY
        if is_scroll:
            match = next((s for s in scrolls if abs(s[0] - b.scroll) < 1.5), None)
            secs = match[2] if match is not None else 1.2
            if match is not None:
                scrolls.remove(match)
            plan.swaps.append(Swap(t0, t0 + secs, k, k + 1, "scroll", b.scroll - a.scroll))
        else:
            plan.swaps.append(Swap(t0, t0 + SWAP_SECONDS, k, k + 1, "fade"))
    plan.swaps.sort(key=lambda s: s.t0)

    # ---- when the caption may appear ----------------------------------------
    if states[0].kind == "slide":
        plan.caption_from = math.inf
        for swap in plan.swaps:
            if 0 <= swap.to < len(states) and states[swap.to].kind != "slide":
                plan.caption_from = swap.t1  # once the cross-fade to the page is done
                break

    # ---- phone shots: no cursor, no Ken Burns, no scrim ----------------------
    plan.phone_states = frozenset(i for i, st in enumerate(states) if st.is_phone)
    if plan.phone_states:
        plan.show_cursor = plan.show_cursor and bool(
            set(range(len(states))) - plan.phone_states
        )
        if len(plan.phone_states) == len(states):
            if plan.cameras:
                log.warning(
                    "[%s] Zoom does nothing on a phone shot - the phone is already the "
                    "subject; ignoring %d camera move(s)", scene_id, len(plan.cameras),
                )
                plan.cameras.clear()
            if plan.highlights:
                log.warning(
                    "[%s] Highlight does nothing on a phone shot; ignoring %d of them",
                    scene_id, len(plan.highlights),
                )
                plan.highlights.clear()
    elif plan.taps:
        log.warning(
            "[%s] %d Tap(s) on a scene with no phone shot - a tap is a finger on the "
            "Lens screen, not a desktop click", scene_id, len(plan.taps),
        )

    # ---- slide drift: a gentle 1.03x push, only while a slide is on screen ---
    plan.slide_states = frozenset(i for i, st in enumerate(states) if st.kind == "slide")
    # Which states actually carry the dashboard's sticky sidebar, and so have a status
    # block under the caption pill that needs repainting. /lens/* is served by the same
    # app but has no sidebar: on scene 16 the repaint sampled a colour from where the
    # sidebar would have been and painted a hard-edged 237x172 px block of it behind the
    # pill, clipping the window's rounded bottom-left corner for the whole scene.
    plan.sidebar_states = frozenset(
        i for i, st in enumerate(states)
        if st.kind == "page" and not st.path.startswith("/lens")
    )
    # A Zoom already owns its stretch of the scene; never drift under one.
    busy = [(c.t0, c.t_out) for c in plan.cameras]

    def _free(a: float, b: float) -> bool:
        return not any(t0 < b and a < t1 for t0, t1 in busy)

    for i, st in enumerate(states[: len(plan.swaps) + 1]):
        slide = st.kind == "slide"
        start = plan.swaps[i - 1].t1 if i > 0 else 0.0
        if i < len(plan.swaps):
            hold_until, t_out = plan.swaps[i].t0, plan.swaps[i].t1
        else:
            hold_until = t_out = plan.duration
        span = hold_until - start
        if slide:
            if SLIDE_DRIFT <= 1.001 or span < 0.5 or not _free(start, t_out):
                continue
            # The push runs the whole time the slide is up, so no frame of it is a repeat
            # of the one before. hold_until == t1 means there is no settle phase to hold,
            # and the drift is still at full extent when the scene dissolves away from it.
            plan.cameras.append(
                CameraEvt(start, hold_until, hold_until, t_out, _drift_rect(SLIDE_DRIFT),
                          hires=False, linear=True)
            )
            continue
        if IDLE_DRIFT_RATE <= 0.0 or span < IDLE_DRIFT_AFTER:
            continue
        # Burst states drift too. A `scan` burst moves the whole viewfinder and needs no
        # help, but scene 18's `card` burst only animates the strip of viewfinder above
        # the card - real captured motion, and still two thirds of a minute that
        # freezedetect calls frozen because it is averaged over the whole frame. The
        # drift is an order of magnitude smaller than the handheld motion (about 0.05
        # against 1.0 mean absolute difference at 6 fps), so it never hides a burst that
        # has stopped playing.
        # Cut the free parts of the hold into equal in-and-out cycles of at most
        # IDLE_DRIFT_CYCLE seconds, so the crop box moves at the same speed whether the
        # voice sits here for five seconds or for forty, and comes back to rest at every
        # cycle boundary and at the end of the hold - the scroll or dissolve that follows
        # starts from an untouched frame. A Zoom that owns part of the hold keeps it; only
        # what is left over drifts.
        for lo, hi in _free_spans(start, hold_until, busy):
            free = hi - lo
            if free < IDLE_DRIFT_AFTER:
                continue
            cycles = max(1, int(math.ceil(free / IDLE_DRIFT_CYCLE)))
            seg = free / cycles
            scale = WIN_W / max(1.0, WIN_W - IDLE_DRIFT_RATE * (seg / 2.0))
            if scale <= 1.0005:
                continue
            rect = _drift_rect(scale)
            for k in range(cycles):
                a = lo + k * seg
                plan.cameras.append(
                    CameraEvt(a, a + seg / 2.0, a + seg / 2.0, a + seg, rect,
                              hires=False, linear=True)
                )
    plan.cameras.sort(key=lambda c: c.t0)
    return plan


def _clamp_css_rect(
    rect: tuple[float, float, float, float], scene_id: str, what: Any
) -> tuple[float, float, float, float]:
    """Keep a target inside the 1600x900 viewport, complaining if it was not.

    capture.py reports viewport-relative rects, so a target outside the viewport
    means the scene needs a scroll state before it points at that element.  We
    clamp rather than drop it, but the warning names the scene and the selector.
    """
    x, y, w, h = rect
    cx, cy = x + w / 2.0, y + h / 2.0
    if -2 <= cx <= CSS_W + 2 and -2 <= cy <= CSS_H + 2:
        return rect
    log.warning(
        "[%s] target %s centres at (%.0f, %.0f), outside the %dx%d viewport - "
        "the scene needs a scroll state; clamping the cursor into frame",
        scene_id, what, cx, cy, CSS_W, CSS_H,
    )
    nx = clamp(cx, 24.0, CSS_W - 24.0) - w / 2.0
    ny = clamp(cy, 24.0, CSS_H - 24.0) - h / 2.0
    return (nx, ny, w, h)


def _point(
    action: Any,
    *names: str,
    geom: Mapping[str, Any],
    scene_id: str,
    strict: bool,
) -> tuple[float, float]:
    """Resolve an action target to a single CSS-space point inside the viewport."""
    rect = resolve_target(_attr(action, *names), geom, scene_id, strict)
    rect = _clamp_css_rect(rect, scene_id, _attr(action, *names, default="?"))
    x, y, w, h = rect
    return (x + w / 2.0, y + h / 2.0) if (w or h) else (x, y)


def _tap_point(
    action: Any,
    *,
    geom: Mapping[str, Any],
    scene_id: str,
    strict: bool,
) -> tuple[float, float]:
    """Where a ``Tap`` lands, in the 390x844 Lens viewport.

    ``Tap(at=..., xy=(x, y))`` is the usual form; a ``css=`` selector works too
    when capture.py resolved it in the phone context.
    """
    raw = _attr(action, "xy", "to", "target", "sel", "selector")
    if raw is None:
        raise GeometryError(
            f"[{scene_id}] a Tap has no target - give it xy=(x, y) in the "
            f"{int(PHONE_CSS_W)}x{int(PHONE_CSS_H)} Lens viewport"
        )
    rect = resolve_target(raw, geom, scene_id, strict)
    x, y, w, h = rect
    return (x + w / 2.0, y + h / 2.0) if (w or h) else (x, y)


def _free_spans(
    start: float, end: float, busy: list[tuple[float, float]]
) -> list[tuple[float, float]]:
    """``[start, end]`` with every ``busy`` interval cut out of it, in order."""
    spans = [(start, end)]
    for b0, b1 in sorted(busy):
        out: list[tuple[float, float]] = []
        for a, b in spans:
            if b1 <= a or b0 >= b:
                out.append((a, b))
                continue
            if b0 > a:
                out.append((a, b0))
            if b1 < b:
                out.append((b1, b))
        spans = out
    return [(a, b) for a, b in spans if b - a > 0.01]


def _drift_rect(scale: float = SLIDE_DRIFT) -> tuple[float, float, float, float]:
    w = WIN_W / scale
    h = WIN_H / scale
    return ((WIN_W - w) / 2.0, (WIN_H - h) / 2.0, w, h)


# --------------------------------------------------------------------------
# Camera (Ken Burns inside the page layer)
# --------------------------------------------------------------------------


def _clamp_zoom_rect(rect: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
    """Fit ``rect`` to the page aspect ratio and cap the zoom at MAX_ZOOM."""
    x, y, w, h = rect
    cx, cy = x + w / 2.0, y + h / 2.0
    aspect = WIN_W / WIN_H
    w = max(w, 40.0)
    h = max(h, 24.0)
    if w / h < aspect:
        w = h * aspect
    else:
        h = w / aspect
    min_w = WIN_W / MAX_ZOOM
    if w < min_w:
        w = min_w
        h = w / aspect
    w = min(w, float(WIN_W))
    h = min(h, float(WIN_H))
    x = clamp(cx - w / 2.0, 0.0, WIN_W - w)
    y = clamp(cy - h / 2.0, 0.0, WIN_H - h)
    return (x, y, w, h)


class Camera:
    """Crop+resize inside the page layer, with a one-entry memo.

    The memo is what makes a slide's slow 1.03x drift cheap: consecutive frames
    quantise to the same quarter-pixel crop box and reuse the previous result.
    """

    def __init__(self) -> None:
        self._key: tuple[Any, ...] | None = None
        self._out: np.ndarray | None = None
        self._pil_key: int | None = None
        self._pil: Image.Image | None = None

    def _as_image(self, page: np.ndarray) -> Image.Image:
        """``Image.fromarray`` copies 5 MB; a drifting slide reuses one array."""
        if self._pil_key == id(page) and self._pil is not None:
            return self._pil
        im = Image.fromarray(page)
        self._pil_key, self._pil = id(page), im
        return im

    def apply(
        self,
        page: np.ndarray,
        rect: tuple[float, float, float, float],
        page_id: int,
        quantum: float = 4.0,
    ) -> np.ndarray:
        """``quantum`` is memo steps per pixel; 0 disables the memo entirely.

        A slide's 1.03x drift only creeps about one pixel per second, so *any*
        quantisation turns it into a visible stair-step: it runs unmemoised.
        """
        x, y, w, h = rect
        if w >= WIN_W - 0.5 and h >= WIN_H - 0.5:
            return page
        key: tuple[Any, ...] | None = None
        if quantum > 0:
            q = quantum
            key = ("p", page_id, int(x * q), int(y * q), int(w * q), int(h * q))
            if key == self._key and self._out is not None:
                return self._out
        out = np.asarray(
            self._as_image(page).resize(
                (WIN_W, WIN_H), Image.BILINEAR, box=(x, y, x + w, y + h)
            ),
            dtype=np.uint8,
        )
        if key is not None:
            self._key, self._out = key, out
        return out

    def apply_source(
        self,
        src: Image.Image,
        rect: tuple[float, float, float, float],
        page_id: int,
        quantum: float = 4.0,
    ) -> np.ndarray:
        """Resample the camera from the original 2x screenshot.

        The shots are 3200x1800 but the window is only 1792x1008, so up to 1.79x
        of zoom still reads real captured pixels instead of upscaled ones.  This
        uses the same LANCZOS filter as ``load_page``, so a push that starts at
        1.0x is pixel-continuous with the untouched frame before it - no pop in
        sharpness when the camera engages.
        """
        x, y, w, h = rect
        kx, ky = src.width / WIN_W, src.height / WIN_H
        q = quantum
        key = ("s", page_id, int(x * q), int(y * q), int(w * q), int(h * q))
        if key == self._key and self._out is not None:
            return self._out
        box = (x * kx, y * ky, (x + w) * kx, (y + h) * ky)
        out = np.asarray(src.resize((WIN_W, WIN_H), Image.LANCZOS, box=box), dtype=np.uint8)
        self._key, self._out = key, out
        return out

    @staticmethod
    def project(
        pt: tuple[float, float], rect: tuple[float, float, float, float]
    ) -> tuple[float, float]:
        """Map a page-layer point through the camera into page-layer output."""
        x, y, w, h = rect
        return ((pt[0] - x) * (WIN_W / w), (pt[1] - y) * (WIN_H / h))


# --------------------------------------------------------------------------
# Frame generation
# --------------------------------------------------------------------------

DIM_STEPS = 8


def _cursor_pos(plan: ScenePlan, t: float) -> tuple[float, float]:
    """Cursor position in CSS space at time ``t``, eased between waypoints."""
    pos = plan.cursor_start
    for seg in plan.moves:
        if t >= seg.t1:
            pos = seg.p1
        elif t > seg.t0:
            u = ease_in_out_cubic((t - seg.t0) / max(1e-6, seg.t1 - seg.t0))
            return (_lerp(seg.p0[0], seg.p1[0], u), _lerp(seg.p0[1], seg.p1[1], u))
        else:
            break
    return pos


def _press_amount(plan: ScenePlan, t: float) -> float:
    for c in plan.clicks:
        dt = t - c.t
        if -0.02 <= dt <= PRESS_SECONDS * 2.6:
            if dt < PRESS_SECONDS:
                return ease_out_cubic(max(0.0, dt) / PRESS_SECONDS)
            u = (dt - PRESS_SECONDS) / (PRESS_SECONDS * 1.6)
            return max(0.0, 1.0 - ease_out_cubic(min(1.0, u)))
    return 0.0


def _camera_rect(
    plan: ScenePlan, t: float
) -> tuple[tuple[float, float, float, float], bool] | None:
    full = (0.0, 0.0, float(WIN_W), float(WIN_H))
    for cam in plan.cameras:
        if t < cam.t0 or t > cam.t_out + 0.001:
            continue
        target = _clamp_zoom_rect(cam.rect)
        if t <= cam.t1:
            raw = (t - cam.t0) / max(1e-6, cam.t1 - cam.t0)
            u = raw if cam.linear else ease_in_out_cubic(raw)
        elif t <= cam.hold_until:
            u = 1.0
            # `linear` drift events have t1 == hold_until, so this only ever runs for a
            # real Zoom: keep inching in rather than sitting on one frame.
            if IDLE_DRIFT_RATE > 0.0:
                dw = abs(float(WIN_W) - float(target[2])) or float(WIN_W)
                u += min(HOLD_CREEP_MAX, IDLE_DRIFT_RATE * max(0.0, t - cam.t1) / dw)
        else:
            u = 1.0 - ease_in_out_cubic(
                (t - cam.hold_until) / max(1e-6, cam.t_out - cam.hold_until)
            )
        if u <= 0.0005:
            return None  # fully zoomed out: use the untouched cached page
        rect = tuple(_lerp(full[i], target[i], u) for i in range(4))
        return rect, cam.hires  # type: ignore[return-value]
    return None


def _highlight_at(plan: ScenePlan, t: float) -> tuple[HighlightEvt, float] | None:
    for hi in plan.highlights:
        if hi.t0 <= t <= hi.t1:
            a_in = clamp((t - hi.t0) / HIGHLIGHT_FADE, 0.0, 1.0)
            a_out = clamp((hi.t1 - t) / HIGHLIGHT_FADE, 0.0, 1.0)
            a = ease_in_out_cubic(min(a_in, a_out))
            if a > 0.002:
                return hi, a
    return None


def _state_at(plan: ScenePlan, t: float) -> tuple[int, int, float, Swap | None]:
    """Return (from_idx, to_idx, progress, active_swap) for time ``t``."""
    idx = 0
    for sw in plan.swaps:
        if t >= sw.t1:
            idx = sw.to
        elif t > sw.t0:
            u = (t - sw.t0) / max(1e-6, sw.t1 - sw.t0)
            return sw.frm, sw.to, u, sw
        else:
            break
    return idx, idx, 0.0, None


_tall_cache: dict[tuple[int, int, int], tuple[np.ndarray | None, int]] = {}


#: Fraction of a non-overlapping scroll's duration spent holding each end still, so the
#: dissolve itself occupies the middle 1 - 2*hold. See the tall is None branch below.
CUT_DISSOLVE_HOLD: Final[float] = 0.20

#: The same idea for an in-scene cross-fade between two page states (a click that reflows
#: the page). Both layouts are text, and text dissolved through text is unreadable, so the
#: dissolve is squeezed into the middle 40% of the swap and each end is held still.
FADE_DISSOLVE_HOLD: Final[float] = 0.30


#: A phone state change with no captured strip between its two offsets is a cut. The blend
#: itself takes this long, centred in the swap, and both ends are held still around it - the
#: same 400 ms the film gives a scene-to-scene dissolve, rather than smearing two card bodies
#: through each other for the whole of a 1.8 s scroll.
CUT_DISSOLVE_SECONDS: Final[float] = DISSOLVE


def _cut_progress(swap: Swap, progress: float) -> float:
    """Remap a swap's 0..1 so the blend happens in a CUT_DISSOLVE_SECONDS window at its centre."""
    span = max(1e-6, swap.t1 - swap.t0)
    hold = max(0.0, min(0.45, (span - CUT_DISSOLVE_SECONDS) / (2.0 * span)))
    return _compressed(progress, hold)


def _compressed(prog: float, hold: float) -> float:
    """Remap 0..1 so the first and last ``hold`` of it are flat."""
    span = 1.0 - 2.0 * hold
    if span <= 0:
        return 0.0 if prog < 0.5 else 1.0
    return min(1.0, max(0.0, (prog - hold) / span))


def _scroll_tall(store: PageStore, sw: Swap) -> tuple[np.ndarray | None, int]:
    """Stack two scroll states into one tall image so the scroll is continuous.

    The two shots overlap by ``viewport - dy`` rows of identical page content,
    so stacking them reconstructs the real document strip and the scroll is a
    genuine translation rather than a cross-fade.  Cached: it is the same strip
    for every frame of the scroll.
    """
    key = (id(store), sw.frm, sw.to)
    hit = _tall_cache.get(key)
    if hit is not None:
        return hit
    a = store.page(sw.frm)
    b = store.page(sw.to)
    dy = int(round(abs(sw.dy_css) * SCALE))
    if dy <= 0:
        _tall_cache[key] = (b, 0)
        return b, 0
    if dy >= WIN_H:
        # The two shots do not overlap, so there is no document strip to reconstruct -
        # everything between them was never captured. Signal that with dy < 0 and let the
        # caller cross-dissolve, which is what the phone scroller already does for the same
        # case. Returning the destination with dy == 0 (as this did) produced a hard jump
        # cut on the scroll's first frame, and handed the caller a read-only array it then
        # tried to paste the fixed bands into.
        log.warning(
            "scroll of %.0f CSS px is taller than the viewport: the two states do not "
            "overlap, so the scroll cross-dissolves instead of gliding. Capture an "
            "intermediate scroll state if this beat needs to move.", abs(sw.dy_css),
        )
        _tall_cache[key] = (None, -1)
        return None, -1
    tall = np.empty((WIN_H + dy, WIN_W, 3), dtype=np.uint8)
    if sw.dy_css > 0:  # scrolling down: A on top, B below
        tall[:WIN_H] = a
        tall[dy:] = b
    else:  # scrolling up
        tall[:WIN_H] = b
        tall[dy:] = a
    _tall_cache[key] = (tall, dy)
    return tall, dy


def _apply_fixed(page: np.ndarray, source: np.ndarray, bands: Iterable[tuple[int, int, int, int]]) -> None:
    """Paste the non-scrolling regions back over a mid-scroll page, in place."""
    for x, y, w, h in bands:
        page[y : y + h, x : x + w] = source[y : y + h, x : x + w]


@dataclass
class SceneResult:
    scene_id: str
    clip: Path
    frames: int
    seconds: float
    elapsed: float
    last_frame: np.ndarray
    cursor_end: tuple[float, float]


def render_scene(
    plan: ScenePlan,
    out_clip: Path,
    prev_frame: np.ndarray | None = None,
    preset: str = "fast",
    crf: int = 19,
    probe_dir: Path | None = None,
    probe_every: int = 0,
    ffmpeg: str = "ffmpeg",
) -> SceneResult:
    """Generate every frame of one scene and encode it to ``out_clip``."""
    started = time.perf_counter()
    out_clip.parent.mkdir(parents=True, exist_ok=True)
    store = PageStore(plan.shots, plan.fixed)
    phones = PhoneStore(plan.states, plan.scene_id) if plan.phone_states else None
    camera = Camera()
    dims = DimCache()
    glow_cache: dict[tuple[int, int], Sprite] = {}
    cap = caption_sprite(plan.caption) if plan.caption else None
    dissolve_frames = int(round(DISSOLVE * FPS)) if prev_frame is not None else 0

    cmd = [
        ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
        "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
        "-i", "-", "-an",
        "-c:v", "libx264", "-preset", preset, "-crf", str(crf),
        "-pix_fmt", "yuv420p", "-g", str(FPS * 2),
        str(out_clip),
    ]
    errlog = tempfile.NamedTemporaryFile(
        prefix=f"ffmpeg_{plan.scene_id}_", suffix=".log", delete=False
    )
    proc: subprocess.Popen[bytes] | None = None
    last: np.ndarray | None = None
    _tall_cache.clear()

    def ffmpeg_tail() -> str:
        try:
            errlog.flush()
        except ValueError:
            pass
        try:
            return Path(errlog.name).read_text(errors="replace")[-3000:]
        except OSError:
            return "(ffmpeg wrote nothing to stderr)"

    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=errlog, stdout=subprocess.DEVNULL)
        assert proc.stdin is not None
        for f in range(plan.n_frames):
            t = f / FPS
            frame = _render_frame(plan, store, camera, dims, glow_cache, cap, t, phones)
            if prev_frame is not None and f < dissolve_frames:
                u = ease_in_out_cubic((f + 1) / (dissolve_frames + 1))
                frame = blend_frames(prev_frame, frame, u)
            if probe_dir is not None and probe_every and f % probe_every == 0:
                probe_dir.mkdir(parents=True, exist_ok=True)
                Image.fromarray(frame).save(probe_dir / f"{plan.scene_id}_f{f:04d}.png")
            try:
                proc.stdin.write(np.ascontiguousarray(frame).tobytes())
            except (BrokenPipeError, OSError) as exc:
                raise ComposeError(
                    f"ffmpeg closed the pipe at frame {f}/{plan.n_frames} of "
                    f"{plan.scene_id}:\n{ffmpeg_tail()}"
                ) from exc
            last = frame
        proc.stdin.close()
        rc = proc.wait(timeout=600)
        if rc != 0:
            raise ComposeError(f"ffmpeg failed for scene {plan.scene_id} (rc={rc}):\n{ffmpeg_tail()}")
    finally:
        _tall_cache.clear()
        if proc is not None and proc.poll() is None:
            try:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        if not errlog.closed:
            errlog.close()
        try:
            Path(errlog.name).unlink(missing_ok=True)
        except OSError:
            pass
        store.release()
        if phones is not None:
            phones.release()

    if last is None:  # pragma: no cover - n_frames >= 1 always
        raise RuntimeError(f"scene {plan.scene_id} produced no frames")
    return SceneResult(
        scene_id=plan.scene_id,
        clip=out_clip,
        frames=plan.n_frames,
        seconds=plan.n_frames / FPS,
        elapsed=time.perf_counter() - started,
        last_frame=last,
        cursor_end=plan.cursor_end,
    )


def _slide_mix(plan: ScenePlan, frm: int, to: int, prog: float, swap: Swap | None) -> float:
    """How much of this frame is a slide, 0..1 - including mid-cross-fade."""
    if not plan.slide_states:
        return 0.0
    if swap is None:
        return 1.0 if frm in plan.slide_states else 0.0
    mix = 0.0
    if frm in plan.slide_states:
        mix += 1.0 - prog
    if to in plan.slide_states:
        mix += prog
    return clamp(mix, 0.0, 1.0)


def _draw_caption(
    plan: ScenePlan,
    canvas: np.ndarray,
    cap: tuple[Sprite, int, int] | None,
    t: float,
    cover: bool,
    cam_rect: tuple[float, float, float, float] | None = None,
    scale: float = 1.0,
) -> None:
    """The lower-third pill, with its own fade.  ``cover`` repaints the sidebar footer.

    ``scale`` is how much of the pill to show: a scene that comes back to a slide (the
    Lens act does it twice) fades the caption out with the slide fading in, because a
    slide carries its own title and fills the frame to its own edges.
    """
    if cap is None or t < plan.caption_from or scale <= 0.004:
        return
    sp, cx0, cy0 = cap
    start = max(LEAD_IN * 0.5, plan.caption_from)
    a_in = clamp((t - start) / CAPTION_FADE, 0.0, 1.0)
    a_out = clamp((plan.duration - 0.25 - t) / CAPTION_FADE, 0.0, 1.0)
    # ...and it leaves of its own accord after CAPTION_HOLD, whichever comes first.
    a_hold = clamp((start + CAPTION_FADE + CAPTION_HOLD - t) / CAPTION_FADE, 0.0, 1.0)
    a = ease_in_out_cubic(min(a_in, a_out, a_hold)) * scale
    if cover:
        # The cover is the pill's own backdrop, so it has to be opaque *before* the pill is
        # legible: matching the two alphas exactly put the sidebar's status lines at 50%
        # under a 50% pill and printed both, which read as crossed text mid-fade.
        _cover_sidebar_foot(canvas, clamp(a * 2.6, 0.0, 1.0), cam_rect)
    blit(canvas, sp, cx0, cy0, a)


def _render_phone_frame(
    plan: ScenePlan,
    phones: PhoneStore,
    store: PageStore,
    cap: tuple[Sprite, int, int] | None,
    t: float,
    frm: int,
    to: int,
    prog: float,
    swap: Swap | None,
) -> np.ndarray:
    """One frame of a Lens shot: the framed phone, any tap, and the caption.

    There is no cursor and no window chrome here.  A ``PhoneScroll`` translates
    the screen content inside the bezel; anything else between two states is a
    cross-fade of the two finished canvases, which is also what carries a scene
    that moves between the dashboard and the phone.
    """

    def canvas_for(idx: int) -> np.ndarray:
        # canvas_at, not canvas: a burst state plays its captured frames, which is how the
        # viewfinder's handheld drift gets into the film.
        return phones.canvas_at(idx, t) if idx in plan.phone_states else store.canvas(idx)

    if swap is None:
        canvas = canvas_for(frm).copy()
    elif swap.kind == "scroll" and frm in plan.phone_states and to in plan.phone_states:
        canvas = phones.scroll_canvas(swap, prog)
    else:
        canvas = blend_frames(canvas_for(frm), canvas_for(to), ease_in_out_cubic(prog))

    for tap in plan.taps:
        idx = frm if frm in plan.phone_states else to
        if idx not in plan.phone_states:
            break
        sp = tap_sprite(t - tap.t, tap.seconds, scale=phones.css_scale(idx))
        if sp is None:
            continue
        tx, ty = phones.to_canvas(idx, tap.css)
        side = sp.alpha.shape[0]
        blit(canvas, sp, tx - side / 2, ty - side / 2)
        break

    # The idle drift, applied here because this path never goes near the page layer: a
    # phone frame is the finished canvas, so the crop box is the one _camera_rect worked
    # out in page-layer pixels, rescaled to it. Taps move with the phone; the caption is
    # drawn afterwards so it stays put and stays crisp. Without this, every Lens scene
    # that holds a card under narration froze - 21.9 s in scene 19 alone.
    cam = _camera_rect(plan, t)
    if cam is not None:
        rx, ry, rw, rh = cam[0]
        h, w = canvas.shape[0], canvas.shape[1]
        sx, sy = w / float(WIN_W), h / float(WIN_H)
        canvas = np.array(
            Image.fromarray(canvas).resize(
                (w, h), Image.BILINEAR,
                box=(rx * sx, ry * sy, (rx + rw) * sx, (ry + rh) * sy),
            ),
            dtype=np.uint8,
        )

    _draw_caption(plan, canvas, cap, t, cover=False,
                  scale=1.0 - _slide_mix(plan, frm, to, prog, swap))
    return canvas


def _render_frame(
    plan: ScenePlan,
    store: PageStore,
    camera: Camera,
    dims: DimCache,
    glow_cache: dict[tuple[int, int], Sprite],
    cap: tuple[Sprite, int, int] | None,
    t: float,
    phones: PhoneStore | None = None,
) -> np.ndarray:
    frm, to, prog, swap = _state_at(plan, t)
    if phones is not None and (frm in plan.phone_states or to in plan.phone_states):
        return _render_phone_frame(plan, phones, store, cap, t, frm, to, prog, swap)
    hi = _highlight_at(plan, t)
    cam = _camera_rect(plan, t)
    cam_rect = cam[0] if cam is not None else None
    press = _press_amount(plan, t)
    # `to` is the state being faded *to*, and equals `frm` when nothing is swapping. Hiding
    # the cursor while a slide is the destination keeps it off title cards but lets it fade
    # in with the dashboard on a slide-to-page cross-dissolve.
    on_slide = to in plan.slide_states
    cursor_css = _cursor_pos(plan, t) if plan.show_cursor and not on_slide else None

    ripple: tuple[Sprite, tuple[float, float]] | None = None
    if not on_slide:
        for c in plan.clicks:
            sp = ripple_sprite(t - c.t)
            if sp is not None:
                ripple = (sp, _cursor_pos(plan, c.t))
                break

    if swap is None and hi is None and cam is None:
        canvas = store.canvas(frm).copy()  # fast path: most frames land here
    else:
        # ---- page layer -----------------------------------------------------
        page_id = frm * 1000 + to
        page_static = swap is None
        if swap is not None and swap.kind == "scroll":
            tall, dy = _scroll_tall(store, swap)
            if tall is None:
                # The two offsets do not overlap, so there is no captured document strip
                # to translate through. Dissolve instead — which is what the phone
                # scroller already does for the same case, and better than the hard jump
                # cut this used to produce on the scroll's first frame.
                #
                # A scroll is declared over 1.3-1.8s, and spreading the dissolve across all
                # of it leaves two dense pages half-visible for most of a second, which
                # reads as ghosting rather than a transition. Hold the source, dissolve
                # across the middle, hold the destination: the same total beat, with the
                # ambiguous part compressed. Nothing is invented either way — both layers
                # are captured pixels.
                u = _compressed(prog, CUT_DISSOLVE_HOLD)
                page = blend_pages(store.page(frm), store.page(to), ease_in_out_cubic(u))
                page_id = 800000 + int(u * 1000)
            else:
                u = ease_in_out_cubic(prog)
                off = int(round(dy * u)) if swap.dy_css > 0 else int(round(dy * (1.0 - u)))
                bands = store.fixed_bands(swap.frm, swap.to)
                window = tall[off : off + WIN_H]
                if bands:
                    # _apply_fixed writes in place, and this window is not ours to write
                    # to. `tall` is either the cached strip — where a write would smear the
                    # pinned header permanently into the document for every later frame of
                    # the same scroll — or, when dy == 0, the store's own page array, which
                    # is read-only and raised "assignment destination is read-only". One
                    # copy per scrolling frame, and only when there is something to paste.
                    page = window.copy()
                    _apply_fixed(page, store.page(swap.to), bands)
                else:
                    page = np.ascontiguousarray(window)
                page_id = 900000 + off
        elif swap is not None:
            # An in-scene fade is usually a *reflow* of the same page - a finding row
            # expanding under a click - and a straight cross-dissolve leaves both layouts
            # half-visible for its whole length: at t=3:18.8 "Telnet open on
            # 192.168.1.142:23" was printed twice, offset, and the column header read
            # "SSUUBBJJEECCTT". Hold the source, dissolve across the middle, hold the
            # destination: the same 220 ms beat, with the ambiguous part cut to ~130 ms.
            u = _compressed(prog, FADE_DISSOLVE_HOLD)
            page = blend_pages(store.page(frm), store.page(to), ease_in_out_cubic(u))
            page_id = 800000 + int(u * 1000)
        else:
            page = store.page(frm)

        # ---- camera (before the highlight, so a Zoom can resample the 2x
        #      source instead of the already-downscaled page) -----------------
        if cam is not None:
            if cam[1] and page_static:
                # a real Zoom: resample the 2x shot, so the pixels it magnifies
                # are captured detail rather than an upscale. The hold phase is
                # a constant rect, so the memo makes it free.
                page = camera.apply_source(store.source(frm), cam_rect, frm, 4.0)
            else:
                # slide drift, and any camera over a mid-swap page. The memo
                # quantum is fine enough (1/64 px) that the moving phase never
                # stair-steps, but exact enough that the settled phase - where
                # the crop stops changing - costs nothing.
                page = camera.apply(page, cam_rect, page_id, quantum=64.0)
            page_static = False

        # ---- highlight ------------------------------------------------------
        if hi is not None:
            evt, amount = hi
            step = int(round(amount * DIM_STEPS))
            if page_static:
                dim = store.dimmed(frm, step, DIM_STEPS).copy()
            else:
                dim = dims.get(page, step, DIM_STEPS).copy()
            x, y, w, h = evt.rect
            if cam_rect is not None:
                x, y = Camera.project((x, y), cam_rect)
                k = WIN_W / cam_rect[2]
                w, h = w * k, h * k
            pad = 6
            x0 = int(clamp(x - pad, 0, WIN_W - 1))
            y0 = int(clamp(y - pad, 0, WIN_H - 1))
            x1 = int(clamp(x + w + pad, x0 + 1, WIN_W))
            y1 = int(clamp(y + h + pad, y0 + 1, WIN_H))
            dim[y0:y1, x0:x1] = page[y0:y1, x0:x1]
            key = (int(w) // 4 * 4, int(h) // 4 * 4)
            g = glow_cache.get(key)
            if g is None:
                if len(glow_cache) > 32:
                    glow_cache.clear()
                g = glow_sprite(max(8, key[0]), max(8, key[1]))
                glow_cache[key] = g
            blit(dim, g, x - 40, y - 40, amount)
            page = dim
        canvas = compose_canvas(page)

    # ---- cursor + ripple (drawn after the camera, so they stay crisp) -------
    if cursor_css is not None or ripple is not None:
        def to_canvas(css: tuple[float, float]) -> tuple[float, float]:
            px, py = css_to_page(css[0], css[1])
            if cam_rect is not None:
                px, py = Camera.project((px, py), cam_rect)
            return WIN_X + px, WIN_Y + py

        if ripple is not None:
            sp, rc = ripple
            rx, ry = to_canvas(rc)
            blit(canvas, sp, rx - _RIPPLE_TILE / 2, ry - _RIPPLE_TILE / 2)
        if cursor_css is not None:
            cx, cy = to_canvas(cursor_css)
            fx, fy = math.floor(cx), math.floor(cy)
            sub_x = int(round((cx - fx) * SUBPIXEL_STEPS))
            sub_y = int(round((cy - fy) * SUBPIXEL_STEPS))
            sp = cursor_sprite(press, sub_x, sub_y)
            blit(canvas, sp, fx - CURSOR_HOT, fy - CURSOR_HOT)

    # ---- caption ------------------------------------------------------------
    # The sidebar sits in the same place on every dashboard page, so the band is a constant
    # in page space and only the camera can move it - but /lens/pair and /lens/stickers are
    # pages with no sidebar at all, and repainting a sidebar that is not there is what put a
    # hard-edged grey rectangle behind the caption for the whole of scene 16.
    cover = (not on_slide) and bool(
        {frm, to} & plan.sidebar_states
    )
    _draw_caption(plan, canvas, cap, t, cover=cover, cam_rect=cam_rect,
                  scale=1.0 - _slide_mix(plan, frm, to, prog, swap))
    return canvas


# --------------------------------------------------------------------------
# Self test: a synthetic fixture so the compositor can be verified standalone
# --------------------------------------------------------------------------


def _fake_shot(path: Path, variant: int, scroll: int = 0) -> None:
    """Draw a plausible dark-dashboard screenshot at capture resolution (2x)."""
    s = 2
    im = Image.new("RGB", (CSS_W * s, CSS_H * s), (15, 17, 23))
    d = ImageDraw.Draw(im)
    f_h1 = _font(26 * s, True)
    f_h2 = _font(17 * s, True)
    f_b = _font(14 * s, False)
    f_s = _font(12 * s, False)

    d.rectangle((0, 0, 210 * s, CSS_H * s), fill=(23, 26, 35))
    d.text((22 * s, 24 * s), "\u25c8  Home SOC", font=f_h2, fill=(230, 232, 239))
    nav = ["Overview", "Findings", "Devices", "Vulnerabilities", "Host", "DNS", "Activity", "Summary"]
    for i, item in enumerate(nav):
        y = (70 + i * 38) * s
        if i == variant % len(nav):
            d.rounded_rectangle((14 * s, y - 6 * s, 196 * s, y + 24 * s), radius=8 * s, fill=ACCENT)
            d.text((28 * s, y + 2 * s), item, font=f_b, fill=(255, 255, 255))
        else:
            d.text((28 * s, y + 2 * s), item, font=f_b, fill=(139, 145, 163))

    top = -scroll * s
    d.text((240 * s, (28 * s) + top), "Overview", font=f_h1, fill=(230, 232, 239))
    d.text((240 * s, (66 * s) + top), "HOME-PC \u00b7 Home-WiFi \u00b7 18 devices", font=f_s, fill=(139, 145, 163))

    cards = [
        ("Security score", "78", "+6 this week", (70, 167, 88)),
        ("Open findings", "31", "2 critical", (229, 72, 77)),
        ("Devices", "18", "1 unknown", (255, 178, 36)),
        ("DNS blocked", "31%", "4,182 queries", (62, 99, 221)),
    ]
    for i, (title, big, sub, col) in enumerate(cards):
        x = (240 + i * 330) * s
        y = (100 * s) + top
        d.rounded_rectangle((x, y, x + 305 * s, y + 118 * s), radius=10 * s, fill=(29, 33, 48))
        d.text((x + 18 * s, y + 16 * s), title, font=f_s, fill=(139, 145, 163))
        d.text((x + 18 * s, y + 38 * s), big, font=_font(40 * s, True), fill=(230, 232, 239))
        d.text((x + 18 * s, y + 92 * s), sub, font=f_s, fill=col)

    rows = [
        ("NET-SVC-001", "Telnet open on 192.168.1.142", "critical", (229, 72, 77)),
        ("NET-VUL-001", "KEV-listed CVE on the gateway", "critical", (229, 72, 77)),
        ("HOST-APP-004", "Outdated browser build", "high", (247, 107, 21)),
        ("NET-SVC-014", "RTSP exposed without auth", "high", (247, 107, 21)),
        ("HOST-CFG-002", "SMBv1 client still enabled", "medium", (255, 178, 36)),
        ("DNS-CFG-001", "Resolver not set on 3 devices", "medium", (255, 178, 36)),
        ("NET-DEV-007", "New device joined the network", "low", (70, 167, 88)),
    ]
    ty = (246 * s) + top
    d.rounded_rectangle((240 * s, ty, 1560 * s, ty + 380 * s), radius=10 * s, fill=(29, 33, 48))
    d.text((258 * s, ty + 18 * s), "Fix these first", font=f_h2, fill=(230, 232, 239))
    for i, (fid, text, sev, col) in enumerate(rows):
        y = ty + (56 + i * 44) * s
        if variant >= 1 and i == 0:
            d.rounded_rectangle((250 * s, y - 6 * s, 1550 * s, y + 32 * s), radius=6 * s, fill=(38, 44, 62))
        d.text((258 * s, y), fid, font=f_s, fill=(139, 145, 163))
        d.text((370 * s, y), text, font=f_b, fill=(230, 232, 239))
        d.rounded_rectangle((1400 * s, y - 2 * s, 1470 * s, y + 20 * s), radius=10 * s, fill=col)
        d.text((1412 * s, y + 2 * s), sev, font=f_s, fill=(20, 22, 30))
    im.save(path)


def _draw_room(d: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """A flat illustration of the thing the phone is pointed at: a camera on a shelf.

    Stands in for ``video/scene_render.py``'s real output (which carries a genuine QR
    from ``homesoc/web/qr.py``) so the compositor can be verified on its own.
    """
    d.rectangle((0, 0, w, h), fill=(26, 29, 38))
    d.rectangle((0, int(h * 0.62), w, h), fill=(20, 23, 30))
    d.line((0, int(h * 0.62), w, int(h * 0.62)), fill=(44, 50, 66), width=max(2, h // 300))
    # shelf
    sy = int(h * 0.60)
    d.rectangle((int(w * 0.10), sy, int(w * 0.92), sy + max(6, h // 90)), fill=(58, 48, 38))
    d.rectangle((int(w * 0.10), sy, int(w * 0.92), sy + max(2, h // 260)), fill=(84, 70, 54))
    # the camera body
    bx0, by0 = int(w * 0.44), int(h * 0.30)
    bx1, by1 = int(w * 0.68), sy
    d.rounded_rectangle((bx0, by0, bx1, by1), radius=max(6, h // 60), fill=(226, 228, 234))
    d.rounded_rectangle((bx0, by0, bx1, by1), radius=max(6, h // 60), outline=(150, 155, 168), width=2)
    lr = int((bx1 - bx0) * 0.22)
    lcx, lcy = (bx0 + bx1) // 2, by0 + int((by1 - by0) * 0.34)
    d.ellipse((lcx - lr, lcy - lr, lcx + lr, lcy + lr), fill=(22, 25, 33), outline=(120, 126, 140), width=3)
    d.ellipse(
        (lcx - lr // 3, lcy - lr // 3, lcx + lr // 4, lcy + lr // 4), fill=(52, 62, 88)
    )
    d.ellipse((bx1 - int(lr * 0.8), by0 + int(lr * 0.5), bx1 - int(lr * 0.4), by0 + int(lr * 0.9)),
              fill=(70, 167, 88))
    # the sticker, with a QR-ish matrix
    qs = int((bx1 - bx0) * 0.34)
    qx, qy = bx0 + int((bx1 - bx0) * 0.10), by1 - qs - int(h * 0.03)
    d.rectangle((qx - 6, qy - 6, qx + qs + 6, qy + qs + 20), fill=(252, 252, 252))
    cells = 21
    cell = qs / cells
    rng = 1
    for gy in range(cells):
        for gx in range(cells):
            rng = (rng * 1103515245 + 12345) & 0x7FFFFFFF
            finder = (gx < 7 and gy < 7) or (gx >= cells - 7 and gy < 7) or (gx < 7 and gy >= cells - 7)
            on = ((rng >> 16) & 1) if not finder else 0
            if on:
                d.rectangle((qx + gx * cell, qy + gy * cell, qx + (gx + 1) * cell, qy + (gy + 1) * cell),
                            fill=(16, 18, 24))
    for ox, oy in ((0, 0), (cells - 7, 0), (0, cells - 7)):
        x0, y0 = qx + ox * cell, qy + oy * cell
        d.rectangle((x0, y0, x0 + 7 * cell, y0 + 7 * cell), fill=(16, 18, 24))
        d.rectangle((x0 + cell, y0 + cell, x0 + 6 * cell, y0 + 6 * cell), fill=(252, 252, 252))
        d.rectangle((x0 + 2 * cell, y0 + 2 * cell, x0 + 5 * cell, y0 + 5 * cell), fill=(16, 18, 24))
    d.text((qx, qy + qs + 4), "hallway camera", font=_font(max(9, qs // 12), False), fill=(40, 44, 56))


def _fake_scene_png(path: Path, w: int = 1600, h: int = 900) -> None:
    im = Image.new("RGB", (w, h), (26, 29, 38))
    _draw_room(ImageDraw.Draw(im), w, h)
    im.save(path)


def _fake_lens_screen(path: Path, state: str, scroll: int = 0) -> None:
    """A stand-in for a real ``/lens`` capture: 390x844 at device_scale_factor=3."""
    s = 3
    w, h = int(PHONE_CSS_W) * s, int(PHONE_CSS_H) * s
    im = Image.new("RGB", (w, h), (10, 12, 16))
    d = ImageDraw.Draw(im)
    _draw_room(d, w, int(h * 0.62))
    d.rectangle((0, int(h * 0.62), w, h), fill=(10, 12, 16))

    f_big = _font(21 * s, True)
    f_mid = _font(15 * s, True)
    f_sm = _font(12 * s, False)

    # status bar + top pill
    d.text((18 * s, 14 * s), "9:41", font=_font(13 * s, True), fill=(236, 238, 244))
    d.rounded_rectangle((110 * s, 10 * s, 280 * s, 34 * s), radius=12 * s, fill=(16, 20, 28))
    d.ellipse((120 * s, 19 * s, 127 * s, 26 * s), fill=(70, 167, 88))
    d.text((134 * s, 14 * s), "Lens · paired", font=f_sm, fill=(200, 206, 220))

    if state == "scan":
        rx0, ry0, rx1, ry1 = 70 * s, 250 * s, 320 * s, 500 * s
        arm = 34 * s
        for cx, cy, dx, dy in (
            (rx0, ry0, 1, 1), (rx1, ry0, -1, 1), (rx0, ry1, 1, -1), (rx1, ry1, -1, -1)
        ):
            d.line((cx, cy, cx + dx * arm, cy), fill=(91, 124, 255), width=4 * s)
            d.line((cx, cy, cx, cy + dy * arm), fill=(91, 124, 255), width=4 * s)
        d.rounded_rectangle((40 * s, 700 * s, 350 * s, 748 * s), radius=14 * s, fill=(22, 26, 36))
        d.text((195 * s, 724 * s), "Pick manually", font=f_mid, fill=(226, 230, 242), anchor="mm")
        d.text((195 * s, 560 * s), "Point at a device", font=f_big, fill=(236, 238, 246), anchor="mm")
        d.text((195 * s, 592 * s), "any barcode or Home SOC sticker",
               font=f_sm, fill=(150, 156, 172), anchor="mm")
    else:
        # The card rises over the bottom two thirds; its header is pinned and only the
        # body scrolls, which is what a PhoneScroll moves - and what detect_fixed_rows
        # has to notice, or the status bar would slide away with the list.
        top = 300 * s
        rows = (
            ("PROBLEMS", None, None),
            ("Telnet is open on port 23", "critical", (229, 72, 77)),
            ("Admin page needs no password", "critical", (229, 72, 77)),
            ("Firmware has a known flaw", "high", (247, 107, 21)),
            ("EXPOSED", None, None),
            ("23  Telnet — remote control, no encryption", "high", (247, 107, 21)),
            ("554  RTSP — the video stream itself", "medium", (255, 178, 36)),
            ("80  HTTP — the admin page", "medium", (255, 178, 36)),
            ("TALKING TO", None, None),
            ("telemetry.example-cam.net  ·  blocked 214", "blocked", (229, 72, 77)),
            ("ntp.example.org  ·  allowed 48", "allowed", (70, 167, 88)),
        )
        head_h = 174 * s
        d.rounded_rectangle((0, top, w, h + 40 * s), radius=22 * s, fill=(14, 17, 23))
        # the body is drawn on its own surface and pasted into the card, so a scrolled
        # row can never appear above the card the way it would on a real phone
        body = Image.new("RGB", (w, h), (14, 17, 23))
        bd = ImageDraw.Draw(body)
        y = top + head_h - scroll * s
        for text, tag, col in rows:
            if tag is None:
                bd.text((22 * s, y + 10 * s), text, font=_font(11 * s, True), fill=(120, 128, 148))
                y += 38 * s
                continue
            bd.rounded_rectangle((16 * s, y, 374 * s, y + 46 * s), radius=10 * s, fill=(22, 26, 36))
            bd.rectangle((16 * s, y + 10 * s, 19 * s, y + 36 * s), fill=col)
            bd.text((30 * s, y + 15 * s), text, font=f_sm, fill=(226, 230, 242))
            y += 54 * s
        cut = top + head_h
        im.paste(body.crop((0, cut, w, h)), (0, cut))
        d.rounded_rectangle((0, top, w, cut), radius=22 * s, fill=(14, 17, 23))
        d.rounded_rectangle((150 * s, top + 12 * s, 240 * s, top + 18 * s), radius=3 * s,
                            fill=(70, 78, 98))
        d.text((22 * s, top + 40 * s), "Hallway camera", font=f_big, fill=(236, 238, 246))
        d.text((22 * s, top + 72 * s), "192.168.1.142  ·  unknown vendor",
               font=f_sm, fill=(150, 156, 172))
        bar_y = top + 100 * s
        for i, col in enumerate(((229, 72, 77), (247, 107, 21), (255, 178, 36), (70, 167, 88))):
            d.rounded_rectangle((22 * s + i * 88 * s, bar_y, 22 * s + i * 88 * s + 80 * s,
                                 bar_y + 6 * s), radius=3 * s, fill=col)
        d.text((22 * s, bar_y + 20 * s), "Two critical problems: Telnet is open, and the",
               font=f_sm, fill=(226, 230, 242))
        d.text((22 * s, bar_y + 40 * s), "admin page needs no password.",
               font=f_sm, fill=(226, 230, 242))
    im.save(path)


def selftest_phone(build: Path, keep: bool = True) -> Path:
    """Render a synthetic Lens clip: a PhonePair, a Tap, a PhoneScroll and a dissolve in.

    Like :func:`selftest`, it draws its own fixtures rather than needing capture.py,
    ``video/phone.py`` or a Lens server, and leaves probe PNGs to look at.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    root = build / "selftest"
    shots = root / "shots"
    shots.mkdir(parents=True, exist_ok=True)

    pair_png = shots / "00-phone_0.png"
    pair_scene = shots / "00-phone_0_scene.png"
    card_png = shots / "00-phone_1.png"
    card_scrolled = shots / "00-phone_2.png"
    desk_png = shots / "00-phone_desk.png"
    _fake_lens_screen(pair_png, "scan")
    _fake_scene_png(pair_scene)
    _fake_lens_screen(card_png, "card", 0)
    _fake_lens_screen(card_scrolled, "card", 260)
    _fake_shot(desk_png, 2, 0)
    print(f"synthetic phone fixtures written to {shots}")
    print(f"  phone.py available: {phone_module() is not None}")

    class Phone:
        def __init__(self, state: str, scroll: int = 0, path: str = "/lens") -> None:
            self.path, self.state, self.scroll = path, state, scroll

    class PhonePair:
        def __init__(self, scene_png: str, phone_state: str) -> None:
            self.scene_png, self.phone_state = scene_png, phone_state

    class PageSequence:
        def __init__(self, shots_: tuple[object, ...], ats: tuple[float, ...] = ()) -> None:
            self.shots, self.ats = shots_, ats

    class Tap:
        def __init__(self, at: float, xy: tuple[float, float]) -> None:
            self.at, self.xy = at, xy

    class PhoneScroll:
        def __init__(self, to_y: int, at: float, seconds: float = 1.1) -> None:
            self.to_y, self.at, self.seconds = to_y, at, seconds

    class Scene:
        id = "00-phone"
        caption = "Lens"
        shot = PageSequence(
            (
                PhonePair(scene_png=pair_scene.as_posix(), phone_state="scan"),
                Phone("card"),
                Phone("card", 260),
            ),
            (0.0, 0.34, 0.64),
        )
        actions = [
            Tap(at=0.28, xy=(195.0, 470.0)),
            Tap(at=0.48, xy=(195.0, 640.0)),
            PhoneScroll(to_y=260, at=0.64, seconds=1.1),
        ]

    states = [
        # aim: where the fixture's own sticker sits, the way capture.py will record
        # where scene_render.py put the real one
        ShotState(pair_png, 0.0, "phone_pair", "/lens", "scan", pair_scene, (0.505, 0.497)),
        ShotState(card_png, 0.0, "phone", "/lens", "card"),
        ShotState(card_scrolled, 260.0, "phone", "/lens", "card"),
    ]
    plan = build_plan(Scene(), states, 11.6, {}, strict=True)
    print(
        f"plan: {plan.n_frames} frames / {plan.duration:.2f}s  taps={len(plan.taps)} "
        f"swaps={len(plan.swaps)} phone_states={sorted(plan.phone_states)} "
        f"cursor={plan.show_cursor}"
    )
    for sw in plan.swaps:
        print(f"  swap {sw.frm}->{sw.to} {sw.kind:6s} {sw.t0:5.2f}s..{sw.t1:5.2f}s dy={sw.dy_css:.0f}")

    prev = compose_canvas(load_page(desk_png))
    out = root / "00-phone.mp4"
    probe = root / "probe_phone"
    shutil.rmtree(probe, ignore_errors=True)
    res = render_scene(plan, out, prev_frame=prev, probe_dir=probe, probe_every=5)
    print(
        f"rendered {res.frames} frames in {res.elapsed:.1f}s "
        f"({res.frames / res.elapsed:.0f} fps) -> {out} ({out.stat().st_size / 1e6:.2f} MB)"
    )
    print(f"probe frames: {len(list(probe.glob('*.png')))} in {probe}")
    if not keep:
        shutil.rmtree(root, ignore_errors=True)
    return out


def selftest(build: Path, keep: bool = True) -> Path:
    """Render a ~10 s synthetic clip exercising every effect, then probe it.

    Deliberately self-contained: it builds its own fake screenshots under
    ``build/selftest/`` rather than touching ``build/shots/``, so it can be run
    while capture.py is producing the real ones.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    root = build / "selftest"
    shots = root / "shots"
    shots.mkdir(parents=True, exist_ok=True)
    for name, variant, scroll in (
        ("00-selftest_0.png", 0, 0),
        ("00-selftest_1.png", 1, 0),
        ("00-selftest_2.png", 1, 420),
    ):
        _fake_shot(shots / name, variant, scroll)
    print(f"synthetic shots written to {shots}")

    class Move:
        def __init__(self, to: str, at: float, seconds: float = 0.9) -> None:
            self.to, self.at, self.seconds = to, at, seconds

    class Click:
        def __init__(self, at: float, then_shot: object) -> None:
            self.at, self.then_shot = at, then_shot

    class Scroll:
        def __init__(self, to_y: int, at: float, seconds: float = 1.2) -> None:
            self.to_y, self.at, self.seconds = to_y, at, seconds

    class Highlight:
        def __init__(self, sel: str, at: float, seconds: float = 2.0) -> None:
            self.sel, self.at, self.seconds = sel, at, seconds

    class Zoom:
        def __init__(self, to_rect: tuple[int, int, int, int], at: float, seconds: float) -> None:
            self.to_rect, self.at, self.seconds = to_rect, at, seconds

    class Page:
        def __init__(self, path: str = "/", scroll: int = 0) -> None:
            self.path, self.scroll = path, scroll

    class PageSequence:
        def __init__(self, shots_: tuple[object, ...], ats: tuple[float, ...] = ()) -> None:
            self.shots, self.ats = shots_, ats

    after = Page("/", 0)
    scrolled = Page("/", 420)

    class Scene:
        id = "00-selftest"
        caption = "Overview"
        shot = PageSequence((Page("/", 0), after, scrolled), (0.0, 0.20, 0.55))
        actions = [
            Move(to="css=.row-critical", at=0.06),
            Click(at=0.20, then_shot=after),
            Highlight(sel="css=.card-score", at=0.30, seconds=1.8),
            Scroll(to_y=420, at=0.55, seconds=1.1),
            Zoom(to_rect=(240, 100, 620, 350), at=0.72, seconds=1.1),
            Move(to="xy=(1300,700)", at=0.90),
        ]

    # geometry.json is keyed by the raw action string, exactly as capture.py writes it
    geom = {
        "css=.row-critical": [370, 302, 700, 26],
        "css=.card-score": [240, 100, 305, 118],
    }
    states = [
        ShotState(shots / "00-selftest_0.png", 0.0, "page", "/"),
        ShotState(shots / "00-selftest_1.png", 0.0, "page", "/"),
        ShotState(shots / "00-selftest_2.png", 420.0, "page", "/"),
    ]
    narration = 9.45  # -> 10.0 s clip with lead-in + tail
    plan = build_plan(Scene(), states, narration, geom, strict=True)
    print(
        f"plan: {plan.n_frames} frames / {plan.duration:.2f}s  "
        f"moves={len(plan.moves)} clicks={len(plan.clicks)} swaps={len(plan.swaps)} "
        f"highlights={len(plan.highlights)} cameras={len(plan.cameras)}"
    )
    for sw in plan.swaps:
        print(f"  swap {sw.frm}->{sw.to} {sw.kind:6s} {sw.t0:5.2f}s..{sw.t1:5.2f}s dy={sw.dy_css:.0f}")

    # a fake "previous scene" frame so the head dissolve is exercised too
    prev = np.empty((H, W, 3), dtype=np.uint8)
    prev[:, :] = (18, 24, 40)

    out = root / "00-selftest.mp4"
    probe = root / "probe"
    shutil.rmtree(probe, ignore_errors=True)
    res = render_scene(plan, out, prev_frame=prev, probe_dir=probe, probe_every=5)
    print(
        f"rendered {res.frames} frames in {res.elapsed:.1f}s "
        f"({res.frames / res.elapsed:.0f} fps) -> {out} ({out.stat().st_size / 1e6:.2f} MB)"
    )
    print(f"probe frames: {len(list(probe.glob('*.png')))} in {probe}")
    if not keep:
        shutil.rmtree(root, ignore_errors=True)
    return out


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Home SOC video compositor")
    ap.add_argument("--selftest", action="store_true", help="render a synthetic 10s test clip")
    ap.add_argument("--selftest-phone", action="store_true",
                    help="render a synthetic Lens clip: PhonePair, Tap, PhoneScroll, dissolve")
    ap.add_argument(
        "--build",
        type=Path,
        default=Path(__file__).resolve().parent / "build",
        help="build directory",
    )
    args = ap.parse_args(argv)
    ran = False
    if args.selftest:
        selftest(args.build)
        ran = True
    if args.selftest_phone:
        selftest_phone(args.build)
        ran = True
    if ran:
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
