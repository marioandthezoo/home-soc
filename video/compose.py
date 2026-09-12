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

--------------------------------------------------------------------------
File conventions this module expects from the other packages
--------------------------------------------------------------------------
``build/shots_manifest.json``  the authority on a scene's *visual states*:
                               ``{"scenes": {id: [{index, kind, path, scroll,
                               png}, ...]}}``, in chronological order.  State 0
                               is the opening shot; each later one is produced
                               by a ``PageSequence`` member, a ``Click``'s
                               ``then_shot``, or a ``Scroll``.
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
probe PNGs in ``build/selftest/probe`` to look at.
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
from typing import Any, Iterable, Mapping, Sequence

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

CURSOR_HEIGHT = 34.0
HALO_RADIUS = 34
#: the halo is centred on the arrow's body, not on its tip, so the whole
#: pointer sits inside the glow
HALO_OFFSET = (7.0, 14.0)
CURSOR_TILE = 112
CURSOR_HOT = 46  # hotspot offset inside the tile, both axes
SUBPIXEL_STEPS = 4

DEFAULT_CURSOR_START = (1180.0, 760.0)  # CSS space

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
    kind: str = "page"  # "page" | "slide"
    path: str = ""


@dataclass
class ScenePlan:
    scene_id: str
    duration: float
    n_frames: int
    states: list[ShotState]
    caption: str | None = None
    moves: list[MoveSeg] = field(default_factory=list)
    clicks: list[ClickEvt] = field(default_factory=list)
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
                out.append(
                    ShotState(
                        png=png,
                        scroll=float(row.get("scroll") or 0.0),
                        kind=str(row.get("kind") or "page"),
                        path=str(row.get("path") or ""),
                    )
                )
            return out
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
        out.append(
            ShotState(
                png=png,
                scroll=float(getattr(member, "scroll", 0) or 0),
                kind="slide" if type(member).__name__ == "Slide" else "page",
                path=str(getattr(member, "path", "") or ""),
            )
        )
    return out


def _seq_members(shot: Any) -> list[Any]:
    """Flatten a Shot into the list of states it declares, in order."""
    if type(shot).__name__ == "PageSequence":
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
    if name == "PageSequence":
        items = _seq_members(shot)
        return _target_key(items[0], current_path) if items else ("page", "/", 0)
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
        if kind == "click":
            then_shot = _attr(action, "then_shot", "then", "after")
            if then_shot is not None:
                declared.append((at, then_shot, "click"))
        elif kind == "scroll":
            declared.append((at, ("__scroll__", float(_attr(action, "to_y", "y", default=0) or 0)), "scroll"))
    declared.sort(key=lambda e: e[0])

    first = _target_key(members[0], None)
    plan = [Transition(0.0, "shot", first)]
    current = first
    for frac, payload, produced_by in declared:
        if isinstance(payload, tuple) and payload and payload[0] == "__scroll__":
            key = ("page", current[1], int(payload[1]))
            to_y: float | None = float(payload[1])
        else:
            key = _target_key(payload, current[1])
            to_y = float(key[2]) if key[0] == "page" else None
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

        elif kind == "scroll":
            scrolls.append(
                (
                    float(_attr(action, "to_y", "y", default=0.0) or 0.0),
                    t,
                    float(_attr(action, "seconds", default=1.2) or 1.2),
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
        is_scroll = "scroll" in tr.produced_by and a.path == b.path
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

    # ---- slide drift: a gentle 1.03x push, only while a slide is on screen ---
    plan.slide_states = frozenset(i for i, st in enumerate(states) if st.kind == "slide")
    for i, st in enumerate(states[: len(plan.swaps) + 1] if SLIDE_DRIFT > 1.001 else []):
        if st.kind != "slide":
            continue
        start = plan.swaps[i - 1].t1 if i > 0 else 0.0
        if i < len(plan.swaps):
            hold_until, t_out = plan.swaps[i].t0, plan.swaps[i].t1
        else:
            hold_until = t_out = plan.duration
        if hold_until - start < 0.5:
            continue
        # The push runs the whole time the slide is up, so no frame of it is a repeat of the
        # one before. hold_until == t1 means there is no settle phase to hold, and the drift
        # is still at full extent when the scene cross-dissolves away from it.
        plan.cameras.append(
            CameraEvt(start, hold_until, hold_until, t_out, _drift_rect(),
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


def _drift_rect() -> tuple[float, float, float, float]:
    w = WIN_W / SLIDE_DRIFT
    h = WIN_H / SLIDE_DRIFT
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


_tall_cache: dict[tuple[int, int, int], tuple[np.ndarray, int]] = {}


def _scroll_tall(store: PageStore, sw: Swap) -> tuple[np.ndarray, int]:
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
            frame = _render_frame(plan, store, camera, dims, glow_cache, cap, t)
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


def _render_frame(
    plan: ScenePlan,
    store: PageStore,
    camera: Camera,
    dims: DimCache,
    glow_cache: dict[tuple[int, int], Sprite],
    cap: tuple[Sprite, int, int] | None,
    t: float,
) -> np.ndarray:
    frm, to, prog, swap = _state_at(plan, t)
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
            u = ease_in_out_cubic(prog)
            off = int(round(dy * u)) if swap.dy_css > 0 else int(round(dy * (1.0 - u)))
            page = np.ascontiguousarray(tall[off : off + WIN_H])
            _apply_fixed(page, store.page(swap.to), store.fixed_bands(swap.frm, swap.to))
            page_id = 900000 + off
        elif swap is not None:
            page = blend_pages(store.page(frm), store.page(to), ease_in_out_cubic(prog))
            page_id = 800000 + int(prog * 1000)
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
    if cap is not None and t >= plan.caption_from:
        sp, cx0, cy0 = cap
        a_in = clamp((t - max(LEAD_IN * 0.5, plan.caption_from)) / CAPTION_FADE, 0.0, 1.0)
        a_out = clamp((plan.duration - 0.25 - t) / CAPTION_FADE, 0.0, 1.0)
        a = ease_in_out_cubic(min(a_in, a_out))
        # Captions only ever run over dashboard pages (a slide-only scene sets caption_from
        # to infinity), and the sidebar sits in the same place on every one of them, so the
        # band is a constant in page space and only the camera can move it.
        if not on_slide:
            _cover_sidebar_foot(canvas, a, cam_rect)
        blit(canvas, sp, cx0, cy0, a)
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
    ap.add_argument(
        "--build",
        type=Path,
        default=Path(__file__).resolve().parent / "build",
        help="build directory",
    )
    args = ap.parse_args(argv)
    if args.selftest:
        selftest(args.build)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
