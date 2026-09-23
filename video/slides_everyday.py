"""Illustrated slides for the everyday-audience film, "Meet the Household" (video/everyday/SCRIPT.md).

Same contract as ``video/slides.py``: every public function returns a complete, self-contained
HTML document for a 1600x900 viewport, meant to be screenshotted at ``device_scale_factor=2``.
Flat inline SVG only: no external assets, no web fonts, no photographs, no real brand logos.

The palette and type are the dashboard's "Stone & Sage" day theme (design/final/tokens.json and
style.css), so an illustration and the redesigned dashboard read as one world: stone page, linen
cards, deep green-black ink, a sage accent, and the five severity pigments used *only* where a
severity is meant. Titles use the dashboard's local book face (Palatino Linotype first), labels
use Segoe UI. Everything is rendered in light mode (``color_scheme="light"``).

Text on the slides is deliberately minimal and large: this audience reads a slide in two seconds
or not at all. The narration carries the explanation; the drawing carries the joke and the idea.

Public API::

    SLIDES: dict[str, Callable[[], str]]    # narrative order, keyed by illustration name
    render(name) -> str
    slide_names() -> list[str]
    write_all(directory) -> list[str]        # HTML files, for eyeballing
    render_png(directory) -> list[Path]      # PNGs via the installed Chrome, plus contact.png

Run ``python video/slides_everyday.py`` to render every slide into ``video/everyday/slides/``.
"""

from __future__ import annotations

import html as _html
import logging
import math
from pathlib import Path
from typing import Callable, Iterable, Sequence

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------- palette (day theme)

VIEWPORT_W = 1600
VIEWPORT_H = 900

BG = "#e5e0d5"            # --bg: stone page
SIDEBAR = "#ddd8cb"       # --sidebar: used here as the floor band
PANEL = "#eeeae0"         # --panel: linen card
PANEL_2 = "#e6e2d7"       # --panel-2
LINE = "#d3cdc0"          # --line
LINE_STRONG = "#767164"   # --line-strong
FG = "#1f2d29"            # --fg: ink
FG_2 = "#33433d"          # --fg-2
MUTED = "#4d5a54"         # --muted
ACCENT = "#46705d"        # --accent: sage
ACCENT_INK = "#2f5a4b"    # --accent-ink: sage as text
ACCENT_FG = "#f5f2ea"     # --accent-fg: the palette's "white"
ACCENT_TINT = "#d5dfd1"   # --accent-tint
FOCUS = "#2f5f73"         # --focus

SEV = {  # (pigment, text-on-pigment, ink, tint) -- severity words, never decoration
    "critical": ("#842a2f", "#f7f3ea", "#842a2f", "#efd9d4"),
    "high": ("#975b30", "#f7f3ea", "#85502a", "#f0dfd0"),
    "medium": ("#ae7b2f", "#1b160d", "#694e12", "#eee3c8"),
    "low": ("#728b6b", "#1b160d", "#4a5f44", "#dfe5d6"),
    "info": ("#365c7a", "#f7f3ea", "#335874", "#dae2e6"),
}
BRICK = SEV["critical"][0]
SEV_WORDS = (
    ("critical", "Fix now"),
    ("high", "Fix this week"),
    ("medium", "Worth fixing"),
    ("low", "When you have time"),
    ("info", "Good to know"),
)

# the dashboard's chart hues: the only other colours an illustration may use
PLUM = "#7a6788"          # --chart-5
TEAL = "#4c7f7a"          # --chart-6
ROSE = "#9c5460"          # --chart-7
WOOD = "#87684a"          # --chart-8
TRACK = "#dcd6ca"         # --chart-track

SANS = '"Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif'
SERIF = '"Palatino Linotype", "Iowan Old Style", "Book Antiqua", Palatino, Georgia, serif'
MONO = 'ui-monospace, "Cascadia Mono", "Consolas", "SF Mono", Menlo, monospace'
#: local handwriting faces only (Windows ships Segoe Print); never a web font
HAND = '"Segoe Print", "Bradley Hand", "Comic Sans MS", cursive'

SW = 3.5  # the house line weight, in CSS px


def _mix(a: str, b: str, t: float) -> str:
    """Blend two hex colours: ``t=0`` is ``a``, ``t=1`` is ``b``. Keeps every tint on-palette."""
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(ca, cb))


WOOD_LIGHT = _mix(WOOD, PANEL, 0.55)
WOOD_PALE = _mix(WOOD, PANEL, 0.75)
WOOD_DARK = _mix(WOOD, FG, 0.25)
SHADOW = _mix(BG, FG, 0.08)
FLOOR = SIDEBAR
LAB = _mix(SEV["medium"][0], PANEL, 0.55)      # a yellow Labrador, from ochre and linen
LAB_LINE = _mix(SEV["medium"][2], WOOD, 0.3)
SLEEVES = (PLUM, TEAL, SEV["info"][0], WOOD, ROSE)
#: skin tones for hands: muted so they sit on stone, varied so every household is in it
SKIN = ("#e3bf9f", "#c08d69", "#8e5e40", "#5f3f2c")


# --------------------------------------------------------------------------- document shell

_BASE_CSS = f"""
*, *::before, *::after {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; width: {VIEWPORT_W}px; height: {VIEWPORT_H}px; overflow: hidden; }}
body {{
  background: {BG}; color: {FG}; font-family: {SANS};
  -webkit-font-smoothing: antialiased; text-rendering: geometricPrecision;
}}
svg.art {{ display: block; width: {VIEWPORT_W}px; height: {VIEWPORT_H}px; }}
"""


def _esc(text: str) -> str:
    return _html.escape(text, quote=True)


def _document(page_title: str, label: str, body: str, extra_css: str = "") -> str:
    """A full HTML document holding one 1600x900 SVG illustration on the stone page."""
    svg = (
        f'<svg class="art" viewBox="0 0 {VIEWPORT_W} {VIEWPORT_H}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" '
        f'aria-label="{_esc(label)}" stroke-linecap="round" stroke-linejoin="round">'
        f'<rect width="{VIEWPORT_W}" height="{VIEWPORT_H}" fill="{BG}"/>'
        f"{body}</svg>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="color-scheme" content="light">\n'
        f"<title>{_esc(page_title)} · Home SOC</title>\n"
        f"<style>{_BASE_CSS}{extra_css}</style>\n"
        "</head>\n<body>\n"
        f"{svg}\n"
        "</body>\n</html>\n"
    )


# --------------------------------------------------------------------------- drawing helpers


def _t(x: float, y: float, text: str, size: float = 28, *, weight: int = 600, fill: str = FG,
       family: str = SANS, anchor: str = "middle", italic: bool = False, ls: float | None = None,
       extra: str = "") -> str:
    style = ' font-style="italic"' if italic else ""
    spacing = f' letter-spacing="{ls:g}"' if ls is not None else ""
    return (
        f'<text x="{x:g}" y="{y:g}" text-anchor="{anchor}" font-family=\'{family}\' '
        f'font-size="{size:g}" font-weight="{weight}" fill="{fill}"{style}{spacing} {extra}>'
        f"{_esc(text)}</text>"
    )


def _lines(x: float, y: float, lines: Sequence[str], size: float, lh: float, **kw) -> str:
    return "".join(_t(x, y + i * lh, s, size, **kw) for i, s in enumerate(lines))


def _rect(x: float, y: float, w: float, h: float, *, rx: float = 0, fill: str = PANEL,
          stroke: str | None = None, sw: float = SW, extra: str = "") -> str:
    st = f' stroke="{stroke}" stroke-width="{sw:g}"' if stroke else ""
    return (f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="{rx:g}" '
            f'fill="{fill}"{st} {extra}/>')


def _circle(cx: float, cy: float, r: float, *, fill: str = PANEL, stroke: str | None = None,
            sw: float = SW, extra: str = "") -> str:
    st = f' stroke="{stroke}" stroke-width="{sw:g}"' if stroke else ""
    return f'<circle cx="{cx:g}" cy="{cy:g}" r="{r:g}" fill="{fill}"{st} {extra}/>'


def _path(d: str, *, fill: str = "none", stroke: str | None = FG, sw: float = SW,
          extra: str = "") -> str:
    st = f' stroke="{stroke}" stroke-width="{sw:g}"' if stroke else ""
    return f'<path d="{d}" fill="{fill}"{st} {extra}/>'


def _line(x1: float, y1: float, x2: float, y2: float, *, stroke: str = FG, sw: float = SW,
          extra: str = "") -> str:
    return (f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}" stroke="{stroke}" '
            f'stroke-width="{sw:g}" {extra}/>')


def _g(body: str, *, x: float = 0, y: float = 0, s: float = 1, rot: float = 0,
       extra: str = "") -> str:
    tf = f"translate({x:g} {y:g})"
    if rot:
        tf += f" rotate({rot:g})"
    if s != 1:
        tf += f" scale({s:g})"
    return f'<g transform="{tf}" {extra}>{body}</g>'


def _card(x: float, y: float, w: float, h: float, *, rx: float = 22, fill: str = PANEL,
          stroke: str = LINE, lift: float = 6) -> str:
    """A linen card like the dashboard's: hairline edge, a soft flat shadow under it."""
    return (_rect(x + 2, y + lift, w, h, rx=rx, fill=SHADOW)
            + _rect(x, y, w, h, rx=rx, fill=fill, stroke=stroke, sw=2))


def _shadow(cx: float, cy: float, rx: float, ry: float = 12) -> str:
    return f'<ellipse cx="{cx:g}" cy="{cy:g}" rx="{rx:g}" ry="{ry:g}" fill="{SHADOW}"/>'


def _floor(y: float = 760) -> str:
    return (_rect(0, y, VIEWPORT_W, VIEWPORT_H - y, fill=FLOOR)
            + _line(0, y, VIEWPORT_W, y, stroke=LINE, sw=3))


def _bubble(x: float, y: float, w: float, h: float, *, tail: tuple[float, float],
            base: float | None = None, r: float = 26, fill: str = PANEL,
            stroke: str = LINE_STRONG, sw: float = 3) -> str:
    """A speech bubble with its tail on the bottom edge, pointing at ``tail``."""
    bx = base if base is not None else min(max(tail[0], x + r + 30), x + w - r - 30)
    b1, b2 = bx - 20, bx + 20
    tx, ty = tail
    d = (f"M {x + r:g} {y:g} H {x + w - r:g} Q {x + w:g} {y:g} {x + w:g} {y + r:g} "
         f"V {y + h - r:g} Q {x + w:g} {y + h:g} {x + w - r:g} {y + h:g} "
         f"H {b2:g} L {tx:g} {ty:g} L {b1:g} {y + h:g} H {x + r:g} "
         f"Q {x:g} {y + h:g} {x:g} {y + h - r:g} V {y + r:g} Q {x:g} {y:g} {x + r:g} {y:g} Z")
    return _path(d, fill=fill, stroke=stroke, sw=sw)


def _brand_mark(cx: float, cy: float, r: float) -> str:
    """The sidebar's sage leaf dot: a ring with a filled centre."""
    return (_circle(cx, cy, r, fill="none", stroke=ACCENT, sw=max(2.0, r * 0.22))
            + _circle(cx, cy, r * 0.52, fill=ACCENT))


def _sparkle(x: float, y: float, r: float, *, fill: str = ACCENT_FG,
             stroke: str = ACCENT) -> str:
    k = r * 0.28
    d = (f"M {x:g} {y - r:g} Q {x + k:g} {y - k:g} {x + r:g} {y:g} "
         f"Q {x + k:g} {y + k:g} {x:g} {y + r:g} Q {x - k:g} {y + k:g} {x - r:g} {y:g} "
         f"Q {x - k:g} {y - k:g} {x:g} {y - r:g} Z")
    return _path(d, fill=fill, stroke=stroke, sw=2.5)


def _check(x: float, y: float, s: float = 1, *, stroke: str = ACCENT, sw: float = 5) -> str:
    return _path(f"M {x - 12 * s:g} {y:g} L {x - 3 * s:g} {y + 9 * s:g} L {x + 14 * s:g} {y - 11 * s:g}",
                 stroke=stroke, sw=sw)


def _cross(x: float, y: float, s: float = 1, *, stroke: str = LINE_STRONG, sw: float = 5) -> str:
    return (_line(x - 10 * s, y - 10 * s, x + 10 * s, y + 10 * s, stroke=stroke, sw=sw)
            + _line(x + 10 * s, y - 10 * s, x - 10 * s, y + 10 * s, stroke=stroke, sw=sw))


def _arm(x1: float, y1: float, x2: float, y2: float, *, sleeve: str, skin: str,
         width: float = 40, hand: float = 21) -> str:
    """A sleeve from (x1,y1) ending in a simple hand at (x2,y2): cuff, sleeve, round hand."""
    ang = math.atan2(y2 - y1, x2 - x1)
    cx, cy = x2 - math.cos(ang) * hand * 0.9, y2 - math.sin(ang) * hand * 0.9
    return (
        _line(x1, y1, cx, cy, stroke=sleeve, sw=width)
        + _line(cx - math.cos(ang) * 4, cy - math.sin(ang) * 4, cx, cy,
                stroke=_mix(sleeve, FG, 0.25), sw=width + 2, extra='stroke-linecap="butt"')
        + _circle(x2, y2, hand, fill=skin, stroke=_mix(skin, FG, 0.35), sw=2.5)
    )


def _person(x: float, base: float, *, h: float = 330, jumper: str = ACCENT, skin: str = SKIN[1],
            hair: str = FG_2, mark: bool = True) -> str:
    """A friendly standing silhouette (head, rounded body, legs). ``x`` is the centre line."""
    head_r = h * 0.085
    head_y = base - h + head_r
    body_top = head_y + head_r + 10
    body_h = h * 0.45
    out = [
        _shadow(x, base + 4, h * 0.22, 10),
        # legs
        _rect(x - h * 0.1, body_top + body_h - 20, h * 0.085, base - body_top - body_h + 20,
              rx=h * 0.04, fill=FG_2),
        _rect(x + h * 0.015, body_top + body_h - 20, h * 0.085, base - body_top - body_h + 20,
              rx=h * 0.04, fill=FG_2),
        # body
        _rect(x - h * 0.16, body_top, h * 0.32, body_h, rx=h * 0.12, fill=jumper,
              stroke=_mix(jumper, FG, 0.3), sw=3),
        # head and hair
        _circle(x, head_y, head_r, fill=skin, stroke=_mix(skin, FG, 0.35), sw=2.5),
        _path(f"M {x - head_r:g} {head_y - 2:g} A {head_r:g} {head_r:g} 0 0 1 {x + head_r:g} {head_y - 2:g} "
              f"Q {x:g} {head_y - head_r * 0.35:g} {x - head_r:g} {head_y - 2:g} Z",
              fill=hair, stroke=None),
    ]
    if mark:
        out.append(_circle(x, body_top + body_h * 0.32, h * 0.03, fill="none",
                           stroke=ACCENT_FG, sw=3))
        out.append(_circle(x, body_top + body_h * 0.32, h * 0.014, fill=ACCENT_FG))
    return "".join(out)


# --------------------------------------------------------------------------- device icons
#
# Every icon is drawn in a ~100 unit box centred on (0, 0), in the house line weight, so the
# same printer is the same printer on every slide.


def _icon(kind: str, x: float, y: float, s: float = 1.0, *, stroke: str = ACCENT,
          fill: str = PANEL, sw: float = SW, opacity: float = 1.0, face: bool = False) -> str:
    st = f'stroke="{stroke}" stroke-width="{sw:g}"'
    p: list[str] = []

    def r(x0, y0, w, h, rx=4, f=fill):
        p.append(f'<rect x="{x0:g}" y="{y0:g}" width="{w:g}" height="{h:g}" rx="{rx:g}" fill="{f}" {st}/>')

    def c(cx, cy, rr, f=fill):
        p.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="{rr:g}" fill="{f}" {st}/>')

    def ln(d):
        p.append(f'<path d="{d}" fill="none" {st}/>')

    def dot(cx, cy, rr, f=stroke):
        p.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="{rr:g}" fill="{f}"/>')

    if kind == "phone":
        r(-17, -32, 34, 64, 8)
        ln("M -6 23 H 6")
    elif kind == "laptop":
        r(-34, -30, 68, 44, 5)
        p.append(f'<path d="M -46 18 H 46 L 40 28 H -40 Z" fill="{fill}" {st}/>')
    elif kind == "tv":
        r(-46, -32, 92, 56, 5)
        ln("M 0 24 V 32 M -18 34 H 18")
    elif kind == "tablet":
        r(-40, -28, 80, 56, 9)
        dot(31, 0, 3)
    elif kind == "kitchen_speaker":
        r(-22, -30, 44, 62, 16)
        ln("M -22 -16 Q 0 -9 22 -16")
        for yy in (4, 14):
            for xx in (-8, 0, 8):
                dot(xx, yy, 2.2)
    elif kind == "speaker":
        r(-21, -38, 42, 76, 11)
        c(0, 10, 12)
        dot(0, -22, 3.2)
    elif kind == "printer":
        r(-24, -38, 48, 26, 3)
        r(-40, -16, 80, 38, 8)
        r(-26, 16, 52, 20, 2)
        dot(28, -4, 3.4)
        if face:  # a small, dignified printer: eyes half-lidded, no smile, no frown
            for ex in (-11, 5):
                dot(ex, 1, 3.4, FG)
                p.append(f'<path d="M {ex - 5:g} -2 H {ex + 5:g}" stroke="{stroke}" stroke-width="2.6" fill="none"/>')
    elif kind == "lamp":
        p.append(f'<path d="M -20 -36 H 20 L 30 -8 H -30 Z" fill="{fill}" {st}/>')
        ln("M 0 -8 V 24 M -16 26 H 16")
        r(20, 14, 20, 20, 5)
        ln("M 16 26 Q 18 20 26 20")
    elif kind == "heater":
        r(-36, -10, 72, 42, 7)
        ln("M -20 -4 V 26 M -6 -4 V 26 M 8 -4 V 26 M 22 -4 V 26")
        ln("M -18 -24 q 5 -6 0 -12 M 0 -24 q 5 -6 0 -12 M 18 -24 q 5 -6 0 -12")
    elif kind == "doorbell":
        r(-17, -36, 34, 72, 15)
        c(0, 14, 10)
        c(0, -16, 6)
    elif kind == "console":
        p.append(f'<path d="M -30 -18 H 30 Q 46 -18 46 2 Q 46 26 32 26 Q 24 26 18 14 H -18 '
                 f'Q -24 26 -32 26 Q -46 26 -46 2 Q -46 -18 -30 -18 Z" fill="{fill}" {st}/>')
        ln("M -28 -2 H -14 M -21 -9 V 5")
        dot(18, -5, 3.6)
        dot(27, 3, 3.6)
    elif kind == "pc":
        r(-46, -34, 62, 46, 5)
        ln("M -15 12 V 22 M -28 24 H -2")
        r(24, -32, 22, 58, 4)
        dot(35, -20, 2.6)
    elif kind == "router":
        ln("M -26 -4 L -34 -36 M 26 -4 L 34 -36")
        r(-44, -6, 88, 30, 8)
        for xx in (-26, -14, -2):
            dot(xx, 9, 3)
    elif kind == "camera":
        r(-32, -26, 64, 46, 11)
        c(0, -3, 13)
        dot(0, -3, 4.5)
        dot(22, -16, 2.8)
        r(-8, 20, 16, 12, 2)
        ln("M -18 34 H 18")
    else:  # pragma: no cover - a typo should fail the render loudly
        raise KeyError(kind)
    op = f' opacity="{opacity:g}"' if opacity != 1 else ""
    tf = f"translate({x:g} {y:g})" + (f" scale({s:g})" if s != 1 else "")
    return f'<g transform="{tf}"{op}>{"".join(p)}</g>'


def _question_badge(x: float, y: float, r: float = 17, *, fill: str = BRICK) -> str:
    return (_circle(x, y, r, fill=fill, stroke=PANEL, sw=3)
            + _t(x, y + r * 0.42, "?", r * 1.25, weight=700, fill=SEV["critical"][1]))


def _camera_char(x: float, y: float, s: float = 1.0, *, eyes: str = "open",
                 arms: str = "") -> str:
    """The villain as a character: an unbranded boxy camera with one lens-eye. Never evil."""
    body = [
        _rect(-70, -52, 140, 100, rx=24, fill=ACCENT_FG, stroke=LINE_STRONG),
        _circle(0, -4, 30, fill=FG_2, stroke=LINE_STRONG),
    ]
    if eyes == "closed":
        body.append(_path("M -14 -2 Q 0 10 14 -2", stroke=ACCENT_FG, sw=4))
    elif eyes == "up":
        body.append(_circle(4, -14, 11, fill=ACCENT_TINT, stroke=None))
        body.append(_circle(7, -17, 4, fill=FG, stroke=None))
    else:
        body.append(_circle(0, -4, 11, fill=ACCENT_TINT, stroke=None))
        body.append(_circle(3, -7, 4, fill=FG, stroke=None))
    body.append(_circle(48, -32, 5, fill=SEV["low"][0], stroke=None))
    body.append(_rect(-16, 48, 32, 22, rx=4, fill=PANEL, stroke=LINE_STRONG))
    body.append(_path("M -40 72 H 40", stroke=LINE_STRONG))
    return _g(arms + "".join(body), x=x, y=y, s=s)


# --------------------------------------------------------------------------- title and end cards


def title_card() -> str:
    """02 title: 'Home SOC', the sage leaf dot, 'Home network safety'."""
    body = [
        # a quiet house outline in the background, the only drawing on the card
        _path("M 1080 640 V 420 L 1240 300 L 1400 420 V 640 Z", fill=PANEL, stroke=LINE, sw=4),
        _rect(1210, 520, 60, 120, rx=6, fill=PANEL_2, stroke=LINE, sw=4),
        _rect(1120, 450, 60, 50, rx=6, fill=PANEL_2, stroke=LINE, sw=4),
        _rect(1300, 450, 60, 50, rx=6, fill=PANEL_2, stroke=LINE, sw=4),
        _brand_mark(1240, 380, 18),
        _brand_mark(250, 395, 34),
        _t(310, 428, "Home SOC", 118, weight=600, family=SERIF, anchor="start"),
        _t(314, 500, "Home network safety", 40, weight=500, fill=MUTED, anchor="start"),
        _line(314, 556, 700, 556, stroke=ACCENT, sw=4),
    ]
    return _document("Title", "Home SOC: home network safety.", "".join(body))


def end_card() -> str:
    """14 end card: the title again, plus 'free and open source'. The printer is still here."""
    body = [
        _brand_mark(250, 395, 34),
        _t(310, 428, "Home SOC", 118, weight=600, family=SERIF, anchor="start"),
        _t(314, 500, "Home network safety · free and open source", 40, weight=500,
           fill=MUTED, anchor="start"),
        _line(314, 556, 700, 556, stroke=ACCENT, sw=4),
        # the printer, at the edge of the frame, would like it noted that it is still here
        _shadow(1386, 736, 62, 9),
        _icon("printer", 1386, 690, 1.25, face=True),
    ]
    return _document("End card", "Home SOC: home network safety, free and open source. "
                     "A small printer sits in the corner.", "".join(body))


# --------------------------------------------------------------------------- I1 the dinner table

_TABLE_C = (800.0, 466.0)
_TABLE_R = 188.0
#: the fifteen gadgets around the room, clockwise from the TV (the three phones are on the table)
_RING = (
    ("tv", -90), ("laptop", -66), ("speaker", -42), ("tablet", -18), ("heater", 6),
    ("lamp", 30), ("printer", 54), ("console", 78), ("doorbell", 102), ("camera", 128),
    ("kitchen_speaker", 152), ("router", 176), ("pc", 200), ("speaker", 223), ("laptop", 246),
)
_ALREADY_THERE = {"tv", "laptop", "tablet", "kitchen_speaker"}  # the family's guess of seven


def _ring_pos(deg: float) -> tuple[float, float]:
    cx, cy = _TABLE_C
    a = math.radians(deg)
    return cx + 560 * math.cos(a), cy + 338 * math.sin(a)


#: The cold open's build, one key frame per phrase (SCRIPT.md I1): the question, the guess, Dad's
#: question, the printer arriving, then each gadget as it is named, the camera, and the count.
#: "guess" and "count" are the original two frames; the others sit between them.
_TABLE_STAGES = ("ask", "guess7", "guess", "printer", "lamp", "heater", "gadgets", "camera",
                 "count")
#: The gadget that each build stage adds (kinds from _RING); "gadgets" adds the rest of the room.
_STAGE_ADDS = {"printer": {"printer"}, "lamp": {"lamp"}, "heater": {"heater"},
               "gadgets": {"doorbell", "speaker", "console", "router", "pc"},
               "camera": {"camera"}}


def _dinner_table(state: str) -> str:
    if state in _TABLE_STAGES and state not in ("guess", "count"):
        return _dinner_table_build(state)
    cx, cy = _TABLE_C
    out: list[str] = []
    # the table, top-down: a wooden round with a linen cloth
    out.append(_circle(cx + 4, cy + 10, _TABLE_R + 14, fill=SHADOW))
    out.append(_circle(cx, cy, _TABLE_R + 12, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_circle(cx, cy, _TABLE_R - 6, fill=PANEL, stroke=LINE, sw=2))
    # a bowl in the middle, because it is dinner
    out.append(_circle(cx, cy, 40, fill=ACCENT_TINT, stroke=ACCENT, sw=3))
    out.append(_circle(cx - 10, cy - 6, 9, fill=SEV["medium"][3], stroke=None))
    out.append(_circle(cx + 12, cy + 6, 8, fill=SEV["low"][3], stroke=None))
    # four places: plate, two hands, sleeves reaching in from the edge of the frame
    people = ((-90, 0, PLUM), (180, 1, TEAL), (0, 2, SEV["info"][0]), (90, 3, WOOD))
    for deg, i, sleeve in people:
        a = math.radians(deg)
        ux, uy = math.cos(a), math.sin(a)
        vx, vy = -uy, ux
        px, py = cx + ux * 118, cy + uy * 118
        out.append(_circle(px, py, 44, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5))
        out.append(_circle(px, py, 28, fill="none", stroke=LINE, sw=2))
        for side in (-1, 1):
            hx, hy = cx + ux * 170 + vx * 58 * side, cy + uy * 170 + vy * 58 * side
            sx, sy = cx + ux * 268 + vx * 70 * side, cy + uy * 268 + vy * 70 * side
            out.append(_arm(sx, sy, hx, hy, sleeve=sleeve, skin=SKIN[i], width=38, hand=19))
    # three phones on the table (Mum's, Dad's, Ellie's)
    phone_op = 0.35 if state == "guess" else 1.0
    for deg in (-90, 180, 0):
        a = math.radians(deg + 34)
        out.append(_g(_icon("phone", 0, 0, 0.62, opacity=phone_op), x=cx + 150 * math.cos(a),
                      y=cy + 150 * math.sin(a), rot=deg + 124))
    # the fifteen around the room
    closing = state in _CLOSING_STATES
    for kind, deg in _RING:
        x, y = _ring_pos(deg)
        if kind == "camera":
            if state in ("closing", "closing_nudge", "guess"):
                continue
            out.append(_shadow(x, y + 44, 40, 7))
            out.append(_icon("camera", x, y, 1.05, stroke=BRICK))
            out.append(_question_badge(x + 38, y - 34, 18))
            continue
        if state == "guess" and kind not in _ALREADY_THERE:
            continue
        op = 0.35 if (state == "guess") else 1.0
        if kind == "printer" and state == "closing_nudge":
            # the printer's one tiny, dignified bounce, on the film's last words
            out.append(_shadow(x, y + 44, 30, 5))
            out.append(_icon(kind, x, y - 12, 1.05, opacity=op, face=True))
            out.append(_path(f"M {x - 50:g} {y - 44:g} q -8 -6 -6 -16 M {x + 50:g} {y - 44:g} "
                             f"q 8 -6 6 -16", stroke=LINE_STRONG, sw=3))
            continue
        out.append(_icon(kind, x, y, 1.05, opacity=op, face=(kind == "printer")))
    # the counter card, top right
    n = {"guess": "7", "count": "18", "closing": "17", "closing18": "18", "closing17": "17",
         "closing_nudge": "17"}[state]
    out.append(_card(1352, 36, 212, 150, rx=20))
    out.append(_t(1458, 76, "on the Wi-Fi", 22, weight=600, fill=MUTED))
    out.append(_t(1458, 160, n, 84, weight=600, family=SERIF,
                  fill=(ACCENT_INK if closing and n == "17" else FG)))
    if state in ("guess", "count"):
        # Mum's guess, and Dad's question
        out.append(_bubble(1034, 262, 150, 90, tail=(1096, 392), base=1092))
        out.append(_t(1109, 324, "7?", 50, weight=600, family=SERIF))
        out.append(_bubble(334, 284, 270, 90, tail=(560, 402), base=548))
        out.append(_t(469, 341, "…the printer?", 36, weight=600, family=SERIF))
    if state in ("closing18", "closing17"):
        # the same kitchen drawer, pulled open and waiting
        out.append(_rect(56, 700, 218, 96, rx=7, fill=_mix(WOOD_PALE, FG, 0.18), stroke=WOOD, sw=3))
        out.append(_rect(70, 712, 190, 74, rx=5, fill=_mix(WOOD_PALE, PANEL, 0.3), stroke=None))
        out.append(_rect(70, 780, 190, 90, rx=9, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
        out.append(_rect(84, 794, 162, 62, rx=6, fill=WOOD_PALE, stroke=WOOD, sw=2.5))
        out.append(_rect(145, 819, 40, 12, rx=6, fill=WOOD, stroke=None))
    if state in ("closing", "closing_nudge"):
        # a small closed kitchen drawer in the corner, with one cable escaping
        out.append(_rect(70, 780, 190, 90, rx=9, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
        out.append(_rect(84, 794, 162, 62, rx=6, fill=WOOD_PALE, stroke=WOOD, sw=2.5))
        out.append(_rect(145, 819, 40, 12, rx=6, fill=WOOD, stroke=None))
        out.append(_path("M 236 794 q 14 -2 18 -16 q 4 -12 16 -10", stroke=FG_2, sw=4))
    return "".join(out)


def _dinner_table_build(state: str) -> str:
    """The frames between the guess and the count: the room fills in as the voice names it.

    Same drawing as :func:`_dinner_table`; only what is on the table changes. The obvious
    gadgets stay faint (the family's guess), each gadget named arrives in full sage, and the
    counter reads "?" until the guess, then 7 until the count.
    """
    stage = _TABLE_STAGES.index(state)
    shown: set[str] = set()
    for name, adds in _STAGE_ADDS.items():
        if stage >= _TABLE_STAGES.index(name):
            shown |= adds
    cx, cy = _TABLE_C
    out: list[str] = []
    out.append(_circle(cx + 4, cy + 10, _TABLE_R + 14, fill=SHADOW))
    out.append(_circle(cx, cy, _TABLE_R + 12, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_circle(cx, cy, _TABLE_R - 6, fill=PANEL, stroke=LINE, sw=2))
    out.append(_circle(cx, cy, 40, fill=ACCENT_TINT, stroke=ACCENT, sw=3))
    out.append(_circle(cx - 10, cy - 6, 9, fill=SEV["medium"][3], stroke=None))
    out.append(_circle(cx + 12, cy + 6, 8, fill=SEV["low"][3], stroke=None))
    people = ((-90, 0, PLUM), (180, 1, TEAL), (0, 2, SEV["info"][0]), (90, 3, WOOD))
    for deg, i, sleeve in people:
        a = math.radians(deg)
        ux, uy = math.cos(a), math.sin(a)
        vx, vy = -uy, ux
        px, py = cx + ux * 118, cy + uy * 118
        out.append(_circle(px, py, 44, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5))
        out.append(_circle(px, py, 28, fill="none", stroke=LINE, sw=2))
        for side in (-1, 1):
            hx, hy = cx + ux * 170 + vx * 58 * side, cy + uy * 170 + vy * 58 * side
            sx, sy = cx + ux * 268 + vx * 70 * side, cy + uy * 268 + vy * 70 * side
            out.append(_arm(sx, sy, hx, hy, sleeve=sleeve, skin=SKIN[i], width=38, hand=19))
    for deg in (-90, 180, 0):
        a = math.radians(deg + 34)
        out.append(_g(_icon("phone", 0, 0, 0.62, opacity=0.35), x=cx + 150 * math.cos(a),
                      y=cy + 150 * math.sin(a), rot=deg + 124))
    for kind, deg in _RING:
        x, y = _ring_pos(deg)
        if kind == "camera":
            if "camera" in shown:
                out.append(_shadow(x, y + 44, 40, 7))
                out.append(_icon("camera", x, y, 1.05, stroke=BRICK))
                out.append(_question_badge(x + 38, y - 34, 18))
            continue
        if kind in _ALREADY_THERE:
            out.append(_icon(kind, x, y, 1.05, opacity=0.35))
        elif kind in shown:
            if kind == "printer":
                out.append(_shadow(x, y + 44, 40, 7))
            out.append(_icon(kind, x, y, 1.05, face=(kind == "printer")))
    n = "?" if state == "ask" else "7"
    out.append(_card(1352, 36, 212, 150, rx=20))
    out.append(_t(1458, 76, "on the Wi-Fi", 22, weight=600, fill=MUTED))
    out.append(_t(1458, 160, n, 84, weight=600, family=SERIF, fill=FG))
    if stage >= _TABLE_STAGES.index("guess7"):
        out.append(_bubble(1034, 262, 150, 90, tail=(1096, 392), base=1092))
        out.append(_t(1109, 324, "7?", 50, weight=600, family=SERIF))
    if stage >= _TABLE_STAGES.index("guess"):
        out.append(_bubble(334, 284, 270, 90, tail=(560, 402), base=548))
        out.append(_t(469, 341, "\u2026the printer?", 36, weight=600, family=SERIF))
    return "".join(out)


def _dinner_table_frame(state: str, alt: str):
    def frame() -> str:
        return _document("The dinner-table count", alt, _dinner_table(state))
    frame.__name__ = f"dinner_table_{state}"
    frame.__doc__ = f"I1, build frame '{state}' (01): {alt}"
    return frame


dinner_table_ask = _dinner_table_frame(
    "ask", "Top-down dinner table, a TV, laptops, a tablet and a kitchen speaker faintly around "
    "the room. The counter reads '?'.")
dinner_table_guess7 = _dinner_table_frame(
    "guess7", "The same table. Someone guesses seven. Counter: 7.")
dinner_table_printer = _dinner_table_frame(
    "printer", "The printer arrives at the edge of the room. Counter still 7.")
dinner_table_lamp = _dinner_table_frame(
    "lamp", "A lamp plug joins the room. Counter still 7.")
dinner_table_heater = _dinner_table_frame(
    "heater", "A heater plug joins the lamp and the printer. Counter still 7.")
dinner_table_gadgets = _dinner_table_frame(
    "gadgets", "The doorbell, two speakers, the games console, the router and the PC join them. "
    "Counter still 7.")
dinner_table_camera = _dinner_table_frame(
    "camera", "One more: a camera with a red question mark. Counter still 7.")


def dinner_table_guess() -> str:
    """I1, first state: '7?' and '...the printer?', with the obvious gadgets faintly there."""
    return _document("The dinner-table count", "Top-down dinner table. Someone guesses seven; "
                     "someone asks about the printer. A TV, laptops, a tablet and a kitchen "
                     "speaker are faintly around the room.", _dinner_table("guess"))


def dinner_table_count() -> str:
    """I1, the reveal: all eighteen, the camera with a brick-red '?', counter at 18."""
    return _document("The dinner-table count", "The same table with all eighteen gadgets "
                     "around it, including a printer, a lamp, a heater, a doorbell, speakers, a "
                     "games console and a camera with a red question mark. Counter: 18.",
                     _dinner_table("count"))


def dinner_table_closing() -> str:
    """I1, closing state (14): all calm sage, the camera gone, a drawer in the corner, 17."""
    return _document("The dinner-table count", "The same table, every gadget calm. The camera "
                     "is gone and a small drawer sits closed in the corner. Counter: 17.",
                     _dinner_table("closing"))


#: The close's key frames (SCRIPT.md I1, closing state), cut on their words like the cold open:
#: the table as the cold open left it (18, the camera and its '?', a drawer open in the corner),
#: 17 on "Seventeen", the camera gone and the drawer shut on "The camera's in the drawer", and
#: the printer's one bounce on "still here".
_CLOSING_STATES = ("closing18", "closing17", "closing", "closing_nudge")

dinner_table_closing18 = _dinner_table_frame(
    "closing18", "The table as the cold open left it: all eighteen gadgets, the camera with its "
    "red question mark, and a kitchen drawer standing open in the corner. Counter: 18.")
dinner_table_closing17 = _dinner_table_frame(
    "closing17", "The same table; the counter drops to 17. The camera is still there, the "
    "drawer still open.")
dinner_table_closing_nudge = _dinner_table_frame(
    "closing_nudge", "The closing table, camera in the drawer, counter 17; the printer gives one "
    "small bounce.")



# --------------------------------------------------------------------------- I2 the new housemate


def _mini_dashboard(x: float, y: float, w: float, h: float) -> str:
    """The Home page, shrunk to a monitor: sidebar, a gauge, three cards. Recognisable, not legible."""
    out = [_rect(x, y, w, h, rx=6, fill=BG),
           _rect(x, y, w * 0.2, h, rx=6, fill=SIDEBAR),
           _circle(x + 14, y + 14, 5, fill=ACCENT)]
    for i in range(5):
        out.append(_rect(x + 8, y + 30 + i * 18, w * 0.2 - 16, 6, rx=3,
                         fill=(ACCENT_TINT if i == 0 else LINE)))
    cx = x + w * 0.2 + 12
    out.append(_rect(cx, y + 12, w * 0.36, h - 24, rx=8, fill=PANEL))
    gx, gy, gr = cx + w * 0.18, y + h * 0.62, w * 0.11
    out.append(_path(f"M {gx - gr:g} {gy:g} A {gr:g} {gr:g} 0 0 1 {gx + gr:g} {gy:g}",
                     stroke=TRACK, sw=8))
    out.append(_path(f"M {gx - gr:g} {gy:g} A {gr:g} {gr:g} 0 0 1 {gx - gr * 0.8:g} {gy - gr * 0.6:g}",
                     stroke=BRICK, sw=8))
    for j in range(3):
        out.append(_rect(cx + w * 0.36 + 10, y + 12 + j * ((h - 24) / 3), w * 0.36 - 16,
                         (h - 24) / 3 - 8, rx=6, fill=PANEL))
    return "".join(out)


def _labrador(x: float, y: float, *, awake: bool) -> str:
    """A yellow Labrador asleep on the floor, facing left. ``awake`` opens one eye."""
    out = [
        _shadow(x + 20, y + 52, 190, 12),
        _path(f"M {x + 150:g} {y:g} q 58 -8 52 -52 q -3 -18 -18 -16", stroke=LAB_LINE, sw=10),
        f'<ellipse cx="{x + 20:g}" cy="{y + 4:g}" rx="150" ry="50" fill="{LAB}" stroke="{LAB_LINE}" stroke-width="3.5"/>',
        f'<ellipse cx="{x - 104:g}" cy="{y + 44:g}" rx="40" ry="13" fill="{LAB}" stroke="{LAB_LINE}" stroke-width="3"/>',
        _circle(x - 140, y - 8, 46, fill=LAB, stroke=LAB_LINE),
        f'<ellipse cx="{x - 184:g}" cy="{y + 12:g}" rx="30" ry="20" fill="{LAB}" stroke="{LAB_LINE}" stroke-width="3.5"/>',
        _circle(x - 208, y + 6, 8, fill=FG_2),
        _path(f"M {x - 126:g} {y - 44:g} q 34 6 26 58 q -22 4 -30 -26 Z", fill=_mix(LAB, WOOD, 0.35),
              stroke=LAB_LINE, sw=3),
    ]
    if awake:
        out.append(_circle(x - 158, y - 14, 8, fill=ACCENT_FG, stroke=FG_2, sw=2.5))
        out.append(_circle(x - 160, y - 14, 4, fill=FG))
    else:
        out.append(_path(f"M {x - 168:g} {y - 12:g} q 10 8 20 0", stroke=FG_2, sw=3.5))
        out.append(_t(x - 84, y - 84, "z", 34, weight=600, fill=MUTED, family=SERIF, italic=True))
        out.append(_t(x - 54, y - 118, "z", 44, weight=600, fill=MUTED, family=SERIF, italic=True))
    return "".join(out)


def _housemate(awake: bool) -> str:
    out = [_floor(770)]
    # the two cards: what it does, what it doesn't
    out.append(_card(70, 50, 500, 272))
    out.append(_circle(126, 110, 26, fill=ACCENT))
    out.append(_check(126, 110, 1.0, stroke=ACCENT_FG, sw=5))
    out.append(_t(170, 126, "Does", 48, weight=600, family=SERIF, anchor="start"))
    out.append(_lines(112, 190, ["Looks around", "Explains in plain words", "Points you to the fix"],
                      32, 50, weight=500, anchor="start"))
    out.append(_card(1030, 50, 500, 272))
    out.append(_circle(1086, 110, 26, fill=TRACK, stroke=LINE_STRONG, sw=2))
    out.append(_cross(1086, 110, 0.9, stroke=FG_2, sw=4.5))
    out.append(_t(1130, 126, "Doesn’t", 48, weight=600, family=SERIF, anchor="start"))
    out.append(_lines(1072, 190, ["Replace your antivirus", "Make you hacker-proof"],
                      32, 50, weight=500, anchor="start"))
    # the kitchen table
    out.append(_rect(420, 566, 24, 204, rx=4, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(1156, 566, 24, 204, rx=4, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(390, 540, 820, 28, rx=6, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    # the family PC, showing Home SOC's Home page
    out.append(_rect(640, 516, 40, 26, rx=3, fill=FG_2))
    out.append(f'<ellipse cx="660" cy="540" rx="58" ry="7" fill="{FG_2}"/>')
    out.append(_rect(506, 344, 308, 180, rx=14, fill=FG_2, stroke=FG, sw=3))
    out.append(_mini_dashboard(520, 358, 280, 152))
    out.append(_rect(836, 404, 70, 136, rx=8, fill=PANEL, stroke=LINE_STRONG, sw=3))
    out.append(_circle(871, 428, 6, fill=ACCENT))
    out.append(_line(852, 470, 890, 470, stroke=LINE, sw=3))
    out.append(_line(852, 486, 890, 486, stroke=LINE, sw=3))
    # a mug of tea, still warm
    out.append(_path("M 994 494 q 26 0 26 20 q 0 20 -26 20", stroke=ACCENT, sw=5))
    out.append(_rect(944, 480, 54, 60, rx=10, fill=ACCENT_TINT, stroke=ACCENT, sw=3.5))
    for sx in (960, 982):
        out.append(_path(f"M {sx} 466 q -9 -12 0 -24 q 9 -12 0 -24", stroke=LINE_STRONG, sw=3))
    # the notepad with its short list
    out.append(_path("M 1040 540 L 1180 540 L 1162 510 L 1056 510 Z", fill=ACCENT_FG,
                     stroke=LINE_STRONG, sw=3))
    out.append(_line(1074, 520, 1150, 520, stroke=LINE, sw=2.5))
    out.append(_line(1070, 530, 1160, 530, stroke=LINE, sw=2.5))
    out.append(_line(1110, 504, 1190, 486, stroke=WOOD, sw=6))
    # the Labrador, who is not the security system
    out.append(_labrador(820, 712, awake=awake))
    return "".join(out)


def new_housemate() -> str:
    """I2: the kitchen table, the family PC, a mug, a list, and a sleeping Labrador."""
    return _document("The new housemate", "A kitchen table with the family PC showing Home SOC, a "
                     "mug and a notepad. Card one: Does: looks around, explains in plain words, "
                     "points you to the fix. Card two: Doesn't: replace your antivirus, make you "
                     "hacker-proof. A Labrador sleeps under the table.", _housemate(False))


def new_housemate_dog_awake() -> str:
    """I2 on 'Labrador': the same frame with the dog's one eye open."""
    return _document("The new housemate", "The same kitchen table; the Labrador has opened one "
                     "eye.", _housemate(True))


# --------------------------------------------------------------------------- I3 double-click


#: I3's key frames, cut on their words (the finish pass: one frame held for fifteen seconds
#: across the own-network rule and the printer joke): the double-click and "No account needed";
#: the rule, on "One rule"; the clock, on "Give it five minutes"; the printer, on "less time than
#: the printer takes".
_CLICK_STAGES = ("start", "rule", "clock", "printer")


def _double_click(stage: str) -> str:
    n = _CLICK_STAGES.index(stage)
    out = [
        _rect(730, 760, 140, 50, fill=LINE_STRONG),
        _rect(640, 806, 320, 18, rx=9, fill=LINE_STRONG),
        _rect(150, 60, 1300, 710, rx=28, fill=FG_2),
        _rect(170, 80, 1260, 670, rx=16, fill=PANEL_2),
        _rect(170, 690, 1260, 60, rx=0, fill=SIDEBAR),
        _line(170, 690, 1430, 690, stroke=LINE, sw=2),
    ]
    for i, x in enumerate((210, 262, 314)):
        out.append(_rect(x, 704, 34, 32, rx=8, fill=(ACCENT if i == 0 else LINE)))
    # the launcher
    out.append(_card(300, 170, 190, 190, rx=40))
    out.append(_brand_mark(395, 265, 50))
    out.append(_t(395, 432, "Home SOC", 34, weight=600, family=SERIF))
    # the double-click: two ripples and the pointer
    out.append(_circle(445, 292, 44, fill="none", stroke=ACCENT, sw=4, extra='opacity=".85"'))
    out.append(_circle(445, 292, 76, fill="none", stroke=ACCENT, sw=3, extra='opacity=".4"'))
    out.append(_path("M 445 292 L 445 366 L 463 349 L 477 380 L 491 373 L 477 343 L 501 342 Z",
                     fill=ACCENT_FG, stroke=FG, sw=3.5))
    # no account
    out.append(_card(660, 170, 640, 124, rx=24))
    out.append(_circle(724, 232, 30, fill=ACCENT))
    out.append(_check(724, 232, 1.1, stroke=ACCENT_FG, sw=5.5))
    out.append(_t(774, 246, "No account needed", 40, weight=600, family=SERIF, anchor="start"))
    if n >= 1:
        # the one rule: your own front door, not next door's
        out.append(_card(660, 322, 640, 124, rx=24))
        out.append(_circle(724, 384, 30, fill=ACCENT_TINT, stroke=ACCENT, sw=3))
        out.append(_path("M 708 398 V 380 L 724 366 L 740 380 V 398 Z", fill=ACCENT_FG,
                         stroke=ACCENT_INK, sw=3))
        out.append(_t(774, 398, "Only networks you own or run", 36, weight=600, family=SERIF,
                      anchor="start"))
    if n >= 2:
        # five minutes on the clock
        cx, cy, r = 420, 572, 62
        a = math.radians(-90 + 30)
        out.append(_circle(cx, cy, r, fill=PANEL, stroke=LINE_STRONG, sw=3.5))
        out.append(_path(f"M {cx} {cy} L {cx} {cy - r + 6} A {r - 6} {r - 6} 0 0 1 "
                         f"{cx + (r - 6) * math.cos(a):.1f} {cy + (r - 6) * math.sin(a):.1f} Z",
                         fill=ACCENT_TINT, stroke=None))
        for k in range(12):
            ang = math.radians(k * 30)
            out.append(_line(cx + (r - 12) * math.cos(ang), cy + (r - 12) * math.sin(ang),
                             cx + (r - 5) * math.cos(ang), cy + (r - 5) * math.sin(ang),
                             stroke=LINE_STRONG, sw=2.5))
        out.append(_line(cx, cy, cx, cy - 44, stroke=FG, sw=4))
        out.append(_line(cx, cy, cx + 28, cy + 8, stroke=FG, sw=5))
        out.append(_circle(cx, cy, 5, fill=FG))
        out.append(_t(cx + 90, cy + 12, "about 5 minutes", 30, weight=600, fill=MUTED,
                      anchor="start"))
    if n >= 3:
        # the printer, unimpressed, still deciding
        out.append(_shadow(1160, 652, 66, 8))
        out.append(_icon("printer", 1160, 602, 1.3, face=True))
        out.append(_bubble(930, 480, 150, 82, tail=(1090, 572), base=1040))
        out.append(_t(1005, 530, "…", 56, weight=700, family=SERIF, fill=FG_2))
    alts = {
        "start": "A desktop with the Home SOC launcher being double-clicked. A card says No "
                 "account needed.",
        "rule": "The same desktop; a second card says Only networks you own or run.",
        "clock": "The same desktop; a small clock shows about five minutes.",
        "printer": "The same desktop; the printer has turned up in the corner, unimpressed, "
                   "with a speech bubble that says only '...'.",
    }
    return _document("Double-click", alts[stage], "".join(out))


def double_click() -> str:
    """I3: a launcher icon, a click ripple, and 'No account needed'."""
    return _double_click("start")


def double_click_rule() -> str:
    """I3 on 'One rule': only networks you own or run."""
    return _double_click("rule")


def double_click_clock() -> str:
    """I3 on 'Give it five minutes': the clock."""
    return _double_click("clock")


def double_click_printer() -> str:
    """I3 on 'less time than the printer takes': the printer, deciding."""
    return _double_click("printer")


# --------------------------------------------------------------------------- I4 the robot forecast


def _cloud(cx: float, cy: float, s: float = 1.0, *, fill: str = ACCENT_FG,
           stroke: str = LINE_STRONG, sw: float = SW) -> str:
    """A soft cumulus centred on (cx, cy), about 200 x 130 at s=1."""
    d = (f"M {cx - 80 * s:g} {cy + 44 * s:g} "
         f"A {40 * s:g} {40 * s:g} 0 0 1 {cx - 70 * s:g} {cy - 32 * s:g} "
         f"A {58 * s:g} {58 * s:g} 0 0 1 {cx + 34 * s:g} {cy - 52 * s:g} "
         f"A {46 * s:g} {46 * s:g} 0 0 1 {cx + 94 * s:g} {cy - 2 * s:g} "
         f"A {32 * s:g} {32 * s:g} 0 0 1 {cx + 86 * s:g} {cy + 44 * s:g} Z")
    return _path(d, fill=fill, stroke=stroke, sw=sw)


def robot_forecast() -> str:
    """I4: a boxy robot reads CRITICAL. HIGH... like a weather warning; the plain words beside."""
    info_tint = SEV["info"][3]
    info_line = SEV["info"][2]
    out = [_floor(770)]
    # the weather wall behind the desk
    out.append(_rect(80, 70, 780, 520, rx=22, fill=info_tint, stroke=info_line, sw=2.5))
    out.append(_cloud(220, 180, 0.7, fill=ACCENT_FG, stroke=info_line))
    out.append(_path("M 226 222 L 204 262 L 230 262 L 210 306", stroke=info_line, sw=6))
    out.append(_circle(770, 150, 34, fill=PANEL, stroke=info_line, sw=2.5))
    out.append(_cloud(740, 200, 0.55, fill=ACCENT_FG, stroke=info_line))
    out.append(_cloud(230, 440, 0.55, fill=ACCENT_FG, stroke=info_line))
    for rx_ in (200, 232, 264):
        out.append(_line(rx_, 486, rx_ - 12, 516, stroke=info_line, sw=4))
    # the robot
    out.append(_line(470, 238, 470, 196, stroke=LINE_STRONG, sw=5))
    out.append(_circle(470, 188, 12, fill=ACCENT, stroke=None))
    out.append(_rect(452, 380, 36, 30, fill=LINE_STRONG))
    out.append(_rect(360, 236, 220, 150, rx=28, fill=PANEL_2, stroke=LINE_STRONG))
    out.append(_rect(344, 290, 18, 44, rx=6, fill=LINE_STRONG))
    out.append(_rect(578, 290, 18, 44, rx=6, fill=LINE_STRONG))
    for ex in (425, 515):
        out.append(_circle(ex, 296, 22, fill=ACCENT_FG, stroke=FG_2, sw=3))
        out.append(_circle(ex, 298, 8, fill=FG))
    out.append(_rect(418, 336, 104, 26, rx=6, fill=ACCENT_FG, stroke=FG_2, sw=3))
    for mx in (439, 460, 481, 502):
        out.append(_line(mx, 338, mx, 360, stroke=FG_2, sw=2.5))
    out.append(_rect(330, 404, 280, 190, rx=26, fill=PANEL_2, stroke=LINE_STRONG))
    # the desk
    out.append(_rect(210, 540, 560, 230, rx=14, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(240, 572, 500, 170, rx=8, fill=WOOD_PALE, stroke=WOOD, sw=2.5))
    # the card, read out in a stiff voice
    card = (_rect(0, 0, 400, 132, rx=10, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3)
            + _t(24, 54, "CRITICAL. HIGH.", 32, weight=700, family=MONO, anchor="start", fill=FG)
            + _t(24, 102, "MEDIUM. LOW. INFO.", 32, weight=700, family=MONO, anchor="start", fill=FG))
    out.append(_line(596, 548, 562, 508, stroke=LINE_STRONG, sw=14))
    out.append(_g(card, x=560, y=438, rot=-3))
    out.append(_circle(560, 506, 16, fill=PANEL_2, stroke=LINE_STRONG, sw=3))
    # becomes: the five plain words
    out.append(_path("M 988 450 H 1034", stroke=ACCENT, sw=6))
    out.append(_path("M 1020 434 L 1040 450 L 1020 466", stroke=ACCENT, sw=6))
    out.append(_t(1290, 138, "Home SOC says", 30, weight=600, fill=MUTED))
    for i, (key, word) in enumerate(SEV_WORDS):
        pig, on = SEV[key][0], SEV[key][1]
        y = 170 + i * 110
        out.append(_rect(1070, y, 440, 86, rx=43, fill=pig))
        out.append(_t(1290, y + 56, word, 38, weight=650, fill=on))
    return _document("The robot forecast", "A boxy robot at a weather desk reads a card: CRITICAL. "
                     "HIGH. MEDIUM. LOW. INFO. Beside it, Home SOC's words: Fix now, Fix this week, "
                     "Worth fixing, When you have time, Good to know.", "".join(out))


# --------------------------------------------------------------------------- I5 the little street


def little_street() -> str:
    """I5: numbered houses on one street, and one road out, through the router gate."""
    out = [_rect(0, 690, VIEWPORT_W, 210, fill=FLOOR)]
    # the road: along the street, through the gate, up to the internet
    road = "M -20 645 H 1250 C 1400 645 1440 560 1440 400"
    out.append(_path(road, stroke=LINE, sw=100))
    out.append(_path(road, stroke=PANEL_2, sw=92))
    out.append(_path(road, stroke=LINE_STRONG, sw=3, extra='stroke-dasharray="18 22"'))
    out.append(_rect(0, 580, 1150, 18, fill=SIDEBAR))
    roofs = (PLUM, TEAL, ROSE, WOOD, ACCENT)
    numbers = (".20", ".31", ".32", ".45", ".142")
    for i, (roof, num) in enumerate(zip(roofs, numbers)):
        x = 60 + i * 196
        rc = _mix(roof, PANEL, 0.3)
        out.append(_rect(x, 400, 160, 182, fill=PANEL, stroke=LINE_STRONG, sw=3))
        out.append(_path(f"M {x - 14} 404 L {x + 80} 318 L {x + 174} 404 Z", fill=rc,
                         stroke=_mix(roof, FG, 0.25), sw=3))
        for wx in (x + 18, x + 110):
            out.append(_rect(wx, 418, 32, 30, rx=4, fill=ACCENT_TINT, stroke=LINE_STRONG, sw=2.5))
        out.append(_rect(x + 58, 496, 44, 86, rx=4, fill=_mix(roof, FG, 0.15), stroke=None))
        out.append(_circle(x + 94, 542, 3.5, fill=ACCENT_FG))
        out.append(_rect(x + 36, 456, 88, 32, rx=6, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2))
        out.append(_t(x + 80, 481, num, 24, weight=700, fill=FG))
        if num == ".142":  # nobody knows who lives here
            out.append(_t(x + 34, 443, "?", 26, weight=700, fill=BRICK, family=SERIF))
    # the router gate: every letter in or out passes through it
    out.append(_rect(1146, 520, 20, 176, rx=4, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(1290, 520, 20, 176, rx=4, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_path("M 1156 524 Q 1228 440 1300 524", stroke=WOOD, sw=10))
    out.append(_icon("router", 1228, 458, 0.9))
    # the internet
    out.append(_cloud(1450, 300, 1.25))
    out.append(_t(1442, 326, "the internet", 30, weight=600, family=SERIF, fill=FG))
    # letters on their way
    for ex, ey, rot in ((520, 645, 0), (930, 645, 0), (1400, 520, -70)):
        env = (_rect(-22, -15, 44, 30, rx=4, fill=ACCENT_FG, stroke=ACCENT, sw=2.5)
               + _path("M -20 -12 L 0 3 L 20 -12", stroke=ACCENT, sw=2.5))
        out.append(_g(env, x=ex, y=ey, rot=rot))
    out.append(_t(1228, 760, "router: the way out to the internet", 32, weight=600, family=SERIF))
    # what the house number is called
    out.append(_t(60, 190, "house number = IP address", 40, weight=600, family=SERIF, anchor="start"))
    out.append(_path("M 84 214 C 10 300 8 430 86 470", stroke=ACCENT, sw=3.5,
                     extra='stroke-dasharray="2 10"'))
    out.append(_path("M 72 456 L 90 472 L 70 484", stroke=ACCENT, sw=3.5))
    return _document("The little street", "A street of small houses numbered .20, .31, .32, .45 "
                     "and .142: the house number is the IP address. One road leaves the street "
                     "through a gate with a router on it, up to a cloud: the internet.",
                     "".join(out))


# --------------------------------------------------------------------------- I6 numbered doors


#: I6's key frames, cut on their words (the finish pass: one drawing held for twenty-one seconds,
#: with the only joke of the scene not animated): the doors on "Every gadget is like a house"; the
#: signs on "Behind each open door is a service"; Home SOC with its torch on "Home SOC walks
#: round"; its hand near door 23's handle on "It never tries"; and the hand politely withdrawn on
#: "the handle". Four doors are open - 23, 80, 554 and 8080, the camera's four, as its device
#: page lists them ("One of its four open doors").
_DOOR_STAGES = ("bare", "signs", "walk", "reach", "withdraw")


def _house_doors(signs: bool = True) -> str:
    """One house with six numbered doors; four are open, each with a sign saying what is behind."""
    out = [_floor(760)]
    out.append(_path("M 272 336 L 890 176 L 1508 336 Z", fill=_mix(ROSE, PANEL, 0.45),
                     stroke=_mix(ROSE, FG, 0.25), sw=3.5))
    out.append(_rect(300, 330, 1180, 430, fill=PANEL, stroke=LINE_STRONG, sw=3.5))
    doors = ((23, "remote control"), (25, None), (80, "web page"), (443, None),
             (554, "video"), (8080, "web page"))
    door_c = _mix(TEAL, PANEL, 0.3)
    for i, (num, sign) in enumerate(doors):
        dx = 346 + i * 196
        out.append(_rect(dx + 12, 516, 80, 34, rx=6, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2))
        out.append(_t(dx + 52, 542, str(num), 25, weight=700))
        if sign:
            out.append(_rect(dx, 570, 104, 190, fill=FG_2))
            out.append(_path(f"M {dx} 570 L {dx - 46} 552 L {dx - 46} 780 L {dx} 760 Z",
                             fill=door_c, stroke=_mix(TEAL, FG, 0.3), sw=3))
            out.append(_circle(dx - 36, 668, 6, fill=ACCENT_FG, stroke=FG_2, sw=2))
            if signs:
                out.append(_line(dx + 20, 404, dx + 20, 424, stroke=LINE_STRONG, sw=2.5))
                out.append(_line(dx + 84, 404, dx + 84, 424, stroke=LINE_STRONG, sw=2.5))
                out.append(_rect(dx - 38, 422, 180, 60, rx=12, fill=ACCENT_TINT, stroke=ACCENT,
                                 sw=2.5))
                out.append(_t(dx + 52, 461, sign, 24, weight=650, fill=ACCENT_INK))
        else:
            out.append(_rect(dx, 570, 104, 190, rx=3, fill=door_c, stroke=_mix(TEAL, FG, 0.3), sw=3))
            out.append(_rect(dx + 16, 590, 72, 60, rx=4, fill="none", stroke=_mix(TEAL, FG, 0.2), sw=2))
            out.append(_circle(dx + 88, 668, 6, fill=ACCENT_FG, stroke=FG_2, sw=2))
    return "".join(out)


def _numbered_doors(stage: str) -> str:
    n = _DOOR_STAGES.index(stage)
    out = [_house_doors(signs=n >= 1)]
    if n >= 1:
        out.append(_t(800, 96, "Port = a numbered door.   Service = what\u2019s behind it.", 40,
                      weight=600, family=SERIF))
    else:
        out.append(_t(800, 96, "Port = a numbered door.", 40, weight=600, family=SERIF))
    if n >= 2:
        # Home SOC, walking round with a torch: reading the sign, not trying the handle
        px, base = 196, 760
        out.append(_path("M 262 424 L 302 418 L 302 492 L 262 470 Z", fill=ACCENT_TINT,
                         stroke=None, extra='opacity=".9"'))
        out.append(_person(px, base, h=340, jumper=ACCENT, skin=SKIN[2]))
        out.append(_arm(222, 520, 250, 452, sleeve=ACCENT, skin=SKIN[2], width=26, hand=14))
        out.append(_g(_rect(-8, -26, 16, 34, rx=4, fill=FG_2), x=256, y=446, rot=62))
        if stage == "walk":
            out.append(_arm(226, 580, 236, 684, sleeve=ACCENT, skin=SKIN[2], width=26, hand=14))
        elif stage == "reach":
            # the hand drifts towards door 23's handle (310, 668) ... and stops short of it
            out.append(_arm(226, 580, 290, 662, sleeve=ACCENT, skin=SKIN[2], width=26, hand=14))
        else:
            # ... and is politely withdrawn: "no, thank you"
            out.append(_arm(226, 580, 222, 628, sleeve=ACCENT, skin=SKIN[2], width=26, hand=14))
            out.append(_path("M 262 640 q 10 -6 8 -18", stroke=LINE_STRONG, sw=3))
            out.append(_path("M 270 664 q 12 -2 14 -14", stroke=LINE_STRONG, sw=3))
            out.append(_path("M 300 676 l 18 -18 m 0 18 l -18 -18", stroke=LINE_STRONG, sw=3,
                             extra='opacity=".7"'))
    alts = {
        "bare": "One house with six numbered doors: 23, 25, 80, 443, 554, 8080. Doors 23, 80, "
                "554 and 8080 are open.",
        "signs": "The same house; each open door has a sign: remote control, web page, video, "
                 "web page.",
        "walk": "A figure with a torch walks round the house reading the sign on door 23.",
        "reach": "The figure's free hand drifts towards the handle of door 23.",
        "withdraw": "The figure's hand is politely withdrawn from the handle.",
    }
    return _document("A house with numbered doors", alts[stage], "".join(out))


def numbered_doors() -> str:
    """I6, on 'Home SOC walks round': the figure with the torch reads the signs."""
    return _numbered_doors("walk")


def numbered_doors_bare() -> str:
    """I6, on 'Every gadget is like a house': the doors, four of them open."""
    return _numbered_doors("bare")


def numbered_doors_signs() -> str:
    """I6, on 'Behind each open door is a service': the signs."""
    return _numbered_doors("signs")


def numbered_doors_reach() -> str:
    """I6, on 'It never tries': a hand near door 23's handle."""
    return _numbered_doors("reach")


def numbered_doors_withdraw() -> str:
    """I6, on 'the handle': the hand politely withdrawn."""
    return _numbered_doors("withdraw")


# --------------------------------------------------------------------------- I7 the postcard


def postcard() -> str:
    """I7: a password on a postcard, readable by every hand it passes through."""
    card = [
        _rect(0, 0, 660, 410, rx=10, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3),
        _line(420, 40, 420, 370, stroke=LINE, sw=3),
        _t(36, 128, "username: admin", 40, weight=400, family=HAND, anchor="start", fill=FOCUS),
        _t(36, 214, "PIN: 1234", 44, weight=400, family=HAND, anchor="start", fill=FOCUS),
        _t(36, 330, "Wish you were here!", 28, weight=400, family=HAND, anchor="start", fill=MUTED),
        _rect(530, 30, 100, 118, rx=4, fill=ACCENT_TINT, stroke=ACCENT, sw=2.5,
              extra='stroke-dasharray="5 5"'),
        _path("M 580 124 C 548 104 552 62 592 50 C 606 88 600 112 580 124 Z M 580 124 L 572 136",
              fill=ACCENT, stroke=ACCENT_INK, sw=2),
        _circle(486, 84, 36, fill="none", stroke=LINE_STRONG, sw=2.5),
        _path("M 444 68 q 20 -10 40 0 t 40 0 M 444 102 q 20 -10 40 0 t 40 0",
              stroke=LINE_STRONG, sw=2.5),
    ]
    for ly in (238, 290, 342):
        card.append(_line(452, ly, 626, ly, stroke=LINE, sw=3))
    out = [
        _arm(250, 960, 482, 628, sleeve=PLUM, skin=SKIN[0], width=64, hand=34),
        _g("".join(card), x=470, y=226, rot=-4),
        _arm(1660, 560, 1142, 436, sleeve=TEAL, skin=SKIN[3], width=64, hand=34),
        _arm(1400, -60, 1216, 196, sleeve=WOOD, skin=SKIN[1], width=64, hand=34),
        _path("M 1150 170 q 12 -14 26 -10", stroke=LINE_STRONG, sw=3.5),
        _path("M 1128 402 q -4 -16 8 -26", stroke=LINE_STRONG, sw=3.5),
        _path("M 1130 490 q -4 16 8 26", stroke=LINE_STRONG, sw=3.5),
    ]
    return _document("The postcard", "A postcard passing from hand to hand to hand. On the back, "
                     "handwritten: username: admin, PIN: 1234. Wish you were here!", "".join(out))


# --------------------------------------------------------------------------- I8 Telnet, 1969


def telnet_1969() -> str:
    """I8: a chunky 1969 terminal (cobweb, reading glasses) beside a cheerful moon rocket."""
    beige = _mix(WOOD, PANEL, 0.72)
    beige_line = _mix(WOOD, FG, 0.1)
    out = [_floor(760)]
    out.append(_t(800, 186, "1969", 150, weight=600, family=SERIF))
    # the terminal
    out.append(_shadow(420, 762, 280, 12))
    out.append(_rect(160, 670, 520, 76, rx=14, fill=beige, stroke=beige_line, sw=3))
    for ky in (690, 712):
        out.append(_line(196, ky, 644, ky, stroke=beige_line, sw=3, extra='stroke-dasharray="26 8"'))
    out.append(_rect(190, 300, 460, 360, rx=34, fill=beige, stroke=beige_line, sw=3.5))
    out.append(_rect(236, 342, 330, 250, rx=26, fill=FG_2, stroke=beige_line, sw=3))
    out.append(_t(268, 420, "login: _", 34, weight=700, family=MONO, anchor="start", fill=ACCENT_TINT))
    for vy in (380, 410, 440, 470):
        out.append(_line(596, vy, 626, vy, stroke=beige_line, sw=4))
    out.append(_circle(610, 620, 9, fill=SEV["low"][0]))
    # a cobweb in the corner, and reading glasses on top
    cx0, cy0 = 196, 306
    spokes = ((300, 306), (290, 350), (262, 386), (196, 400))
    for ex, ey in spokes:
        out.append(_line(cx0, cy0, ex, ey, stroke=LINE_STRONG, sw=1.8))
    for k in (0.35, 0.6, 0.85):
        pts = [(cx0 + (ex - cx0) * k, cy0 + (ey - cy0) * k) for ex, ey in spokes]
        d = f"M {pts[0][0]:.1f} {pts[0][1]:.1f} " + " ".join(
            f"Q {cx0 + (a[0] + b[0] - 2 * cx0) * 0.42:.1f} {cy0 + (a[1] + b[1] - 2 * cy0) * 0.42:.1f} "
            f"{b[0]:.1f} {b[1]:.1f}" for a, b in zip(pts, pts[1:]))
        out.append(_path(d, stroke=LINE_STRONG, sw=1.8))
    out.append(_path("M 356 286 L 330 296 M 504 286 L 530 296", stroke=FG_2, sw=4))
    out.append(_circle(390, 284, 30, fill=ACCENT_TINT, stroke=FG_2, sw=5, extra='fill-opacity=".6"'))
    out.append(_circle(470, 284, 30, fill=ACCENT_TINT, stroke=FG_2, sw=5, extra='fill-opacity=".6"'))
    out.append(_path("M 420 280 q 10 -8 20 0", stroke=FG_2, sw=4))
    # the moon, and a rocket heading for it
    out.append(_circle(1420, 180, 76, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3))
    for mx, my, mr in ((1396, 160, 16), (1446, 206, 11), (1440, 140, 8)):
        out.append(_circle(mx, my, mr, fill=PANEL_2, stroke=LINE, sw=2.5))
    for px, py, pr in ((1080, 720, 44), (1150, 736, 34), (1010, 738, 30), (1210, 744, 24)):
        out.append(_circle(px, py, pr, fill=PANEL, stroke=LINE, sw=3))
    rocket = [
        _path("M -26 116 Q -60 150 -20 190 Q -6 160 0 150 Q 6 160 20 190 Q 60 150 26 116 Z",
              fill=ROSE, stroke=None),
        _path("M -14 120 Q -22 150 0 176 Q 22 150 14 120 Z", fill=_mix(ROSE, PANEL, 0.55), stroke=None),
        _path("M -40 60 L -74 120 L -36 110 Z M 40 60 L 74 120 L 36 110 Z",
              fill=_mix(TEAL, PANEL, 0.2), stroke=_mix(TEAL, FG, 0.3), sw=3),
        _path("M 0 -150 C 52 -96 50 40 40 120 L -40 120 C -50 40 -52 -96 0 -150 Z",
              fill=ACCENT_FG, stroke=LINE_STRONG, sw=3.5),
        _circle(0, -30, 24, fill=ACCENT_TINT, stroke=ACCENT, sw=4),
    ]
    out.append(_g("".join(rocket), x=1130, y=500, rot=16))
    return _document("Telnet, 1969", "1969: a chunky computer terminal with a cobweb and reading "
                     "glasses, its screen saying login, beside a cheerful rocket heading for the "
                     "moon.", "".join(out))


# --------------------------------------------------------------------------- I9 the obliging router


def obliging_router() -> str:
    """I9: the camera tugs the router's sleeve; the router, beaming, holds the door wide open."""
    out = [_floor(760)]
    # the view through the doorway: the whole wide world
    out.append(_rect(980, 170, 270, 590, fill=ACCENT_TINT))
    out.append(_rect(980, 610, 270, 150, fill=_mix(SEV["low"][3], ACCENT_TINT, 0.3)))
    for hx, hw, hh in ((990, 60, 56), (1060, 50, 80), (1116, 70, 50), (1192, 50, 70)):
        out.append(_rect(hx, 610 - hh, hw, hh, fill=_mix(ACCENT, ACCENT_TINT, 0.55)))
    out.append(_path("M 1060 760 L 1100 610 L 1130 610 L 1180 760 Z", fill=PANEL_2, stroke=None))
    out.append(_cloud(1120, 300, 0.7))
    out.append(_rect(966, 160, 298, 604, fill="none", stroke=LINE_STRONG, sw=8))
    # the door, swung wide
    out.append(_path("M 966 164 L 890 130 L 890 800 L 966 764 Z", fill=_mix(TEAL, PANEL, 0.3),
                     stroke=_mix(TEAL, FG, 0.3), sw=3.5))
    out.append(_circle(904, 470, 9, fill=ACCENT_FG, stroke=FG_2, sw=2.5))
    # the doormat, which it put out itself
    out.append(_path("M 952 772 L 1278 772 L 1310 830 L 920 830 Z", fill=WOOD_LIGHT,
                     stroke=WOOD, sw=3))
    out.append(_t(1115, 813, "WELCOME", 28, weight=700, family=SERIF, fill=WOOD_DARK, ls=6))
    # the router, very pleased to help
    out.append(_shadow(700, 764, 170, 11))
    out.append(_rect(612, 600, 34, 160, rx=14, fill=FG_2))
    out.append(_rect(754, 600, 34, 160, rx=14, fill=FG_2))
    out.append(_line(600, 470, 572, 350, stroke=ACCENT, sw=8))
    out.append(_line(800, 470, 828, 350, stroke=ACCENT, sw=8))
    out.append(_circle(572, 346, 12, fill=ACCENT))
    out.append(_circle(828, 346, 12, fill=ACCENT))
    out.append(_path("M 846 530 C 880 520 890 490 896 474", stroke=ACCENT, sw=24))
    out.append(_circle(896, 474, 17, fill=PANEL, stroke=ACCENT, sw=3.5))
    out.append(_rect(540, 460, 320, 160, rx=34, fill=PANEL, stroke=ACCENT, sw=4.5))
    out.append(_path("M 638 522 q 16 -18 32 0 M 732 522 q 16 -18 32 0", stroke=FG, sw=5))
    out.append(_path("M 664 560 q 36 30 72 0", stroke=FG, sw=5))
    for i, lx in enumerate((620, 650, 680)):
        out.append(_circle(lx, 596, 6, fill=(SEV["low"][0] if i < 2 else ACCENT)))
    out.append(_path("M 548 540 C 510 560 492 580 478 600", stroke=ACCENT, sw=24))
    # the camera, tugging at its sleeve
    out.append(_line(446, 648, 470, 606, stroke=LINE_STRONG, sw=12))
    out.append(_circle(472, 602, 13, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3))
    out.append(_camera_char(380, 686, 0.95, eyes="up"))
    return _document("The obliging router", "A small camera tugs at the router's sleeve; the "
                     "router, beaming, holds its front door wide open to the world outside, "
                     "with a WELCOME mat.", "".join(out))



# --------------------------------------------------------------------------- I10 recall vs bulletin


def _continents(x: float, y: float, w: float, h: float, fill: str) -> str:
    """Friendly blob continents on a flat map box (x, y, w, h): the whole world, no street in it."""
    def pt(u: float, v: float) -> str:
        return f"{x + u * w:.1f} {y + v * h:.1f}"
    shapes = (
        # the Americas
        f"M {pt(.08, .18)} Q {pt(.2, .08)} {pt(.3, .2)} Q {pt(.3, .36)} {pt(.22, .44)} "
        f"Q {pt(.16, .48)} {pt(.12, .38)} Q {pt(.04, .3)} {pt(.08, .18)} Z",
        f"M {pt(.22, .5)} Q {pt(.32, .5)} {pt(.3, .66)} Q {pt(.27, .84)} {pt(.23, .9)} "
        f"Q {pt(.2, .72)} {pt(.19, .6)} Q {pt(.18, .52)} {pt(.22, .5)} Z",
        # Europe and Africa
        f"M {pt(.44, .16)} Q {pt(.54, .1)} {pt(.56, .24)} Q {pt(.5, .3)} {pt(.45, .28)} Z",
        f"M {pt(.44, .36)} Q {pt(.58, .32)} {pt(.6, .48)} Q {pt(.58, .66)} {pt(.52, .8)} "
        f"Q {pt(.47, .66)} {pt(.46, .54)} Q {pt(.4, .46)} {pt(.44, .36)} Z",
        # Asia
        f"M {pt(.58, .14)} Q {pt(.78, .06)} {pt(.9, .2)} Q {pt(.92, .34)} {pt(.8, .42)} "
        f"Q {pt(.7, .46)} {pt(.64, .34)} Q {pt(.56, .26)} {pt(.58, .14)} Z",
        # Australia
        f"M {pt(.78, .66)} Q {pt(.88, .6)} {pt(.92, .72)} Q {pt(.86, .82)} {pt(.78, .78)} Z",
    )
    return "".join(_path(d, fill=fill, stroke=None) for d in shapes)


def recall_vs_bulletin() -> str:
    """I10: a polite recall notice vs. a news bulletin with a whole-world map. KEV is the second."""
    crit_pig, _, crit_ink, crit_tint = SEV["critical"]
    out = [_floor(700)]
    # the doormat both of them landed on
    out.append(_path("M 200 560 L 1400 560 L 1440 700 L 160 700 Z", fill=WOOD_LIGHT,
                     stroke=WOOD, sw=3))
    for bx in range(230, 1400, 26):
        out.append(_line(bx, 590, bx - 6, 676, stroke=_mix(WOOD, PANEL, 0.35), sw=2))
    # the two labels
    out.append(_rect(300, 72, 380, 64, rx=32, fill=PANEL_2, stroke=LINE_STRONG, sw=2.5))
    out.append(_t(490, 115, "A flaw exists", 32, weight=650, fill=FG))
    out.append(_rect(860, 72, 480, 64, rx=32, fill=crit_tint, stroke=crit_pig, sw=2.5))
    out.append(_t(1100, 115, "Attackers are using it", 32, weight=650, fill=crit_ink))
    # left: the recall letter, half out of its envelope
    out.append(_rect(310, 170, 380, 310, rx=6, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3))
    out.append(_t(500, 232, "Recall notice", 42, weight=700, family=SERIF))
    out.append(_t(500, 282, "this lock has a known flaw", 28, weight=500, fill=FG_2))
    out.append(_rect(280, 330, 440, 290, rx=10, fill=PANEL_2, stroke=LINE_STRONG, sw=3))
    out.append(_path("M 280 336 L 500 470 L 720 336 V 612 Q 720 620 712 620 H 288 Q 280 620 280 612 Z",
                     fill=_mix(PANEL_2, BG, 0.5), stroke=LINE_STRONG, sw=3))
    out.append(_path("M 480 548 V 532 a 20 20 0 0 1 40 0 V 548", stroke=LINE_STRONG, sw=5))
    out.append(_rect(468, 546, 64, 48, rx=8, fill=PANEL, stroke=LINE_STRONG, sw=3))
    # right: the bulletin, with the whole world on the front
    paper = [
        _rect(0, 0, 480, 470, rx=6, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3),
        _t(240, 54, "WORLD NEWS", 34, weight=700, family=SERIF, ls=5),
        _line(24, 74, 456, 74, stroke=FG_2, sw=3),
        _line(24, 82, 456, 82, stroke=FG_2, sw=1.5),
        _lines(240, 130, ["Burglars are using", "this trick on this lock,", "right now"], 36, 44,
               weight=700, family=SERIF),
        _rect(30, 260, 420, 190, rx=8, fill=SEV["info"][3], stroke=LINE, sw=2),
        _continents(30, 260, 420, 190, _mix(ACCENT, SEV["info"][3], 0.45)),
    ]
    out.append(_g("".join(paper), x=860, y=160, rot=2.5))
    out.append(_t(800, 790, "Matched by software version: a strong clue, not proof.", 30,
                  weight=500, fill=MUTED))
    return _document("Recall notice vs. news bulletin", "On a doormat: a recall notice saying "
                     "this lock has a known flaw, and a newspaper with a world map: burglars are "
                     "using this trick on this lock, right now. Below: matched by software "
                     "version, a strong clue, not proof.", "".join(out))


# --------------------------------------------------------------------------- I11 world forecast


def _world_forecast(umbrella: bool) -> str:
    water = _mix(SEV["info"][0], PANEL, 0.62)
    out = [
        _rect(740, 720, 120, 50, fill=LINE_STRONG),
        _rect(640, 764, 320, 18, rx=9, fill=LINE_STRONG),
        _rect(130, 50, 1340, 690, rx=30, fill=FG_2),
        _rect(158, 78, 1284, 634, rx=14, fill=SEV["info"][3]),
        '<clipPath id="globe"><circle cx="560" cy="400" r="176"/></clipPath>',
        _circle(560, 400, 176, fill=water, stroke=SEV["info"][2], sw=3),
        f'<g clip-path="url(#globe)">{_continents(384, 224, 352, 352, _mix(ACCENT, PANEL, 0.3))}</g>',
    ]
    for rx_, ry_ in ((440, 420), (500, 470), (580, 440), (640, 500), (700, 430), (470, 530),
                     (610, 560), (380, 480)):
        out.append(_line(rx_, ry_, rx_ - 12, ry_ + 30, stroke=SEV["info"][2], sw=4))
    out.append(_cloud(560, 250, 1.75, fill=PANEL, stroke=LINE_STRONG))
    out.append(_t(575, 300, "94%", 86, weight=700, family=SERIF))
    # your garden, in the corner of the screen
    out.append(_rect(1040, 118, 360, 330, rx=16, fill=PANEL, stroke=LINE_STRONG, sw=2.5))
    out.append(_t(1068, 160, "your garden", 26, weight=600, fill=MUTED, anchor="start"))
    out.append(_rect(1042, 366, 356, 80, rx=0, fill=_mix(SEV["low"][3], ACCENT_TINT, 0.4)))
    out.append(_rect(1040, 118, 360, 330, rx=16, fill="none", stroke=LINE_STRONG, sw=2.5))
    for fx in range(1060, 1390, 30):
        out.append(_line(fx, 336, fx, 380, stroke=WOOD, sw=5))
    out.append(_line(1052, 350, 1390, 350, stroke=WOOD, sw=4))
    out.append(_path("M 1250 380 V 300 L 1300 262 L 1350 300 V 380 Z", fill=ACCENT_FG,
                     stroke=LINE_STRONG, sw=3))
    out.append(_rect(1288, 336, 24, 44, rx=3, fill=_mix(TEAL, PANEL, 0.3)))
    for fx, col in ((1110, ROSE), (1150, PLUM), (1190, ROSE)):
        out.append(_line(fx, 400, fx, 372, stroke=ACCENT, sw=3))
        out.append(_circle(fx, 368, 9, fill=col))
    if umbrella:
        out.append(_path("M 1090 300 Q 1090 200 1200 196 Q 1310 200 1310 300 "
                         "Q 1282 284 1255 300 Q 1228 284 1200 300 Q 1172 284 1145 300 "
                         "Q 1118 284 1090 300 Z", fill=ACCENT, stroke=ACCENT_INK, sw=3))
        out.append(_path("M 1200 196 V 380 q 0 16 -16 16 q -12 0 -12 -12", stroke=FG_2, sw=5))
    else:
        out.append(_t(1180, 300, "?", 90, weight=600, family=SERIF, fill=MUTED))
    # the lower third, TV-style
    out.append(_rect(158, 610, 1284, 102, rx=0, fill=ACCENT_FG))
    out.append(_rect(158, 610, 14, 102, fill=ACCENT))
    out.append(_t(800, 674, "Chance this flaw gets used somewhere in the world, next 30 days: 94%",
                  31, weight=600))
    return "".join(out)


def world_forecast() -> str:
    """I11: a rain cloud labelled 94% over the whole globe; a small garden with a '?'."""
    return _document("World forecast", "A TV weather screen: a rain cloud labelled 94 percent over "
                     "the whole globe. In the corner, your garden with a question mark. Caption: "
                     "chance this flaw gets used somewhere in the world, next 30 days: 94%.",
                     _world_forecast(False))


def world_forecast_umbrella() -> str:
    """I11 on 'bring an umbrella': the same screen with a sage umbrella open over the garden."""
    return _document("World forecast", "The same weather screen; a sage umbrella is now open over "
                     "your garden.", _world_forecast(True))


# --------------------------------------------------------------------------- I12 a better lock in the post


def lock_in_the_post() -> str:
    """I12: a parcel on the doormat with a shiny new lock in its window: 'Firmware update: free'."""
    door = _mix(TEAL, PANEL, 0.3)
    door_line = _mix(TEAL, FG, 0.3)
    card_box = _mix(WOOD, PANEL, 0.5)
    out = [_floor(640)]
    out.append(_rect(470, -20, 660, 660, rx=6, fill=door, stroke=door_line, sw=3.5))
    for py in (40, 420):
        out.append(_rect(520, py, 250, 170 if py == 40 else 160, rx=6, fill="none", stroke=door_line, sw=2.5))
        out.append(_rect(830, py, 250, 170 if py == 40 else 160, rx=6, fill="none", stroke=door_line, sw=2.5))
    out.append(_rect(660, 290, 280, 56, rx=8, fill=_mix(WOOD, FG, 0.1), stroke=door_line, sw=3))
    out.append(_rect(672, 300, 256, 22, rx=4, fill=_mix(WOOD, PANEL, 0.35)))
    out.append(_path("M 360 660 L 1240 660 L 1300 810 L 300 810 Z", fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    # the parcel
    out.append(_shadow(800, 780, 330, 14))
    out.append(_path("M 520 520 L 580 470 L 1140 470 L 1080 520 Z", fill=_mix(card_box, PANEL, 0.3),
                     stroke=WOOD_DARK, sw=3))
    out.append(_path("M 1080 520 L 1140 470 L 1140 730 L 1080 780 Z", fill=_mix(card_box, WOOD, 0.3),
                     stroke=WOOD_DARK, sw=3))
    out.append(_rect(520, 520, 560, 260, rx=4, fill=card_box, stroke=WOOD_DARK, sw=3))
    out.append(_path("M 776 520 L 818 520 L 878 470 L 836 470 Z", fill=_mix(card_box, PANEL, 0.6),
                     stroke=None))
    out.append(_rect(776, 520, 42, 36, fill=_mix(card_box, PANEL, 0.6)))
    # the window, and the lock in it
    out.append(_rect(556, 560, 220, 180, rx=12, fill=ACCENT_FG, stroke=WOOD_DARK, sw=3))
    out.append(_path("M 632 640 V 612 a 34 34 0 0 1 68 0 V 640", stroke=LINE_STRONG, sw=11))
    out.append(_rect(608, 636, 116, 84, rx=14, fill=ACCENT, stroke=ACCENT_INK, sw=3))
    out.append(_circle(666, 670, 10, fill=ACCENT_FG))
    out.append(_rect(662, 674, 8, 24, rx=3, fill=ACCENT_FG))
    out.append(_sparkle(742, 598, 14))
    out.append(_sparkle(592, 604, 9))
    # the label
    out.append(_rect(800, 560, 250, 150, rx=10, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5))
    out.append(_t(925, 616, "Firmware update", 28, weight=650))
    out.append(_line(830, 634, 1020, 634, stroke=LINE, sw=2))
    out.append(_t(925, 686, "free", 48, weight=700, family=SERIF, fill=ACCENT_INK))
    return _document("The better lock in the post", "A parcel on the doormat under the letterbox, "
                     "unopened, with a shiny new lock showing through its window. Label: firmware "
                     "update, free.", "".join(out))


# --------------------------------------------------------------------------- I13 the PDF costume


def _gear(cx: float, cy: float, r: float, teeth: int, fill: str, stroke: str) -> str:
    out = []
    for k in range(teeth):
        a = 360.0 * k / teeth
        out.append(_g(_rect(-r * 0.14, -r - r * 0.2, r * 0.28, r * 0.4, rx=6, fill=fill,
                            stroke=stroke, sw=3), x=cx, y=cy, rot=a))
    out.append(_circle(cx, cy, r, fill=fill, stroke=stroke, sw=3.5))
    return "".join(out)


def pdf_costume() -> str:
    """I13: a gear in a too-small paper costume ('invoice.pdf'), with glasses and a moustache."""
    gear_fill = _mix(SEV["info"][0], PANEL, 0.25)
    gear_line = _mix(SEV["info"][0], FG, 0.35)
    out = [_floor(790)]
    out.append(_shadow(800, 792, 230, 14))
    out.append(_gear(800, 610, 170, 12, gear_fill, gear_line))
    out.append(_t(800, 744, ".exe", 56, weight=700, family=MONO, fill=ACCENT_FG))
    # the costume: a page, slightly too small, worn over the top
    out.append(_path("M 610 110 H 930 L 1000 180 V 600 Q 900 626 800 604 Q 700 626 600 600 V 120 "
                     "Q 600 110 610 110 Z", fill=ACCENT_FG, stroke=LINE_STRONG, sw=3.5))
    out.append(_path("M 930 110 V 170 Q 930 180 940 180 H 1000", fill=PANEL_2, stroke=LINE_STRONG, sw=3))
    # the disguise
    out.append(_circle(742, 262, 44, fill=PANEL, stroke=FG, sw=6))
    out.append(_circle(858, 262, 44, fill=PANEL, stroke=FG, sw=6))
    out.append(_path("M 786 258 q 14 -10 28 0", stroke=FG, sw=6))
    out.append(_circle(748, 268, 8, fill=FG))
    out.append(_circle(852, 268, 8, fill=FG))
    out.append(f'<ellipse cx="800" cy="318" rx="24" ry="30" fill="{_mix(ROSE, PANEL, 0.45)}" '
               f'stroke="{_mix(ROSE, FG, 0.2)}" stroke-width="3"/>')
    out.append(_path("M 800 352 C 780 338 740 340 716 368 C 746 360 770 378 800 364 "
                     "C 830 378 854 360 884 368 C 860 340 820 338 800 352 Z", fill=FG, stroke=FG, sw=2))
    for ly, lw in ((438, 260), (466, 220), (494, 250)):
        out.append(_rect(800 - lw / 2, ly, lw, 10, rx=5, fill=LINE))
    out.append(_t(800, 560, "invoice.pdf", 44, weight=700, family=MONO, fill=FG))
    return _document("The PDF costume", "A gear labelled .exe wearing a slightly too small paper "
                     "costume labelled invoice.pdf, with round glasses, a fake nose and a "
                     "moustache.", "".join(out))


# --------------------------------------------------------------------------- I14 the phone book that says no


def phone_book() -> str:
    """I14: DNS as the internet's phone book; the listing for a fake sign-in page says no."""
    cover = _mix(TEAL, PANEL, 0.25)
    out = [_floor(770)]
    out.append(_t(800, 88, "DNS = the internet’s phone book", 44, weight=600, family=SERIF))
    # the book
    out.append(_path("M 380 316 L 800 336 L 1220 316 L 1220 730 L 800 750 L 380 730 Z", fill=cover,
                     stroke=_mix(TEAL, FG, 0.3), sw=3))
    out.append(_path("M 400 300 L 794 320 L 794 724 L 400 706 Z", fill=ACCENT_FG, stroke=LINE_STRONG, sw=3))
    out.append(_path("M 806 320 L 1200 300 L 1200 706 L 806 724 Z", fill=ACCENT_FG, stroke=LINE_STRONG, sw=3))
    for i in range(6):
        y = 380 + i * 54
        if i == 2:
            out.append(_rect(420, y - 32, 356, 46, rx=8, fill=ACCENT_TINT))
            out.append(_t(432, y - 2, "example-shop", 22, weight=700, family=MONO, anchor="start"))
            out.append(_t(766, y - 2, "203.0.113.7", 22, weight=700, family=MONO, anchor="end",
                          fill=ACCENT_INK))
        else:
            out.append(_rect(436, y - 16, 120 + (i * 37) % 60, 12, rx=6, fill=LINE))
            out.append(_rect(680, y - 16, 84, 12, rx=6, fill=LINE))
        if i in (0, 1, 4, 5):
            out.append(_rect(836, y - 16, 110 + (i * 29) % 70, 12, rx=6, fill=LINE))
            out.append(_rect(1090, y - 16, 84, 12, rx=6, fill=LINE))
    out.append(_t(840, 490, "fake-sign-in", 22, weight=700, family=MONO, anchor="start", fill=MUTED))
    out.append(_line(836, 482, 1016, 482, stroke=MUTED, sw=3))
    stamp = (_rect(-150, -40, 300, 80, rx=12, fill=ACCENT_FG, stroke=ACCENT_INK, sw=4)
             + _rect(-140, -30, 280, 60, rx=8, fill="none", stroke=ACCENT_INK, sw=2)
             + _t(0, 12, "Sorry, no listing", 32, weight=700, family=SERIF, fill=ACCENT_INK))
    out.append(_g(stamp, x=1004, y=576, rot=-7))
    # who is asking
    out.append(_icon("laptop", 210, 420, 1.6))
    out.append(_bubble(60, 150, 470, 90, tail=(210, 350), base=210))
    out.append(_t(295, 206, "Where does example-shop live?", 28, weight=600))
    out.append(_icon("tablet", 1400, 420, 1.5))
    out.append(_bubble(1070, 150, 470, 90, tail=(1400, 364), base=1390))
    out.append(_t(1305, 206, "Where does fake-sign-in live?", 28, weight=600))
    return _document("The phone book that says no", "DNS is the internet's phone book. A laptop "
                     "asks where example-shop lives and the book lists a number. A tablet asks "
                     "for fake-sign-in and the book is stamped: Sorry, no listing.", "".join(out))


# --------------------------------------------------------------------------- I15 the homesick camera


def homesick_camera() -> str:
    """I15: the camera at summer camp, on the phone again; a pile of 'Just checking in!' notes."""
    out = [_floor(770)]
    # the camp pennant
    out.append(_line(1150, 130, 1150, 290, stroke=WOOD, sw=6))
    out.append(_path("M 1154 140 L 1440 190 L 1154 250 Z", fill=ACCENT, stroke=ACCENT_INK, sw=3))
    out.append(_t(1260, 208, "CAMP", 38, weight=700, family=SERIF, fill=ACCENT_FG, ls=4))
    # the bunk bed
    for px in (330, 990):
        out.append(_rect(px, 150, 26, 620, rx=6, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    for by in (330, 600):
        out.append(_rect(356, by - 44, 634, 44, rx=10, fill=PANEL, stroke=LINE_STRONG, sw=3))
        out.append(_rect(344, by, 660, 22, rx=4, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(380, 256, 150, 40, rx=18, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5))
    out.append(_rect(380, 526, 150, 40, rx=18, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5))
    # the camera, sitting on the lower bunk, on the phone again
    out.append(_camera_char(640, 486, 1.0, eyes="open"))
    out.append(_line(704, 470, 742, 440, stroke=LINE_STRONG, sw=12))
    out.append(_rect(734, 404, 28, 50, rx=6, fill=FG_2))
    out.append(_bubble(800, 336, 290, 84, tail=(772, 440), base=842))
    out.append(_t(945, 389, "Just checking in!", 30, weight=600, family=HAND))
    # the notes, piling up
    out.append(_rect(1080, 640, 260, 130, rx=8, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    for i, rot in enumerate((-4, 3, -2, 5, -3, 2, -5)):
        note = _rect(-100, -30, 200, 60, rx=4, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2)
        if i == 6:
            note += _t(0, 10, "Just checking in!", 22, weight=600, family=HAND, fill=FOCUS)
        out.append(_g(note, x=1210, y=616 - i * 20, rot=rot))
    for nx, ny, rot in ((1080, 760, -12), (1400, 752, 10)):
        out.append(_g(_rect(-60, -20, 120, 40, rx=4, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2),
                      x=nx, y=ny, rot=rot))
    return _document("The homesick camera", "The unbranded camera at summer camp, sitting on a "
                     "bunk bed with a tiny phone, saying Just checking in! A stack of identical "
                     "Just checking in! notes piles up beside it.", "".join(out))


# --------------------------------------------------------------------------- I16 the PC nods off


def pc_nods_off() -> str:
    """I16: the PC asleep in a nightcap, the phone book shut, the gadgets all asking '?'."""
    out = [_floor(770)]
    out.append(_rect(470, 590, 24, 180, rx=4, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(1106, 590, 24, 180, rx=4, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(440, 564, 720, 28, rx=6, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    # the PC, fast asleep
    out.append(_rect(700, 540, 40, 26, rx=3, fill=FG_2))
    out.append(f'<ellipse cx="720" cy="564" rx="60" ry="7" fill="{FG_2}"/>')
    out.append(_rect(560, 350, 320, 196, rx=14, fill=FG_2, stroke=FG, sw=3))
    out.append(_rect(576, 366, 288, 164, rx=6, fill=_mix(FG_2, FG, 0.4)))
    out.append(_path("M 664 452 q 16 12 32 0 M 744 452 q 16 12 32 0", stroke=_mix(ACCENT_TINT, FG, 0.45), sw=5))
    # the nightcap
    out.append(_path("M 580 360 Q 640 250 760 236 Q 850 232 930 312 L 900 330 Q 840 290 800 300 "
                     "Q 740 314 860 360 Z", fill=PLUM, stroke=_mix(PLUM, FG, 0.3), sw=3))
    out.append(_rect(566, 340, 308, 30, rx=15, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5))
    out.append(_circle(930, 318, 22, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5))
    for zx, zy, zs in ((950, 250, 40), (995, 196, 52), (1050, 132, 66)):
        out.append(_t(zx, zy, "z", zs, weight=600, family=SERIF, italic=True, fill=MUTED))
    # the phone book, shut for the night
    out.append(_rect(930, 510, 190, 54, rx=6, fill=_mix(TEAL, PANEL, 0.25), stroke=_mix(TEAL, FG, 0.3), sw=3))
    out.append(_line(946, 526, 1104, 526, stroke=ACCENT_FG, sw=3))
    out.append(_line(946, 548, 1104, 548, stroke=ACCENT_FG, sw=3))
    out.append(_path("M 1060 564 V 596 l 10 -8 l 10 8 V 564", fill=ROSE, stroke=None))
    # the gadgets, all asking the same thing
    for kind, x, y in (("phone", 200, 250), ("tv", 250, 580), ("speaker", 1390, 260),
                       ("tablet", 1400, 590)):
        out.append(_icon(kind, x, y, 1.35))
        out.append(_circle(x + 62, y - 58, 26, fill=PANEL, stroke=LINE_STRONG, sw=2.5))
        out.append(_t(x + 62, y - 46, "?", 34, weight=700, family=SERIF, fill=MUTED))
    return _document("The PC nods off", "The family PC asleep in a nightcap, screen dark, z z z. "
                     "The phone book beside it is shut. A phone, a TV, a speaker and a tablet "
                     "each show a question mark.", "".join(out))



# --------------------------------------------------------------------------- I17 twenty minutes before


def twenty_minutes() -> str:
    """I17: 'Important call: in 20 min' on the laptop, while the internet cloud quietly goes grey."""
    out = [_floor(770)]
    # the internet, gone grey, and the link to it broken
    out.append(_cloud(1330, 170, 1.05, fill=TRACK, stroke=LINE_STRONG, sw=3))
    out.append(_t(1332, 190, "the internet", 28, weight=600, fill=MUTED, family=SERIF))
    out.append(_path("M 1090 290 Q 1150 250 1180 236", stroke=LINE_STRONG, sw=4,
                     extra='stroke-dasharray="4 12"'))
    out.append(_path("M 1222 230 Q 1236 226 1244 224", stroke=LINE_STRONG, sw=4,
                     extra='stroke-dasharray="4 12"'))
    out.append(_cross(1202, 232, 0.8, stroke=LINE_STRONG, sw=4))
    # the house
    out.append(_path("M 400 346 L 800 160 L 1200 346 Z", fill=_mix(WOOD, PANEL, 0.45),
                     stroke=_mix(WOOD, FG, 0.2), sw=3.5))
    out.append(_rect(430, 340, 740, 430, fill=PANEL, stroke=LINE_STRONG, sw=3.5))
    # a wall clock, because it is always nearly time
    out.append(_circle(520, 430, 38, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3))
    out.append(_line(520, 430, 520, 404, stroke=FG, sw=4))
    out.append(_line(520, 430, 540, 440, stroke=FG, sw=4))
    # the table and the laptop
    out.append(_rect(560, 660, 480, 22, rx=5, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(590, 682, 20, 88, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(990, 682, 20, 88, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    out.append(_rect(636, 420, 328, 220, rx=12, fill=FG_2, stroke=FG, sw=3))
    out.append(_rect(650, 434, 300, 192, rx=6, fill=BG))
    out.append(_path("M 610 640 H 990 L 1010 660 H 590 Z", fill=PANEL_2, stroke=LINE_STRONG, sw=3))
    out.append(_rect(672, 466, 256, 128, rx=12, fill=ACCENT_FG, stroke=LINE, sw=2))
    out.append(_rect(672, 466, 256, 12, rx=6, fill=ROSE))
    out.append(_t(800, 520, "Important call:", 26, weight=650))
    out.append(_t(800, 570, "in 20 min", 36, weight=700, family=SERIF, fill=ACCENT_INK))
    return _document("Twenty minutes before something important", "A house with a laptop on the "
                     "table showing Important call: in 20 min, while the internet cloud above has "
                     "gone grey and the line to it is broken.", "".join(out))


# --------------------------------------------------------------------------- I18 the shelf of white boxes


def white_box_shelf() -> str:
    """I18: four identical small white boxes on a hallway shelf, each wearing a '?'.

    SCRIPT.md points at ``slides.lens_why``; that slide is the old dark theme and a paragraph of
    text, so this is the same shelf redrawn in Stone & Sage with the text taken out.
    """
    out = [_t(800, 104, "Which one is the camera?", 50, weight=600, family=SERIF)]
    for bx in (250, 1330):
        out.append(_path(f"M {bx} 584 L {bx} 660 L {bx + 20} 660 L {bx + 20} 604 Z", fill=WOOD,
                         stroke=None))
    out.append(_rect(150, 560, 1300, 26, rx=5, fill=WOOD_LIGHT, stroke=WOOD, sw=3))
    for i, cx in enumerate((340, 640, 940, 1240)):
        out.append(_path(f"M {cx} 586 C {cx} 640 {cx + (30 if i % 2 else -30)} 650 "
                         f"{cx + (46 if i % 2 else -46)} 700", stroke=FG_2, sw=6))
        out.append(_rect(cx - 88, 404, 176, 156, rx=24, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3.5))
        # lens upper left, as on the close-up the scan rig films (scene_render._white_box_html)
        out.append(_circle(cx - 46, 450, 26, fill=FG_2, stroke=LINE_STRONG, sw=3))
        out.append(_circle(cx - 53, 443, 7, fill=_mix(FG_2, PANEL, 0.3)))
        out.append(_circle(cx + 62, 426, 6, fill=SEV["low"][0]))
        out.append(_rect(cx - 46, 526, 92, 9, rx=4.5, fill=LINE))
        out.append(_line(cx, 356, cx, 396, stroke=ACCENT, sw=3, extra='stroke-dasharray="4 8"'))
        out.append(_rect(cx - 34, 290, 68, 62, rx=14, fill=PANEL, stroke=ACCENT, sw=3))
        out.append(_t(cx, 336, "?", 40, weight=700, family=SERIF, fill=ACCENT_INK))
    # a houseplant, because it is a hallway
    out.append(_path("M 1380 560 L 1372 510 H 1432 L 1424 560 Z", fill=ROSE, stroke=None))
    out.append(_path("M 1402 510 C 1380 470 1360 470 1350 450 C 1380 450 1398 470 1402 510 Z "
                     "M 1402 510 C 1410 460 1430 440 1450 436 C 1446 470 1420 490 1402 510 Z "
                     "M 1402 510 C 1400 470 1402 440 1404 420 C 1416 450 1414 480 1402 510 Z",
                     fill=ACCENT, stroke=ACCENT_INK, sw=2))
    return _document("The shelf of identical white boxes", "A hallway shelf with four identical "
                     "small white boxes, each with a question mark above it. Which one is the "
                     "camera?", "".join(out))


# --------------------------------------------------------------------------- I19 not this


def not_this() -> str:
    """I19: a sci-fi heads-up display, stamped 'Not this'; beside it, the real viewfinder and card."""
    hud = _mix(TEAL, PANEL, 0.35)
    out = [_rect(60, 80, 900, 690, rx=22, fill=FG_2)]
    for gx in range(100, 960, 60):
        out.append(_line(gx, 90, gx, 760, stroke=TEAL, sw=1, extra='opacity=".35"'))
    for gy in range(120, 770, 60):
        out.append(_line(70, gy, 950, gy, stroke=TEAL, sw=1, extra='opacity=".35"'))
    for kind, x, y in (("tv", 220, 560), ("speaker", 430, 600), ("camera", 640, 580),
                       ("lamp", 830, 600)):
        out.append(_icon(kind, x, y, 1.3, stroke=hud, fill=FG_2))
        lx, ly = x - 40, y - 250 + (40 if kind in ("speaker", "lamp") else 0)
        out.append(_line(x, y - 60, lx + 60, ly + 60, stroke=hud, sw=2))
        out.append(_path(f"M {lx} {ly} L {lx + 150} {ly - 20} L {lx + 150} {ly + 44} L {lx} {ly + 64} Z",
                         fill=_mix(TEAL, FG_2, 0.7), stroke=hud, sw=2))
        out.append(_rect(lx + 16, ly + 18, 90, 8, rx=4, fill=hud, extra='transform="skewY(-7.6)"'
                         f' transform-origin="{lx + 16} {ly + 18}"'))
        out.append(_rect(lx + 16, ly + 36, 60, 8, rx=4, fill=hud, extra='opacity=".6" transform="skewY(-7.6)"'
                         f' transform-origin="{lx + 16} {ly + 36}"'))
    for cx, cy in ((110, 130), (910, 130), (110, 720), (910, 720)):
        sx = 1 if cx < 500 else -1
        sy = 1 if cy < 400 else -1
        out.append(_path(f"M {cx} {cy + 40 * sy} V {cy} H {cx + 40 * sx}", stroke=hud, sw=4))
    stamp = (_rect(-230, -70, 460, 140, rx=20, fill=ACCENT_FG, stroke=ACCENT_INK, sw=6)
             + _rect(-214, -54, 428, 108, rx=12, fill="none", stroke=ACCENT_INK, sw=2.5)
             + _t(0, 26, "Not this", 76, weight=700, family=SERIF, fill=ACCENT_INK))
    out.append(_g(stamp, x=510, y=400, rot=-9))
    # the real thing: a viewfinder and one card
    out.append(_circle(1156, 64, 22, fill=ACCENT))
    out.append(_check(1156, 64, 0.9, stroke=ACCENT_FG, sw=5))
    out.append(_t(1190, 80, "This", 44, weight=600, family=SERIF, anchor="start"))
    out.append(_rect(1100, 110, 360, 700, rx=44, fill=FG_2))
    out.append(_rect(1118, 140, 324, 640, rx=26, fill=_mix(BG, PANEL_2, 0.5)))
    out.append(_rect(1118, 440, 324, 30, fill=WOOD_LIGHT))
    out.append(_rect(1216, 320, 128, 120, rx=18, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3))
    out.append(_circle(1280, 370, 24, fill=FG_2))
    for cx, cy, sx, sy in ((1196, 300, 1, 1), (1364, 300, -1, 1), (1196, 460, 1, -1), (1364, 460, -1, -1)):
        out.append(_path(f"M {cx} {cy + 30 * sy} V {cy} H {cx + 30 * sx}", stroke=ACCENT_FG, sw=6))
    out.append(_rect(1134, 560, 292, 200, rx=18, fill=PANEL, stroke=LINE, sw=2))
    out.append(_t(1156, 610, "Unnamed camera", 26, weight=700, anchor="start"))
    out.append(_t(1156, 648, "6 problems", 24, weight=500, anchor="start", fill=MUTED))
    out.append(_rect(1156, 676, 150, 44, rx=22, fill=BRICK))
    out.append(_t(1231, 706, "1 Fix now", 22, weight=650, fill=SEV["critical"][1]))
    return _document("Not this", "Left: a sci-fi heads-up display with floating labels over "
                     "every gadget, stamped Not this. Right: This: a phone viewfinder on a white "
                     "box with an information card: Unnamed camera, 6 problems, Fix now.",
                     "".join(out))


# --------------------------------------------------------------------------- I20 back in the drawer


def back_in_drawer() -> str:
    """I20: a hand closes the kitchen drawer on the camera, among the cables, remote and menu."""
    out = [
        _rect(0, 300, VIEWPORT_W, 600, fill=PANEL_2),
        _rect(0, 276, VIEWPORT_W, 30, fill=WOOD_LIGHT),
        _line(0, 306, VIEWPORT_W, 306, stroke=WOOD, sw=3),
        _line(0, 740, VIEWPORT_W, 740, stroke=LINE_STRONG, sw=3),
        _rect(1320, 760, 120, 16, rx=8, fill=LINE_STRONG),
        _rect(160, 760, 120, 16, rx=8, fill=LINE_STRONG),
    ]
    # the drawer, pulled half out: we look down into it
    out.append(_path("M 440 360 H 1160 L 1210 560 H 390 Z", fill=WOOD_PALE, stroke=WOOD, sw=3))
    out.append(_path("M 460 372 H 1140 L 1180 548 H 420 Z", fill=_mix(WOOD_PALE, PANEL, 0.4),
                     stroke=None))
    # a tangle of cables that belong to nothing
    out.append(_path("M 470 470 C 520 400 600 520 640 450 S 700 380 740 470 S 600 540 560 500 "
                     "S 520 420 470 470", stroke=FG_2, sw=6))
    out.append(_path("M 520 530 C 560 490 640 540 700 510", stroke=TEAL, sw=6))
    # a remote with no batteries
    remote = (_rect(-34, -80, 68, 160, rx=18, fill=PANEL, stroke=LINE_STRONG, sw=3)
              + _circle(0, -50, 10, fill=ROSE)
              + "".join(_circle(dx, dy, 6, fill=LINE_STRONG) for dx in (-14, 14) for dy in (-18, 6))
              + _rect(-22, 26, 44, 42, rx=6, fill=_mix(PANEL, BG, 0.5), stroke=LINE_STRONG, sw=2,
                      extra='stroke-dasharray="4 4"'))
    out.append(_g(remote, x=820, y=460, rot=-70))
    # the takeaway menu
    menu = (_rect(-80, -50, 160, 100, rx=4, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5)
            + _line(0, -50, 0, 50, stroke=LINE, sw=2)
            + _t(-40, 10, "MENU", 22, weight=700, family=SERIF, fill=ROSE))
    out.append(_g(menu, x=1060, y=430, rot=8))
    # the camera, unplugged and very peaceful
    out.append(_path("M 1010 520 C 1060 540 1100 520 1130 530", stroke=LINE_STRONG, sw=5))
    out.append(_rect(1128, 520, 28, 20, rx=4, fill=PANEL, stroke=LINE_STRONG, sw=2.5))
    out.append(_g(_camera_char(0, 0, 0.62, eyes="closed"), x=940, y=470, rot=-12))
    out.append(_t(946, 424, "z", 30, weight=600, family=SERIF, italic=True, fill=MUTED))
    # the drawer front
    out.append(_rect(380, 556, 840, 150, rx=8, fill=WOOD_LIGHT, stroke=WOOD, sw=3.5))
    out.append(_rect(740, 610, 120, 20, rx=10, fill=WOOD))
    # the hand, closing it
    out.append(_arm(1640, 700, 1236, 628, sleeve=PLUM, skin=SKIN[1], width=58, hand=32))
    return _document("Back in the drawer", "A hand closes a kitchen drawer on the camera, which "
                     "is unplugged and asleep among odd cables, a remote with no batteries and a "
                     "takeaway menu.", "".join(out))


# --------------------------------------------------------------------------- I21 the spotless house


def spotless_house() -> str:
    """I21: a spotless house, windows gleaming, garden neat, and the front door wide open."""
    lawn = _mix(SEV["low"][3], ACCENT_TINT, 0.4)
    out = [_rect(0, 700, VIEWPORT_W, 200, fill=lawn), _line(0, 700, VIEWPORT_W, 700, stroke=LINE, sw=3)]
    out.append(_path("M 760 700 L 840 700 L 900 900 L 700 900 Z", fill=PANEL_2, stroke=None))
    out.append(_path("M 424 346 L 800 150 L 1176 346 Z", fill=_mix(ACCENT, PANEL, 0.35),
                     stroke=ACCENT_INK, sw=3.5))
    out.append(_rect(460, 336, 680, 364, fill=ACCENT_FG, stroke=LINE_STRONG, sw=3.5))
    for wx, wy in ((520, 380), (960, 380), (520, 540), (960, 540)):
        out.append(_rect(wx, wy, 120, 96, rx=6, fill=ACCENT_TINT, stroke=LINE_STRONG, sw=3))
        out.append(_line(wx + 60, wy, wx + 60, wy + 96, stroke=LINE_STRONG, sw=2.5))
        out.append(_line(wx + 18, wy + 30, wx + 40, wy + 12, stroke=ACCENT_FG, sw=5))
        out.append(_sparkle(wx + 104, wy + 18, 14))
    # the door: wide open
    out.append(_rect(740, 520, 120, 180, fill=FG_2))
    out.append(_path("M 860 520 L 916 500 L 916 716 L 860 700 Z", fill=_mix(ROSE, PANEL, 0.2),
                     stroke=_mix(ROSE, FG, 0.3), sw=3))
    out.append(_circle(904, 612, 6, fill=ACCENT_FG, stroke=FG_2, sw=2))
    out.append(_rect(730, 510, 140, 12, rx=4, fill=LINE_STRONG))
    # neat hedges and flowers
    for hx in (470, 1010):
        out.append(_rect(hx, 650, 120, 60, rx=30, fill=ACCENT, stroke=ACCENT_INK, sw=3))
    for fx, col in ((620, ROSE), (660, PLUM), (940, ROSE), (980, PLUM), (400, ROSE), (1200, PLUM)):
        out.append(_line(fx, 730, fx, 700, stroke=ACCENT_INK, sw=3))
        out.append(_circle(fx, 696, 10, fill=col))
    out.append(_sparkle(380, 250, 20))
    out.append(_sparkle(1230, 220, 16))
    out.append(_sparkle(1290, 300, 10))
    return _document("The spotless house", "A spotless house, windows gleaming and garden neat, "
                     "with its front door wide open.", "".join(out))


# --------------------------------------------------------------------------- I22 on the fridge


def on_the_fridge() -> str:
    """I22: the safety report on the fridge, under a leaf magnet, beside a child's drawing."""
    out = [_rect(410, 16, 780, 920, rx=34, fill=PANEL, stroke=LINE_STRONG, sw=3.5)]
    out.append(_line(410, 250, 1190, 250, stroke=LINE_STRONG, sw=3))
    out.append(_rect(1120, 90, 22, 120, rx=11, fill=LINE_STRONG))
    out.append(_rect(1120, 290, 22, 260, rx=11, fill=LINE_STRONG))
    # the report
    paper = [
        _rect(0, 0, 360, 470, rx=4, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5),
        _brand_mark(34, 50, 12),
        _t(58, 60, "Your safety report", 28, weight=600, family=SERIF, anchor="start"),
        _line(24, 88, 336, 88, stroke=LINE, sw=2),
        _line(40, 130, 40, 300, stroke=LINE_STRONG, sw=2.5),
        _line(40, 300, 330, 300, stroke=LINE_STRONG, sw=2.5),
        _path("M 50 282 L 100 270 L 150 262 L 200 236 L 250 210 L 300 170 L 320 150",
              stroke=ACCENT, sw=5),
        _circle(320, 150, 8, fill=ACCENT),
    ]
    for i, w in enumerate((260, 210, 240, 180)):
        paper.append(_rect(34, 340 + i * 30, w, 10, rx=5, fill=LINE))
    out.append(_g("".join(paper), x=500, y=300, rot=-2))
    out.append(_path("M 680 312 C 640 290 646 250 690 238 C 706 274 702 298 680 312 Z M 680 312 L 672 326",
                     fill=ACCENT, stroke=ACCENT_INK, sw=2.5))
    # the child's drawing: the printer, smiling (it has always counted)
    kid = [
        _rect(0, 0, 220, 260, rx=4, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2.5),
        _circle(176, 44, 22, fill="none", stroke=SEV["medium"][0], sw=5),
        _path("M 176 10 V 0 M 208 44 H 218 M 150 18 L 144 10 M 202 18 L 210 10", stroke=SEV["medium"][0], sw=4),
        _rect(50, 110, 120, 70, rx=10, fill="none", stroke=PLUM, sw=6),
        _rect(70, 84, 80, 30, rx=4, fill="none", stroke=PLUM, sw=5),
        _rect(72, 176, 76, 40, rx=2, fill="none", stroke=PLUM, sw=5),
        _circle(88, 136, 5, fill=FG), _circle(128, 136, 5, fill=FG),
        _path("M 90 154 Q 108 168 126 154", stroke=FG, sw=4),
        _path("M 20 240 Q 60 230 110 240 T 200 238", stroke=ACCENT, sw=6),
    ]
    out.append(_g("".join(kid), x=900, y=360, rot=5))
    out.append(_circle(1010, 366, 16, fill=PLUM, stroke=_mix(PLUM, FG, 0.3), sw=2.5))
    out.append(_circle(560, 120, 16, fill=TEAL, stroke=_mix(TEAL, FG, 0.3), sw=2.5))
    return _document("On the fridge", "The one-page safety report, its line climbing, held to the "
                     "fridge by a leaf-shaped magnet, next to a child's drawing of a smiling "
                     "printer.", "".join(out))


# --------------------------------------------------------------------------- I23 smoke alarm, not car alarm


def smoke_not_car_alarm() -> str:
    """I23: a calm smoke alarm and one notification, vs. a car alarm going off, gently crossed out."""
    out = [_card(60, 70, 700, 700), _card(840, 70, 700, 700)]
    # left: one small light, one notification
    out.append(_line(100, 130, 720, 130, stroke=LINE_STRONG, sw=3))
    out.append(f'<ellipse cx="410" cy="170" rx="130" ry="40" fill="{ACCENT_FG}" stroke="{LINE_STRONG}" stroke-width="3.5"/>')
    out.append(f'<ellipse cx="410" cy="164" rx="80" ry="20" fill="none" stroke="{LINE}" stroke-width="3"/>')
    out.append(_circle(410, 186, 18, fill=ACCENT_TINT))
    out.append(_circle(410, 186, 8, fill=ACCENT))
    out.append(_rect(300, 290, 220, 440, rx=34, fill=FG_2))
    out.append(_rect(316, 318, 188, 390, rx=20, fill=BG))
    out.append(_rect(330, 350, 160, 88, rx=14, fill=PANEL, stroke=LINE, sw=2))
    out.append(_brand_mark(354, 376, 9))
    out.append(_rect(372, 370, 100, 10, rx=5, fill=FG_2))
    out.append(_rect(346, 400, 128, 9, rx=4.5, fill=LINE))
    out.append(_rect(346, 418, 96, 9, rx=4.5, fill=LINE))
    # right: a car alarm, and fifty notifications
    car = (_path("M -230 40 V -10 Q -226 -40 -190 -44 L -120 -54 L -60 -110 H 90 L 150 -50 "
                 "L 210 -40 Q 236 -34 236 0 V 40 Z", fill=_mix(SEV["info"][0], PANEL, 0.35),
                 stroke=_mix(SEV["info"][0], FG, 0.3), sw=3.5)
           + _path("M -46 -96 H 20 V -54 H -94 Z M 36 -96 H 82 L 124 -54 H 36 Z", fill=ACCENT_TINT,
                   stroke=_mix(SEV["info"][0], FG, 0.3), sw=3)
           + _circle(-130, 44, 40, fill=FG_2) + _circle(-130, 44, 16, fill=LINE)
           + _circle(140, 44, 40, fill=FG_2) + _circle(140, 44, 16, fill=LINE)
           + _circle(214, -16, 10, fill=SEV["medium"][3]))
    out.append(_g(car, x=1190, y=520))
    for k in range(9):
        a = math.radians(-160 + k * 17.5)
        out.append(_line(1190 + 280 * math.cos(a), 470 + 200 * math.sin(a),
                         1190 + 320 * math.cos(a), 470 + 232 * math.sin(a), stroke=ROSE, sw=5))
    for nx, ny, rot in ((900, 150, -8), (1060, 120, 6), (1260, 160, -4), (1420, 130, 9), (950, 300, 5),
                        (1440, 300, -7), (900, 660, 4), (1100, 700, -6), (1300, 690, 8), (1460, 640, -3),
                        (1170, 250, 3), (1360, 250, -9)):
        n = (_rect(-58, -24, 116, 48, rx=10, fill=PANEL, stroke=LINE_STRONG, sw=2)
             + _rect(-44, -10, 70, 8, rx=4, fill=FG_2) + _rect(-44, 4, 88, 7, rx=3.5, fill=LINE))
        out.append(_g(n, x=nx, y=ny, rot=rot))
    out.append(_line(880, 740, 1500, 100, stroke=LINE_STRONG, sw=10, extra='opacity=".75"'))
    return _document("Smoke alarm, not car alarm", "Left: a calm smoke alarm with one small sage "
                     "light, and a phone with one notification. Right: a car alarm going off "
                     "under a dozen notifications, gently crossed out.", "".join(out))


# --------------------------------------------------------------------------- I24 three promises


def three_promises() -> str:
    """I24: three linen cards: free and open source / no account, no cloud / stays on your PC."""
    out: list[str] = []
    texts = (("Free and", "open source"), ("No account,", "no cloud"), ("What it learns", "stays on your PC"))
    for i, (a, b) in enumerate(texts):
        x = 90 + i * 490
        cx = x + 220
        out.append(_card(x, 200, 440, 500, rx=28))
        out.append(_circle(cx, 360, 92, fill=ACCENT_TINT))
        if i == 0:
            out.append(_path(f"M {cx - 48} 330 L {cx - 78} 360 L {cx - 48} 390 M {cx + 48} 330 "
                             f"L {cx + 78} 360 L {cx + 48} 390", stroke=ACCENT_INK, sw=8))
            out.append(_path(f"M {cx} 392 C {cx - 44} 364 {cx - 36} 322 {cx} 340 "
                             f"C {cx + 36} 322 {cx + 44} 364 {cx} 392 Z", fill=ACCENT, stroke=ACCENT_INK, sw=3))
        elif i == 1:
            out.append(_cloud(cx - 6, 364, 0.72, fill=ACCENT_FG, stroke=ACCENT_INK, sw=4))
            out.append(_line(cx - 70, 300, cx + 70, 424, stroke=ACCENT_INK, sw=8))
        else:
            out.append(_path(f"M {cx - 64} 418 V 352 L {cx} 300 L {cx + 64} 352 V 418 Z",
                             fill=ACCENT_FG, stroke=ACCENT_INK, sw=5))
            out.append(_icon("pc", cx + 6, 382, 0.72, stroke=ACCENT_INK))
        out.append(_lines(cx, 540, [a, b], 40, 54, weight=600, family=SERIF))
    return _document("Three promises", "Three cards: Free and open source. No account, no cloud. "
                     "What it learns stays on your PC.", "".join(out))


# --------------------------------------------------------------------------- I25 two front doors


def two_front_doors() -> str:
    """I25: your front door and next door's. Knocking on your own is housekeeping."""
    out = [_floor(740)]
    out.append(_rect(120, 180, 680, 560, fill=_mix(ACCENT, PANEL, 0.82), stroke=LINE_STRONG, sw=3))
    out.append(_rect(800, 180, 680, 560, fill=_mix(PLUM, PANEL, 0.82), stroke=LINE_STRONG, sw=3))
    for dx, col, num, mat in ((380, ACCENT, "12", "yours"), (1060, PLUM, "14", "next door")):
        out.append(_rect(dx - 10, 300, 200, 12, rx=4, fill=LINE_STRONG))
        out.append(_rect(dx, 312, 180, 428, rx=4, fill=_mix(col, PANEL, 0.2),
                         stroke=_mix(col, FG, 0.3), sw=3.5))
        out.append(_rect(dx + 24, 340, 132, 130, rx=6, fill="none", stroke=_mix(col, FG, 0.25), sw=2.5))
        out.append(_rect(dx + 24, 500, 132, 200, rx=6, fill="none", stroke=_mix(col, FG, 0.25), sw=2.5))
        out.append(_circle(dx + 156, 540, 8, fill=ACCENT_FG, stroke=FG_2, sw=2.5))
        out.append(_rect(dx + 56, 240, 68, 44, rx=8, fill=ACCENT_FG, stroke=LINE_STRONG, sw=2))
        out.append(_t(dx + 90, 272, num, 28, weight=700, family=SERIF))
        out.append(_path(f"M {dx - 40} 752 H {dx + 220} L {dx + 244} 812 H {dx - 64} Z",
                         fill=WOOD_LIGHT, stroke=WOOD, sw=3))
        out.append(_t(dx + 90, 794, mat, 34, weight=700, family=SERIF, fill=WOOD_DARK))
    # next door's peephole, with someone looking out of it
    out.append(_circle(1150, 400, 22, fill=FG_2))
    out.append(f'<ellipse cx="1150" cy="402" rx="15" ry="9" fill="{ACCENT_FG}"/>')
    out.append(_circle(1143, 402, 6, fill=FG))
    out.append(_path("M 1134 394 Q 1150 386 1166 394", stroke=FG_2, sw=4))
    # Home SOC at its own front door, torch on the house number
    out.append(_path("M 332 384 L 436 232 L 436 292 Z", fill=ACCENT_TINT, stroke=None, extra='opacity=".85"'))
    out.append(_person(260, 740, h=360, jumper=ACCENT, skin=SKIN[0], hair=WOOD_DARK))
    out.append(_arm(288, 494, 318, 408, sleeve=ACCENT, skin=SKIN[0], width=28, hand=15))
    out.append(_g(_rect(-8, -26, 16, 34, rx=4, fill=FG_2), x=324, y=396, rot=40))
    return _document("Two front doors", "Two front doors side by side. The left doormat says "
                     "yours; the right says next door. Home SOC shines a torch on its own house "
                     "number; next door, an eye watches through the peephole.", "".join(out))


# --------------------------------------------------------------------------- the score, worked out (13)


def _gauge(cx: float, cy: float, r: float, score: int, *, fill: str) -> str:
    """The Home page's safety gauge, drawn: a half-ring track, the filled share, the number."""
    out = [_path(f"M {cx - r:g} {cy:g} A {r:g} {r:g} 0 0 1 {cx + r:g} {cy:g}", stroke=TRACK, sw=34)]
    a = math.radians(180 - 180 * score / 100)
    ex, ey = cx + r * math.cos(a), cy - r * math.sin(a)
    out.append(_path(f"M {cx - r:g} {cy:g} A {r:g} {r:g} 0 0 1 {ex:.1f} {ey:.1f}", stroke=fill, sw=34))
    out.append(_t(cx, cy - 18, str(score), 88, weight=600, family=SERIF))
    out.append(_t(cx, cy + 34, "Needs work", 26, weight=650, fill=SEV["critical"][2]))
    return "".join(out)


def score_doubles() -> str:
    """13, on 'Clear both, and the score doubles': the sum the two '+4 points' pills do not show.

    The demo database's own score (SCRIPT.md honesty check): 10 on Monday, 14 with the camera's
    Telnet off, 20 with the router's flaw fixed too. Still "Needs work" at 20 - 0-49 is the
    dashboard's "Needs work" band - so the drawing says that too rather than promising a green.
    """
    out = [_t(800, 110, "Clear both Fix-now problems", 48, weight=600, family=SERIF)]
    steps = ((260, 10, "Monday"), (800, 14, "one of the two fixed"), (1340, 20, "both fixed"))
    for i, (cx, score, label) in enumerate(steps):
        out.append(_card(cx - 220, 200, 440, 420, rx=28))
        out.append(_gauge(cx, 470, 150, score, fill=BRICK))
        out.append(_t(cx, 578, label, 30, weight=600, fill=(MUTED if i == 0 else ACCENT_INK)))
        if i:
            px = cx - 270
            out.append(_path(f"M {px - 26} 410 H {px + 22}", stroke=ACCENT, sw=6))
            out.append(_path(f"M {px + 8} 394 L {px + 26} 410 L {px + 8} 426", stroke=ACCENT, sw=6))
    out.append(_t(800, 720, "10 \u2192 14 \u2192 20: the score doubles. Next up: the rest of the list.",
                  32, weight=600, fill=FG_2))
    return _document("The score, worked out", "Three safety gauges: 10 on Monday; 14 with one "
                     "of the two Fix-now problems fixed; 20 with both fixed. Still Needs work, but "
                     "doubled.", "".join(out))


# --------------------------------------------------------------------------- how sure it is (11)


def how_sure_key() -> str:
    """11, on 'Every line shows how sure it is': the map's own key, drawn without the jargon.

    The line styles are the product's (homesoc/web/static/map.css): Seen is a solid sage-ink
    line, Worked out dashed (6 / 3.5), Assumed dotted (1.5 / 4, round caps). A service nothing
    was seen using is a dashed pentagon with no line drawn to it - "with nothing to go on, it
    draws nothing".
    """
    out = [_t(800, 110, "How sure is Home SOC about each link?", 48, weight=600, family=SERIF)]
    out.append(_card(250, 170, 1100, 620, rx=28))
    rows = (
        ("Seen", "recorded, from this device’s address", f'stroke="{ACCENT_INK}" stroke-width="7"'),
        ("Worked out", "not seen: it follows from the layout",
         f'stroke="{FG_2}" stroke-width="5" stroke-dasharray="24 14"'),
        ("Assumed", "a sensible default, not confirmed",
         f'stroke="{FG_2}" stroke-width="6" stroke-dasharray="1 16" stroke-linecap="round"'),
    )
    for i, (word, note, style) in enumerate(rows):
        y = 270 + i * 130
        out.append(_icon("laptop", 380, y, 0.8, stroke=ACCENT))
        out.append(f'<line x1="440" y1="{y}" x2="660" y2="{y}" {style}/>')
        out.append(_icon("router", 720, y + 6, 0.8, stroke=ACCENT))
        out.append(_t(820, y + 2, word, 40, weight=650, family=SERIF, anchor="start"))
        out.append(_t(820, y + 40, note, 26, weight=500, fill=MUTED, anchor="start"))
    y = 660
    out.append(_icon("printer", 380, y, 0.8, stroke=ACCENT))
    pts = " ".join(f"{720 + 34 * math.cos(math.radians(-90 + k * 72)):.1f},"
                   f"{y + 34 * math.sin(math.radians(-90 + k * 72)):.1f}" for k in range(5))
    out.append(f'<polygon points="{pts}" fill="none" stroke="{FG_2}" stroke-width="4" '
               f'stroke-dasharray="9 7"/>')
    out.append(_t(820, y + 2, "Nothing to go on", 40, weight=650, family=SERIF, anchor="start"))
    out.append(_t(820, y + 40, "no line at all: it will not guess", 26, weight=500, fill=MUTED,
                  anchor="start"))
    return _document("How sure is Home SOC?", "The map's key, drawn: a solid line means seen, a "
                     "dashed line worked out, a dotted line assumed; a service with nothing to go on "
                     "has no line drawn to it.", "".join(out))


# ====================================================================== registry and rendering

#: Narrative order. Keys are what a scene plan references; I-numbers are SCRIPT.md's.
SLIDES: dict[str, Callable[[], str]] = {
    "dinner_table_guess": dinner_table_guess,        # I1 (01)
    "dinner_table_count": dinner_table_count,        # I1 (01)
    # I1 build frames between the guess and the count (01), one per phrase
    "dinner_table_ask": dinner_table_ask,
    "dinner_table_guess7": dinner_table_guess7,
    "dinner_table_printer": dinner_table_printer,
    "dinner_table_lamp": dinner_table_lamp,
    "dinner_table_heater": dinner_table_heater,
    "dinner_table_gadgets": dinner_table_gadgets,
    "dinner_table_camera": dinner_table_camera,
    "title_card": title_card,                        # 02
    "new_housemate": new_housemate,                  # I2 (02)
    "new_housemate_dog_awake": new_housemate_dog_awake,  # I2 on 'Labrador'
    "double_click": double_click,                    # I3 (03)
    "double_click_rule": double_click_rule,          # I3 on "One rule"
    "double_click_clock": double_click_clock,        # I3 on "five minutes"
    "double_click_printer": double_click_printer,    # I3 on "the printer takes"
    "robot_forecast": robot_forecast,                # I4 (03)
    "little_street": little_street,                  # I5 (04)
    "numbered_doors_bare": numbered_doors_bare,      # I6 (05), key frames on their words
    "numbered_doors_signs": numbered_doors_signs,
    "numbered_doors": numbered_doors,                # I6 (05)
    "numbered_doors_reach": numbered_doors_reach,
    "numbered_doors_withdraw": numbered_doors_withdraw,
    "telnet_1969": telnet_1969,                      # I8 (06)
    "postcard": postcard,                            # I7 (06)
    "obliging_router": obliging_router,              # I9 (06)
    "recall_vs_bulletin": recall_vs_bulletin,        # I10 (07)
    "world_forecast": world_forecast,                # I11 (07)
    "world_forecast_umbrella": world_forecast_umbrella,  # I11 on 'umbrella'
    "lock_in_the_post": lock_in_the_post,            # I12 (08)
    "pdf_costume": pdf_costume,                      # I13 (09)
    "phone_book": phone_book,                        # I14 (10)
    "homesick_camera": homesick_camera,              # I15 (10)
    "pc_nods_off": pc_nods_off,                      # I16 (10)
    "twenty_minutes": twenty_minutes,                # I17 (11)
    "how_sure_key": how_sure_key,                    # 11, the map key without jargon
    "white_box_shelf": white_box_shelf,              # I18 (12)
    "not_this": not_this,                            # I19 (12)
    "back_in_drawer": back_in_drawer,                # I20 (12)
    "spotless_house": spotless_house,                # I21 (13)
    "score_doubles": score_doubles,                  # 13, 10 -> 14 -> 20
    "on_the_fridge": on_the_fridge,                  # I22 (13)
    "smoke_not_car_alarm": smoke_not_car_alarm,      # I23 (13)
    "three_promises": three_promises,                # I24 (14)
    "two_front_doors": two_front_doors,              # I25 (14)
    "dinner_table_closing18": dinner_table_closing18,  # I1 closing key frames (14)
    "dinner_table_closing17": dinner_table_closing17,
    "dinner_table_closing": dinner_table_closing,    # I1 closing (14)
    "dinner_table_closing_nudge": dinner_table_closing_nudge,
    "end_card": end_card,                            # 14
}


def slide_names() -> list[str]:
    """The slide names, in narrative order."""
    return list(SLIDES)


def render(name: str) -> str:
    """Return the full HTML document for one slide; unknown names fail loudly."""
    try:
        fn = SLIDES[name]
    except KeyError:
        raise KeyError(f"unknown slide {name!r}; known slides: {', '.join(SLIDES)}") from None
    return fn()


def write_all(directory: str | Path) -> list[str]:
    """Write every slide to ``directory`` as ``<name>.html``; returns the paths written."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name in SLIDES:
        path = out_dir / f"{name}.html"
        path.write_text(render(name), encoding="utf-8")
        written.append(str(path))
    return written


def render_png(directory: str | Path, names: Iterable[str] | None = None, *,
               contact: bool = True) -> list[Path]:
    """Screenshot slides with the installed Chrome at 1600x900 @2x into ``directory``.

    Also reports any text that runs outside the frame, and builds ``contact.png``.
    """
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = list(names) if names else list(SLIDES)
    paths: list[Path] = []
    probe = """
() => {
  const bad = [];
  for (const el of document.querySelectorAll('svg.art text')) {
    const b = el.getBoundingClientRect();
    if (b.left < 0 || b.top < 0 || b.right > 1600 || b.bottom > 900) bad.push(el.textContent);
  }
  return bad;
}
"""
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        page = browser.new_page(viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
                                device_scale_factor=2, color_scheme="light")
        for name in wanted:
            page.set_content(render(name), wait_until="load")
            bad = page.evaluate(probe)
            if bad:
                logger.warning("%s: text outside the frame: %s", name, bad)
            path = out_dir / f"{name}.png"
            page.screenshot(path=str(path), full_page=False)
            paths.append(path)
            logger.info("rendered %s", path)
        browser.close()
    if contact and not names:
        paths.append(contact_sheet(out_dir, list(SLIDES)))
    return paths


def contact_sheet(directory: str | Path, names: Sequence[str], *, cols: int = 5,
                  thumb_w: int = 480) -> Path:
    """One PNG with every slide as a labelled thumbnail, in narrative order."""
    from PIL import Image, ImageDraw, ImageFont  # noqa: PLC0415

    out_dir = Path(directory)
    thumb_h = thumb_w * VIEWPORT_H // VIEWPORT_W
    pad, label_h = 24, 34
    rows = math.ceil(len(names) / cols)
    sheet = Image.new("RGB", (pad + cols * (thumb_w + pad), pad + rows * (thumb_h + label_h + pad)),
                      SIDEBAR)
    draw = ImageDraw.Draw(sheet)
    try:
        font = ImageFont.truetype("segoeui.ttf", 18)
    except OSError:
        font = ImageFont.load_default()
    for i, name in enumerate(names):
        im = Image.open(out_dir / f"{name}.png").convert("RGB")
        im.thumbnail((thumb_w, thumb_h), Image.LANCZOS)
        x = pad + (i % cols) * (thumb_w + pad)
        y = pad + (i // cols) * (thumb_h + label_h + pad)
        sheet.paste(im, (x, y))
        draw.rectangle((x - 1, y - 1, x + thumb_w, y + thumb_h), outline=LINE_STRONG)
        draw.text((x, y + thumb_h + 6), f"{i + 1:02d}  {name}", fill=FG, font=font)
    path = out_dir / "contact.png"
    sheet.save(path)
    return path


if __name__ == "__main__":  # pragma: no cover - developer convenience
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Render the everyday-film illustrations.")
    parser.add_argument("--out", default=str(_HERE / "everyday" / "slides"))
    parser.add_argument("names", nargs="*", help="only these slides (no contact sheet)")
    args = parser.parse_args()
    for written in render_png(args.out, args.names or None):
        print(written)
