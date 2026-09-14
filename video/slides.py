"""HTML slides for the Home SOC walkthrough video.

Every function here returns a complete HTML document sized for a 1600x900 viewport, which
``video/capture.py`` renders with the same Playwright/Chrome session it uses for the dashboard
(``device_scale_factor=2``, ``prefers-color-scheme: dark``). Sharing the browser is the point: the
slides then share the product's font stack, palette, radii and shadows, so a title card and the real
dashboard look like the same piece of software.

The palette below is copied from ``homesoc/web/static/style.css`` (dark theme). There are no
external assets, no CDN fonts and no images -- everything is inline CSS and inline SVG, exactly like
the dashboard.

Public API (the names ``script.py`` uses as ``Slide(html_fn=...)``)::

    title() what_it_is() architecture() first_run() daily_use() close()
    SLIDES: dict[str, Callable[[], str]]
    render(name) -> str
    slide_names() -> list[str]

Every ``<text>`` element in the architecture diagram carries a ``data-maxx`` attribute: the right
edge its content must stay inside. :func:`overflow_probe` returns a one-liner that checks all of
them in the page, so a reworded label can never silently overrun its box.
"""

from __future__ import annotations

import datetime as _dt
import logging
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
#: The video's own database — never the owner's. Slides that quote a figure the dashboard
#: also shows read it from here, so the two cannot drift apart between renders.
DEMO_DB = _HERE / "demo_data" / "homesoc.db"


def _catalogue_counts() -> tuple[int, int]:
    """``(rules, categories)`` from the product's findings catalogue."""
    try:
        sys.path.insert(0, str(_HERE))
        from script import catalogue_counts  # type: ignore[import-not-found]

        return catalogue_counts()
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not read the findings catalogue (%s)", exc)
        raise


def _device_count() -> str:
    """How many devices the demo network has, spelled out.

    The first-run slide said "a twenty-device network" while the narration spoken over it
    said "an eighteen-device network" and the topbar behind it read 17 / 18.
    """
    from script import spell  # type: ignore[import-not-found]  # noqa: PLC0415

    sys.path.insert(0, str(_HERE))
    rows = _demo_query("SELECT COUNT(*) AS n FROM devices")
    word = spell(int(rows[0]["n"]))
    return f"{'an' if word[:1] in 'aeiou' else 'a'} {word}"


def _schema_version() -> int:
    """``homesoc.db.SCHEMA_VERSION`` — what a fresh install actually prints."""
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))
    from homesoc import db as _db  # noqa: PLC0415

    return int(_db.SCHEMA_VERSION)


def _demo_query(sql: str, params: Sequence[object] = ()) -> list[sqlite3.Row]:
    """Read-only query against ``video/demo_data/homesoc.db``. Never the real data/."""
    if not DEMO_DB.exists():
        raise FileNotFoundError(
            f"{DEMO_DB} does not exist — run `python video/seed_demo.py` before rendering "
            "slides that quote the demo network."
        )
    conn = sqlite3.connect(f"file:{DEMO_DB.as_posix()}?mode=ro", uri=True, timeout=10)
    try:
        conn.row_factory = sqlite3.Row
        return list(conn.execute(sql, tuple(params)))
    finally:
        conn.close()

# --------------------------------------------------------------------------- palette / metrics

VIEWPORT_W = 1600
VIEWPORT_H = 900

BG = "#0f1117"
PANEL = "#171a23"
PANEL_2 = "#1d2130"
LINE = "#262a36"
FG = "#e6e8ef"
MUTED = "#8b91a3"
ACCENT = "#3e63dd"
SEV_CRITICAL = "#e5484d"
SEV_HIGH = "#f76b15"
SEV_MEDIUM = "#ffb224"
SEV_LOW = "#46a758"
SEV_INFO = "#3e63dd"

#: printed-sticker colours, shared with ``video/scene_render.py`` so the sticker on the
#: explanatory slide and the sticker in the illustrated scene are the same object
STICKER = "#f6f7fb"
STICKER_LINE = "#dfe2ea"
STICKER_INK = "#1a1d27"

SANS = 'system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
MONO = 'ui-monospace, "Cascadia Mono", "Consolas", "SF Mono", Menlo, monospace'

BRAND_MARK = "\u25c9"  # the dashboard sidebar's brand glyph
TRI = "\u25b3"  # "needs administrator"
ARROW = "\u2192"


@dataclass(frozen=True)
class Rect:
    """A box in diagram coordinates. ``inner`` is the text area after padding."""

    x: float
    y: float
    w: float
    h: float

    @property
    def right(self) -> float:
        return self.x + self.w

    @property
    def bottom(self) -> float:
        return self.y + self.h

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2

    def inner(self, pad: float = 14.0) -> tuple[float, float]:
        """(left x for text, max right x for text)."""
        return self.x + pad, self.right - pad


# --------------------------------------------------------------------------- document shell

_BASE_CSS = f"""
*, *::before, *::after {{ box-sizing: border-box; }}
html, body {{
  margin: 0; padding: 0;
  width: {VIEWPORT_W}px; height: {VIEWPORT_H}px;
  overflow: hidden;
}}
body {{
  background: {BG};
  color: {FG};
  font-family: {SANS};
  font-size: 16px;
  line-height: 1.45;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}}
.slide {{
  width: {VIEWPORT_W}px; height: {VIEWPORT_H}px;
  position: relative;
  display: flex; flex-direction: column;
  padding: 44px;
}}
.slide--tight {{ padding: 24px 40px 14px; }}
h1, h2, h3, h4, p, ul, ol {{ margin: 0; }}
b, strong {{ font-weight: 650; }}
.mono {{ font-family: {MONO}; }}
.muted {{ color: {MUTED}; }}
.eyebrow {{
  font-size: 13.5px; font-weight: 650; letter-spacing: .16em;
  text-transform: uppercase; color: {MUTED};
}}
.head h1 {{ font-size: 34px; font-weight: 700; letter-spacing: -.015em; line-height: 1.15; }}
.head p {{ font-size: 17.5px; color: {MUTED}; margin-top: 8px; max-width: 1240px; }}
.card {{
  background: {PANEL};
  border: 1px solid {LINE};
  border-radius: 12px;
  box-shadow: 0 1px 2px rgba(0,0,0,.35);
  padding: 20px 22px;
}}
.card h2 {{
  font-size: 13px; font-weight: 650; letter-spacing: .12em;
  text-transform: uppercase; color: {MUTED}; margin-bottom: 14px;
}}
.rule {{ height: 1px; background: {LINE}; border: 0; }}
.chip {{
  display: inline-flex; align-items: center; gap: 6px;
  background: {PANEL}; border: 1px solid {LINE}; border-radius: 999px;
  padding: 6px 14px; font-size: 14.5px; color: {MUTED}; white-space: nowrap;
}}
.chip b {{ color: {FG}; font-weight: 650; }}
.sev-bar {{ display: flex; height: 5px; border-radius: 3px; overflow: hidden; }}
.sev-bar span {{ flex: 1 1 0; }}
.foot {{
  margin-top: auto; display: flex; align-items: center; justify-content: space-between;
  gap: 24px; font-size: 14.5px; color: {MUTED};
}}
"""


def _document(page_title: str, body: str, extra_css: str = "") -> str:
    """Wrap slide markup in a full, self-contained HTML document."""
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="color-scheme" content="dark">\n'
        f"<title>{page_title} \u00b7 Home SOC</title>\n"
        f"<style>{_BASE_CSS}{extra_css}</style>\n"
        "</head>\n<body>\n"
        f"{body}\n"
        "</body>\n</html>\n"
    )


def _head(eyebrow: str, heading: str, sub: str) -> str:
    return (
        '<header class="head">'
        f'<div class="eyebrow">{eyebrow}</div>'
        f"<h1>{heading}</h1>"
        f"<p>{sub}</p>"
        "</header>"
    )


def _sev_bar() -> str:
    cols = (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO)
    return '<div class="sev-bar">' + "".join(f'<span style="background:{c}"></span>' for c in cols) + "</div>"


# --------------------------------------------------------------------------- 1. title


def title() -> str:
    """Opening card: the product name and the one-line pitch."""
    css = f"""
.title-slide {{ justify-content: center; padding: 0 110px; }}
.title-glow {{
  position: absolute; inset: 0; pointer-events: none;
  background:
    radial-gradient(900px 620px at 14% 18%, rgba(62,99,221,.20), transparent 68%),
    radial-gradient(760px 560px at 90% 96%, rgba(70,167,88,.11), transparent 66%);
}}
.title-grid {{
  position: absolute; inset: 0; pointer-events: none; opacity: .5;
  background-image:
    linear-gradient(to right, {LINE} 1px, transparent 1px),
    linear-gradient(to bottom, {LINE} 1px, transparent 1px);
  background-size: 64px 64px;
  mask-image: radial-gradient(1200px 700px at 20% 30%, #000 20%, transparent 78%);
}}
.title-body {{ position: relative; }}
.brand-row {{ display: flex; align-items: center; gap: 20px; }}
.brand-mark {{ font-size: 62px; color: {ACCENT}; line-height: 1; }}
.brand-name {{ font-size: 96px; font-weight: 750; letter-spacing: -.035em; line-height: 1; }}
.pitch {{ font-size: 32px; font-weight: 500; margin-top: 30px; max-width: 1120px; line-height: 1.32; }}
.pitch em {{ font-style: normal; color: {ACCENT}; }}
.sub {{ font-size: 19.5px; color: {MUTED}; margin-top: 18px; max-width: 1000px; line-height: 1.55; }}
.title-bar {{ width: 300px; margin-top: 34px; }}
.title-chips {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 34px; }}
/* right-aligned so the compositor's lower-third caption pill owns the bottom-left corner */
.title-foot {{
  position: absolute; left: 110px; right: 110px; bottom: 46px;
  display: flex; justify-content: flex-end; gap: 34px; font-size: 15px; color: {MUTED};
}}
"""
    chips = (
        "device discovery",
        "service &amp; port scan",
        "CISA KEV \u00b7 NVD \u00b7 EPSS",
        "Windows posture",
        "Microsoft Defender",
        "LAN DNS sinkhole",
        # The headline addition of v2, and the thing the narration over this very card ends
        # on ("you do not know which of four identical white boxes it is"). Without it the
        # title card advertised the v1 feature set for the first nineteen seconds.
        "Lens \u00b7 point your phone at a device",
    )
    body = f"""
<div class="slide title-slide">
  <div class="title-glow"></div>
  <div class="title-grid"></div>
  <div class="title-body">
    <div class="brand-row">
      <span class="brand-mark">{BRAND_MARK}</span>
      <span class="brand-name">Home SOC</span>
    </div>
    <div class="title-bar">{_sev_bar()}</div>
    <p class="pitch">A small security operations centre for <em>your own home network</em>.</p>
    <p class="sub">One Python process, on a PC you already own. It finds what is on your network,
      what is wrong with it, and what to do about it &mdash; and nothing ever leaves the machine.</p>
    <div class="title-chips">
      {''.join(f'<span class="chip">{c}</span>' for c in chips)}
    </div>
  </div>
  <div class="title-foot">
    <span>Open source \u00b7 MIT licence</span>
    <span class="mono">python -m homesoc run &nbsp;\u2192&nbsp; http://127.0.0.1:8787</span>
  </div>
</div>
"""
    return _document("Home SOC", body, css)


# --------------------------------------------------------------------------- 2. what it is


@dataclass(frozen=True)
class _Point:
    colour: str
    heading: str
    detail: str


_DOES: tuple[_Point, ...] = (
    _Point(SEV_INFO, "Updates the definitions",
           "CISA KEV, EPSS exploit scores, the IEEE OUI vendor database and a set of DNS blocklists "
           "&mdash; 15 feeds, ETag-cached, so a re-check costs almost nothing."),
    _Point(SEV_LOW, "Finds every device on your Wi-Fi",
           "The ARP table first, then a gentle TCP sweep, then a service scan: open ports, banners, "
           "products and versions."),
    _Point(SEV_MEDIUM, "Separates real risk from noise",
           "Services are matched against CISA KEV, NVD and EPSS, so &ldquo;exploited in the wild&rdquo; "
           "is never filed next to &ldquo;theoretically vulnerable&rdquo;."),
    _Point(SEV_HIGH, "Audits this computer",
           "Microsoft Defender state, firewall, Windows Update, local accounts, autostart entries, "
           "listening ports, Wi-Fi encryption and your router&rsquo;s exposure to the internet."),
    _Point(SEV_CRITICAL, "Filters DNS for the whole house",
           "An optional resolver on port 53 that blocks ads and trackers and sinkholes known-malicious "
           "domains &mdash; including for devices that can&rsquo;t run an ad-blocker."),
)

_IS_NOT: tuple[tuple[str, str], ...] = (
    ("Not an antivirus engine",
     "It has no detection engine of its own and never scans a file with one. Defender stays the thing "
     "that catches malware."),
    ("Not an EDR",
     "No kernel driver, no hooks, no process-tree monitoring, no memory scanning. It reads what Windows "
     "already shows an ordinary user."),
    ("Not an IDS/IPS",
     "It is not in the path of your traffic and cannot block a connection. The only thing it can refuse "
     "is a DNS name."),
    ("Not an attack tool",
     "It never sends an exploit, never tries a credential, never attempts a login and never changes "
     "anything on another device."),
    ("Not a cloud service",
     "No account, no sign-up, no telemetry, no crash reporting, no remote control plane."),
)


def what_it_is() -> str:
    """The two-column &ldquo;what it does / what it is not&rdquo; card."""
    css = f"""
.two {{ display: grid; grid-template-columns: 1fr 1fr; gap: 26px; margin-top: 26px; flex: 1 1 auto; }}
.col {{ display: flex; flex-direction: column; }}
.col > h2 {{ margin-bottom: 18px; }}
.pt {{ display: grid; grid-template-columns: 12px minmax(0,1fr); gap: 14px; padding: 13px 0; }}
.pt + .pt {{ border-top: 1px solid {LINE}; }}
.dot {{ width: 10px; height: 10px; border-radius: 50%; margin-top: 8px; }}
.pt h3 {{ font-size: 19px; font-weight: 650; letter-spacing: -.01em; }}
.pt p {{ font-size: 15px; color: {MUTED}; margin-top: 4px; line-height: 1.5; }}
.no h3 {{ color: {FG}; }}
/* a hollow ring against the left column's filled dots: does / does not */
.no .x {{
  width: 10px; height: 10px; margin-top: 8px; border-radius: 50%;
  border: 1.5px solid {MUTED}; background: transparent;
}}
.col--yes {{ border-left: 3px solid {ACCENT}; padding-left: 22px; }}
.col--no {{ border-left: 3px solid {LINE}; padding-left: 22px; }}
.strip {{
  margin-top: 22px; display: flex; align-items: center; gap: 18px;
  border: 1px solid {LINE}; border-radius: 12px; background: {PANEL};
  padding: 16px 22px; font-size: 17px;
}}
.strip .lead {{ font-weight: 650; }}
.strip .sep {{ color: {LINE}; }}
"""
    yes = "".join(
        f'<div class="pt"><span class="dot" style="background:{p.colour}"></span>'
        f"<div><h3>{p.heading}</h3><p>{p.detail}</p></div></div>"
        for p in _DOES
    )
    no = "".join(
        f'<div class="pt"><span class="x"></span><div><h3>{h}</h3><p>{d}</p></div></div>'
        for h, d in _IS_NOT
    )
    body = f"""
<div class="slide">
  {_head("Home SOC", "What it is, in one breath",
         "One process, on your PC, watching your own network. Everything it learns stays in one SQLite "
         "file on that machine.")}
  <div class="two">
    <section class="col col--yes"><h2>What it does</h2>{yes}</section>
    <section class="col col--no no"><h2>What it is not</h2>{no}</section>
  </div>
  <div class="strip">
    <span class="lead">One process.</span><span class="sep">|</span>
    <span class="lead">One SQLite file.</span><span class="sep">|</span>
    <span class="lead">One PC.</span><span class="sep">|</span>
    <span class="muted">No account, no cloud, no telemetry &mdash; and no administrator rights for the
      default setup.</span>
  </div>
</div>
"""
    return _document("What it is", body, css)


# --------------------------------------------------------------------------- 3. architecture

# Diagram coordinate system. Everything below is in these units; the <svg> is drawn 1:1 in CSS px.
_AW = 1520.0
_AH = 772.0

_COL_A = Rect(8, 100, 222, 330)     # definition feeds (outside the process boundary)
_COL_B = Rect(322, 100, 268, 330)   # scanners
_COL_C = Rect(682, 100, 320, 330)   # findings engine
_COL_D = Rect(1084, 100, 420, 330)  # outputs

_SCHED = Rect(322, 28, 1182, 42)
_DB = Rect(322, 462, 826, 64)
_RESOLVER = Rect(360, 566, 646, 192)
_LAN = Rect(8, 598, 222, 132)
_UPSTREAM = Rect(1208, 598, 296, 124)

#: Lens: the phone that reads the same database, over HTTPS, with its own scoped token.
#: It sits *outside* the process boundary because it is a different device - which is the
#: whole point of the notch below, and the reason the notch now starts at column D's foot
#: rather than halfway down the diagram.
_LENS_PHONE = Rect(1186, 476, 318, 112)

_BOUND_L, _BOUND_T, _BOUND_R = 252.0, 10.0, 1512.0
# BG composited with the boundary's rgba(62,99,221,.045) wash: the exact colour inside the
# process outline, so a label backdrop drawn there is invisible.
_INSIDE_BG = "#111520"
_BOUND_SHOULDER_Y, _BOUND_NOTCH_X, _BOUND_B = 436.0, 1160.0, 762.0

_CAPTION_Y = 90.0


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _t(
    x: float,
    y: float,
    text: str,
    *,
    maxx: float,
    size: float = 14.0,
    weight: int = 400,
    fill: str = FG,
    anchor: str = "start",
    letter_spacing: float | None = None,
    mono: bool = False,
    opacity: float | None = None,
) -> str:
    """One SVG text run, tagged with the right edge it must not cross (``data-maxx``)."""
    family = MONO if mono else SANS
    parts = [
        f'<text x="{x:g}" y="{y:g}"',
        f'font-family=\'{family}\'',
        f'font-size="{size:g}"',
        f'font-weight="{weight}"',
        f'fill="{fill}"',
        f'data-maxx="{maxx:g}"',
    ]
    if anchor != "start":
        parts.append(f'text-anchor="{anchor}"')
    if letter_spacing is not None:
        parts.append(f'letter-spacing="{letter_spacing:g}"')
    if opacity is not None:
        parts.append(f'opacity="{opacity:g}"')
    return " ".join(parts) + f">{_esc(text)}</text>"


def _box(r: Rect, *, fill: str = PANEL, stroke: str = LINE, rx: float = 10.0,
         stroke_width: float = 1.0, dash: str | None = None) -> str:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    return (
        f'<rect x="{r.x:g}" y="{r.y:g}" width="{r.w:g}" height="{r.h:g}" rx="{rx:g}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width:g}"{dash_attr}/>'
    )


def _line(x1: float, y1: float, x2: float, y2: float, *, stroke: str = MUTED,
          width: float = 1.6, marker: str | None = None, dash: str | None = None,
          opacity: float | None = None) -> str:
    bits = [f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}"',
            f'stroke="{stroke}"', f'stroke-width="{width:g}"', 'stroke-linecap="round"']
    if marker:
        bits.append(f'marker-end="url(#{marker})"')
    if dash:
        bits.append(f'stroke-dasharray="{dash}"')
    if opacity is not None:
        bits.append(f'opacity="{opacity:g}"')
    return " ".join(bits) + "/>"


def _path(d: str, *, stroke: str = MUTED, width: float = 1.6, marker: str | None = None,
          dash: str | None = None, fill: str = "none", opacity: float | None = None) -> str:
    bits = [f'<path d="{d}"', f'fill="{fill}"', f'stroke="{stroke}"', f'stroke-width="{width:g}"',
            'stroke-linejoin="round"', 'stroke-linecap="round"']
    if marker:
        bits.append(f'marker-end="url(#{marker})"')
    if dash:
        bits.append(f'stroke-dasharray="{dash}"')
    if opacity is not None:
        bits.append(f'opacity="{opacity:g}"')
    return " ".join(bits) + "/>"


def _marker(name: str, colour: str) -> str:
    return (
        f'<marker id="{name}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6.5" '
        'markerHeight="6.5" orient="auto-start-reverse">'
        f'<path d="M0,0.6 L10,5 L0,9.4 z" fill="{colour}"/></marker>'
    )


def _feed_boxes() -> str:
    """Column A: the definition feeds, the only thing Home SOC downloads."""
    items = (
        ("CISA KEV", "exploited in the wild", SEV_CRITICAL),
        ("NVD \u00b7 EPSS", "detail + exploit probability", SEV_HIGH),
        ("IEEE OUI", "MAC prefix \u2192 vendor", SEV_LOW),
        ("DNS blocklists", "oisd \u00b7 HaGeZi \u00b7 URLhaus", SEV_MEDIUM),
    )
    out: list[str] = []
    h, gap = 72.0, 14.0
    for i, (name, sub, colour) in enumerate(items):
        r = Rect(_COL_A.x, _COL_A.y + i * (h + gap), _COL_A.w, h)
        tx, mx = r.inner(14)
        out.append(_box(r))
        out.append(f'<rect x="{r.x:g}" y="{r.y + 14:g}" width="3" height="{h - 28:g}" rx="1.5" fill="{colour}"/>')
        out.append(_t(tx + 6, r.y + 32, name, maxx=mx, size=19, weight=650))
        out.append(_t(tx + 6, r.y + 54, sub, maxx=mx, size=13, fill=MUTED))
    return "".join(out)


def _scanner_panel() -> str:
    """Column B: the scanners, plus the honest note about what they never do."""
    rows = (
        ("discovery", "ARP table, then a gentle sweep", SEV_LOW),
        ("services", "ports, banners, nmap -sT -sV", SEV_LOW),
        ("vulns", "match against KEV / NVD / EPSS", SEV_MEDIUM),
        (f"host posture  {TRI}", "firewall, accounts, encryption", SEV_HIGH),
        ("defender", "reads state, threats, scan age", SEV_HIGH),
        ("exposure", "public IP \u00b7 Shodan InternetDB", SEV_CRITICAL),
    )
    out = [_box(_COL_B)]
    tx, mx = _COL_B.inner(16)
    y = _COL_B.y + 30
    for name, sub, colour in rows:
        out.append(f'<circle cx="{tx + 4:g}" cy="{y - 5:g}" r="4.5" fill="{colour}"/>')
        out.append(_t(tx + 18, y, name, maxx=mx, size=17, weight=650, mono=True))
        out.append(_t(tx + 18, y + 19, sub, maxx=mx, size=13, fill=MUTED))
        y += 44
    out.append(_line(tx, y - 12, mx, y - 12, stroke=LINE, width=1))
    out.append(_t(tx, y + 6, "Read-only. It never sends an exploit,", maxx=mx, size=12.5, fill=MUTED))
    out.append(_t(tx, y + 22, "never tries a credential, never logs in.", maxx=mx, size=12.5, fill=MUTED))
    return "".join(out)


def _engine_panel() -> str:
    """Column C: catalogue, lifecycle and score -- the part that owns a finding's life story."""
    # Read from the catalogue, not typed: the literal here said 88 while the code had 92
    # and the narration said eighty-nine. script.catalogue_counts() is the same import the
    # voice uses, so the slide and the voice cannot disagree.
    rules, categories = _catalogue_counts()
    cards = (
        ("CATALOGUE", f"{rules} rules \u00b7 {categories} categories",
         "title, why it matters, numbered fix steps"),
        ("LIFECYCLE", "open \u2192 acknowledged \u2192 resolved",
         "auto-resolves only after a complete run"),
        ("SCORE", "0\u2013100, halving curve, A\u2013F",
         "one open critical caps the score at 34"),
    )
    out = [_box(_COL_C)]
    ch, gap = 86.0, 10.0
    y = _COL_C.y + 14
    for label, value, sub in cards:
        r = Rect(_COL_C.x + 14, y, _COL_C.w - 28, ch)
        tx, mx = r.inner(12)
        out.append(_box(r, fill=PANEL_2, rx=8))
        out.append(_t(tx, r.y + 23, label, maxx=mx, size=12, weight=650, fill=ACCENT, letter_spacing=1.4))
        out.append(_t(tx, r.y + 49, value, maxx=mx, size=16.5, weight=650))
        out.append(_t(tx, r.y + 71, sub, maxx=mx, size=13, fill=MUTED))
        y += ch + gap
    tx, mx = _COL_C.inner(16)
    out.append(_t(tx, _COL_C.bottom - 14, "Scanners observe. The engine remembers.",
                  maxx=mx, size=13.5, fill=MUTED))
    return "".join(out)


def _output_panel() -> str:
    """Column D: everything a person actually reads - now including the phone."""
    rows = (
        ("Dashboard", "127.0.0.1:8787", "overview \u00b7 findings \u00b7 devices \u00b7 vulns \u00b7 host \u00b7 DNS",
         SEV_INFO, False),
        ("Activity feed", "/feed", "one stream of everything that happened \u00b7 also RSS",
         SEV_LOW, False),
        ("Remediation summary", "/summary", "found vs fixed \u00b7 time-to-fix \u00b7 the open worklist",
         SEV_MEDIUM, False),
        ("Notifications", "outbound", "ntfy \u00b7 Discord \u00b7 webhook \u00b7 toast \u00b7 digest",
         SEV_HIGH, False),
        ("Lens", "/lens \u00b7 TLS", "point a phone at a device and see what it knows",
         ACCENT, True),
    )
    out = [_box(_COL_D)]
    # five rows in the height four used to have: 57 + 5 still clears the type at
    # 17.5/13 px, and the alternative - a sixth column - would crowd the diagram.
    rh, gap = 57.0, 5.0
    y = _COL_D.y + 11
    for name, tag, sub, colour, is_lens in rows:
        r = Rect(_COL_D.x + 14, y, _COL_D.w - 28, rh)
        tx, mx = r.inner(14)
        out.append(_box(r, fill=PANEL_2, rx=8, stroke=ACCENT if is_lens else LINE))
        out.append(f'<rect x="{r.x:g}" y="{r.y + 10:g}" width="3" height="{rh - 20:g}" rx="1.5" fill="{colour}"/>')
        out.append(_t(tx + 6, r.y + 25, name, maxx=mx - 108, size=17.5, weight=650))
        out.append(_t(mx, r.y + 25, tag, maxx=mx + 1, size=12.5, fill=MUTED, anchor="end", mono=True))
        out.append(_t(tx + 6, r.y + 45, sub, maxx=mx, size=13, fill=MUTED))
        y += rh + gap
    return "".join(out)


def _lens_phone() -> str:
    """The phone, drawn outside the process boundary, and the link that reaches it."""
    out: list[str] = []
    r = _LENS_PHONE

    # the arrow out of the Lens row, crossing the boundary on its way to the phone
    ax = 1230.0
    out.append(_line(ax, _COL_D.bottom - 10, ax, r.y - 6, stroke=ACCENT, width=2.4,
                     marker="ah-accent"))
    # the label sits below the boundary line, on its own backdrop, so neither the
    # dashes nor the text has to survive being drawn through the other
    out.append(f'<rect x="1244" y="444" width="188" height="22" fill="{BG}"/>')
    out.append(_t(1250, 460, "HTTPS \u00b7 scoped read-only token", maxx=1432, size=12.5,
                  fill=MUTED))

    # solid, not dashed: the legend spends the dashed outline on "one OS process", and
    # the point of this box is that the phone is a different machine altogether
    out.append(_box(r, fill=PANEL_2, stroke=ACCENT, stroke_width=1.6))
    tx, mx = r.inner(14)
    out.append(_t(tx, r.y + 28, "Your phone", maxx=mx - 96, size=18.5, weight=650))
    out.append(_t(mx, r.y + 28, "Chrome \u00b7 Android", maxx=mx + 1, size=12.5, fill=MUTED,
                  anchor="end"))
    for i, line in enumerate((
        "the camera reads a barcode or a sticker,",
        "the token resolves only on this PC,",
        "and a phone is revoked on its own.",
    )):
        out.append(_t(tx, r.y + 54 + i * 18, line, maxx=mx, size=13, fill=MUTED))
    return "".join(out)


def _flow_arrow(x1: float, x2: float, y: float, lines: Sequence[str]) -> str:
    """A fat left-to-right arrow between two columns, with a stacked label above it."""
    cx = (x1 + x2) / 2
    base = y - 34 + (len(lines) - 1) * -16
    # the A -> B arrow crosses the dashed process boundary, so the label gets its own backdrop
    # rather than being cut in half by it. 76 keeps every backdrop inside the narrowest gap
    # between two columns (82 px), so it never bites a notch out of a panel border.
    bw = 76.0
    out = [
        f'<rect x="{cx - bw / 2:g}" y="{base - 14:g}" width="{bw:g}" '
        f'height="{16 * len(lines) + 8:g}" fill="{_INSIDE_BG}"/>',
        _line(x1, y, x2, y, stroke=ACCENT, width=3.4, marker="ah-accent", opacity=0.9),
    ]
    for i, text in enumerate(lines):
        out.append(_t(cx, base + i * 16, text, maxx=cx + bw / 2, size=12.5, fill=MUTED, anchor="middle"))
    return "".join(out)


def _dns_band() -> str:
    """The resolver: LAN clients on one side, upstream resolvers on the other."""
    out: list[str] = []

    # --- LAN clients (outside the process boundary, on the left)
    out.append(_box(_LAN, fill=PANEL_2))
    tx, mx = _LAN.inner(14)
    out.append(_t(tx, _LAN.y + 30, "LAN clients", maxx=mx, size=18.5, weight=650))
    out.append(_t(tx, _LAN.y + 52, "phones \u00b7 TV \u00b7 printer \u00b7 plug", maxx=mx, size=13, fill=MUTED))
    out.append(_t(tx, _LAN.y + 70, "your router hands out this PC", maxx=mx, size=13, fill=MUTED))
    out.append(_t(tx, _LAN.y + 88, "as the DNS server", maxx=mx, size=13, fill=MUTED))
    out.append(_t(tx, _LAN.y + 110, f"{TRI} reaching it from the LAN", maxx=mx, size=12.5, fill=SEV_MEDIUM))
    out.append(_t(tx, _LAN.y + 125, "needs one firewall rule", maxx=mx, size=12.5, fill=SEV_MEDIUM))

    # --- resolver panel
    out.append(_box(_RESOLVER, stroke=ACCENT, dash="6 5"))
    rtx, rmx = _RESOLVER.inner(16)
    out.append(_t(rtx, _RESOLVER.y + 28, "Embedded DNS resolver", maxx=rmx - 210, size=18.5, weight=650))
    out.append(_t(rmx, _RESOLVER.y + 28, "optional \u00b7 UDP + TCP :53", maxx=rmx + 1,
                  size=13, fill=MUTED, anchor="end", mono=True))

    stages = (
        ("1. POLICY", ("your overrides win, then", "the blocklists, then a", "reputation verdict")),
        ("2. CACHE", ("TTL-aware LRU. Policy runs", "first, so a new block", "applies immediately")),
        ("3. FORWARD", ("a fresh request upstream:", "UDP \u2192 TCP \u2192 DoH. Your", "client's EDNS never leaks")),
    )
    cw, cgap = 194.0, 18.0
    cy, chh = _RESOLVER.y + 44, 112.0
    for i, (label, lines) in enumerate(stages):
        r = Rect(_RESOLVER.x + 14 + i * (cw + cgap), cy, cw, chh)
        ctx, cmx = r.inner(13)
        out.append(_box(r, fill=PANEL_2, rx=8))
        out.append(_t(ctx, r.y + 24, label, maxx=cmx, size=12, weight=650, fill=ACCENT, letter_spacing=1.3))
        for j, text in enumerate(lines):
            out.append(_t(ctx, r.y + 48 + j * 18, text, maxx=cmx, size=13, fill=MUTED))
        if i < len(stages) - 1:
            out.append(_line(r.right + 4, r.cy, r.right + cgap - 4, r.cy,
                             stroke=MUTED, width=1.8, marker="ah-muted", opacity=0.8))
    out.append(_t(rtx, _RESOLVER.bottom - 14,
                  "Every answer is logged: who asked, for what, and which list decided.",
                  maxx=rmx, size=13, fill=MUTED))

    # --- upstream resolvers (outside the boundary, on the right)
    out.append(_box(_UPSTREAM, fill=PANEL_2))
    utx, umx = _UPSTREAM.inner(14)
    out.append(_t(utx, _UPSTREAM.y + 30, "Upstream resolvers", maxx=umx, size=18.5, weight=650))
    out.append(_t(utx, _UPSTREAM.y + 54, "1.1.1.2 \u00b7 9.9.9.9", maxx=umx, size=15, fill=FG, mono=True))
    out.append(_t(utx, _UPSTREAM.y + 76, "DoH fallback when UDP fails", maxx=umx, size=13, fill=MUTED))
    out.append(_t(utx, _UPSTREAM.y + 96, "the only thing the resolver", maxx=umx, size=13, fill=MUTED))
    out.append(_t(utx, _UPSTREAM.y + 112, "sends off this machine", maxx=umx, size=13, fill=MUTED))

    # --- arrows: client -> resolver -> upstream, and the two answers back
    out.append(_line(_LAN.right + 4, 648, _RESOLVER.x - 4, 648, stroke=ACCENT, width=2.6, marker="ah-accent"))
    out.append(_t((_LAN.right + _RESOLVER.x) / 2, 636, "a query", maxx=_RESOLVER.x, size=12.5,
                  fill=MUTED, anchor="middle"))
    out.append(_line(_RESOLVER.x - 4, 700, _LAN.right + 4, 700, stroke=SEV_CRITICAL, width=2.6,
                     marker="ah-critical"))
    out.append(_t((_LAN.right + _RESOLVER.x) / 2, 718, "blocked \u2192 0.0.0.0", maxx=_RESOLVER.x + 10,
                  size=12.5, fill=SEV_CRITICAL, anchor="middle"))
    out.append(_line(_RESOLVER.right + 4, 640, _UPSTREAM.x - 4, 640, stroke=ACCENT, width=2.6,
                     marker="ah-accent"))
    out.append(_t((_RESOLVER.right + _UPSTREAM.x) / 2, 628, "allowed names only",
                  maxx=_UPSTREAM.x, size=12.5, fill=MUTED, anchor="middle"))
    out.append(_line(_UPSTREAM.x - 4, 692, _RESOLVER.right + 4, 692, stroke=MUTED, width=2.2,
                     marker="ah-muted"))
    out.append(_t((_RESOLVER.right + _UPSTREAM.x) / 2, 710, "the answer", maxx=_UPSTREAM.x,
                  size=12.5, fill=MUTED, anchor="middle"))
    return "".join(out)


def _architecture_svg() -> str:
    parts: list[str] = [
        f'<svg width="{_AW:g}" height="{_AH:g}" viewBox="0 0 {_AW:g} {_AH:g}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" '
        'aria-label="Home SOC architecture: definition feeds, scanners, findings engine, outputs, '
        'SQLite and the embedded DNS resolver, all inside one Python process - plus Lens, a phone '
        'outside that process reading the same database over HTTPS with a scoped read-only token.">',
        "<defs>",
        _marker("ah-muted", MUTED),
        _marker("ah-accent", ACCENT),
        _marker("ah-critical", SEV_CRITICAL),
        _marker("ah-medium", SEV_MEDIUM),
        "</defs>",
        f'<rect width="{_AW:g}" height="{_AH:g}" fill="{BG}"/>',
    ]

    # ---- the process boundary (notched so the upstream resolvers stay outside it)
    boundary = (
        f"M {_BOUND_L:g},{_BOUND_T:g} H {_BOUND_R:g} V {_BOUND_SHOULDER_Y:g} "
        f"H {_BOUND_NOTCH_X:g} V {_BOUND_B:g} H {_BOUND_L:g} Z"
    )
    parts.append(f'<path d="{boundary}" fill="rgba(62,99,221,.045)" stroke="{ACCENT}" '
                 'stroke-width="1.6" stroke-dasharray="9 7" stroke-linejoin="round"/>')
    label = ("ONE PYTHON PROCESS   \u00b7   python -m homesoc run   \u00b7   one PC you already own   "
             "\u00b7   no cloud, no account, no telemetry")
    parts.append(f'<rect x="426" y="{_BOUND_T - 12:g}" width="912" height="24" fill="{BG}"/>')
    parts.append(_t(882, _BOUND_T + 5, label, maxx=1338, size=14, weight=650,
                    fill=ACCENT, anchor="middle", letter_spacing=0.8))

    # ---- scheduler strip
    parts.append(_box(_SCHED, fill=PANEL_2, rx=8))
    stx, smx = _SCHED.inner(18)
    parts.append(_t(stx, _SCHED.y + 27, "SCHEDULER", maxx=stx + 110, size=14, weight=650,
                    fill=FG, letter_spacing=1.4))
    parts.append(_t(stx + 112, _SCHED.y + 27,
                    "one worker thread, one job at a time   \u00b7   discovery 10 min   \u00b7   "
                    "services + vulns 24 h   \u00b7   host posture 6 h   \u00b7   exposure 12 h   "
                    "\u00b7   feeds 6 h   \u00b7   score 1 h",
                    maxx=smx, size=14.5, fill=MUTED))

    # ---- column captions
    for rect, caption in ((_COL_A, "DEFINITIONS"), (_COL_B, "SCANNERS"),
                          (_COL_C, "FINDINGS ENGINE"), (_COL_D, "WHAT YOU SEE")):
        parts.append(_t(rect.x, _CAPTION_Y, caption, maxx=rect.right, size=14, weight=650,
                        fill=MUTED, letter_spacing=1.7))

    # ---- the four columns
    parts.append(_feed_boxes())
    parts.append(_scanner_panel())
    parts.append(_engine_panel())
    parts.append(_output_panel())

    # ---- left-to-right flow arrows
    parts.append(_flow_arrow(_COL_A.right + 10, _COL_B.x - 6, 272, ("read from", "data/feeds/")))
    parts.append(_flow_arrow(_COL_B.right + 10, _COL_C.x - 6, 272, ("FindingDraft",)))
    parts.append(_flow_arrow(_COL_C.right + 10, _COL_D.x - 6, 272, ("one row", "per problem")))

    # ---- notes under the feed column
    # kept clear of the dashed blocklist line that leaves this column at x = 210
    parts.append(_t(_COL_A.x, _COL_A.bottom + 22, "15 feeds, ETag-cached.",
                    maxx=198, size=13, fill=MUTED))
    parts.append(_t(_COL_A.x, _COL_A.bottom + 40, "The only data it downloads.",
                    maxx=198, size=13, fill=MUTED))

    # ---- SQLite band and its connectors
    parts.append(_box(_DB, fill=PANEL_2))
    dtx, dmx = _DB.inner(18)
    parts.append(_t(dtx, _DB.y + 28, "SQLite  \u2014  data/homesoc.db", maxx=dtx + 330, size=18.5,
                    weight=650, mono=True))
    parts.append(_t(dtx, _DB.y + 50,
                    "one file \u00b7 WAL, one writer \u00b7 devices, services, vulns, findings, "
                    "host_checks, dns_queries, events, metrics",
                    maxx=dmx, size=13.5, fill=MUTED))
    for cx, text in ((456.0, "writes"), (842.0, "writes")):
        parts.append(_line(cx, _COL_B.bottom + 6, cx, _DB.y - 6, stroke=MUTED, width=1.8,
                           marker="ah-muted"))
        parts.append(_t(cx + 9, _DB.y - 14, text, maxx=cx + 70, size=12.5, fill=MUTED))
    parts.append(_line(1116, _DB.y - 6, 1116, _COL_D.bottom + 6, stroke=MUTED, width=1.8,
                       marker="ah-muted"))
    parts.append(_t(1125, _DB.y - 14, "reads", maxx=1180, size=12.5, fill=MUTED))

    # ---- the blocklists feed the resolver, and the resolver writes its query log back
    parts.append(_path(f"M 210,{_COL_A.bottom:g} V 550 H 420 V {_RESOLVER.y - 6:g}",
                       stroke=SEV_MEDIUM, width=1.8, marker="ah-medium", dash="6 5"))
    parts.append(_t(300, 542, "blocklists", maxx=418, size=12.5, fill=SEV_MEDIUM))
    parts.append(_line(683, _RESOLVER.y - 6, 683, _DB.bottom + 6, stroke=MUTED, width=1.8,
                       marker="ah-muted"))
    parts.append(_t(692, 552, "dns_queries", maxx=800, size=12.5, fill=MUTED, mono=True))

    parts.append(_lens_phone())
    parts.append(_dns_band())
    parts.append("</svg>")
    return "".join(parts)


def architecture() -> str:
    """The centrepiece: how the real system is put together."""
    css = f"""
.arch {{ display: flex; flex-direction: column; gap: 10px; }}
.arch .head h1 {{ font-size: 27px; }}
.arch .head p {{ font-size: 15.5px; margin-top: 5px; max-width: 1480px; }}
.arch-legend {{
  display: flex; gap: 28px; align-items: baseline; font-size: 13px; color: {MUTED};
  padding-top: 2px;
}}
.arch-legend b {{ color: {SEV_MEDIUM}; font-weight: 650; }}
svg {{ display: block; }}
"""
    body = f"""
<div class="slide slide--tight arch">
  <header class="head">
    <h1>Architecture &mdash; one process, one database, one PC</h1>
    <p>Definitions come in on the left, the scanners look, the engine remembers, and everything you read
      comes out on the right &mdash; in a browser, or on your phone through Lens. It complements Defender:
      <b>not an antivirus engine, not an EDR</b>.</p>
  </header>
  {_architecture_svg()}
  <div class="arch-legend">
    <span><b>{TRI} needs administrator</b> &mdash; Secure Boot, TPM and BitLocker report
      &ldquo;needs administrator&rdquo; rather than failing; so does the one inbound firewall rule that
      lets the LAN reach the resolver. Everything else runs as a normal user.</span>
    <span style="margin-left:auto; white-space:nowrap">dashed outline = one OS process</span>
  </div>
</div>
"""
    return _document("Architecture", body, css)


# --------------------------------------------------------------------------- 4. first run

# Taken from the real console output: run.bat's own `echo` lines, cli.cmd_init's emit() calls,
# cli._serve_forever's "Dashboard:" line, and the logging format set in cli.setup_logging
# ("%(asctime)s %(levelname)-7s %(name)s: %(message)s").
_TERMINAL: tuple[tuple[str, str], ...] = (
    ("prompt", "C:\\Users\\you\\Home_SOC&gt; <span class='cmd'>run.bat</span>"),
    ("blank", ""),
    ("tag", "[Home SOC] creating virtual environment ..."),
    ("tag", "[Home SOC] installing dependencies ..."),
    ("out", "config: C:\\Users\\you\\Home_SOC\\config.toml (created from example with a random "
            "web.token - edit it to taste)"),
    ("out", "database: C:\\Users\\you\\Home_SOC\\data\\homesoc.db (schema v{schema})"),
    ("out", "downloading first feeds (oui, kev) ..."),
    ("out", "&nbsp;&nbsp;kev: <span class='ok'>ok</span>"),
    ("out", "&nbsp;&nbsp;oui: <span class='ok'>ok</span>"),
    ("blank", ""),
    ("out", "Next: python -m homesoc run   (dashboard at "
            "<span class='url'>http://127.0.0.1:8787/login?token=Qh7dK2\u2026</span>)"),
    ("log", "{t0} <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "scheduler started with 15 jobs"),
    ("hero", "Dashboard: <span class='url'>http://127.0.0.1:8787/login?token=Qh7dK2\u2026</span>"
             "  (Ctrl-C to stop)"),
    ("log", "{t1} <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job feeds starting"),
    ("log", "{t2} <span class='lvl'>INFO</span>    homesoc.feeds.updater: "
            "feed kev updated: 1743210 bytes, 1412 entries, sha256=3b91f0c2ad4e"),
    ("log", "{t3} <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job discovery starting"),
    ("log", "{t4} <span class='lvl'>INFO</span>    homesoc.cli: "
            "[discovery] sweep 254/254"),
    ("log", "{t5} <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job services starting"),
    ("log", "{t6} <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job vulns starting"),
    ("log", "{t7} <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job host starting"),
)

_FIRST_RUN_STEPS: tuple[tuple[str, str], ...] = (
    ("Creates a virtual environment", "in <span class='m'>.venv</span> &mdash; a few seconds."),
    ("Installs three packages",
     "<span class='m'>flask</span>, <span class='m'>requests</span>, <span class='m'>dnslib</span> "
     "&mdash; skipped on later runs."),
    ("Runs <span class='m'>homesoc init</span>",
     "creates <span class='m'>data/</span>, a <span class='m'>config.toml</span> with a random web "
     "token, and the SQLite schema."),
    ("Downloads the first two feeds",
     "the OUI vendor database and the CISA KEV catalogue."),
    ("Runs <span class='m'>homesoc run</span>",
     "scheduler and dashboard start, and it prints the one link you need."),
)


def first_run() -> str:
    """A terminal window showing what ``run.bat`` actually prints on a first run."""
    css = f"""
.run {{ display: flex; flex-direction: column; }}
.run .head h1 {{ font-size: 30px; }}
.run-row {{
  display: grid; grid-template-columns: 1080px minmax(0,1fr); gap: 32px; margin-top: 22px;
  flex: 1 1 auto; min-height: 0;
}}
.term {{
  background: #0b0e14; border: 1px solid {LINE}; border-radius: 12px;
  box-shadow: 0 18px 46px rgba(0,0,0,.55); overflow: hidden;
}}
.term-bar {{
  display: flex; align-items: center; gap: 9px;
  background: {PANEL}; border-bottom: 1px solid {LINE}; padding: 12px 16px;
}}
.term-bar i {{ width: 11px; height: 11px; border-radius: 50%; display: block; }}
.term-bar .t {{
  margin-left: 12px; font-size: 13px; color: {MUTED};
  font-family: {MONO};
}}
.term-body {{
  padding: 18px 22px 24px; font-family: {MONO}; font-size: 15px; line-height: 1.75;
  color: {FG}; white-space: pre-wrap; word-break: break-word;
}}
.term-body div {{ min-height: 26px; }}
.term-body .prompt {{ color: {SEV_LOW}; }}
.term-body .cmd {{ color: {FG}; font-weight: 700; }}
.term-body .tag {{ color: {ACCENT}; }}
.term-body .out {{ color: {FG}; }}
.term-body .log {{ color: {MUTED}; font-size: 13.5px; line-height: 1.7; }}
.term-body .lvl {{ color: #7f8aa8; }}
.term-body .ok {{ color: {SEV_LOW}; font-weight: 700; }}
.term-body .url {{ color: {ACCENT}; }}
.term-body .hero {{
  color: {FG}; font-weight: 700;
  background: rgba(62,99,221,.14); border-left: 3px solid {ACCENT};
  margin: 4px -22px; padding: 3px 22px 3px 19px;
}}
.term-body .caret {{
  display: inline-block; width: 9px; height: 17px; background: {FG};
  vertical-align: -3px; opacity: .85;
}}
.side {{ display: flex; flex-direction: column; gap: 14px; }}
.side .card {{ padding: 16px 18px; }}
.steps {{ list-style: none; counter-reset: s; padding: 0; }}
.steps li {{
  counter-increment: s; display: grid; grid-template-columns: 26px minmax(0,1fr);
  gap: 12px; padding: 9px 0;
}}
.steps li + li {{ border-top: 1px solid {LINE}; }}
.steps li::before {{
  content: counter(s); display: grid; place-items: center;
  width: 24px; height: 24px; border-radius: 50%;
  background: {PANEL_2}; border: 1px solid {LINE};
  font-size: 12.5px; font-weight: 700; color: {MUTED}; margin-top: 1px;
}}
.steps h3 {{ font-size: 15.5px; font-weight: 650; }}
.steps p {{ font-size: 13.5px; color: {MUTED}; margin-top: 3px; line-height: 1.5; }}
.m {{ font-family: {MONO}; font-size: .93em; color: {FG}; }}
.note {{ font-size: 15px; line-height: 1.55; }}
.note b {{ color: {FG}; }}
.side-chips {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.side-chips .chip {{ font-size: 13px; padding: 5px 12px; }}
"""
    # The terminal used to carry a literal `schema v1` and eight literal 2026-09-07
    # timestamps — the day of the v1 recording. The product is on schema 3 (Lens's tables
    # arrived by migration, so a fresh install cannot print v1), and CONTRACT.md §1 says
    # seeded times are relative to now so the film never looks stale. Both are filled in at
    # render time; the offsets below keep the original relative spacing, which is what makes
    # the run read as "about a minute, then a couple of minutes of first scans".
    schema = _schema_version()
    started = _dt.datetime.now().replace(microsecond=0) - _dt.timedelta(minutes=9, seconds=14)
    offsets = (0, 1, 9, 10, 31, 34, 162, 169)
    stamps = {
        f"t{i}": (started + _dt.timedelta(seconds=off)).strftime("%Y-%m-%d %H:%M:%S")
        for i, off in enumerate(offsets)
    }

    lines: list[str] = []
    for kind, html in _TERMINAL:
        if kind == "blank":
            lines.append("<div>&nbsp;</div>")
        else:
            lines.append(f'<div class="{kind}">{html.format(schema=schema, **stamps)}</div>')
    lines.append('<div class="prompt">C:\\Users\\you\\Home_SOC&gt; <span class="caret"></span></div>')

    steps = "".join(f"<li><div><h3>{h}</h3><p>{d}</p></div></li>" for h, d in _FIRST_RUN_STEPS)
    body = f"""
<div class="slide run">
  {_head("Getting it running", "Double-click run.bat",
         "That is the whole install. No administrator rights, no account, and nothing written outside "
         "this folder.")}
  <div class="run-row">
    <div class="term">
      <div class="term-bar">
        <i style="background:{SEV_CRITICAL}"></i><i style="background:{SEV_MEDIUM}"></i>
        <i style="background:{SEV_LOW}"></i>
        <span class="t">Home_SOC &mdash; run.bat</span>
      </div>
      <div class="term-body">{''.join(lines)}</div>
    </div>
    <aside class="side">
      <div class="card">
        <h2>What the first run does</h2>
        <ol class="steps">{steps}</ol>
      </div>
      <div class="card">
        <h2>Then give it five minutes</h2>
        <p class="note muted">About <b>a minute</b> before the link appears; the scans run in the
          background after that. The first full picture of {_device_count()}-device network lands
          inside <b>five minutes</b>.</p>
      </div>
      <div class="side-chips">
        <span class="chip">no admin</span>
        <span class="chip">no account</span>
        <span class="chip">nothing installed outside this folder</span>
      </div>
    </aside>
  </div>
</div>
"""
    return _document("First run", body, css)


# --------------------------------------------------------------------------- 5. daily use

_JOBS: tuple[tuple[str, str], ...] = (
    ("discovery", "every 10 min"),
    ("score \u00b7 dns_rollup", "every hour"),
    ("feeds", "every 6 h"),
    ("host", "every 6 h"),
    ("exposure", "every 12 h"),
    ("services", "every 24 h"),
    ("vulns", "every 24 h"),
    ("files", "every 24 h"),
    ("housekeeping", "every 24 h"),
    ("digest", "daily at 08:00"),
    ("quick \u00b7 full \u00b7 device_scan", "on demand"),
)

_CHANNELS: tuple[tuple[str, str, str], ...] = (
    ("ntfy", "notify.ntfy_url",
     "a push to your phone, no account needed \u2014 but pick a long, unguessable topic, because the "
     "topic name is the password"),
    ("Discord", "notify.discord_webhook",
     "a coloured embed in your own server: Server Settings \u2192 Integrations \u2192 Webhooks, then "
     "paste the URL in"),
    ("Generic webhook", "notify.webhook_url",
     "a JSON POST carrying subject, body, severity and the findings \u2014 enough to drive Home "
     "Assistant, n8n or a script of your own"),
    ("Windows toast", "notify.windows_toast",
     "on by default on Windows and needs no extra software; ignored everywhere else"),
    ("Daily digest", "notify.digest_hour",
     "one summary a day at 08:00 local through the same channels; set it to <em>-1</em> to switch "
     "the digest off"),
)

_COMMANDS: tuple[tuple[str, str], ...] = (
    ("python -m homesoc status", "score, findings, devices, last scans, feeds and jobs"),
    ("python -m homesoc findings --severity high", "the short list that actually matters"),
    ("python -m homesoc report --days 30", "the remediation summary as Markdown"),
    ("python -m homesoc scan --quick", "discovery, a quick service scan and vulns, right now"),
    ("python -m homesoc baseline", "accept the devices you already own, once"),
    ("python -m homesoc dns-test &lt;domain&gt;", "allow or block, and which list decided"),
)


def daily_use() -> str:
    """The cadence, the notification channels and the handful of commands worth knowing."""
    css = f"""
.three {{ display: grid; grid-template-columns: 1fr 1.12fr 1.18fr; gap: 24px; margin-top: 26px; flex: 1 1 auto; }}
.three .card {{ display: flex; flex-direction: column; }}
.jobs {{ list-style: none; padding: 0; }}
.jobs li {{
  display: flex; align-items: baseline; justify-content: space-between; gap: 12px;
  padding: 11px 0;
}}
.jobs li + li {{ border-top: 1px solid {LINE}; }}
.jobs .n {{ font-family: {MONO}; font-size: 15px; }}
.jobs .v {{ color: {MUTED}; font-size: 14.5px; white-space: nowrap; }}
.chan {{ list-style: none; padding: 0; }}
.chan li {{ padding: 15px 0; }}
.chan li + li {{ border-top: 1px solid {LINE}; }}
.chan .row {{ display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }}
.chan h3 {{ font-size: 17px; font-weight: 650; }}
.chan code {{ font-family: {MONO}; font-size: 12.5px; color: {MUTED}; }}
.chan p {{ font-size: 14.5px; color: {MUTED}; margin-top: 4px; line-height: 1.45; }}
.chan em {{ font-style: normal; font-family: {MONO}; font-size: .93em; color: {FG}; }}
.cmds {{ list-style: none; padding: 0; }}
.cmds li {{ padding: 11px 0; }}
.cmds li + li {{ border-top: 1px solid {LINE}; }}
.cmds code {{
  display: block; font-family: {MONO}; font-size: 15px; color: {FG};
  background: {PANEL_2}; border: 1px solid {LINE}; border-radius: 7px;
  padding: 8px 11px;
}}
.cmds p {{ font-size: 13.5px; color: {MUTED}; margin-top: 6px; }}
.card .kicker {{
  margin-top: auto; padding-top: 14px; border-top: 1px solid {LINE};
  font-size: 14px; color: {MUTED}; line-height: 1.5;
}}
.card .kicker b {{ color: {FG}; }}
"""
    jobs = "".join(f'<li><span class="n">{n}</span><span class="v">{v}</span></li>' for n, v in _JOBS)
    chans = "".join(
        f'<li><div class="row"><h3>{name}</h3><code>{key}</code></div><p>{desc}</p></li>'
        for name, key, desc in _CHANNELS
    )
    cmds = "".join(f"<li><code>{c}</code><p>{d}</p></li>" for c, d in _COMMANDS)
    body = f"""
<div class="slide">
  {_head("Day to day", "You mostly leave it alone",
         "It runs on a timer, batches what it finds into one message per scan, and keeps a worklist for "
         "the evening you feel like fixing things.")}
  <div class="three">
    <section class="card">
      <h2>The timetable</h2>
      <ul class="jobs">{jobs}</ul>
      <p class="kicker">One worker thread, <b>one job at a time</b> &mdash; a discovery sweep and a
        blocklist download hitting the Wi-Fi together is exactly what makes a cheap smart plug fall over.</p>
    </section>
    <section class="card">
      <h2>How you hear about it</h2>
      <ul class="chan">{chans}</ul>
      <p class="kicker">New findings are batched into <b>one message per scan</b>, never fifty toasts at
        once. <span class="mono" style="font-size:13px">notify.min_severity</span> is <b>high</b> by
        default; webhook URLs are treated as secrets and never echoed back.</p>
    </section>
    <section class="card">
      <h2>From the terminal</h2>
      <ul class="cmds">{cmds}</ul>
      <p class="kicker">Everything the dashboard does is also a command, so the monthly five minutes can
        be a scheduled task, an SSH session or a shortcut &mdash; whatever you already use.</p>
    </section>
  </div>
</div>
"""
    return _document("Day to day", body, css)


# --------------------------------------------------------------------------- 6. Lens: the gap


def _shelf_svg() -> str:
    """The hallway shelf: four identical white boxes, none of them wearing its IP address."""
    w, h = 1080.0, 396.0
    boxes = [96.0, 344.0, 592.0, 840.0]
    bw, bh = 144.0, 132.0
    shelf_y = 300.0
    out: list[str] = [
        f'<svg width="{w:g}" height="{h:g}" viewBox="0 0 {w:g} {h:g}" '
        'xmlns="http://www.w3.org/2000/svg" role="img" '
        'aria-label="A shelf with four identical white boxes on it, each labelled with a '
        'question mark: from the hallway, nothing tells you which one is 192.168.1.142.">',
        f'<rect width="{w:g}" height="{h:g}" rx="12" fill="#12151d"/>',
        f'<rect x="0" y="{shelf_y + 46:g}" width="{w:g}" height="{h - shelf_y - 46:g}" '
        f'fill="#0e111a"/>',
        # the shelf itself
        f'<rect x="28" y="{shelf_y:g}" width="{w - 56:g}" height="18" rx="3" fill="#3b3226"/>',
        f'<rect x="28" y="{shelf_y:g}" width="{w - 56:g}" height="5" rx="2.5" fill="#5c4d3a"/>',
        f'<rect x="28" y="{shelf_y + 18:g}" width="{w - 56:g}" height="8" fill="#241f18"/>',
    ]
    for i, x in enumerate(boxes):
        top = shelf_y - bh
        out.append(
            f'<rect x="{x:g}" y="{top:g}" width="{bw:g}" height="{bh:g}" rx="14" '
            f'fill="#e9ebf1" stroke="#c6cad6" stroke-width="2"/>'
        )
        # the one feature every one of them has: a dark disc that could be a lens, or a vent
        out.append(
            f'<circle cx="{x + bw / 2:g}" cy="{top + 52:g}" r="27" fill="#1b1e27" '
            'stroke="#aeb3c2" stroke-width="2"/>'
        )
        out.append(f'<circle cx="{x + bw / 2 - 8:g}" cy="{top + 44:g}" r="7" fill="#39415c"/>')
        out.append(f'<circle cx="{x + bw - 24:g}" cy="{top + 22:g}" r="5" fill="{SEV_LOW}"/>')
        out.append(
            f'<rect x="{x + 30:g}" y="{top + 96:g}" width="{bw - 60:g}" height="8" rx="4" '
            'fill="#d3d7e2"/>'
        )
        # a cable, because these things are plugged into something
        out.append(
            f'<path d="M {x + bw / 2:g},{shelf_y:g} C {x + bw / 2:g},{shelf_y + 34:g} '
            f'{x + bw / 2 + (26 if i % 2 else -26):g},{shelf_y + 40:g} '
            f'{x + bw / 2 + (44 if i % 2 else -44):g},{shelf_y + 62:g}" '
            'fill="none" stroke="#2a2f3d" stroke-width="5" stroke-linecap="round"/>'
        )
        # the question mark each of them is wearing instead of an address
        cy = top - 52.0
        out.append(
            f'<rect x="{x + bw / 2 - 30:g}" y="{cy - 26:g}" width="60" height="52" rx="12" '
            f'fill="{PANEL}" stroke="{ACCENT}" stroke-width="1.6"/>'
        )
        out.append(
            f'<text x="{x + bw / 2:g}" y="{cy + 11:g}" text-anchor="middle" '
            f'font-family=\'{SANS}\' font-size="30" font-weight="700" fill="{ACCENT}">?</text>'
        )
        out.append(
            f'<line x1="{x + bw / 2:g}" y1="{cy + 30:g}" x2="{x + bw / 2:g}" y2="{top - 10:g}" '
            f'stroke="{ACCENT}" stroke-width="1.6" stroke-dasharray="5 5" opacity=".75"/>'
        )
    out.append("</svg>")
    return "".join(out)


def _camera_row(ip: str = "192.168.1.142") -> dict[str, str]:
    """The demo camera's row as the dashboard renders it, read from the demo database.

    This slide used to carry the literals "first seen 12 days ago" and three port chips.
    Both were contradicted by the real pages minutes later in the same film — /devices
    says the camera arrived three days ago, and the Lens card says "Exposed 4". The seed
    is relative to *now*, so a literal age is wrong the day after it is typed.
    """
    rows = _demo_query(
        "SELECT ip, first_seen FROM devices WHERE ip = ? LIMIT 1", (ip,)
    )
    if not rows:
        raise LookupError(f"{DEMO_DB} has no device at {ip}; re-run video/seed_demo.py")
    first_seen = str(rows[0]["first_seen"] or "")
    try:
        seen = _dt.datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        days = max(0, (_dt.datetime.now(_dt.timezone.utc) - seen).days)
    except ValueError:
        days = 0
    age = "today" if days == 0 else ("1 day ago" if days == 1 else f"{days} days ago")

    ports = _demo_query(
        "SELECT port, name FROM services s JOIN devices d ON d.id = s.device_id "
        "WHERE d.ip = ? AND s.state = 'open' ORDER BY s.port",
        (ip,),
    )
    chips = "".join(
        f'<span class="port">{int(r["port"])} {str(r["name"] or "?")}</span>' for r in ports
    )
    return {"ip": str(rows[0]["ip"]), "age": age, "ports": chips}


def lens_why() -> str:
    """Scene 14: the gap between a row in a table and an object on a shelf."""
    camera = _camera_row()
    css = f"""
.why {{ display: flex; flex-direction: column; }}
.why .head h1 {{ font-size: 31px; }}
.why-row {{
  display: grid; grid-template-columns: 430px minmax(0,1fr); gap: 28px;
  margin-top: 24px; flex: 1 1 auto; min-height: 0; align-items: stretch;
}}
.why-row .card {{ display: flex; flex-direction: column; }}
.row-mock {{
  background: {PANEL_2}; border: 1px solid {LINE}; border-radius: 10px; padding: 16px 18px;
}}
.row-mock .ip {{ font-family: {MONO}; font-size: 27px; color: {FG}; }}
.row-mock .who {{ font-size: 14px; color: {MUTED}; margin-top: 4px; }}
.row-mock .ports {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }}
.row-mock .port {{
  font-family: {MONO}; font-size: 12.5px; color: {FG};
  background: {PANEL}; border: 1px solid {LINE}; border-radius: 6px; padding: 5px 9px;
}}
.row-mock .sev {{
  display: inline-block; margin-top: 14px; font-size: 12.5px; font-weight: 650;
  letter-spacing: .06em; text-transform: uppercase; color: #1a1d27;
  background: {SEV_CRITICAL}; border-radius: 999px; padding: 4px 12px;
}}
.why p.lede {{ font-size: 16px; color: {MUTED}; line-height: 1.55; margin-top: 16px; }}
.why p.lede b {{ color: {FG}; }}
.why-art {{ display: flex; flex-direction: column; }}
.why-art svg {{ display: block; width: 100%; height: auto; }}
.why-art .cap {{ font-size: 15px; color: {MUTED}; margin-top: 14px; line-height: 1.5; }}
.why-art .cap b {{ color: {FG}; }}
.why .kicker {{
  margin-top: auto; padding-top: 14px; border-top: 1px solid {LINE};
  font-size: 14.5px; color: {MUTED}; line-height: 1.5;
}}
.why-foot {{
  margin-top: 20px; display: flex; align-items: center; gap: 16px;
  border: 1px solid {LINE}; border-left: 3px solid {ACCENT}; border-radius: 12px;
  background: {PANEL}; padding: 14px 20px; font-size: 16px; color: {MUTED};
}}
.why-foot b {{ color: {FG}; font-weight: 650; }}
"""
    body = f"""
<div class="slide why">
  {_head("The gap", "A row in a table is not an object on a shelf",
         "Everything up to here has been a screen telling you about a network. This is where "
         "that stops being enough.")}
  <div class="why-row">
    <section class="card">
      <h2>What the dashboard says</h2>
      <div class="row-mock">
        <div class="ip">{camera['ip']}</div>
        <div class="who">unknown vendor &middot; first seen {camera['age']} &middot; not trusted</div>
        <div class="ports">
          {camera['ports']}
        </div>
        <div><span class="sev">critical</span></div>
      </div>
      <p class="lede">All of it true. All of it <b>useless</b> while you are standing in the
        hallway, because the thing you have to go and unplug does not know its own IP address
        and would not tell you if it did.</p>
      <p class="kicker">You can pull plugs one at a time and watch the dashboard for a device
        going offline. That works. It takes an evening.</p>
    </section>
    <section class="card why-art">
      <h2>What the hallway says</h2>
      {_shelf_svg()}
      <p class="cap"><b>Two of these are cameras, one is a smart plug you forgot you owned,
        and one is a doorbell.</b> None of them has an address written on the side.</p>
    </section>
  </div>
  <div class="why-foot">
    <span>That gap &mdash; between a row in a table and an object on a shelf &mdash;
      <b>is what Lens closes.</b></span>
  </div>
</div>
"""
    return _document("Lens · the gap", body, css)


# --------------------------------------------------------------------------- 7. Lens: how it identifies

#: The token on the demo camera's sticker. Opaque on purpose: 22 url-safe characters after
#: an ``hs1:`` prefix, exactly what ``lens.mint_sticker_codes`` produces, and deliberately
#: not the token in ``video/demo_data`` - this is a slide, not a credential.
_DEMO_STICKER = "hs1:9Fq2xNt7Lm0aVb3Rd6Ks1p"


def _qr_svg(payload: str, *, scale: int = 4, quiet_zone: int = 2) -> str:
    """A real QR code for ``payload``, rendered by the product's own encoder.

    ``homesoc/web/qr.py`` is the module that prints the stickers, so the code on this
    slide is the same code the product would generate rather than a drawing of one. If
    the package cannot be imported (slides are sometimes rendered on their own), fall
    back to a plainly decorative grid rather than failing the whole render.
    """
    try:
        import sys
        from pathlib import Path as _Path

        root = str(_Path(__file__).resolve().parent.parent)
        if root not in sys.path:
            sys.path.insert(0, root)
        from homesoc.web.qr import to_svg  # type: ignore[import-not-found]

        return to_svg(payload, scale=scale, quiet_zone=quiet_zone)
    except Exception as exc:  # noqa: BLE001 - a slide must still render
        logger.warning("homesoc.web.qr unavailable (%s); drawing a placeholder QR", exc)
        side = 29 * scale
        cells: list[str] = []
        state = 0x2F6E2B93
        for row in range(29):
            for col in range(29):
                state = (state * 1103515245 + 12345) & 0x7FFFFFFF
                corner = (row < 8 and col < 8) or (row < 8 and col > 20) or (row > 20 and col < 8)
                if corner or not (state >> 17) & 1:
                    continue
                cells.append(f'<rect x="{col * scale}" y="{row * scale}" width="{scale}" '
                             f'height="{scale}" fill="#1a1d27"/>')
        for ox, oy in ((0, 0), (22, 0), (0, 22)):
            cells.append(
                f'<rect x="{ox * scale}" y="{oy * scale}" width="{7 * scale}" height="{7 * scale}" '
                f'fill="#1a1d27"/><rect x="{(ox + 1) * scale}" y="{(oy + 1) * scale}" '
                f'width="{5 * scale}" height="{5 * scale}" fill="#fff"/>'
                f'<rect x="{(ox + 2) * scale}" y="{(oy + 2) * scale}" width="{3 * scale}" '
                f'height="{3 * scale}" fill="#1a1d27"/>'
            )
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{side}" height="{side}" '
                f'viewBox="0 0 {side} {side}" role="img" aria-label="QR code">'
                f'<rect width="{side}" height="{side}" fill="#fff"/>{"".join(cells)}</svg>')


def _barcode_svg(width: float = 236.0, height: float = 56.0) -> str:
    """A factory label's barcode - the kind already printed on the back of a router."""
    widths = (3, 1, 2, 1, 1, 3, 2, 1, 1, 2, 3, 1, 2, 2, 1, 1, 3, 1, 2, 1, 1, 2, 2, 3, 1, 2, 1, 3)
    unit = width / (sum(widths) + 2)
    bars: list[str] = []
    x = unit
    for i, w in enumerate(widths):
        if i % 2 == 0:
            bars.append(f'<rect x="{x:.2f}" y="0" width="{w * unit:.2f}" height="{height:g}" '
                        f'fill="{STICKER_INK}"/>')
        x += w * unit
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:g}" height="{height:g}" '
            f'viewBox="0 0 {width:g} {height:g}" role="img" aria-label="barcode">'
            f'{"".join(bars)}</svg>')


_LEARN_STEPS: tuple[tuple[str, str], ...] = (
    ("Lens decodes a code it has never seen",
     "any format the phone can read &mdash; Code&nbsp;128, EAN, Data Matrix, QR."),
    ("It asks which device this is",
     "the list is ranked: online first, then anything with open findings."),
    ("You tap once",
     "the code and the device are bound, and the tag is saved."),
    ("Every later scan is instant",
     "the same sticker, the same barcode, the same box &mdash; resolved immediately."),
)

_NEVER: tuple[tuple[str, str], ...] = (
    ("00:1A:2B:3C:4D:5E", "its MAC address"),
    ("192.168.1.142", "its address on your network"),
    ("hallway-cam.local", "its hostname"),
    ("Hallway camera", "the name you gave it"),
)


def lens_how() -> str:
    """Scene 15: how Lens knows which physical object you are pointing at."""
    css = f"""
.how {{ display: flex; flex-direction: column; }}
.how .head h1 {{ font-size: 31px; }}
.how-three {{
  display: grid; grid-template-columns: 1.06fr 1fr 1.16fr; gap: 22px;
  margin-top: 24px; flex: 1 1 auto; min-height: 0;
}}
.how-three .card {{ display: flex; flex-direction: column; }}
.art {{
  display: flex; align-items: center; justify-content: center; gap: 18px;
  background: {PANEL_2}; border: 1px solid {LINE}; border-radius: 10px;
  padding: 13px 18px; margin-bottom: 13px;
}}
.art svg {{ display: block; }}
.art .label {{ font-family: {MONO}; font-size: 12.5px; color: {MUTED}; }}
.art--label {{
  flex-direction: column; gap: 9px; padding: 20px 18px 16px;
  background: {STICKER}; border-color: {STICKER_LINE};
}}
.art--label .label {{ color: #4a4f5e; letter-spacing: .06em; }}
.art--label .model {{
  font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: #6b7182;
}}
.art-cap {{ font-size: 13px; color: {MUTED}; margin: -4px 0 12px; }}
.sheet {{
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 7px;
  background: {PANEL_2}; border: 1px solid {LINE}; border-radius: 10px; padding: 10px;
  margin-top: 12px;
}}
.sheet i {{
  display: flex; align-items: center; gap: 7px; background: {STICKER}; border-radius: 5px;
  padding: 7px 8px; font-style: normal; font-size: 9.5px; color: #4a4f5e;
}}
.sheet i b {{ display: block; width: 22px; height: 22px; border-radius: 2px; background: {STICKER_INK}; }}
.resolve {{
  display: flex; align-items: center; gap: 10px; margin-top: 13px;
  background: {PANEL_2}; border: 1px solid {LINE}; border-radius: 10px; padding: 13px 14px;
  font-size: 13px; color: {MUTED};
}}
.resolve .m {{ font-family: {MONO}; font-size: 12.5px; color: {FG}; }}
.resolve .step {{ min-width: 0; }}
.resolve .sep {{ color: {ACCENT}; }}
.sticker {{
  background: {STICKER}; border: 1px solid {STICKER_LINE}; border-radius: 10px;
  padding: 12px 12px 10px; display: flex; flex-direction: column; align-items: center; gap: 6px;
}}
.sticker .nick {{ font-size: 13.5px; font-weight: 650; color: {STICKER_INK}; }}
.sticker .mark {{ font-size: 10.5px; color: #6b7182; letter-spacing: .1em; text-transform: uppercase; }}
.sticker-note {{ font-size: 13.5px; color: {MUTED}; line-height: 1.5; }}
.steps {{ list-style: none; padding: 0; }}
.steps li {{ display: grid; grid-template-columns: 26px minmax(0,1fr); gap: 12px; padding: 10px 0; }}
.steps li + li {{ border-top: 1px solid {LINE}; }}
.steps .n {{
  width: 24px; height: 24px; border-radius: 50%; margin-top: 1px;
  background: rgba(62,99,221,.18); color: #9db0ff;
  font-size: 12.5px; font-weight: 650; display: grid; place-items: center;
}}
.steps h3 {{ font-size: 15.5px; font-weight: 650; }}
.steps p {{ font-size: 13.5px; color: {MUTED}; margin-top: 3px; line-height: 1.45; }}
.tok {{ display: flex; flex-direction: column; gap: 6px; min-width: 0; }}
.tok .cap {{ font-size: 12px; letter-spacing: .1em; text-transform: uppercase; color: {MUTED}; }}
.tok code {{
  font-family: {MONO}; font-size: 14px; color: {FG};
  background: {PANEL}; border: 1px solid {LINE}; border-radius: 7px; padding: 8px 10px;
}}
.art .to {{ color: {ACCENT}; font-size: 22px; }}
.never {{ list-style: none; padding: 0; }}
.never li {{
  display: flex; align-items: baseline; gap: 12px; padding: 8px 0; font-size: 14px;
}}
.never li + li {{ border-top: 1px solid {LINE}; }}
.never s {{
  font-family: {MONO}; font-size: 13.5px; color: {SEV_CRITICAL}; opacity: .85;
  text-decoration-thickness: 1.5px;
}}
.never span {{ color: {MUTED}; margin-left: auto; }}
.how-foot {{
  margin-top: 16px; display: flex; align-items: center; gap: 16px;
  border: 1px solid {LINE}; border-left: 3px solid {ACCENT}; border-radius: 12px;
  background: {PANEL}; padding: 12px 20px; font-size: 15px; color: {MUTED};
}}
.how-foot b {{ color: {FG}; font-weight: 650; }}
.how-foot .m {{ font-family: {MONO}; font-size: 13.5px; color: {FG}; }}
.how .steps li {{ padding: 10px 0; }}
.how .never li {{ padding: 9px 0; }}
.how .kicker {{
  margin-top: auto; padding-top: 14px; border-top: 1px solid {LINE};
  font-size: 14px; color: {MUTED}; line-height: 1.5;
}}
.how .kicker b {{ color: {FG}; }}
.how .kicker .m {{ font-family: {MONO}; font-size: 13px; color: {FG}; }}
"""
    steps = "".join(
        f'<li><span class="n">{i}</span><div><h3>{h}</h3><p>{d}</p></div></li>'
        for i, (h, d) in enumerate(_LEARN_STEPS, start=1)
    )
    never = "".join(
        f"<li><s>{code}</s><span>{what}</span></li>" for code, what in _NEVER
    )
    body = f"""
<div class="slide how">
  {_head("Lens", "How it knows which box you are pointing at",
         "One mechanism &mdash; a visual tag &mdash; from two sources, plus a manual pick that always "
         "works. No OCR, no fingerprinting, no guessing from the camera image.")}
  <div class="how-three">
    <section class="card">
      <h2>1 &nbsp;The label it already has</h2>
      <div class="art art--label">
        <span class="model">Model RT-58U &nbsp;·&nbsp; 12V 2A</span>
        {_barcode_svg()}
        <span class="label">SN 4C8A-2219-KQ</span>
      </div>
      <p class="art-cap">The sticker the manufacturer already put on the box.</p>
      <ul class="steps">{steps}</ul>
      <p class="kicker">Most devices need no sticker at all: the barcode already printed on the back
        of the router <b>becomes</b> its identifier the first time you scan it.</p>
    </section>
    <section class="card">
      <h2>2 &nbsp;A sticker for the rest</h2>
      <div class="art">
        <div class="sticker">
          {_qr_svg(_DEMO_STICKER, scale=5)}
          <span class="nick">Hallway camera</span>
          <span class="mark">{BRAND_MARK} Home SOC</span>
        </div>
      </div>
      <p class="sticker-note">Smart plugs, cameras, anything already screwed to a wall: no readable
        label, and no way to reach one. <span class="mono" style="font-size:13px">/lens/stickers</span>
        prints a sheet from the inventory &mdash; Avery&nbsp;5160 labels or 40&nbsp;mm squares, with
        the nickname under each code.</p>
      <div class="sheet">
        {''.join(f'<i><b></b>{n}</i>' for n in
                 ("Hallway camera", "Front doorbell", "Kitchen plug",
                  "Utility plug", "Epson printer", "Garage TV"))}
      </div>
      <p class="kicker">Minting is <b>idempotent</b>: reprinting the sheet never invalidates a sticker
        that is already on a device.</p>
    </section>
    <section class="card">
      <h2>3 &nbsp;What a photograph of it gives away</h2>
      <div class="art">
        {_qr_svg(_DEMO_STICKER, scale=3)}
        <span class="to">&rarr;</span>
        <div class="tok">
          <span class="cap">everything it encodes</span>
          <code>{_DEMO_STICKER}</code>
        </div>
      </div>
      <ul class="never">{never}</ul>
      <div class="resolve">
        <span class="step"><span class="m">{_DEMO_STICKER[:12]}&hellip;</span></span>
        <span class="sep">&rarr;</span>
        <span class="step"><span class="m">lens_tags</span><br>in your own database</span>
        <span class="sep">&rarr;</span>
        <span class="step"><span class="m">Hallway camera</span><br>192.168.1.142</span>
      </div>
      <p class="kicker">An opaque random token, and nothing else. A visitor who photographs a sticker
        &mdash; or a stranger who finds the printed sheet &mdash; learns <b>nothing</b> about your
        network: the token resolves only against <span class="m">data/homesoc.db</span> on your PC.</p>
    </section>
  </div>
  <div class="how-foot">
    <span><b>And there is always the third path.</b> A persistent <span class="m">Pick manually</span>
      button lists every device, ranked the same way &mdash; online first, then whatever has open
      findings &mdash; so Lens still works with the camera closed, in a browser that cannot scan, and
      on a device that carries no code at all.</span>
  </div>
</div>
"""
    return _document("Lens · identification", body, css)


# --------------------------------------------------------------------------- 7. Lens: honest limits

_LIMITS: tuple[tuple[str, str, str], ...] = (
    ("The browser", "Chrome on Android is the target",
     "Automatic scanning uses <span class='m'>BarcodeDetector</span>, a platform API Chrome ships on "
     "Android. Where it is missing &mdash; desktop browsers, iOS &mdash; Lens hides the reticle, says "
     "so on screen, and the manual picker becomes the main path. It never leaves you staring at a "
     "camera that silently does nothing."),
    ("The certificate", "A self-signed certificate is a real trust decision",
     "Browsers hand out the camera only in a secure context, and a home LAN has no certificate "
     "authority. So Home SOC generates its own: your phone warns you once and you accept it "
     "knowingly &mdash; or you run Home SOC behind Tailscale Serve and get a genuinely trusted one, "
     "which <span class='m'>docs/LENS_SETUP.md</span> walks through."),
    ("The first scan", "One tap per device, once",
     "A code Lens has never seen costs a single tap to bind to a device. That is the whole price of "
     "identification, and it is paid once per code &mdash; every later scan of it resolves "
     "immediately."),
    ("The illusion", "It is not augmented reality",
     "No world-anchored 3D labels floating on the device. It is a camera viewfinder with an "
     "information panel over it, which is what stays readable at arm&rsquo;s length in a dim "
     "cupboard."),
    ("The camera", "It cannot read a model number off a label",
     "There is no OCR: vendoring an engine for it would break the rule that this project ships no "
     "external assets. A device with no barcode and no sticker is picked from the list &mdash; "
     "ranked, so it is usually the first row."),
    ("The scope", "Read-only until you decide otherwise",
     "A paired phone gets the <span class='m'>read</span> scope. Rescanning, acknowledging and "
     "trusting need <span class='m'>act</span>, which is off by default. Any phone can be revoked on "
     "its own, without changing the dashboard password."),
)


def lens_limits() -> str:
    """The honest-limits card that closes the Lens act."""
    css = f"""
.lim {{ display: flex; flex-direction: column; }}
.lim .head h1 {{ font-size: 31px; }}
.lim-grid {{
  display: grid; grid-template-columns: repeat(2, 1fr); grid-auto-rows: 1fr;
  gap: 18px 22px; margin-top: 24px; flex: 1 1 auto; min-height: 0;
}}
.lim-grid .card {{
  display: grid; grid-template-columns: 132px minmax(0,1fr); align-items: center;
  column-gap: 20px; padding: 20px 24px;
}}
.lim-grid .eyebrow {{ font-size: 12px; color: {SEV_MEDIUM}; line-height: 1.5; }}
.lim-grid h3 {{ font-size: 20px; font-weight: 650; letter-spacing: -.012em; }}
.lim-grid p {{ font-size: 15px; color: {MUTED}; margin-top: 8px; line-height: 1.55; }}
.lim-grid .m {{ font-family: {MONO}; font-size: .92em; color: {FG}; }}
.lim-foot {{
  margin-top: 22px; display: flex; align-items: center; gap: 18px;
  border: 1px solid {LINE}; border-left: 3px solid {SEV_MEDIUM}; border-radius: 12px;
  background: {PANEL}; padding: 15px 20px; font-size: 15.5px; color: {MUTED};
}}
.lim-foot b {{ color: {FG}; font-weight: 650; }}
.lim-foot .m {{ font-family: {MONO}; font-size: 13.5px; color: {FG}; }}
"""
    cards = "".join(
        f'<section class="card"><div class="eyebrow">{eyebrow}</div>'
        f"<div><h3>{heading}</h3><p>{detail}</p></div></section>"
        for eyebrow, heading, detail in _LIMITS
    )
    body = f"""
<div class="slide lim">
  {_head("Lens", "What Lens does not do",
         "It widens Home SOC from one loopback address to your LAN, so it is worth being exact about "
         "where the edges are.")}
  <div class="lim-grid">{cards}</div>
  <div class="lim-foot">
    <span><b>Lens is off by default.</b> Turning it on is a deliberate decision: choose a bind
      address, generate a certificate, open one firewall port. Do it over plain HTTP from a LAN
      address and Home SOC raises a finding against itself &mdash;
      <span class="m">SOC-LENS-001</span>.</span>
  </div>
</div>
"""
    return _document("Lens · honest limits", body, css)


# --------------------------------------------------------------------------- 8. close


def close() -> str:
    """Closing card: where it runs, the docs, the licence and the safety line."""
    css = f"""
.close-slide {{ padding: 64px 92px 54px; }}
.close-glow {{
  position: absolute; inset: 0; pointer-events: none;
  background: radial-gradient(1000px 640px at 82% 8%, rgba(62,99,221,.16), transparent 66%);
}}
.close-body {{ position: relative; display: flex; flex-direction: column; height: 100%; }}
.close-brand {{ display: flex; align-items: center; gap: 16px; }}
.close-brand .m {{ font-size: 40px; color: {ACCENT}; line-height: 1; }}
.close-brand .n {{ font-size: 54px; font-weight: 750; letter-spacing: -.03em; }}
.close-line {{ font-size: 25px; font-weight: 500; margin-top: 20px; max-width: 1020px; line-height: 1.38; }}
.close-bar {{ width: 240px; margin-top: 26px; }}
.close-cards {{
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 22px; margin-top: 42px;
  flex: 1 1 auto; min-height: 0;
}}
.close-cards .card {{ display: flex; flex-direction: column; }}
.close-cards h2 {{ margin-bottom: 12px; }}
.close-cards ul {{ list-style: none; padding: 0; }}
.close-cards li {{ font-size: 15px; padding: 6px 0; color: {MUTED}; line-height: 1.45; }}
.close-cards li b {{ color: {FG}; font-weight: 600; }}
.close-cards .doc {{ font-family: {MONO}; font-size: 13.5px; color: {FG}; }}
.card-foot {{
  margin-top: auto; padding-top: 14px; border-top: 1px solid {LINE};
  font-size: 14px; color: {MUTED}; line-height: 1.5;
}}
.safety {{ border-color: {SEV_MEDIUM}; }}
.safety h2 {{ color: {SEV_MEDIUM}; }}
.safety li {{ color: {FG}; font-size: 15px; }}
.safety .card-foot {{ border-top-color: rgba(255,178,36,.35); }}
.close-foot {{
  display: flex; align-items: baseline; justify-content: flex-end;
  gap: 34px; font-size: 15.5px; color: {MUTED}; padding-top: 30px;
}}
.close-foot .mono {{ color: {FG}; }}
"""
    docs = (
        ("README.md", "install, tour, every command"),
        ("docs/ARCHITECTURE.md", "how the pieces fit together"),
        ("docs/PLAYBOOKS.md", "what to do about each finding"),
        ("docs/GUIDE_HOME_PROTECTION.md", "securing a home network at all"),
        ("docs/NETWORK_DNS_SETUP.md", "the LAN DNS walkthrough, router by router"),
        # Act 3 is five minutes of Lens and ends by naming the certificate as a real trust
        # decision. This is the document that resolves it — including the Tailscale route —
        # and it was the one doc the closing card did not list.
        ("docs/LENS_SETUP.md", "turning Lens on: certificate, firewall, Tailscale"),
    )
    docs_html = "".join(f'<li><span class="doc">{p}</span><br>{d}</li>' for p, d in docs)
    body = f"""
<div class="slide close-slide">
  <div class="close-glow"></div>
  <div class="close-body">
    <div class="close-brand"><span class="m">{BRAND_MARK}</span><span class="n">Home SOC</span></div>
    <p class="close-line">It runs on a PC you already own, it costs nothing, and every byte it produces
      stays in one folder on that machine.</p>
    <div class="close-bar">{_sev_bar()}</div>
    <div class="close-cards">
      <section class="card">
        <h2>Read next</h2>
        <ul>{docs_html}</ul>
        <p class="card-foot">All of it ships inside the repository &mdash; no wiki, no website, no
          sign-up. Run the tests with <span class="doc">python -m pytest -q</span>; they are offline
          and fixture-driven.</p>
      </section>
      <section class="card">
        <h2>Licence</h2>
        <ul>
          <li><b>MIT</b> &mdash; use it, fork it, ship it.</li>
          <li>The threat-intelligence feeds carry their own licences, recorded next to each entry in
            <span class="doc">homesoc/feeds/registry.py</span>.</li>
          <li>A few &mdash; Phishing Army, OpenPhish, EPSS, Spamhaus DROP &mdash; are free for
            <b>non-commercial use only</b>. Check them before you build a business on top.</li>
        </ul>
        <p class="card-foot">Bug reports, new finding rules and platform fixes are welcome. A security
          problem in Home SOC itself goes to <span class="doc">SECURITY.md</span>, privately, rather
          than into a public issue.</p>
      </section>
      <section class="card safety">
        <h2>{TRI} Before you run it</h2>
        <ul>
          <li><b>Scan only networks you own or administer.</b> Port-scanning equipment that is not
            yours is illegal in many places. <span class="doc">network.cidr</span> is what draws that
            line &mdash; keep it pointed at your own LAN.</li>
          <li><b>Nothing is exploited.</b> Home SOC reads a banner and a version string and looks them
            up. It never sends a payload, never tries a credential, never logs in.</li>
          <li>Running a DNS server on port 53 affects everyone in the house. Tell them first.</li>
        </ul>
        <p class="card-foot">Only known devices are scanned, only inside your configured subnet, never
          faster than nmap&rsquo;s T3, at most three hosts at a time &mdash; and never anything listed
          in <span class="doc">network.exclude</span>.</p>
      </section>
    </div>
    <div class="close-foot">
      <span class="mono">python -m homesoc run &nbsp;\u2192&nbsp; http://127.0.0.1:8787</span>
      <span>No account \u00b7 no cloud \u00b7 no telemetry \u00b7 no phone-home of any kind</span>
    </div>
  </div>
</div>
"""
    return _document("Close", body, css)


# --------------------------------------------------------------------------- registry


SLIDES: dict[str, Callable[[], str]] = {
    "title": title,
    "what_it_is": what_it_is,
    "architecture": architecture,
    "first_run": first_run,
    "daily_use": daily_use,
    "lens_why": lens_why,
    "lens_how": lens_how,
    "lens_limits": lens_limits,
    "close": close,
}

#: Spellings :func:`render` also answers to. ``script.py`` and ``slides.py`` are written by
#: different hands; a near-miss on a slide name should not cost a whole capture run. The
#: canonical names above are the ones :func:`slide_names` and :func:`write_all` use.
ALIASES: dict[str, str] = {
    "lens_gap": "lens_why",
    "lens_problem": "lens_why",
    "lens_identify": "lens_how",
    "lens_tags": "lens_how",
    "lens_identification": "lens_how",
    "lens_honest": "lens_limits",
    "lens_honest_limits": "lens_limits",
    "lens_caveats": "lens_limits",
}


def slide_names() -> list[str]:
    """The slide names ``script.py`` may reference, in narrative order."""
    return list(SLIDES)


def render(name: str) -> str:
    """Return the full HTML document for one slide.

    Raises ``KeyError`` with the known names listed, so a typo in ``script.py`` fails loudly during
    capture rather than producing a blank frame.
    """
    key = name if name in SLIDES else ALIASES.get(name, name)
    try:
        fn = SLIDES[key]
    except KeyError:
        raise KeyError(f"unknown slide {name!r}; known slides: {', '.join(SLIDES)}") from None
    html = fn()
    logger.debug("rendered slide %s (%d bytes)", name, len(html))
    return html


def overflow_probe() -> str:
    """JavaScript that reports any diagram text that runs past the box it belongs to.

    ``capture.py`` (or the checker in ``video/`` during development) can evaluate this in the page
    right after loading a slide: it returns a list of offenders, and an empty list means every label
    fits. Cheap insurance against a wording change silently clipping a label.
    """
    return """
(() => {
  const bad = [];
  for (const el of document.querySelectorAll('[data-maxx]')) {
    const b = el.getBBox();
    const max = parseFloat(el.dataset.maxx);
    if (b.x + b.width > max + 0.5) {
      bad.push({text: el.textContent, right: +(b.x + b.width).toFixed(1), max: max});
    }
  }
  const de = document.documentElement;
  return {
    overflow: bad,
    scrollWidth: de.scrollWidth,
    scrollHeight: de.scrollHeight,
  };
})()
"""


def write_all(directory: str) -> list[str]:
    """Write every slide to ``directory`` as ``slide_<name>.html``; returns the paths written.

    Only used for eyeballing the slides outside the capture pipeline.
    """
    from pathlib import Path

    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name in SLIDES:
        path = out_dir / f"slide_{name}.html"
        path.write_text(render(name), encoding="utf-8")
        written.append(str(path))
        logger.info("wrote %s", path)
    return written


if __name__ == "__main__":  # pragma: no cover - developer convenience
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Write the walkthrough slides as HTML files.")
    parser.add_argument("--out", default="video/build/slides", help="output directory")
    args = parser.parse_args()
    for written_path in write_all(args.out):
        print(written_path)
