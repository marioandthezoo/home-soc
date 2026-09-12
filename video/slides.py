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

import logging
from dataclasses import dataclass
from typing import Callable, Sequence

logger = logging.getLogger(__name__)

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

_BOUND_L, _BOUND_T, _BOUND_R = 252.0, 10.0, 1512.0
# BG composited with the boundary's rgba(62,99,221,.045) wash: the exact colour inside the
# process outline, so a label backdrop drawn there is invisible.
_INSIDE_BG = "#111520"
_BOUND_SHOULDER_Y, _BOUND_NOTCH_X, _BOUND_B = 540.0, 1180.0, 762.0

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
    cards = (
        ("CATALOGUE", "88 rules \u00b7 16 categories",
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
    """Column D: everything a person actually reads."""
    rows = (
        ("Dashboard", "127.0.0.1:8787", "overview \u00b7 findings \u00b7 devices \u00b7 vulns \u00b7 host \u00b7 DNS", SEV_INFO),
        ("Activity feed", "/feed", "one stream of everything that happened \u00b7 also RSS", SEV_LOW),
        ("Remediation summary", "/summary", "found vs fixed \u00b7 time-to-fix \u00b7 the open worklist", SEV_MEDIUM),
        ("Notifications", "outbound", "ntfy \u00b7 Discord \u00b7 webhook \u00b7 Windows toast \u00b7 digest", SEV_HIGH),
    )
    out = [_box(_COL_D)]
    rh, gap = 70.0, 9.0
    y = _COL_D.y + 14
    for name, tag, sub, colour in rows:
        r = Rect(_COL_D.x + 14, y, _COL_D.w - 28, rh)
        tx, mx = r.inner(14)
        out.append(_box(r, fill=PANEL_2, rx=8))
        out.append(f'<rect x="{r.x:g}" y="{r.y + 12:g}" width="3" height="{rh - 24:g}" rx="1.5" fill="{colour}"/>')
        out.append(_t(tx + 6, r.y + 30, name, maxx=mx - 130, size=18.5, weight=650))
        out.append(_t(mx, r.y + 30, tag, maxx=mx + 1, size=13, fill=MUTED, anchor="end", mono=True))
        out.append(_t(tx + 6, r.y + 53, sub, maxx=mx, size=13.5, fill=MUTED))
        y += rh + gap
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
        'SQLite and the embedded DNS resolver, all inside one Python process.">',
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
      comes out on the right. It complements Defender: <b>not an antivirus engine, not an EDR</b>.</p>
  </header>
  {_architecture_svg()}
  <div class="arch-legend">
    <span><b>{TRI} needs administrator</b> &mdash; Secure Boot, TPM and BitLocker report
      &ldquo;needs administrator&rdquo; rather than failing; so does the one inbound firewall rule that
      lets the LAN reach the resolver. Everything else runs as a normal user.</span>
    <span style="margin-left:auto">dashed outline = one OS process</span>
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
    ("out", "database: C:\\Users\\you\\Home_SOC\\data\\homesoc.db (schema v1)"),
    ("out", "downloading first feeds (oui, kev) ..."),
    ("out", "&nbsp;&nbsp;kev: <span class='ok'>ok</span>"),
    ("out", "&nbsp;&nbsp;oui: <span class='ok'>ok</span>"),
    ("blank", ""),
    ("out", "Next: python -m homesoc run   (dashboard at "
            "<span class='url'>http://127.0.0.1:8787/login?token=Qh7dK2\u2026</span>)"),
    ("log", "2026-09-07 09:14:02 <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "scheduler started with 15 jobs"),
    ("hero", "Dashboard: <span class='url'>http://127.0.0.1:8787/login?token=Qh7dK2\u2026</span>"
             "  (Ctrl-C to stop)"),
    ("log", "2026-09-07 09:14:03 <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job feeds starting"),
    ("log", "2026-09-07 09:14:11 <span class='lvl'>INFO</span>    homesoc.feeds.updater: "
            "feed kev updated: 1743210 bytes, 1412 entries, sha256=3b91f0c2ad4e"),
    ("log", "2026-09-07 09:14:12 <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job discovery starting"),
    ("log", "2026-09-07 09:14:33 <span class='lvl'>INFO</span>    homesoc.cli: "
            "[discovery] sweep 254/254"),
    ("log", "2026-09-07 09:14:36 <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job services starting"),
    ("log", "2026-09-07 09:16:44 <span class='lvl'>INFO</span>    homesoc.scheduler: "
            "job vulns starting"),
    ("log", "2026-09-07 09:16:51 <span class='lvl'>INFO</span>    homesoc.scheduler: "
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
    lines: list[str] = []
    for kind, html in _TERMINAL:
        if kind == "blank":
            lines.append("<div>&nbsp;</div>")
        else:
            lines.append(f'<div class="{kind}">{html}</div>')
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
          background after that. The first full picture of a twenty-device network lands inside
          <b>five minutes</b>.</p>
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


# --------------------------------------------------------------------------- 6. close


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
    "close": close,
}


def slide_names() -> list[str]:
    """The slide names ``script.py`` may reference, in narrative order."""
    return list(SLIDES)


def render(name: str) -> str:
    """Return the full HTML document for one slide.

    Raises ``KeyError`` with the known names listed, so a typo in ``script.py`` fails loudly during
    capture rather than producing a blank frame.
    """
    try:
        fn = SLIDES[name]
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
