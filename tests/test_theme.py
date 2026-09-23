"""The "Stone & Sage" theme and the plain-language shell.

Part 1 is the design's palette audit (the design lead's tools/palette.py), ported so a future
edit to a token cannot quietly break it: the tokens are parsed straight out of the shipped
``static/style.css`` (day = the first ``:root`` block, dusk = ``:root[data-theme="dusk"]``, which
must equal the ``prefers-color-scheme: dark`` block), then every WCAG 2.x contrast pair, the
map-edge contrast after opacity, and colour-vision separation (Machado 2009, severity 1.0, in
linear RGB; CIEDE2000) are asserted against the thresholds in the design record.

Part 2 covers the shared template contract: the ``sev_word`` / ``status_word`` /
``device_label`` filters, the staleness rule, the glossary ``term()`` macro (escaped), the
navigation, and the honesty rules for wording.
"""

from __future__ import annotations

import itertools
import math
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "homesoc" / "web"
STATIC = WEB / "static"
TEMPLATES = WEB / "templates"
CSS = (STATIC / "style.css").read_text(encoding="utf-8")
MAPCSS = (STATIC / "map.css").read_text(encoding="utf-8")

# --------------------------------------------------------------------------- colour maths


def hex_rgb(h: str) -> tuple[float, float, float]:
    h = h.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def delin(c: float) -> float:
    c = max(0.0, min(1.0, c))
    return 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055


def lum(h: str) -> float:
    r, g, b = (lin(c) for c in hex_rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a: str, b: str) -> float:
    la, lb = lum(a), lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


MACHADO = {
    "deuteranopia": [[0.367322, 0.860646, -0.227968], [0.280085, 0.672501, 0.047413], [-0.011820, 0.042940, 0.968881]],
    "protanopia": [[0.152286, 1.052583, -0.204868], [0.114503, 0.786281, 0.099216], [-0.003882, -0.048116, 1.051998]],
    "tritanopia": [[1.255528, -0.076749, -0.178779], [-0.078411, 0.930809, 0.147602], [0.004733, 0.691367, 0.303900]],
}


def simulate(h: str, kind: str) -> str:
    r, g, b = (lin(c) for c in hex_rgb(h))
    m = MACHADO[kind]
    out = [m[i][0] * r + m[i][1] * g + m[i][2] * b for i in range(3)]
    return "#" + "".join(f"{round(delin(c) * 255):02x}" for c in out)


def lab(h: str) -> tuple[float, float, float]:
    r, g, b = (lin(c) for c in hex_rgb(h))
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 216 / 24389 else (24389 / 27 * t + 16) / 116

    fx, fy, fz = f(x), f(y), f(z)
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def lch(h: str) -> tuple[float, float, float]:
    L, a, b = lab(h)
    return L, math.hypot(a, b), math.degrees(math.atan2(b, a)) % 360


def de2000(h1: str, h2: str) -> float:
    L1, a1, b1 = lab(h1)
    L2, a2, b2 = lab(h2)
    C1, C2 = math.hypot(a1, b1), math.hypot(a2, b2)
    Cb = (C1 + C2) / 2
    G = 0.5 * (1 - math.sqrt(Cb ** 7 / (Cb ** 7 + 25 ** 7)))
    a1p, a2p = (1 + G) * a1, (1 + G) * a2
    C1p, C2p = math.hypot(a1p, b1), math.hypot(a2p, b2)
    h1p = math.degrees(math.atan2(b1, a1p)) % 360
    h2p = math.degrees(math.atan2(b2, a2p)) % 360
    dL, dC = L2 - L1, C2p - C1p
    if C1p * C2p == 0:
        dh = 0.0
    elif abs(h2p - h1p) <= 180:
        dh = h2p - h1p
    else:
        dh = h2p - h1p - 360 if h2p > h1p else h2p - h1p + 360
    dH = 2 * math.sqrt(C1p * C2p) * math.sin(math.radians(dh / 2))
    Lb, Cbp = (L1 + L2) / 2, (C1p + C2p) / 2
    if C1p * C2p == 0:
        hb = h1p + h2p
    elif abs(h1p - h2p) <= 180:
        hb = (h1p + h2p) / 2
    else:
        hb = (h1p + h2p + 360) / 2 if h1p + h2p < 360 else (h1p + h2p - 360) / 2
    T = (1 - 0.17 * math.cos(math.radians(hb - 30)) + 0.24 * math.cos(math.radians(2 * hb))
         + 0.32 * math.cos(math.radians(3 * hb + 6)) - 0.20 * math.cos(math.radians(4 * hb - 63)))
    dth = 30 * math.exp(-(((hb - 275) / 25) ** 2))
    Rc = 2 * math.sqrt(Cbp ** 7 / (Cbp ** 7 + 25 ** 7))
    Sl = 1 + 0.015 * (Lb - 50) ** 2 / math.sqrt(20 + (Lb - 50) ** 2)
    Sc, Sh = 1 + 0.045 * Cbp, 1 + 0.015 * Cbp * T
    Rt = -math.sin(math.radians(2 * dth)) * Rc
    return math.sqrt((dL / Sl) ** 2 + (dC / Sc) ** 2 + (dH / Sh) ** 2 + Rt * (dC / Sc) * (dH / Sh))


def blend(fg: str, bg: str, alpha: float) -> str:
    f, g = hex_rgb(fg), hex_rgb(bg)
    return "#" + "".join(f"{round((alpha * x + (1 - alpha) * y) * 255):02x}" for x, y in zip(f, g))


def test_colour_maths_matches_known_values():
    """Guard the guard: WCAG reference ratios, a neutral that CVD simulation leaves alone, blending."""
    assert ratio("#ffffff", "#000000") == pytest.approx(21.0)
    assert ratio("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)
    assert simulate("#ffffff", "deuteranopia") == "#ffffff"
    assert de2000("#000000", "#000000") == 0
    assert blend("#000000", "#ffffff", 0.5) == "#808080"


# --------------------------------------------------------------------------- token parsing


def _tokens(block: str) -> dict[str, str]:
    return {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block)}


def _block(pattern: str) -> str:
    m = re.search(pattern, CSS, re.S | re.M)
    assert m, f"token block not found: {pattern}"
    return m.group(1)


DAY = _tokens(_block(r"^:root\s*\{(.*?)\n\}"))
DUSK_OVER = _tokens(_block(r'^:root\[data-theme="dusk"\]\s*\{(.*?)\n\}'))
DUSK_MEDIA = _tokens(_block(r':root:not\(\[data-theme="day"\]\)\s*\{(.*?)\n  \}'))
DUSK = {**DAY, **DUSK_OVER}
THEMES = {"day": DAY, "dusk": DUSK}
SEVS = ("critical", "high", "medium", "low", "info")
VIEWS = ("normal", "deuteranopia", "protanopia", "tritanopia")


def test_dusk_blocks_are_identical():
    """Dusk is defined twice (OS dark preference, and the manual data-theme="dusk"); they must
    never drift apart, or the toggle and the OS setting would show two different "dusks"."""
    assert DUSK_MEDIA == DUSK_OVER
    assert DUSK_OVER, "dusk overrides are empty"


def test_day_is_the_default_and_the_toggle_can_force_it():
    assert re.search(r"^:root\s*\{\s*color-scheme:\s*light;", CSS, re.M)
    assert '@media (prefers-color-scheme: dark)' in CSS
    assert ':root:not([data-theme="day"])' in CSS


def test_no_pure_white_or_black_in_the_stylesheets():
    literals = re.findall(r"#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b", CSS + MAPCSS)
    assert not [h for h in literals if h.lower() in ("#fff", "#ffffff", "#000", "#000000")]


def test_every_token_is_a_hex_colour_where_a_colour_is_expected():
    for name, tokens in THEMES.items():
        for key, value in tokens.items():
            if key.startswith(("--sev-", "--status-", "--chart-")) and key not in ("--chart-label-size",) or key in (
                "--bg", "--panel", "--panel-2", "--sidebar", "--fg", "--fg-2", "--muted", "--accent", "--accent-ink",
                "--accent-fg", "--accent-tint", "--focus", "--ok", "--warn", "--err", "--line", "--line-strong",
            ):
                assert re.fullmatch(r"#[0-9a-f]{6}", value), f"{name} {key} = {value!r}"


# --------------------------------------------------------------------------- contrast


def _contrast_checks() -> list[tuple[str, str, str, str, float]]:
    """(theme, label, fg token, bg token, need) — the full audit from DESIGN.md section 5."""
    out: list[tuple[str, str, str, str, float]] = []
    for theme in THEMES:
        def chk(label: str, fg: str, bg: str, need: float) -> None:
            out.append((theme, label, fg, bg, need))

        for bg in ("--bg", "--panel", "--panel-2", "--sidebar"):
            chk(f"body text on {bg}", "--fg", bg, 7)
            chk(f"secondary text on {bg}", "--fg-2", bg, 7)
            chk(f"muted text on {bg}", "--muted", bg, 4.5)
            chk(f"link text on {bg}", "--accent-ink", bg, 4.5)
            chk(f"UI boundary on {bg}", "--line-strong", bg, 3)
        chk("active nav text on sage wash", "--fg", "--accent-tint", 7)
        chk("primary button label", "--accent-ink", "--accent-tint", 4.5)
        chk("primary button edge vs panel", "--accent", "--panel", 3)
        chk("primary button edge vs bg", "--accent", "--bg", 3)
        chk("primary hover label", "--accent-fg", "--accent", 4.5)
        chk("+N score pill", "--ok", "--accent-tint", 4.5)
        chk("focus ring vs panel", "--focus", "--panel", 3)
        chk("focus ring vs bg", "--focus", "--bg", 3)
        for s in SEVS:
            chk(f"{s} badge label on fill", f"--sev-{s}-on", f"--sev-{s}", 4.5)
            chk(f"{s} fill vs panel", f"--sev-{s}", "--panel", 3)
            chk(f"{s} ink vs panel", f"--sev-{s}-ink", "--panel", 4.5)
            chk(f"{s} ink vs map canvas", f"--sev-{s}-ink", "--panel-2", 4.5)
            chk(f"{s} ink on own tint", f"--sev-{s}-ink", f"--sev-{s}-tint", 4.5)
        for k in ("ok", "warn", "err"):
            for bg in ("--panel", "--panel-2", "--sidebar"):
                chk(f"{k} text on {bg}", f"--{k}", bg, 4.5)
        chk("resolved/online pill", "--ok", "--accent-tint", 4.5)
        chk("open badge text", "--sev-high-ink", "--sev-high-tint", 4.5)
        chk("stale banner text", "--fg", "--sev-medium-tint", 7)
        chk("status dot on (sidebar)", "--ok", "--sidebar", 3)
        for k in ("open", "ack", "resolved"):
            chk(f"status series {k} vs panel", f"--status-{k}", "--panel", 3)
        for i in range(5, 9):
            chk(f"chart-{i} vs panel", f"--chart-{i}", "--panel", 3)
    return out


CONTRAST = _contrast_checks()


@pytest.mark.parametrize("theme,label,fg,bg,need", CONTRAST, ids=[f"{c[0]}:{c[1]}" for c in CONTRAST])
def test_contrast(theme, label, fg, bg, need):
    t = THEMES[theme]
    r = ratio(t[fg], t[bg])
    assert r >= need, f"{theme}: {label} is {r:.2f}:1 ({fg} {t[fg]} on {bg} {t[bg]}), needs {need}:1"


def _edge_opacity(selector: str) -> float:
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", MAPCSS)
    assert m, f"{selector} missing from map.css"
    o = re.search(r"opacity:\s*([\d.]+)", m.group(1))
    return float(o.group(1)) if o else 1.0


@pytest.mark.parametrize("theme", list(THEMES))
@pytest.mark.parametrize("selector,colour", [
    (".map-edge", "--muted"),
    (".map-edge.conf-observed", "--accent-ink"),
    (".map-edge.conf-inferred", "--muted"),
    (".map-edge.conf-assumed", "--muted"),
])
def test_map_edges_clear_3_to_1_after_opacity(theme, selector, colour):
    """Every dependency line must be visible on the map canvas once its opacity is applied."""
    t = THEMES[theme]
    canvas = t["--panel-2"]
    effective = blend(t[colour], canvas, _edge_opacity(selector))
    assert ratio(effective, canvas) >= 3, f"{theme} {selector}: {ratio(effective, canvas):.2f}:1"


def test_observed_edges_are_sage_never_a_severity():
    block = re.search(r"\.map-edge\.conf-observed\s*\{([^}]*)\}", MAPCSS).group(1)
    assert "--accent-ink" in block and "--sev-" not in block


# --------------------------------------------------------------------------- colour vision


def _min_pair(t: dict[str, str], keys: list[str], view: str) -> tuple[float, str]:
    sims = {k: (t[k] if view == "normal" else simulate(t[k], view)) for k in keys}
    pairs = {f"{a}|{b}": de2000(sims[a], sims[b]) for a, b in itertools.combinations(keys, 2)}
    worst = min(pairs, key=pairs.get)
    return pairs[worst], worst


@pytest.mark.parametrize("theme", list(THEMES))
@pytest.mark.parametrize("view", VIEWS)
def test_severities_stay_apart_under_colour_vision_deficiency(theme, view):
    d, pair = _min_pair(THEMES[theme], [f"--sev-{s}" for s in SEVS], view)
    assert d >= 10, f"{theme} {view}: {pair} only {d:.1f} dE00 apart (need 10)"


@pytest.mark.parametrize("theme", list(THEMES))
@pytest.mark.parametrize("view", VIEWS)
def test_status_series_stay_apart_under_colour_vision_deficiency(theme, view):
    d, pair = _min_pair(THEMES[theme], ["--status-open", "--status-ack", "--status-resolved"], view)
    assert d >= 12, f"{theme} {view}: {pair} only {d:.1f} dE00 apart (need 12)"


@pytest.mark.parametrize("theme", list(THEMES))
def test_severity_ladder_constraints(theme):
    """DESIGN.md section 6: critical stays red and clearly darker (day) / clearly distinct (dusk)
    than high, and high vs low keep a lightness gap."""
    t = THEMES[theme]
    L = {s: lch(t[f"--sev-{s}"])[0] for s in SEVS}
    crit_hue = lch(t["--sev-critical"])[2]
    assert 20 <= crit_hue <= 36, f"{theme} critical hue {crit_hue:.1f} is no longer red"
    assert abs(L["high"] - L["critical"]) >= 8, f"{theme} critical/high lightness gap {abs(L['high'] - L['critical']):.1f}"
    assert L["critical"] < L["high"], "critical must be the darker (day) / deeper (dusk) of the two"
    if theme == "day":
        # Day's high and low were the pair the judges saw collapse; they keep a lightness gap
        # (dusk separates them by hue and chroma instead, covered by the CVD test above).
        assert abs(L["high"] - L["low"]) >= 8, f"day high/low lightness gap {abs(L['high'] - L['low']):.1f}"
    else:
        assert abs(L["low"] - L["info"]) >= 7, f"dusk low/info lightness gap {abs(L['low'] - L['info']):.1f}"


def test_all_is_well_is_sage_not_the_low_severity_moss():
    for name, t in THEMES.items():
        assert t["--accent"] != t["--sev-low"], name
        assert de2000(t["--accent"], t["--sev-low"]) >= 5, name


# --------------------------------------------------------------------------- stylesheet contract


SHELL_CLASSES = (
    ".stale-banner", ".status-line", ".tech-details", ".quiet-badge", ".term", ".status-banner",
    ".sev-word", ".sev-pair", ".nav-divider", ".statusline", ".badge.is-zero", ".chart-empty",
    ".plain-title", ".plain-why", "details.tech", ".theme-toggle", ".page-tech", ".tech-word",
    ".device-ip", ".status-chip",
)


@pytest.mark.parametrize("selector", SHELL_CLASSES)
def test_shell_classes_exist(selector):
    assert selector in CSS


def test_stylesheets_load_nothing_external():
    for text in (CSS, MAPCSS):
        assert "@import" not in text and "url(" not in text
        assert "@font-face" not in text


def test_serif_is_a_local_system_face():
    serif = DAY["--serif"]
    assert "Palatino Linotype" in serif and serif.rstrip().endswith("serif")


# --------------------------------------------------------------------------- scripts


def _hex_literals(js: str) -> list[tuple[int, str]]:
    return [(i, line) for i, line in enumerate(js.splitlines(), 1)
            if re.search(r"""['"]#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?['"]""", line)]


def test_charts_read_every_colour_from_tokens():
    js = (STATIC / "charts.js").read_text(encoding="utf-8")
    stray = [(i, line) for i, line in _hex_literals(js) if "cssVar(" not in line]
    assert not stray, f"hard-coded colours outside a cssVar fallback: {stray}"
    for retired in ("#e5484d", "#f76b15", "#ffb224", "#46a758", "#3e63dd", "#8e4ec6", "#12a594", "#e93d82"):
        assert retired not in js.lower(), f"retired neon colour {retired} still in charts.js"
    assert "attributeFilter: ['data-theme']" in js, "charts must redraw when the theme toggle flips"
    assert "prefers-color-scheme: dark" in js, "charts must redraw when the OS theme flips"


def test_app_and_graph_have_no_colour_literals():
    for name in ("app.js", "graph.js"):
        js = (STATIC / name).read_text(encoding="utf-8")
        assert not _hex_literals(js), f"{name}: {_hex_literals(js)}"
    app = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "token: '--status-open'" in app and "token: '--status-resolved'" in app
    assert "col.high" not in app and "col.medium" not in app


def test_scripts_never_write_html():
    for path in STATIC.glob("*.js"):
        js = path.read_text(encoding="utf-8")
        assert ".innerHTML" not in js and "insertAdjacentHTML" not in js and "outerHTML =" not in js, path.name


def test_theme_script_is_loaded_early_and_is_not_inline():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    head = base.split("</head>", 1)[0]
    m = re.search(r"<script src=\"\{\{ url_for\('static', filename='theme.js'\) \}\}\"></script>", head)
    assert m, "theme.js must be a plain (not deferred) external script in <head>"
    assert head.index("theme.js") < head.index("style.css"), "theme.js must run before the stylesheet paints"
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", base), "no inline script (CSP default-src 'self')"
    assert " style=" not in base and re.search(r"\son[a-z]+=", base) is None
    js = (STATIC / "theme.js").read_text(encoding="utf-8")
    for mode in ("'auto'", "'day'", "'dusk'"):
        assert mode in js
    assert "localStorage" in js and "try" in js  # storage may be blocked: must not throw


# --------------------------------------------------------------------------- filters


from homesoc.web import app as appmod  # noqa: E402


@pytest.mark.parametrize("severity,word", [
    ("critical", "Fix now"), ("high", "Fix this week"), ("medium", "Worth fixing"),
    ("low", "When you have time"), ("info", "Good to know"), ("CRITICAL", "Fix now"),
    ("bogus", ""), (None, ""),
])
def test_sev_word(severity, word):
    assert appmod.sev_word(severity) == word


@pytest.mark.parametrize("status,word", [
    ("open", "Needs attention"), ("acknowledged", "Seen, not fixed yet"), ("resolved", "Fixed"),
    ("suppressed", "Ignored (your choice)"), ("weird", ""), (None, ""),
])
def test_status_word(status, word):
    assert appmod.status_word(status) == word


@pytest.mark.parametrize("score,word", [(0, "Needs work"), (10, "Needs work"), (49, "Needs work"), (50, "Fair"),
                                        (79, "Fair"), (80, "Good"), (100, "Good"), (None, ""), ("x", "")])
def test_score_word(score, word):
    assert appmod.score_word(score) == word


def test_device_label_names_devices_not_addresses():
    dl = appmod.device_label
    assert dl({"nickname": "Kitchen tablet", "hostname": "galaxy-tab-a9", "ip": "192.168.1.35"}) == "Kitchen tablet"
    assert dl({"nickname": None, "hostname": "sonos-kitchen", "ip": "192.168.1.41"}) == "sonos-kitchen"
    # _device_row's display_name falls back to the IP: that is not a name.
    assert dl({"display_name": "192.168.1.142", "ip": "192.168.1.142", "kind": "camera"}) == "Unnamed camera"
    assert dl({"hostname": "", "ip": "192.168.1.9", "mac": "aa:bb:cc:dd:ee:ff"}) == "Unnamed device"
    assert dl({"hostname": "aa:bb:cc:dd:ee:ff", "kind": "iot"}) == "Unnamed smart device"
    assert dl({"hostname": "192.168.1.1", "kind": "router"}) == "Unnamed router"
    # A finding: device_name first, never the IP.
    assert dl({"subject": "device:aa:bb", "device_id": 3, "device_name": "Front door bell", "device_ip": "192.168.1.60"}) == "Front door bell"
    # An API payload's own label is used when there is nothing better.
    assert dl({"ip": "192.168.1.7", "device_label": "Unnamed printer"}) == "Unnamed printer"
    assert dl(None) == "Unnamed device"
    assert dl("192.168.1.5") == "Unnamed device"
    assert dl("Living room TV") == "Living room TV"


def test_device_label_for_this_computer():
    assert appmod.device_label("host:HOME-PC") == "This computer (HOME-PC)"
    assert appmod.device_label({"subject": "host:HOME-PC", "device_id": None}) == "This computer (HOME-PC)"
    assert appmod.device_label("host").startswith("This computer")


def test_css_token_cannot_break_out_of_a_class_attribute():
    assert appmod.css_token('critical" onmouseover="x') == "critical-onmouseover-x"
    assert appmod.css_token("needs_admin") == "needs-admin"
    assert appmod.css_token("") == "unknown"


# --------------------------------------------------------------------------- staleness


NOW = datetime(2026, 9, 22, 18, 0, tzinfo=timezone.utc)


def _iso(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def scans_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, started_at TEXT NOT NULL, "
                 "finished_at TEXT, status TEXT NOT NULL, summary TEXT, error TEXT)")
    yield conn
    conn.close()


def _cfg(minutes=10):
    return SimpleNamespace(schedule=SimpleNamespace(discovery_minutes=minutes))


def _scan(conn, kind, finished_minutes_ago, status="ok"):
    finished = None if finished_minutes_ago is None else _iso(finished_minutes_ago)
    conn.execute("INSERT INTO scans(kind, started_at, finished_at, status) VALUES(?,?,?,?)",
                 (kind, _iso((finished_minutes_ago or 0) + 1), finished, status))


def test_staleness_never_checked(scans_db):
    s = appmod.staleness(scans_db, _cfg(), now=NOW)
    assert s["stale"] is False and s["never"] is True and s["last_check"] is None
    assert s["schedule_minutes"] == 10
    assert set(s) >= {"stale", "age_text", "last_check", "schedule_minutes"}


def test_staleness_fresh_and_stale_at_three_schedules(scans_db):
    _scan(scans_db, "discovery", 29)
    s = appmod.staleness(scans_db, _cfg(10), now=NOW)
    assert s["stale"] is False and s["age_text"] == "29 minutes ago"
    scans_db.execute("DELETE FROM scans")
    _scan(scans_db, "discovery", 31)
    s = appmod.staleness(scans_db, _cfg(10), now=NOW)
    assert s["stale"] is True and s["last_check"] == _iso(31)


def test_staleness_ignores_runs_that_did_not_look(scans_db):
    """A running, failed or aborted discovery did not check the network; another kind of scan
    (feeds) is not a network check either."""
    _scan(scans_db, "discovery", 8 * 24 * 60)             # 8 days ago, ok
    _scan(scans_db, "discovery", 5, status="error")
    _scan(scans_db, "discovery", 4, status="aborted")
    _scan(scans_db, "discovery", None, status="running")
    _scan(scans_db, "feeds", 1)
    s = appmod.staleness(scans_db, _cfg(10), now=NOW)
    assert s["stale"] is True and s["age_text"] == "8 days ago"
    _scan(scans_db, "discovery", 3, status="partial")     # partial still looked
    assert appmod.staleness(scans_db, _cfg(10), now=NOW)["stale"] is False


def test_staleness_caps_at_a_day_for_long_schedules(scans_db):
    _scan(scans_db, "discovery", 25 * 60)
    assert appmod.staleness(scans_db, _cfg(12 * 60), now=NOW)["stale"] is True
    assert appmod.staleness(scans_db, _cfg(0), now=NOW)["schedule_minutes"] == 10


def test_staleness_survives_a_missing_table():
    conn = sqlite3.connect(":memory:")
    try:
        s = appmod.staleness(conn, _cfg(), now=NOW)
        assert s["stale"] is False
    finally:
        conn.close()


@pytest.mark.parametrize("secs,text", [(0, "just now"), (59, "just now"), (60, "1 minute ago"), (125, "2 minutes ago"),
                                       (3600, "1 hour ago"), (8 * 86400 + 5, "8 days ago"), (-30, "just now")])
def test_human_age(secs, text):
    assert appmod.human_age(secs) == text


# --------------------------------------------------------------------------- glossary + macros


REQUIRED_TERMS = ("DNS", "CVE", "KEV", "EPSS", "CVSS", "UPnP", "port", "MAC", "IP", "resolver", "firmware",
                  "telemetry", "Telnet", "SSH", "SMB", "RDP", "CPE")


def test_glossary_has_every_contract_term():
    for word in REQUIRED_TERMS:
        assert appmod.GLOSSARY.get(word), word


def test_epss_is_never_a_chance_of_attack():
    tip = appmod.GLOSSARY["EPSS"].lower()
    assert "30 days" in tip and "somewhere" in tip
    assert "chance of attack" not in tip and "will be attacked" not in tip


@pytest.fixture
def web_app(memory_conn):
    cfg = SimpleNamespace(
        general=SimpleNamespace(name="Home SOC Test"),
        web=SimpleNamespace(host="127.0.0.1", port=8787, token="", refresh_seconds=15),
        dns=SimpleNamespace(enabled=True),
        schedule=SimpleNamespace(discovery_minutes=10),
    )
    app = appmod.create_app(cfg, memory_conn)
    app.config["TESTING"] = True
    return app


def _render(app, source: str, **ctx) -> str:
    with app.test_request_context("/"):
        return app.jinja_env.from_string('{% import "_macros.html" as ui %}' + source).render(**ctx)


def test_term_renders_an_escaped_tooltip(web_app):
    html = _render(web_app, "{{ ui.term('KEV') }}")
    # Keyboard- and touch-reachable (review finding): focusable, the tip in data-tip for the
    # CSS tooltip, and the same text behind aria-describedby for screen readers. No title=.
    assert html.startswith('<abbr class="term" tabindex="0" data-tip="') and ">KEV</abbr>" in html
    assert "title=" not in html
    tip_id = html.split('aria-describedby="')[1].split('"')[0]
    assert f'id="{tip_id}" hidden>' in html and html.endswith("</span>")
    assert "Known Exploited" in html
    html = _render(web_app, "{{ ui.term('ports') }}")  # plural falls back to "port"
    assert 'class="term"' in html and ">ports</abbr>" in html
    html = _render(web_app, "{{ ui.term('resolver') }}")
    assert "&#34;where is this website?&#34;" in html or "&quot;where is this website?&quot;" in html


def test_term_escapes_what_it_is_given(web_app):
    html = _render(web_app, "{{ ui.term(w) }}", w="<script>alert(1)</script>")
    assert "<script>" not in html and "&lt;script&gt;" in html and "abbr" not in html
    html = _render(web_app, "{{ ui.term('DNS', t) }}", t='<b onclick="x">look-ups</b>')
    assert "<b " not in html and "&lt;b onclick=" in html


def test_sev_badge_carries_the_technical_label_and_the_word(web_app):
    html = _render(web_app, "{{ ui.sev_badge('critical') }}")
    assert 'badge badge-critical' in html and ">critical</span>" in html and ">Fix now</span>" in html
    zero = _render(web_app, "{{ ui.sev_badge('high', 0) }}")
    assert "is-zero quiet-badge" in zero and ">0 high</span>" in zero and "Fix this week" in zero
    assert "sev-word-high" not in zero  # a zero count's word is muted, not in the warning ink
    nasty = _render(web_app, "{{ ui.sev_badge(s) }}", s='x" onmouseover="alert(1)')
    assert 'onmouseover="' not in nasty


def test_sev_global_matches_the_macro(web_app):
    html = str(appmod.sev_badge_markup("medium", 2))
    assert ">2 medium</span>" in html and "Worth fixing" in html and "badge-medium" in html
    assert "is-zero" in str(appmod.sev_badge_markup("low", 0))
    assert "&lt;i&gt;" in str(appmod.sev_badge_markup("<i>"))


def test_status_chip_keeps_the_technical_status_beside_the_word(web_app):
    html = _render(web_app, "{{ ui.status_chip('acknowledged') }}")
    assert "status-badge badge-acknowledged" in html and "Seen, not fixed yet" in html
    assert '<span class="tech-word">acknowledged</span>' in html and 'data-status="acknowledged"' in html


def test_device_name_macro_puts_the_ip_second(web_app):
    html = _render(web_app, "{{ ui.device_name(d) }}", d={"id": 4, "nickname": "Epson printer", "ip": "192.168.1.50", "mac": "aa"})
    assert html.index("Epson printer") < html.index("192.168.1.50") and 'href="/devices/4"' in html
    html = _render(web_app, "{{ ui.device_name(d) }}", d={"id": 9, "ip": "192.168.1.142", "kind": "camera", "mac": "bb"})
    assert "Unnamed camera" in html and html.count("192.168.1.142") == 1
    finding = {"id": 77, "subject": "device:aa", "device_id": None, "device_name": "Hall plug"}
    assert 'href="/devices/77"' not in _render(web_app, "{{ ui.device_name(f) }}", f=finding)


def test_filters_are_registered(web_app):
    env = web_app.jinja_env
    for name in ("sev_word", "status_word", "device_label", "score_word"):
        assert name in env.filters
    html = _render(web_app, "{{ 'critical'|sev_word }}|{{ 'open'|status_word }}|{{ d|device_label }}",
                   d={"hostname": "echo-kitchen", "ip": "192.168.1.81"})
    assert html == "Fix now|Needs attention|echo-kitchen"


# --------------------------------------------------------------------------- navigation + frame


def test_navigation_order_and_paths():
    assert [(k, h, label) for k, h, label, _t in appmod.NAV] == [
        ("overview", "/", "Home"), ("findings", "/findings", "Things to fix"), ("devices", "/devices", "Devices"),
        ("feed", "/feed", "What happened"), ("summary", "/summary", "Report"), ("host", "/host", "This computer"),
        ("dns", "/dns", "Blocking"),
    ]
    assert [(k, h, label) for k, h, label, _t in appmod.NAV_ADVANCED] == [
        ("map", "/map", "What depends on what"), ("vulns", "/vulns", "Known flaws"), ("scans", "/scans", "Checks"),
        ("telemetry", "/telemetry", "System health"), ("settings", "/settings", "Settings"),
    ]


def test_the_map_is_never_about_connections():
    """SPEC_TOPOLOGY C1: Home SOC cannot see devices talking to each other."""
    for _k, _h, label, tech in appmod.NAV + appmod.NAV_ADVANCED:
        assert not re.search(r"connect|traffic|flow", label + " " + tech, re.I), label
    assert not re.search(r"connect|traffic|flow", appmod.PAGE_TITLES["map"], re.I)


BANNED = (
    (re.compile(r"how things connect", re.I), "the map is not about connections (SPEC_TOPOLOGY C1)"),
    (re.compile(r"chance of (an )?attack", re.I), "EPSS is the chance a flaw is exploited somewhere, not an attack on you"),
    (re.compile(r"you will be attacked", re.I), "overclaims"),
)


@pytest.mark.parametrize("path", sorted([*TEMPLATES.glob("*.html"), *STATIC.glob("*.js"), WEB / "app.py", WEB / "api.py"]),
                         ids=lambda p: p.name)
def test_no_dishonest_wording(path):
    text = path.read_text(encoding="utf-8")
    for pattern, why in BANNED:
        m = pattern.search(text)
        assert m is None, f"{path.name}: {m.group(0)!r} — {why}"


def test_page_frame_renders_the_shell(web_app):
    client = web_app.test_client()
    html = client.get("/scans").get_data(as_text=True)
    assert 'class="nav-divider"' in html and ">Advanced<" in html
    assert 'title="Dependency map">What depends on what</a>' in html
    assert 'aria-current="page"' in html and ">Checks</a>" in html
    assert 'id="theme-toggle"' in html
    # The page clock says it is the SCREEN's refresh, so it cannot be read as a network check.
    refresh = re.search(r'id="last-refresh"[^>]*>([^<]*)<', html).group(1)
    assert refresh.startswith("Screen refreshes every") and "updated" not in refresh.lower()
    assert "Network not checked yet" in html
    assert 'id="stale-banner"' in html and re.search(r'id="stale-banner"[^>]*\shidden', html)
    assert '<span class="page-tech">Scans</span>' in html
    assert 'content="light dark"' in html


def test_stale_banner_shows_on_every_page_when_the_check_is_old(web_app, memory_conn):
    old = (datetime.now(timezone.utc) - timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
    memory_conn.execute("INSERT INTO scans(kind, started_at, finished_at, status) VALUES('discovery',?,?,'ok')", (old, old))
    memory_conn.commit()
    client = web_app.test_client()
    for path in ("/scans", "/settings", "/telemetry"):
        html = client.get(path).get_data(as_text=True)
        banner = re.search(r'<div class="status-banner is-stale stale-banner" id="stale-banner"[^>]*>', html).group(0)
        assert "hidden" not in banner, path
        assert "Home SOC last checked your network <b>8 days ago</b>" in html
        assert "what you see may be out of date" in html
        assert "Network last checked 8 days ago" in html and "is-stale" in html


def test_fresh_check_hides_the_banner(web_app, memory_conn):
    recent = (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    memory_conn.execute("INSERT INTO scans(kind, started_at, finished_at, status) VALUES('discovery',?,?,'ok')", (recent, recent))
    memory_conn.commit()
    html = web_app.test_client().get("/scans").get_data(as_text=True)
    assert re.search(r'id="stale-banner"[^>]*\shidden', html)
    assert "Network last checked 2 minutes ago" in html


def test_polling_relabels_the_page_clock_and_keeps_the_banner_current():
    """app.js must not write a bare "updated <time>" (it reads as a network check), and it must
    keep the stale banner and the "Network last checked" line current on a screen left up."""
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "'updated '" not in js
    assert "'Screen refreshed '" in js
    assert "function renderStaleness(s)" in js and "renderStaleness(s);" in js
    assert "Math.min(3 * minutes, 24 * 60)" in js  # the same rule as app.staleness
    assert "chance of" not in js.lower()
