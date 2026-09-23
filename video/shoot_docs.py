"""Render the documentation screenshots in ``docs/images/`` from the demo database.

``python video/shoot_docs.py`` starts a throwaway dashboard against a copy of
``video/demo_data`` — the *fictional* household :mod:`seed_demo` builds — drives it with the
installed Google Chrome, and writes thirteen PNGs that ``README.md`` and ``docs/`` link to.

Nothing here ever looks at the real ``data/`` directory or ``config.toml``. The dashboard is
started exactly the way :mod:`capture` starts it (``HOMESOC_DATA`` pointed at a copy under
``video/build/``, a generated token-free config), so every pixel comes from ``HOME-PC``,
``Home-WiFi``, ``203.0.113.42`` and the eighteen invented devices. If a shot ever showed a
real hostname, the data directory would be the thing at fault, not this script.

How a shot is taken
-------------------
Viewport 1600x900 CSS at ``device_scale_factor=2``, day theme (the default), so Chrome renders a
3200x1800 image; :mod:`PIL` then downsamples it to 1600x900 and writes an optimised PNG.
Text ends up crisp and the files stay a few hundred kilobytes instead of a few megabytes.

Between-run jitter is killed the same way :mod:`capture` kills it: its ``FREEZE_CSS`` (no
animations, no scrollbars, no focus rings), its ``FREEZE_JS`` (pins the sidebar's "Screen
refreshed h:mm" label), and Playwright's fixed clock. The working copy's timestamps are moved
forward (:func:`freshen`) so the household reads as checked five minutes ago.

Web blocking is really running, exactly as in the film: ``capture.Dashboard`` starts the demo
dashboard through ``capture``'s launcher, which asks the product's own ``Runtime.start_dns()`` for
the embedded resolver on 127.0.0.1 and a free high port (never 53, never the LAN). Before the first
shot, ``capture.verify_blocking_running`` refuses to continue unless Home, the Blocking chip, the
sidebar and the Blocking page all say it is running. Nothing is repainted. The film's redactions
(the unbranded router, brand domains on Blocking) are a film rule and are not applied here.

Scroll offsets are not hand-tuned pixel numbers. Each shot names the thing that has to be on
screen (``reveal=``, or ``foot=True`` for "the last screenful") and the page is scrolled by
the smallest amount that brings it into view; ``snap=`` keeps the top edge of the frame from
slicing through a tile. So the shots survive a reseed that makes a table one row longer.

Usage::

    python video/shoot_docs.py              # all thirteen
    python video/shoot_docs.py --only 03-summary,10-dns-filter
    python video/shoot_docs.py --probe      # print page/element geometry, write nothing
    python video/shoot_docs.py --headed     # watch it work
"""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import sys
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final

HERE: Final[Path] = Path(__file__).resolve().parent
PROJECT_ROOT: Final[Path] = HERE.parent
if str(HERE) not in sys.path:  # so `python video/shoot_docs.py` finds capture.py / slides.py
    sys.path.insert(0, str(HERE))

import capture  # noqa: E402  - the proven dashboard/browser machinery, reused wholesale

OUT_DIR: Final[Path] = PROJECT_ROOT / "docs" / "images"
DEMO_DATA: Final[Path] = HERE / "demo_data"
SEED_SCRIPT: Final[Path] = HERE / "seed_demo.py"

#: Its own port, work copy, config and log so a `capture.py` run in another window cannot
#: collide with this one (capture.py owns 8899 / build/demo_data_run / build/demo_config.toml).
PORT: Final[int] = 8911
WORK_DATA: Final[Path] = capture.BUILD / "docs_shots_data"
DEMO_CONFIG: Final[Path] = capture.BUILD / "docs_shots_config.toml"
DASHBOARD_LOG: Final[Path] = capture.BUILD / "docs_shots_dashboard.log"

VIEWPORT_W: Final[int] = 1600
VIEWPORT_H: Final[int] = 900
SCALE: Final[int] = 2
#: Breathing room kept between a revealed element and the edge of the frame.
PAD: Final[int] = 18

logger = logging.getLogger("homesoc.video.shoot_docs")


class ShootError(RuntimeError):
    """Anything that stops the shoot, always naming the image at fault."""


# --------------------------------------------------------------------------- fresh demo data

_TS: Final = re.compile(r"^(\d{4}-\d{2}-\d{2})(T\d{2}(?::\d{2}(?::\d{2}(?:\.\d+)?)?)?)?(Z|[+-]\d{2}:\d{2})?$")


def _shifter(delta: timedelta):
    def shift(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        m = _TS.match(value)
        if not m:
            return value
        date, tpart, tz = m.group(1), m.group(2) or "", m.group(3) or ""
        if not tpart:
            return (datetime.strptime(date, "%Y-%m-%d") + delta).strftime("%Y-%m-%d")
        body = date + tpart
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H"):
            try:
                return (datetime.strptime(body, fmt) + delta).strftime(fmt) + tz
            except ValueError:
                continue
        return value
    return shift


def freshen(db: Path) -> None:
    """Move every timestamp in the WORKING COPY forward so its last network check was five
    minutes ago. The seeded household is days old by the time anyone regenerates the docs, and a
    stale picture would put the "last checked 8 days ago" banner (correctly) on every image.
    Only ``video/build/`` is touched; ``video/demo_data`` stays exactly as seeded."""
    conn = sqlite3.connect(db)
    try:
        last = conn.execute("SELECT max(finished_at) FROM scans WHERE kind='discovery'").fetchone()[0]
        if not last:
            return
        then = datetime.strptime(str(last)[:19], "%Y-%m-%dT%H:%M:%S")
        delta = datetime.now(timezone.utc).replace(tzinfo=None) - then - timedelta(minutes=5)
        conn.create_function("shift_ts", 1, _shifter(delta), deterministic=True)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for t in tables:
            for col in [r[1] for r in conn.execute(f'PRAGMA table_info("{t}")')]:
                where = (f'WHERE typeof("{col}")=\'text\' AND '
                         f'"{col}" GLOB \'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*\'')
                try:
                    conn.execute(f'UPDATE "{t}" SET "{col}"=shift_ts("{col}") {where}')
                except sqlite3.IntegrityError:  # a unique key: step aside, then shift
                    conn.execute(f'UPDATE "{t}" SET "{col}"=\'~\' || "{col}" {where}')
                    conn.execute(f'UPDATE "{t}" SET "{col}"=shift_ts(substr("{col}", 2)) '
                                 f'WHERE typeof("{col}")=\'text\' AND "{col}" GLOB \'~*\'')
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- injected JS

#: Resolve ``"card:Posture checks"`` to the ``<section class="card">`` whose ``<h2>`` starts
#: with that text, anything else to ``document.querySelector``, and report where it sits in
#: *document* space (``rect.top + scrollY``) so a scroll offset can be computed from it.
FIT_JS: Final[str] = """
(spec) => {
  const pick = (s) => {
    if (s.startsWith('card:')) {
      const want = s.slice(5).trim().toLowerCase();
      for (const sec of document.querySelectorAll('section.card')) {
        const h = sec.querySelector('h2');
        if (h && h.textContent.trim().toLowerCase().startsWith(want)) return sec;
      }
      return null;
    }
    return document.querySelector(s);
  };
  const el = pick(spec);
  const doc = Math.max(document.documentElement.scrollHeight, document.body.scrollHeight);
  if (!el) return { found: false, doc };
  const r = el.getBoundingClientRect();
  return {
    found: true,
    doc,
    top: Math.round(r.top + window.scrollY),
    bottom: Math.round(r.bottom + window.scrollY),
    height: Math.round(r.height),
  };
}
"""

#: Document-space ``[top, bottom]`` of every element matching a selector, so a frame edge can
#: be pushed clear of a tile it would otherwise slice through.
EDGES_JS: Final[str] = """
(sel) => Array.from(document.querySelectorAll(sel)).map(el => {
  const r = el.getBoundingClientRect();
  return [Math.round(r.top + window.scrollY), Math.round(r.bottom + window.scrollY)];
})
"""

#: Several panels (DNS query log, telemetry events/metrics) fill themselves from the API after
#: first paint and say "Loading…" until they do. A shot of a spinner is a wasted shot.
LOADED_JS: Final[str] = """
() => {
  const text = document.body ? (document.body.innerText || '') : '';
  return !text.includes('Loading\\u2026') && !text.includes('Loading...');
}
"""

#: Chrome's own find-bar-free way to confirm the frame is not an empty state: the dashboard
#: prints ``<td class="empty">`` / ``<li class="muted">`` placeholders when a table has no rows.
EMPTY_JS: Final[str] = """
() => Array.from(document.querySelectorAll('.empty'))
  .filter(el => el.offsetParent !== null)
  .map(el => (el.textContent || '').trim().slice(0, 80))
"""


# --------------------------------------------------------------------------- the shot list


class Shot:
    """One documentation PNG.

    ``path``     dashboard route (or ``None`` for a slide).
    ``reveal``   what must be on screen; the page is scrolled the least amount that gets its
                 bottom edge into the frame. ``None`` means "the top of the page".
    ``snap``     repeated blocks the frame's top edge must not slice through.
    ``foot``     scroll to the foot of the document instead — for a page whose last screenful
                 is the interesting one, and with no pixel number to go stale.
    ``click``    a selector clicked before the shot (expands the finding detail row).
    ``slide``    a ``video/slides.py`` name, rendered instead of a dashboard page.
    """

    def __init__(
        self,
        name: str,
        *,
        path: str | None = None,
        reveal: str | None = None,
        snap: str | None = None,
        foot: bool = False,
        click: str | None = None,
        slide: str | None = None,
        shows: str = "",
    ) -> None:
        self.name = name
        self.path = path
        self.reveal = reveal
        self.snap = snap
        self.foot = foot
        self.click = click
        self.slide = slide
        self.shows = shows

    @property
    def filename(self) -> str:
        return f"{self.name}.png"


SHOTS: Final[tuple[Shot, ...]] = (
    Shot(
        "01-overview", path="/",
        shows="Home (the overview): the one-sentence status, the safety score, what needs fixing "
              "by urgency, the devices, web blocking over 24 hours and what to fix first.",
    ),
    Shot(
        "02-activity-feed", path="/feed",
        shows="What happened (the activity feed): one timeline of everything that happened, with "
              "each row's urgency in words, and the chips and filters that narrow it.",
    ),
    Shot(
        "03-summary", path="/summary", reveal="#chart-found-remediated",
        shows="Your safety report (the security summary): score, found all time, fixed and still "
              "to fix, over the found-and-fixed-by-urgency chart.",
    ),
    Shot(
        "04-findings", path="/findings?status=open",
        shows="Things to fix (the findings list): what needs attention, most urgent first, each "
              "with its plain headline, why it matters and the device it is on.",
    ),
    Shot(
        "05-finding-detail", path="/findings?status=open&severity=critical",
        click='#findings-table tbody tr.expandable[data-category="lan-services"]',
        reveal='#findings-table tr.expandable[data-category="lan-services"] + tr.detail-row',
        shows="A \"Fix now\" finding opened: the exposed Telnet service on the unnamed camera, "
              "with what Home SOC found, how to fix it, and the technical details one click away.",
    ),
    Shot(
        "06-devices", path="/devices",
        shows="Devices: every device by name with its address beside it, its kind, whether it "
              "was seen at the last check, what it has to fix and whether it is yours.",
    ),
    Shot(
        # The identity card is as tall as the seven-day presence table beside it, so the last
        # screenful is the one worth showing: services, matched CVEs and findings together.
        "07-device-detail", path="/devices/18", foot=True,
        shows="One device in detail — the unnamed camera: its open doors (ports), the known "
              "software flaw matched against its web server, and what depends on what.",
    ),
    Shot(
        # The table is only seven rows, so the frame would be two thirds empty. Expanding the
        # one KEV row fills it with the thing the page is for: why this CVE, on what evidence,
        # and what to do — while the KEV badge and the EPSS column stay in shot above it.
        "08-vulnerabilities", path="/vulns",
        click="#vulns-table tbody tr.expandable:first-child",
        shows="Known software flaws (the CVE table): whether attackers are known to use each one "
              "(KEV), how bad it could be (CVSS) and the chance it is exploited somewhere in the "
              "next 30 days (EPSS), with the KEV row opened.",
    ),
    Shot(
        # Defender sits at the top (112-532) and the posture grid starts at 546, so the top of
        # the page is the only offset that gets both into one frame.
        "09-host-posture", path="/host",
        shows="This computer (host posture on Windows): the antivirus panel, pending updates, and "
              "the safety settings with what was found.",
    ),
    Shot(
        # /dns is 4700px tall and no single 900px frame holds all of it. The top gives the two
        # numbers the page exists for — queries and block rate — the per-hour chart and the top
        # blocked domains; the live query log is the same page, 1800px further down.
        "10-dns-filter", path="/dns",
        shows="Web blocking (the DNS filter): look-ups and blocks over 24 hours, the per-hour "
              "chart, and the websites being blocked most, with the reason in words.",
    ),
    Shot(
        "11-telemetry", path="/telemetry", reveal="card:Background jobs", snap=".metrics-grid > *",
        shows="System health (telemetry): whether each of Home SOC's background jobs is working, "
              "in plain words, with the technical job table one click away.",
    ),
    Shot(
        "12-scans", path="/scans",
        shows="Checks (scan history): when each check last ran and how it went, with the full "
              "history one click away.",
    ),
    Shot(
        "13-architecture", slide="architecture",
        shows="The architecture diagram: definition feeds into scanners, scanners into the "
              "findings engine, and the engine into the dashboard, alerts and the DNS filter.",
    ),
)

SHOTS_BY_NAME: Final[dict[str, Shot]] = {s.name: s for s in SHOTS}


# --------------------------------------------------------------------------- helpers


def ensure_demo_db() -> Path:
    """The seeded demo database, building it if this is a fresh checkout."""
    db = DEMO_DATA / "homesoc.db"
    if db.is_file():
        return DEMO_DATA
    print(f"  {db} is missing - running seed_demo.py --force", flush=True)
    import subprocess

    result = subprocess.run(
        [sys.executable, str(SEED_SCRIPT), "--force"],
        cwd=str(PROJECT_ROOT), check=False,
    )
    if result.returncode != 0 or not db.is_file():
        raise ShootError(
            f"seed_demo.py exited {result.returncode} and {db} still does not exist - the "
            "screenshots cannot be taken without the fictional demo database."
        )
    return DEMO_DATA


def compute_scroll(page: Any, spec: str, *, shot: str, snap: str | None = None) -> int:
    """The smallest scroll offset that puts ``spec``'s bottom edge inside the frame.

    ``snap`` names repeated blocks (a grid of metric tiles) that the top edge of the frame
    must not cut through: if the computed offset would slice one, the frame is pushed down to
    just below it — but only while ``spec`` itself stays whole in shot.
    """
    info = page.evaluate(FIT_JS, spec)
    if not info.get("found"):
        raise ShootError(
            f"{shot}: nothing on the page matches {spec!r}, so the shot cannot be framed. "
            "Fix the selector in SHOTS rather than guessing a pixel offset."
        )
    top, bottom, height = int(info["top"]), int(info["bottom"]), int(info["height"])
    limit = max(0, int(info["doc"]) - VIEWPORT_H)
    if height > VIEWPORT_H - 2 * PAD:
        # Taller than the frame: show it from its top and accept that it runs off the bottom.
        wanted = top - PAD
        logger.info(
            "%s: %r is %dpx tall, taller than the %dpx frame; anchoring to its top",
            shot, spec, height, VIEWPORT_H,
        )
    else:
        wanted = bottom + PAD - VIEWPORT_H
    scroll = max(0, min(limit, wanted))

    if snap:
        for edge_top, edge_bottom in page.evaluate(EDGES_JS, snap) or []:
            if edge_top < scroll < edge_bottom:
                candidate = min(limit, edge_bottom)
                if candidate > scroll and top >= candidate and bottom <= candidate + VIEWPORT_H:
                    logger.info(
                        "%s: top edge cut a %r block at %d-%d; snapping %d -> %d",
                        shot, snap, edge_top, edge_bottom, scroll, candidate,
                    )
                    scroll = candidate
                break
    return scroll


def wait_loaded(page: Any, *, shot: str) -> None:
    with suppress(Exception):
        page.wait_for_function(LOADED_JS, timeout=15_000)
    page.wait_for_timeout(250)


def empty_states(page: Any) -> list[str]:
    try:
        return list(page.evaluate(EMPTY_JS) or [])
    except Exception:  # noqa: BLE001 - a diagnostic must never fail the shoot
        return []


def downscale(src: Path, dest: Path) -> int:
    """3200x1800 -> an optimised 1600x900 PNG. Returns the written size in bytes."""
    from PIL import Image

    with Image.open(src) as img:
        rgb = img.convert("RGB")
        small = rgb.resize((VIEWPORT_W, VIEWPORT_H), Image.LANCZOS)
        dest.parent.mkdir(parents=True, exist_ok=True)
        small.save(dest, format="PNG", optimize=True, compress_level=9)
    return dest.stat().st_size


# --------------------------------------------------------------------------- the shoot


def shoot(
    *,
    only: list[str] | None = None,
    headed: bool = False,
    probe: bool = False,
) -> list[tuple[str, int, int]]:
    """Take every wanted shot. Returns ``(filename, scroll, bytes)`` per image."""
    from playwright.sync_api import sync_playwright

    wanted = [s for s in SHOTS if only is None or s.name in only]
    if not wanted:
        raise ShootError("nothing to do - --only matched no shot names")

    data_dir = ensure_demo_db()

    # capture.py's Dashboard/Capturer read these module globals; point them at this script's
    # own port, working copy, config and log so the two harnesses never fight over a file.
    capture.PORT = PORT
    capture.BASE_URL = f"http://127.0.0.1:{PORT}"
    capture.WORK_DATA = WORK_DATA
    capture.DEMO_CONFIG = DEMO_CONFIG
    capture.DASHBOARD_LOG = DASHBOARD_LOG

    # The architecture diagram (13) is a slides.py slide; capture.py now defaults to the
    # everyday film's slide module, which has no such slide.
    capture.SLIDES_MODULE = "slides"
    registry = capture.load_slides()
    tmp_dir = capture.BUILD / "docs_shots_raw"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.now().replace(second=0, microsecond=0)
    # The sidebar line is the SCREEN's refresh time, never a network check (app.js words it the
    # same way); pinned so two runs of the same shoot give identical pixels.
    frozen_label = "Screen refreshed " + now.strftime("%I:%M %p").lstrip("0")
    # The film's REDACTIONS (unbranded router, blurred brand domains) are a film rule, not a
    # documentation one: the docs show the demo household's pages as the product draws them.
    capture.REDACT = False

    needs_dashboard = any(s.slide is None for s in wanted)
    written: list[tuple[str, int, int]] = []

    dashboard: capture.Dashboard | None = None
    browser = None
    with sync_playwright() as p:
        try:
            if needs_dashboard:
                work = capture.make_working_copy(data_dir)
                freshen(work / "homesoc.db")
                # freshen() moved feeds.last_updated forward; date the blocklist files to match,
                # or the running resolver (rightly) reports them as stale.
                capture.sync_blocklist_mtimes(work)
                dashboard = capture.Dashboard(
                    data_dir=work, port=PORT,
                    # Plain HTTP on loopback, matching BASE_URL above: no Lens page is shot here,
                    # and capture.Dashboard now defaults to --tls for the video's Lens scenes.
                    tls=False,
                )
                dashboard.start()

            browser = p.chromium.launch(channel="chrome", headless=not headed)
            context = browser.new_context(
                viewport={"width": VIEWPORT_W, "height": VIEWPORT_H},
                device_scale_factor=SCALE,
                color_scheme="light",   # the day theme, which is what a new install shows
                reduced_motion="reduce",
                base_url=capture.BASE_URL,
            )
            context.set_default_timeout(capture.NAV_TIMEOUT_MS)
            with suppress(Exception):
                context.clock.set_fixed_time(now)
            capture._strip_csp(context)
            page = context.new_page()
            cap = capture.Capturer(page, frozen_label=frozen_label)
            if needs_dashboard and not probe:
                # The same gate the film passes: the real resolver, reading "running" on its own.
                capture.verify_blocking_running(cap)

            for i, s in enumerate(wanted, start=1):
                scroll = 0
                if s.slide is not None:
                    cap.set_content(capture.slide_html(registry, s.slide, scene_id=s.name))
                    cap.current_path = None
                else:
                    cap.goto(str(s.path))
                    wait_loaded(page, shot=s.name)
                    if s.click:
                        rect = cap.rect(s.click, scene_id=s.name)
                        cap.click_at(
                            rect[0] + rect[2] / 2, rect[1] + rect[3] / 2, scene_id=s.name
                        )
                        page.wait_for_timeout(400)
                    if s.foot:
                        scroll = int(page.evaluate(
                            "() => Math.max(0, Math.max(document.documentElement.scrollHeight,"
                            " document.body.scrollHeight) - window.innerHeight)"
                        ))
                        cap.scroll_to(scroll)
                    elif s.reveal:
                        scroll = compute_scroll(page, s.reveal, shot=s.name, snap=s.snap)
                        cap.scroll_to(scroll)
                    else:
                        cap.scroll_to(0)

                if probe:
                    doc_h = page.evaluate(
                        "() => Math.max(document.documentElement.scrollHeight,"
                        " document.body.scrollHeight)"
                    ) if s.slide is None else VIEWPORT_H
                    print(
                        f"  [{i:02d}/{len(wanted)}] {s.name:<20} path={s.path} "
                        f"doc={doc_h}px scroll={scroll} empty={empty_states(page)}",
                        flush=True,
                    )
                    continue

                raw = tmp_dir / f"{s.name}@2x.png"
                cap.shoot(raw)
                size = downscale(raw, OUT_DIR / s.filename)
                empties = empty_states(page)
                written.append((s.filename, scroll, size))
                print(
                    f"  [{i:02d}/{len(wanted)}] {s.filename:<24} scroll={scroll:<5} "
                    f"{size / 1024:6.0f} KiB"
                    + (f"  EMPTY STATES VISIBLE: {empties}" if empties else ""),
                    flush=True,
                )
        finally:
            if browser is not None:
                with suppress(Exception):
                    browser.close()
            if dashboard is not None:
                dashboard.stop()

    return written


# --------------------------------------------------------------------------- README


README_HEAD: Final[str] = """\
# Documentation screenshots

**Every screenshot here is of the fictional demo network** created by
[`video/seed_demo.py`](../../video/seed_demo.py) — an invented family home whose PC is called
`HOME-PC`, on a Wi-Fi network called `Home-WiFi`, behind the RFC 5737 documentation address
`203.0.113.42`, with eighteen made-up devices. It is not a real home, and nothing in these
images comes off anybody's real network: no real hostname, no real MAC address, no real public
IP. (`13-architecture.png` is not a screenshot at all — it is the architecture diagram, drawn
by [`video/slides.py`](../../video/slides.py).)

Regenerate them all with:

```
python video/seed_demo.py --force     # only if video/demo_data/homesoc.db is missing
python video/shoot_docs.py
```

Each image is 1600x900, rendered in the day theme ("Stone & Sage", the default) at 2x and
downsampled, so the text stays sharp on a high-DPI display. The dusk theme looks the same in
a warm dark palette.

Web blocking is genuinely running in these images. A plain `serve` never starts the resolver,
so the demo server is started through the film's capture launcher, which runs the product's own
embedded resolver (the same `Runtime.start_dns()` that `homesoc run` uses) on `127.0.0.1` at a
free high port, never port 53 and never the LAN. Before the first shot the script checks that
Home, the Blocking chip, the sidebar and the Blocking page all report it running; nothing is
repainted. That is why the Blocking page's technical details show `127.0.0.1:<port>` rather
than a household's `0.0.0.0:53`. No query is sent to it, so the look-up and block numbers are
the seeded household's last 24 hours. The demo's timestamps are moved forward so it reads as
checked a few minutes ago.

| Image | What it shows |
| --- | --- |
"""


def write_readme() -> Path:
    lines = [README_HEAD]
    for s in SHOTS:
        lines.append(f"| [`{s.filename}`]({s.filename}) | {s.shows} |\n")
    dest = OUT_DIR / "README.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("".join(lines), encoding="utf-8")
    return dest


# --------------------------------------------------------------------------- driver


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render the docs/images/ screenshots from the fictional demo database."
    )
    parser.add_argument("--only", metavar="NAME[,NAME]", help="only take these shots")
    parser.add_argument("--probe", action="store_true", help="print geometry, write no PNGs")
    parser.add_argument("--headed", action="store_true", help="show the browser window")
    parser.add_argument("--no-readme", action="store_true", help="skip docs/images/README.md")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    only: list[str] | None = None
    if args.only:
        only = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in only if n not in SHOTS_BY_NAME]
        if unknown:
            print(f"shoot_docs: unknown shot(s): {', '.join(unknown)}", file=sys.stderr)
            print(f"known: {', '.join(SHOTS_BY_NAME)}", file=sys.stderr)
            return 2

    print(
        f"shoot_docs: data={DEMO_DATA} port={PORT} "
        f"viewport={VIEWPORT_W}x{VIEWPORT_H}@{SCALE}x -> {OUT_DIR}"
    )
    try:
        written = shoot(only=only, headed=args.headed, probe=args.probe)
    except (ShootError, capture.CaptureError) as exc:
        print(f"\nshoot_docs: FAILED\n{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nshoot_docs: interrupted", file=sys.stderr)
        return 130

    if args.probe:
        return 0
    if not args.no_readme:
        print(f"\n  {write_readme()}")
    total = sum(size for _, _, size in written)
    print(f"  {len(written)} image(s), {total / 1024:.0f} KiB total, in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
