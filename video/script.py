"""The narration and action script for the Home SOC walkthrough video.

This module is **data and type definitions only**. It contains no pipeline logic: nothing
here seeds a database, launches a browser, calls a text-to-speech service or writes a
frame. `narrate.py`, `capture.py` and `compose.py` import :data:`SCENES` and do all of
that.

Contract
--------
The dataclasses below are the ones named in ``video/CONTRACT.md`` section 2. Timings on
actions are **fractions of that scene's measured narration duration** (0.0 = the first
syllable, 1.0 = the last), so the visuals follow the voice automatically however long
edge-tts decides a sentence takes.

Conventions the other packages rely on
--------------------------------------
1. **Selector strings** are always ``"css=<selector>"`` (or ``"xy=(x, y)"`` for a raw
   point). Every selector in this file was written against the real Jinja templates in
   ``homesoc/web/templates/`` and is intended to resolve to exactly **one** element on
   the shot that is on screen when the action fires. ``capture.py`` must fail loudly with
   the scene id and the selector if one does not resolve — never silently place the cursor
   at the origin. Exactly one selector deliberately matches several elements
   (``NEEDS_ADMIN_BADGE`` — several checks carry that badge); the rule there is **first in
   document order wins**, which is what Playwright's ``.first`` gives you.
2. **Scroll states are declared, not implied.** Whenever a scene scrolls, its shot is a
   :class:`PageSequence` whose members carry the exact ``scroll`` offsets used, and every
   :class:`Scroll` action's ``to_y`` equals one of those offsets. :func:`validate` checks
   this. So ``capture.py`` only ever has to screenshot the offsets it is handed. Each
   non-zero offset carries a ``note`` naming the element it has to bring into view: the
   numbers were chosen against the real page structure, but the exact pixel depends on how
   many rows ``seed_demo.py`` writes, so nudge the number until the note is true.
   ``capture.py`` must clamp every offset to ``max(0, scrollHeight - 900)`` and log a
   warning when it does, rather than silently screenshotting the bottom of the page.
3. **Selectors used after a Click must be measured on the after-state.** In scene
   ``06-findings`` the remediation list and the Acknowledge button live inside a
   ``<tr class="detail-row" hidden>`` that only becomes visible once the row above it has
   been clicked. A hidden element has no box, so ``capture.py`` must resolve geometry for
   actions whose ``at`` is later than a Click's ``at`` **after** performing that click.
4. **Only ``<select>`` elements auto-submit.** ``static/app.js`` binds
   ``form[data-submit-on-change]`` to the ``change`` event of its selects only, so ticking
   the Vulnerabilities page's "KEV only" checkbox does *not* navigate — scene 8 therefore
   ticks the box and then clicks **Apply**, which is what a person would do anyway. The
   Findings page's severity strip is a plain ``<a>``, so one click there does navigate.
5. **Numbers spoken out loud** are not written into the prose by hand. They come from the
   placeholder constants below and are interpolated with ``.format(**NUMBERS)``. When
   ``seed_demo.py`` settles, reconcile the constants in one place and the narration is
   correct everywhere. Every one of them is marked ``TODO(seed)``.

What this script needs from ``seed_demo.py``
--------------------------------------------
Four things, beyond what ``CONTRACT.md`` section 1 already asks for, because the shots
below point straight at them:

* **Exactly two open criticals** — ``NET-SVC-001`` on the camera and ``NET-VUL-001`` on the
  gateway. Scene 6 filters to open criticals and expects two rows, and picks the Telnet one
  out by ``data-category="lan-services"`` (``api.category_for`` reads the category off the
  catalog spec, so ``NET-SVC-*`` is ``lan-services`` and ``NET-VUL-*`` is ``vulns``). Any
  other open critical whose category is ``lan-services`` would make that selector ambiguous.
* **Exactly one KEV row** in ``vulns``, on the gateway, so ``/vulns?kev=1`` has one row.
* **Defender status** lives in ``settings`` under the key ``defender.status_json``
  (``api.host_data`` reads it there, not from ``host_checks``), and at least one
  ``host_checks`` row with ``status='needs_admin'`` so scene 9's badge exists.
* **The camera's and gateway's ``devices.id``**, printed at the end of the seed run, so
  ``CAMERA_DEVICE_ID`` and ``GATEWAY_DEVICE_ID`` below can be corrected.

Voice
-----
Second person, calm, concrete, generous with the *why*, honest about the limits. Numerals
that a speech engine could mangle are spelled out ("port fifty-three", "eighty-eight
rules"); IP addresses are written as "192 dot 168 dot 1 dot 142" for the same reason.

Total narration is 1077 words. Synthesised for real with
``en-US-AndrewMultilingualNeural`` at ``-4%`` and measured with ffprobe, that is
**457.7 seconds — 7 minutes 38 seconds** of speech (about 141 words per minute once
punctuation pauses are counted), comfortably inside the contract's 6.5-8 minute window
with room for the scene transitions on top. Weighted toward the dashboard tour: scenes 5
to 12 carry about two thirds of it. Running this module as a script prints the per-scene
word count and a rough estimate, and runs :func:`validate`; the estimate uses 145 wpm and
so reads a few percent short of the measured figure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Union

log = logging.getLogger(__name__)

__all__ = [
    "Slide",
    "Page",
    "PageSequence",
    "Shot",
    "Move",
    "Click",
    "Scroll",
    "Highlight",
    "Zoom",
    "Action",
    "Scene",
    "SCENES",
    "NUMBERS",
    "SLIDE_NAMES",
    "validate",
]


# ---------------------------------------------------------------------------------------
# Placeholder constants — every number and identifier the voice says out loud.
#
# TODO(seed): reconcile every value in this block with what `video/seed_demo.py` actually
# writes into `video/demo_data/homesoc.db`. The render engineer should change these and
# nothing else; the narration interpolates them. `seed_demo.py` is asked to print the
# device row ids it created so CAMERA_DEVICE_ID / GATEWAY_DEVICE_ID can be filled in.
# ---------------------------------------------------------------------------------------

# -- the score, and why it is where it is ------------------------------------------------
# Two open criticals means findings/score.py clamps the score to 20 (one critical caps at
# 34, two or more at 20), so anything above 20 here would be impossible for the seeded
# data. Grade F follows from GRADE_BANDS. This is deliberate: it gives the video an honest
# subject and lets scene 5 explain the ceiling rule.
SCORE_NOW = 10
SCORE_GRADE = "F"

# -- finding counts ----------------------------------------------------------------------
# Two sets of numbers exist, because scene 6 really clicks Acknowledge on the Telnet
# finding and the dashboard really writes that to its database. Scenes 1-6 are captured
# before that click, scenes 7-14 after it. Measured on the seeded DB, before / after:
#   score 10 -> 13, open findings 33 -> 32, acknowledged 2 -> 3, open criticals 2 -> 1.
# Everything else (found 48, remediated 12, 27%, median 12.0 h) is unchanged by it.
# Scene 5 therefore speaks the "before" score and scene 12 the "after" open count.
FOUND_ALL_TIME = 48
RESOLVED_TOTAL = 12
OPEN_TOTAL = 33  # before scene 6's acknowledge
OPEN_AFTER_ACK = 32  # what /summary shows from scene 7 onwards
ACKNOWLEDGED_TOTAL = 2
SUPPRESSED_TOTAL = 1
REMEDIATION_RATE_PCT = 27  # what summary.py prints: resolved / (found - ack - suppressed)
MEDIAN_TTR_HOURS = 12
OPEN_CRITICAL = 2

# -- devices -------------------------------------------------------------------------------
DEVICES_TOTAL = 18
DEVICES_ONLINE = 17
# Spelled out because edge-tts reads "an 18-device network" as "an eighteen dash device
# network". Keep it in step with DEVICES_TOTAL.
DEVICES_TOTAL_SPOKEN = "eighteen"

# -- the star of the show: the unbranded IP camera -----------------------------------------
CAMERA_IP = "192.168.1.142"
CAMERA_IP_SPOKEN = "192 dot 168 dot 1 dot 142"
CAMERA_DEVICE_ID = 18  # verified: devices.id 18 == 192.168.1.142, the unbranded camera
TELNET_PORT = 23

# -- the gateway CVE -------------------------------------------------------------------------
# CVE-2023-1389 is a genuine CISA KEV entry (TP-Link Archer AX21 command injection, used by
# Mirai variants), and it is the single kev=1 row seed_demo.py writes.
GATEWAY_DEVICE_ID = 1  # verified: devices.id 1 == 192.168.1.1, the gateway
GATEWAY_CVE = "CVE-2023-1389"

# -- DNS ---------------------------------------------------------------------------------
# Deliberately approximate: the seed is relative to `now`, and the block bursts overshoot or
# undershoot their hourly budget, so the realised 24 h total moves a few tens of queries
# between seed runs. Measured 2,589 on the seed this video was captured from; "about twenty-six
# hundred" is true anywhere in 2,550-2,649. If a reseed lands outside that, change the words
# here rather than leaving the voice arguing with the number on the card.
DNS_QUERIES_24H_SPOKEN = "about twenty-six hundred"
DNS_BLOCK_PCT_SPOKEN = "close to a third"

# -- host posture --------------------------------------------------------------------------
DEFENDER_SIGNATURE_AGE_DAYS_SPOKEN = "a day"
DEFENDER_THREATS_30D_SPOKEN = "one threat"

# -- product facts (not seeded; these come from the repo) -------------------------------------
TEST_COUNT_SPOKEN = "seven hundred and nineteen"
RULE_COUNT_SPOKEN = "eighty-eight"

NUMBERS: dict[str, object] = {
    "score": SCORE_NOW,
    "grade": SCORE_GRADE,
    "found": FOUND_ALL_TIME,
    "resolved": RESOLVED_TOTAL,
    "open": OPEN_TOTAL,
    "open_after_ack": OPEN_AFTER_ACK,
    "rate": REMEDIATION_RATE_PCT,
    "ttr": MEDIAN_TTR_HOURS,
    "open_critical": OPEN_CRITICAL,
    "devices_total": DEVICES_TOTAL,
    "devices_total_spoken": DEVICES_TOTAL_SPOKEN,
    "devices_online": DEVICES_ONLINE,
    "camera_ip_spoken": CAMERA_IP_SPOKEN,
    "telnet_port": TELNET_PORT,
    "dns_queries": DNS_QUERIES_24H_SPOKEN,
    "dns_block_pct": DNS_BLOCK_PCT_SPOKEN,
    "sig_age": DEFENDER_SIGNATURE_AGE_DAYS_SPOKEN,
    "threats_30d": DEFENDER_THREATS_30D_SPOKEN,
    "tests": TEST_COUNT_SPOKEN,
    "rules": RULE_COUNT_SPOKEN,
}

# The six slides `slides.py` must render, by the exact names agreed with that package.
SLIDE_NAMES: tuple[str, ...] = (
    "title",
    "what_it_is",
    "architecture",
    "first_run",
    "daily_use",
    "close",
)


# ---------------------------------------------------------------------------------------
# Shots — what is on screen
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Slide:
    """A full-frame HTML card rendered by ``slides.py``.

    `html_fn` is one of :data:`SLIDE_NAMES`; ``capture.py`` renders it to
    ``build/shots/slide_<html_fn>.png``.
    """

    html_fn: str


@dataclass(frozen=True)
class Page:
    """A live dashboard page, captured at a given vertical scroll offset.

    `path` is served from ``http://127.0.0.1:8899`` with ``HOMESOC_DATA`` pointed at
    ``video/demo_data``. `scroll` is CSS pixels from the top of the document, in the
    1600x900 viewport. `note` is a human comment for the capture engineer and is never
    rendered.
    """

    path: str
    scroll: int = 0
    note: str = ""


@dataclass(frozen=True)
class PageSequence:
    """Several shots shown one after another inside a single scene.

    `shots[0]` is on screen from the start. `ats[i]` is the fraction of the scene at which
    `shots[i]` takes over; ``ats[0]`` is ignored and treated as 0.0. When `ats` is empty
    the shots split the scene evenly. Transitions between members are the usual 400 ms
    cross-dissolve, except that a change of scroll offset within the same `path` should be
    animated by the matching :class:`Scroll` action rather than dissolved.
    """

    shots: tuple["Shot", ...]
    ats: tuple[float, ...] = ()


Shot = Union[Slide, Page, PageSequence]


# ---------------------------------------------------------------------------------------
# Actions — cursor choreography, timed as fractions of the scene's narration duration
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Move:
    """Glide the cursor to a target, easing in and out. Never teleports.

    `to` is ``"css=<selector>"`` (the cursor lands on the element's centre) or
    ``"xy=(x, y)"`` in the 1600x900 CSS space. `seconds` is how long the glide takes;
    ``at`` is when it starts.
    """

    to: str
    at: float
    seconds: float = 0.9


@dataclass(frozen=True)
class Click:
    """Click wherever the cursor currently is — i.e. the target of the preceding Move.

    Plays the ripple, then cross-fades to `then_shot`, which is the state the real click
    actually produces. `capture.py` performs the click for real and screenshots the
    result; it does not synthesise the after-state.
    """

    at: float
    then_shot: Shot
    note: str = ""


@dataclass(frozen=True)
class Scroll:
    """Smoothly scroll the captured page from its current offset to `to_y`.

    `to_y` must match the `scroll` of one of the scene's declared :class:`Page` shots.
    """

    to_y: int
    at: float
    seconds: float = 1.2


@dataclass(frozen=True)
class Highlight:
    """Draw a soft glow around an element and dim the rest of the frame slightly."""

    sel: str
    at: float
    seconds: float = 2.0


@dataclass(frozen=True)
class Zoom:
    """A slow Ken Burns push toward a rectangle, in 1600x900 CSS pixels.

    Rects are approximate framing hints centred on what matters; the compositor clamps the
    push to at most 1.6x and keeps the rect inside the frame, so being a few dozen pixels
    off is harmless. Used three times in the whole video, on purpose.
    """

    to_rect: tuple[int, int, int, int]
    at: float
    seconds: float = 1.5


Action = Union[Move, Click, Scroll, Highlight, Zoom]


# ---------------------------------------------------------------------------------------
# Scene
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scene:
    """One narrated beat: some words, one thing on screen, and the cursor work over it."""

    id: str
    narration: str
    shot: Shot
    actions: list[Action] = field(default_factory=list)
    caption: str | None = None


def css(selector: str) -> str:
    """Format a CSS selector for :class:`Move` / :class:`Highlight`."""
    return "css=" + selector


def _n(text: str) -> str:
    """Interpolate the placeholder numbers into a narration string."""
    return " ".join(text.format(**NUMBERS).split())


# ---------------------------------------------------------------------------------------
# Selectors, named once so a template change is a one-line fix.
# Every one of these was checked against homesoc/web/templates/*.html and
# homesoc/web/app.py (NAV, the badge helper, CATEGORY_BY_PREFIX).
# ---------------------------------------------------------------------------------------

NAV_OVERVIEW = css('.sidebar .nav-link[href="/"]')
NAV_FEED = css('.sidebar .nav-link[href="/feed"]')
NAV_SUMMARY = css('.sidebar .nav-link[href="/summary"]')
NAV_FINDINGS = css('.sidebar .nav-link[href="/findings"]')
NAV_DEVICES = css('.sidebar .nav-link[href="/devices"]')
NAV_VULNS = css('.sidebar .nav-link[href="/vulns"]')
NAV_HOST = css('.sidebar .nav-link[href="/host"]')
NAV_DNS = css('.sidebar .nav-link[href="/dns"]')

# base.html topbar — unique, and always visible, which makes it a safe Highlight target.
CHIP_SCORE = css("#chip-score")
CHIP_DEVICES = css('.topbar-stats .chip[title="Devices online / total"]')
CHIP_DNS = css('.topbar-stats .chip[title="DNS queries in the last 24 h"]')

# overview.html
GAUGE = css("#chart-gauge")
TREND_SPARK = css("#chart-trend")
SEVERITY_DONUT = css("#chart-severity")
DEVICES_INVENTORY_LINK = css('a.link[href="/devices"]')
DNS_BARS = css("#chart-dns")
FIX_FIRST = css("#score-breakdown")
FEEDS_BODY = css("#feeds-body")
JOBS_CHIPS = css("#jobs-chips")

# findings.html — the severity strip links carry the exact query we want, so clicking one
# is a real navigation rather than a synthetic filter change.
FINDINGS_CRITICAL_LINK = css('.sev-counts a[href*="severity=critical"]')
# Both open criticals are NET-* rules, but api.category_for() takes the category from the
# catalog spec (falling back to CATEGORY_BY_PREFIX only when there is none), so NET-SVC-001
# is "lan-services" and NET-VUL-001 is "vulns". data-category therefore picks the Telnet row
# without anyone having to know its database row id. Verified against a live dashboard.
# Uniqueness holds because the page is filtered to open criticals: the other lan-services
# findings in the seed are high or below and are not listed here.
TELNET_ROW = css('#findings-table tbody tr.expandable[data-category="lan-services"]')
TELNET_DETAIL = css('#findings-table tr.expandable[data-category="lan-services"] + tr.detail-row')
TELNET_REMEDIATION = css(
    '#findings-table tr.expandable[data-category="lan-services"] + tr.detail-row .detail ol'
)
TELNET_ACK_BUTTON = css(
    '#findings-table tr.expandable[data-category="lan-services"] + tr.detail-row '
    'button[data-action="finding-status"][data-status="acknowledged"]'
)

# devices.html / device_detail.html
DEVICES_TABLE = css("#devices-table")
CAMERA_LINK = css(f'#devices-table a[href="/devices/{CAMERA_DEVICE_ID}"]')
# On device_detail.html the Services card is the only <section class="card"> that is a
# direct child of <main class="main"> — the others are nested inside .grid wrappers.
DEVICE_SERVICES_CARD = css(".main > section.card")
DEVICE_SERVICES_TABLE = css(".main > section.card table.tbl")
DEVICE_SCAN_BUTTON = css('button[data-action="device-scan"]')

# vulns.html
# Ticking the checkbox does NOT submit (app.js only wires selects), so Apply is a real,
# necessary second click — verified against a live dashboard, which then lands on
# /vulns?kev=1&min_cvss=&q= .
VULNS_KEV_CHECKBOX = css('form.filters input[name="kev"]')
VULNS_APPLY = css('form.filters button[type="submit"]')
VULNS_TABLE = css("#vulns-table")
VULNS_FIRST_ROW = css("#vulns-table tbody tr.expandable:first-child")
# vulns_list orders by `kev DESC` first, and the seed writes exactly one kev=1 row, so on the
# unfiltered page the first tbody child is the KEV row and the third (row 1 is expandable,
# row 2 is its hidden detail-row) is the first merely-theoretical one.
VULNS_SECOND_ROW = css("#vulns-table tbody tr.expandable:nth-child(3)")
# Columns of that row: 6 is Service (port, product, version), 7 is "Matched on" - the two
# cells the second half of scene 8 is actually about.
VULNS_SECOND_SERVICE = css("#vulns-table tbody tr.expandable:nth-child(3) td:nth-child(6)")
VULNS_SECOND_MATCHED = css("#vulns-table tbody tr.expandable:nth-child(3) td:nth-child(7)")

# host.html — .stat-row only exists in the Defender card; the standalone <section class="card">
# under <main> is the "Posture checks" card (Defender/Updates and Persistence/Listeners are
# inside .grid wrappers).
HOST_SCAN_BUTTON = css('button[data-action="scan"][data-kind="host"]')
DEFENDER_STATS = css(".stat-row")
DEFENDER_ACTIONS = css('button[data-action="defender"][data-op="quick-scan"]')
POSTURE_CARD = css(".main > section.card")
# _badge() lowercases the kind and turns "_" into "-", so status "needs_admin" renders as
# .badge-needs-admin. Several checks carry it (Secure Boot, TPM, BitLocker, the Security
# event log) — the first in document order is the one to point at.
NEEDS_ADMIN_BADGE = css(".badge-needs-admin")

# dns.html
DNS_HOURS_CHART = css("#chart-dns-hours")
DNS_OVERRIDE_FORM = css('form.inline-form input[name="domain"]')
# The log table itself is 2,455 px tall, so its centre can never be on screen and a
# glow around it would cover the whole frame. Point at the log card's head instead
# (the "Live query log" title plus its client/action filters) - one compact rect, and
# the rows the eye is being sent to start immediately below it. Only one .card-head
# exists on /dns.
DNS_QUERY_LOG = css(".card-head")
DNS_LOG_BODY = css("#log-body")
# The client filter sits in the query-log card's header, so it is on screen as soon as the
# card is — a safer cursor target than the tall table itself.
DNS_LOG_CLIENT_FILTER = css("#log-client")

# feed.html — base.html also links /feed.rss, but only as <a class="link">, so .btn is unique.
FEED_CHIPS = css(".feed-chips")
FEED_FILTERS = css("#feed-filters")
FEED_TIMELINE = css("#feed-timeline")
# #feed-timeline itself is 8,700 px tall on the seeded feed, so a glow around it would
# cover the whole frame and mean nothing. Point at one event instead. This matches every
# `li.tl-item`; first in document order wins, same rule as NEEDS_ADMIN_BADGE.
FEED_FIRST_ITEM = css("#feed-timeline li.tl-item")
FEED_RSS_BUTTON = css('a.btn[href="/feed.rss"]')

# summary.html
SUMMARY_LEDE = css(".lede")
SUMMARY_TREND = css("#chart-summary-trend")
FOUND_VS_REMEDIATED = css("#chart-found-remediated")
REMEDIATED_TABLE = css("#remediated-table")
WORKLIST_FIRST = css("article.work:first-of-type")
SUMMARY_EXPORT_MD = css('a.btn[href^="/api/summary/report.md"]')

# telemetry.html / scans.html / settings.html
TELEMETRY_JOBS = css("#jobs-body")
SCANS_FULL_BUTTON = css('button[data-action="scan"][data-kind="full"]')
SETTINGS_NOTIFY_TEST = css('button[data-action="notify-test"]')


# ---------------------------------------------------------------------------------------
# The script
# ---------------------------------------------------------------------------------------

SCENES: list[Scene] = [
    # -- 1 -------------------------------------------------------------------------------
    Scene(
        id="01-cold-open",
        narration=_n(
            """
            You know roughly what is on your home network. You do not know what any of it
            is listening on. You do not know whether your router is running software with
            a published hole in it, or whether Defender was switched off three weeks ago.
            This is Home SOC. It answers those questions, on a PC you already own.
            """
        ),
        shot=Slide(html_fn="title"),
        actions=[],
        caption=None,
    ),
    # -- 2 -------------------------------------------------------------------------------
    Scene(
        id="02-what-it-is",
        narration=_n(
            """
            Home SOC is one Python process. One SQLite file. One dashboard on localhost.
            No account, no cloud, no telemetry, nothing leaves the machine. It is also not
            an antivirus engine, and not an EDR. It does not hook the kernel or scan your
            files with a detection engine of its own. Defender stays the thing that
            catches malware. Home SOC is the thing that notices Defender was turned off.
            """
        ),
        shot=Slide(html_fn="what_it_is"),
        actions=[],
        caption="What it is",
    ),
    # -- 3 -------------------------------------------------------------------------------
    Scene(
        id="03-architecture",
        narration=_n(
            """
            Definitions come in on the left: CISA's known-exploited catalogue, EPSS
            exploit probabilities, the IEEE vendor database, DNS blocklists. Scanners go
            out in the middle, asking who is here, what each device is listening on, and
            whether any of it has a published CVE. What they see becomes a draft, and one
            findings engine — {rules} rules — sets the severity, writes the
            fix steps, and remembers. Scanners never decide a finding's life story; the
            engine owns that. Out the other side: the dashboard, a DNS resolver on port
            fifty-three, and a scheduler.
            """
        ),
        shot=Slide(html_fn="architecture"),
        actions=[],
        caption="Architecture",
    ),
    # -- 4 -------------------------------------------------------------------------------
    Scene(
        id="04-first-run",
        narration=_n(
            """
            Getting it running is a double-click. The launcher builds a virtual
            environment, installs three packages, creates the database, downloads the
            first two feeds, and starts the scheduler and the dashboard. About a minute
            before the link appears, and no administrator rights needed. The link carries a
            one-time token, which the browser trades for a cookie, so after that plain
            localhost is enough. Then give it five minutes before you judge it. The first
            full picture of an {devices_total_spoken}-device network lands inside that.
            """
        ),
        shot=PageSequence(
            shots=(
                Slide(html_fn="first_run"),
                Page(path="/", scroll=0, note="the dashboard as it looks on arrival"),
            ),
            # The dashboard arrives just before "Then give it five minutes" (frac 0.777),
            # so the sentence about an eighteen-device network lands over a topbar that is
            # already showing 17 / 18 devices rather than over the launcher slide.
            ats=(0.0, 0.76),
        ),
        actions=[
            # ...and the highlight goes on the device count the voice is quoting, not on the
            # score chip, which nothing in this scene mentions. Sentence starts at 0.852.
            Move(to=CHIP_DEVICES, at=0.84, seconds=0.9),
            Highlight(sel=CHIP_DEVICES, at=0.88, seconds=1.6),
        ],
        caption="First run",
    ),
    # -- 5 -------------------------------------------------------------------------------
    Scene(
        id="05-overview",
        narration=_n(
            """
            The Overview is the page you check daily. Top left, the security score.
            {score} out of a hundred, grade {grade}. That number is a ceiling, not an
            average: one open critical caps it at thirty-four, and two caps it at twenty.
            Two are open here, and the rest of the backlog takes it the rest of the way
            down. An A means nothing high or critical is open. The trend underneath is
            rising, which is the number that matters. Beside it, open findings by
            severity. Then devices, {devices_online} of {devices_total} online. Then a day
            of DNS. And here, fix these first: the finding types costing the most points,
            and how far the score climbs once each is cleared.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/", scroll=0),
                Page(path="/", scroll=300,
                     note="must frame the 'Fix these first' card (ol#score-breakdown) and "
                          "the feed freshness table"),
            ),
            ats=(0.0, 0.80),
        ),
        # Every `at` from the trend spark on is set from where its sentence actually starts in
        # the finished narration, not from an even spread. Measured on the SRT: "The trend
        # underneath is rising" begins at frac 0.551, "Beside it, open findings by severity"
        # at 0.658, "Then devices" at 0.719, "And here, fix these first" at 0.800. The
        # highlights used to land 2-3.5 s early, and the scroll took the DNS card off the top
        # of the page at the exact moment the voice named it.
        actions=[
            Move(to=GAUGE, at=0.04, seconds=1.0),
            Highlight(sel=GAUGE, at=0.09, seconds=2.4),
            # Measured: #chart-gauge is at (259, 156, 290, 128) with the trend spark
            # directly below it, so this frames the score and its trend together.
            Zoom(to_rect=(4, 15, 800, 450), at=0.13, seconds=2.2),
            Move(to=TREND_SPARK, at=0.51, seconds=0.8),
            Highlight(sel=TREND_SPARK, at=0.56, seconds=1.8),
            Move(to=SEVERITY_DONUT, at=0.63, seconds=0.9),
            Highlight(sel=SEVERITY_DONUT, at=0.67, seconds=1.6),
            Move(to=CHIP_DEVICES, at=0.70, seconds=0.9),
            Highlight(sel=CHIP_DEVICES, at=0.73, seconds=1.4),
            Move(to=DNS_BARS, at=0.76, seconds=0.7),
            Scroll(to_y=300, at=0.80, seconds=1.2),
            Move(to=FIX_FIRST, at=0.84, seconds=1.0),
            Highlight(sel=FIX_FIRST, at=0.88, seconds=2.4),
        ],
        caption="Overview",
    ),
    # -- 6 -------------------------------------------------------------------------------
    Scene(
        id="06-findings",
        narration=_n(
            """
            Every issue Home SOC has raised lives here. Filter to open criticals: there
            are {open_critical}. An unbranded camera at {camera_ip_spoken} has Telnet open on
            port twenty-three. Telnet sends passwords in clear text. It is how Mirai and
            its descendants take over cameras and DVRs, and nothing built this decade
            needs it. Open the row: the evidence Home SOC saw, then numbered steps. Turn
            Telnet off, or move the camera to the guest network. The last step is the nmap
            command to verify the fix. Acknowledge, resolve or suppress from right here —
            acknowledging keeps it visible without dominating the score.
            """
        ),
        shot=Page(path="/findings", scroll=0),
        actions=[
            Move(to=FINDINGS_CRITICAL_LINK, at=0.05, seconds=1.0),
            Click(
                at=0.11,
                then_shot=Page(path="/findings?status=open&severity=critical", scroll=0),
                note="real navigation: the severity strip link carries the query itself",
            ),
            Highlight(sel=TELNET_ROW, at=0.20, seconds=2.2),
            Move(to=TELNET_ROW, at=0.48, seconds=0.9),
            Click(
                # "Open the row: the evidence Home SOC saw, then numbered steps" starts at
                # frac 0.546 of this scene. At 0.43 the panel was already open, and being
                # zoomed into, a whole sentence before the voice asked for it.
                at=0.53,
                then_shot=Page(
                    path="/findings?status=open&severity=critical",
                    scroll=0,
                    note="the row's sibling tr.detail-row is no longer hidden; only two "
                    "rows are listed, so the whole detail fits in the 900px viewport",
                ),
                note="expands the finding — geometry for every action below must be "
                "measured on THIS after-state",
            ),
            Highlight(sel=TELNET_DETAIL, at=0.57, seconds=2.0),
            Move(to=TELNET_REMEDIATION, at=0.65, seconds=1.0),
            # Measured on the expanded row: <main> starts at x=220, the findings card at
            # x=242 w=1336, and the detail column pair at 267..903 and 917..1553. No 1000 px
            # window (the narrowest MAX_ZOOM allows) has both edges in a gutter, so a rect
            # drawn tightly round the remediation column was grown to 1000 px and then
            # clamped against the right edge of the page - left edge at x=600, straight
            # through the sentences in the DETAIL column, half-words and stray glyphs down
            # the side. x=232 sits in the 220..242 gutter and the right edge is the page own,
            # so nothing is sliced, and the sidebar - whose status footer the caption pill
            # covers - is out of frame entirely. A gentler 1.17x push, with the glow below
            # doing the pointing the crop used to do badly.
            Zoom(to_rect=(232, 120, 1368, 770), at=0.68, seconds=2.4),
            Highlight(sel=TELNET_REMEDIATION, at=0.73, seconds=2.8),
            Move(to=TELNET_ACK_BUTTON, at=0.84, seconds=1.0),
            Click(
                at=0.89,
                then_shot=Page(
                    path="/findings?status=open&severity=critical",
                    scroll=0,
                    note="status badge flips to 'acknowledged' and the toast fires",
                ),
            ),
        ],
        caption="Findings",
    ),
    # -- 7 -------------------------------------------------------------------------------
    Scene(
        id="07-devices",
        narration=_n(
            """
            The inventory is where that camera came from. {devices_total} devices: name,
            address, MAC, vendor, open ports, findings. Discovery
            reads the operating system's ARP table first, then sweeps gently for what it
            missed. Open the camera and you see why an unknown device matters:
            Telnet, RTSP, and an HTTP admin page that asks for nothing. Nothing here was
            exploited. Home SOC connected, read the banner the service volunteered, and
            wrote it down.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/devices", scroll=0),
                Page(path=f"/devices/{CAMERA_DEVICE_ID}", scroll=0),
                Page(
                    path=f"/devices/{CAMERA_DEVICE_ID}",
                    scroll=820,
                    note="frames the Services card (.main > section.card, measured at "
                         "y=1124 h=241 on this page) with the telnet, http and rtsp rows "
                         "visible; the page is 1,861 tall so 820 is well inside the max",
                ),
            ),
            ats=(0.0, 0.52, 0.64),
        ),
        actions=[
            Highlight(sel=DEVICES_TABLE, at=0.06, seconds=2.6),
            Move(to=CAMERA_LINK, at=0.42, seconds=1.1),
            Click(
                at=0.50,
                then_shot=Page(path=f"/devices/{CAMERA_DEVICE_ID}", scroll=0),
            ),
            Scroll(to_y=820, at=0.64, seconds=1.4),
            Highlight(sel=DEVICE_SERVICES_TABLE, at=0.70, seconds=2.8),
            Move(to=DEVICE_SERVICES_CARD, at=0.86, seconds=0.9),
        ],
        caption="Devices",
    ),
    # -- 8 -------------------------------------------------------------------------------
    Scene(
        id="08-vulnerabilities",
        narration=_n(
            """
            Vulnerabilities separates two things people blur together. Filter to KEV only,
            press apply, and one row survives: a known-exploited CVE on the gateway.
            Criminals are using it right now, and the EPSS probability agrees. Take the
            filter off, and everything else is theoretically vulnerable: a version string
            matching a published CVE. Inference, not proof. Backported patches and lying
            banners get it wrong in both directions, so an unconfirmed version is reported
            as possible, not certain. Install nmap if you can: without it Home SOC still
            finds open ports, but reads far fewer versions.
            """
        ),
        shot=Page(path="/vulns", scroll=0),
        actions=[
            # Sentence fractions this scene is cut to: "Filter to KEV only, press apply"
            # 0.100, "Criminals are using it right now" 0.267, "Take the filter off" 0.392,
            # "a version string matching a published CVE" 0.499, "Backported patches and
            # lying banners" 0.600, "Install nmap if you can" 0.823.
            Highlight(sel=VULNS_TABLE, at=0.04, seconds=2.0),
            Move(to=VULNS_KEV_CHECKBOX, at=0.12, seconds=1.0),
            Click(
                at=0.17,
                then_shot=Page(path="/vulns", scroll=0,
                               note="the box is now ticked; the page has NOT navigated"),
                note="a checkbox does not auto-submit this form — see docstring note 4",
            ),
            Move(to=VULNS_APPLY, at=0.20, seconds=0.7),
            Click(
                at=0.235,
                then_shot=Page(path="/vulns?kev=1&min_cvss=&q=", scroll=0,
                               note="exact query string the form produces; verified live"),
            ),
            Highlight(sel=VULNS_FIRST_ROW, at=0.28, seconds=2.4),
            # The scene spends its whole second half arguing KEV-versus-theoretical, and used
            # to do it over a page filtered down to the single KEV row - the "everything else"
            # was never on screen. Take the filter back off and put the full list up for it.
            Move(to=VULNS_KEV_CHECKBOX, at=0.33, seconds=0.9),
            Click(
                at=0.385,
                then_shot=Page(path="/vulns?kev=1&min_cvss=&q=", scroll=0,
                               note="the tick is gone; the page has NOT navigated yet"),
            ),
            Move(to=VULNS_APPLY, at=0.415, seconds=0.7),
            Click(
                at=0.445,
                then_shot=Page(path="/vulns?min_cvss=&q=", scroll=0,
                               note="an unticked checkbox is not submitted, so the query "
                                    "string keeps only the two empty fields"),
            ),
            Move(to=VULNS_SECOND_ROW, at=0.49, seconds=0.9),
            Highlight(sel=VULNS_SECOND_ROW, at=0.52, seconds=2.6),
            # "Matched on" is literally the column that says how the inference was made, and
            # the Service column is the product/version string nmap is what reads. Pointing
            # at them also keeps the second half of the scene moving: the page used to hold
            # one dead frame for nineteen seconds here.
            Move(to=VULNS_SECOND_MATCHED, at=0.62, seconds=0.9),
            Highlight(sel=VULNS_SECOND_MATCHED, at=0.66, seconds=2.6),
            Move(to=VULNS_SECOND_SERVICE, at=0.80, seconds=0.9),
            Highlight(sel=VULNS_SECOND_SERVICE, at=0.84, seconds=2.4),
        ],
        caption="Vulnerabilities",
    ),
    # -- 9 -------------------------------------------------------------------------------
    Scene(
        id="09-host-posture",
        narration=_n(
            """
            Host posture is the one machine Home SOC can see from the inside. Defender:
            real-time protection on, signatures {sig_age} old, {threats_30d} found in the
            last thirty days. It reads that state, it does not replace it, though it can
            trigger a quick scan or a signature update. Below, the posture checks:
            firewall, accounts, encryption, network. Two say needs administrator rather
            than fail: the built-in Administrator account, and TPM. Home SOC will not
            pretend it checked something it could not.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/host", scroll=0),
                Page(path="/host", scroll=560,
                     note="must frame the 'Posture checks' card (.main > section.card) "
                          "with at least one needs-administrator badge visible"),
            ),
            ats=(0.0, 0.56),
        ),
        actions=[
            Move(to=DEFENDER_STATS, at=0.09, seconds=1.0),
            Highlight(sel=DEFENDER_STATS, at=0.14, seconds=2.8),
            Move(to=DEFENDER_ACTIONS, at=0.38, seconds=0.9),
            Highlight(sel=DEFENDER_ACTIONS, at=0.43, seconds=1.6),
            Scroll(to_y=560, at=0.56, seconds=1.3),
            Highlight(sel=POSTURE_CARD, at=0.63, seconds=2.2),
            Move(to=NEEDS_ADMIN_BADGE, at=0.76, seconds=1.0),
            Highlight(sel=NEEDS_ADMIN_BADGE, at=0.81, seconds=2.2),
        ],
        caption="Host posture",
    ),
    # -- 10 ------------------------------------------------------------------------------
    Scene(
        id="10-dns-filter",
        narration=_n(
            """
            The DNS filter is optional, and it protects devices that cannot protect
            themselves. Point your router here and every phone, TV and smart plug in the
            house resolves through it. That is {dns_queries} queries in a day,
            {dns_block_pct} of them blocked: ads and trackers from the public lists, plus
            malware and
            phishing domains sent nowhere. Your own overrides beat every list. Two honest
            limits. If this PC sleeps, the house loses DNS. And a device using its own
            encrypted DNS never asks this resolver at all — you will not see it here, and
            you cannot filter it.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/dns", scroll=0),
                Page(path="/dns", scroll=520,
                     note="must frame the 'Top blocked domains' and 'Top clients' cards"),
                # Measured on the seeded page (scrollHeight 4,617): the override form sits
                # at y=1,269 and the live query log's rows start at 1,757 in 40 px steps.
                # 1,320 put the form 51 px *above* the window; 1,160 frames the Overrides
                # card whole at y=109 and still shows eight log rows from y=597 down.
                Page(path="/dns", scroll=1160,
                     note="must frame the Overrides card (form.inline-form) with the top "
                          "of the live query log below it"),
            ),
            ats=(0.0, 0.40, 0.62),
        ),
        # Sentence fractions: the query count at 0.299, "ads and trackers from the public
        # lists" at 0.484, "Your own overrides beat every list" at 0.616, "you will not see
        # it here" at 0.782.
        actions=[
            Move(to=CHIP_DNS, at=0.25, seconds=1.0),
            Highlight(sel=CHIP_DNS, at=0.285, seconds=1.6),
            Highlight(sel=DNS_HOURS_CHART, at=0.335, seconds=1.8),
            Scroll(to_y=520, at=0.40, seconds=1.3),
            Scroll(to_y=1160, at=0.62, seconds=1.4),
            Move(to=DNS_OVERRIDE_FORM, at=0.68, seconds=1.0),
            Highlight(sel=DNS_OVERRIDE_FORM, at=0.71, seconds=1.8),
            Move(to=DNS_LOG_CLIENT_FILTER, at=0.84, seconds=1.0),
            Highlight(sel=DNS_QUERY_LOG, at=0.88, seconds=2.0),
        ],
        caption="DNS filter",
    ),
    # -- 11 ------------------------------------------------------------------------------
    Scene(
        id="11-activity-feed",
        narration=_n(
            """
            Everything lands in one stream. A finding opening or resolving, a device
            joining, a scan finishing, a feed updating, a domain blocked, a notification
            sent — all in time order, on one page. Filter by kind, severity or window, or
            just search it. There is an RSS version if you would rather read it elsewhere.
            """
        ),
        # Measured on the seeded feed: the filters form and the RSS button sit at y=196,
        # so they are only reachable at scroll 0. The scene therefore rides the stream
        # down while the voice lists the event kinds, then comes back up to the controls.
        shot=PageSequence(
            shots=(
                Page(path="/feed", scroll=0),
                Page(path="/feed", scroll=400,
                     note="the stream continuing - several more timeline items"),
                Page(path="/feed", scroll=0,
                     note="back to the top: #feed-filters and the RSS button live at y=196"),
            ),
            ats=(0.0, 0.34, 0.58),
        ),
        actions=[
            Highlight(sel=FEED_FIRST_ITEM, at=0.05, seconds=2.2),
            Move(to=FEED_CHIPS, at=0.16, seconds=1.0),
            Highlight(sel=FEED_CHIPS, at=0.20, seconds=1.8),
            Scroll(to_y=400, at=0.34, seconds=1.4),
            Scroll(to_y=0, at=0.58, seconds=1.2),
            Move(to=FEED_FILTERS, at=0.64, seconds=1.0),
            Highlight(sel=FEED_FILTERS, at=0.68, seconds=2.0),
            Move(to=FEED_RSS_BUTTON, at=0.84, seconds=1.0),
            Highlight(sel=FEED_RSS_BUTTON, at=0.88, seconds=1.6),
        ],
        caption="Activity feed",
    ),
    # -- 12 ------------------------------------------------------------------------------
    Scene(
        id="12-summary",
        narration=_n(
            """
            The Summary answers the other question. Not what is broken, but what got
            fixed. {found} issues found, {resolved} fixed, {open_after_ack} still open. A
            {rate} percent remediation rate, median {ttr} hours to fix. Found versus remediated,
            by severity, shows where the backlog sits. Below, everything resolved and how
            long it stayed open, verified by rescan or marked fixed by you. Then the
            worklist: worst and oldest first, each item carrying its own steps. Export it
            as Markdown or JSON, or print it.
            """
        ),
        # Offsets measured against the seeded summary page (scrollHeight 11,969):
        # #remediated-table starts at y=1493 and is 497 tall, so scroll 1300 frames it
        # whole (193..690); article.work:first-of-type starts at y=2067 and is 295 tall,
        # so scroll 1900 frames it whole (167..462). The export buttons are in the page
        # toolbar at y=63 and are NOT sticky, so the scene returns to the top for them.
        shot=PageSequence(
            shots=(
                Page(path="/summary", scroll=0),
                Page(path="/summary", scroll=1300,
                     note="frames the 'Remediated' table (#remediated-table) whole"),
                Page(path="/summary", scroll=1900,
                     note="frames the first card of 'Still open - what to do next' "
                          "(article.work) with its numbered steps visible"),
                Page(path="/summary", scroll=0,
                     note="back to the toolbar for the Markdown / JSON export buttons"),
            ),
            # "Found versus remediated" starts at 0.367, "Below, everything resolved" at
            # 0.540, "Then the worklist" at 0.730, "Export it as Markdown" at 0.890. The
            # scrolls used to run a whole sentence ahead of the voice, and the first of them
            # landed in the middle of the zoom's hold.
            ats=(0.0, 0.53, 0.72, 0.87),
        ),
        actions=[
            Move(to=SUMMARY_LEDE, at=0.04, seconds=0.9),
            Highlight(sel=SUMMARY_LEDE, at=0.09, seconds=2.6),
            Move(to=FOUND_VS_REMEDIATED, at=0.31, seconds=1.1),
            # Same rule as scene 6's zoom: crop from the gutter at x=232 to the page's own
            # right edge, never to a 1000 px window clamped against the right. The old rect
            # put the left edge at x=600, which beheaded the SCORE TREND card, cut
            # "FOUND - ALL TIME" to "OUND" and sliced the 4 off "48". Measured here: the four
            # tiles run 242..1579 at y=171 and the two chart cards 298..833, so this frames
            # every one of them whole.
            Zoom(to_rect=(232, 130, 1368, 770), at=0.35, seconds=2.0),
            Scroll(to_y=1300, at=0.53, seconds=1.4),
            Highlight(sel=REMEDIATED_TABLE, at=0.58, seconds=2.4),
            Scroll(to_y=1900, at=0.72, seconds=1.3),
            Highlight(sel=WORKLIST_FIRST, at=0.77, seconds=2.6),
            Move(to=SUMMARY_EXPORT_MD, at=0.91, seconds=1.0),
            Highlight(sel=SUMMARY_EXPORT_MD, at=0.94, seconds=1.4),
        ],
        caption="Summary",
    ),
    # -- 13 ------------------------------------------------------------------------------
    Scene(
        id="13-day-to-day",
        narration=_n(
            """
            Day to day you mostly leave it alone. Discovery every ten minutes, service and
            vulnerability scans daily, the host audit and the feeds every six hours.
            Telemetry shows every job, when it last ran and whether it failed. The Scans
            page runs anything on demand. New findings above your severity floor are
            batched into one notification: ntfy, Discord, a webhook or a Windows toast.
            Never fifty at once. And everything the dashboard does, the command line does
            too.
            """
        ),
        shot=PageSequence(
            shots=(
                Slide(html_fn="daily_use"),
                Page(path="/telemetry", scroll=0),
                Page(path="/scans", scroll=0),
                Page(path="/settings", scroll=0),
                # The notifications card is the last on /settings: the "send a test"
                # button sits at y=1320 and the page is only 1,395 tall (495 maximum
                # scroll). 480 framed the card but put the window's top edge straight
                # through the middle of the scan.* labels; 462 lands it in the gap above
                # that row and still leaves the button clear of the bottom edge.
                Page(path="/settings", scroll=462,
                     note="frames the Notifications card and its 'send a test' button"),
            ),
            # ats[2] used to be 0.58, which put /scans on screen a full second after the
            # sentence about it had finished. Measured on the SRT: "Telemetry shows every
            # job" starts at frac 0.318, "The Scans page runs anything on demand" at 0.468,
            # and "ntfy, Discord, a webhook..." at 0.714.
            ats=(0.0, 0.30, 0.46, 0.70, 0.80),
        ),
        actions=[
            Move(to=TELEMETRY_JOBS, at=0.33, seconds=1.0),
            Highlight(sel=TELEMETRY_JOBS, at=0.37, seconds=2.2),
            Move(to=SCANS_FULL_BUTTON, at=0.485, seconds=1.0),
            Highlight(sel=SCANS_FULL_BUTTON, at=0.515, seconds=1.6),
            Scroll(to_y=462, at=0.80, seconds=1.0),
            Move(to=SETTINGS_NOTIFY_TEST, at=0.85, seconds=1.1),
            Highlight(sel=SETTINGS_NOTIFY_TEST, at=0.89, seconds=1.8),
        ],
        caption="Day to day",
    ),
    # -- 14 ------------------------------------------------------------------------------
    Scene(
        id="14-close",
        narration=_n(
            """
            That is Home SOC. One process, on hardware you already own, costing nothing
            and sending nothing anywhere. MIT licensed, {tests} tests, and docs for the
            parts a walkthrough cannot cover. One rule before you start: scan only
            networks you own or administer. Point it at your own house, and give it five
            minutes.
            """
        ),
        shot=Slide(html_fn="close"),
        actions=[],
        caption=None,
    ),
]


# ---------------------------------------------------------------------------------------
# Self-check. Not pipeline logic — it only reads SCENES and reports inconsistencies, so a
# typo in a scroll offset or a stray slide name is caught before a nine-minute render.
# ---------------------------------------------------------------------------------------


def _shots_of(shot: Shot) -> list[Shot]:
    return list(shot.shots) if isinstance(shot, PageSequence) else [shot]


def validate() -> list[str]:
    """Return a list of problems with :data:`SCENES`. Empty means the script is coherent."""
    problems: list[str] = []
    seen_ids: set[str] = set()

    for scene in SCENES:
        if scene.id in seen_ids:
            problems.append(f"{scene.id}: duplicate scene id")
        seen_ids.add(scene.id)

        if not scene.narration.strip():
            problems.append(f"{scene.id}: empty narration")
        if "{" in scene.narration or "}" in scene.narration:
            problems.append(f"{scene.id}: un-interpolated placeholder left in narration")

        members = _shots_of(scene.shot)
        if isinstance(scene.shot, PageSequence):
            if len(scene.shot.ats) not in (0, len(members)):
                problems.append(f"{scene.id}: ats has {len(scene.shot.ats)} entries for "
                                f"{len(members)} shots")
            if scene.shot.ats and list(scene.shot.ats) != sorted(scene.shot.ats):
                problems.append(f"{scene.id}: ats are not in ascending order")

        for member in members:
            if isinstance(member, Slide) and member.html_fn not in SLIDE_NAMES:
                problems.append(f"{scene.id}: unknown slide '{member.html_fn}'")
            if isinstance(member, PageSequence):
                problems.append(f"{scene.id}: PageSequence may not be nested")

        # Every declared scroll offset the scene can reach, including the ones a Click
        # lands on via then_shot.
        offsets = {m.scroll for m in members if isinstance(m, Page)}
        for action in scene.actions:
            if isinstance(action, Click):
                for after in _shots_of(action.then_shot):
                    if isinstance(after, Page):
                        offsets.add(after.scroll)

        last_at = -1.0
        for action in scene.actions:
            at = action.at
            if not 0.0 <= at <= 1.0:
                problems.append(f"{scene.id}: action at={at} outside 0..1")
            if at < last_at:
                problems.append(f"{scene.id}: action at={at} is out of order")
            last_at = at

            if isinstance(action, Scroll):
                if action.to_y not in offsets:
                    problems.append(
                        f"{scene.id}: Scroll to_y={action.to_y} has no matching Page shot "
                        f"(declared: {sorted(offsets)})"
                    )
                # The shot carrying that offset must take over at the same moment the
                # scroll starts, otherwise the compositor gets a dissolve and a scroll
                # fighting over the same 1.2 seconds.
                elif isinstance(scene.shot, PageSequence) and scene.shot.ats:
                    when = [
                        scene.shot.ats[i]
                        for i, m in enumerate(members)
                        if isinstance(m, Page) and m.scroll == action.to_y
                    ]
                    if when and not any(abs(w - at) < 1e-6 for w in when):
                        problems.append(
                            f"{scene.id}: Scroll to_y={action.to_y} starts at {at} but its "
                            f"shot takes over at {when}"
                        )
            target = getattr(action, "to", None) or getattr(action, "sel", None)
            if target is not None and not (
                target.startswith("css=") or target.startswith("xy=")
            ):
                problems.append(f"{scene.id}: target '{target}' is not css= or xy=")
            if isinstance(action, Zoom):
                x, y, w, h = action.to_rect
                if w <= 0 or h <= 0 or x < 0 or y < 0 or x + w > 1600 or y + h > 900:
                    problems.append(f"{scene.id}: Zoom rect {action.to_rect} leaves the "
                                    "1600x900 viewport")

        # A Click must be preceded by a Move, so the cursor is never clicking thin air.
        cursor_placed = False
        for action in scene.actions:
            if isinstance(action, Move):
                cursor_placed = True
            elif isinstance(action, Click):
                if not cursor_placed:
                    problems.append(f"{scene.id}: Click at={action.at} with no preceding Move")

    used_slides = {
        m.html_fn for s in SCENES for m in _shots_of(s.shot) if isinstance(m, Slide)
    }
    for name in SLIDE_NAMES:
        if name not in used_slides:
            problems.append(f"slide '{name}' is declared but never used")

    return problems


def _word_count(text: str) -> int:
    return len(text.split())


if __name__ == "__main__":  # pragma: no cover - a developer convenience, not the pipeline
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    WPM = 145.0  # en-US-AndrewMultilingualNeural at -4%
    total_words = 0
    print(f"{'scene':<20} {'words':>6} {'~sec':>6}  shot")
    print("-" * 78)
    for _scene in SCENES:
        words = _word_count(_scene.narration)
        total_words += words
        kind = type(_scene.shot).__name__
        if isinstance(_scene.shot, PageSequence):
            kind += f"({len(_scene.shot.shots)})"
        print(f"{_scene.id:<20} {words:>6} {words / WPM * 60:>6.1f}  {kind}")
    print("-" * 78)
    print(f"{'TOTAL':<20} {total_words:>6} {total_words / WPM * 60:>6.1f} s "
          f"= {total_words / WPM:.2f} min")
    issues = validate()
    if issues:
        print("\nPROBLEMS:")
        for issue in issues:
            print("  -", issue)
        raise SystemExit(1)
    print("\nvalidate(): OK")
