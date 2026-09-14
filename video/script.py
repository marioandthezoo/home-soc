"""The narration and action script for the Home SOC walkthrough video — **v2, with Lens**.

This module is **data and type definitions only**. It contains no pipeline logic: nothing
here seeds a database, launches a browser, calls a text-to-speech service or writes a
frame. ``narrate.py``, ``capture.py``, ``phone.py``, ``scene_render.py`` and ``compose.py``
import :data:`SCENES` and do all of that.

Contract
--------
The dataclasses below are the ones named in ``video/CONTRACT.md`` section 2 plus the four
added by ``video/CONTRACT_V2.md`` section V2 (:class:`Phone`, :class:`PhonePair`,
:class:`Tap`, :class:`PhoneScroll`). Timings on actions are **fractions of that scene's
measured narration duration** (0.0 = the first syllable, 1.0 = the last), so the visuals
follow the voice automatically however long edge-tts decides a sentence takes.

Twenty scenes in three acts: what it is (1-4), the dashboard (5-13), Lens (14-19), close
(20).

Conventions the other packages rely on
--------------------------------------
1. **Selector strings** are always ``"css=<selector>"`` (or ``"xy=(x, y)"`` for a raw
   point). Every selector in this file was resolved against a live dashboard served from
   ``video/demo_data`` on 2026-09-13 — desktop selectors in a 1600x900 viewport, Lens
   selectors in the 390x844 mobile context of CONTRACT_V2 V2 — and each resolves to
   exactly **one** element on the shot that is on screen when the action fires.
   ``capture.py``/``phone.py`` must fail loudly with the scene id and the selector if one
   does not resolve — never silently place the cursor or the touch circle at the origin.
   Two selectors deliberately match several elements (``NEEDS_ADMIN_BADGE`` — two checks
   carry that badge — and ``FEED_FIRST_ITEM``); the rule there is **first in document
   order wins**, which is what Playwright's ``.first`` gives you.
2. **Scroll states are declared, not implied.** Whenever a scene scrolls, its shot is a
   :class:`PageSequence` whose members carry the exact ``scroll`` offsets used, and every
   :class:`Scroll` / :class:`PhoneScroll` action's ``to_y`` equals one of those offsets.
   :func:`validate` checks this. Each non-zero offset carries a ``note`` naming the element
   it has to bring into view: the numbers were measured against the real page, but the
   exact pixel depends on how many rows ``seed_demo.py`` writes, so nudge the number until
   the note is true. ``capture.py`` must clamp every offset to
   ``max(0, scrollHeight - 900)`` (``max(0, scrollHeight - 626)`` for the Lens card, whose
   scroller is ``#card-body``, not the window) and log a warning when it does, rather than
   silently screenshotting the bottom of the page.
3. **Selectors used after a Click or a Tap must be measured on the after-state.** In scene
   ``06-findings`` the remediation list and the status buttons live inside a
   ``<tr class="detail-row" hidden>`` that only becomes visible once the row above it has
   been clicked; in scene ``19-lens-card`` the Vulnerabilities section is a collapsed
   ``<details>`` until it is tapped. A hidden element has no box, so geometry for actions
   whose ``at`` is later than a Click/Tap's ``at`` must be resolved **after** performing
   that click or tap.
4. **Only ``<select>`` elements auto-submit.** ``static/app.js`` binds
   ``form[data-submit-on-change]`` to the ``change`` event of its selects only, so ticking
   the Vulnerabilities page's "KEV only" checkbox does *not* navigate — scene 8 therefore
   ticks the box and then clicks **Apply**, which is what a person would do anyway. The
   Findings page's severity strip is a plain ``<a>``, so one click there does navigate.
5. **Numbers spoken out loud** are not written into the prose by hand. They come from the
   constants below and are interpolated with ``.format(**NUMBERS)``. Reconcile the
   constants in one place and the narration is correct everywhere. Every one of them was
   read off a live dashboard or a live ``/api/lens/device/18`` response on 2026-09-13; the
   comment above each says where.
6. **The database does not change during the video.** v1's scene 6 really pressed
   *Acknowledge*, which forked every subsequent number into a before and an after. v2 does
   not, for a reason bigger than tidiness: ``lens_device`` builds its headline, its
   severity strip and its ``score_contribution`` from **open** findings only, so
   acknowledging the Telnet finding in scene 6 would have turned Act 3's card from "six
   problems, one of them critical, minus forty-four points" into "five problems, one of
   them serious, minus nineteen" and buried the critical at the bottom of the list.
   Measured, both ways. Scene 6 now points at the three status buttons and explains what
   each one does instead, which costs the video a click and buys it one consistent set of
   figures from scene 1 to scene 20.

What this script needs from ``seed_demo.py``
--------------------------------------------
Beyond ``CONTRACT.md`` section 1 and ``CONTRACT_V2.md`` section V4, because the shots below
point straight at them:

* **Exactly two open criticals** — ``NET-SVC-001`` on the camera and ``NET-VUL-001`` on the
  gateway. Scene 6 filters to open criticals and expects two rows, and picks the Telnet one
  out by ``data-category="lan-services"`` (``api.category_for`` reads the category off the
  catalog spec, so ``NET-SVC-*`` is ``lan-services`` and ``NET-VUL-*`` is ``vulns``). Any
  other open critical whose category is ``lan-services`` would make that selector ambiguous.
* **Exactly one KEV row** in ``vulns``, on the gateway, so ``/vulns?kev=1`` has one row.
* **Defender status** lives in ``settings`` under the key ``defender.status_json``
  (``api.host_data`` reads it there, not from ``host_checks``), and at least one
  ``host_checks`` row with ``status='needs_admin'`` so scene 9's badge exists. Two exist
  today: ``WIN-ACC-002`` (built-in Administrator) and ``WIN-SYS-008`` (TPM).
* **The camera's and gateway's ``devices.id``**, printed at the end of the seed run, so
  ``CAMERA_DEVICE_ID`` and ``GATEWAY_DEVICE_ID`` below stay correct.
* **A sticker tag on the camera**, because ``scene_render.py`` encodes that exact token into
  the QR it draws on the underside of the illustrated camera (CONTRACT_V2 V3.1). The token
  is deliberately **not** written into this file: the render rig reads it from the database
  at capture time, so a reseed cannot leave a stale string here.
* **At least four devices with no tag**, so ``/lens/stickers`` has something to print.
  Scene 17 nonetheless captures ``?which=all&names=1``, which is full whatever the seed
  does, and is a better-looking sheet.

Voice
-----
Second person, calm, concrete, generous with the *why*, honest about the limits. Numerals a
speech engine could mangle are spelled out ("port fifty-three", "eighty-nine rules"); IP
addresses are written as "192 dot 168 dot 1 dot 142" for the same reason.

Honesty, and the one substitution
---------------------------------
CONTRACT_V2 V3: the Lens scenes are recorded in Chrome on a PC in a phone-shaped viewport,
because desktop Chrome has no ``BarcodeDetector``; a zxing-cpp sidecar decodes the real
pixels beside the browser. The narration in Act 3 therefore describes **the product**
("point the phone at the sticker and Lens recognises it" — which is what it does on Chrome
on Android, the target platform) and never **the recording** ("here it is running on a
phone" — which would be false). Nothing in Act 3 claims world-anchored AR: scene 18 says
out loud that it is a viewfinder with a panel over it. Nothing claims iOS.

Length
------
Total narration is 1,920 words. Running this module as a script prints the per-scene word
count, a 145 wpm estimate and the split by act, and runs :func:`validate`.

The estimate is not the measurement. Every scene was synthesised for real with
``en-US-AndrewMultilingualNeural`` at ``-4%`` and measured with ffprobe **twice**, into two
separate directories, because the public speech endpoint intermittently closes the stream
early and hands back a short file — ``narrate.py``'s ``written == 0`` guard does not catch
a partial one, and a truncated take of a long scene reads a minute faster than the truth.
Both runs agreed to within half a second on every scene, and three scenes were
cross-checked a third way by synthesising each sentence separately and summing (21.8 vs
22.2 s, 33.2 vs 33.6 s, 64.8 vs 66.2 s), which is what rules truncation out rather than
merely hoping.

Measured speech: **768.9 s = 12 min 49 s**. ``narrate.py`` adds ``LEAD_IN`` 0.30 s and
``TAIL_PAD`` 0.40 s to each of the twenty scenes plus 0.25 s of end room tone, so the
finished film runs about **13 minutes 3 seconds** — inside CONTRACT_V2's 11-14 minute
window with just under a minute of headroom. The per-scene rate is not uniform: short
declarative sentences run near 180 wpm and number-heavy ones near 122, so word count alone
is a poor predictor and any re-edit should be re-measured rather than re-estimated.

Weighted as asked, by words: Act 1 (what it is) 14%, the dashboard tour 43%, the Lens act
39%, the close 3%. If a re-edit pushes the measured total past 14 minutes, cut from scenes
19, 05, 16 and 15 in that order — they are the four longest, and each still has a sentence
that repeats what is legible on screen.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------------------
# Product facts read from the product, not typed in.
#
# The catalogue grew from 88 to 92 rules between the v1 recording and this one, and three
# different numbers ended up in the film: the architecture slide said 88, the voice said
# eighty-nine, and the code had 92. Nothing typed by hand survives a product that is still
# being worked on, so both the slide and the voice now read the same import at build time.
# ``slides.py`` calls :func:`catalogue_counts` for the tile; ``_n`` interpolates
# ``RULE_COUNT_SPOKEN`` into scene 3.
# ---------------------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def catalogue_counts() -> tuple[int, int]:
    """``(rules, categories)`` from the live findings catalogue.

    Imports the product read-only. Raises if it cannot, because a video that quotes a
    number must not quote a guess: a stale literal is exactly the failure this replaces.
    """
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))
    from homesoc.findings import catalog  # noqa: PLC0415  (deliberately lazy)

    return len(catalog.all_ids()), len(catalog.by_category())


DEMO_DB = Path(__file__).resolve().parent / "demo_data" / "homesoc.db"


def _dns_24h(client: str | None = None) -> tuple[int, int]:
    """``(queries, blocked)`` in the demo database's last 24 hours, for one client or all.

    The seed is written relative to *now*, so these move every time the clock does: the
    literals here said "about twenty-eight hundred" and "Almost half" while the pages said
    2,639 and 51%. Reading them at build time is the only way the voice and the card stay in
    step, and it costs one SELECT.
    """
    import datetime as _dt
    import sqlite3 as _sqlite3

    cut = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    sql = (
        "SELECT COUNT(*) AS n, SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) AS b "
        "FROM dns_queries WHERE ts >= ?"
    )
    params: list[object] = [cut]
    if client:
        sql += " AND client = ?"
        params.append(client)
    conn = _sqlite3.connect(f"file:{DEMO_DB.as_posix()}?mode=ro", uri=True, timeout=10)
    try:
        row = conn.execute(sql, tuple(params)).fetchone()
    finally:
        conn.close()
    return int(row[0] or 0), int(row[1] or 0)


def _about_hundreds(n: int) -> str:
    """2,639 -> "about twenty-six hundred"."""
    return f"about {spell(int(round(n / 100.0)))} hundred"


def _share_phrase(pct: float, *, capitalised: bool = False) -> str:
    """A share of something, in words that stay true across a few points of drift."""
    for low, high, words in (
        (56.0, 101.0, "more than half"),
        (45.0, 56.0, "about half"),
        (36.0, 45.0, "more than a third"),
        (28.0, 36.0, "close to a third"),
        (20.0, 28.0, "about a quarter"),
        (-1.0, 20.0, "a small fraction"),
    ):
        if low <= pct < high:
            return words.capitalize() if capitalised else words
    return "some"  # pragma: no cover - the bands above are exhaustive


_ONES = (
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
    "eighteen", "nineteen",
)
_TENS = ("", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety")


def spell(n: int) -> str:
    """Spell a small integer for edge-tts. "92" is read as "ninety-two", not "nine two"."""
    n = int(n)
    if n < 0:
        return str(n)
    if n < 20:
        return _ONES[n]
    if n < 100:
        tens, ones = divmod(n, 10)
        return _TENS[tens] + (f"-{_ONES[ones]}" if ones else "")
    if n < 1000:
        hundreds, rest = divmod(n, 100)
        head = f"{_ONES[hundreds]} hundred"
        return head if not rest else f"{head} and {spell(rest)}"
    return str(n)

__all__ = [
    "Slide",
    "Page",
    "Phone",
    "PhonePair",
    "PageSequence",
    "Shot",
    "Move",
    "Click",
    "Scroll",
    "Highlight",
    "Zoom",
    "Tap",
    "PhoneScroll",
    "Action",
    "Scene",
    "SCENES",
    "NUMBERS",
    "SLIDE_NAMES",
    "SCENE_RENDERS",
    "PHONE_STATES",
    "validate",
]


# ---------------------------------------------------------------------------------------
# Every number and identifier the voice says out loud, in one block.
#
# Reconcile these against `video/demo_data/homesoc.db` after a reseed and the narration is
# correct everywhere; nothing else in this file needs touching. Each was read off a live
# dashboard (http://127.0.0.1 serving HOMESOC_DATA=video/demo_data) or a live
# /api/lens/device/<camera> response on 2026-09-13, and the comments say which.
# ---------------------------------------------------------------------------------------

# -- the score, and why it is where it is ------------------------------------------------
# Live: the overview card reads "grade F (10/100)". Two open criticals means
# findings/score.py clamps to CEILING_MANY_CRITICAL = 20, and the 198.6 points of penalty
# below that ceiling take it the rest of the way to 10. Grade F follows from GRADE_BANDS.
# Deliberate: it gives the video an honest subject and lets scene 5 explain the ceiling.
SCORE_NOW = 10
SCORE_GRADE = "F"

# The two ceilings, straight out of homesoc/findings/score.py. Spoken in scene 5.
CEILING_ONE_CRITICAL = 34
CEILING_MANY_CRITICAL = 20

# What clearing *both* open criticals would do: penalty 198.6 -> 138.6, the critical ceiling
# lifts, six open highs cap it at 79 instead, and the halving curve lands on 20. Verified
# with score.score_from_penalty(138.6, open_critical=0, open_high=6).
SCORE_IF_CRITICALS_CLEARED = 20

# The "+N" beside the first row of the "Fix these first" list on /overview. Live: the Telnet
# finding shows +4, because the *other* critical is still holding the ceiling down. This is
# the whole point of scene 5's last sentence, so if a reseed moves it, move the words too.
TOP_FIX_GAIN = 4
TOP_FIX_GAIN_SPOKEN = "four points"

# STATUS_FACTORS["acknowledged"] in findings/score.py. Spoken in scene 6.
ACK_COST_SPOKEN = "a quarter"

# -- finding counts ----------------------------------------------------------------------
# Live /api/summary and the /summary lede: found 48, resolved 12, open 33, acknowledged 2,
# suppressed 1, 27% remediation rate, median 12.0 h, p90 3.0 days. Scene 6 no longer
# mutates any of this (see docstring note 6), so one set of numbers serves the whole video.
FOUND_ALL_TIME = 48
RESOLVED_TOTAL = 12
OPEN_TOTAL = 33
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
TELNET_PORT_SPOKEN = "twenty-three"
RTSP_PORT_SPOKEN = "five fifty-four"

# -- the gateway CVE -------------------------------------------------------------------------
# CVE-2023-1389 is a genuine CISA KEV entry (TP-Link Archer AX21 command injection, used by
# Mirai variants), and it is the single kev=1 row seed_demo.py writes.
GATEWAY_DEVICE_ID = 1  # verified: devices.id 1 == 192.168.1.1, the gateway
GATEWAY_CVE = "CVE-2023-1389"

# -- DNS ---------------------------------------------------------------------------------
# Deliberately approximate: the seed is relative to `now`, and the block bursts overshoot or
# undershoot their hourly budget, so the realised 24 h total moves a few tens of queries
# between seed runs. Live after the 2026-09-13 reseed: 2,833 queries, 887 blocked, 31.3%
# (the previous seed landed on 2,620/31.5%, which is the spread this note warned about).
# "About twenty-eight hundred" is true anywhere in 2,750-2,849. If a reseed lands outside
# that, change the words here rather than leaving the voice arguing with the number on the
# card. Verified against GET /api/summary and the DNS card's own "2,833" on /.
_DNS_ALL_N, _DNS_ALL_B = _dns_24h()
DNS_QUERIES_24H_SPOKEN = _about_hundreds(_DNS_ALL_N)
DNS_BLOCK_PCT_SPOKEN = _share_phrase(100.0 * _DNS_ALL_B / max(1, _DNS_ALL_N))

# -- host posture --------------------------------------------------------------------------
# Live settings["defender.status_json"]: AntivirusSignatureAge 1. The two needs_admin
# host_checks rows are WIN-ACC-002 (built-in Administrator) and WIN-SYS-008 (TPM).
#
# Scene 9 used to say "Two say needs administrator". Only one of them can ever be on
# screen: WIN-ACC-002 sits at document y=698 and WIN-SYS-008 at roughly y=1,639, which is
# 941 px apart in a 900 px viewport. CONTRACT.md §6 is about what is *visible* when the
# number is spoken, so the line points at the badge the cursor is glowing instead of
# counting - the general point ("it says needs administrator rather than fail") is
# unchanged and still true of both rows.
DEFENDER_SIGNATURE_AGE_DAYS_SPOKEN = "a day"
DEFENDER_THREATS_30D_SPOKEN = "one threat"

# -- Lens: the camera's card ----------------------------------------------------------------
# Live GET /api/lens/device/18?hours=24, with no finding acknowledged:
#   posture.headline           "Six problems, one of them critical: this camera accepts
#                               Telnet logins, ... and three more."
#   posture.score_contribution 44
#   severity_counts            critical 1, high 1, medium 2, low 1, info 1
#   services                   23 Telnet (critical), 554 RTSP (high), 80 + 8080 HTTP (low)
#   vulns                      one row, CVE-2017-9833, kev false, CVSS 7.5, EPSS 4.2%
#   dns                        90 of 183 lookups blocked (49.2%), 1 known-bad destination
#                              (the 2026-09-13 reseed; the previous seed gave 96 of 175, 55%)
CAMERA_PROBLEMS_SPOKEN = "six problems"
CAMERA_CRITICAL_SPOKEN = "one of them critical"
CAMERA_SCORE_COST = 44
CAMERA_SCORE_COST_SPOKEN = "forty-four points"
CAMERA_OPEN_PORTS_SPOKEN = "four"
# Banded on purpose, like the DNS figures above. The 2026-09-13 reseed put this client at
# 49.2% (90 of 183), just under half, so "more than half" would have been false against the
# card on screen. "Almost half" is true anywhere in 44-50%; above 52% say "more than half"
# again, below 40% say "more than a third". Nothing else in the sentence changes. It also
# opens a sentence, so keep it capitalised — the .srt renders this text verbatim.
_CAM_DNS_N, _CAM_DNS_B = _dns_24h(CAMERA_IP)
CAMERA_DNS_BLOCK_SPOKEN = _share_phrase(
    100.0 * _CAM_DNS_B / max(1, _CAM_DNS_N), capitalised=True
)
# The camera's only CVE is a directory traversal in Boa, a web server abandoned upstream in
# 2005; the card's own remediation line says so and tells you to replace the device. It is
# NOT a KEV row — scene 19 says the KEV badge appears "when" a CVE is on that list, never
# that this one is.
CAMERA_CVE_ABANDONED_YEAR_SPOKEN = "two thousand and five"

# -- Lens: setup facts (SPEC_LENS B3/B4, and the live /lens/pair page) --------------------
PAIRING_CODE_MINUTES_SPOKEN = "five minutes"
LENS_SCAN_RATE_SPOKEN = "about five times a second"
LENS_TARGET_SPOKEN = "Chrome on Android"

# -- product facts (not seeded; these come from the repo) -------------------------------------
# Both of these used to be literals, and both had gone stale. The rule count is read from
# the catalogue at build time (see catalogue_counts above) so the voice and the
# architecture slide cannot disagree with each other or with the code.
RULE_COUNT, RULE_CATEGORY_COUNT = catalogue_counts()
RULE_COUNT_SPOKEN = spell(RULE_COUNT)
# The test count is deliberately NOT spoken. It was "a thousand and nine"; a collect-only
# run on 2026-09-13 reported 1,118, and the number moves whenever anyone adds a test — with
# nothing on screen to correct it, any figure here is a promise the film cannot keep. The
# close scene says "an offline test suite" instead, which stays true.

NUMBERS: dict[str, object] = {
    "score": SCORE_NOW,
    "grade": SCORE_GRADE,
    "ceiling_one": CEILING_ONE_CRITICAL,
    "ceiling_many": CEILING_MANY_CRITICAL,
    "score_cleared": SCORE_IF_CRITICALS_CLEARED,
    "top_fix_gain": TOP_FIX_GAIN_SPOKEN,
    "ack_cost": ACK_COST_SPOKEN,
    "found": FOUND_ALL_TIME,
    "resolved": RESOLVED_TOTAL,
    "open": OPEN_TOTAL,
    "rate": REMEDIATION_RATE_PCT,
    "ttr": MEDIAN_TTR_HOURS,
    "open_critical": OPEN_CRITICAL,
    "devices_total": DEVICES_TOTAL,
    "devices_total_spoken": DEVICES_TOTAL_SPOKEN,
    "devices_online": DEVICES_ONLINE,
    "camera_ip_spoken": CAMERA_IP_SPOKEN,
    "telnet_port": TELNET_PORT,
    "telnet_port_spoken": TELNET_PORT_SPOKEN,
    "rtsp_port_spoken": RTSP_PORT_SPOKEN,
    "dns_queries": DNS_QUERIES_24H_SPOKEN,
    "dns_block_pct": DNS_BLOCK_PCT_SPOKEN,
    "sig_age": DEFENDER_SIGNATURE_AGE_DAYS_SPOKEN,
    "threats_30d": DEFENDER_THREATS_30D_SPOKEN,
    "cam_problems": CAMERA_PROBLEMS_SPOKEN,
    "cam_critical": CAMERA_CRITICAL_SPOKEN,
    "cam_cost": CAMERA_SCORE_COST_SPOKEN,
    "cam_ports": CAMERA_OPEN_PORTS_SPOKEN,
    "cam_dns_block": CAMERA_DNS_BLOCK_SPOKEN,
    "cam_cve_year": CAMERA_CVE_ABANDONED_YEAR_SPOKEN,
    "pair_minutes": PAIRING_CODE_MINUTES_SPOKEN,
    "scan_rate": LENS_SCAN_RATE_SPOKEN,
    "lens_target": LENS_TARGET_SPOKEN,
    "rules": RULE_COUNT_SPOKEN,
}

#: The nine slides ``slides.py`` must render, by the exact names agreed with that package.
#: ``lens_why`` and ``lens_how`` are new in v2; ``architecture`` is re-drawn to carry Lens as
#: a third output path alongside the dashboard and the resolver (CONTRACT_V2 V1.3).
SLIDE_NAMES: tuple[str, ...] = (
    "title",
    "what_it_is",
    "architecture",
    "first_run",
    "daily_use",
    "lens_why",
    "lens_how",
    "lens_limits",
    "close",
)

#: The synthetic scenes ``scene_render.py`` must draw (CONTRACT_V2 V3.1), by name. One, for
#: now: a small wall-mounted camera on a shelf with a genuine QR sticker on its underside,
#: encoding the demo camera's real sticker token read from the database at capture time.
SCENE_RENDERS: tuple[str, ...] = ("shelf",)

#: The Lens screen states ``phone.py`` knows how to drive (CONTRACT_V2 V2).
PHONE_STATES: tuple[str, ...] = ("scan", "card", "picker", "unknown")


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
class Phone:
    """A Lens screen, captured in the 390x844 @3x mobile context of CONTRACT_V2 V2.

    `state` is one of :data:`PHONE_STATES`:

    ``scan``     the viewfinder — live fake-camera feed, reticle, dock.
    ``card``     the device card risen over the feed (``#card`` visible, ``body.card-open``).
    ``picker``   the manual device list (``#picker`` visible).
    ``unknown``  the "Which device is this?" sheet for a code Lens has never seen
                 (``#unknown`` visible, ``#unknown-code`` showing the raw decoded value).

    `scroll` means the window offset for ``scan``/``picker``/``unknown``, and the
    **``#card-body`` ``scrollTop``** for ``card`` — that element is the scroller, and its
    client height is 626 px in this viewport, so the maximum useful offset is
    ``#card-body.scrollHeight - 626``.

    ``phone.py`` composites the returned 390x844 screen into the drawn phone body; the
    compositor must land the phone at 55-70% of frame height in phone-only scenes so the
    card text is legible at 1080p (CONTRACT_V2 V5).
    """

    path: str = "/lens"
    state: str = "scan"
    scroll: int = 0
    #: Capture this state as a short burst of ``burst`` screenshots ``burst_ms`` apart
    #: instead of one still, and play them back. Only meaningful for a state whose subject
    #: actually moves — in practice the viewfinder, which is a real ``<video>`` playing
    #: ``build/scene_camera.y4m`` with the handheld drift CONTRACT_V2 V3.2 requires. A
    #: single screenshot throws that drift away; see the note on scene 18.
    burst: int = 0
    burst_ms: int = 66
    #: ``scan`` only. Photograph the instant of recognition instead of the idle viewfinder:
    #: the reticle green, the chip reading "identifying…", the card not yet up. It is a real
    #: state of the real page (``lens.js`` sets ``is-hit`` on a decode), reached by a real
    #: decode of the real pixels; ``phone.py`` holds the lookup's *answer* back for
    #: ``hit_ms`` so the state lasts longer than two frames, and fails loudly if the
    #: reticle's own 600 ms window closes before the shutter.
    hit: bool = False
    hit_ms: int = 2600
    note: str = ""


@dataclass(frozen=True)
class PhonePair:
    """The illustrated scene and the phone, side by side — CONTRACT_V2 V2, used by scene 18.

    `scene_png` names one of :data:`SCENE_RENDERS`; ``scene_render.py`` draws it and
    ``compose.py`` places the phone frame beside it. `phone_state` and `scroll` mean exactly
    what they mean on :class:`Phone`.
    """

    scene_png: str
    phone_state: str = "scan"
    scroll: int = 0
    #: See :class:`Phone.burst`. Scene 18 uses it on its viewfinder and its card.
    burst: int = 0
    burst_ms: int = 66
    #: See :class:`Phone.hit`.
    hit: bool = False
    hit_ms: int = 2600
    note: str = ""


@dataclass(frozen=True)
class PageSequence:
    """Several shots shown one after another inside a single scene.

    `shots[0]` is on screen from the start. `ats[i]` is the fraction of the scene at which
    `shots[i]` takes over; ``ats[0]`` is ignored and treated as 0.0. When `ats` is empty
    the shots split the scene evenly. Transitions between members are the usual 400 ms
    cross-dissolve, except that a change of scroll offset within the same `path` (or within
    the same Lens `state`) should be animated by the matching :class:`Scroll` /
    :class:`PhoneScroll` action rather than dissolved.
    """

    shots: tuple["Shot", ...]
    ats: tuple[float, ...] = ()


Shot = Union[Slide, Page, Phone, PhonePair, PageSequence]


# ---------------------------------------------------------------------------------------
# Actions
#
# Desktop scenes use Move / Click / Scroll / Highlight / Zoom — a drawn mouse cursor.
# Phone scenes use Tap / PhoneScroll — a touch circle, no pointer. `validate` enforces that
# no scene mixes the two, because a mouse arrow gliding across a phone screen would be a
# lie about how the thing is used.
#
# Everything is timed as a fraction of the scene's narration duration.
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
    off is harmless. Desktop scenes only — a phone shot is already a crop.
    """

    to_rect: tuple[int, int, int, int]
    at: float
    seconds: float = 1.5


@dataclass(frozen=True)
class Tap:
    """A finger, not a mouse: a touch circle that expands and fades over `seconds`.

    `xy` is ``"css=<selector>"`` resolved in the 390x844 Lens viewport, or ``"xy=(x, y)"``
    in that same space. There is no Move before a Tap — a finger arrives, it does not
    glide — so the circle simply appears, which is why phone scenes need a beat of stillness
    either side of one.

    When `then_shot` is given, ``phone.py`` performs the tap for real and captures the
    resulting screen, exactly as ``capture.py`` does for :class:`Click`; geometry for any
    later action in the scene is then resolved on that after-state (docstring note 3).
    """

    at: float
    xy: str
    seconds: float = 0.5
    then_shot: Shot | None = None
    note: str = ""


@dataclass(frozen=True)
class PhoneScroll:
    """Smoothly scroll the Lens screen from its current offset to `to_y`.

    For a ``card`` shot this scrolls ``#card-body``; otherwise the window. `to_y` must match
    the `scroll` of one of the scene's declared :class:`Phone` / :class:`PhonePair` shots.
    Slower than a desktop scroll on purpose: a thumb moves a 390 px column of text past the
    eye, and at 1080p the reader needs it to settle.
    """

    to_y: int
    at: float
    seconds: float = 1.4
    note: str = ""


Action = Union[Move, Click, Scroll, Highlight, Zoom, Tap, PhoneScroll]

#: Actions that imply a mouse pointer, and actions that imply a finger. No scene may mix.
DESKTOP_ACTIONS = (Move, Click, Scroll, Highlight, Zoom)
PHONE_ACTIONS = (Tap, PhoneScroll)


# ---------------------------------------------------------------------------------------
# Scene
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scene:
    """One narrated beat: some words, one thing on screen, and the hands over it."""

    id: str
    narration: str
    shot: Shot
    actions: list[Action] = field(default_factory=list)
    caption: str | None = None


def css(selector: str) -> str:
    """Format a CSS selector for :class:`Move` / :class:`Highlight` / :class:`Tap`."""
    return "css=" + selector


def _n(text: str) -> str:
    """Interpolate the spoken numbers into a narration string."""
    return " ".join(text.format(**NUMBERS).split())


# ---------------------------------------------------------------------------------------
# Selectors, named once so a template change is a one-line fix.
#
# Desktop selectors were resolved in a 1600x900 Chrome against the live demo dashboard on
# 2026-09-13; the measured boxes are in the comments where a scene depends on them.
# ---------------------------------------------------------------------------------------

NAV_OVERVIEW = css('.sidebar .nav-link[href="/"]')
NAV_FEED = css('.sidebar .nav-link[href="/feed"]')
NAV_SUMMARY = css('.sidebar .nav-link[href="/summary"]')
NAV_FINDINGS = css('.sidebar .nav-link[href="/findings"]')
NAV_DEVICES = css('.sidebar .nav-link[href="/devices"]')
NAV_VULNS = css('.sidebar .nav-link[href="/vulns"]')
NAV_HOST = css('.sidebar .nav-link[href="/host"]')
NAV_DNS = css('.sidebar .nav-link[href="/dns"]')
# NOTE: app.NAV has no Lens row today, so there is deliberately no NAV_LENS here and no
# scene clicks one. /lens/pair and /lens/stickers are reached by navigation, not by a click
# on a sidebar entry that does not exist. If the product gains that entry, scene 16 can open
# with a click on it; until then, referencing it would fail capture on an unresolvable
# selector, which is exactly the outcome docstring note 1 is there to prevent.

# base.html topbar — unique, and always visible, which makes it a safe Highlight target.
CHIP_SCORE = css("#chip-score")
CHIP_DEVICES = css('.topbar-stats .chip[title="Devices online / total"]')
CHIP_DNS = css('.topbar-stats .chip[title="DNS queries in the last 24 h"]')

# overview.html. Measured: #chart-gauge (259,155,289x128) with #chart-trend directly below
# it, #score-breakdown (259,433,627x202) — a six-row ol.cost-list, one row per finding type.
GAUGE = css("#chart-gauge")
TREND_SPARK = css("#chart-trend")
SEVERITY_DONUT = css("#chart-severity")
DNS_BARS = css("#chart-dns")
FIX_FIRST = css("#score-breakdown")
# The first row of "Fix these first" is the Telnet finding, and .cost-gain is its "+4" — the
# single element scene 5's last sentence is about. It is a 15x18 box, so point at the row and
# glow the number.
FIX_FIRST_ROW = css("#score-breakdown li.cost:first-child")
FIX_FIRST_GAIN = css("#score-breakdown li.cost:first-child .cost-gain")
FIX_FIRST_NOTE = css("#score-breakdown-note")
FEEDS_BODY = css("#feeds-body")
JOBS_CHIPS = css("#jobs-chips")

# findings.html — the severity strip links carry the exact query we want, so clicking one
# is a real navigation rather than a synthetic filter change.
FINDINGS_CRITICAL_LINK = css('.sev-counts a[href*="severity=critical"]')
# Both open criticals are NET-* rules, but api.category_for() takes the category from the
# catalog spec (falling back to CATEGORY_BY_PREFIX only when there is none), so NET-SVC-001
# is "lan-services" and NET-VUL-001 is "vulns". data-category therefore picks the Telnet row
# without anyone having to know its database row id. Uniqueness holds because the page is
# filtered to open criticals: the other lan-services findings in the seed are high or below.
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

# vulns.html
# Ticking the checkbox does NOT submit (app.js only wires selects), so Apply is a real,
# necessary second click, which then lands on /vulns?kev=1&min_cvss=&q= .
VULNS_KEV_CHECKBOX = css('form.filters input[name="kev"]')
VULNS_APPLY = css('form.filters button[type="submit"]')
VULNS_TABLE = css("#vulns-table")
VULNS_FIRST_ROW = css("#vulns-table tbody tr.expandable:first-child")
# vulns_list orders by `kev DESC` first, and the seed writes exactly one kev=1 row, so on the
# unfiltered page the first tbody child is the KEV row and the third (row 1 is expandable,
# row 2 is its hidden detail-row) is the first merely-theoretical one.
VULNS_SECOND_ROW = css("#vulns-table tbody tr.expandable:nth-child(3)")
# Columns of that row: 6 is Service (port, product, version), 7 is "Matched on" — the two
# cells the second half of scene 8 is actually about.
VULNS_SECOND_SERVICE = css("#vulns-table tbody tr.expandable:nth-child(3) td:nth-child(6)")
VULNS_SECOND_MATCHED = css("#vulns-table tbody tr.expandable:nth-child(3) td:nth-child(7)")

# host.html — .stat-row only exists in the Defender card; the standalone <section class="card">
# under <main> is the "Posture checks" card (Defender/Updates and Persistence/Listeners are
# inside .grid wrappers).
DEFENDER_STATS = css(".stat-row")
DEFENDER_ACTIONS = css('button[data-action="defender"][data-op="quick-scan"]')
POSTURE_CARD = css(".main > section.card")
# _badge() lowercases the kind and turns "_" into "-", so status "needs_admin" renders as
# .badge-needs-admin. Two checks carry it in the seed (the built-in Administrator account and
# TPM) — the first in document order is the one to point at.
NEEDS_ADMIN_BADGE = css(".badge-needs-admin")

# dns.html
DNS_HOURS_CHART = css("#chart-dns-hours")
DNS_OVERRIDE_FORM = css('form.inline-form input[name="domain"]')
# The log table itself is 2,530 px tall, so its centre can never be on screen and a glow
# around it would cover the whole frame. Point at the log card's head instead (the "Live
# query log" title plus its client/action filters) — one compact rect, and the rows the eye
# is being sent to start immediately below it. Only one .card-head exists on /dns.
DNS_QUERY_LOG = css(".card-head")
DNS_LOG_CLIENT_FILTER = css("#log-client")

# feed.html — base.html also links /feed.rss, but only as <a class="link">, so .btn is unique.
FEED_CHIPS = css(".feed-chips")
FEED_FILTERS = css("#feed-filters")
# #feed-timeline itself is 10,772 px tall on the seeded feed, so a glow around it would cover
# the whole frame and mean nothing. Point at one event instead. This matches every
# `li.tl-item`; first in document order wins, same rule as NEEDS_ADMIN_BADGE.
FEED_FIRST_ITEM = css("#feed-timeline li.tl-item")
FEED_RSS_BUTTON = css('a.btn[href="/feed.rss"]')

# summary.html
SUMMARY_LEDE = css(".lede")
FOUND_VS_REMEDIATED = css("#chart-found-remediated")
REMEDIATED_TABLE = css("#remediated-table")
WORKLIST_FIRST = css("article.work:first-of-type")
SUMMARY_EXPORT_MD = css('a.btn[href^="/api/summary/report.md"]')

# telemetry.html / scans.html / settings.html
TELEMETRY_JOBS = css("#jobs-body")
SCANS_FULL_BUTTON = css('button[data-action="scan"][data-kind="full"]')
SETTINGS_NOTIFY_TEST = css('button[data-action="notify-test"]')

# ---------------------------------------------------------------------------------------
# lens_pair.html / lens_stickers.html — desktop pages, 1600x900, same as the dashboard.
#
# CAPTURE WARNING, scene 16. Two of these selectors exist only once a certificate exists:
# lens_pair.html renders .qr-wrap, .pair-url and .pair-steps inside `{% if qr %}`, and
# .fingerprint inside `{% if fingerprint %}`. On a loopback-only, no-certificate install the
# page renders its preflight in "Fix" state, mints nothing, and those four selectors do not
# resolve — capture will fail, correctly, because a pairing scene with no pairing QR is not
# the scene CONTRACT_V2 V1.16 asks for. So the demo dashboard for this scene must be started
# with a generated certificate and a non-loopback `web.host`.
#
# PRIVACY WARNING, same scene, and this one is not optional. The preflight prints the
# machine's actual LAN address into its fix steps ("--hosts 192.168.1.105" was in the live
# render while this script was written) and the QR encodes `https://<lan-host>:<port>/...`.
# That is the author's real network, which CONTRACT.md section 6 forbids on screen. The
# capture rig must pin the demo dashboard's advertised host to a neutral address from the
# demo household's own range and generate the certificate for that name, so every string on
# this page belongs to the fictional network. Check the finished frame with your eyes.
# ---------------------------------------------------------------------------------------

PAIR_CHECKS = css(".pair-checks")
PAIR_FIRST_CHECK = css(".pair-checks li.check:first-child")
PAIR_QR_PANEL = css(".pair-qr-panel")
PAIR_QR = css(".qr-wrap")
PAIR_URL = css(".pair-url")
PAIR_STEPS = css(".pair-steps")
PAIR_FINGERPRINT = css(".fingerprint")

STICKERS_CONTROLS = css(".sticker-controls")
STICKERS_WHICH = css("#which")
STICKERS_SIZE = css("#size")
STICKERS_PRINT = css("#btn-print")
STICKERS_GRID = css(".label-grid")
STICKERS_FIRST_LABEL = css(".label:first-child")

# ---------------------------------------------------------------------------------------
# Lens phone selectors — resolved in the 390x844 mobile context against a live /lens on
# 2026-09-13, with the camera's card open. Measured card geometry, which is where scene 19's
# scroll offsets come from (#card-body: clientHeight 626, scrollHeight 3,322 collapsed /
# 3,503 with Vulnerabilities open):
#
#     header + headline + severity strip     0 ..  417
#     details.sec 1  Problems      (open)   417 .. 2085
#     details.sec 2  Exposed       (open)  2086 .. 2527
#     details.sec 3  Vulnerabilities       2527 .. 2580 collapsed, .. 2761 once tapped open
#     details.sec 4  Talking to    (open)  2761 .. 3357
#     details.sec 5  History                3357 ..
#
# lens.js builds the card with createElement + textContent only, so these class names are
# the markup: there is no template to diverge from.
# ---------------------------------------------------------------------------------------

LENS_STATE_CHIP = css("#scan-state")
LENS_RETICLE = css("#reticle")
LENS_RETICLE_HINT = css("#reticle-hint")
LENS_PICK_BUTTON = css("#btn-pick")
LENS_DEVICES_TAB = css("#tab-devices")

LENS_CARD = css("#card")
LENS_CARD_BODY = css("#card-body")
LENS_CARD_HANDLE = css("#card-handle")
LENS_DEV_HEAD = css("#card-body .dev-head")
LENS_DEV_NAME = css("#card-body .dev-name")
LENS_HEADLINE = css("#card-body .headline")
LENS_SEV_STRIP = css("#card-body .sev-strip")
# The last chip in the strip is the "−44 points" one; the severity chips precede it.
LENS_SCORE_CHIP = css("#card-body .sev-strip .sev-chip:last-child")

# :nth-of-type counts <details> children of #card-body. The per-finding "Fix it" blocks are
# also <details>, but they are children of a section, not of #card-body, so these five stay
# unambiguous. Verified live: the titles come back Problems / Exposed / Vulnerabilities /
# Talking to / History in exactly this order.
LENS_SEC_PROBLEMS = css("#card-body > details.sec:nth-of-type(1)")
LENS_SEC_PROBLEMS_HEAD = css("#card-body > details.sec:nth-of-type(1) .sec-head")
LENS_PROBLEM_FIRST = css("#card-body > details.sec:nth-of-type(1) .row:first-of-type")
LENS_SEC_EXPOSED = css("#card-body > details.sec:nth-of-type(2)")
LENS_SEC_EXPOSED_HEAD = css("#card-body > details.sec:nth-of-type(2) .sec-head")
LENS_SEC_VULNS = css("#card-body > details.sec:nth-of-type(3)")
LENS_SEC_VULNS_HEAD = css("#card-body > details.sec:nth-of-type(3) .sec-head")
LENS_SEC_DNS = css("#card-body > details.sec:nth-of-type(4)")
LENS_SEC_DNS_HEAD = css("#card-body > details.sec:nth-of-type(4) .sec-head")
LENS_DNS_HERO = css("#card-body .dns-hero")
LENS_DNS_NUM = css("#card-body .dns-num")
# Three blocked rows and one threat row on the camera today; first in document order wins
# for the blocked one, same rule as NEEDS_ADMIN_BADGE.
LENS_DNS_BLOCKED_ROW = css("#card-body .bar-row.blocked")
LENS_DNS_THREAT_ROW = css("#card-body .bar-row.threat")
LENS_SEC_HISTORY = css("#card-body > details.sec:nth-of-type(5)")

LENS_UNKNOWN_SHEET = css("#unknown")
LENS_UNKNOWN_CODE = css("#unknown-code")
LENS_UNKNOWN_LIST = css("#unknown-list")
LENS_UNKNOWN_FIRST = css("#unknown-list li.device-item:first-child .device-btn")
LENS_UNKNOWN_IGNORE = css("#unknown-ignore")
LENS_PICKER_FIRST = css("#picker-list li.device-item:first-child .device-btn")


# ---------------------------------------------------------------------------------------
# The script
# ---------------------------------------------------------------------------------------

SCENES: list[Scene] = [
    # == ACT 1 — what it is ==============================================================
    # -- 1 -------------------------------------------------------------------------------
    Scene(
        id="01-cold-open",
        narration=_n(
            """
            You know roughly what is on your home network. You do not know what any of it
            is listening on, whether your router runs software with a published hole in
            it, or whether Defender was switched off three weeks ago. And when something
            is wrong, you do not know which of four identical white boxes it is. This is
            Home SOC. It answers all four, on a PC you own.
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
            No account, no cloud, no telemetry. It is not an antivirus engine and not an
            EDR: it does not hook the kernel or run a detection engine of its own.
            Defender stays the thing that catches malware. Home SOC is the thing that
            notices Defender was turned off.
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
            exploit probabilities, DNS blocklists. Scanners go out, asking who is here,
            what each one is listening on, and what has a published CVE. What they see
            becomes a draft; one findings engine — {rules} rules — sets the severity,
            writes the fix steps and remembers. Out the other side, three ways to read one
            database: the dashboard, a resolver on port fifty-three, and Lens, on your
            phone, in front of the device itself.
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
            first feeds, and starts the scheduler and the dashboard. About a minute, and
            no administrator rights. Then give it five minutes before you judge it: the
            first full picture of an {devices_total_spoken}-device network lands inside
            that.
            """
        ),
        shot=PageSequence(
            shots=(
                Slide(html_fn="first_run"),
                Page(path="/", scroll=0, note="the dashboard as it looks on arrival"),
            ),
            # "Then give it five minutes" starts at word 39 of 59, so the dashboard arrives
            # just under it and the sentence about an eighteen-device network (word 48,
            # frac 0.81) lands over a topbar already showing 17 / 18 devices rather than
            # over the launcher slide.
            ats=(0.0, 0.64),
        ),
        actions=[
            # The highlight goes on the device count the voice is quoting, not on the score
            # chip, which nothing in this scene mentions.
            Move(to=CHIP_DEVICES, at=0.78, seconds=0.9),
            Highlight(sel=CHIP_DEVICES, at=0.83, seconds=1.8),
        ],
        caption="First run",
    ),
    # == ACT 2 — the dashboard ===========================================================
    # -- 5 -------------------------------------------------------------------------------
    # REWRITTEN for v2. The score is no longer "100 minus 25 per critical"; v1's narration
    # about it is wrong and none of it survives. Everything said here was read off the live
    # page: the card says "grade F (10/100)", and ol#score-breakdown's first row is the
    # Telnet finding carrying "+4".
    Scene(
        id="05-overview",
        narration=_n(
            """
            The Overview is what you check daily. Top left, the security score: {score}
            out of a hundred, grade {grade}. Here is how that is built, because a score you
            do not trust is a score you ignore. Every unfixed finding above informational
            costs points by severity. But twenty copies of one problem are still one problem, so each
            repeat costs half the one before, and a pile can never cost more than twice a
            single one. Then the ceilings. One open critical caps the score at
            {ceiling_one}, two or more at {ceiling_many}, and any open high forbids an A.
            So an A means nothing high or critical is open. Two are open here. The trend
            underneath is rising, which is what matters. Beside it, findings by severity;
            devices; a day of DNS. And down here, fix these first: a row per finding type,
            worst first, and the plus number is what the score gains once that type is
            gone. Telnet on that camera is worth {top_fix_gain}, held down by the second
            critical underneath it. Clear both and the score doubles.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/", scroll=0),
                Page(path="/", scroll=300,
                     note="must frame the 'Fix these first' card (ol#score-breakdown, "
                          "measured at y=433 h=202 at scroll 0) with its six rows and the "
                          "'+N is roughly how far the score rises' note beneath it"),
            ),
            ats=(0.0, 0.73),
        ),
        # Every `at` is set from where its sentence actually starts, counted in words through
        # the finished narration rather than spread evenly. Out of 183 spoken words: the
        # formula runs 0.22-0.42, the ceilings 0.44-0.61, "The trend underneath" starts at
        # 0.628, "Beside it, findings by severity" at 0.678, "devices" at 0.705, "a day of
        # DNS" at 0.71, "fix these first" at 0.732, "Telnet on that camera" at 0.88.
        # No Zoom here, unlike v1. The push that framed the score card (rect 4,15,800x450)
        # leaves the Devices and DNS cards and the whole topbar outside the frame, and the
        # second half of this scene walks across exactly those — so a held push would have
        # the voice naming things that were not on screen. Two glows on the gauge carry the
        # formula instead, and the ceilings paragraph glows the severity donut, which is
        # where the two open criticals are actually visible.
        actions=[
            # NOT `Move(to=GAUGE)`: the selector's centre is the score numeral itself, and
            # the arrow parked on it turned "10" into "1U" for the twelve seconds the voice
            # spends explaining that very number. The gauge rect is (259,156,289x128), so
            # this lands inside the card, below the digits and clear of the donut's stroke.
            Move(to="xy=(300, 268)", at=0.03, seconds=1.0),
            Highlight(sel=GAUGE, at=0.07, seconds=2.4),
            Highlight(sel=GAUGE, at=0.23, seconds=2.2),
            # The halving-curve sentence (0.27-0.42) has nothing of its own on screen, and
            # used to leave a 10 s still frame here. A walk down to the trend strip and a
            # third pulse on the gauge keep the shot alive without inventing a subject.
            Move(to=TREND_SPARK, at=0.28, seconds=0.9),
            Highlight(sel=GAUGE, at=0.315, seconds=2.4),
            Move(to="xy=(300, 268)", at=0.375, seconds=0.8),
            Move(to=SEVERITY_DONUT, at=0.42, seconds=1.0),
            Highlight(sel=SEVERITY_DONUT, at=0.45, seconds=2.6),
            Move(to=TREND_SPARK, at=0.60, seconds=0.8),
            Highlight(sel=TREND_SPARK, at=0.63, seconds=1.8),
            Move(to=SEVERITY_DONUT, at=0.665, seconds=0.7),
            Move(to=CHIP_DEVICES, at=0.695, seconds=0.7),
            Highlight(sel=CHIP_DEVICES, at=0.71, seconds=1.2),
            Move(to=DNS_BARS, at=0.715, seconds=0.6),
            Scroll(to_y=300, at=0.73, seconds=1.2),
            Move(to=FIX_FIRST, at=0.76, seconds=1.0),
            Highlight(sel=FIX_FIRST, at=0.79, seconds=2.6),
            # Let the eye rest on the list before the cursor picks one row out of it.
            Move(to=FIX_FIRST_ROW, at=0.86, seconds=1.0),
            Highlight(sel=FIX_FIRST_GAIN, at=0.885, seconds=2.4),
        ],
        caption="Overview",
    ),
    # -- 6 -------------------------------------------------------------------------------
    Scene(
        id="06-findings",
        narration=_n(
            """
            Every issue Home SOC has raised lives here. Filter to open criticals: there
            are {open_critical}. An unbranded camera at {camera_ip_spoken} has Telnet open
            on port {telnet_port_spoken}. Telnet sends passwords in clear text. It is how
            Mirai takes over cameras, and nothing built this decade needs it. Open the row:
            the evidence, then numbered steps, ending with the nmap command to verify the
            fix. Then three buttons. Resolve says you fixed it; the next scan checks
            whether you did. Suppress says this is not a problem here. Acknowledge is not
            dismissal: the finding stays, and still costs the score {ack_cost} of what it
            did.
            """
        ),
        shot=Page(path="/findings", scroll=0),
        # Sentence starts, in words through the narration (114 total): "Filter to open
        # criticals" 0.07, the camera named 0.14, "Open the row" 0.48, "Then three buttons"
        # 0.63, "Acknowledge is not dismissal" 0.83.
        actions=[
            Move(to=FINDINGS_CRITICAL_LINK, at=0.03, seconds=1.0),
            Click(
                at=0.08,
                then_shot=Page(path="/findings?status=open&severity=critical", scroll=0),
                note="real navigation: the severity strip link carries the query itself",
            ),
            Highlight(sel=TELNET_ROW, at=0.13, seconds=2.2),
            # 0.19-0.44 is the "Telnet sends passwords in clear text / it is how Mirai takes
            # over cameras" pair, and it used to be twelve seconds of a still frame with the
            # cursor parked on the CRITICAL chip it had clicked. Walk it down onto the row
            # the sentences are about and pulse it twice.
            Move(to=TELNET_ROW, at=0.19, seconds=1.0),
            Highlight(sel=TELNET_ROW, at=0.235, seconds=2.4),
            Move(to="xy=(560, 205)", at=0.31, seconds=0.9),
            Highlight(sel=TELNET_ROW, at=0.35, seconds=2.4),
            Move(to=TELNET_ROW, at=0.44, seconds=0.9),
            Click(
                at=0.48,
                then_shot=Page(
                    path="/findings?status=open&severity=critical",
                    scroll=0,
                    note="the row's sibling tr.detail-row is no longer hidden; only two "
                         "rows are listed, so the whole detail fits in the 900 px viewport",
                ),
                note="expands the finding — geometry for every action below must be "
                     "measured on THIS after-state (docstring note 3)",
            ),
            Highlight(sel=TELNET_DETAIL, at=0.51, seconds=1.6),
            Move(to=TELNET_REMEDIATION, at=0.54, seconds=1.0),
            # Crop from the gutter at x=232 (main starts at 220, the findings card at 242) to
            # the page's own right edge, never to a 1000 px window clamped against the right:
            # that put the left edge through the middle of the DETAIL column and sliced
            # half-words down the side. A gentle 1.17x push, with the glow below doing the
            # pointing.
            Zoom(to_rect=(232, 120, 1368, 770), at=0.56, seconds=2.2),
            Highlight(sel=TELNET_REMEDIATION, at=0.58, seconds=2.4),
            # The last third of the scene is about the three status buttons: the cursor
            # arrives over the button group as they are introduced (0.62), waits while
            # Resolve and Suppress are described, and the glow lands on Acknowledge only
            # when it is named. It does NOT press it — see docstring note 6.
            Move(to=TELNET_ACK_BUTTON, at=0.65, seconds=1.1),
            Highlight(sel=TELNET_ACK_BUTTON, at=0.84, seconds=2.6),
        ],
        caption="Findings",
    ),
    # -- 7 -------------------------------------------------------------------------------
    Scene(
        id="07-devices",
        narration=_n(
            """
            The inventory is where that camera came from. {devices_total} devices: name,
            address, MAC, vendor, open ports, findings. Discovery reads the ARP table
            first, then sweeps gently for what it missed. Open the camera and you see why
            an unknown device matters: Telnet, RTSP, and an HTTP admin page that asks for
            nothing. Nothing was exploited — Home SOC connected, read the banner the
            service volunteered, and wrote it down.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/devices", scroll=0),
                Page(path=f"/devices/{CAMERA_DEVICE_ID}", scroll=0),
                Page(
                    path=f"/devices/{CAMERA_DEVICE_ID}",
                    scroll=940,
                    note="frames the Services card with the telnet, http, rtsp and http-alt "
                         "rows, and the Vulnerabilities / Findings cards under it. Was 820, "
                         "which put the *empty tail* of the device-detail card - a bordered "
                         "740x330 box with nothing in it - in the top-left quadrant for the "
                         "last nine seconds of the scene. The page is 1,861 tall, so the "
                         "maximum offset is 961; 940 is the deepest framing that does not "
                         "get clamped.",
                ),
            ),
            # "Open the camera" starts at word 35 of 72 (frac 0.49); the services are named
            # at 0.58.
            ats=(0.0, 0.50, 0.58),
        ),
        actions=[
            Highlight(sel=DEVICES_TABLE, at=0.06, seconds=2.6),
            Move(to=CAMERA_LINK, at=0.38, seconds=1.1),
            Click(
                at=0.46,
                then_shot=Page(path=f"/devices/{CAMERA_DEVICE_ID}", scroll=0),
            ),
            Scroll(to_y=940, at=0.58, seconds=1.4),
            Highlight(sel=DEVICE_SERVICES_TABLE, at=0.63, seconds=2.6),
            Move(to=DEVICE_SERVICES_CARD, at=0.78, seconds=0.9),
            # "Home SOC connected, read the banner the service volunteered, and wrote it
            # down" is the last sentence; the banner text is in the services table, so
            # pulse it again rather than sitting still for the last nine seconds.
            Highlight(sel=DEVICE_SERVICES_TABLE, at=0.83, seconds=2.4),
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
            Criminals are using it right now. Take the filter off and everything else is
            theoretically vulnerable: a version string matching a published CVE. Inference,
            not proof. Backported patches and lying banners get it wrong both ways, so an
            unconfirmed version is reported as possible, not certain. Install nmap if you
            can: without it Home SOC reads far fewer versions.
            """
        ),
        shot=Page(path="/vulns", scroll=0),
        actions=[
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
            # The scene spends its whole second half arguing KEV-versus-theoretical, so take
            # the filter back off and put the full list up for it: "everything else" has to
            # be on screen while it is being discussed.
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
            # Service is the product/version string nmap is what reads.
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
            real-time protection on, signatures {sig_age} old, {threats_30d} in thirty
            days. It reads that state, it does not replace it, though it can trigger a
            quick scan or a signature update. Below, the posture checks. This one says
            needs administrator rather than fail. Home SOC will not pretend it checked
            something it could not.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/host", scroll=0),
                Page(path="/host", scroll=560,
                     note="must frame the 'Posture checks' card (.main > section.card, "
                          "y=545 h=1142) with both needs-administrator badges visible"),
            ),
            # "Below, the posture checks" starts at word 48 of 70 (frac 0.686).
            ats=(0.0, 0.67),
        ),
        actions=[
            Move(to=DEFENDER_STATS, at=0.12, seconds=1.0),
            Highlight(sel=DEFENDER_STATS, at=0.19, seconds=2.6),
            Move(to=DEFENDER_ACTIONS, at=0.42, seconds=0.9),
            Highlight(sel=DEFENDER_ACTIONS, at=0.46, seconds=1.6),
            Scroll(to_y=560, at=0.67, seconds=1.3),
            Highlight(sel=POSTURE_CARD, at=0.69, seconds=1.6),
            Move(to=NEEDS_ADMIN_BADGE, at=0.72, seconds=1.0),
            Highlight(sel=NEEDS_ADMIN_BADGE, at=0.755, seconds=2.4),
        ],
        caption="Host posture",
    ),
    # -- 10 ------------------------------------------------------------------------------
    Scene(
        id="10-dns-filter",
        narration=_n(
            """
            The DNS filter is optional, and it protects devices that cannot protect
            themselves. Point your router here and everything in the house resolves
            through it. That is {dns_queries} queries in a day, {dns_block_pct} of them
            blocked: ads and trackers, plus malware and phishing domains sent nowhere.
            Your own overrides beat every list. Two honest limits. If this PC sleeps, the
            house loses DNS. And a device using its own encrypted DNS never asks this
            resolver, so you cannot see it or filter it.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/dns", scroll=0),
                Page(path="/dns", scroll=520,
                     note="must frame the 'Top blocked domains' and 'Top clients' cards "
                          "(both at y=433, 898 tall)"),
                # Measured on the seeded page (scrollHeight 4,738): the Overrides card runs
                # 1,345..1,773 and the live query log starts at 1,787. 1,280 puts the
                # Overrides card whole at y=65 and the log's card-head at y=507, which is the
                # framing this beat wants — the overrides being named, the log below them.
                Page(path="/dns", scroll=1280,
                     note="must frame the Overrides card (form.inline-form) with the top "
                          "of the live query log below it"),
            ),
            # Sentence starts out of 88 words: the query count 0.284, "ads and trackers"
            # 0.466, "Your own overrides beat every list" 0.58, "a device using its own
            # encrypted DNS" 0.773.
            ats=(0.0, 0.46, 0.58),
        ),
        actions=[
            Move(to=CHIP_DNS, at=0.24, seconds=1.0),
            Highlight(sel=CHIP_DNS, at=0.285, seconds=1.6),
            Highlight(sel=DNS_HOURS_CHART, at=0.34, seconds=1.8),
            Scroll(to_y=520, at=0.46, seconds=1.3),
            Scroll(to_y=1280, at=0.58, seconds=1.4),
            Move(to=DNS_OVERRIDE_FORM, at=0.60, seconds=1.0),
            Highlight(sel=DNS_OVERRIDE_FORM, at=0.625, seconds=1.8),
            Move(to=DNS_LOG_CLIENT_FILTER, at=0.78, seconds=1.0),
            Highlight(sel=DNS_QUERY_LOG, at=0.82, seconds=2.2),
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
            sent — all in time order, on one page. Open it when something changed and you
            want the context. Filter by kind, severity or window, or search it. There is an
            RSS version too.
            """
        ),
        # The filters form and the RSS button sit at y=152 and y=178, so they are only
        # reachable at scroll 0. The scene rides the stream down while the voice lists the
        # event kinds, then comes back up to the controls.
        shot=PageSequence(
            shots=(
                Page(path="/feed", scroll=0),
                Page(path="/feed", scroll=400,
                     note="the stream continuing — several more timeline items"),
                Page(path="/feed", scroll=0,
                     note="back to the top: #feed-filters is at y=152, the RSS button at 178"),
            ),
            # Out of 61 words: the list of event kinds runs 0.08-0.59, "Open it when
            # something changed" starts at 0.59, "Filter by kind" at 0.754, "RSS" at 0.90.
            ats=(0.0, 0.32, 0.58),
        ),
        actions=[
            Highlight(sel=FEED_FIRST_ITEM, at=0.05, seconds=2.2),
            Move(to=FEED_CHIPS, at=0.14, seconds=1.0),
            Highlight(sel=FEED_CHIPS, at=0.17, seconds=1.8),
            Scroll(to_y=400, at=0.32, seconds=1.4),
            Scroll(to_y=0, at=0.58, seconds=1.2),
            Move(to=FEED_FILTERS, at=0.71, seconds=1.0),
            Highlight(sel=FEED_FILTERS, at=0.755, seconds=1.8),
            Move(to=FEED_RSS_BUTTON, at=0.865, seconds=1.0),
            Highlight(sel=FEED_RSS_BUTTON, at=0.90, seconds=1.6),
        ],
        caption="Activity feed",
    ),
    # -- 12 ------------------------------------------------------------------------------
    Scene(
        id="12-summary",
        narration=_n(
            """
            The Summary answers the other question. Not what is broken, but what got
            fixed. {found} issues found, {resolved} fixed, {open} still open. A {rate}
            percent remediation rate, median {ttr} hours to fix. Found versus remediated,
            by severity, shows where the backlog sits. Below, everything resolved and how
            long it stayed open. Then the worklist: worst and oldest first, each item
            carrying its own steps. Export it as Markdown or JSON.
            """
        ),
        # Offsets measured against the seeded summary page (scrollHeight 11,969):
        # #remediated-table starts at y=1,492 and is 496 tall, so scroll 1300 frames it
        # whole; article.work:first-of-type starts at y=2,066 and is 295 tall, so scroll
        # 1900 frames it whole. The export buttons are in the page toolbar at y=63 and are
        # NOT sticky, so the scene returns to the top for them.
        # The first scroll travels 1,300 px through a 900 px viewport, so those two states
        # share no captured rows and the compositor cross-dissolves instead of gliding. It
        # cannot be made to glide: the table needs scroll >= 1,088 to be framed whole, a
        # glide needs scroll <= 899, and an intermediate state would land inside the 0.10
        # MERGE_WINDOW and be folded back into this one. 1,300 -> 1,900 does glide.
        shot=PageSequence(
            shots=(
                Page(path="/summary", scroll=0),
                Page(path="/summary", scroll=1300,
                     note="frames the 'Remediated' table (#remediated-table) whole"),
                Page(path="/summary", scroll=1900,
                     note="frames the first card of 'Still open — what to do next' "
                          "(article.work) with its numbered steps visible"),
                Page(path="/summary", scroll=0,
                     note="back to the toolbar for the Markdown / JSON export buttons"),
            ),
            # Out of 76 words: the lede's figures run 0.20-0.46, "Found versus remediated"
            # starts at 0.46, "Below, everything resolved" at 0.605, "Then the worklist" at
            # 0.737, "Export it as Markdown or JSON" at 0.92.
            ats=(0.0, 0.59, 0.72, 0.88),
        ),
        actions=[
            Move(to=SUMMARY_LEDE, at=0.06, seconds=0.9),
            Highlight(sel=SUMMARY_LEDE, at=0.11, seconds=2.4),
            Move(to=FOUND_VS_REMEDIATED, at=0.42, seconds=1.1),
            # Same rule as scene 6's zoom: crop from the gutter at x=232 to the page's own
            # right edge. The four tiles run 242..1579 at y=171 and the two chart cards
            # 298..833, so this frames every one of them whole.
            Zoom(to_rect=(232, 130, 1368, 770), at=0.46, seconds=2.0),
            Scroll(to_y=1300, at=0.59, seconds=1.4),
            Highlight(sel=REMEDIATED_TABLE, at=0.62, seconds=2.2),
            Scroll(to_y=1900, at=0.72, seconds=1.3),
            Highlight(sel=WORKLIST_FIRST, at=0.75, seconds=2.6),
            Move(to=SUMMARY_EXPORT_MD, at=0.90, seconds=1.0),
            Highlight(sel=SUMMARY_EXPORT_MD, at=0.93, seconds=1.4),
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
            Telemetry shows every job and whether it failed. The Scans page runs anything
            on demand. New findings above your severity floor are batched into one
            notification — ntfy, Discord, a webhook or a Windows toast. Never fifty at
            once. One command is worth running on your first day: baseline. It marks the
            devices already on your network as trusted and closes their new-device
            findings in one go. After that, a new-device finding means something genuinely
            new.
            """
        ),
        shot=PageSequence(
            shots=(
                Slide(html_fn="daily_use"),
                Page(path="/telemetry", scroll=0),
                Page(path="/scans", scroll=0),
                Page(path="/settings", scroll=0),
                # The notifications card is the last on /settings: the "send a test" button
                # sits at y=1,309 and the page is only 1,384 tall (484 maximum scroll). 480
                # framed the card but put the window's top edge through the middle of the
                # scan.* labels; 462 lands it in the gap above that row and still leaves the
                # button clear of the bottom edge.
                Page(path="/settings", scroll=462,
                     note="frames the Notifications card and its 'send a test' button"),
                # Back to the slide for the baseline paragraph: the daily_use card is where
                # the CLI lines live, and `baseline` is a terminal command, not a page.
                Slide(html_fn="daily_use"),
            ),
            # Out of 105 words: "Telemetry shows every job" starts at 0.286, "The Scans
            # page" at 0.362, the notification kinds at 0.43, and "One command is worth
            # running on your first day: baseline" at 0.648 — which is where the slide comes
            # back, because baseline is a terminal command with no page of its own.
            ats=(0.0, 0.28, 0.36, 0.43, 0.48, 0.65),
        ),
        actions=[
            Move(to=TELEMETRY_JOBS, at=0.30, seconds=1.0),
            Highlight(sel=TELEMETRY_JOBS, at=0.32, seconds=1.8),
            Move(to=SCANS_FULL_BUTTON, at=0.375, seconds=0.9),
            Highlight(sel=SCANS_FULL_BUTTON, at=0.395, seconds=1.4),
            Scroll(to_y=462, at=0.48, seconds=1.0),
            Move(to=SETTINGS_NOTIFY_TEST, at=0.51, seconds=1.1),
            Highlight(sel=SETTINGS_NOTIFY_TEST, at=0.54, seconds=1.8),
        ],
        caption="Day to day",
    ),
    # == ACT 3 — Lens ====================================================================
    # -- 14 ------------------------------------------------------------------------------
    # The problem, landed honestly. The first half is a real table row, so the abstraction
    # is concrete before the illustration takes over; the second half is the hallway.
    Scene(
        id="14-lens-why",
        narration=_n(
            """
            Here is where a screen stops being enough. Home SOC says the worst thing on
            this network is {camera_ip_spoken}. An unbranded camera, Telnet open,
            streaming video to anyone who asks. Good. Now go and fix it. You are in a
            hallway holding a phone, looking at a shelf with four identical white boxes.
            Two are cameras, one is a smart plug you forgot you owned, and one is a
            doorbell. You can unplug them one at a time, or you can guess. That gap — between a row in a table and an
            object on a shelf — is what Lens closes.
            """
        ),
        shot=PageSequence(
            shots=(
                Page(path="/devices", scroll=0,
                     note="the inventory; the camera's row is the one being pointed at"),
                Slide(html_fn="lens_why"),
            ),
            # "Now go and fix it" ends at word 46 of 105 and the hallway begins there, so
            # the illustration takes over on the word "hallway", not before it.
            ats=(0.0, 0.44),
        ),
        actions=[
            Move(to=CAMERA_LINK, at=0.10, seconds=1.2),
            Highlight(sel=CAMERA_LINK, at=0.15, seconds=2.4),
            # A tight push on the camera's row, so the address the voice is reading out is
            # the largest thing on screen when the scene cuts away from the table. The row
            # sits at y=321 in the 1600x900 shot; the rect keeps the table header in frame
            # for context and crops from the gutter at x=232, same rule as scenes 6 and 12.
            Zoom(to_rect=(232, 130, 1368, 430), at=0.20, seconds=2.2),
        ],
        caption="The gap",
    ),
    # -- 15 ------------------------------------------------------------------------------
    Scene(
        id="15-lens-how",
        narration=_n(
            """
            Lens is a phone-sized web app that Home SOC serves itself. Point the phone's
            camera at a device and it tells you which device on the network that is.
            Identification has one automatic mechanism: a visual tag — any machine-readable
            code the camera can decode. The barcode on the back of the router; the data
            matrix under the printer. And there is always a second path, whatever the
            camera can see: Pick manually sits on the bar the whole time. Scan a code Lens
            has never seen and it does not fail: it asks which device this is, likeliest
            first. You tap once, and every later scan of that code is instant. So most
            devices never need a sticker; their label already is one. For the rest, Home
            SOC prints stickers. A sticker carries an opaque random token. Never a MAC
            address, never an IP, never a hostname. Photograph one and you learn nothing
            about the network it belongs to.
            """
        ),
        shot=PageSequence(
            shots=(
                Slide(html_fn="lens_how"),
                Phone(path="/lens", state="unknown", scroll=0,
                      note="the 'Which device is this?' sheet: #unknown-code shows the raw "
                           "decoded value and #unknown-list the ranked candidates. phone.py "
                           "reaches this state by feeding the shim a code with no lens_tags "
                           "row — NOT by faking the sheet.\n\n"
                           "The code on screen is the camera's own sticker, with its "
                           "lens_tags row deleted for the length of this one screenshot and "
                           "put straight back. That is not a contradiction with scene 18, it "
                           "is the setup for it: this is the sticker's FIRST scan, the tap "
                           "below is what binds it, and scene 18 is a later scan of the same "
                           "code resolving instantly — which is exactly the sentence this "
                           "scene speaks over it."),
                Slide(html_fn="lens_how"),
            ),
            # The slide carries the definition, the phone carries the tag-learning beat, and
            # the slide comes back for the sticker privacy rule, which is a statement about
            # the token rather than about a screen. Measured in words (150 total): "Scan a
            # code Lens has never seen" starts at 0.45 and "You tap once... instant" ends at
            # 0.67.
            ats=(0.0, 0.50, 0.71),
        ),
        # "You tap once" used to play over a sheet with no finger anywhere in it, held
        # perfectly still for eleven seconds. The circle lands on the top candidate — which
        # the ranking has already put first, and which is the right answer — and there is a
        # beat of stillness either side of it, because a finger arrives, it does not glide.
        # No `then_shot`: binding the tag and opening the card is what scenes 18 and 19 are,
        # and re-showing it here would cost the scene its last sentence.
        actions=[
            Tap(at=0.645, xy=LENS_UNKNOWN_FIRST, seconds=0.55),
        ],
        caption="How it identifies",
    ),
    # -- 16 ------------------------------------------------------------------------------
    # Why HTTPS, not just "turn on HTTPS". See the two CAPTURE/PRIVACY warnings above the
    # PAIR_* selectors before recording this one.
    Scene(
        id="16-lens-setup",
        narration=_n(
            """
            A browser only hands a page your camera in a secure context. Localhost counts;
            a plain address on your own network does not. Without that rule, anything
            between your phone and this PC could quietly swap the page for one that keeps
            the video. So Lens runs over HTTPS, on a certificate Home SOC generates for
            itself. Self-signed means your phone has never heard of the issuer, and it will
            say so loudly. This page gives you the fingerprint: read the one the phone
            shows, check they match, and only then go on. If they do not, stop — something
            else answered. The pairing screen tests the rest, then shows a QR. Scan it with
            the phone's camera app. The code is single-use and lasts {pair_minutes}, and
            what comes back is the phone's own token: read-only, revocable on its own.
            """
        ),
        # Measured on the real page in the capture context (1600x900, dsf 2, dark, TLS with a
        # generated certificate): /lens/pair is exactly 900 px tall — scrollHeight ==
        # clientHeight — so the whole page is on screen at scroll 0 and there is nothing to
        # scroll to. .pair-checks sits at y=111 h=266, .fingerprint at y=465 h=63, .qr-wrap
        # at y=111 (right column), .pair-url at y=411. v1 of this scene declared a
        # three-state PageSequence scrolling to 300 and back; capture clamped both scrolls to
        # 0 and produced three identical images. One state, and the choreography does the
        # work instead.
        shot=Page(
            path="/lens/pair",
            scroll=0,
            note="the whole page fits the viewport: the 'Before you pair' preflight on the "
                 "left, the QR panel on the right, the certificate fingerprint below the "
                 "preflight. REQUIRES a generated certificate and the launcher's fictional "
                 "host, or .qr-wrap / .pair-url / .fingerprint do not exist — see the "
                 "CAPTURE WARNING above PAIR_CHECKS.",
        ),
        # Out of 143 words: the secure-context argument runs to 0.31, the certificate
        # 0.31-0.51, "This page gives you the fingerprint" starts at 0.51, "The pairing
        # screen tests the rest, then shows a QR" at 0.72, "Scan it with the phone's
        # camera app" at 0.79.
        actions=[
            # The whole first half is the *why*, spoken over the preflight panel — the part
            # of the page that says what is being checked and why it matters.
            Move(to=PAIR_CHECKS, at=0.04, seconds=1.1),
            Highlight(sel=PAIR_FIRST_CHECK, at=0.08, seconds=2.4),
            Highlight(sel=PAIR_CHECKS, at=0.32, seconds=2.2),
            Move(to=PAIR_FINGERPRINT, at=0.51, seconds=1.1),
            Highlight(sel=PAIR_FINGERPRINT, at=0.56, seconds=3.0),
            Move(to=PAIR_QR, at=0.75, seconds=1.1),
            Highlight(sel=PAIR_QR, at=0.78, seconds=2.4),
            Move(to=PAIR_URL, at=0.84, seconds=0.9),
            Highlight(sel=PAIR_URL, at=0.87, seconds=1.8),
        ],
        caption="Pairing a phone",
    ),
    # -- 17 ------------------------------------------------------------------------------
    Scene(
        id="17-lens-stickers",
        narration=_n(
            """
            The sticker sheet is one page. Choose a label size, choose whether to print the
            nickname under each code, and print it on whatever you have. By default it
            offers only the devices with nothing a camera can already read. The code itself
            carries only that device's token — the name printed beside it is there for you,
            not encoded in the square. Reprinting is safe: a device keeps the
            same code forever, so a sticker stuck on the printer last year still works.
            """
        ),
        shot=Page(
            path="/lens/stickers?names=1",
            scroll=0,
            note="the DEFAULT view — #which reads 'untagged' — which is what the narration "
                 "describes. seed_demo.py now leaves 16 of 18 devices untagged, so this "
                 "renders a full 16-label sheet (measured: .label count 16, page 1,302 px "
                 "tall). Only `names=1` is forced, so the nickname line the second sentence "
                 "mentions is actually on screen. An earlier take used ?which=all because "
                 "the then-current seed had tagged every device and the default sheet came "
                 "up empty; that is fixed, and 'all' would have put the select in a state "
                 "the voice was not describing.",
        ),
        # Out of 74 words: the label-size choice at 0.08, "By default it offers only the
        # devices..." at 0.39, "Each square is that device's token" at 0.595, "Reprinting is
        # safe" at 0.716 — after which the zoomed label simply holds while the voice explains
        # why a stuck sticker survives a reprint.
        actions=[
            Move(to=STICKERS_SIZE, at=0.05, seconds=1.0),
            Highlight(sel=STICKERS_SIZE, at=0.09, seconds=1.8),
            Move(to=STICKERS_WHICH, at=0.27, seconds=0.9),
            Highlight(sel=STICKERS_WHICH, at=0.31, seconds=2.2),
            Highlight(sel=STICKERS_GRID, at=0.39, seconds=2.0),
            # One label, big, while the voice says the square is the token and nothing else.
            # .label:first-child is at (409,275,252x96); the rect around it is grown to the
            # compositor's minimum window and kept inside the page.
            Zoom(to_rect=(330, 200, 940, 530), at=0.455, seconds=2.2),
            Move(to=STICKERS_FIRST_LABEL, at=0.475, seconds=0.9),
            Highlight(sel=STICKERS_FIRST_LABEL, at=0.505, seconds=2.6),
        ],
        caption="Stickers",
    ),
    # -- 18 ------------------------------------------------------------------------------
    # The money shot. Read CONTRACT_V2 section V3 before touching this scene: the recording
    # is Chrome on a PC in a phone-shaped viewport, with a zxing-cpp sidecar standing in for
    # the BarcodeDetector that desktop Chrome does not have. The pixels are genuinely
    # decoded; only the decoder lives beside the browser. Every sentence below is therefore
    # written about the product on Chrome on Android — "point the phone at the sticker" —
    # and never about this recording. Nothing here says "here it is on a phone".
    Scene(
        id="18-lens-scan",
        narration=_n(
            """
            So: the camera on the shelf, and a sticker on the front of it. Open Lens,
            point the phone at the label, hold still. There is no shutter and no button to
            press — Lens reads frames the whole time, {scan_rate}, from a shrunken copy of
            the picture. The reticle flashes on a hit, the token is looked up, and the card
            comes up over the live image. One thing to be straight about: that card is not
            glued to the wall in three dimensions. This is a viewfinder with an information
            panel over it.
            """
        ),
        # Three states, not two. The v2 cut had two, with no actions and no bursts, and the
        # whole 33 s was a still held for 19.5 s, a hard cut, and a second still held for
        # 13.2 s — under narration that says "hold still" (implying something is moving),
        # "Lens reads frames the whole time" and "the reticle flashes on a hit". Now:
        #   * every state is a *burst*, so the handheld drift scene_render.py baked into
        #     build/scene_camera.y4m (CONTRACT_V2 V3.2) actually reaches the film;
        #   * the middle state is the real instant of recognition, timed to the sentence
        #     that names it;
        #   * the card rises on the words "the card comes up over the live image", not
        #     seven seconds early.
        shot=PageSequence(
            shots=(
                PhonePair(
                    scene_png="shelf",
                    phone_state="scan",
                    scroll=0,
                    burst=26,
                    burst_ms=66,
                    note="the illustrated shelf on one side, the phone on the other, both "
                         "large enough that the QR sticker and the reticle on the screen "
                         "are legible at 1080p. 26 frames at 66 ms is 1.7 s of the real "
                         "camera feed, played forwards and backwards so it never cuts.",
                ),
                PhonePair(
                    scene_png="shelf",
                    phone_state="scan",
                    scroll=0,
                    hit=True,
                    note="the flash: #reticle carries is-hit (its four corners green) and "
                         "#scan-state reads 'identifying…' while the lookup is in flight. "
                         "One frame, deliberately — the state lives 600 ms in the real "
                         "product and a burst would run past it and flicker.",
                ),
                PhonePair(
                    scene_png="shelf",
                    phone_state="card",
                    scroll=0,
                    burst=26,
                    burst_ms=66,
                    note="#card is up, #scan-state reads the device name, and the "
                         "viewfinder is still drifting behind it. If the shim did not "
                         "decode, render.py FAILS here — it must never fall through to the "
                         "manual picker and let this narration run over it "
                         "(CONTRACT_V2 V3.4).",
                ),
            ),
            # Out of 101 words: "The reticle flashes on a hit" starts at 0.525 and "the card
            # comes up over the live image" at 0.67.
            ats=(0.0, 0.53, 0.645),
        ),
        actions=[],
        caption="The scan",
    ),
    # -- 19 ------------------------------------------------------------------------------
    # Reading the card, then the limits. Every figure spoken here came from a live
    # GET /api/lens/device/18 — see the CAMERA_* constants. The scroll offsets came from
    # measuring #card-body in the real 390x844 context; the comment above LENS_SEC_PROBLEMS
    # has the section map.
    Scene(
        id="19-lens-card",
        narration=_n(
            """
            Top of the card: no nickname, no hostname, no vendor. An unbranded camera,
            online, not trusted. Then a sentence of plain English rather than a severity
            table: {cam_problems}, {cam_critical}. Then the cost: {cam_cost} off your home
            score. Problems comes first, worst first, each opening into the same numbered
            steps as the dashboard, read in front of the thing. Exposed is the open ports,
            {cam_ports} of them, glossed in words: port {telnet_port_spoken}, Telnet —
            remote control with no encryption at all. Vulnerabilities stays folded until
            you want it, because the card leads with what to do rather than with a list of
            CVE numbers. Open it: this camera's web server matches a published flaw with no
            fix, because the software behind it was abandoned in {cam_cve_year}. The card
            says to replace the device. Anything on CISA's actively-exploited list is
            badged here. And then Talking to, the section that changes how people feel
            about their house. {cam_dns_block} of this camera's lookups in the last day
            were blocked. And what it keeps reaching for, over and over, is its vendor's
            telemetry collector. Three honest limits, then. Automatic scanning needs
            {lens_target}; anywhere else you pick from a list instead. The certificate
            warning is a real trust decision. And a code Lens has never seen costs you one
            tap, once.
            """
        ),
        shot=PageSequence(
            shots=(
                Phone(path="/lens", state="card", scroll=0,
                      note="header, headline and severity strip; the top of Problems is "
                           "below them at y=417 in #card-body"),
                Phone(path="/lens", state="card", scroll=150,
                      note="a short settle onto the severity strip and the -44 chip, which "
                           "is what 'Then the cost' is about. Without it the card's first "
                           "beat was a single frame held for 10.5 s."),
                Phone(path="/lens", state="card", scroll=360,
                      note="must frame the Problems section head and the Telnet row with "
                           "its severity badge; the section runs 417..1762"),
                Phone(path="/lens", state="card", scroll=1710,
                      note="must frame the Exposed section head (1762) and the 23/tcp and "
                           "554/tcp rows with their plain-English glosses; Exposed runs "
                           "1762..2204, so the whole section sits inside the 626 px window"),
                Phone(path="/lens", state="card", scroll=2150,
                      note="puts the Vulnerabilities section head (2203) 53 px below the top "
                           "of the 626 px window, so the tap below has somewhere to land. "
                           "Valid before the tap: max scroll is 2,991-626 = 2,365."),
                Phone(path="/lens", state="card", scroll=2290,
                      note="AFTER the tap: the CVE row's remediation line, 'No fixed version "
                           "exists: Boa has been unmaintained since 2005. Replace the "
                           "device.' The expanded section runs 2,203..2,437."),
                Phone(path="/lens", state="card", scroll=2400,
                      note="AFTER the tap, with Vulnerabilities expanded: Talking to starts "
                           "at 2,437 and runs to 3,033, and max scroll is 3,171-626 = 2,545. "
                           "Must frame the block-rate hero line."),
                Phone(path="/lens", state="card", scroll=2545,
                      note="the bottom of the expanded card: the destination bars under the "
                           "block-rate hero, with the History section head beneath them. "
                           "2,545 is exactly the maximum offset, so it cannot be clamped."),
                Slide(html_fn="lens_limits"),
            ),
            # Fractions measured by word position through the narration above (217 words):
            # "Problems comes first" 0.198, "Exposed is the open ports" 0.295, "Vulnerabilities
            # stays folded" 0.396, "Open it" 0.456, "And then Talking to" 0.641, "And what it
            # keeps reaching for" 0.728, "Three honest limits, then" 0.788.
            #
            # v2 held the Exposed state only to 0.35 and then sat on the Vulnerabilities /
            # Talking-to framing while the voice was still on port 23; and it ended on a
            # single frozen frame of the DNS panel for 27.5 s, through the entire honest-
            # limits block. Now the card follows the voice, and the limits get the slide
            # that was written for them — which also retires the stale "Reading the card"
            # caption, because _slide_mix fades the pill out as a slide fades in.
            ats=(0.0, 0.08, 0.19, 0.275, 0.385, 0.575, 0.655, 0.765, 0.825),
        ),
        # Every offset below was measured on the card this seed actually renders, in the real
        # 390x844 mobile context, before and after the tap:
        #   collapsed  #card-body clientHeight 626, scrollHeight 2,991, max scroll 2,365
        #              Problems 417 · Exposed 1,762 · Vulnerabilities 2,203 · Talking to
        #              2,256 · History 2,852
        #   expanded   scrollHeight 3,171, max scroll 2,545; the tap adds 180 px, so
        #              Talking to moves to 2,437 and History to 3,033
        # v1 of this scene carried offsets from an older card (scrollHeight 3,322) and asked
        # for 2,060 / 2,500 / 2,740; the last two clamped and the first framed the wrong
        # section. Re-measure here if the card's content changes again.
        actions=[
            PhoneScroll(to_y=150, at=0.08, seconds=1.1),
            PhoneScroll(to_y=360, at=0.19, seconds=1.6),
            PhoneScroll(to_y=1710, at=0.275, seconds=1.8,
                        note="a long travel on purpose — the thumb is passing six findings. "
                             "1,350 px is more than the card's own 626 px window, so the "
                             "two states share no captured rows and the compositor "
                             "cross-dissolves rather than inventing the strip between "
                             "them. That is deliberate and cannot be fixed by adding "
                             "intermediate offsets: any state close enough in time to "
                             "make this glide falls inside the 0.10 MERGE_WINDOW and is "
                             "folded back into this one."),
            PhoneScroll(to_y=2150, at=0.385, seconds=1.5),
            # Move, pause, then act: the section head has been on screen for a beat before
            # the finger arrives, and the expanded content gets its own beat afterwards.
            # 0.51 rather than 0.46: the tap's `then_shot` is the same target as the state
            # above it, so anything inside capture/compose's 0.10 MERGE_WINDOW of 0.40 folds
            # into it and the section is already open before the finger lands.
            Tap(
                at=0.495,
                xy=LENS_SEC_VULNS_HEAD,
                seconds=0.5,
                then_shot=Phone(path="/lens", state="card", scroll=2150,
                                note="Vulnerabilities is now open: the CVE row, its CVSS and "
                                     "EPSS line, and the 'no fixed version exists' "
                                     "remediation are visible. The expanded section runs "
                                     "2,203..2,437, entirely inside the window at this "
                                     "offset."),
                note="a real <details> toggle. Geometry for everything after this must be "
                     "measured on the expanded card (docstring note 3), which is 180 px "
                     "taller.",
            ),
            # "The card says to replace the device" (0.588) is the remediation line at the
            # bottom of the section the finger just opened, so go and look at it. The tap
            # and the scroll to Talking to were 0.16 apart, which was twelve seconds of a
            # still frame in the middle of the densest paragraph in the film.
            PhoneScroll(to_y=2290, at=0.575, seconds=1.3),
            PhoneScroll(to_y=2400, at=0.655, seconds=1.6),
            # "And what it keeps reaching for, over and over" — the destination bars, which
            # are below the block-rate hero. Also the beat that keeps the last stretch of
            # the card alive instead of holding one frame into the limits.
            PhoneScroll(to_y=2545, at=0.765, seconds=1.4),
        ],
        caption="Reading the card",
    ),
    # == close ===========================================================================
    # -- 20 ------------------------------------------------------------------------------
    Scene(
        id="20-close",
        narration=_n(
            """
            That is Home SOC. One process, on hardware you already own, costing nothing and
            sending nothing anywhere. A dashboard for the desk, a resolver for the house,
            and Lens for the hallway. MIT licensed, an offline test suite, and docs for the
            parts a walkthrough cannot cover. One rule: scan only networks you own. Point it at
            your own house, and give it five minutes.
            """
        ),
        shot=Slide(html_fn="close"),
        actions=[],
        caption=None,
    ),
]


# ---------------------------------------------------------------------------------------
# Self-check. Not pipeline logic — it only reads SCENES and reports inconsistencies, so a
# typo in a scroll offset or a stray slide name is caught before a fifteen-minute render.
# ---------------------------------------------------------------------------------------


def _shots_of(shot: Shot) -> list[Shot]:
    return list(shot.shots) if isinstance(shot, PageSequence) else [shot]


def _is_phone(shot: Shot) -> bool:
    return isinstance(shot, (Phone, PhonePair))


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

        # Every shot the scene can reach, including the ones a Click or a Tap lands on.
        reachable: list[Shot] = list(members)
        for action in scene.actions:
            after = getattr(action, "then_shot", None)
            if after is not None:
                reachable.extend(_shots_of(after))

        for member in reachable:
            if isinstance(member, Slide) and member.html_fn not in SLIDE_NAMES:
                problems.append(f"{scene.id}: unknown slide '{member.html_fn}'")
            if isinstance(member, Phone) and member.state not in PHONE_STATES:
                problems.append(f"{scene.id}: unknown Lens state '{member.state}'")
            if isinstance(member, PhonePair):
                if member.scene_png not in SCENE_RENDERS:
                    problems.append(f"{scene.id}: unknown scene render '{member.scene_png}'")
                if member.phone_state not in PHONE_STATES:
                    problems.append(f"{scene.id}: unknown Lens state '{member.phone_state}'")
            if isinstance(member, PageSequence):
                problems.append(f"{scene.id}: PageSequence may not be nested")

        # A scene may not hold both a live dashboard page and a Lens screen: their geometry
        # spaces differ (1600x900 vs 390x844) and so does the hand on screen. Slides are
        # neutral — scene 15 legitimately cuts between a slide and the phone — but a mouse
        # pointer gliding across a phone screen would misrepresent how the product is used,
        # so the action families are pinned to the scene's kind below.
        phone_scene = any(_is_phone(m) for m in reachable)
        if phone_scene and any(isinstance(m, Page) for m in reachable):
            problems.append(f"{scene.id}: mixes Lens screens and dashboard pages in one scene")

        offsets = {m.scroll for m in reachable if isinstance(m, (Page, Phone, PhonePair))}

        last_at = -1.0
        for action in scene.actions:
            at = action.at
            if not 0.0 <= at <= 1.0:
                problems.append(f"{scene.id}: action at={at} outside 0..1")
            if at < last_at:
                problems.append(f"{scene.id}: action at={at} is out of order")
            last_at = at

            if isinstance(action, PHONE_ACTIONS) and not phone_scene:
                problems.append(f"{scene.id}: {type(action).__name__} in a desktop scene")
            if isinstance(action, DESKTOP_ACTIONS) and phone_scene:
                problems.append(f"{scene.id}: {type(action).__name__} in a phone scene")

            if isinstance(action, (Scroll, PhoneScroll)):
                if action.to_y not in offsets:
                    problems.append(
                        f"{scene.id}: {type(action).__name__} to_y={action.to_y} has no "
                        f"matching shot (declared: {sorted(offsets)})"
                    )
                # The shot carrying that offset must take over at the same moment the scroll
                # starts, otherwise the compositor gets a dissolve and a scroll fighting over
                # the same second and a half.
                elif isinstance(scene.shot, PageSequence) and scene.shot.ats:
                    when = [
                        scene.shot.ats[i]
                        for i, m in enumerate(members)
                        if isinstance(m, (Page, Phone, PhonePair)) and m.scroll == action.to_y
                    ]
                    if when and not any(abs(w - at) < 1e-6 for w in when):
                        problems.append(
                            f"{scene.id}: {type(action).__name__} to_y={action.to_y} starts "
                            f"at {at} but its shot takes over at {when}"
                        )

            target = (
                getattr(action, "to", None)
                or getattr(action, "sel", None)
                or getattr(action, "xy", None)
            )
            if target is not None and not (
                target.startswith("css=") or target.startswith("xy=")
            ):
                problems.append(f"{scene.id}: target '{target}' is not css= or xy=")

            if isinstance(action, Zoom):
                x, y, w, h = action.to_rect
                if w <= 0 or h <= 0 or x < 0 or y < 0 or x + w > 1600 or y + h > 900:
                    problems.append(f"{scene.id}: Zoom rect {action.to_rect} leaves the "
                                    "1600x900 viewport")

        # A Click must be preceded by a Move, so the cursor is never clicking thin air. A Tap
        # deliberately has no such rule: a finger arrives, it does not glide.
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

    used_renders = {
        m.scene_png for s in SCENES for m in _shots_of(s.shot) if isinstance(m, PhonePair)
    }
    for name in SCENE_RENDERS:
        if name not in used_renders:
            problems.append(f"scene render '{name}' is declared but never used")

    return problems


def _word_count(text: str) -> int:
    return len(text.split())


if __name__ == "__main__":  # pragma: no cover - a developer convenience, not the pipeline
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    WPM = 145.0  # en-US-AndrewMultilingualNeural at -4%; measured speech runs nearer 141
    ACTS = {"01": "1 what it is", "02": "1 what it is", "03": "1 what it is",
            "04": "1 what it is", "14": "3 lens", "15": "3 lens", "16": "3 lens",
            "17": "3 lens", "18": "3 lens", "19": "3 lens", "20": "close"}
    total_words = 0
    per_act: dict[str, int] = {}
    print(f"{'scene':<20} {'words':>6} {'~sec':>6}  shot")
    print("-" * 78)
    for _scene in SCENES:
        words = _word_count(_scene.narration)
        total_words += words
        act = ACTS.get(_scene.id[:2], "2 dashboard")
        per_act[act] = per_act.get(act, 0) + words
        kind = type(_scene.shot).__name__
        if isinstance(_scene.shot, PageSequence):
            kind += "(" + ", ".join(type(m).__name__ for m in _scene.shot.shots) + ")"
        print(f"{_scene.id:<20} {words:>6} {words / WPM * 60:>6.1f}  {kind}")
    print("-" * 78)
    print(f"{'TOTAL':<20} {total_words:>6} {total_words / WPM * 60:>6.1f} s "
          f"= {total_words / WPM:.2f} min")
    for act in sorted(per_act):
        print(f"  act {act:<14} {per_act[act]:>5} words  "
              f"{per_act[act] / total_words * 100:>5.1f}%")
    issues = validate()
    if issues:
        print("\nPROBLEMS:")
        for issue in issues:
            print("  -", issue)
        raise SystemExit(1)
    print("\nvalidate(): OK")
