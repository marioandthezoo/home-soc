"""The scene script for the everyday film, "Meet the Household: one week with Home SOC".

This module turns ``video/everyday/SCRIPT.md`` into the data the pipeline already knows how to
film. It is **data only**, exactly like ``video/script.py`` (the technical cut, preserved
verbatim as ``video/script_technical.py``): nothing here seeds, captures, narrates or draws.

Same types, not look-alikes
---------------------------
Every shot and action below is an instance of the dataclasses defined in ``video/script.py``
(``Slide``, ``Page``, ``PhonePair``, ``PageSequence``, ``Move``, ``Click``, ``Scroll``,
``Highlight``, ``Scene``...), imported from there rather than redefined, so ``capture.py``,
``phone.py``, ``compose.py``, ``narrate.py`` and ``render.py`` treat this film exactly as they
treat the technical one. Importing ``script`` reads ``video/demo_data/homesoc.db`` (it derives
a few spoken figures of the technical cut from it), so the demo database must exist - which
``render.py`` guarantees by seeding first.

The words are settled
---------------------
Every narration string is SCRIPT.md's, word for word, with its ``[beat]`` / ``[beat 1.2]``
marks left in place: ``narrate.py`` synthesises the text between marks as separate segments
and joins them with exactly that much silence, and never speaks or subtitles a mark. One line
was changed after the script was written, because the product changed under it, and the change
is recorded in SCRIPT.md's "Production changes" section:

* 03 - Home's status sentence now adds up to the "N to fix" chip: "Eight things need your
  attention, two of them urgent; 25 more can wait." The narration said "Two things today, six
  more this week", which a viewer reads against "25 more can wait" as a contradiction. It now
  says "Eight things, two of them urgent."

:func:`check_script_md` compares every narration string with SCRIPT.md so a stray edit in
either place is caught; running this file does that and :func:`validate`.

Slides
------
``Slide(html_fn=...)`` names a function in ``video/slides_everyday.py`` (``SLIDES``), which the
pipeline selects for this film. All 38 are used. The animated beats are key-frame *variants*
of one illustration, cut on the word that animates them: the cold open builds the dinner table
in nine frames, ``dinner_table_ask`` -> ``guess7`` -> ``guess`` -> ``printer`` -> ``lamp`` ->
``heater`` -> ``gadgets`` -> ``camera`` -> ``count`` (each gadget arrives as it is named and the
counter reads 18 on "eighteen"), ``new_housemate`` ->
``new_housemate_dog_awake`` ("Labrador"), ``world_forecast`` -> ``world_forecast_umbrella``
("bring an umbrella"), and ``dinner_table_closing`` for the last callback.

Timing: on the word, not on the scene
-------------------------------------
Every ``at`` is a fraction of the scene's narration, but none is typed as a bare fraction: each
comes from :func:`narrate.phrase_at` / :func:`narrate.beat_at`, which read the word boundaries
and beat positions ``narrate.py`` measured in the scene's own audio (``build/<film>/beats.json``).
So a highlight lands on the word that names it however long the voice takes, and re-narrating
re-times the film. Each call carries a ``default`` - the value measured on 2026-09-23 with
``en-US-AndrewMultilingualNeural`` at ``-4%`` - which is used only until narration exists.

The choreography is a friend showing you around: the cursor *moves* (about a second, easing),
*pauses*, then *acts* - a glow or a click - on the word, and the result is left on screen long
enough to land. Offsets are in seconds: ``offset=-1.2`` on a Move means "set off 1.2 s before
the word, so the pointer is resting on the thing when the word arrives".

The dashboard on camera
-----------------------
Every page is the redesigned Stone & Sage dashboard in its **day** theme (the film's capture
browser reports ``prefers-color-scheme: light``; a dark browser gets the Dusk theme, which must
never appear). Every selector below was resolved on 2026-09-23 against a live dashboard served
from a freshly seeded scratch copy of ``video/demo_data`` - with the product's own embedded
resolver genuinely running on a loopback high port, so Home, the sidebar and the Blocking page
all read "running" - in a 1600x900 Chrome, on the state that is on screen when the action
fires (after the click, after the scroll). Measured boxes are in the comments.

Eight things about the capture engine shaped the choreography - each was found by running the
real capture and compose on this script - and they are worth knowing before editing a scene
(:func:`validate` checks 2, 5, 6 and 8; :func:`timing_problems` checks hold times, glows that
outlive their page and clicks that fire before the pointer arrives):

1. **A slide resets the page.** Slides are drawn into the same browser tab, so a page shown
   after a slide is freshly loaded: rows opened before the slide are closed again. Scene 06
   therefore opens its two rows *after* its last slide.
2. **A click needs somewhere new to land.** ``capture.plan_states`` merges a click's
   ``then_shot`` into the state before it when the two are the same page at the same scroll and
   less than ``MERGE_WINDOW`` (0.10 of the scene) apart - the "after" image then appears before
   the click. Where a click follows its page quickly, its ``then_shot`` scrolls a little (and
   usefully: to frame what the click opened). :func:`validate` enforces this.
3. **Only selects auto-submit.** Ticking Known flaws' "attackers are known to use" box does not
   navigate, so scene 07 ticks it and then presses Search, as a person would.
4. **Hover tooltips are native** (``title=``) and never reach a screenshot, so scene 08 points
   at "I've fixed it" rather than promising a tooltip.
5. **Nothing may fire at 0.0.** Capture runs an action *before* a state declared at the same
   instant, so an action at 0.0 is resolved on the previous scene's page. Openers use 0.012.
6. **One rect per selector string per scene.** ``geometry.json`` is keyed on the selector text,
   so a target that moves between two states of one scene needs a second spelling
   (``UPNP_TITLE`` / ``UPNP_TITLE_LATER``).
7. **Forms that POST cannot be pressed.** Capture's request routing re-fetches every request
   without the browser's origin headers, and the dashboard (rightly) refuses such a POST as
   cross-site. Only GET forms and in-page toggles are clicked; the sticker sheet in 12 is shown
   as the seed left it rather than by pressing "Create codes".
8. **Two phone states of one kind merge.** ``hit`` is not part of a phone state's identity, so an
   idle viewfinder less than ``MERGE_WINDOW`` before the recognition flash swallows the flash.

What must not be in frame (SCRIPT.md capture checklist)
-------------------------------------------------------
* **The router's make and model** (checklist 2). Devices shows it as "made by ..." under the
  router's row, Known flaws in the KEV row's title, Things to fix in the router finding's "What
  Home SOC found" and step 2. Scene 04 never scrolls Devices above the router's row. Where the
  scene is *about* that flaw (07, 08) it cannot be framed out, so :data:`REDACTIONS` lists the
  exact strings and :func:`redaction_js` returns a script that blurs them in place (text only,
  layout untouched); capture must run it on every dashboard page after it settles.
* **Real brand domains** on Blocking (checklist 5): the most-blocked table's top rows are
  visible at scroll 0. Also covered by :data:`REDACTIONS`. The camera's "phoning home" beat
  (10) is filmed on What happened filtered to ``ipcam-vendor`` - every row there is the
  fictional maker's ``.example`` domain, "from Unnamed camera's address" - so no brand domain
  and not the known-bad relay (checklist 6) is anywhere near it.

Honesty
-------
The screen, not the voice, is the authority on certainty. DNS rows say "requested from <device>'s
address" because a lookup is matched by network address, which another device can forge; the
narration speaks naturally ("the camera phones home") but never claims Home SOC caught a device
red-handed. The map is reliance, never traffic, and scene 11 says so over the page's own note.
94% is "somewhere in the world, next 30 days" (07). Lens is a viewfinder with a card, needs
Chrome on Android, and the scan is recorded through the decode sidecar (CONTRACT_V2 V3): scene
12's narration describes the product, never "this phone". Only networks you own (03, 14).
Everything on screen is the fictional demo household.
"""

from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:  # `python video/script_everyday.py` finds its siblings
    sys.path.insert(0, str(_HERE))

# The pipeline's own types - imported, never redefined (see the module docstring).
from script import (  # noqa: E402
    DESKTOP_ACTIONS,
    PHONE_ACTIONS,
    PHONE_STATES,
    SCENE_RENDERS,
    Action,
    Click,
    Highlight,
    Move,
    Page,
    PageSequence,
    Phone,
    PhonePair,
    PhoneScroll,
    Scene,
    Scroll,
    Shot,
    Slide,
    Tap,
    Zoom,
    css,
)

log = logging.getLogger(__name__)

__all__ = [
    "SCENES", "SLIDE_NAMES", "REDACTIONS", "Redaction", "redaction_js", "validate",
    "check_script_md", "timing_problems", "timeline", "CAMERA_IP", "SCRIPT_MD",
    # re-exported so `from script_everyday import *` is a complete scene vocabulary
    "Scene", "Slide", "Page", "Phone", "PhonePair", "PageSequence", "Move", "Click", "Scroll",
    "Highlight", "Zoom", "Tap", "PhoneScroll", "Shot", "Action", "css",
]

SCRIPT_MD = _HERE / "everyday" / "SCRIPT.md"

#: ``capture.py`` reads this off the film's script module to find the demo camera (the device
#: the scan rig draws a sticker for). Unbranded, "house number one forty-two".
CAMERA_IP = "192.168.1.142"
CAMERA_DEVICE_ID = 18
GATEWAY_DEVICE_ID = 1
PRINTER_DEVICE_ID = 12
SWITCH_DEVICE_ID = 16
LAMP_PLUG_DEVICE_ID = 14

# --------------------------------------------------------------------------- slides

try:  # the film's slide module; validation only - capture loads it itself
    import slides_everyday as _slides
    SLIDE_NAMES: tuple[str, ...] = tuple(_slides.SLIDES)
except Exception as _exc:  # pragma: no cover - reported by validate()
    log.warning("slides_everyday could not be imported: %s", _exc)
    SLIDE_NAMES = ()

# --------------------------------------------------------------------------- timing


def _no_beats(*_a: Any, default: float = 0.5, **_k: Any) -> float:
    return default


try:
    from narrate import beat_at as _beat_at, phrase_at as _phrase_at  # noqa: E402
except Exception:  # pragma: no cover - narrate.py missing or broken: defaults only
    _beat_at = _phrase_at = _no_beats


class _Clock:
    """``at`` fractions for one scene, read off its narration audio.

    ``t("phrase", default)`` is the moment the phrase starts (``edge="end"``: its last sound);
    ``t.beat(n, default)`` is where the scene's n-th ``[beat]`` ends (``edge="start"``: where
    it begins). ``offset`` is in seconds. ``default`` is the measured value, used until the
    film has been narrated. Values are clamped to 0..1 by narrate.py.
    """

    def __init__(self, scene_id: str) -> None:
        self.scene_id = scene_id

    def __call__(self, phrase: str, default: float, *, offset: float = 0.0,
                 occurrence: int = 1, edge: str = "start") -> float:
        return _phrase_at(self.scene_id, phrase, occurrence=occurrence, edge=edge,
                          offset=offset, default=default)

    def beat(self, n: int, default: float, *, edge: str = "end", offset: float = 0.0) -> float:
        return _beat_at(self.scene_id, n, edge=edge, offset=offset, default=default)


#: Seconds a Move takes. Long enough to be followed by the eye, short enough to feel direct.
GLIDE = 0.9
#: How long before a word a Move sets off, so the pointer is resting when the word lands.
LEAD = -1.3
#: A page that follows a slide takes over this long before its sentence: the 400 ms dissolve
#: is finished, and the page is still, when the words about it begin.
SETTLE = -0.45

# --------------------------------------------------------------------------- selectors
#
# Resolved 2026-09-23, 1600x900 CSS px, day theme. Rects are [x, y, w, h] on the state that is
# on screen when the action fires. "first in document order wins" wherever a selector could
# in principle match more than one element, as in capture.py.

# -- sidebar / topbar (every dashboard page)
NAV_HOME = css('.sidebar .nav-link[href="/"]')
NAV_FINDINGS = css('.sidebar .nav-link[href="/findings"]')        # 16,127,211x41 "Things to fix"
NAV_DNS = css('.sidebar .nav-link[href="/dns"]')                  # "Blocking"
SIDEBAR_BLOCKING = css("#chip-dns-state")                         # "Blocking: running"
CHIP_SCORE = css("#chip-score")                                   # 761,26,204x35 "Safety 10/100 · Needs work"
CHIP_OPEN = css("#chip-open")                                     # 975,26,153x35 "33 to fix · 2 urgent"
CHIP_DEVICES = css("#chip-devices")                               # "17 of 18 devices seen at last check"

# -- Home (/)
HOME_BANNER = css(".status-banner.is-attention")                  # 276,84,1292x61
HOME_GAUGE = css("#chart-gauge")                                  # 299,281,262x150
#: Beside the gauge's arc, not on it: an arrow parked on the numeral turns "10" into "1U".
HOME_GAUGE_REST = "xy=(566, 402)"
HOME_SEVERITY = css("#chart-severity")                            # 627,282,262x290
HOME_FIX_FIRST = css("#score-breakdown")                          # 299,672,590x472 @0
#: At scroll 0 the list runs past the fold (to y=1144), so it is only glowed from this offset,
#: where the whole card - heading and six rows - is on screen (list at y~372..844).
HOME_FIX_FIRST_SCROLL = 300
HOME_FIX_1 = css("#score-breakdown li:nth-child(1)")              # camera Telnet, 299,672,590x65
HOME_FIX_1_GAIN = css("#score-breakdown li:nth-child(1) .cost-gain")   # "+4 points"
HOME_FIX_2 = css("#score-breakdown li:nth-child(2)")              # router KEV, 299,737,590x86
HOME_FIX_2_GAIN = css("#score-breakdown li:nth-child(2) .cost-gain")   # "+4 points"
HOME_ATTN_CAMERA = css('#devices-attention li.cost:has(a[href="/devices/18"])')  # "not marked as yours yet"

# -- Things to fix (/findings)
SEV_CHIPS = css(".sev-counts")                                    # 276,142,1292x28
SEV_FIX_NOW = css(".sev-counts > a:nth-child(1)")                 # "2 critical Fix now"
SEV_THIS_WEEK = css(".sev-counts > a:nth-child(2)")
SEV_WORTH = css(".sev-counts > a:nth-child(3)")
SEV_WHEN = css(".sev-counts > a:nth-child(4)")
SEV_GOOD = css(".sev-counts > a:nth-child(5)")                    # 974,142,157x28
#: Filtered to the camera by the page's own search box (a GET form): six rows, Telnet first and
#: the router-door (UPnP) finding second. The box shows the address, so the filter is visible.
FINDINGS_CAMERA = "/findings?status=open&q=192.168.1.142"
_TELNET = 'tr.expandable[data-category="lan-services"][data-severity="critical"]'
TELNET_ROW = css(_TELNET)                                         # 299,363,1246x120
TELNET_TITLE = css(f"{_TELNET} .row-toggle")
TELNET_BADGE = css(f"{_TELNET} .sev-pair")                        # "Critical  Fix now"
TELNET_STEPS = css(f"{_TELNET} + tr.detail-row ol")               # 932,534,595x204 open, at scroll 0
TELNET_STEP_OFF = css(f"{_TELNET} + tr.detail-row ol li:nth-child(2)")  # "... disable Telnet ..."
_UPNP = 'tr.expandable[data-category="wan"]'
UPNP_ROW = css(_UPNP)                                             # 299,483,1246x96 (Telnet closed)
UPNP_TITLE = css(f"{_UPNP} .row-toggle")
#: The same button once the Telnet row above it is open and the page has scrolled. geometry.json
#: keeps one rect per selector *string* per scene, so a target that moves between two states
#: needs a second spelling of the same selector.
UPNP_TITLE_LATER = css(f'tr[data-category="wan"].expandable .row-toggle')
UPNP_STEP_OFF = css(f"{_UPNP} + tr.detail-row ol li:nth-child(3)")  # "Disable UPnP ... delete mappings"
#: The two "Fix now" findings: the router's known-exploited flaw first, then the camera's Telnet.
FINDINGS_URGENT = "/findings?status=open&severity=critical"
_ROUTER_KEV = 'tr.expandable[data-category="vulns"][data-severity="critical"]'
ROUTER_KEV_TITLE = css(f"{_ROUTER_KEV} .row-toggle")
ROUTER_KEV_STEPS = css(f"{_ROUTER_KEV} + tr.detail-row ol")
ROUTER_KEV_FIXED = css(f"{_ROUTER_KEV} + tr.detail-row .actions .btn-ok")   # "I've fixed it"

# -- Devices (/devices). Scroll 530 is the first offset at which the router's row (and the
# "made by" line under it) is above the fold: the page never shows Devices higher than that.
DEVICES_FIRST_SAFE_SCROLL = 530
DEVICES_BOTTOM = 764                                               # scrollHeight 1664 - 900
SWITCH_ROW = css(f'#devices-table tr.expandable:has(a[href="/devices/{SWITCH_DEVICE_ID}"])')
SWITCH_OFFLINE = css(
    f'#devices-table tr.expandable:has(a[href="/devices/{SWITCH_DEVICE_ID}"]) td:nth-child(3)'
)                                                                  # "Offline · last seen 19 hours ago"
LAMP_KIND = css(
    f'#devices-table tr.expandable:has(a[href="/devices/{LAMP_PLUG_DEVICE_ID}"]) td:nth-child(2)'
)                                                                  # "Smart device"
YOURS_LAMP = css(
    f'#devices-table tr.expandable:has(a[href="/devices/{LAMP_PLUG_DEVICE_ID}"]) td:nth-child(5) .btn'
)
YOURS_SWITCH = css(
    f'#devices-table tr.expandable:has(a[href="/devices/{SWITCH_DEVICE_ID}"]) td:nth-child(5) .btn'
)

# -- the camera (/devices/18)
CAMERA_PAGE = f"/devices/{CAMERA_DEVICE_ID}"
CAMERA_TITLE = css(".page-title")                                  # "Devices / Unnamed camera"
CAMERA_LEDE = css(".main > .lede")                                 # 276,133,699x58
CAMERA_MAKER = css(".toolbar > span.muted")                        # "Maker not known"
#: Scroll 1000 frames "About this device" (the empty name, no maker) above "Open doors".
CAMERA_DOORS_SCROLL = 1000
CAMERA_ABOUT = css('section.card:has(> form[data-post^="/api/devices/"])')   # 276,145,636x321 @1000
CAMERA_DOORS = css(".main > section.card:nth-of-type(3) table.tbl")          # 299,542,1246x228 @1000
CAMERA_DOOR_23 = css(".main > section.card:nth-of-type(3) table.tbl tbody tr:first-child")  # 23/tcp

# -- Known flaws (/vulns)
VULNS_KEV_BOX = css('form.filters input[name="kev"]')
VULNS_SEARCH = css('form.filters button[type="submit"]')
#: What the form submits when the box is ticked and Search is pressed.
VULNS_KEV_ONLY = "/vulns?kev=1&min_cvss=&q="
VULNS_KEV_BADGE = css("#vulns-table tbody tr.expandable:first-child .badge-kev")
VULNS_EPSS = css("#vulns-table tbody tr.expandable:first-child td:nth-child(5)")      # "94%"
VULNS_EPSS_HEAD = css("#vulns-table thead th:nth-child(5)")      # "Exploited somewhere, next 30 days"
_BOA = '#vulns-table tr.expandable:has(a[href="/devices/18"])'
BOA_TITLE = css(f"{_BOA} .row-toggle")
BOA_FIX = css(f"{_BOA} + tr.detail-row .detail > div:first-child > p:first-of-type")
#: After the Boa row is open, 420 puts the router's row (and its title) above the fold.
VULNS_BOA_SCROLL = 420

# -- This computer (/host)
HOST_LEDE = css(".main > .lede")                                   # "21 of 35 safety settings ... OK"
HOST_AV = css(".grid-top > section.card:nth-child(1) .stat-row")  # On / On / 1 day
HOST_THREAT = css(".grid-top > section.card:nth-child(1) .check-list li")   # invoice_2026_08.pdf.exe
HOST_UPDATES_LIST = css(".grid-top > section.card:nth-child(2) .check-list")
HOST_LAST_UPDATE = css(".grid-top > section.card:nth-child(2) > p.muted")   # "Last update installed ..."

# -- Blocking (/dns)
DNS_LOOKUPS = css(".grid-4 > .card:nth-child(1)")                 # "Websites looked up · last 24 h"
DNS_BLOCKED = css(".grid-4 > .card:nth-child(2)")
DNS_DEVICES = css(".grid-4 > .card:nth-child(3)")                 # "Devices using it: 12"
DNS_STATUS = css(".grid-4 > .card:nth-child(4)")
DNS_RUNNING = css(".kpi .badge")                                   # 1283,140,76x28 "Running"
#: Where the pointer rests while the Status card is lit: just right of the badge, in the card's
#: empty corner, so the one word this scene must show stays readable.
DNS_RUNNING_REST = "xy=(1368, 142)"
DNS_HOURS = css("#chart-dns-hours")                                # 299,417,1246x150
#: What happened, filtered by the page's own search box to the camera maker's domain: every row
#: is "Blocked N requests to ipcam-vendor.example from Unnamed camera's address", all day.
FEED_CAMERA_HOME = "/feed?q=ipcam-vendor"
FEED_FIRST = css("#feed-timeline > li:nth-child(2)")   # the first row under "Today"
FEED_SEARCH = css('#feed-filters input[name="q"]')

# -- What depends on what (/map)
MAP_NOTE = css("#map-note")                                        # "This is not a traffic diagram."
MAP_ROUTER = css(f'.map-node[data-id="device:{GATEWAY_DEVICE_ID}"]')   # 469,508,104x41 (and after)
MAP_PRINTER = css(f'.map-node[data-id="device:{PRINTER_DEVICE_ID}"]')  # 834,292,107x32 @33
MAP_HEADLINE = css(".map-headline")                                # 1231,245,314x102 @33
MAP_STATS = css(".map-stats")                                      # 0 / 17 / 0
MAP_LEGEND = css(".map-legend .legend-block:first-child")         # "How sure is Home SOC ..."
MAP_SEEN = css(".map-legend .legend-block:first-child .legend-list li:nth-child(1)")
MAP_WORKED_OUT = css(".map-legend .legend-block:first-child .legend-list li:nth-child(2)")
MAP_ASSUMED = css(".map-legend .legend-block:first-child .legend-list li:nth-child(3)")
#: "a pentagon drawn as a dashed outline is offered but has no confirmed consumers: Home SOC has
#: seen nothing use it, and it will not guess who might."
MAP_NO_CONSUMERS = css(".map-legend .legend-block:nth-child(2) li:last-child")
#: Selecting a node inserts "Back to the whole map" above the canvas and pushes it down 33 px;
#: the click's after-state is scrolled by exactly that, so the map stays put under the cursor.
MAP_AFTER_CLICK = 33
#: Frames the confidence legend and, beside it, "How each device is drawn" down to its last
#: entry (the pentagon with no confirmed consumers). Clamped by capture if the map is shorter.
MAP_LEGEND_SCROLL = 700

# -- Lens pairing and stickers (desktop pages, no sidebar)
PAIR_CERT = css(".pair-checks li.check:nth-child(2)")              # "HTTPS certificate · Self-signed"
PAIR_FINGERPRINT = css(".fingerprint")                             # 209,550,621x65 - the long code
#: Just right of the code grid (which ends near x=706), clear of every group.
PAIR_FINGERPRINT_REST = "xy=(738, 560)"
#: All devices, nicknames printed. A code exists only once someone asks for one, and the seed
#: has asked for exactly one: the camera's. So the sheet shows the villain's real QR sticker
#: (captioned "camera" - it has no nickname) among "no code" boxes. The page's own "Create
#: codes" button is a POST, which the capture browser's request routing cannot replay with
#: its origin headers (the dashboard then refuses it as cross-site), so it is not pressed.
STICKERS_ALL = "/lens/stickers?which=all&names=1"
STICKERS_CAMERA = css(".label:has(svg.qr)")                        # 410,569,252x96 - the camera's
STICKERS_EXPLAIN = css(".sticker-controls > p:first-of-type")       # "Each code is a random number ..."

# -- Report (/summary) and the diary (/feed)
REPORT_FOUND = css(".grid-4 > .card:nth-child(2)")                 # "Found all time"
#: The four figures together - "found, fixed" is said in under a second, too quick for the
#: pointer to visit two cards, so the row glows as one.
REPORT_FIGURES = css(".main .grid-4")
REPORT_TREND = css("#chart-summary-trend")                         # 299,602,590x170 "Is it getting better?"
FEED_DIARY = "/feed?window=7d&kinds=finding_new,finding_resolved,finding_auto_resolved,finding_ack,device_offline,device_new"
DIARY_TODAY = css("#feed-timeline > li.tl-day:first-child")        # "Today"
#: The first plain row of the day. (Where "Yesterday" falls depends on the hour the seed runs,
#: so it is not pointed at: it can be below the fold in the evening.)
DIARY_FIRST = css("#feed-timeline > li.tl-day:first-child + li.tl-item")

# --------------------------------------------------------------------------- redactions


@dataclass(frozen=True)
class Redaction:
    """Text that must not be legible in any frame of a page, blurred in place at capture.

    ``path`` is a path prefix ("/" matches every dashboard page). Inside every element matching
    ``within``, each text match of ``pattern`` (a JavaScript regular expression, case-sensitive)
    is wrapped in a span that is blurred - layout, wrapping and every other word untouched - so
    the page is still the product's own page, with one string made unreadable.
    """

    path: str
    pattern: str
    within: str = "body"
    why: str = ""


REDACTIONS: tuple[Redaction, ...] = (
    # Checklist 2: the router is unbranded in this film. Its make, model and firmware build
    # appear on Devices ("made by ..."), on Known flaws (the KEV row's title and fix line) and
    # on Things to fix (the finding's evidence, step 2 and its technical title).
    Redaction("/", r"TP-Link(?: Technologies Co\.,\s?Ltd\.?)?", why="the router's make"),
    Redaction("/", r"Archer AX21", why="the router's model"),
    Redaction("/", r"(?:httpd )?1\.1\.4 Build 2022\d{4}", why="the router's firmware build"),
    Redaction("/", r"1\.1\.4 Build 2023\d{4}", why="the router's fixed firmware build"),
    # Checklist 5: real brand domains on Blocking. Everything that is not the fictional
    # household's .example namespace is blurred in the most-blocked table (visible at scroll 0)
    # and in the overrides and live log further down.
    Redaction(
        "/dns",
        r"\b(?:[a-z0-9-]+\.)+(?:com|net|io|org|co|tv|app|ms|dev)\b",
        within=".main table.tbl td",
        why="real brand domains",
    ),
)


def redaction_js(path: str) -> str | None:
    """A self-contained script that blurs this page's :data:`REDACTIONS`, or ``None``.

    Run it with ``page.evaluate(js)`` after the page has settled (and again after a click
    re-renders part of it); it is idempotent. It returns the number of strings it blurred.
    """
    rules = [r for r in REDACTIONS if path.split("?")[0].startswith(r.path)]
    if not rules:
        return None
    import json

    spec = json.dumps([[r.pattern, r.within] for r in rules])
    return (
        "(() => { const rules = " + spec + "; let n = 0;"
        " for (const [pat, within] of rules) {"
        "  const re = new RegExp(pat, 'g');"
        "  for (const root of document.querySelectorAll(within)) {"
        "   const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);"
        "   const hits = [];"
        "   for (let t = walker.nextNode(); t; t = walker.nextNode()) {"
        "    if (t.parentElement && t.parentElement.closest('.hs-redact, script, style')) continue;"
        "    re.lastIndex = 0; if (re.test(t.data)) hits.push(t);"
        "   }"
        "   for (const t of hits) {"
        "    const frag = document.createDocumentFragment(); let last = 0; re.lastIndex = 0;"
        "    for (const m of t.data.matchAll(re)) {"
        "     frag.append(t.data.slice(last, m.index));"
        "     const s = document.createElement('span'); s.className = 'hs-redact';"
        "     s.textContent = m[0]; s.style.filter = 'blur(5px)'; s.style.userSelect = 'none';"
        "     frag.append(s); last = m.index + m[0].length; n++;"
        "    }"
        "    frag.append(t.data.slice(last)); t.replaceWith(frag);"
        "   }"
        "  }"
        " } return n; })()"
    )


# --------------------------------------------------------------------------- the scenes

SCENES: list[Scene] = []


def _scene(**kw: Any) -> None:
    SCENES.append(Scene(**kw))


# == 01 ======================================================================================
# The dinner table, built one phrase at a time (added at render, 2026-09-23: with only the
# guess and the count, the counter read 18 eight seconds before "eighteen" and the first 23 s
# of the film were one near-still). The question ("?"), the guess ("7?"), Dad's question, the
# printer, the lamp, the heater, the rest of the room, the camera with its brick-red "?", and
# the count (18) on "eighteen", holding for the reveal and the dinner line.
t = _Clock("01-cold-open")
_scene(
    id="01-cold-open",
    narration=(
        "Quick question. [beat] How many things in your house are on the Wi-Fi? [beat 1.2] "
        "This family guessed seven. [beat] Then Dad asked whether the printer counts. [beat] "
        "The printer counts. [beat] The printer would like it noted [beat] that it has always "
        "counted. [beat 1.2] So does the lamp. And the heater. The doorbell, the speakers, the "
        "games console. [beat] And one camera that nobody [beat] remembers buying. [beat 1.2] "
        "The real answer: eighteen. [beat] Try it at your next family dinner."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="dinner_table_ask"),
            Slide(html_fn="dinner_table_guess7"),
            Slide(html_fn="dinner_table_guess"),
            Slide(html_fn="dinner_table_printer"),
            Slide(html_fn="dinner_table_lamp"),
            Slide(html_fn="dinner_table_heater"),
            Slide(html_fn="dinner_table_gadgets"),
            Slide(html_fn="dinner_table_camera"),
            Slide(html_fn="dinner_table_count"),
        ),
        # One key frame per phrase, so each thing arrives as it is named and the counter
        # ticks to 18 on "eighteen", not eight seconds early (SCRIPT.md I1).
        ats=(
            0.0,
            t("guessed seven", 0.180, offset=-0.15),
            t("Dad asked", 0.234, offset=-0.15),
            # occurrence 2: the first "the printer counts" is Dad's question
            t("The printer counts", 0.335, occurrence=2, offset=-0.1),
            t("So does the lamp", 0.513, offset=-0.1),
            t("And the heater", 0.556, offset=-0.1),
            t("The doorbell", 0.592, offset=-0.1),
            t("one camera", 0.722, offset=-0.1),
            t("eighteen", 0.912, offset=-0.1),
        ),
    ),
    actions=[],
    caption="How many things are on your Wi-Fi?",
)

# == 02 ======================================================================================
# Title card, then the housemate. Home appears for the housemate's one line of dialogue - "Did
# you know the back door's open?" is exactly what Home's status banner is - so the new
# sidebar is seen once, at rest, for a couple of seconds. The illustration comes back for the
# Labrador, and the dog opens one eye on the word.
t = _Clock("02-meet-the-housemate")
_scene(
    id="02-meet-the-housemate",
    narration=(
        "Meet the new housemate: Home SOC. Big companies have a Security Operations Centre, a "
        "SOC. This is the home version, [beat] minus the room, the team and the budget: a free "
        "program for a Windows PC you already own. It looks around, explains in plain words, "
        "and points you to the fix. [beat] It's not an antivirus. It's the housemate who says, "
        "\"Did you know the back door's open?\" [beat] Not the one who tackles burglars. [beat] "
        "That's more of a Labrador thing."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="title_card"),
            Slide(html_fn="new_housemate"),
            Page(path="/", scroll=0,
                 note="Home at rest: the everyday sidebar (Home ... Blocking, then 'Advanced') "
                      "and the status banner the narration is paraphrasing."),
            Slide(html_fn="new_housemate"),
            Slide(html_fn="new_housemate_dog_awake"),
        ),
        # The finish pass: the title card holds for "Meet the new housemate: Home SOC." only (it
        # sat frozen for 13 s, under the first joke after the cold open); the Does / Doesn't
        # cards carry "minus the room, the team and the budget" and "It's not an antivirus";
        # Home arrives on the housemate's line itself, "Did you know the back door's open?".
        ats=(
            0.0,
            t("Big companies", 0.110, offset=-0.25),
            t("Did you know", 0.787, offset=-0.3),
            t("Not the one who tackles", 0.854, offset=-0.3),
            t("Labrador", 0.955, offset=-0.1),
        ),
    ),
    actions=[
        # The pointer drifts to the banner while the housemate "speaks" it - no glow, no
        # click: this is the page at rest, being introduced.
        Move(to=HOME_BANNER, at=t("Did you know", 0.795, offset=0.1), seconds=0.9),
    ],
    # No lower third: Home is up for two seconds, at rest, and the pill covered the third row
    # of "Fix these first" in that one look. The title card has just named the scene.
    caption=None,
)

# == 03 ======================================================================================
t = _Clock("03-monday-am-i-ok")
_scene(
    id="03-monday-am-i-ok",
    narration=(
        "Monday. Double-click to start. No account, no administrator password. One rule: only "
        "check networks you own or run. [beat] Give it five minutes, [beat] less time than the "
        "printer takes to decide whether it feels like printing. [beat 1.2] Home sums it up: "
        "your network needs attention. Eight things, two of them urgent. [beat] Score: ten out "
        "of a hundred. [beat] Don't panic. It's low for two fixable reasons. [beat] Security "
        "people say Critical, High, Medium, Low and Info, [beat] like a robot reading out a "
        "weather warning. Home SOC translates: Fix now. Fix this week. Worth fixing. When you "
        "have time. Good to know. [beat] No sirens. Just a housemate with a list."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="double_click"),
            Slide(html_fn="double_click_rule"),
            Slide(html_fn="double_click_clock"),
            Slide(html_fn="double_click_printer"),
            Page(path="/", scroll=0,
                 note="Home: the status banner reads 'Eight things need your attention, two of "
                      "them urgent; 25 more can wait.' beside the '33 to fix · 2 urgent' chip, "
                      "and the gauge reads 10 · Needs work."),
            Slide(html_fn="robot_forecast"),
            Page(path="/findings", scroll=0,
                 note="Things to fix: the five severity chips, each with its plain word, in "
                      "the row under the tabs (.sev-counts)."),
        ),
        ats=(
            0.0,
            t("One rule", 0.080, offset=-0.15),
            t("Give it five minutes", 0.140, offset=-0.1),
            t("less time than the printer", 0.190, offset=-0.1),
            t("Home sums it up", 0.330, offset=SETTLE),
            t("Security people say", 0.566, offset=-0.3),
            t("Home SOC translates", 0.756, offset=SETTLE),
        ),
    ),
    actions=[
        # Home: the sentence, then the number, then the reason it is low.
        Move(to=HOME_BANNER, at=t("Home sums it up", 0.342, offset=0.1), seconds=GLIDE),
        Highlight(sel=HOME_BANNER, at=t("your network needs attention", 0.365), seconds=4.2),
        Move(to=HOME_GAUGE_REST, at=t("Score", 0.425, offset=-0.9), seconds=GLIDE),
        Highlight(sel=HOME_GAUGE, at=t("ten out of a hundred", 0.459), seconds=2.2),
        Highlight(sel=CHIP_SCORE, at=t("ten out of a hundred", 0.478, edge="end", offset=0.1),
                  seconds=1.6),
        # "two fixable reasons": the two Fix-now rows of "Fix these first", one on each word,
        # not the "33 to fix" donut (three competing numbers on the reassuring line).
        Move(to=HOME_FIX_1, at=t("Don't panic", 0.484, offset=-0.2), seconds=GLIDE),
        Highlight(sel=HOME_FIX_1, at=t("two fixable", 0.515), seconds=0.8),
        Move(to=HOME_FIX_2, at=t("fixable", 0.525, offset=0.0), seconds=0.4),
        Highlight(sel=HOME_FIX_2, at=t("reasons", 0.535, offset=-0.15), seconds=0.95),
        # Things to fix: one chip per plain word, in step with the voice.
        Move(to=SEV_FIX_NOW, at=t("Fix now", 0.791, offset=-0.8), seconds=0.7),
        Highlight(sel=SEV_FIX_NOW, at=t("Fix now", 0.808), seconds=1.0),
        Move(to=SEV_THIS_WEEK, at=t("Fix this week", 0.826, offset=-0.35), seconds=0.45),
        Highlight(sel=SEV_THIS_WEEK, at=t("Fix this week", 0.833), seconds=1.0),
        Move(to=SEV_WORTH, at=t("Worth fixing", 0.850, offset=-0.35), seconds=0.45),
        Highlight(sel=SEV_WORTH, at=t("Worth fixing", 0.858), seconds=1.0),
        Move(to=SEV_WHEN, at=t("When you have time", 0.874, offset=-0.35), seconds=0.45),
        Highlight(sel=SEV_WHEN, at=t("When you have time", 0.882), seconds=1.1),
        Move(to=SEV_GOOD, at=t("Good to know", 0.901, offset=-0.35), seconds=0.45),
        Highlight(sel=SEV_GOOD, at=t("Good to know", 0.908), seconds=1.2),
        # "...a housemate with a list": the pointer comes to rest on the list itself.
        Move(to=NAV_FINDINGS, at=t("No sirens", 0.937, offset=0.2), seconds=1.1),
        Highlight(sel=NAV_FINDINGS, at=t("a housemate with a list", 0.964), seconds=1.4),
    ],
    caption="Monday: am I OK?",
)

# == 04 ======================================================================================
# Devices never shows its first three rows here: the router's "made by" line sits in the third
# (checklist 2). The list is joined at the row after it and scrolled to the bottom, where the
# Switch is. "One, nobody can explain" is landed on Home's "Devices that need attention" card,
# whose camera row says "not marked as yours yet" - the same fact as Devices' "Not sure".
t = _Clock("04-monday-roll-call")
_scene(
    id="04-monday-roll-call",
    narration=(
        "Roll call. Think of your network as a little street. Every gadget gets a house number, "
        "called an IP address, and the router is the one road out to the internet. [beat] "
        "Devices lists them all. The Switch is offline. [beat] It's a school night. [beat] Why "
        "eighteen? Because \"smart\" now mostly means \"has Wi-Fi\", and every one is a small "
        "computer that needs updates. [beat] Seventeen, the family recognised. [beat] One, "
        "nobody can explain."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="little_street"),
            Page(path="/devices", scroll=DEVICES_FIRST_SAFE_SCROLL,
                 note="joined below the router's row: Ellie's iPhone at the top, Kitchen "
                      "tablet at the bottom; the router's 'made by' line is above the fold"),
            Page(path="/devices", scroll=DEVICES_BOTTOM,
                 note="the bottom of the list: Nintendo Switch 'Offline · last seen ...'"),
            Page(path="/", scroll=0,
                 note="Home's 'Devices that need attention': Unnamed camera 192.168.1.142, "
                      "'6 things to fix · not marked as yours yet'"),
        ),
        ats=(
            0.0,
            t("Devices lists them all", 0.370, offset=SETTLE),
            t("The Switch is offline", 0.438, offset=-0.2),
            t("One, nobody can explain", 0.919, offset=-0.55),
        ),
    ),
    actions=[
        # Into the list as it arrives, so the pointer is not left behind on the sidebar.
        Move(to="xy=(820, 470)", at=t("Devices lists them all", 0.393, offset=0.2), seconds=1.0),
        Scroll(to_y=DEVICES_BOTTOM, at=t("The Switch is offline", 0.438, offset=-0.2), seconds=1.3),
        Move(to=SWITCH_OFFLINE, at=t("The Switch is offline", 0.459, offset=0.4), seconds=GLIDE),
        Highlight(sel=SWITCH_ROW, at=t("offline", 0.467), seconds=3.0),
        # "smart now mostly means has Wi-Fi": the lamp plug, whose kind reads "Smart device".
        Move(to=LAMP_KIND, at=t("smart", 0.576, offset=-0.9), seconds=GLIDE),
        Highlight(sel=LAMP_KIND, at=t("smart", 0.607), seconds=2.0),
        # "Seventeen, the family recognised": down the "Is it yours?" column.
        Move(to=YOURS_LAMP, at=t("Seventeen", 0.806, offset=-1.0), seconds=0.8),
        Move(to=YOURS_SWITCH, at=t("Seventeen", 0.840, offset=0.0), seconds=0.9),
        Highlight(sel=YOURS_SWITCH, at=t("the family recognised", 0.873), seconds=1.25),
        # "One, nobody can explain": the one that is not.
        Move(to=HOME_ATTN_CAMERA, at=t("One, nobody can explain", 0.931, offset=-0.2), seconds=0.8),
        Highlight(sel=HOME_ATTN_CAMERA, at=t("nobody can explain", 0.955), seconds=2.0),
    ],
    caption="Monday: the roll call",
)

# == 05 ======================================================================================
t = _Clock("05-tuesday-open-doors")
_scene(
    id="05-tuesday-open-doors",
    narration=(
        "Tuesday: the mystery guest. Unnamed camera, house number one forty-two. [beat] Family "
        "theories: a gift, a bargain, or \"it came free with something\". [beat 1.2] Every "
        "gadget is like a house with numbered doors, called ports. Behind each open door is a "
        "service: a web page, a video stream. Doors are how gadgets work, but each is also a "
        "way in, so fewer is safer. [beat] Home SOC walks round and reads the sign on each open "
        "door. [beat] It never tries the handle. [beat] One of its four open doors [beat] is "
        "door twenty-three."
    ),
    shot=PageSequence(
        shots=(
            Page(path=CAMERA_PAGE, scroll=0,
                 note="the camera's page: 'Devices / Unnamed camera 192.168.1.142', the summary "
                      "line and 'Maker not known'"),
            Page(path=CAMERA_PAGE, scroll=CAMERA_DOORS_SCROLL,
                 note="'About this device' (the name box empty, only the placeholder) with "
                      "'Open doors on this device' below it: 23, 80, 554, 8080"),
            Slide(html_fn="numbered_doors_bare"),
            Slide(html_fn="numbered_doors_signs"),
            Slide(html_fn="numbered_doors"),
            Slide(html_fn="numbered_doors_reach"),
            Slide(html_fn="numbered_doors_withdraw"),
            Page(path=CAMERA_PAGE, scroll=CAMERA_DOORS_SCROLL,
                 note="back on the open doors: four rows, 23/tcp first"),
        ),
        # I6 builds on its words (the finish pass: one drawing held 21 s, the joke not
        # animated): the doors, the signs, Home SOC with its torch, a hand near door 23's
        # handle on "It never tries" and politely withdrawn on "the handle".
        ats=(
            0.0,
            t("a bargain", 0.219, offset=-0.1),
            t("Every gadget is like a house", 0.316, offset=-0.3),
            t("Behind each open door", 0.450, offset=-0.2),
            t("Home SOC walks round", 0.700, offset=-0.2),
            t("It never tries", 0.830, offset=-0.2),
            t("the handle", 0.860, offset=0.0),
            t("One of its four open doors", 0.897, offset=-0.1),
        ),
    ),
    actions=[
        Move(to=CAMERA_TITLE, at=0.012, seconds=1.0),
        Highlight(sel=CAMERA_TITLE, at=t("Unnamed camera", 0.066), seconds=2.6),
        # Nobody knows who made it - the page says "Maker not known" - hence the theories.
        Move(to=CAMERA_MAKER, at=t("Family theories", 0.132, offset=-0.8), seconds=0.8),
        Highlight(sel=CAMERA_MAKER, at=t("Family theories", 0.153), seconds=1.3),
        Scroll(to_y=CAMERA_DOORS_SCROLL, at=t("a bargain", 0.219, offset=-0.1), seconds=1.2),
        Move(to=CAMERA_ABOUT, at=t("it came free with something", 0.246, offset=-0.3),
             seconds=0.8),
        Highlight(sel=CAMERA_ABOUT, at=t("it came free with something", 0.262, offset=0.3),
                  seconds=1.9),
        Move(to=CAMERA_DOORS, at=t("One of its four open doors", 0.909, offset=0.0), seconds=0.8),
        Highlight(sel=CAMERA_DOORS, at=t("four open doors", 0.916), seconds=1.4),
        Move(to=CAMERA_DOOR_23, at=t("is door twenty-three", 0.947, offset=-0.7), seconds=0.6),
        Highlight(sel=CAMERA_DOOR_23, at=t("twenty-three", 0.975), seconds=2.2),
    ],
    caption="Tuesday: the mystery guest",
)

# == 06 ======================================================================================
# Things to fix, filtered to the camera by its search box: Telnet (Fix now) is the first row
# and the door the camera opened in the router (UPnP, Fix this week) is the second. The two
# illustrations sit inside the Telnet explanation; the router's-sleeve illustration inside the
# UPnP one. Both rows are opened only after the last slide (a slide reloads the page), on
# "How to fix it says", and the camera stays on the steps through the unplug aside - which is
# the narrator's joke, never an on-screen instruction.
t = _Clock("06-tuesday-telnet")
_scene(
    id="06-tuesday-telnet",
    narration=(
        "Door twenty-three is Telnet: remote control by typing, from nineteen sixty-nine, the "
        "year of the moon landing. [beat] It has aged considerably worse. [beat] It sends your "
        "password unscrambled, like a PIN on a postcard. So: Fix now. [beat 1.2] Then the camera "
        "asked the router to open a door from the internet to its settings page. That's called "
        "Universal Plug and Play, [beat] which is exactly as careful as it sounds: any gadget "
        "asks, and the router says yes. [beat] How to fix it says: Telnet off on the camera, "
        "Plug and Play off on the router. [beat] Or unplug it and see who complains. [beat 1.2] "
        "Somebody always complains. That's how you find out whose it is. [beat] It isn't evil. "
        "Just very old on the inside."
    ),
    shot=PageSequence(
        shots=(
            Page(path=FINDINGS_CAMERA, scroll=0,
                 note="Things to fix filtered to 192.168.1.142 (the address shows in the search "
                      "box): six rows, Telnet first, the router-door finding second"),
            Slide(html_fn="telnet_1969"),
            Slide(html_fn="postcard"),
            Page(path=FINDINGS_CAMERA, scroll=0, note="back for 'So: Fix now'"),
            Slide(html_fn="obliging_router"),
            Page(path=FINDINGS_CAMERA, scroll=0,
                 note="fresh after the slide: both rows closed until the two clicks below"),
        ),
        ats=(
            0.0,
            t("from nineteen sixty-nine", 0.085, offset=-0.2),
            t("like a PIN on a postcard", 0.273, offset=-0.3),
            t("So Fix now", 0.310, offset=-0.35),
            t("any gadget asks", 0.573, offset=-0.3),
            t("How to fix it says", 0.632, offset=-0.8),
        ),
    ),
    actions=[
        Move(to=TELNET_TITLE, at=0.012, seconds=1.0),
        Highlight(sel=TELNET_ROW, at=t("Telnet", 0.029), seconds=2.6),
        # So: Fix now.
        Move(to=TELNET_BADGE, at=t("So Fix now", 0.313, offset=-0.2), seconds=0.7),
        Highlight(sel=TELNET_BADGE, at=t("Fix now", 0.322), seconds=2.2),
        # The door through the router: the next row down.
        Move(to=UPNP_TITLE, at=t("Then the camera asked", 0.360), seconds=GLIDE),
        Highlight(sel=UPNP_ROW, at=t("to open a door", 0.394), seconds=3.4),
        # How to fix it says: open Telnet, point at "disable Telnet" ...
        Move(to=TELNET_TITLE, at=t("How to fix it says", 0.634, offset=-0.7), seconds=0.6),
        Click(at=t("fix it says", 0.655, offset=0.1),
              then_shot=Page(path=FINDINGS_CAMERA, scroll=150,
                             note="Telnet open: What Home SOC found / How to fix it / the three "
                                  "buttons; the router-door row is at y~696, below it"),
              note="a real click on the row: it expands in place"),
        Highlight(sel=TELNET_STEP_OFF, at=t("Telnet off on the camera", 0.681), seconds=1.2),
        # ... then open the router-door row and point at "Disable UPnP".
        Move(to=UPNP_TITLE_LATER, at=t("Plug and Play off", 0.695, offset=-0.75), seconds=0.55),
        Click(at=t("Plug and Play off", 0.708, offset=-0.1),
              then_shot=Page(path=FINDINGS_CAMERA, scroll=560,
                             note="the router-door row open: its steps end with 'Disable UPnP "
                                  "... and delete existing mappings'"),
              note="a real click on the second row"),
        Highlight(sel=UPNP_STEP_OFF, at=t("off on the router", 0.734), seconds=3.4),
        # The unplug aside is said over the steps; the pointer rests on them and then on the
        # camera's name as the voice forgives it.
        Move(to=css(f"{_UPNP} td:nth-child(3)"), at=t("It isn't evil", 0.925, offset=-0.4),
             seconds=1.0),
    ],
    caption="Tuesday: why the camera is the villain",
)

# == 07 ======================================================================================
# Known flaws. The router's row is the subject, so its make and model cannot be framed out:
# REDACTIONS blurs them. The percentage column is headed "Exploited somewhere, next 30 days" -
# never "chance of attack" - and is pointed at while the voice says what it is not.
t = _Clock("07-wednesday-kev")
_scene(
    id="07-wednesday-kev",
    narration=(
        "Wednesday. Home SOC checks the router's software against public lists of known flaws. "
        "[beat] A flaw existing is a recall notice for your lock. Attackers using it is a news "
        "bulletin: burglars somewhere are using this exact trick, on this exact lock, right "
        "now. [beat] America's cybersecurity agency keeps a list of those, called KEV. [beat] "
        "Just think of him as Kev. [beat 1.2] This router is on Kev's list. [beat] The "
        "ninety-four percent beside it isn't your chance of being attacked. It's the chance "
        "this flaw gets used somewhere in the world in the next thirty days. [beat] A forecast "
        "for the whole world, not your garden. [beat] Still, bring an umbrella."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="recall_vs_bulletin"),
            Page(path="/vulns", scroll=0,
                 note="Known software flaws, unfiltered: seven rows, the KEV one first"),
            Slide(html_fn="world_forecast"),
            Slide(html_fn="world_forecast_umbrella"),
        ),
        ats=(
            0.0,
            t("America's cybersecurity agency", 0.420, offset=-0.5),
            t("A forecast for the whole world", 0.874, offset=-0.3),
            t("bring an umbrella", 0.971, offset=-0.2),
        ),
    ),
    actions=[
        Move(to=VULNS_KEV_BOX, at=t("called KEV", 0.505, offset=-0.8), seconds=GLIDE),
        Click(at=t("Just think of him as Kev", 0.577, offset=0.2),
              then_shot=Page(path="/vulns", scroll=0,
                             note="the box is ticked; the page has not moved (checkboxes do not "
                                  "submit - only selects do)"),
              note="ticks 'Only flaws attackers are known to use (KEV)'"),
        Move(to=VULNS_SEARCH, at=t("Just think of him as Kev", 0.584, offset=0.5), seconds=0.6),
        Click(at=t("This router is on Kev's list", 0.605, offset=-0.9),
              then_shot=Page(path=VULNS_KEV_ONLY, scroll=0,
                             note="one row left: the Home router, KEV, 94%"),
              note="Search submits the form: a real navigation"),
        Move(to=VULNS_KEV_BADGE, at=t("This router is on Kev's list", 0.628, offset=0.1),
             seconds=0.8),
        Highlight(sel=VULNS_KEV_BADGE, at=t("Kev's list", 0.644), seconds=2.0),
        Move(to=VULNS_EPSS, at=t("ninety-four percent", 0.657, offset=-0.9), seconds=GLIDE),
        Highlight(sel=VULNS_EPSS, at=t("ninety-four percent", 0.679), seconds=2.6),
        Highlight(sel=VULNS_EPSS_HEAD, at=t("It's the chance", 0.777), seconds=3.8),
    ],
    caption="Wednesday: a flaw vs. a flaw in use",
)

# == 08 ======================================================================================
t = _Clock("08-thursday-updates")
_scene(
    id="08-thursday-updates",
    narration=(
        "Thursday. The umbrella is an update. A router's software is called firmware, and an "
        "update is the maker posting you a better lock, free. [beat] You just have to open the "
        "post. [beat] Dad presses update, and the house is offline for ninety seconds. [beat] "
        "Exactly long enough for someone upstairs to shout, \"Is the internet down?\" [beat 1.2] "
        "Press \"I've fixed it\", and Home SOC double-checks on the next scan. [beat] No update "
        "at all, like the camera? Then switch it off, or replace it."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="world_forecast_umbrella"),
            Slide(html_fn="lock_in_the_post"),
            Page(path=FINDINGS_URGENT, scroll=0,
                 note="the two Fix-now findings; the router's known-exploited flaw is first"),
            Page(path="/vulns", scroll=0,
                 note="Known flaws again, for the camera's web-server flaw (third row)"),
        ),
        ats=(
            0.0,
            t("A router's software is called firmware", 0.082, offset=-0.3),
            t("Dad presses update", 0.347, offset=SETTLE),
            t("No update at all", 0.837, offset=-0.6),
        ),
    ),
    actions=[
        Move(to=ROUTER_KEV_TITLE, at=t("Dad presses update", 0.362, offset=0.0), seconds=0.8),
        Click(at=t("and the house is offline", 0.406, offset=-0.2),
              then_shot=Page(path=FINDINGS_URGENT, scroll=80,
                             note="the router's row open: its steps (install the latest "
                                  "firmware ... or replace the device) and the three buttons"),
              note="a real click: the row expands"),
        Move(to=ROUTER_KEV_STEPS, at=t("ninety seconds", 0.458, offset=-0.2), seconds=GLIDE),
        Highlight(sel=ROUTER_KEV_STEPS, at=t("ninety seconds", 0.480, offset=0.5), seconds=3.0),
        Move(to=ROUTER_KEV_FIXED, at=t("Press I've fixed it", 0.665, offset=-1.0), seconds=GLIDE),
        Highlight(sel=ROUTER_KEV_FIXED, at=t("I've fixed it", 0.720), seconds=3.2),
        Move(to=BOA_TITLE, at=t("No update at all", 0.852, offset=-0.1), seconds=0.8),
        Click(at=t("like the camera", 0.901, offset=0.1),
              then_shot=Page(path="/vulns", scroll=VULNS_BOA_SCROLL,
                             note="the camera's Boa row open: 'No fixed version exists: Boa has "
                                  "been unmaintained since 2005. Replace the device.' The "
                                  "router's row is scrolled off the top."),
              note="a real click: the row expands"),
        Highlight(sel=BOA_FIX, at=t("Then switch it off", 0.932), seconds=2.6),
    ],
    caption="Thursday: updates are the fix",
)

# == 09 ======================================================================================
t = _Clock("09-thursday-this-computer")
_scene(
    id="09-thursday-this-computer",
    narration=(
        "It also checks the PC it runs on. The antivirus is Windows' job, and Home SOC tells you "
        "if it's ever switched off. [beat] Recently it caught invoice dot P D F dot E X E: a "
        "program in a PDF costume. [beat] And updates are waiting. We've all pressed \"remind me "
        "tomorrow\". [beat] Tomorrow has been going on for a while."
    ),
    shot=PageSequence(
        shots=(
            Page(path="/host", scroll=0,
                 note="This computer: '21 of 35 safety settings ... are OK', the antivirus card "
                      "(On / On), the caught threat, and Windows updates"),
            Slide(html_fn="pdf_costume"),
            Page(path="/host", scroll=0, note="back for the updates"),
        ),
        ats=(
            0.0,
            t("a program in a PDF costume", 0.586, offset=-0.3),
            t("And updates are waiting", 0.698, offset=SETTLE),
        ),
    ),
    actions=[
        Move(to=HOST_LEDE, at=0.012, seconds=1.0),
        Highlight(sel=HOST_LEDE, at=t("checks the PC it runs on", 0.021), seconds=2.2),
        Move(to=HOST_AV, at=t("The antivirus is Windows' job", 0.087, offset=-0.6), seconds=GLIDE),
        Highlight(sel=HOST_AV, at=t("The antivirus is Windows' job", 0.114), seconds=3.8),
        Move(to=HOST_THREAT, at=t("Recently it caught", 0.353, offset=-0.8), seconds=GLIDE),
        Highlight(sel=HOST_THREAT, at=t("invoice", 0.433), seconds=2.6),
        Move(to=HOST_UPDATES_LIST, at=t("And updates are waiting", 0.703, offset=-0.35), seconds=0.7),
        Highlight(sel=HOST_UPDATES_LIST, at=t("updates are waiting", 0.725), seconds=2.4),
        Move(to=HOST_LAST_UPDATE, at=t("Tomorrow has been going on", 0.872, offset=-0.9),
             seconds=0.8),
        Highlight(sel=HOST_LAST_UPDATE, at=t("Tomorrow has been going on", 0.912), seconds=2.4),
    ],
    caption="Thursday: the PC it lives on",
)

# == 10 ======================================================================================
# Blocking is genuinely running (capture starts the product's own resolver on a loopback high
# port and refuses to capture unless Home, the sidebar and this page say so). The camera's
# phoning home is shown on What happened, searched for its maker's domain: row after row of
# "Blocked N requests to ipcam-vendor.example from Unnamed camera's address", through the day.
t = _Clock("10-friday-blocking")
_scene(
    id="10-friday-blocking",
    narration=(
        "Friday: the phone book. Before a gadget visits a website, it looks up where it lives. "
        "That's DNS: the internet's phone book. [beat] Switch on Blocking, do a one-time setup, "
        "and if your router allows it, Home SOC becomes your house's phone book: one that "
        "refuses ads, trackers, scams and malware. [beat] Thousands of lookups a day. [beat] You "
        "didn't do that. The gadgets did. [beat] The camera phones home all day, "
        "like a homesick kid at camp who checks in constantly and never says what about. [beat] "
        "Two limits. If this PC sleeps, nothing can look anything up, and the internet seems "
        "down. And some gadgets bring their own phone book. [beat] A filter, not a force field."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="phone_book"),
            Page(path="/dns", scroll=0,
                 note="Web blocking: 'Websites looked up · last 24 h' (thousands), 'Blocked', "
                      "'Devices using it', Status 'Running', and the per-hour chart. Brand "
                      "domains in the most-blocked table are blurred (REDACTIONS)."),
            Page(path=FEED_CAMERA_HOME, scroll=0,
                 note="What happened, searched for 'ipcam-vendor': every row is the camera's "
                      "address asking for its maker's .example domain, and being refused"),
            Slide(html_fn="homesick_camera"),
            Slide(html_fn="pc_nods_off"),
        ),
        ats=(
            0.0,
            t("Switch on Blocking", 0.190, offset=SETTLE),
            t("The camera phones home", 0.564, offset=SETTLE),
            t("like a homesick kid", 0.627, offset=-0.3),
            t("Two limits", 0.742, offset=-0.2),
        ),
    ),
    actions=[
        # beside the badge, not on it: the arrow on the badge read "Run?ing"
        Move(to=DNS_RUNNING_REST, at=t("Switch on Blocking", 0.200, offset=0.0), seconds=GLIDE),
        Highlight(sel=DNS_STATUS, at=t("Switch on Blocking", 0.213, offset=0.6), seconds=2.6),
        Move(to=DNS_HOURS, at=t("refuses ads", 0.357, offset=-1.0), seconds=GLIDE),
        Highlight(sel=DNS_HOURS, at=t("refuses ads", 0.378), seconds=2.6),
        Move(to=DNS_LOOKUPS, at=t("Thousands of lookups", 0.453, offset=-0.9), seconds=GLIDE),
        Highlight(sel=DNS_LOOKUPS, at=t("Thousands of lookups", 0.472), seconds=2.8),
        Move(to=DNS_DEVICES, at=t("The gadgets did", 0.524, offset=-0.8), seconds=0.8),
        Highlight(sel=DNS_DEVICES, at=t("The gadgets did", 0.542), seconds=0.9),
        Move(to=FEED_FIRST, at=t("The camera phones home", 0.574, offset=0.0), seconds=0.8),
        Highlight(sel=FEED_FIRST, at=t("phones home", 0.590, offset=0.3), seconds=1.0),
    ],
    caption="Friday: the phone book that says no",
)

# == 11 ======================================================================================
# What depends on what. The router is clicked for real; the panel then says "If Home router
# fails, 17 devices lose their internet connection. They stay on the local network and can
# still reach the others." The honesty is shown on the page's own words: the note at the top,
# the confidence legend, and the printer's Printing service with no lines drawn to it.
t = _Clock("11-saturday-what-depends")
_scene(
    id="11-saturday-what-depends",
    narration=(
        "Saturday. What if the internet goes down? [beat] Usually twenty minutes before "
        "something important. [beat 1.2] In What depends on what, click the router, the one road "
        "out. Seventeen devices lose the internet, but can still reach each other at home, while "
        "the Wi-Fi is up. [beat] So the laptops can still print. [beat] Whether the printer "
        "agrees is between you and the printer. [beat 1.2] It can't see what gadgets say to each "
        "other, only who relies on whom, and it says so. Every line shows how sure it is, and "
        "with nothing to go on, it draws nothing."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="twenty_minutes"),
            Page(path="/map", scroll=0,
                 note="the whole map, default 7-day window: internet, router, shared services, "
                      "devices, outside services"),
            Slide(html_fn="how_sure_key"),
        ),
        # The finish pass: the legend is four paragraphs of mDNS / subnet / default gateway, and
        # the scroll down to it tore (two screenshots stacked at the wrong offset, the side
        # panel printed twice) under the scene's honesty line. The key is drawn instead, in the
        # product's own line styles and words (Seen / Worked out / Assumed), and the map is not
        # scrolled at all.
        ats=(0.0, t("In What depends on what", 0.175, offset=SETTLE),
             t("Every line shows how sure", 0.839, offset=-0.3)),
    ),
    actions=[
        Move(to=MAP_ROUTER, at=t("In What depends on what", 0.188, offset=0.0), seconds=1.0),
        Click(at=t("click the router", 0.225, offset=0.15),
              then_shot=Page(path="/map", scroll=MAP_AFTER_CLICK,
                             note="blast-radius mode for Home router: the headline, 0 / 17 / 0, "
                                  "the rest of the map dimmed; scrolled 33 px so the map does "
                                  "not jump under the cursor"),
              note="a real click on the router node; the URL does not change"),
        Move(to=MAP_HEADLINE, at=t("Seventeen devices", 0.268, offset=-0.8), seconds=GLIDE),
        Highlight(sel=MAP_HEADLINE, at=t("Seventeen devices", 0.290), seconds=3.2),
        Highlight(sel=MAP_STATS, at=t("while the Wi-Fi is up", 0.430), seconds=1.8),
        Move(to=MAP_PRINTER, at=t("So the laptops can still print", 0.472, offset=-0.3),
             seconds=GLIDE),
        Highlight(sel=MAP_PRINTER, at=t("still print", 0.507), seconds=3.6),
        Move(to=MAP_NOTE, at=t("It can't see what gadgets say", 0.659, offset=-0.6), seconds=GLIDE),
        Highlight(sel=MAP_NOTE, at=t("It can't see what gadgets say", 0.676), seconds=3.4),
    ],
    caption="Saturday: if the internet goes down",
)

# == 12 ======================================================================================
# Lens. The scan is the rig of CONTRACT_V2 V3: the illustrated shelf with a real QR sticker,
# Lens in Chrome with a fake camera fed from it, and the decode done by the zxing-cpp sidecar
# because desktop Chrome has no BarcodeDetector. So the voice describes the product ("Point,
# and a card appears"), never "this phone". The certificate step is shown from the PC's side:
# the pairing page's Security fingerprint is "the one on your PC" the voice asks you to match.
t = _Clock("12-saturday-lens")
_scene(
    id="12-saturday-lens",
    narration=(
        "Saturday afternoon: find the camera, on a shelf of identical white boxes. [beat] Every "
        "gadget maker on earth agreed on one design: \"small white box\". [beat 1.2] Enter Lens: "
        "point a phone at a gadget, and it tells you which one it is. It needs Chrome on "
        "Android. iPhones get a pick-list instead, so the family uses the kitchen tablet. "
        "[beat] At first, the tablet won't trust Home SOC's certificate. [beat] Fair: they've "
        "never met. Check the long code matches the one on your PC, then trust it. [beat] "
        "Stickers carry a random code that tells a stranger nothing. [beat] Point, [beat] and a "
        "card appears: unnamed camera, six problems, one Fix now. A viewfinder with a card, "
        "not floating 3D labels. [beat] Dad unplugs it. [beat 1.2] Nobody complains. [beat 1.2] "
        "Back to the drawer it almost certainly came from."
    ),
    shot=PageSequence(
        shots=(
            Slide(html_fn="white_box_shelf"),
            PhonePair(scene_png="shelf", phone_state="scan", burst=26, burst_ms=66,
                      note="Lens pointed at the shelf: the live viewfinder, drifting"),
            Page(path="/lens/pair", scroll=0,
                 note="Pair a phone: 'HTTPS certificate · Self-signed' and, below, the Security "
                      "fingerprint - the long code the tablet's warning must match"),
            Page(path=STICKERS_ALL, scroll=0,
                 note="the sticker sheet for all devices: the camera's real QR sticker, and "
                      "'no code' boxes for devices nobody has asked a code for yet"),
            # No second idle viewfinder before the flash: capture.plan_states treats two "scan"
            # states less than MERGE_WINDOW apart as one (``hit`` is not part of its identity),
            # and the flash would silently vanish. The drifting viewfinder was on screen from
            # "Enter Lens"; "Point," is the flash itself.
            PhonePair(scene_png="shelf", phone_state="scan", hit=True,
                      note="the instant of recognition: reticle green, 'identifying...' "
                           "(the lookup's answer held back, CONTRACT_V2 V3.6)"),
            PhonePair(scene_png="shelf", phone_state="card", burst=26, burst_ms=66,
                      note="the card over the live image: Unnamed camera, 'Six problems, one of "
                           "them critical', '1 Critical · Fix now'"),
            Slide(html_fn="not_this"),
            Slide(html_fn="back_in_drawer"),
        ),
        ats=(
            0.0,
            t("Enter Lens", 0.206, offset=-0.3),
            t("At first, the tablet", 0.407, offset=SETTLE),
            t("Stickers carry", 0.605, offset=SETTLE),
            t("Point and a card", 0.680, offset=-0.3),
            t("and a card appears", 0.699, offset=-0.15),
            t("not floating 3D labels", 0.826, offset=-0.2),
            # I19's "This" holds through "Dad unplugs it. Nobody complains." and the drawer
            # arrives with its own words, not four seconds before them
            t("Back to the drawer", 0.940, offset=-0.2),
        ),
    ),
    actions=[
        Move(to=PAIR_CERT, at=t("won't trust", 0.428, offset=-0.8), seconds=GLIDE),
        Highlight(sel=PAIR_CERT, at=t("won't trust", 0.443), seconds=2.4),
        # beside the code grid, not on a group of it (the arrow hid "58:3?:64")
        Move(to=PAIR_FINGERPRINT_REST, at=t("Check the long code", 0.521, offset=-0.6),
             seconds=GLIDE),
        Highlight(sel=PAIR_FINGERPRINT, at=t("the long code", 0.535), seconds=3.6),
        Move(to=STICKERS_CAMERA, at=t("Stickers carry", 0.615, offset=0.1), seconds=0.8),
        Highlight(sel=STICKERS_CAMERA, at=t("a random code", 0.627), seconds=1.4),
        Move(to=STICKERS_EXPLAIN, at=t("tells a stranger nothing", 0.643, offset=-0.6),
             seconds=0.6),
        Highlight(sel=STICKERS_EXPLAIN, at=t("tells a stranger nothing", 0.654, offset=0.0),
                  seconds=0.9),
    ],
    caption="Saturday: point, and it tells you",
)

# == 13 ======================================================================================
t = _Clock("13-sunday-score")
_scene(
    id="13-sunday-score",
    narration=(
        "Sunday. So why was the score only ten? Any Fix-now problem holds the score down, "
        "however tidy the rest is. [beat] A spotless house with the front door wide open isn't a "
        "safe house. [beat] Fix these first lists both: the camera's Telnet, plus four. The "
        "router's flaw, plus four. Clear both, and the score doubles. [beat] Report is the page "
        "for the fridge door: found, fixed, and a line creeping up. What happened is the diary. "
        "[beat] And it doesn't nag. Something serious means one notification. Not fifty. [beat] "
        "A smoke alarm, not a car alarm."
    ),
    shot=PageSequence(
        shots=(
            Page(path="/", scroll=0,
                 note="Home: the gauge (10 · Needs work) and, below it, 'Fix these first' with "
                      "the two +4 rows on top"),
            Slide(html_fn="spotless_house"),
            Page(path="/", scroll=0, note="back for 'Fix these first'"),
            Slide(html_fn="score_doubles"),
            Slide(html_fn="on_the_fridge"),
            Page(path="/summary", scroll=0,
                 note="Your safety report: Found / Fixed and 'Is it getting better?' rising"),
            Page(path=FEED_DIARY, scroll=0,
                 note="What happened as a diary: 'Today', 'Yesterday', plain rows"),
            Slide(html_fn="smoke_not_car_alarm"),
        ),
        ats=(
            0.0,
            t("A spotless house", 0.208, offset=-0.3),
            t("Fix these first lists both", 0.331, offset=SETTLE),
            t("Clear both", 0.521, offset=-0.2),
            t("Report is the page", 0.587, offset=-0.3),
            t("found, fixed", 0.645, offset=-0.35),
            t("What happened is the diary", 0.731, offset=-0.4),
            t("Something serious", 0.822, offset=-0.3),
        ),
    ),
    actions=[
        Move(to=HOME_GAUGE_REST, at=0.012, seconds=1.0),
        Highlight(sel=HOME_GAUGE, at=t("only ten", 0.048), seconds=2.4),
        Move(to=HOME_FIX_1, at=t("Fix these first lists both", 0.343, offset=0.0), seconds=GLIDE),
        Highlight(sel=HOME_FIX_1, at=t("the camera's Telnet", 0.397), seconds=1.6),
        Move(to=HOME_FIX_1_GAIN, at=t("the camera's Telnet", 0.405, offset=0.3), seconds=0.5),
        Highlight(sel=HOME_FIX_1_GAIN, at=t("plus four", 0.432), seconds=1.0),
        Move(to=HOME_FIX_2, at=t("The router's flaw", 0.454, offset=-0.4), seconds=0.6),
        Highlight(sel=HOME_FIX_2, at=t("The router's flaw", 0.464), seconds=1.4),
        Move(to=HOME_FIX_2_GAIN, at=t("The router's flaw", 0.485, offset=0.8), seconds=0.4),
        Highlight(sel=HOME_FIX_2_GAIN, at=t("plus four", 0.496, occurrence=2), seconds=1.0),
        Move(to=REPORT_FOUND, at=t("found, fixed", 0.649, offset=-0.2), seconds=0.6),
        Highlight(sel=REPORT_FIGURES, at=t("found", 0.654), seconds=1.2),
        Move(to=REPORT_TREND, at=t("a line creeping up", 0.688, offset=-0.5), seconds=0.6),
        Highlight(sel=REPORT_TREND, at=t("a line creeping up", 0.701), seconds=1.1),
        Move(to=DIARY_TODAY, at=t("What happened is the diary", 0.741, offset=0.0), seconds=0.6),
        Highlight(sel=DIARY_TODAY, at=t("the diary", 0.765), seconds=1.2),
        Highlight(sel=DIARY_FIRST, at=t("the diary", 0.791, offset=1.0), seconds=1.2),
    ],
    caption="Sunday: the report",
)

# == 14 ======================================================================================
# The close. Home once more for "a short to-do list" (its "Fix these first" card is exactly
# that); then the three promises, the two front doors, the table in its closing state -
# seventeen, the camera gone, a drawer in the corner - and the end card, whose printer is
# still here for the last line. (SCRIPT.md's healthy-network example screen is a different
# seed that this pipeline does not serve; it is left out rather than faked.)
t = _Clock("14-close")
_scene(
    id="14-close",
    narration=(
        "So that's Home SOC. [beat] It won't make you hacker-proof. Nothing will. It turns a "
        "vague unease into a short to-do list. [beat] It's free and open source. No account, no "
        "cloud. What it learns about your house stays on your PC. It only goes online for things "
        "like public lists of known flaws, safety checks on new websites, and phone alerts if you "
        "set them up. [beat] Knocking "
        "on your own doors is housekeeping. [beat] Knocking on your neighbour's is a different "
        "conversation. So: only networks you own or run. [beat 1.2] Next family dinner, when "
        "someone asks how many things are on the Wi-Fi, [beat] you'll know. [beat] Seventeen. "
        "[beat] The camera's in the drawer. [beat 1.2] And the printer would like it noted "
        "[beat] that it is still here."
    ),
    shot=PageSequence(
        shots=(
            Page(path="/", scroll=0, note="Home, one last time"),
            Slide(html_fn="three_promises"),
            Slide(html_fn="two_front_doors"),
            Slide(html_fn="dinner_table_closing18"),
            Slide(html_fn="dinner_table_closing17"),
            Slide(html_fn="dinner_table_closing"),
            Slide(html_fn="dinner_table_closing_nudge"),
            Slide(html_fn="dinner_table_closing"),
            Slide(html_fn="end_card"),
        ),
        # The finish pass: the table opens as the cold open left it (18, the camera and its "?",
        # the drawer open) and pays the count off on the words, with the cold open's key-frame
        # cut - 17 on "Seventeen", the camera gone and the drawer shut on "drawer" - and the
        # printer's one bounce on "still here". The end card follows the last word and holds
        # (compose.END_HOLD) before the film fades.
        ats=(
            0.0,
            t("It's free and open source", 0.200, offset=-0.3),
            t("Knocking on your own doors", 0.502, offset=-0.3),
            t("Next family dinner", 0.726, offset=-0.4),
            t("Seventeen", 0.851, offset=-0.1),
            t("drawer", 0.894, offset=-0.1),
            t("still here", 0.979, offset=-0.05),
            t("here", 0.986, offset=0.0),
            t("still here", 0.997, edge="end", offset=0.3),
        ),
    ),
    actions=[
        Scroll(to_y=HOME_FIX_FIRST_SCROLL, at=t("It turns a vague unease", 0.105, offset=-0.6),
               seconds=1.2),
        Move(to=HOME_FIX_FIRST, at=t("It turns a vague unease", 0.126, offset=0.3), seconds=1.0),
        Highlight(sel=HOME_FIX_FIRST, at=t("a short to-do list", 0.166), seconds=1.4),
    ],
    caption="Seventeen, and counting",
)

del t


# --------------------------------------------------------------------------- film graphics


@dataclass(frozen=True)
class Overlay:
    """Film graphics compose.py draws over a scene, between two ``at`` fractions.

    ``tag``: a small ink tab on the window's top edge ("Monday's screen"). The week is a story
    and the dashboard is one capture: on Sunday and in the close, Home still shows Monday's 10
    and the camera's "Fix now", so those shots say whose screen it is.
    ``fingerprint_tablet``: scene 12's drawn tablet, beside the pairing page's real Security
    fingerprint, carrying the same groups (read from the captured page, never typed) - so
    "check the long code matches the one on your PC" has two codes to compare.
    """

    kind: str
    at: float
    until: float
    text: str = ""


_t13 = _Clock("13-sunday-score")
_t12 = _Clock("12-saturday-lens")
_t14 = _Clock("14-close")
OVERLAYS: dict[str, tuple[Overlay, ...]] = {
    "12-saturday-lens": (
        Overlay("fingerprint_tablet", _t12("Check the long code", 0.521, offset=-0.3),
                _t12("Stickers carry", 0.605, offset=-0.6)),
    ),
    "13-sunday-score": (
        Overlay("tag", 0.012, _t13("A spotless house", 0.208, offset=-0.4), "Monday’s screen"),
        Overlay("tag", _t13("Fix these first lists both", 0.331, offset=0.0),
                _t13("Clear both", 0.521, offset=-0.3), "Monday’s screen"),
    ),
    "14-close": (
        Overlay("tag", 0.012, _t14("It's free and open source", 0.200, offset=-0.4),
                "Monday’s screen"),
    ),
}
del _t12, _t13, _t14


# --------------------------------------------------------------------------- self-checks

#: capture.plan_states / compose merge two declarations of the same state closer than this.
MERGE_WINDOW = 0.10

_BEAT_RE = re.compile(r"\[\s*beat(?:\s+(\d+(?:\.\d+)?)\s*s?)?\s*\]", re.IGNORECASE)
_MARK_RE = re.compile(r"\[[^\]]*\]")


def _members(shot: Shot) -> list[Shot]:
    return list(shot.shots) if isinstance(shot, PageSequence) else [shot]


def _kind(shot: Shot) -> str:
    if isinstance(shot, Slide):
        return "slide"
    if isinstance(shot, (Phone, PhonePair)):
        return "phone"
    return "page"


def _key(shot: Shot) -> tuple:
    if isinstance(shot, Slide):
        return ("slide", shot.html_fn)
    if isinstance(shot, Page):
        return ("page", shot.path, shot.scroll)
    # as capture.Target sees them: `hit` and `burst` are not part of a phone state's identity
    if isinstance(shot, PhonePair):
        return ("pair", shot.phone_state, shot.scroll)
    if isinstance(shot, Phone):
        return ("phone", shot.state, shot.scroll)
    return ("?", repr(shot))


def timeline(scene: Scene) -> list[tuple[float, Shot, str]]:
    """The states a scene passes through, as capture plans them: ``[(at, shot, cause)]``."""
    members = _members(scene.shot)
    ats = list(scene.shot.ats) if isinstance(scene.shot, PageSequence) else []
    out: list[tuple[float, Shot, str]] = [(0.0, members[0], "shot")]
    declared: list[tuple[float, Any, str]] = []
    for i, m in enumerate(members[1:], start=1):
        declared.append((ats[i] if len(ats) == len(members) else i / len(members), m, "sequence"))
    for a in scene.actions:
        if isinstance(a, (Click, Tap)) and a.then_shot is not None:
            declared.append((a.at, a.then_shot, "click"))
        elif isinstance(a, (Scroll, PhoneScroll)):
            declared.append((a.at, a.to_y, "scroll"))
    declared.sort(key=lambda d: d[0])
    for at, payload, cause in declared:
        cur_at, cur, _ = out[-1]
        if cause == "scroll":
            if isinstance(cur, Page):
                payload = Page(path=cur.path, scroll=int(payload), note="(scroll)")
            else:
                continue
        if cause != "click" and _key(payload) == _key(cur) and at - cur_at <= MERGE_WINDOW:
            continue  # the same state declared twice (a member and its Scroll): captured once
        out.append((at, payload, cause))
    return out


def validate() -> list[str]:
    """Everything that can be checked without a browser. Returns a list of problems."""
    problems: list[str] = []
    seen: set[str] = set()
    used_slides: set[str] = set()
    for scene in SCENES:
        sid = scene.id
        if sid in seen:
            problems.append(f"{sid}: duplicate scene id")
        seen.add(sid)
        text = scene.narration
        for mark in _MARK_RE.findall(text):
            if not _BEAT_RE.fullmatch(mark):
                problems.append(f"{sid}: bracketed text {mark!r} is not a beat mark - it would be read aloud")
        if "{" in text or "}" in text:
            problems.append(f"{sid}: stray brace in narration")

        members = _members(scene.shot)
        if isinstance(scene.shot, PageSequence):
            ats = list(scene.shot.ats)
            if ats and len(ats) != len(members):
                problems.append(f"{sid}: {len(ats)} ats for {len(members)} shots")
            if ats != sorted(ats):
                problems.append(f"{sid}: ats out of order {ats}")
            for i in range(1, len(members)):
                if (len(ats) == len(members) and _key(members[i]) == _key(members[i - 1])
                        and ats[i] - ats[i - 1] <= MERGE_WINDOW):
                    problems.append(f"{sid}: shots {i - 1} and {i} ({_key(members[i])}) are "
                                    f"{ats[i] - ats[i - 1]:.3f} apart - capture merges them into one")
        for m in members + [a.then_shot for a in scene.actions
                            if isinstance(a, (Click, Tap)) and a.then_shot is not None]:
            if isinstance(m, PageSequence):
                problems.append(f"{sid}: nested PageSequence")
            if isinstance(m, Slide):
                used_slides.add(m.html_fn)
                if SLIDE_NAMES and m.html_fn not in SLIDE_NAMES:
                    problems.append(f"{sid}: slides_everyday has no slide {m.html_fn!r}")
            if isinstance(m, PhonePair) and m.scene_png not in SCENE_RENDERS:
                problems.append(f"{sid}: unknown scene render {m.scene_png!r}")
            if isinstance(m, (Phone, PhonePair)):
                state = m.state if isinstance(m, Phone) else m.phone_state
                if state not in PHONE_STATES:
                    problems.append(f"{sid}: unknown Lens state {state!r}")

        # Actions: in order, inside the scene, and on the right kind of screen.
        states = timeline(scene)
        last = -1.0
        last_move: float | None = None
        used_on: dict[str, tuple] = {}
        for a in scene.actions:
            if not 0.0 <= a.at <= 1.0:
                problems.append(f"{sid}: {type(a).__name__} at {a.at} outside 0..1")
            if a.at < last - 1e-9:
                problems.append(f"{sid}: {type(a).__name__} at {a.at:.3f} is before the previous "
                                f"action ({last:.3f})")
            last = a.at
            # the state on screen when the action fires: capture fires an action *before* a
            # state declared at the same instant, including the scene's first state at 0.0
            on = [s for s in states if s[0] < a.at]
            if not on:
                problems.append(f"{sid}: {type(a).__name__} at {a.at} fires before the scene's "
                                "first state is on screen (capture resolves it on the previous "
                                "scene's page) - start it a moment later")
            at_state, shot, _cause = on[-1] if on else states[0]
            # the pointer survives page changes, but not a slide or a phone in between
            cursor_on_page = last_move is not None and not any(
                _kind(s) != "page" and last_move < s0 <= a.at for s0, s, _c in states
            )
            kind = _kind(shot)
            name = type(a).__name__
            if isinstance(a, DESKTOP_ACTIONS) and kind != "page":
                problems.append(f"{sid}: {name} at {a.at:.3f} fires while a {kind} is on screen")
            if isinstance(a, PHONE_ACTIONS) and kind != "phone":
                problems.append(f"{sid}: {name} at {a.at:.3f} fires while a {kind} is on screen")
            target = getattr(a, "to", None) or getattr(a, "sel", None) or getattr(a, "xy", None)
            if target is not None and not (target.startswith("css=") or target.startswith("xy=")):
                problems.append(f"{sid}: target {target!r} is neither css= nor xy=")
            if isinstance(a, Move):
                last_move = a.at
            if isinstance(a, Click):
                if not cursor_on_page:
                    problems.append(f"{sid}: Click at {a.at:.3f} with no Move on this screen before it")
                if a.then_shot is not None and _key(a.then_shot) == _key(shot) \
                        and a.at - at_state <= MERGE_WINDOW:
                    problems.append(
                        f"{sid}: Click at {a.at:.3f} lands on the state that took over at "
                        f"{at_state:.3f} ({_key(shot)}); capture would merge them and show the "
                        f"result before the click. Give then_shot a different scroll, or move it."
                    )
            if target is not None and target.startswith("css="):
                where = _key(shot)
                seen_at = used_on.setdefault(target, where)
                if seen_at != where:
                    problems.append(
                        f"{sid}: {target} is used on {seen_at} and again on {where}; capture keeps "
                        "one rect per selector per scene, so spell the second use differently")
            if isinstance(a, Zoom):
                x, y, w, h = a.to_rect
                if w <= 0 or h <= 0 or x < 0 or y < 0 or x + w > 1600 or y + h > 900:
                    problems.append(f"{sid}: Zoom rect {a.to_rect} leaves the viewport")


    if SLIDE_NAMES:
        for name in SLIDE_NAMES:
            if name not in used_slides:
                problems.append(f"slide {name!r} is drawn but never shown")
    else:
        problems.append("slides_everyday.SLIDES could not be read")
    problems.extend(check_script_md())
    return problems


#: Narration that differs from SCRIPT.md on purpose (recorded in its "Production changes").
_APPROVED_CHANGES: dict[str, tuple[tuple[str, str], ...]] = {
    "03-monday-am-i-ok": (
        ("your network needs attention. Two things today, six more this week.",
         "your network needs attention. Eight things, two of them urgent."),
        # the finish pass: Things to fix shows "Critical Fix now" side by side, so the line no
        # longer claims the robot words are absent
        ("Home SOC just says: Fix now.", "Home SOC translates: Fix now."),
    ),
    # the finish pass: the camera's page says "Maker not known", and the rows are matched by
    # address - the voice no longer names a maker the product says it does not know
    "10-friday-blocking": (
        ("The camera phones home to its maker all day,", "The camera phones home all day,"),
    ),
    # the finish pass: the product (and every other shot) calls it "Unnamed camera"
    "12-saturday-lens": (
        ("a card appears: unbranded camera,", "a card appears: unnamed camera,"),
    ),
    # the finish pass: the demo's own Blocking page shows VirusTotal safety look-ups, which
    # send the domains devices looked up to an online service
    "14-close": (
        ("public lists of known flaws, and phone alerts",
         "public lists of known flaws, safety checks on new websites, and phone alerts"),
    ),
}


def _norm_quotes(text: str) -> str:
    return (text.replace("“", '"').replace("”", '"')
            .replace("‘", "'").replace("’", "'"))


def script_md_narration(path: Path = SCRIPT_MD) -> dict[str, str]:
    """``{scene_id: narration}`` as SCRIPT.md has it (the ``> `` block under **Narration.**)."""
    out: dict[str, str] = {}
    current: str | None = None
    grab = False
    for line in path.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^### (\d\d-[a-z0-9-]+)\s*$", line)
        if heading:
            current, grab = heading.group(1), False
            continue
        if current and line.strip() == "**Narration.**":
            grab = True
            continue
        if current and grab and line.startswith("> "):
            out[current] = line[2:].strip()
            grab = False
    return out


def check_script_md() -> list[str]:
    """Every narration string equals SCRIPT.md's, apart from the recorded changes."""
    if not SCRIPT_MD.is_file():
        return [f"{SCRIPT_MD} not found - cannot check the narration against it"]
    source = script_md_narration()
    problems: list[str] = []
    ids = [s.id for s in SCENES]
    if ids != list(source):
        problems.append(f"scene ids differ from SCRIPT.md: {ids} vs {list(source)}")
    for scene in SCENES:
        want = _norm_quotes(source.get(scene.id, ""))
        got = _norm_quotes(scene.narration)
        for was, now in _APPROVED_CHANGES.get(scene.id, ()):
            if was in want:
                want = want.replace(was, now)
        if got != want:
            i = next((k for k, (x, y) in enumerate(zip(got, want)) if x != y), min(len(got), len(want)))
            problems.append(f"{scene.id}: narration differs from SCRIPT.md at char {i}: "
                            f"{got[max(0, i - 30):i + 30]!r} vs {want[max(0, i - 30):i + 30]!r}")
    return problems


def timing_problems(min_hold: float = 1.0) -> list[str]:
    """Checks that need the narration's real length (``build/<film>/beats.json``).

    * every state stays on screen at least ``min_hold`` seconds (the recognition flash of a
      scan is exempt: in the product it lasts 600 ms);
    * no Highlight outlives the state it was drawn on (a glow left behind on a page that has
      scrolled or changed points at nothing).
    """
    try:
        from narrate import _beats_for  # type: ignore[attr-defined]
    except Exception:
        return ["narrate._beats_for unavailable - cannot check timing"]
    problems: list[str] = []
    for scene in SCENES:
        row = _beats_for(scene.id, None)
        if not row:
            problems.append(f"{scene.id}: not narrated yet (no beats.json row)")
            continue
        secs = float(row.get("seconds") or 0.0)
        states = timeline(scene)
        edges = [s[0] for s in states] + [1.0]
        for (a0, st, _c), a1 in zip(states, edges[1:]):
            hold = (a1 - a0) * secs
            flash = isinstance(st, (Phone, PhonePair)) and getattr(st, "hit", False)
            if hold < (0.45 if flash else min_hold):
                problems.append(f"{scene.id}: {_key(st)} is on screen for only {hold:.2f}s")
        last_move: Move | None = None
        for a in scene.actions:
            if isinstance(a, Move):
                last_move = a
            if isinstance(a, Click) and last_move is not None:
                lands = last_move.at + last_move.seconds / secs
                if lands > a.at + 1e-6:
                    problems.append(f"{scene.id}: Click at {a.at:.3f} fires {(lands - a.at) * secs:.2f}s "
                                    "before the pointer arrives")
            if isinstance(a, Highlight):
                end = a.at + a.seconds / secs
                cut = [s0 for s0, _s, _c in states if a.at < s0 < end - 0.05 / secs]
                if cut:
                    problems.append(f"{scene.id}: Highlight {a.sel} at {a.at:.3f} outlives its "
                                    f"state (next state at {cut[0]:.3f}, "
                                    f"{(end - cut[0]) * secs:.2f}s too long)")
    return problems


def _words(text: str) -> int:
    return len(_BEAT_RE.sub(" ", text).split())


if __name__ == "__main__":  # pragma: no cover - a developer convenience, not the pipeline
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    total = 0
    print(f"{'scene':<28} {'words':>5} {'beats':>5}  states")
    for s in SCENES:
        w = _words(s.narration)
        total += w
        n_beats = len(_BEAT_RE.findall(s.narration))
        chain = " > ".join(
            (st.html_fn if isinstance(st, Slide) else
             f"{st.path}@{st.scroll}" if isinstance(st, Page) else
             f"lens:{getattr(st, 'phone_state', getattr(st, 'state', '?'))}")
            + f"({at:.2f})"
            for at, st, _c in timeline(s)
        )
        print(f"{s.id:<28} {w:>5} {n_beats:>5}  {chain}")
    print(f"{'TOTAL':<28} {total:>5}")
    issues = validate()
    if "--timing" in sys.argv:
        issues += timing_problems()
    if issues:
        print("\nPROBLEMS:")
        for issue in issues:
            print("  -", issue)
        raise SystemExit(1)
    print("\nvalidate(): OK")
