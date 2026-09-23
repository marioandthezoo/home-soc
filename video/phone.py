"""The phone rig for the Home SOC walkthrough video (CONTRACT_V2 section V2).

Two jobs, and nothing else:

:func:`capture_phone`
    Drive ``/lens`` in a 390x844 @3x mobile Chrome context and save one PNG per screen
    state the script asks for — ``scan``, ``card``, ``picker``, ``unknown`` — at
    1170x2532. The Lens pairing token is written into ``localStorage`` under
    ``homesoc.lens.token`` *before the first render*, via ``add_init_script``, because
    ``lens.js`` reads it on boot and a token that arrives later means a screenful of
    "this phone is no longer paired".

:func:`phone_frame`
    Composite a captured screen into a **drawn** phone body — rounded corners, a dark
    bezel with a rim highlight, a speaker slot and a soft drop shadow — returned RGBA so
    the compositor can put it over an illustrated scene, a slide, or nothing at all.
    Everything is drawn with Pillow; this module ships no image assets.

Honesty (CONTRACT_V2 V3)
------------------------
This is Chrome on a PC in a phone-shaped viewport, not an Android phone. The module
never pretends otherwise, and it does not invent screen content: every pixel below the
bezel comes from the real Lens page talking to a real Home SOC over real HTTPS.

The one substitution is the decoder. Desktop Chrome on Windows has no ``BarcodeDetector``
(it is an Android/macOS/ChromeOS platform API), so when the caller supplies a ``decode``
callback this module installs a shim that grabs the frame the page was about to decode,
hands it to that callback — in the video pipeline, a zxing-cpp sidecar looking at the
real pixels of the fake camera feed — and returns the result in the shape the real API
returns. What is decoded is whatever is genuinely on screen. :data:`ShotResult.decodes`
records every value the shim returned so the caller can *prove* that, and
``capture.py`` refuses to ship scene 18 unless the value matches the sticker.

``decode`` is reached through a Playwright binding rather than ``fetch`` from the page:
Lens ships ``default-src 'self'``, so a cross-origin request to a loopback sidecar is
blocked by CSP and then again by CORS. The shim still falls back to ``fetch`` when the
binding is missing, so a page driven by hand in a browser can use the sidecar too.

Usage::

    from phone import capture_phone, phone_frame
    out = capture_phone("/lens", token=tok, shots=[...], out_dir=Path("build/shots"),
                        base_url="https://127.0.0.1:8899")
    frame = phone_frame(Image.open(out["screens"]["18-lens-scan_1"]["png"]), scale=0.27)
"""

from __future__ import annotations

import json
import logging
import re
import time
from contextlib import ExitStack, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Final, Iterable, Sequence

from PIL import Image, ImageChops, ImageDraw, ImageFilter

logger = logging.getLogger("homesoc.video.phone")

__all__ = [
    "PhoneError",
    "PHONE_W",
    "PHONE_H",
    "PHONE_SCALE",
    "SCREEN_W",
    "SCREEN_H",
    "TOKEN_KEY",
    "STATES",
    "ShotResult",
    "capture_phone",
    "phone_frame",
    "phone_frame_size",
    "mobile_context_options",
    "strip_csp",
]


# --------------------------------------------------------------------------- geometry

#: The CSS viewport Lens is designed for: a Pixel-class phone in portrait.
PHONE_W: Final[int] = 390
PHONE_H: Final[int] = 844
#: Captured at 3x and downscaled exactly once, by the compositor or by
#: :func:`phone_frame`'s ``scale`` — never both (CONTRACT_V2 V5).
PHONE_SCALE: Final[int] = 3
SCREEN_W: Final[int] = PHONE_W * PHONE_SCALE   # 1170
SCREEN_H: Final[int] = PHONE_H * PHONE_SCALE   # 2532

#: Where ``lens.js`` looks for the pairing token (``static/lens.js``, ``TOKEN_KEY``).
TOKEN_KEY: Final[str] = "homesoc.lens.token"
#: The other two keys Lens writes, cleared with it so a re-run starts from a virgin phone.
CARD_KEY: Final[str] = "homesoc.lens.card"
IGNORE_KEY: Final[str] = "homesoc.lens.ignored"

#: A real Chrome-on-Android UA string. Lens does not sniff it, but the page is being
#: photographed as a phone and `navigator.userAgent` is visible to anything that looks.
ANDROID_UA: Final[str] = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Mobile Safari/537.36"
)

#: The four screen states CONTRACT_V2 names.
STATES: Final[tuple[str, ...]] = ("scan", "card", "picker", "unknown")

NAV_TIMEOUT_MS: Final[int] = 30_000
STATE_TIMEOUT_MS: Final[int] = 20_000
CAMERA_TIMEOUT_MS: Final[int] = 15_000
SETTLE_MS: Final[int] = 420
#: ``lens.js`` REPEAT_MS: the same code is ignored again for 3.5 s. Waiting it out is
#: cheaper than reasoning about whether a reload cleared it.
REPEAT_GUARD_MS: Final[int] = 3_800

#: Chrome flags that make a headless PC behave like a phone that was handed a camera.
#: ``--use-file-for-fake-video-capture`` is added by the caller when a clip exists.
CAMERA_FLAGS: Final[tuple[str, ...]] = (
    "--use-fake-ui-for-media-stream",       # grant getUserMedia without a prompt
    "--use-fake-device-for-media-stream",   # a synthetic camera exists at all
    "--autoplay-policy=no-user-gesture-required",
    "--allow-insecure-localhost",
)


class PhoneError(RuntimeError):
    """Anything that stops a phone capture, always naming the shot at fault."""


# --------------------------------------------------------------------------- injected JS


#: Same intent as capture.FREEZE_CSS, tuned for the phone: Lens animates the card rising,
#: the reticle pulsing and the scrim fading, none of which may be caught mid-flight.
FREEZE_CSS: Final[str] = """
*, *::before, *::after {
  animation: none !important;
  transition: none !important;
  animation-duration: 0s !important;
  transition-duration: 0s !important;
  caret-color: transparent !important;
  scroll-behavior: auto !important;
}
html { scrollbar-width: none !important; }
::-webkit-scrollbar { width: 0 !important; height: 0 !important; }
*:focus, *:focus-visible { outline: none !important; }
"""

#: Written before any of the page's own script runs, so `lens.js` finds a paired phone on
#: its very first line instead of booting into the "not paired" notice and then being
#: fixed up afterwards (which would be visible in a screenshot taken too early).
_BOOTSTRAP_JS: Final[str] = """
(payload) => {
  try {
    localStorage.removeItem(payload.cardKey);
    localStorage.removeItem(payload.ignoreKey);
    if (payload.token) { localStorage.setItem(payload.tokenKey, payload.token); }
    else { localStorage.removeItem(payload.tokenKey); }
  } catch (e) { /* private mode: Lens still works, it just forgets */ }
}
"""

#: The BarcodeDetector substitution (CONTRACT_V2 V3.4). It is deliberately thin: it takes
#: the frame `lens.js` was going to decode, hands it out, and re-shapes the answer. It
#: invents nothing — with no decoder wired up it reports "no barcode in this frame", which
#: is what an empty viewfinder looks like.
_SHIM_JS: Final[str] = """
(config) => {
  const bus = {
    armed: config.armed !== false,
    calls: 0,
    decodes: [],
    errors: [],
    lastAt: 0
  };
  window.__homesocLens = bus;

  const FORMATS = config.formats;

  function shape(hit, width, height) {
    const box = hit.boundingBox || {};
    const x = Number(box.x || 0), y = Number(box.y || 0);
    const w = Number(box.width || 0), h = Number(box.height || 0);
    const corners = Array.isArray(hit.cornerPoints) && hit.cornerPoints.length === 4
      ? hit.cornerPoints.map(p => ({ x: Number(p.x || 0), y: Number(p.y || 0) }))
      : [{x: x, y: y}, {x: x + w, y: y}, {x: x + w, y: y + h}, {x: x, y: y + h}];
    return {
      boundingBox: DOMRectReadOnly.fromRect({ x: x, y: y, width: w, height: h }),
      cornerPoints: corners,
      format: String(hit.format || 'qr_code'),
      rawValue: String(hit.rawValue === undefined ? (hit.raw_value || hit.text || '') : hit.rawValue)
    };
  }

  function frameToDataUrl(source) {
    if (source && typeof source.toDataURL === 'function') { return source.toDataURL('image/png'); }
    const w = source.videoWidth || source.naturalWidth || source.width || 0;
    const h = source.videoHeight || source.naturalHeight || source.height || 0;
    if (!w || !h) { return ''; }
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    canvas.getContext('2d').drawImage(source, 0, 0, w, h);
    return canvas.toDataURL('image/png');
  }

  function ask(dataUrl) {
    if (typeof window.__homesocLensDecode === 'function') {
      return window.__homesocLensDecode(dataUrl);
    }
    if (!config.sidecar) { return Promise.resolve(null); }
    return fetch(config.sidecar, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image: dataUrl, data_url: dataUrl, png: dataUrl })
    }).then(r => r.json());
  }

  class ShimBarcodeDetector {
    constructor(options) {
      const wanted = (options && options.formats) || FORMATS;
      this.formats = FORMATS.filter(f => wanted.indexOf(f) >= 0);
    }
    static getSupportedFormats() { return Promise.resolve(FORMATS.slice()); }
    detect(source) {
      bus.calls += 1;
      if (!bus.armed) { return Promise.resolve([]); }
      let dataUrl = '';
      try { dataUrl = frameToDataUrl(source); } catch (e) { bus.errors.push(String(e)); return Promise.resolve([]); }
      if (!dataUrl) { return Promise.resolve([]); }
      return Promise.resolve(ask(dataUrl)).then(answer => {
        const parsed = typeof answer === 'string' ? JSON.parse(answer) : answer;
        const hits = (parsed && (parsed.results || parsed.barcodes || parsed.codes || parsed.decodes)) || [];
        const width = source.width || source.videoWidth || 0;
        const height = source.height || source.videoHeight || 0;
        const out = hits.map(h => shape(h, width, height)).filter(h => h.rawValue);
        if (out.length) {
          bus.decodes.push({ value: out[0].rawValue, format: out[0].format, at: Date.now() });
          bus.lastAt = Date.now();
        }
        return out;
      }).catch(err => { bus.errors.push(String(err && err.message || err)); return []; });
    }
  }

  Object.defineProperty(window, 'BarcodeDetector', {
    configurable: true, writable: true, value: ShimBarcodeDetector
  });
}
"""

#: A latency knob on ``/api/lens/identify``, and nothing else.
#:
#: Lens shows a real intermediate state between decoding a code and opening the card: the
#: reticle's four corners turn green and the chip reads "identifying…" while the lookup is
#: in flight. On loopback that lookup answers in a few milliseconds, so the state exists for
#: about two frames and cannot be photographed — which is why the v2 cut had no reticle
#: flash anywhere in scene 18, over narration that names one.
#:
#: This delays the *response* to that one endpoint, so the page sits in its own genuine
#: in-flight state long enough to screenshot. It fabricates nothing: the code came off the
#: same real pixels, the request is the page's own, and the answer is the server's. It is a
#: recording aid of the same kind as the BarcodeDetector substitution, and like that one it
#: is disclosed in CONTRACT_V2 / video/README.md. It is off (0 ms) unless a shot asks.
_LATENCY_JS: Final[str] = """
() => {
  const real = window.fetch.bind(window);
  window.__homesocLensLatency = 0;
  window.fetch = function (input, init) {
    const url = String((input && input.url) || input || '');
    const wait = Number(window.__homesocLensLatency || 0);
    if (!wait || url.indexOf('/api/lens/identify') < 0) { return real(input, init); }
    return real(input, init).then(function (r) {
      return new Promise(function (resolve) { setTimeout(function () { resolve(r); }, wait); });
    });
  };
}
"""

#: Formats the shim advertises. `lens.js` intersects its wanted list with this one, so it
#: must be a superset of what the sidecar can actually read.
SHIM_FORMATS: Final[tuple[str, ...]] = (
    "qr_code", "code_128", "code_39", "code_93", "codabar", "data_matrix",
    "ean_13", "ean_8", "itf", "pdf417", "upc_a", "upc_e", "aztec",
)


# --------------------------------------------------------------------------- results


@dataclass
class ShotResult:
    """One captured phone screen."""

    id: str
    state: str
    png: Path
    scroll: int = 0
    decoded: str | None = None
    decode_calls: int = 0
    held: bool = False
    note: str = ""
    geometry: dict[str, list[float]] = field(default_factory=dict)
    #: Viewport rect of the element a ``PhoneScroll`` actually moves, in the 390x844 CSS
    #: space. compose.py needs it: the viewfinder above the Lens card is a *live* camera
    #: feed, so two scroll states of the same card are never pixel-identical up there, and
    #: a compositor that infers "what does not move" by differencing the two screenshots
    #: concluded that nothing was fixed and dragged the viewfinder and the card header
    #: through the frame with the content. Measured, not guessed.
    scroller: list[float] | None = None
    #: Extra frames of the same state, in order, for a shot captured as a burst. Frame 0 is
    #: :attr:`png`; these are the ones after it.
    frames: list[Path] = field(default_factory=list)
    #: Seconds between burst frames as captured, so compose.py can play them back at the
    #: rate they were taken rather than at an invented one.
    frame_interval: float = 0.0

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "png": self.png.as_posix(),
            "scroll": self.scroll,
            "size": [SCREEN_W, SCREEN_H],
            "viewport": [PHONE_W, PHONE_H],
            "decoded": self.decoded,
            "decode_calls": self.decode_calls,
            "decode_held": self.held,
            "note": self.note,
            "scroller": self.scroller,
            "frames": [p.as_posix() for p in self.frames],
            "frame_interval": round(float(self.frame_interval), 4),
        }


# --------------------------------------------------------------------------- context


def mobile_context_options(*, base_url: str | None = None) -> dict[str, Any]:
    """Exactly the context CONTRACT_V2 V2 specifies, in one place so it cannot drift."""
    options: dict[str, Any] = {
        "viewport": {"width": PHONE_W, "height": PHONE_H},
        "screen": {"width": PHONE_W, "height": PHONE_H},
        "device_scale_factor": PHONE_SCALE,
        "is_mobile": True,
        "has_touch": True,
        "color_scheme": "dark",
        "reduced_motion": "reduce",
        "permissions": ["camera"],
        "ignore_https_errors": True,   # the demo certificate is self-signed by design
        "user_agent": ANDROID_UA,
        "locale": "en-GB",
    }
    if base_url:
        options["base_url"] = base_url
    return options


def strip_csp(context: Any) -> None:
    """Drop ``Content-Security-Policy`` for this throwaway context only.

    Lens ships ``default-src 'self'``, which is right for the product and fatal for a
    capture rig: it blocks the injected freeze stylesheet. The product's headers are not
    touched — this rewrites responses on their way into one automated browser.
    """

    def handler(route: Any) -> None:
        try:
            response = route.fetch()
            headers = {
                k: v for k, v in response.headers.items()
                if k.lower() not in ("content-security-policy", "content-security-policy-report-only")
            }
            route.fulfill(response=response, headers=headers)
        except Exception:  # noqa: BLE001 - a routing hiccup must never kill a capture
            with suppress(Exception):
                route.continue_()

    context.route("**/*", handler)


def _install(context: Any, *, token: str, decode: Callable[[str], Any] | None,
             sidecar_url: str | None, armed: bool) -> None:
    """Everything that has to exist before the page's own first line runs."""
    context.add_init_script(
        f"({_BOOTSTRAP_JS})({json.dumps({'tokenKey': TOKEN_KEY, 'cardKey': CARD_KEY, 'ignoreKey': IGNORE_KEY, 'token': token})})"
    )
    context.add_init_script(f"({_LATENCY_JS})()")
    if decode is not None or sidecar_url:
        config = {"formats": list(SHIM_FORMATS), "sidecar": sidecar_url or "", "armed": bool(armed)}
        context.add_init_script(f"({_SHIM_JS})({json.dumps(config)})")
    if decode is not None:
        def _bridge(_source: Any, data_url: str) -> Any:
            try:
                return decode(data_url)
            except Exception as exc:  # noqa: BLE001 - surfaced through bus.errors, never silent
                logger.warning("decode sidecar raised %s: %s", type(exc).__name__, exc)
                return {"results": [], "error": f"{type(exc).__name__}: {exc}"}

        with suppress(Exception):  # a re-used context may already carry the binding
            context.expose_binding("__homesocLensDecode", _bridge)


# --------------------------------------------------------------------------- driving


_SEL_RE = re.compile(r"^(css|xy)\s*=\s*(.*)$", re.I | re.S)


def _selector_of(target: str) -> str:
    """``"css=#btn-pick"`` -> ``"#btn-pick"``; anything else is returned unchanged."""
    match = _SEL_RE.match(str(target).strip())
    if match and match.group(1).lower() == "css":
        return match.group(2).strip()
    return str(target).strip()


def _point(target: Any) -> tuple[float, float] | None:
    """``(x, y)`` for a literal target in the 390x844 space, else None."""
    if isinstance(target, (tuple, list)) and len(target) == 2:
        return float(target[0]), float(target[1])
    match = _SEL_RE.match(str(target).strip())
    if not match or match.group(1).lower() != "xy":
        return None
    numbers = re.findall(r"-?\d+(?:\.\d+)?", match.group(2))
    if len(numbers) != 2:
        return None
    return float(numbers[0]), float(numbers[1])


def _is_xy(target: Any) -> bool:
    """True for a literal point — ``(x, y)`` or ``"xy=(x, y)"`` — which needs no element."""
    if isinstance(target, (tuple, list)):
        return len(target) == 2
    match = _SEL_RE.match(str(target).strip())
    return bool(match and match.group(1).lower() == "xy")


class _Phone:
    """One mobile page, driven through Lens's real controls."""

    def __init__(self, page: Any, *, page_path: str) -> None:
        self.page = page
        self.page_path = page_path
        self.last_decode_ms = 0.0
        #: The screen currently up, so a run of card shots can scroll instead of starting
        #: over — which matters because a Tap that opened a <details> must stay open.
        self.state_now = ""
        self.camera_ok = False
        self.loaded = False

    # -- plumbing ------------------------------------------------------

    def reload(self) -> None:
        """A virgin boot. Cheaper than reasoning about `lens.js`'s in-memory guards.

        ``closeUnknown`` snoozes a code for sixty seconds and ``onCode`` ignores a repeat
        for 3.5 s; both live in closure variables that only a fresh document clears.
        """
        self.page.goto(self.page_path, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        with suppress(Exception):
            self.page.wait_for_load_state("networkidle", timeout=10_000)
        with suppress(Exception):
            self.page.add_style_tag(content=FREEZE_CSS)
        with suppress(Exception):
            self.page.evaluate("() => document.fonts && document.fonts.ready")
        self.state_now = ""
        self.loaded = True

    def wait_camera(self, *, required: bool) -> bool:
        """True once the viewfinder is showing frames; False when Lens fell back."""
        try:
            self.page.wait_for_function(
                "() => { const v = document.getElementById('cam');"
                " return !!v && v.videoWidth > 0 && v.readyState >= 2; }",
                timeout=CAMERA_TIMEOUT_MS,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            if required:
                raise PhoneError(
                    "the phone's camera never produced a frame. Chrome needs "
                    "--use-fake-ui-for-media-stream (and a --use-file-for-fake-video-capture "
                    f"clip for a real scene) — {type(exc).__name__}: {exc}"
                ) from exc
            logger.warning("no camera frames; Lens will show its documented fallback")
            return False

    def arm(self, on: bool) -> None:
        self.page.evaluate(
            "(on) => { if (window.__homesocLens) { window.__homesocLens.armed = !!on; } }", bool(on)
        )

    def bus(self) -> dict[str, Any]:
        value = self.page.evaluate(
            "() => window.__homesocLens ? {"
            " calls: window.__homesocLens.calls,"
            " decodes: window.__homesocLens.decodes,"
            " errors: window.__homesocLens.errors } : null"
        )
        return dict(value or {"calls": 0, "decodes": [], "errors": []})

    def visible(self, selector: str) -> bool:
        return bool(self.page.evaluate(
            "(sel) => { const el = document.querySelector(sel); return !!el && !el.hidden; }", selector
        ))

    def tap(self, selector: str, *, shot_id: str) -> None:
        locator = self.page.locator(selector)
        if locator.count() == 0:
            raise PhoneError(f"{shot_id}: nothing matches {selector!r} on {self.page_path}")
        locator.first.click(timeout=STATE_TIMEOUT_MS)
        self.page.wait_for_timeout(120)

    def wait_for(self, expression: str, *, shot_id: str, what: str,
                 timeout: int = STATE_TIMEOUT_MS) -> None:
        try:
            self.page.wait_for_function(expression, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - the shot id is the whole point of the message
            raise PhoneError(
                f"{shot_id}: {what} never happened ({type(exc).__name__}). "
                f"Lens says: {self.status()!r}"
            ) from exc

    def status(self) -> str:
        with suppress(Exception):
            return str(self.page.evaluate(
                "() => (document.getElementById('scan-state') || {}).textContent || ''"
            )).strip()
        return ""

    def rect(self, target: str, *, shot_id: str) -> list[float] | None:
        """Viewport rect in the 390x844 CSS space, or None for an ``xy=`` literal."""
        if _is_xy(target):
            return None
        selector = _selector_of(target)
        locator = self.page.locator(selector)
        try:
            count = locator.count()
        except Exception as exc:  # noqa: BLE001
            raise PhoneError(f"{shot_id}: {target!r} is not a valid selector ({exc})") from exc
        if count == 0:
            raise PhoneError(
                f"{shot_id}: selector {target!r} matched nothing on the phone. "
                "phone.py never guesses tap coordinates."
            )
        if count > 1:
            logger.warning("%s: %r matched %d elements; using the first", shot_id, target, count)
        box = locator.first.bounding_box()
        if not box:
            raise PhoneError(
                f"{shot_id}: selector {target!r} matched an element with no box "
                "(hidden, or zero-sized) — measure it on the state that is actually up."
            )
        return [round(float(box["x"]), 2), round(float(box["y"]), 2),
                round(float(box["width"]), 2), round(float(box["height"]), 2)]

    # -- states --------------------------------------------------------

    def scroll_to(self, to_y: int, *, state: str) -> int:
        """Scroll the thing that actually scrolls, and report where it stopped.

        On a ``card`` shot that is ``#card-body`` — the card is a fixed panel and the
        document behind it does not move. Everywhere else it is the window. A request
        past the end is clamped by the browser, and the clamped value is what goes into
        the manifest, so the compositor animates to a position that exists.
        """
        actual = int(self.page.evaluate(
            "([y, card]) => {"
            " const b = card ? document.getElementById('card-body') : null;"
            " if (b) { b.scrollTop = y; return Math.round(b.scrollTop); }"
            " window.scrollTo(0, y); return Math.round(window.scrollY); }",
            [int(to_y), state == "card"],
        ))
        if abs(actual - int(to_y)) > 4:
            logger.warning(
                "requested scroll %s on the %s screen but it stopped at %s (the content is "
                "shorter than the script thinks)", to_y, state, actual,
            )
        self.page.wait_for_timeout(120)
        return actual

    def scroller_rect(self, state: str) -> list[float] | None:
        """Viewport rect of whatever :meth:`scroll_to` moves, in 390x844 CSS pixels.

        ``None`` when the window is the scroller — then everything moves, and the
        compositor needs no band.
        """
        if state != "card":
            return None
        box = self.page.evaluate(
            "() => { const b = document.getElementById('card-body');"
            " if (!b) { return null; }"
            " const r = b.getBoundingClientRect();"
            " return [r.x, r.y, r.width, r.height]; }"
        )
        if not box:
            return None
        return [round(float(v), 2) for v in box]

    def press(self, target: str, *, shot_id: str) -> None:
        """A real press on the phone, by selector or by point in the 390x844 space."""
        point = _point(target)
        if point is not None:
            self.page.mouse.click(point[0], point[1])
        else:
            self.tap(_selector_of(target), shot_id=shot_id)
        self.page.wait_for_timeout(220)

    def dismiss_all(self, *, shot_id: str) -> None:
        """Back to the viewfinder through the app's own controls, not by reaching in."""
        if self.visible("#unknown"):
            self.tap("#unknown-close", shot_id=shot_id)
        if self.visible("#picker"):
            self.tap("#picker-close", shot_id=shot_id)
        if self.visible("#card"):
            self.tap("#card-handle", shot_id=shot_id)

    def go_scan(self, *, shot_id: str, hold: bool) -> None:
        self.dismiss_all(shot_id=shot_id)
        self.arm(not hold)
        self.wait_for(
            "() => document.getElementById('card').hidden"
            " && document.getElementById('picker').hidden"
            " && document.getElementById('unknown').hidden",
            shot_id=shot_id, what="the viewfinder coming back",
        )

    def go_picker(self, *, shot_id: str, mode: str) -> None:
        self.dismiss_all(shot_id=shot_id)
        self.arm(False)
        self.tap("#tab-devices" if mode == "browse" else "#btn-pick", shot_id=shot_id)
        self.wait_for(
            "() => { const p = document.getElementById('picker');"
            " return p && !p.hidden && document.querySelectorAll('#picker-list li').length > 0; }",
            shot_id=shot_id, what="the device picker filling in",
        )

    def go_card_by_pick(self, *, shot_id: str, needle: str) -> None:
        """The manual path, which is a real part of the product (SPEC B2)."""
        self.go_picker(shot_id=shot_id, mode="pick")
        if needle:
            self.page.fill("#picker-search", needle)
            self.page.wait_for_timeout(150)
            self.wait_for(
                "(n) => document.querySelectorAll('#picker-list li').length > 0",
                shot_id=shot_id, what=f"a device matching {needle!r}",
            )
        rows = self.page.locator("#picker-list li")
        if rows.count() == 0:
            raise PhoneError(f"{shot_id}: no device in the picker matches {needle!r}")
        target = rows.first.locator("button")
        (target.first if target.count() else rows.first).click(timeout=STATE_TIMEOUT_MS)
        self.wait_card(shot_id=shot_id)

    def go_hit(self, *, shot_id: str, expect: str | None, hold_ms: int = 2600) -> str:
        """Stop on the instant of recognition — green reticle, chip reading "identifying…".

        A real state of the real page, reached the real way: the shim decodes the sticker
        off the camera frame, ``lens.js`` marks the reticle and fires its own lookup. The
        only intervention is :data:`_LATENCY_JS` holding the *answer* back for ``hold_ms``
        so the state lasts longer than two frames. ``lens.js`` strips ``is-hit`` after
        600 ms of its own accord, so anything photographed here must be photographed
        quickly — keep the burst inside that window.
        """
        self.dismiss_all(shot_id=shot_id)
        self._respect_repeat_guard()
        self.page.evaluate("(ms) => { window.__homesocLensLatency = ms; }", int(hold_ms))
        self.arm(True)
        try:
            self.wait_for(
                "() => { const r = document.getElementById('reticle');"
                " return !!r && r.classList.contains('is-hit'); }",
                shot_id=shot_id, what="the reticle flashing on a decode", timeout=STATE_TIMEOUT_MS,
            )
        except PhoneError:
            self.page.evaluate("() => { window.__homesocLensLatency = 0; }")
            raise
        decoded = self._last_decode() or ""
        if expect and decoded and decoded != expect:
            self.page.evaluate("() => { window.__homesocLensLatency = 0; }")
            raise PhoneError(
                f"{shot_id}: the shim decoded {decoded!r} but the script expects {expect!r}"
            )
        return decoded

    def clear_latency(self) -> None:
        with suppress(Exception):
            self.page.evaluate("() => { window.__homesocLensLatency = 0; }")

    def go_card_by_scan(self, *, shot_id: str, expect: str | None) -> str:
        """The scan path: arm the decoder and let the page find the code for itself."""
        self.dismiss_all(shot_id=shot_id)
        self._respect_repeat_guard()
        self.arm(True)
        try:
            self.wait_card(shot_id=shot_id, what="the card rising after a decode")
        except PhoneError as exc:
            bus = self.bus()
            raise PhoneError(
                f"{shot_id}: nothing was scanned. The decoder was asked "
                f"{bus.get('calls', 0)} times and returned "
                f"{[d.get('value') for d in bus.get('decodes') or []]!r}; this shot expects "
                f"{expect!r}. Check that the scene clip really contains that code and that "
                "the sidecar can read it. capture.py will not fall back to the manual picker "
                "and let the narration call it a scan."
                + (f" Decoder errors: {bus['errors'][-2:]}" if bus.get("errors") else "")
            ) from exc
        decoded = self._last_decode()
        if expect and decoded != expect:
            raise PhoneError(
                f"{shot_id}: the scan produced {decoded!r}, not the expected {expect!r}. "
                "The narration calls this a scan, so it has to be one — fix the scene clip "
                "or the sticker token rather than falling back to the picker."
            )
        return decoded or ""

    def go_unknown(self, *, shot_id: str, expect: str | None) -> str:
        self.dismiss_all(shot_id=shot_id)
        self._respect_repeat_guard()
        self.arm(True)
        self.wait_for(
            "() => { const u = document.getElementById('unknown');"
            " return u && !u.hidden && document.querySelectorAll('#unknown-list li').length > 0; }",
            shot_id=shot_id, what="the unrecognised-code sheet opening",
        )
        decoded = self._last_decode()
        if expect and decoded != expect:
            raise PhoneError(f"{shot_id}: decoded {decoded!r}, expected {expect!r}")
        return decoded or ""

    def wait_card(self, *, shot_id: str, what: str = "the device card opening") -> None:
        self.wait_for(
            "() => { const c = document.getElementById('card');"
            " const b = document.getElementById('card-body');"
            " return c && !c.hidden && b && b.children.length > 0; }",
            shot_id=shot_id, what=what,
        )

    def _respect_repeat_guard(self) -> None:
        if self.last_decode_ms:
            self.page.wait_for_timeout(REPEAT_GUARD_MS)
            self.last_decode_ms = 0.0

    def _last_decode(self) -> str | None:
        decodes = list(self.bus().get("decodes") or [])
        if not decodes:
            return None
        self.last_decode_ms = float(decodes[-1].get("at") or 0)
        return str(decodes[-1].get("value") or "")


# --------------------------------------------------------------------------- capture


def _shot_field(shot: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in shot and shot[name] is not None:
            return shot[name]
    return default


def capture_phone(
    page_path: str,
    *,
    token: str,
    shots: Sequence[dict[str, Any]],
    out_dir: Path,
    base_url: str | None = None,
    browser: Any = None,
    playwright: Any = None,
    launch_args: Iterable[str] = (),
    headless: bool = True,
    decode: Callable[[str], Any] | None = None,
    sidecar_url: str | None = None,
    clock: Any = None,
) -> dict[str, Any]:
    """Drive ``/lens`` in a phone-shaped context and save the screens ``shots`` asks for.

    Each entry of ``shots`` is a dict:

    ``id``         file stem (``"18-lens-scan_1"``) — the PNG is ``out_dir/<id>.png``
    ``state``      one of :data:`STATES`
    ``scroll``     how far to scroll the card's own body, in CSS px (``card`` only)
    ``via``        ``"scan"`` to make the page decode it for real, ``"pick"`` to tap it
                   out of the picker. Defaults to ``"scan"`` when ``code`` is set and a
                   decoder is wired up, else ``"pick"``.
    ``code``       the value the scan is expected to produce; a mismatch raises
    ``device``     picker search text for ``via="pick"`` (``"192.168.1.142"``)
    ``mode``       ``"pick"`` or ``"browse"`` for the picker's two titles
    ``hold``       ``scan`` only: leave the decoder disarmed so the viewfinder can be
                   photographed still looking, rather than a tenth of a second after the
                   card has already covered it. Defaults to True.
    ``taps``       targets to press for real *before* this screenshot — a ``Tap`` with a
                   ``then_shot``, which is how scene 19 opens the card's Vulnerabilities
                   section. The press happens at the declared scroll offset, and the
                   offset is re-asserted afterwards.
    ``selectors``  targets to measure into geometry, as written in the script
                   (``"css=#btn-pick"``). Measured after ``taps``, so a selector that
                   only exists once something is open resolves.
    ``before`` / ``after``   callables run either side of the shot, so the caller can
                   arrange server-side state (forgetting a tag to make a code unknown)

    Consecutive shots share one document wherever they can — a run of ``card`` shots is
    scrolled, not re-opened — so a press in one shot is still in effect in the next. Only
    a shot that has to be decoded reloads, because ``lens.js``'s repeat guard and snooze
    list live in closure variables that nothing else clears.

    Returns ``{"screens": {...}, "geometry": {...}, "shots": [...], "decodes": [...]}``.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = page_path if str(page_path).startswith("/") else "/" + str(page_path)
    url = (base_url.rstrip("/") + path) if base_url else path

    results: list[ShotResult] = []
    with ExitStack() as stack:
        if browser is None:
            # The fake camera is a launch flag, so the phone always needs its own browser —
            # but never its own Playwright: the sync API cannot be nested, and capture.py
            # is already inside one. It hands its driver down as `playwright`.
            if playwright is None:
                from playwright.sync_api import sync_playwright

                playwright = stack.enter_context(sync_playwright())
            args = list(CAMERA_FLAGS) + [a for a in launch_args if a not in CAMERA_FLAGS]
            browser = playwright.chromium.launch(channel="chrome", headless=headless, args=args)
            owned = browser
            stack.callback(lambda: _quietly(owned.close))

        context = browser.new_context(**mobile_context_options(base_url=base_url))
        stack.callback(lambda: _quietly(context.close))
        context.set_default_timeout(STATE_TIMEOUT_MS)
        if clock is not None:
            with suppress(Exception):
                context.clock.set_fixed_time(clock)
        strip_csp(context)
        _install(context, token=token, decode=decode, sidecar_url=sidecar_url, armed=False)

        page = context.new_page()
        phone = _Phone(page, page_path=url)

        for raw in shots:
            results.append(_one_shot(phone, dict(raw), out_dir=out_dir, decoding=decode is not None))

    screens = {r.id: r.as_json() for r in results}
    geometry = {r.id: r.geometry for r in results if r.geometry}
    return {
        "screens": screens,
        "geometry": geometry,
        "shots": [r.as_json() for r in results],
        "decodes": [r.decoded for r in results if r.decoded],
    }


#: How many fresh decodes a recognition-flash shot may take to photograph its 600 ms window.
HIT_ATTEMPTS = 4


def _quietly(fn: Callable[[], Any]) -> None:
    with suppress(Exception):
        fn()


def _one_shot(phone: _Phone, shot: dict[str, Any], *, out_dir: Path, decoding: bool) -> ShotResult:
    shot_id = str(_shot_field(shot, "id", "name", default="")).strip()
    if not shot_id:
        raise PhoneError(f"a phone shot has no id ({shot!r})")
    state = str(_shot_field(shot, "state", default="scan")).strip().lower()
    if state not in STATES:
        raise PhoneError(f"{shot_id}: unknown phone state {state!r} (expected one of {', '.join(STATES)})")

    before = _shot_field(shot, "before")
    after = _shot_field(shot, "after")
    if callable(before):
        before()

    code = _shot_field(shot, "code")
    via = str(_shot_field(shot, "via", default="scan" if (code and decoding) else "pick")).lower()
    scroll = int(_shot_field(shot, "scroll", default=0) or 0)
    hold = bool(_shot_field(shot, "hold", default=True))
    taps = [str(t) for t in (_shot_field(shot, "taps", default=()) or ())]

    # A decode needs a virgin document: `lens.js` keeps its repeat guard, its snooze list
    # and the code it last saw in closure variables that only a reload clears. Everything
    # else continues on the page already up — which is what keeps a <details> a Tap opened
    # open across the scroll states that follow it.
    hit = bool(_shot_field(shot, "hit", default=False))
    needs_decode = state == "unknown" or (state == "card" and via == "scan") or hit
    reuse = (
        phone.loaded and not needs_decode and phone.state_now == state
        and state in ("card", "picker", "scan")
    )

    decoded: str | None = None
    if not reuse:
        phone.reload()
        phone.camera_ok = phone.wait_camera(required=bool(decoding and needs_decode))
        if state == "scan" and hit:
            if not decoding:
                raise PhoneError(
                    f"{shot_id}: this shot asks for the moment of recognition, which only "
                    "exists after a real decode. Wire up the scan rig."
                )
            decoded = phone.go_hit(
                shot_id=shot_id, expect=str(code) if code else None,
                hold_ms=int(_shot_field(shot, "hit_ms", default=2600) or 2600),
            )
        elif state == "scan":
            phone.go_scan(shot_id=shot_id, hold=hold)
        elif state == "picker":
            phone.go_picker(
                shot_id=shot_id, mode=str(_shot_field(shot, "mode", default="pick")).lower()
            )
        elif state == "card":
            if via == "scan":
                if not decoding:
                    raise PhoneError(
                        f"{shot_id}: this card is declared as reached by scanning, but no "
                        "decoder is wired up. Start the sidecar and the scene clip, or "
                        "declare via='pick'."
                    )
                decoded = phone.go_card_by_scan(shot_id=shot_id, expect=str(code) if code else None)
            else:
                phone.go_card_by_pick(
                    shot_id=shot_id, needle=str(_shot_field(shot, "device", default=""))
                )
        elif state == "unknown":
            if not decoding:
                raise PhoneError(
                    f"{shot_id}: the unrecognised-code sheet only exists after a decode. "
                    "Wire up the decoder (the scan rig) for this scene."
                )
            decoded = phone.go_unknown(shot_id=shot_id, expect=str(code) if code else None)
        phone.state_now = state

    # Scroll, then press, then scroll again: a press auto-scrolls its target into view, and
    # the offset the script declared is the one that has to be on screen.
    #
    # A `hit` shot skips all of it. `lens.js` strips the green reticle 600 ms after it sets
    # it, and a scroll (120 ms) plus the usual 420 ms settle would spend the whole window
    # before the shutter. There is nothing to scroll on the viewfinder anyway.
    if hit:
        # The shutter goes first and the geometry after it (the reticle does not move), and a
        # missed window is retried with a fresh page and a fresh real decode rather than
        # accepted: on a busy machine one 3x screenshot can outlast lens.js's 600 ms.
        hit_settle = int(_shot_field(shot, "settle_ms", default=40) or 40)
        png = out_dir / f"{shot_id}.png"
        for attempt in range(1, HIT_ATTEMPTS + 1):
            if attempt > 1:
                phone.clear_latency()
                phone.page.wait_for_timeout(700)
                phone.reload()
                phone.camera_ok = phone.wait_camera(required=True)
                decoded = phone.go_hit(
                    shot_id=shot_id, expect=str(code) if code else None,
                    hold_ms=int(_shot_field(shot, "hit_ms", default=2600) or 2600),
                )
            phone.page.wait_for_timeout(hit_settle)
            started = time.monotonic()
            phone.page.screenshot(path=str(png), full_page=False, animations="disabled", caret="hide")
            still_green = bool(phone.page.evaluate(
                "() => { const r = document.getElementById('reticle');"
                " return !!r && r.classList.contains('is-hit'); }"
            ))
            took = (time.monotonic() - started) * 1000
            if still_green:
                logger.info("  [phone] %s recognition flash caught on attempt %d (shutter %.0f ms)",
                            shot_id, attempt, took)
                break
            logger.warning("  [phone] %s attempt %d: the green window closed during a %.0f ms "
                           "shutter; retrying with a fresh decode", shot_id, attempt, took)
        else:
            phone.clear_latency()
            raise PhoneError(
                f"{shot_id}: the reticle's 600 ms green window closed before the shutter "
                f"on all {HIT_ATTEMPTS} attempts. This shot exists to show the flash the "
                "narration names, so a white reticle here would be a still frame pretending "
                "to be a beat. Take it on a less busy machine."
            )
    else:
        scroll = phone.scroll_to(scroll, state=state)
        for target in taps:
            phone.press(target, shot_id=shot_id)
        if taps:
            scroll = phone.scroll_to(scroll, state=state)
        phone.page.wait_for_timeout(
            int(_shot_field(shot, "settle_ms", default=SETTLE_MS) or SETTLE_MS)
        )
    camera = phone.camera_ok

    geometry: dict[str, list[float]] = {}
    for target in list(_shot_field(shot, "selectors", default=()) or ()):
        rect = phone.rect(str(target), shot_id=shot_id)
        if rect is not None:
            geometry[str(target)] = rect

    png = out_dir / f"{shot_id}.png"
    if hit:
        phone.clear_latency()   # photographed above, inside the green window
    else:
        phone.page.screenshot(path=str(png), full_page=False, animations="disabled", caret="hide")
    _check_size(png, shot_id)

    # A burst, for a state whose subject is *moving*. The viewfinder is a real video
    # element playing build/scene_camera.y4m, which carries the handheld drift CONTRACT_V2
    # V3.2 asks for - and a single screenshot throws all of it away, which is how the money
    # shot ended up as a 33-second still photograph. Take a short run of screenshots
    # instead and let compose.py play them back.
    frames: list[Path] = []
    interval = 0.0
    burst = _shot_field(shot, "burst")
    if burst:
        count = int(burst.get("frames", 24)) if isinstance(burst, dict) else int(burst)
        interval_ms = int(burst.get("interval_ms", 66)) if isinstance(burst, dict) else 66
        interval = interval_ms / 1000.0
        for n in range(1, max(1, count)):
            phone.page.wait_for_timeout(interval_ms)
            frame_png = out_dir / f"{shot_id}_b{n:03d}.png"
            phone.page.screenshot(
                path=str(frame_png), full_page=False, animations="disabled", caret="hide"
            )
            frames.append(frame_png)
        if frames:
            _check_size(frames[-1], shot_id)
        logger.info("  [phone] %-22s burst of %d frames @ %d ms", shot_id, len(frames) + 1,
                    interval_ms)

    scroller = phone.scroller_rect(state)
    bus = phone.bus()
    if bus.get("errors"):
        logger.warning("%s: decoder reported %s", shot_id, bus["errors"][-3:])

    if callable(after):
        after()

    note = str(_shot_field(shot, "note", default="") or "")
    if not camera:
        note = (note + " " if note else "") + "camera fallback: Lens showed its no-camera panel"
    result = ShotResult(
        id=shot_id, state=state, png=png, scroll=scroll, decoded=decoded,
        decode_calls=int(bus.get("calls") or 0), held=bool(state == "scan" and hold),
        note=note.strip(), geometry=geometry, scroller=scroller,
        frames=frames, frame_interval=interval,
    )
    logger.info(
        "  [phone] %-22s %-7s%s -> %s", shot_id, state,
        f" decoded={decoded}" if decoded else "", png.name,
    )
    return result


def _check_size(png: Path, shot_id: str) -> None:
    with Image.open(png) as img:
        size = img.size
    if size != (SCREEN_W, SCREEN_H):
        raise PhoneError(
            f"{shot_id}: screenshot is {size[0]}x{size[1]}, expected {SCREEN_W}x{SCREEN_H}. "
            "The mobile context's viewport or device_scale_factor is wrong."
        )


# --------------------------------------------------------------------------- the phone body


#: Proportions, all relative to the screen's own width so the body scales with whatever
#: it is handed. Measured off a Pixel-class phone rather than invented: a 390 pt screen
#: sits inside ~14 pt of bezel, with a ~44 pt corner on the outside and ~35 pt inside.
_BEZEL = 0.036          # bezel thickness / screen width
_OUTER_RADIUS = 0.118
_INNER_RADIUS = 0.092
_RIM = 0.005            # the bright hairline around the body
_SPEAKER_W = 0.155
_SPEAKER_H = 0.0075

_BODY_TOP = (96, 103, 118)      # the rim, lit from above
_BODY_BOTTOM = (30, 33, 40)
_BODY_FILL = (14, 15, 19)
_SPEAKER = (40, 43, 50)
_SHADOW = (0, 0, 0)


#: Key under which :func:`phone_frame` records where the screen ended up, so a caller does
#: not have to infer it from the alpha channel. ``Image.info`` survives ``convert`` and
#: ``resize``, which is how the compositor gets it.
SCREEN_RECT_KEY: Final[str] = "homesoc_screen_rect"


def screen_rect(framed: Image.Image) -> tuple[float, float, float, float]:
    """``(x, y, w, h)`` of the screen inside an image :func:`phone_frame` returned.

    The compositor needs this to place a tap circle or a scroll translation on the screen
    rather than on the bezel. It is recorded when the frame is drawn; when that record has
    been lost (a re-encoded copy), the bezel and shadow padding are solved back out of the
    image's own width, which is exact because every one of them is a fixed fraction of the
    screen's width.
    """
    stored = framed.info.get(SCREEN_RECT_KEY)
    if isinstance(stored, (tuple, list)) and len(stored) == 4:
        return tuple(float(v) for v in stored)  # type: ignore[return-value]

    width, height = framed.size
    low, high = 1, max(2, width)
    while low < high:  # canvas width grows monotonically with screen width
        mid = (low + high + 1) // 2
        if _canvas_size((mid, mid * 2))[0] <= width:
            low = mid
        else:
            high = mid - 1
    m = _metrics((low, low * 2))
    pad = m["blur"] * 3 + m["drop"]
    inset = pad + m["bezel"]
    return (float(inset), float(inset),
            float(width - inset * 2), float(height - m["drop"] - inset * 2))


def phone_frame_size(screen_size: tuple[int, int], *, scale: float = 1.0) -> tuple[int, int]:
    """The size :func:`phone_frame` will return for a screen of ``screen_size``."""
    w, h = _canvas_size(screen_size)
    return max(1, int(round(w * scale))), max(1, int(round(h * scale)))


def _metrics(screen_size: tuple[int, int]) -> dict[str, int]:
    sw, sh = int(screen_size[0]), int(screen_size[1])
    bezel = max(2, int(round(sw * _BEZEL)))
    return {
        "sw": sw, "sh": sh, "bezel": bezel,
        "bw": sw + bezel * 2, "bh": sh + bezel * 2,
        "outer": max(4, int(round(sw * _OUTER_RADIUS))),
        "inner": max(2, int(round(sw * _INNER_RADIUS))),
        "rim": max(1, int(round(sw * _RIM))),
        "blur": max(2, int(round(sw * 0.026))),
        "drop": max(2, int(round(sw * 0.016))),
    }


def _canvas_size(screen_size: tuple[int, int]) -> tuple[int, int]:
    m = _metrics(screen_size)
    pad = m["blur"] * 3 + m["drop"]
    return m["bw"] + pad * 2, m["bh"] + pad * 2 + m["drop"]


def _vertical_gradient(size: tuple[int, int], top: tuple[int, int, int],
                       bottom: tuple[int, int, int]) -> Image.Image:
    """A one-pixel-wide ramp stretched across the body: cheap, and perfectly smooth."""
    w, h = size
    ramp = Image.new("RGB", (1, max(2, h)))
    pixels = ramp.load()
    for y in range(max(2, h)):
        t = y / float(max(1, h - 1))
        # Ease the ramp so the highlight hugs the top edge instead of washing the whole body.
        t = t ** 0.65
        pixels[0, y] = tuple(int(round(top[i] + (bottom[i] - top[i]) * t)) for i in range(3))
    return ramp.resize((w, h), Image.Resampling.BILINEAR)


def phone_frame(screen: Image.Image, *, scale: float = 1.0) -> Image.Image:
    """Composite a Lens screen into a drawn phone body, alpha preserved.

    ``screen`` is normally the 1170x2532 PNG :func:`capture_phone` saved, but any size
    works — every proportion is derived from its width.

    ``scale`` resizes the finished frame **once**, with Lanczos. That is the single
    downscale CONTRACT_V2 V5 allows, so the compositor must place the result at its
    natural size rather than resizing it again.

    The result is RGBA on a fully transparent ground, including a soft drop shadow, so it
    can be dropped over an illustrated scene, a slide, or a flat colour.
    """
    if screen.mode != "RGBA":
        screen = screen.convert("RGBA")
    m = _metrics(screen.size)
    cw, ch = _canvas_size(screen.size)
    pad = m["blur"] * 3 + m["drop"]

    canvas = Image.new("RGBA", (cw, ch), (0, 0, 0, 0))

    # -- shadow: the body's own silhouette, blurred and dropped straight down -------
    silhouette = Image.new("L", (cw, ch), 0)
    ImageDraw.Draw(silhouette).rounded_rectangle(
        (pad, pad + m["drop"], pad + m["bw"], pad + m["drop"] + m["bh"]),
        radius=m["outer"], fill=255,
    )
    shadow_alpha = silhouette.filter(ImageFilter.GaussianBlur(m["blur"]))
    shadow_alpha = shadow_alpha.point(lambda v: int(v * 0.55))
    canvas.paste(Image.new("RGBA", (cw, ch), _SHADOW + (255,)), (0, 0), shadow_alpha)

    # -- body: a lit rim, then the matte shell inside it ---------------------------
    body_box = (pad, pad, pad + m["bw"], pad + m["bh"])
    body_mask = Image.new("L", (cw, ch), 0)
    ImageDraw.Draw(body_mask).rounded_rectangle(body_box, radius=m["outer"], fill=255)
    rim = _vertical_gradient((cw, ch), _BODY_TOP, _BODY_BOTTOM).convert("RGBA")
    canvas.paste(rim, (0, 0), body_mask)

    shell_mask = Image.new("L", (cw, ch), 0)
    ImageDraw.Draw(shell_mask).rounded_rectangle(
        (body_box[0] + m["rim"], body_box[1] + m["rim"],
         body_box[2] - m["rim"], body_box[3] - m["rim"]),
        radius=max(2, m["outer"] - m["rim"]), fill=255,
    )
    canvas.paste(Image.new("RGBA", (cw, ch), _BODY_FILL + (255,)), (0, 0), shell_mask)

    # -- the screen, with its corners cut to match the bezel -----------------------
    screen_xy = (pad + m["bezel"], pad + m["bezel"])
    screen_mask = Image.new("L", screen.size, 0)
    ImageDraw.Draw(screen_mask).rounded_rectangle(
        (0, 0, screen.size[0] - 1, screen.size[1] - 1), radius=m["inner"], fill=255
    )
    # Multiplied with the screen's own alpha, so a transparent screenshot stays transparent
    # inside the rounded corners instead of being forced opaque.
    canvas.paste(screen, screen_xy, ImageChops.multiply(screen.getchannel("A"), screen_mask))

    # -- speaker slot, centred in the top bezel ------------------------------------
    slot_w = max(6, int(round(m["sw"] * _SPEAKER_W)))
    slot_h = max(2, int(round(m["sw"] * _SPEAKER_H)))
    slot_x = pad + (m["bw"] - slot_w) // 2
    slot_y = pad + max(1, (m["bezel"] - slot_h) // 2)
    ImageDraw.Draw(canvas).rounded_rectangle(
        (slot_x, slot_y, slot_x + slot_w, slot_y + slot_h),
        radius=slot_h // 2, fill=_SPEAKER + (255,),
    )

    rect = (float(screen_xy[0]), float(screen_xy[1]), float(m["sw"]), float(m["sh"]))
    if scale and abs(float(scale) - 1.0) > 1e-6:
        target = (max(1, int(round(cw * scale))), max(1, int(round(ch * scale))))
        canvas = canvas.resize(target, Image.Resampling.LANCZOS)
        rect = tuple(v * float(scale) for v in rect)  # type: ignore[assignment]
    canvas.info[SCREEN_RECT_KEY] = rect
    return canvas


# --------------------------------------------------------------------------- self-check


def _demo_screen() -> Image.Image:
    """A stand-in screen for ``python video/phone.py``, so the body can be eyeballed."""
    img = Image.new("RGBA", (SCREEN_W, SCREEN_H), (11, 13, 19, 255))
    draw = ImageDraw.Draw(img)
    for i in range(14):
        y = 240 + i * 150
        draw.rounded_rectangle((90, y, SCREEN_W - 90, y + 110), radius=28,
                               fill=(22, 26, 34, 255), outline=(44, 52, 66, 255), width=3)
    draw.rounded_rectangle((90, 90, SCREEN_W - 90, 190), radius=24, fill=(31, 91, 143, 255))
    return img


if __name__ == "__main__":  # pragma: no cover - a developer convenience
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    out = Path(__file__).resolve().parent / "build" / "phone_frame_check.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    frame = phone_frame(_demo_screen(), scale=0.28)
    frame.save(out)
    print(f"{out}  {frame.size[0]}x{frame.size[1]}  mode={frame.mode}")
