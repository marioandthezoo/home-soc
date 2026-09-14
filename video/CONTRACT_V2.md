# Home SOC walkthrough video — v2 contract (full rebuild, including Lens)

Extends `video/CONTRACT.md`, which still governs everything it already specifies: narration via edge-tts
(`en-US-AndrewMultilingualNeural`), Playwright driving the **installed** Chrome (`channel="chrome"` — the bundled
download fails on this machine), 1920x1080 / 30fps / H.264+AAC, the drawn cursor with its halo and click ripple,
letterboxed window treatment, lower-third captions, 400 ms cross-dissolves, and the rule that nothing in the video
may show the author's real network.

This is a **full rebuild**, not an append. Every desktop scene is re-captured, because the product changed after v1:
the security score was redesigned (diminishing returns per finding type, explainable "fix these first" breakdown,
grade bands recalibrated, one open critical caps the score), a `baseline` command was added, and the sidebar now
carries a Lens entry.

Target length 11–14 minutes. `video/out/HomeSOC-walkthrough.mp4` is replaced; keep the same filenames.

## V1. Scene plan (20 scenes, three acts)

**Act 1 — what it is (1–4)**
1. `01-cold-open` — the question, title card.
2. `02-what-it-is` — one process, your PC, nothing leaves it. What it is *not*: not an antivirus engine, not an EDR.
3. `03-architecture` — the diagram slide, narrated as data flowing. Update it to include Lens as an output path.
4. `04-first-run` — run.bat, what the first run does.

**Act 2 — the dashboard (5–13)** — same order as v1, re-captured and re-narrated where the UI changed.
5. `05-overview` — **rewritten**: the score is now explainable; narrate the "fix these first" panel and the idea that
   clearing the top item is worth a stated number of points. Do not repeat v1's wording about a flat score.
6. `06-findings` · 7. `07-devices` · 8. `08-vulnerabilities` · 9. `09-host-posture` · 10. `10-dns-filter`
11. `11-activity-feed` · 12. `12-summary`
13. `13-day-to-day` — scheduler cadence, notifications, and the CLI worth knowing, now including `baseline`.

**Act 3 — Lens (14–19)** — the new material.
14. `14-lens-why` — the problem. Home SOC tells you `192.168.1.142` is the worst thing on your network. You are now
    standing in a hallway holding a phone, looking at four identical white boxes. Which one is it? That gap between
    a row in a table and an object on a shelf is what Lens closes.
15. `15-lens-how` — slide: identification by visual tag. Any barcode already on the label works; scan an unknown code
    once, tap the device, and every later scan is instant. Stickers cover devices with no readable label, and a
    sticker QR carries an opaque token — never a MAC, IP or hostname — so photographing one reveals nothing.
16. `16-lens-setup` — why HTTPS is required (browsers only hand out the camera in a secure context), the certificate,
    and the pairing screen with its QR. Show the real `/lens/pair` page.
17. `17-lens-stickers` — the printable sheet at `/lens/stickers`.
18. `18-lens-scan` — **the money shot**. The phone is pointed at a device; the sticker is recognised; the card rises.
    See V3 for how this is produced.
19. `19-lens-card` — reading the card: the plain-English headline, Problems with numbered fix steps, Exposed ports,
    Vulnerabilities with the actively-exploited ones flagged, and **Talking to** — the section that shows the camera
    phoning home to its vendor's telemetry, most of it blocked. Close the act with the honest limits, spoken plainly:
    Chrome on Android is the target, the self-signed certificate is a real trust decision, and identification costs
    one tap per device the first time.
20. `20-close` — where it runs, what it costs, the docs, MIT, and "only scan networks you own".

Narration rules from CONTRACT.md still apply: second person, calm, concrete, no marketing, explain *why* before
*what*, and never claim a capability the product does not have.

## V2. Phone capture and compositing

`video/phone.py` (new, owned by the capture package):
```python
def capture_phone(page_path: str, *, token: str, shots: list[dict], out_dir: Path) -> dict
    """Drive /lens in a 390x844 @3x mobile context and save screen PNGs."""
def phone_frame(screen: Image, *, scale: float = 1.0) -> Image
    """Composite a 390x844 screen into a drawn phone body: rounded corners, a dark bezel with a
    subtle rim highlight, a speaker slot, and a soft drop shadow. Returned with an alpha channel
    so the compositor can place it over anything. Drawn programmatically — no image assets."""
```
Mobile context: `viewport 390x844`, `device_scale_factor=3`, `is_mobile=True`, `has_touch=True`,
`color_scheme="dark"`, `permissions=["camera"]`, `ignore_https_errors=True`, and an Android user agent.
The Lens token is injected into `localStorage` under `homesoc.lens.token` before the first render.

New `Shot` variant for `script.py`: `Phone(path="/lens", state="scan"|"card"|"picker"|"unknown", scroll=0)`, and a
`PhonePair(scene_png, phone_state)` for scene 18 that places the illustrated scene and the phone side by side.
Cursor choreography does not apply to phone shots; instead use `Tap(at=..., xy=...)` which draws a touch circle that
expands and fades (finger, not mouse pointer), and `PhoneScroll(to_y=..., at=..., seconds=...)`.

## V3. The scan rig — how scene 18 is produced honestly

Desktop Chrome on Windows has **no `BarcodeDetector`** (verified: it is an Android/macOS/ChromeOS platform API), so
the recording machine cannot run the real in-browser decode. The scan is still produced from real pixels rather than
faked, as follows:

1. `video/scene_render.py` draws a **synthetic scene**: a small wall-mounted camera on a shelf, rendered as HTML/SVG
   in the same browser, with a genuine QR sticker on its underside produced by `homesoc/web/qr.py` encoding the demo
   camera's real sticker token. Flat vector illustration in the product's palette — no photographs, no stock art.
2. That still is converted to a short **Y4M** clip with a slow handheld drift (a few pixels of translation and a
   fraction of a degree of rotation, eased) so the camera feed looks alive, and Chrome is launched with
   `--use-file-for-fake-video-capture=<clip>.y4m --use-fake-ui-for-media-stream`.
3. `video/decode_sidecar.py` runs a loopback HTTP endpoint that accepts a PNG data URL and decodes it with
   **zxing-cpp** (a capture-time dev dependency, installed with `pip install --user zxing-cpp`; it must NOT appear in
   `requirements.txt` or `pyproject.toml`).
4. Playwright injects a `BarcodeDetector` shim via `add_init_script` that grabs the frame, posts it to the sidecar,
   and returns the decoded `rawValue` and bounding box in the shape the real API returns.

5. The viewfinder states of scene 18 are captured as **bursts** — `Phone(burst=N, burst_ms=M)` takes N real
   screenshots M ms apart and `compose.py` plays them back. A single screenshot of a `<video>` element throws the
   step-2 drift away, which is exactly what happened in the first v2 cut: the money shot was a still photograph for
   33 s under narration describing continuous motion. Every burst frame is a real screenshot; nothing is interpolated.
6. One shot in scene 18 carries `hit=True`: the real instant of recognition, with the reticle green and the chip
   reading "identifying…". `phone.py` holds back **the response to `/api/lens/identify`** for a couple of seconds
   (`_LATENCY_JS`) so that genuine in-flight state lasts longer than two frames, photographs it, and releases it. It
   fails loudly if Lens's own 600 ms green window closes before the shutter, so it can never quietly degrade into a
   still of an idle viewfinder.

So the pixels on screen are genuinely decoded; only the decoder lives beside the browser instead of inside it, and the
only other intervention is how long one loopback request took. Both substitutions **must be stated** in
`video/CONTRACT_V2.md` (here), in `video/README.md`, and — because the video makes
a claim about the product — the narration must not say anything that is untrue of a real Android phone. Saying "point
the phone at the sticker and Lens recognises it" is fine, because that is what the product does on the target
platform. Claiming "here it is running on a phone" would not be, because this is Chrome on a PC in a phone-shaped
viewport. Prefer wording that describes the product, not the recording.

If the shim fails for any reason, `render.py` must **fail loudly** rather than silently falling back to the manual
picker and narrating it as a scan.

## V4. Demo data additions (`video/seed_demo.py`)

Extend the existing fictional household so the Lens scenes have real content:
- a `lens_tokens` row for a paired phone labelled "Pixel in the hallway", scope `read`, so `/lens` renders;
- `lens_tags`: a **sticker** tag for the camera at `192.168.1.142` (the token the scene render encodes), a **learned**
  tag bound to the printer to demonstrate tag learning, and one **ignored** code so that state exists;
- leave at least four devices untagged so the sticker sheet has something to print.
Keep everything relative to now, keep the host `HOME-PC`, SSID `Home-WiFi`, public IP `203.0.113.42`.
Regenerating must stay idempotent and must never touch the real `data/`.

## V5. Quality bar (additions to CONTRACT.md §6)

- Every desktop scene is re-captured against the current build; no v1 stills survive into v2.
- Any number spoken matches what is on screen at that moment, including the new score figures.
- Phone screens are captured at 3x and downscaled once; text in the phone frame must be legible at 1080p, which means
  the phone occupies enough of the canvas — roughly 55–70% of frame height in phone-only scenes.
- The Lens act must not imply world-anchored 3D AR. It is a camera viewfinder with an information panel.
- No frame shows the author's real network, real MAC, real SSID, real public IP, or a path containing their username.
- The finished file still passes the v1 checks: one H.264 stream, one AAC stream, durations within 0.5 s, and it
  plays in VLC and a browser.
