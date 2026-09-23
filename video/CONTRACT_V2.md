# Home SOC walkthrough video — v2 contract (full rebuild, including Lens and the dependency map)

Extends `video/CONTRACT.md`, which still governs everything it already specifies: narration via edge-tts
(`en-US-AndrewMultilingualNeural`), Playwright driving the **installed** Chrome (`channel="chrome"` — the bundled
download fails on this machine), 1920x1080 / 30fps / H.264+AAC, the drawn cursor with its halo and click ripple,
letterboxed window treatment, lower-third captions, 400 ms cross-dissolves, and the rule that nothing in the video
may show the author's real network.

This is a **full rebuild**, not an append. Every desktop scene is re-captured, because the product changed after v1:
the security score was redesigned (diminishing returns per finding type, explainable "fix these first" breakdown,
grade bands recalibrated, one open critical caps the score), a `baseline` command was added, and the sidebar now
carries a Lens entry.

Target length **15–16 minutes** (11–14 before the dependency map was added). The rendered cut is **16:48**, 48 s over.
Scene 19 grew when the Lens card turned out to carry *three* new sections rather than one and the two dependency lists were on
screen with nothing said about them (V6, V7); then a review pass found four sentences that were not true of the picture under
them, and fixing each one cost seconds — see V8. Length is the thing this cut trades away; it does not trade the other way.
`video/out/HomeSOC-walkthrough.mp4` is replaced; keep the same filenames.

## V1. Scene plan (21 scenes, three acts)

**Act 1 — what it is (1–4)**
1. `01-cold-open` — the question, title card.
2. `02-what-it-is` — one process, your PC, nothing leaves it. What it is *not*: not an antivirus engine, not an EDR.
3. `03-architecture` — the diagram slide, narrated as data flowing. It carries **four** output paths now: the
   dashboard, the dependency map at `/map`, the resolver, and Lens on the phone. `slides.py`'s output column is six
   rows at a 47 px pitch; the `/map` row reads "what depends on what · what stops working without it".
4. `04-first-run` — run.bat, what the first run does.

**Act 2 — the dashboard (5–13, with `07a`)** — same order as v1, re-captured and re-narrated where the UI changed.
5. `05-overview` — **rewritten**: the score is now explainable; narrate the "fix these first" panel and the idea that
   clearing the top item is worth a stated number of points. Do not repeat v1's wording about a flat score.
6. `06-findings` · 7. `07-devices`
7a. `07a-dependency-map` — **new**, and placed here on purpose: the viewer has just been told Home SOC knows every
   device, which is the moment "so what happens when one of them dies?" is a question they are ready to ask. The id is
   lettered so every existing scene id stays as it is. The scene covers, in this order:
   1. **the question** — on the `dependency_why` slide: you are told `192.168.1.142` is the worst thing on the
      network, but if the router dies, what actually stops working?
   2. **the honest line, said plainly and early** (at 0.116 of the scene, over the page's own `#map-note`): this is
      not a traffic diagram, Home SOC has no packet visibility, and it cannot see one device talking to another. It is
      not a caveat at the end and it is not hedged. SPEC addendum C1.
   3. **the map, left to right** — internet, gateway, infrastructure (resolver and offered services), devices sized by
      what leans on them, external services folded up on the right.
   4. **the four link styles**, on the page's own legend at scroll 316, one glow per row as it is named: solid
      observed, dashed inferred, dotted assumed — and *why* they are drawn differently — then the fourth, fainter
      still: a domain the filter refused, drawn because the lookup happened and not because anything depends on it.
   5. **the provider nodes reading "no confirmed consumers"**, narrated as the feature they are: the printer
      advertises printing, nothing has been seen printing to it, so the map draws no consumer link at all where a
      product willing to guess would have drawn one per laptop. This is the reason the rest of the picture can be
      trusted, and the scene says so.
   6. **blast-radius mode** — a real click on the router node, then the panel's sentence read out ("seventeen devices
      lose their internet connection … nothing becomes unreachable"), its counts, and its confidence word: *inferred,
      not observed*, plus what would make it observed.
8. `08-vulnerabilities` · 9. `09-host-posture` · 10. `10-dns-filter`
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
19. `19-lens-card` — reading the card: the plain-English headline, the cost in score points, then **If this fails** —
    the dependency map's answer carried to the phone, which is the single best use of the feature (SPEC C7): the house
    loses this camera's video stream, nothing has been seen watching it, so nothing else is known to stop working, and
    the card says whether that was observed or inferred and repeats the packet-visibility limit. Deliberately the
    shortest beat in the act: the argument was made in full in `07a` and this act is already the longest. Then
    Problems with numbered fix steps, Exposed ports, Vulnerabilities with the actively-exploited ones flagged, and
    **Talking to** — the section that shows the camera phoning home to its vendor's telemetry, most of it blocked.
    Close the act with the honest limits, spoken plainly: Chrome on Android is the target, the self-signed certificate
    is a real trust decision, and identification costs one tap per device the first time.
20. `20-close` — where it runs, what it costs, the docs, MIT, and "only scan networks you own". Its **Read next** card
    lists `docs/TOPOLOGY.md` alongside the rest, because the map's honesty depends on the reader being able to find
    the argument for it in full.

Narration rules from CONTRACT.md still apply: second person, calm, concrete, no marketing, explain *why* before
*what*, and never claim a capability the product does not have. The dependency map raises the stakes on that last
rule: nothing in the film may call the map a traffic diagram, describe it as flows or connections, or imply that Home
SOC watches conversations between devices. It says *depends on*, it says how each link was established, and it says
out loud what it cannot see.

**Slides** (`slides.py`), ten of them in narrative order: `title`, `what_it_is`, `architecture`, `first_run`,
`dependency_why`, `daily_use`, `lens_why`, `lens_how`, `lens_limits`, `close`. `dependency_why` is the map act's
opening card: the question as its heading, three cards for *depends on* / *depended on by* / *if this fails* with a
small drawn sketch each, and a footer strip carrying the packet-visibility statement in the same words the page uses.

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
- **The dependency map is never described as traffic.** The words "not a traffic diagram", "no packet visibility" and
  "it cannot see one device talking to another" are spoken in the first third of scene `07a`, over the page's own
  note, and the same admission is repeated on the Lens card in scene 19. A cut that moves either of them to the end,
  softens them into a caveat, or drops them fails this bar regardless of how good the rest looks.
- **Nothing on screen is narrated as a relationship the product has not evidenced.** In particular the provider nodes
  that read "no confirmed consumers" are narrated as a deliberate refusal to guess, and the one link such a node does
  have — back to the device hosting the service — is named rather than ignored, so no viewer can mistake it for a
  consumer. `07a`'s Zoom keeps that link in shot while the sentence is spoken.

## V6. Scene 07a — capture requirements and measured length

- The `/map` shot must be the page's **default window**. The `window` select reads "7 days" (`topology.window_hours`
  = 168), which is the same week `script.MAP_WINDOW_HOURS` reads the spoken figures over. Do not navigate to
  `/map?hours=…` for this scene.
- The graph fits the viewport at scroll 0 (`#map-canvas` 958×684 at y=173.5; the drawing inside it is 935 px wide
  since the labels stopped truncating), so the left-to-right walk needs no scrolling. The page is **1,216 px** tall
  against the 900 px viewport, so **316 is both the offset that frames the legend and the page's maximum** — it
  cannot be clamped. It was 1,237/337 before the collapsed external-services sublabels were shortened.
- Every node is a `<g class="map-node" data-id="…">` drawn by `static/graph.js` with an invisible hit rect covering
  its shape and its label, so `bounding_box()` and a centre click both land correctly. The blast-radius panel
  (`.map-headline`, `.map-stats`, `.map-evidence`) and `#map-exit` **do not exist until a node is selected**:
  geometry for anything after the click is resolved on the after-state, and the click does not change the URL, so
  capture re-settles on the same page instead of navigating.
- The engine builds the graph from rows `seed_demo.py` already writes (`dns_queries`, `services`, `device_sightings`,
  advertisements). `dep_edges` is a cache and need not be populated; deleting it must stay harmless.
- Measured with `en-US-AndrewMultilingualNeural` at `-4%` on 2026-09-14, after the V8 pass: `07a-dependency-map`
  396 words → **149.4 s** (357 / 133.0 before it); `19-lens-card` 343 words → **140.3 s** (331 / 134.2);
  `03-architecture` 98 words → **40.3 s** (89 / 37.0). Total speech **993.3 s**; the rendered film is
  **1,008.2 s = 16 min 48 s** with `narrate.py`'s per-scene padding (measured on the finished file:
  `ffprobe` 1008.13 s of H.264 and 1008.17 s of AAC).
- The `/map` page is **1,216 px** tall against the 900 px viewport, so the legend shot is at scroll **316**, which is
  the maximum. It was 337 before the collapsed external-services nodes had their sublabels shortened to fit.
- **Time the choreography off the SRT, not off word position.** `narrate.py` snaps each sentence boundary to a
  silence it measured in that scene's own MP3, so the cue times are where the words actually are; a fraction
  computed from word index through the text is a guess, and on `07a` it was three seconds out at the top of the
  scene. Render once, read the fractions out of `out/HomeSOC-walkthrough.srt`, re-time, re-render that scene.

## V7. Scene 19 — the Lens card has EIGHT sections, and the render bar the previous cut missed

Two defects were found by driving the card that this cut actually captures, and both were invisible in the script:

- **`lens.js` renders eight sections, not six.** "If this fails" is followed by **"Depends on"** and **"Depended on
  by"**, and only then by Problems: `1 If this fails · 2 Depends on · 3 Depended on by · 4 Problems · 5 Exposed ·
  6 Vulnerabilities · 7 Talking to · 8 History`. The committed script assumed one new section, so
  `details.sec:nth-of-type(4)` — meant to open Vulnerabilities — was **Problems**, and the tap *closed* it while the
  narration said "Vulnerabilities stays folded … open it". Every offset after it was measured on a card 470 px
  shorter than the real one, so four states clamped to the same maximum and the scene held one frame for 22 s.
  Measured layout (`#card-body` clientHeight 626): collapsed scrollHeight 4,121, max scroll 3,495, sections at
  417 / 707 / 1,364 / 1,547 / 2,892 / 3,334 / 3,387 / 3,983; with Vulnerabilities open, scrollHeight 4,301,
  max scroll 3,675, Talking to 3,567, History 4,163. (The vendor dependency row is 104 px rather than 85: it
  carries both halves of a part-refused domain now, which is one extra wrapped line and 20 px on everything
  below it.)
- **The narration now names the two lists.** They cannot be scrolled past in silence: the card shows them between
  "If this fails" and Problems, and the sentence that used to say "Problems comes next" was simply false. The added
  beat says what depends on the camera, that each row carries its confidence word and its evidence, that the refused
  domains are kept apart from the rows because asking is not depending, and that "Depended on by" is empty and says
  so in words. That is the printer principle from `07a` carried to the phone, and it is what pushed the film to
  16:23; the V8 pass took it to 16:48. If it has to come back under 16:00, cut the refused-domains clause in
  19 (~8 s) before anything in `07a`.

**No frozen stretch longer than 6 s.** Measured on this cut: `freezedetect=n=-60dB:d=2` reports 20 stretches, the
longest **4.47 s**, and the drift is running through all of them — a bit-identical check (mean absolute inter-frame
difference on a 320x180 grey decode) finds no run longer than **0.8 s** anywhere in the film. -60 dB is below the
drift's own per-frame delta, so freezedetect flags "moving but very quiet" as frozen; both numbers are reported
because only the second one means *nothing changed*. The film is built out of held screenshots, and `freezedetect` found 21.9 s,
12.6 s, 12.0 s and 10.8 s stretches in it. `compose.py` now drifts a held page or phone state the way it has always
drifted a slide, but at a fixed *speed* (`IDLE_DRIFT_RATE`, 2.5 page-layer px/s) in short in-and-out cycles
(`IDLE_DRIFT_CYCLE`) rather than one push across the whole hold: a slide's single push gets slower the longer the
hold, and below about 0.05 px/frame a dark dashboard rounds to the same bytes two frames running and freezes anyway.
A Zoom's hold phase is a freeze of the same kind, so it keeps creeping at the same speed, capped at `HOLD_CREEP_MAX`
past the rect the Zoom asked for. The excursion stays under one per cent, which is far too small to read as movement
or to soften 2x-captured text. It roughly halves compose throughput and it costs file size — nothing in the frame
repeats any more, so x264 has nothing to coast on.

## V8. The honesty pass — what a frame-by-frame review found, and what it cost

Four sentences were true of the product and false of the frame under them, and two features of the map contradicted the
panel beside them. Length was the only thing available to pay with, and it was paid.

**Narration.**

1. The `EXTERNAL SERVICES` column holds 24 endpoints, **15 of which were asked for and refused**. It was narrated as
   "the outside services they reach". It now names both halves, and both numbers come from the graph
   (`script._topology_facts`) rather than from the script.
2. The legend headed "How each link was established" has **four** rows. The voice said "the three", and the row it left
   unspoken was *Blocked* — the one that says a refused lookup is drawn because the lookup happened, not because
   anything depends on it. All four are named and all four get a glow.
3. `SPEC_TOPOLOGY` C3 defines a watched outage as devices going offline **in the same discovery cycle**, and requires
   every surface reporting one to state that resolution. The film said "dropping together", which reads as
   simultaneity, and the words "discovery cycle" appeared nowhere in the SRT. They are now in the Observed sentence,
   beside the legend row that states them, and in the evidence sentence at the end of the scene.
4. Scene 03's architecture slide has carried **four** output paths since the map shipped (V1 §3). The voice said
   "three ways to read one database" over a column showing six rows, of which the second is the dependency map. It now
   says four and names it. The title card gained a `dependency map · what depends on what` chip for the same reason:
   the film's second new feature was absent from Act 1 entirely.

**The product, because the narration could not be made true without it.**

5. Blast-radius mode dimmed *The internet* and *Home SOC DNS filter* while the panel listed both under "what the house
   loses", and reported "0 unaffected" beside four dim nodes. Non-device nodes the failure reaches are now in the
   radius, read off the graph's `internet` edges, and the panel says in words that the three tiles count devices.
6. It also ringed **thirteen** provider nodes as lost on a router failure — printing, scanning, AirPlay, Sonos — when
   the panel listed exactly one. A degraded host keeps offering what it offers. Only the node that failed, and anything
   the payload calls unreachable, take their services with them; the other twelve dim, which is what finally gives
   "the rest dims" something true to point at.
7. The two ring colours were `--sev-critical` and `--sev-medium`, the same two hues the map spends on finding severity,
   with nothing in the legend to separate the meanings. There is one accent ring now; which kind of harm it is is a
   word, on the node and in the panel (C7: never colour alone).
8. Five node labels were cut mid-word for the whole 2¼-minute scene, including the two the narration asks the viewer
   to read. `MAX_LABEL` is 126, the offline suffix has its own room instead of eating the name's, and the collapsed
   groups' sublabels were shortened to fit. The drawing is 935 px wide in a 956 px canvas.
9. The Lens card's "asked for, but blocked" list omitted the largest refusal on the device — the vendor's telemetry
   collector, 46 lookups — because its registrable domain also appears as an allowed dependency, so the answered half
   won and the refused half vanished into a row labelled OBSERVED. The row states both counts now. It is not a second
   endpoint and it is not evidence of dependence, so it is not a second row and it is not in `observed_count`.

**Timing.** The blast-radius click fired four seconds after the voice had described its result; the printer Zoom and
Highlight ended two to four seconds before the sentence they illustrate; the Assumed glow opened 2.5 s into a 3.9 s
sentence and overhung the next one; a 1.8 s cross-fade on the Lens card put two complete card bodies on screen at 50/50
for 0.8 s, under the words naming the section. All four were the same mistake: fractions computed from word position
rather than read off the SRT. See the note in V6.

**Freeze.** `IDLE_DRIFT_AFTER` was 4.0 s and scene 18's `hit=True` shot is on screen for 3.83 s, so the one frame in the
film whose narration claims continuous motion was the one frame the drift skipped: 3.7 s bit-identical. The threshold is
2.5 s and the shot is 4.5 s long.
