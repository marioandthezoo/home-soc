# CONTRACT_EVERYDAY: "Meet the Household"

The walkthrough film for everyday viewers. It sits beside the technical cut (CONTRACT.md,
CONTRACT_V2.md) and borrows everything that contract proved (edge-tts narration, Playwright
capture through the installed Chrome, the phone rig, the scan rig and its disclosure, the
compositor), with three changes: its own script, a beat mechanism for comedy, and the
redesigned dashboard's look.

## What this film is

* **Script:** `video/everyday/SCRIPT.md`. 14 scenes, about 9.9 minutes, one ordinary week in a
  fictional household. The words are settled; the pipeline realises them and does not rewrite
  them. `video/script_everyday.py` carries them as data (`SCENES`, same shot and action classes
  as `script.py`).
* **Slides:** `video/slides_everyday.py` (31 flat SVG illustrations, including key-frame
  variants for animated beats). They go through the same slide path as `slides.py`:
  `capture.py` sets each slide's HTML as the page in the capture browser and screenshots it at
  1600x900 @2x.
* **Audience:** people who have never heard the word "SOC". Plain words, one idea at a time,
  jokes to keep them watching, and the film opens on a joke.
* **Deliverable:** `video/out/HomeSOC-walkthrough.mp4` + `.srt`, 1920x1080, 30 fps, H.264 +
  AAC. The technical cut now renders to `video/out/HomeSOC-walkthrough-technical.mp4`.
  Before the first everyday render, whatever `out/HomeSOC-walkthrough.*` held is moved to
  `out/archive/HomeSOC-walkthrough-<date>.<ext>`. A previous film is never deleted.

## Look

Every dashboard frame shows the redesigned "Stone & Sage" day theme with its plain-language
labels. The capture browser reports `prefers-color-scheme: light`. The redesigned `style.css`
follows that setting, so a "dark" browser would get the cocoa Dusk theme. The compositor's
`stone` look puts the window on a stone canvas and draws the lower third in ink with a sage
dot. The cursor halo, click ripple and highlight glow are sage too. No frame may contain the
old near-black theme. Lens itself (`/lens` on the phone) is dark by the product's own design.

## Beats

Narration carries `[beat]` (0.6 s) and `[beat N]` (N seconds, from 0.05 to 4) marks.

* The text between marks is synthesised as separate edge-tts segments. Each one is cached by
  `sha256(text | voice | rate)` in `build/audio/cache/`, beside its word boundaries.
* Each segment's own leading and trailing silence is measured on the decoded PCM (-50 dBFS,
  10 ms windows) and trimmed. The segments are then joined with digital silence, so **the gap
  between the last sound before a beat and the first sound after it is the beat's length**.
  The test fixture measured every beat within 15 ms, in the scene WAV and again in the final
  muxed AAC.
* Marks are never spoken and never subtitled. Any other `[...]` in narration fails the run,
  because the voice would read it out.
* Subtitles are timed from the real segment boundaries and the endpoint's word boundaries, not
  from character counts. A cue never spans a beat, so a punchline is never on screen before it
  is said. A set-up cue may stay on screen through its beat for up to 0.7 s.
* `build/everyday/beats.json` records every scene's segments, beats and words, in seconds and
  as `at` fractions. Scripts place actions with `narrate.beat_at(scene, n, edge=...)`,
  `narrate.line_at(scene, n)` and `narrate.phrase_at(scene, "eighteen")`. Each helper returns
  its `default` until the scene has been narrated. `render.py` imports the script only after
  narration, so the values that reach the film are the measured ones.
* Voice `en-US-AndrewMultilingualNeural`, rate `-4%`. Do not change them.

## Web blocking really runs

`homesoc serve` never starts the resolver, so a plain capture would show "Web blocking is
switched on but not running" beside a day of blocked look-ups. The capture launcher starts the
product's own resolver (`Runtime.start_dns()`, the same call `homesoc run` makes) on 127.0.0.1
and a free high port. It never binds port 53 or the LAN. That port is written only into the
working copy's settings. The v2 script that repainted the indicators is gone. Before the first
shot, `capture.py`:

1. waits until `/api/summary` reports the resolver running, and lets its first health pass
   finish, so any NET-DNS finding it files lands before the first scene and not between two;
2. loads Home and Blocking in the capture browser and fails unless nothing says
   "not running", the topbar chip is live, the sidebar reads "Blocking: running" and the
   Blocking page's status badge reads "Running". The pages are left as
   `build/everyday/verify_blocking_{home,dns}.png` to look at.

Nothing sends a query to the resolver during capture, so every count on screen is the seed's.
The Blocking page's small "Technical details" line truthfully shows `127.0.0.1:<port>`.

The running resolver judges blocklists by file age. The working copy's list files are dated to
the seed's `feeds.last_updated`. So a seed older than three days makes the resolver file
NET-DNS-003 ("blocklists older than 3 days"). Capture prints a note when that happens, and the
"to fix" count rises by one. With the 2026-09-14 seed that happened: 33 open became 34, and
Home showed "last checked 8 days ago" with no look-ups in the last 24 hours. Reseed
(`render.py --reseed`) before the real capture, then re-check the spoken figures.

Do not run `homesoc scan --only topology` on `video/demo_data`. The map page builds its graph
live (`build_graph`: 62 nodes and 99 edges with or without the scan), so the scan adds nothing
to scene 11. What it does add is seven "Good to know" findings: the "to fix" count goes from 33
to 40, several titles name real ad domains, and the camera gets a seventh finding, so the Lens
card reads "Seven problems" under narration that says "six problems". Measured 2026-09-23.

## Honesty rules (from SCRIPT.md's honesty check; they bind the film)

* Home SOC is not an antivirus and does not make a home hacker-proof.
* The dependency map shows reliance ("who relies on whom"), never connections or traffic.
* The 94% (EPSS) figure means "exploited somewhere in the world in the next 30 days". It is
  never "your chance of being attacked".
* Lens needs Chrome on Android and a certificate step (matching the long fingerprint).
  SCRIPT.md deliberately avoids promising the step is "one-time", because Chrome can ask again
  after a restart. Lens is a viewfinder with a card, not 3D labels.
* The recording's Lens scan uses the zxing-cpp decode sidecar (CONTRACT_V2 V3, README). The
  narration describes the product, never "this phone". The scan rig check still gates the
  render. To arm it, the scan scene must use `PhonePair` or `via="scan"`.
* Only scan networks you own or run.
* Everything shown is the fictional demo household (`video/demo_data`, working copy only).
* A DNS look-up is matched to a device by network address, which another device can forge. The
  screen says "requested from Ellie's iPhone's address". Narration may speak naturally but must
  not claim more certainty than the screen does.
* Every number spoken matches the frame it is spoken over, such as Home's status sentence and
  the "N to fix" chip.

## Re-rendering

```bat
python video/render.py                          :: everything (seed reused, narrate, capture, compose)
python video/render.py --only 10-friday-blocking
python video/render.py --no-capture             :: recompose from the shots on disk
python video/render.py --no-narrate --no-capture
python video/render.py --list                   :: scenes, words and beats
python video/narrate.py                         :: narration + beats.json + SRT only
```

The build lives in `video/build/everyday/`. `--script technical` renders the technical cut (`script_technical.py`, or `script.py` when that
file is absent) from `video/build/`. A fixture film (`--script <name>` for a `script_<name>` module on `PYTHONPATH`)
builds under `video/build/films/<name>/` and never writes to `video/out/`.
