"""Narration stage of the Home SOC walkthrough video.

Turns every ``Scene.narration`` string in :mod:`script` into an MP3 with edge-tts
(Microsoft's neural voices), measures each file with ``ffprobe`` and writes the two
artefacts the rest of the pipeline consumes:

``video/build/timings.json``
    ``{scene_id: {"audio": <abs path>, "seconds": float, ...}}`` — the shape named in
    ``CONTRACT.md`` §3, plus a few extra keys (``index``, ``lead_in``, ``pad``, ``start``,
    ``end``, ``sentences``) so ``render.py`` can lay the timeline out with exactly the same
    numbers this module used for the subtitles.

``video/out/HomeSOC-walkthrough.srt``
    One cue per sentence, timed by proportional character length inside its scene.

Timeline model (shared with ``render.py`` via the extra keys above)::

    scene_duration = LEAD_IN + speech + TAIL_PAD
    scene_start[0] = 0
    scene_start[i] = scene_start[i-1] + scene_duration[i-1]
    total          = sum(scene_duration) + END_ROOM_TONE

Scene cross-dissolves are assumed to happen *inside* the lead-in / tail padding, i.e. scenes
do not overlap on the timeline. Speech in scene *i* therefore starts at
``scene_start[i] + LEAD_IN``, which is the 0.3 s "audio starts after the visual settles"
rule from ``CONTRACT.md`` §6.

Synthesis is cached by ``sha256(text | voice | rate)`` under ``build/audio/cache/`` so
re-running after a script tweak only re-synthesises the scenes whose words changed.

Usage::

    python video/narrate.py               # synthesise everything that is not cached
    python video/narrate.py --force       # ignore the cache
    python video/narrate.py --only 06-findings
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Sequence
from typing import Any, Final

HERE: Final[Path] = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # so `python video/narrate.py` finds script.py next door
    sys.path.insert(0, str(HERE))

BUILD: Final[Path] = HERE / "build"
AUDIO_DIR: Final[Path] = BUILD / "audio"
CACHE_DIR: Final[Path] = AUDIO_DIR / "cache"
OUT_DIR: Final[Path] = HERE / "out"
TIMINGS_PATH: Final[Path] = BUILD / "timings.json"
SRT_PATH: Final[Path] = OUT_DIR / "HomeSOC-walkthrough.srt"

VOICE: Final[str] = "en-US-AndrewMultilingualNeural"
RATE: Final[str] = "-4%"

#: Silence before the voice at the start of every scene (CONTRACT §6).
LEAD_IN: Final[float] = 0.30
#: Silence after the voice, before the scene hands over to the next one.
TAIL_PAD: Final[float] = 0.40
#: Room tone at the very end of the film (CONTRACT §6). Must match compose.END_ROOM_TONE.
#: TAIL_PAD + this is the silence the pipeline adds after the last word; edge-tts leaves
#: roughly another third of a second of its own, so 0.60 here measured 1.34 s of dead air.
END_ROOM_TONE: Final[float] = 0.25

#: Sentences shorter than this are merged into their neighbour so no subtitle flashes past.
MIN_CUE_CHARS: Final[int] = 28
#: ...but never merge past this, or a cue outstays its welcome on screen.
MAX_CUE_CHARS: Final[int] = 150
#: A sentence longer than this is broken at the clause boundary nearest its middle.
SPLIT_CUE_CHARS: Final[int] = 130
#: Subtitle line wrapping.
SRT_LINE_CHARS: Final[int] = 42
SRT_MAX_LINES: Final[int] = 3

FFPROBE_TIMEOUT: Final[int] = 30
#: Seconds of speech per word for this voice at this rate, measured across all 20 scenes of
#: the v2 script (1,919 words, 794 s). Only ever used to *doubt* a take, never to time one.
SECONDS_PER_WORD: Final[float] = 0.414

#: A finished take shorter than this fraction of the length its word count predicts is
#: treated as a truncated stream rather than a fast reading. The public speech endpoint
#: intermittently closes the socket mid-scene: the file is valid MP3, ``written`` is far from
#: zero, and the old guard let it straight through — one observed take of scene 5 came back
#: 39.6 s instead of 64.8 s (61%), which would have desynchronised every cue after it.
#: Chosen well below any plausible fast reading; see :func:`_accept_duration`.
SHORT_TAKE_RATIO: Final[float] = 0.65

#: If two takes of the same text land within this fraction of each other, the length is the
#: voice's real opinion of the text, not a truncation — truncation is intermittent and cuts
#: at a different point every time. This keeps an unusually terse scene from failing the run.
STABLE_TAKE_RATIO: Final[float] = 0.05

#: CONTRACT_V2 §preamble: the finished film should land between these, in minutes.
FILM_TARGET_MIN: Final[float] = 11.0
FILM_TARGET_MAX: Final[float] = 14.0

SYNTH_TIMEOUT: Final[float] = 120.0
#: The public speech endpoint drops the occasional connection; retry before giving up.
SYNTH_ATTEMPTS: Final[int] = 3
SYNTH_BACKOFF: Final[float] = 2.0

logger = logging.getLogger("homesoc.video.narrate")


class NarrationError(RuntimeError):
    """Anything that stops narration being produced, with an actionable message."""


class TransientTTSError(RuntimeError):
    """A speech-endpoint hiccup that is worth retrying rather than failing the run."""


# --------------------------------------------------------------------------- data


@dataclass(frozen=True)
class Cue:
    """One subtitle: absolute seconds on the finished film's timeline."""

    text: str
    start: float
    end: float


@dataclass
class SceneAudio:
    """One scene's synthesised narration and where it sits on the timeline."""

    index: int
    scene_id: str
    text: str
    path: Path
    seconds: float
    start: float = 0.0
    cues: list[Cue] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Wall-clock length of the scene, padding included."""
        return LEAD_IN + self.seconds + TAIL_PAD

    @property
    def end(self) -> float:
        return self.start + self.duration

    def as_json(self) -> dict[str, Any]:
        return {
            "audio": self.path.as_posix(),
            "seconds": round(self.seconds, 3),
            "index": self.index,
            "lead_in": LEAD_IN,
            "pad": TAIL_PAD,
            "start": round(self.start, 3),
            "end": round(self.end, 3),
            "duration": round(self.duration, 3),
            "sentences": len(self.cues),
        }


# --------------------------------------------------------------------------- scenes


def load_scenes() -> list[tuple[str, str]]:
    """``[(scene_id, narration), ...]`` from ``video/script.py``, in order."""
    try:
        import script  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on sibling module
        raise NarrationError(
            f"cannot import {HERE / 'script.py'} - the scene script must exist before "
            f"narration can be produced ({exc})"
        ) from exc
    scenes = getattr(script, "SCENES", None)
    if not scenes:
        raise NarrationError(f"{HERE / 'script.py'} defines no non-empty SCENES list")
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for i, scene in enumerate(scenes):
        scene_id = str(getattr(scene, "id", "") or f"scene-{i + 1:02d}")
        narration = str(getattr(scene, "narration", "") or "").strip()
        if not narration:
            raise NarrationError(f"scene {scene_id!r} has empty narration")
        if scene_id in seen:
            raise NarrationError(f"duplicate scene id {scene_id!r} in SCENES")
        seen.add(scene_id)
        out.append((scene_id, " ".join(narration.split())))
    return out


# --------------------------------------------------------------------------- synthesis


def cache_key(text: str, voice: str, rate: str) -> str:
    digest = hashlib.sha256()
    digest.update(text.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(voice.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(rate.encode("utf-8"))
    return digest.hexdigest()[:24]


def _safe_str(exc: BaseException) -> str:
    """``str(exc)``, but never raising - some aiohttp errors format themselves badly, and a
    failure inside the error message would hide the failure it is reporting."""
    try:
        return str(exc) or repr(exc.args)
    except Exception:  # noqa: BLE001 - reporting must not be able to fail
        return f"<{type(exc).__name__} whose str() raised>"


async def _synthesise(text: str, dest: Path, voice: str, rate: str) -> None:
    import edge_tts

    communicate = edge_tts.Communicate(text, voice, rate=rate)
    tmp = dest.with_suffix(".part")
    written = 0
    try:
        with tmp.open("wb") as handle:
            async for chunk in communicate.stream():
                if chunk.get("type") == "audio" and chunk.get("data"):
                    handle.write(chunk["data"])
                    written += len(chunk["data"])
        if written == 0:
            raise TransientTTSError("the speech endpoint sent no audio for this scene")
        tmp.replace(dest)
    finally:
        tmp.unlink(missing_ok=True)


def _accept_duration(got: float, expected: float, takes: Sequence[float], *,
                     what: str, attempt: int) -> bool:
    """Is this take a real reading of the text, or a stream that was cut short?

    ``written == 0`` only catches the case where the endpoint sends nothing at all. The
    failure that actually bites is a socket closed *part way* through a scene: a perfectly
    valid MP3 that stops mid-sentence. Nothing downstream notices — ``probe_seconds``
    returns a real number, the SRT is generated against it, and every visual cue in that
    scene is timed to a fraction of the wrong length.

    A long take is never suspicious (the voice slows for numbers and abbreviations), so only
    the short side is checked, and a length two independent takes agree on is the voice's
    real opinion of the text rather than a truncation.
    """
    if got >= expected * SHORT_TAKE_RATIO:
        return True
    for earlier in takes[:-1]:
        if earlier > 0 and abs(got - earlier) <= earlier * STABLE_TAKE_RATIO:
            logger.warning(
                "%s: %.1fs is short for %.1fs of text, but two takes agree within %.0f%% - "
                "accepting it as a terse reading, not a truncated stream",
                what, got, expected, STABLE_TAKE_RATIO * 100,
            )
            return True
    logger.warning(
        "%s: take %d came back %.1fs, but the text should take about %.1fs (%.0f%%) - "
        "the speech stream looks truncated; re-synthesising",
        what, attempt, got, expected, 100 * got / expected if expected else 0.0,
    )
    return False


def synthesise(text: str, dest: Path, *, voice: str, rate: str, label: str = "") -> None:
    """Run edge-tts for one scene, retrying transient hiccups and explaining real failures.

    The public speech endpoint intermittently closes a socket or answers with no audio at
    all (``NoAudioReceived``); that is a hiccup, not a broken setup, so it is retried with
    a short backoff before the run is allowed to fail.
    """
    try:
        import edge_tts  # noqa: F401
    except ImportError as exc:
        raise NarrationError(
            "edge-tts is not installed. Install it with:  python -m pip install edge-tts"
        ) from exc

    what = label or dest.name
    expected = len(text.split()) * SECONDS_PER_WORD
    takes: list[float] = []
    last: BaseException | None = None
    for attempt in range(1, SYNTH_ATTEMPTS + 1):
        try:
            asyncio.run(asyncio.wait_for(_synthesise(text, dest, voice, rate), SYNTH_TIMEOUT))
            got = probe_seconds(dest)
            takes.append(got)
            if _accept_duration(got, expected, takes, what=what, attempt=attempt):
                return
            raise TransientTTSError(
                f"the take is {got:.1f}s but {len(text.split())} words should take about "
                f"{expected:.1f}s - the speech stream was cut short"
            )
        except NarrationError:
            raise
        except Exception as exc:  # TimeoutError, aiohttp, DNS and WS errors all land here
            last = exc
            if attempt < SYNTH_ATTEMPTS:
                delay = SYNTH_BACKOFF * attempt
                logger.warning(
                    "%s: edge-tts attempt %d/%d failed (%s: %s); retrying in %.1fs",
                    what, attempt, SYNTH_ATTEMPTS, type(exc).__name__, _safe_str(exc), delay,
                )
                time.sleep(delay)

    assert last is not None
    if isinstance(last, TransientTTSError) and takes:
        raise NarrationError(
            f"{what}: every one of {SYNTH_ATTEMPTS} takes came back short - "
            f"{', '.join(f'{t:.1f}s' for t in takes)} against about {expected:.1f}s of text. "
            "Microsoft's speech endpoint is cutting the stream mid-scene. Wait a minute and "
            "re-run (already-synthesised scenes are cached, so only this scene is retried). "
            "If the voice really does read this text that quickly, raise SHORT_TAKE_RATIO."
        ) from last
    if isinstance(last, TimeoutError):
        raise NarrationError(
            f"{what}: edge-tts timed out after {SYNTH_TIMEOUT:.0f}s on every one of "
            f"{SYNTH_ATTEMPTS} attempts. The Microsoft speech endpoint is slow or "
            "unreachable - check your internet connection and any proxy or firewall, then "
            "re-run (already-synthesised scenes are cached, so a re-run is cheap)."
        ) from last
    raise NarrationError(
        f"{what}: edge-tts failed {SYNTH_ATTEMPTS} times - "
        f"{type(last).__name__}: {_safe_str(last)}\n"
        "edge-tts needs a working internet connection to Microsoft's speech endpoint. "
        "Check that you are online and that no proxy or firewall blocks "
        "speech.platform.bing.com, then re-run - already-synthesised scenes are cached, "
        "so only the scenes that failed are retried."
    ) from last


def probe_seconds(path: Path) -> float:
    """Duration of an audio file, in seconds, via ffprobe."""
    cmd = [
        "ffprobe", "-v", "error",
        "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1",
        str(path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=FFPROBE_TIMEOUT, check=False)
    except FileNotFoundError as exc:
        raise NarrationError(
            "ffprobe was not found on PATH - install the ffmpeg full build and re-run."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise NarrationError(f"ffprobe timed out reading {path}") from exc
    raw = (proc.stdout or "").strip()
    if proc.returncode != 0 or not raw:
        raise NarrationError(
            f"ffprobe could not read a duration from {path} "
            f"(exit {proc.returncode}): {(proc.stderr or '').strip()[:300]}"
        )
    try:
        seconds = float(raw)
    except ValueError as exc:
        raise NarrationError(f"ffprobe returned a non-numeric duration {raw!r} for {path}") from exc
    if seconds <= 0:
        raise NarrationError(f"{path} has a duration of {seconds}s - synthesis produced silence")
    return seconds


# --------------------------------------------------------------------------- pauses

#: silencedetect thresholds: quiet enough to catch a breath between sentences, long enough
#: not to fire on the gap inside "192 dot 168 dot 1 dot 142".
SILENCE_DB: Final[int] = -38
SILENCE_MIN: Final[float] = 0.18
#: How far a proportional cue boundary may be dragged onto a real pause. It has to be wide
#: enough to cover the worst case the character-count model gets wrong: in scene 6 the
#: sentence ending "...has Telnet open on port twenty-three" spells out an IP address and
#: runs 2.2 s longer than its length predicts, which is exactly the cue that was showing two
#: seconds early. Boundaries stay in order and at least 0.30 s apart, so a window this wide
#: cannot make two cues cross.
SNAP_WINDOW: Final[float] = 2.6

_SILENCE_RE = re.compile(r"silence_(start|end):\s*(-?[\d.]+)")


def detect_pauses(path: Path) -> list[float]:
    """Midpoints of the silences inside one scene's narration, in seconds from its start.

    Cue boundaries are placed by character count, which assumes every character takes the
    same time to say. Spelled-out numbers break that badly: "192 dot 168 dot 1 dot 142" is
    26 characters and takes about three seconds, so in scene 6 the cue after it was shown
    two full seconds before it was spoken. Snapping each boundary onto the nearest real
    breath fixes that without needing to model how long any particular token takes.
    """
    cmd = [
        "ffmpeg", "-v", "info", "-nostdin", "-i", str(path),
        "-af", f"silencedetect=n={SILENCE_DB}dB:d={SILENCE_MIN}", "-f", "null", "-",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=FFPROBE_TIMEOUT, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.warning("silencedetect on %s failed (%s); cue timing stays proportional",
                       path.name, type(exc).__name__)
        return []
    starts: list[float] = []
    pauses: list[float] = []
    for kind, value in _SILENCE_RE.findall(proc.stderr or ""):
        if kind == "start":
            starts.append(float(value))
        elif starts:
            pauses.append((starts.pop() + float(value)) / 2.0)
    return sorted(pauses)


def snap_to_pauses(boundaries: list[float], pauses: Sequence[float], span: float) -> list[float]:
    """Drag each boundary onto the nearest pause within SNAP_WINDOW, keeping them ordered.

    A pause belongs to exactly one boundary: the one whose proportional estimate is closest
    to it. Without that rule a boundary could reach past its neighbour and take the pause
    that neighbour was going to land on - which is how cue #3 of the v2 SRT ended up 2.9 s
    late, printing nine words in 1.54 s (5.8 words/s against a 2.9 w/s average) while the
    sentence it was split from stretched to 1.4 w/s.
    """
    if not pauses:
        return boundaries

    def owner(pause: float) -> int:
        return min(range(len(boundaries)), key=lambda i: abs(boundaries[i] - pause))

    claimed: dict[int, list[float]] = {}
    for pause in pauses:
        claimed.setdefault(owner(pause), []).append(pause)

    out: list[float] = []
    floor = 0.0
    for i, want in enumerate(boundaries):
        ceiling = boundaries[i + 1] if i + 1 < len(boundaries) else span
        best, best_gap = want, SNAP_WINDOW
        for pause in claimed.get(i, ()):
            gap = abs(pause - want)
            if gap < best_gap and floor + 0.30 <= pause <= ceiling + SNAP_WINDOW:
                best, best_gap = pause, gap
        best = max(best, floor + 0.30)
        out.append(best)
        floor = best
    return out


# --------------------------------------------------------------------------- subtitles

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])[\"')\]]*\s+")
_ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "no.", "fig.", "approx.", "mr.", "mrs.", "dr.", "st.")


def split_sentences(text: str) -> list[str]:
    """Sentence-ish chunks suitable for one subtitle each.

    Splits on terminal punctuation followed by whitespace (so ``192.168.1.1`` and ``8787``
    survive), re-joins common abbreviations, then merges anything too short to read.
    """
    raw = [part.strip() for part in _SENTENCE_SPLIT.split(text.strip()) if part.strip()]
    if not raw:
        return []

    # Re-join "e.g. this" style splits.
    joined: list[str] = []
    for part in raw:
        if joined and joined[-1].lower().endswith(_ABBREVIATIONS):
            joined[-1] = f"{joined[-1]} {part}"
        else:
            joined.append(part)

    # Merge fragments too short to be readable as their own cue.
    merged: list[str] = []
    for part in joined:
        too_short = len(part) < MIN_CUE_CHARS or (merged and len(merged[-1]) < MIN_CUE_CHARS)
        if merged and too_short and len(merged[-1]) + len(part) + 1 <= MAX_CUE_CHARS:
            merged[-1] = f"{merged[-1]} {part}"
        else:
            merged.append(part)

    out: list[str] = []
    for part in merged:
        out.extend(_split_long(part))
    return out


def split_sentences_grouped(text: str) -> list[list[str]]:
    """:func:`split_sentences`, but keeping the parts of one sentence together.

    A long sentence is broken at a comma into two cues, and the two halves are *not*
    independent: the speaker does not breathe at that comma the way they breathe at a full
    stop. Cue timing therefore snaps only the sentence boundaries onto real pauses and
    divides each sentence's own span between its parts by character length.
    """
    flat = split_sentences(text)
    if not flat:
        return []
    # Walk the sentence-level split again and collect the pieces _split_long made from each.
    regrouped: list[list[str]] = []
    cursor = 0
    for sentence in _sentence_level(text):
        pieces = _split_long(sentence)
        take = flat[cursor : cursor + len(pieces)]
        if take != pieces:  # a merge reshaped things; fall back to one cue per group
            return [[part] for part in flat]
        regrouped.append(list(pieces))
        cursor += len(pieces)
    if cursor != len(flat):
        return [[part] for part in flat]
    return regrouped


def _sentence_level(text: str) -> list[str]:
    """The sentence split :func:`split_sentences` does, *before* long ones are broken up."""
    raw = [part.strip() for part in _SENTENCE_SPLIT.split(text.strip()) if part.strip()]
    joined: list[str] = []
    for part in raw:
        if joined and joined[-1].lower().endswith(_ABBREVIATIONS):
            joined[-1] = f"{joined[-1]} {part}"
        else:
            joined.append(part)
    merged: list[str] = []
    for part in joined:
        too_short = len(part) < MIN_CUE_CHARS or (merged and len(merged[-1]) < MIN_CUE_CHARS)
        if merged and too_short and len(merged[-1]) + len(part) + 1 <= MAX_CUE_CHARS:
            merged[-1] = f"{merged[-1]} {part}"
        else:
            merged.append(part)
    return merged


_CLAUSE_BREAK = re.compile(r"(?<=[,;:-])\s+")


def _split_long(sentence: str) -> list[str]:
    """Break one over-long sentence at the clause boundary nearest its middle."""
    if len(sentence) <= SPLIT_CUE_CHARS:
        return [sentence]
    pieces = _CLAUSE_BREAK.split(sentence)
    if len(pieces) < 2:
        return [sentence]
    middle = len(sentence) / 2
    best, best_gap, cursor = 1, None, 0
    for i, piece in enumerate(pieces[:-1], start=1):
        cursor += len(piece) + 1
        gap = abs(cursor - middle)
        if best_gap is None or gap < best_gap:
            best, best_gap = i, gap
    head = " ".join(pieces[:best]).strip()
    tail = " ".join(pieces[best:]).strip()
    if not head or not tail:
        return [sentence]
    return _split_long(head) + _split_long(tail)


def wrap_cue(text: str) -> str:
    """Wrap a cue to at most :data:`SRT_MAX_LINES` lines of ~:data:`SRT_LINE_CHARS` chars."""
    words = text.split()
    if not words:
        return text
    target = max(SRT_LINE_CHARS, -(-len(text) // SRT_MAX_LINES))
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if current and len(candidate) > target and len(lines) < SRT_MAX_LINES - 1:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return "\n".join(lines)


def cues_for_scene(
    text: str, *, start: float, seconds: float, pauses: Sequence[float] = ()
) -> list[Cue]:
    """One cue per sentence: a share of ``seconds`` by character length, snapped to breaths.

    ``pauses`` are silence midpoints measured on the scene's own MP3, in seconds from the
    first sample. Character length gets each boundary roughly right; the snap puts it on the
    breath the speaker actually took, which is what a viewer hears the sentence end on.
    """
    groups = split_sentences_grouped(text)
    sentences = [part for group in groups for part in group]
    if not sentences:
        return []
    total = float(sum(max(len(s), 1) for s in sentences))

    # Snap only the *sentence* boundaries: those are where the speaker actually breathes.
    group_weights = [sum(max(len(p), 1) for p in g) for g in groups]
    group_edges: list[float] = []
    running = 0.0
    for weight in group_weights[:-1]:
        running += seconds * (weight / total)
        group_edges.append(running)
    group_edges = snap_to_pauses(group_edges, pauses, seconds)

    # Then divide each sentence's own span between the clauses it was split into, by
    # character length. A comma split has no pause of its own to find, and letting one half
    # go looking for one is what produced a 5.8 words-per-second cue next to a 1.4 one.
    edges: list[float] = [0.0]
    bounds = [0.0, *group_edges, seconds]
    for gi, group in enumerate(groups):
        g0, g1 = bounds[gi], bounds[gi + 1]
        inner_total = float(sum(max(len(p), 1) for p in group))
        run = g0
        for part in group[:-1]:
            run += (g1 - g0) * (max(len(part), 1) / inner_total)
            edges.append(run)
        edges.append(g1)
    return [
        Cue(
            text=sentence,
            start=start + edges[i],
            end=start + max(edges[i + 1], edges[i] + 0.30),
        )
        for i, sentence in enumerate(sentences)
    ]


def srt_timestamp(seconds: float) -> str:
    if seconds < 0:
        seconds = 0.0
    millis = int(round(seconds * 1000))
    hours, millis = divmod(millis, 3_600_000)
    minutes, millis = divmod(millis, 60_000)
    secs, millis = divmod(millis, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"


def build_srt(scenes: list[SceneAudio]) -> str:
    blocks: list[str] = []
    n = 0
    for scene in scenes:
        for cue in scene.cues:
            n += 1
            blocks.append(
                f"{n}\n{srt_timestamp(cue.start)} --> {srt_timestamp(cue.end)}\n{wrap_cue(cue.text)}\n"
            )
    return "\n".join(blocks)


# --------------------------------------------------------------------------- driver


def narrate(
    *,
    voice: str = VOICE,
    rate: str = RATE,
    force: bool = False,
    only: str | None = None,
) -> list[SceneAudio]:
    """Synthesise (or reuse) every scene's audio and write timings.json + the SRT."""
    scenes = load_scenes()
    if only:
        wanted = {s.strip() for s in only.split(",") if s.strip()}
        unknown = wanted - {sid for sid, _ in scenes}
        if unknown:
            raise NarrationError(f"--only names unknown scene ids: {', '.join(sorted(unknown))}")
    else:
        wanted = None

    AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    results: list[SceneAudio] = []
    for index, (scene_id, text) in enumerate(scenes, start=1):
        dest = AUDIO_DIR / f"scene_{index:02d}.mp3"
        cached = CACHE_DIR / f"{cache_key(text, voice, rate)}.mp3"
        skipped = wanted is not None and scene_id not in wanted

        if skipped and dest.exists():
            # --only left this scene alone; say so loudly if its words have since changed,
            # or the timeline would be built from audio that no longer matches the script.
            state = "kept" if cached.exists() else "KEPT (STALE)"
        elif cached.exists() and not force:
            if not dest.exists() or dest.stat().st_size != cached.stat().st_size:
                shutil.copyfile(cached, dest)
            state = "cached"
        else:
            synthesise(text, cached, voice=voice, rate=rate, label=scene_id)
            shutil.copyfile(cached, dest)
            state = "synthesised"

        if not dest.exists():
            raise NarrationError(
                f"{scene_id}: {dest} is missing - run without --only first to build every scene"
            )
        seconds = probe_seconds(dest)
        results.append(SceneAudio(index=index, scene_id=scene_id, text=text, path=dest, seconds=seconds))
        print(
            f"  [{index:02d}/{len(scenes)}] {scene_id:<22} {state:<12} "
            f"{seconds:6.2f}s  {len(text):4d} chars  {dest.name}",
            flush=True,
        )

    cursor = 0.0
    for scene in results:
        scene.start = cursor
        scene.cues = cues_for_scene(
            scene.text,
            start=cursor + LEAD_IN,
            seconds=scene.seconds,
            pauses=detect_pauses(scene.path),
        )
        cursor = scene.end

    total = cursor + END_ROOM_TONE
    speech = sum(s.seconds for s in results)

    TIMINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {scene.scene_id: scene.as_json() for scene in results}
    TIMINGS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    SRT_PATH.write_text(build_srt(results), encoding="utf-8")

    print(
        f"\n  narration {speech / 60:.2f} min speech | timeline {total / 60:.2f} min "
        f"({total:.1f}s incl. {END_ROOM_TONE}s room tone)"
    )
    print(f"  {TIMINGS_PATH}")
    print(f"  {SRT_PATH}  ({sum(len(s.cues) for s in results)} cues)")
    # CONTRACT_V2 targets the *finished film* at 11-14 minutes, and the film is this
    # timeline: every scene is exactly as long as its narration plus the lead-in and tail
    # pad, so `total` is the number to judge. v1's 6.5-8 minute figure was for a 14-scene
    # script with no Lens act and is no longer the bar.
    if not FILM_TARGET_MIN * 60 <= total <= FILM_TARGET_MAX * 60:
        print(
            f"  NOTE: CONTRACT_V2 asks for a {FILM_TARGET_MIN:g}-{FILM_TARGET_MAX:g} minute "
            f"film; this timeline is {total / 60:.2f} min ({speech / 60:.2f} min of speech).",
            file=sys.stderr,
        )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthesise the Home SOC walkthrough narration.")
    parser.add_argument("--force", action="store_true", help="re-synthesise even when cached")
    parser.add_argument("--only", metavar="ID[,ID]", help="only (re)synthesise these scene ids")
    parser.add_argument("--voice", default=VOICE, help=f"edge-tts voice (default {VOICE})")
    # argparse %-expands help strings, so the literal '%' in a rate like "-4%" needs doubling.
    parser.add_argument("--rate", default=RATE, help=f"edge-tts rate (default {RATE.replace('%', '%%')})")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    print(f"narrate: voice={args.voice} rate={args.rate}")
    try:
        narrate(voice=args.voice, rate=args.rate, force=args.force, only=args.only)
    except NarrationError as exc:
        print(f"\nnarrate: FAILED\n{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
