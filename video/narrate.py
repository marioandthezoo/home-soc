"""Narration stage of the Home SOC walkthrough films.

Turns every ``Scene.narration`` string of the selected film into one WAV per scene with
edge-tts (Microsoft's neural voices), and writes the artefacts the rest of the pipeline
consumes. Two films share this module (``--script``):

``everyday`` (the default)
    ``video/script_everyday.py`` - "Meet the Household", the ~10 minute film for everyday
    viewers (CONTRACT_EVERYDAY.md). Its build lives in ``video/build/everyday/``.
``technical``
    ``video/script.py`` - the 16 minute technical cut (CONTRACT.md, CONTRACT_V2.md). Its build
    lives in ``video/build/`` exactly where it always has.

Beats
-----
The everyday script times its jokes with marks inside the narration::

    The printer counts. [beat] The printer would like it noted [beat] that it has always counted.

``[beat]`` is a 0.6 s pause and ``[beat N]`` is an N second one. The text between marks is
synthesised as *separate* edge-tts segments (each cached by ``sha256(text | voice | rate)``),
every segment's own leading and trailing silence is measured and trimmed, and the segments
are joined with real digital silence so that **the gap a listener hears between the last
sound of one segment and the first sound of the next is the beat's length** - not the beat
plus whatever padding the speech endpoint happened to add. A mark is never spoken and never
subtitled. A scene without marks is one segment, so the technical cut's cache stays valid.

Artefacts (paths are per film)
------------------------------
``<build>/audio/scene_NN.wav``
    The assembled narration of scene NN (24 kHz mono, lossless, so no encoder delay can move a
    beat or a cue).
``<build>/timings.json``
    ``{scene_id: {"audio", "seconds", "index", "lead_in", "pad", "start", "end", "duration",
    "sentences", "segments", "beats"}}`` - CONTRACT.md section 3's shape plus the layout.
``<build>/beats.json``
    ``{scene_id: {"seconds", "segments": [...], "beats": [...], "words": [...]}}`` - where every
    beat and every spoken line sits, in seconds from the start of the scene's audio **and** as
    ``at`` fractions (compose fires an action at ``LEAD_IN + at * seconds``). Read it through
    :func:`beat_at`, :func:`line_at` and :func:`phrase_at`.
``<film srt>``
    One cue per sentence (a long sentence is split at a clause). Cues are timed from the real
    segment boundaries and, where the endpoint reported them, from its word boundaries; a cue
    never spans a beat, so a punchline is never on screen before it is said.

Timeline model (shared with ``render.py`` via the extra keys above)::

    scene_duration = LEAD_IN + speech + TAIL_PAD
    scene_start[0] = 0
    scene_start[i] = scene_start[i-1] + scene_duration[i-1]
    total          = sum(scene_duration) + END_ROOM_TONE

Usage::

    python video/narrate.py                        # the everyday film
    python video/narrate.py --script technical     # the technical cut
    python video/narrate.py --force                # ignore the cache
    python video/narrate.py --only 06-tuesday-telnet
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import wave
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final

HERE: Final[Path] = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # so `python video/narrate.py` finds the script modules next door
    sys.path.insert(0, str(HERE))

BUILD_ROOT: Final[Path] = HERE / "build"
OUT_DIR: Final[Path] = HERE / "out"
#: One segment cache for every film: a segment is keyed by its words, voice and rate only.
CACHE_DIR: Final[Path] = BUILD_ROOT / "audio" / "cache"

VOICE: Final[str] = "en-US-AndrewMultilingualNeural"
RATE: Final[str] = "-4%"

#: Silence before the voice at the start of every scene (CONTRACT §6).
LEAD_IN: Final[float] = 0.30
#: Silence after the voice, before the scene hands over to the next one.
TAIL_PAD: Final[float] = 0.40
#: Room tone at the very end of the film (CONTRACT §6). Must match compose.END_ROOM_TONE.
END_ROOM_TONE: Final[float] = 0.25

# --------------------------------------------------------------------------- beats

#: ``[beat]`` and ``[beat 1.2]`` (also ``[Beat 2s]``). Anything else in brackets is an error:
#: the voice would read it out.
BEAT_RE: Final[re.Pattern[str]] = re.compile(
    r"\[\s*beat(?:\s+(\d+(?:\.\d+)?)\s*s?)?\s*\]", re.IGNORECASE
)
_ANY_MARK_RE: Final[re.Pattern[str]] = re.compile(r"\[[^\]]*\]")
#: A bare ``[beat]``.
BEAT_DEFAULT: Final[float] = 0.6
#: No beat may be longer than this - a typo like ``[beat 12]`` would stall the film.
BEAT_MAX: Final[float] = 4.0

#: Speech onset/offset detection on the decoded PCM: 10 ms windows, and a window counts as
#: speech above this level. -50 dBFS sits under every consonant tail this voice produces and
#: well above the endpoint's digital-silence padding.
ONSET_DB: Final[float] = -50.0
WINDOW_S: Final[float] = 0.010
#: What survives of a segment's own edges after trimming: enough to keep a soft onset and a
#: breathy release intact, and counted *inside* the beat so the gap stays exact.
HEAD_KEEP: Final[float] = 0.03
TAIL_KEEP: Final[float] = 0.06
#: The scene's own silence before the first and after the last word (on top of LEAD_IN and
#: TAIL_PAD). edge-tts used to leave ~0.15 s and ~0.33 s; these keep the old feel.
SCENE_HEAD: Final[float] = 0.10
SCENE_TAIL: Final[float] = 0.30

#: A beat's measured gap may differ from its designed length by at most this much before the
#: run says so (it can only differ when a segment's edge could not be trimmed).
BEAT_TOLERANCE: Final[float] = 0.05

# --------------------------------------------------------------------------- subtitles

#: Sentences shorter than this are merged into their neighbour so no subtitle flashes past
#: (inside one segment only: a merge never crosses a beat).
MIN_CUE_CHARS: Final[int] = 28
#: Subtitle line wrapping: two lines of at most 42 characters, the broadcast norm. Three-line
#: cues sat over the film's own lower third (the scene caption and the sidebar's "Blocking:
#: running"), and the old wrapper dumped whatever did not fit into its last line (47 chars).
SRT_LINE_CHARS: Final[int] = 42
SRT_MAX_LINES: Final[int] = 2
#: ...but never merge past this, or a cue no longer fits two lines.
MAX_CUE_CHARS: Final[int] = SRT_LINE_CHARS * SRT_MAX_LINES
#: A sentence that cannot be set in two such lines is broken at the clause boundary nearest
#: its middle (or, with no clause boundary, at the word boundary nearest its middle).
SPLIT_CUE_CHARS: Final[int] = SRT_LINE_CHARS * SRT_MAX_LINES
#: A cue stays up this long after its last word at most (it lingers through a beat so the
#: set-up is still readable while the pause lands), never into the next cue.
CUE_LINGER: Final[float] = 0.70
#: ...and is on screen at least this long, when the next cue allows it.
MIN_CUE_SECONDS: Final[float] = 0.90
#: Clear air between two cues.
CUE_GAP: Final[float] = 0.04

FFPROBE_TIMEOUT: Final[int] = 30
#: Seconds of speech per word for this voice at this rate, measured across all 20 scenes of
#: the v2 script (1,919 words, 794 s). Only ever used to *doubt* a take, never to time one.
SECONDS_PER_WORD: Final[float] = 0.414
#: The same for a one- or two-sentence segment between beats, which has no breaths in it
#: (measured: ten words of a question in 2.5 s).
SEGMENT_SECONDS_PER_WORD: Final[float] = 0.30
#: A finished take shorter than this fraction of the length its word count predicts is
#: treated as a truncated stream rather than a fast reading (see :func:`_accept_duration`).
SHORT_TAKE_RATIO: Final[float] = 0.65
#: Two takes within this fraction of each other are the voice's real opinion of the text.
STABLE_TAKE_RATIO: Final[float] = 0.05

SYNTH_TIMEOUT: Final[float] = 120.0
#: The public speech endpoint drops the occasional connection; retry before giving up.
SYNTH_ATTEMPTS: Final[int] = 3
SYNTH_BACKOFF: Final[float] = 2.0

logger = logging.getLogger("homesoc.video.narrate")


class NarrationError(RuntimeError):
    """Anything that stops narration being produced, with an actionable message."""


class TransientTTSError(RuntimeError):
    """A speech-endpoint hiccup that is worth retrying rather than failing the run."""


# --------------------------------------------------------------------------- film selection


@dataclass(frozen=True)
class Film:
    """Everything that differs between the two films. ``render.py`` and ``capture.py`` use it too."""

    name: str
    script_module: str
    slides_module: str
    build: Path
    out_mp4: Path
    out_srt: Path
    #: Target length of the finished film, in minutes. A note, never a failure.
    target_min: float
    target_max: float
    #: ``prefers-color-scheme`` the capture browser reports. "light" is the dashboard's Stone &
    #: Sage day theme; the technical cut was shot in "dark".
    color_scheme: str
    #: compose.py's canvas, caption and cursor palette (``compose.set_look``).
    look: str
    #: A fixture film (``--script <name>`` for a ``script_<name>`` module on sys.path) renders
    #: under build/films/<name>/ and never writes into video/out/.
    fixture: bool = False

    @property
    def audio_dir(self) -> Path:
        return self.build / "audio"

    @property
    def timings(self) -> Path:
        return self.build / "timings.json"

    @property
    def beats(self) -> Path:
        return self.build / "beats.json"


FILMS: Final[dict[str, Film]] = {
    "everyday": Film(
        name="everyday",
        script_module="script_everyday",
        slides_module="slides_everyday",
        build=BUILD_ROOT / "everyday",
        out_mp4=OUT_DIR / "HomeSOC-walkthrough.mp4",
        out_srt=OUT_DIR / "HomeSOC-walkthrough.srt",
        target_min=9.0,
        target_max=11.0,
        color_scheme="light",
        look="stone",
    ),
    "technical": Film(
        name="technical",
        script_module="script",
        slides_module="slides",
        build=BUILD_ROOT,
        out_mp4=OUT_DIR / "HomeSOC-walkthrough-technical.mp4",
        out_srt=OUT_DIR / "HomeSOC-walkthrough-technical.srt",
        target_min=15.0,
        target_max=17.0,
        color_scheme="dark",
        look="classic",
    ),
}
DEFAULT_FILM: Final[str] = "everyday"
#: Set by every entry point, and inherited by the child processes render.py starts, so a
#: script module's :func:`beat_at` reads the beats of the film being rendered.
FILM_ENV: Final[str] = "HOMESOC_VIDEO_FILM"

_FIXTURE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,40}$")


def film_profile(name: str | None = None) -> Film:
    """The :class:`Film` called ``name`` (default: ``$HOMESOC_VIDEO_FILM``, else everyday).

    Any other lower-case name is a *fixture* film: its script is the module
    ``script_<name>`` (found on ``sys.path``/``PYTHONPATH``), it borrows the everyday film's
    slides and look, and everything it writes lands under ``build/films/<name>/`` - it can
    never overwrite a real film. The pipeline's own tests use this.
    """
    key = (name or os.environ.get(FILM_ENV) or DEFAULT_FILM).strip().lower()
    if key == "technical" and (HERE / "script_technical.py").is_file():
        # The technical cut's scenes may live in script_technical.py (script.py keeping the
        # shared shot/action classes); fall back to script.py, where they always were.
        return replace(FILMS[key], script_module="script_technical")
    if key in FILMS:
        return FILMS[key]
    if not _FIXTURE_NAME.match(key):
        raise NarrationError(
            f"unknown film {key!r}: use one of {', '.join(FILMS)}, or a fixture name "
            "(lower-case letters, digits, underscores) whose script_<name>.py is importable"
        )
    base = BUILD_ROOT / "films" / key
    return Film(
        name=key,
        script_module=f"script_{key}",
        slides_module=FILMS["everyday"].slides_module,
        build=base,
        out_mp4=base / "out" / f"HomeSOC-{key}.mp4",
        out_srt=base / "out" / f"HomeSOC-{key}.srt",
        target_min=0.0,
        target_max=1e9,
        color_scheme="light",
        look="stone",
        fixture=True,
    )


def select_film(name: str | None) -> Film:
    """:func:`film_profile`, and export it so child processes and script modules agree."""
    film = film_profile(name)
    os.environ[FILM_ENV] = film.name
    return film


def import_script(film: Film) -> Any:
    """The film's scene-script module (``SCENES`` and friends)."""
    import importlib

    try:
        return importlib.import_module(film.script_module)
    except ImportError as exc:
        raise NarrationError(
            f"cannot import {film.script_module}.py for the {film.name} film - the scene "
            f"script must exist before it can be narrated ({exc})"
        ) from exc


# --------------------------------------------------------------------------- previous films

#: Where a replaced film goes: ``<the film's out dir>/archive/``.
ARCHIVE_NAME: Final[str] = "archive"


def _deliverables_stamp(film: Film) -> Path:
    return film.build / "deliverables.json"


def record_deliverable(film: Film, path: Path) -> None:
    """Remember that this pipeline wrote ``path`` for ``film`` (so it is not archived next time)."""
    stamp = _deliverables_stamp(film)
    try:
        data = json.loads(stamp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}
    st = path.stat()
    data[path.name] = {"size": st.st_size, "mtime_ns": st.st_mtime_ns}
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def archive_previous(film: Film) -> list[Path]:
    """Move any ``out/<film stem>.*`` this film's pipeline did not write into ``out/archive/``.

    The everyday film takes over ``HomeSOC-walkthrough.mp4`` / ``.srt``, which until now held
    the technical cut. A previous film is never deleted: before the first everyday render the
    old files are moved to ``out/archive/HomeSOC-walkthrough-<date>.<ext>`` (the date is the
    file's own), and every later render only replaces files it wrote itself.
    """
    if film.fixture:
        return []
    try:
        ours = json.loads(_deliverables_stamp(film).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        ours = {}
    moved: list[Path] = []
    stem = film.out_mp4.stem
    archive = film.out_mp4.parent / ARCHIVE_NAME
    for path in sorted(film.out_mp4.parent.glob(f"{stem}.*")):
        if not path.is_file():
            continue
        st = path.stat()
        mine = ours.get(path.name) or {}
        if mine.get("size") == st.st_size and mine.get("mtime_ns") == st.st_mtime_ns:
            continue
        archive.mkdir(parents=True, exist_ok=True)
        date = time.strftime("%Y-%m-%d", time.localtime(st.st_mtime))
        dest = archive / f"{stem}-{date}{path.suffix}"
        n = 2
        while dest.exists():
            dest = archive / f"{stem}-{date}-{n}{path.suffix}"
            n += 1
        path.replace(dest)
        moved.append(dest)
        print(f"  archived the previous {path.name} -> {dest}", flush=True)
    return moved


# --------------------------------------------------------------------------- data


@dataclass(frozen=True)
class Cue:
    """One subtitle: absolute seconds on the finished film's timeline."""

    text: str
    start: float
    end: float


@dataclass
class Segment:
    """One stretch of speech between beats, as placed in its scene's audio."""

    text: str
    key: str
    start: float = 0.0      # speech onset, seconds from the start of the scene audio
    end: float = 0.0        # speech offset
    words: list[dict[str, Any]] = field(default_factory=list)   # {"text","start","end"}
    pauses: list[float] = field(default_factory=list)            # breath midpoints inside it
    state: str = ""


@dataclass
class Beat:
    """A designed pause, and where it really landed."""

    n: int
    seconds: float          # what the script asked for
    start: float = 0.0      # last sound before it (0 for a beat that opens the scene)
    end: float = 0.0        # first sound after it (the scene's end for a closing beat)
    after: str = ""         # the words just before it
    before: str = ""        # the words just after it

    @property
    def measured(self) -> float:
        return self.end - self.start


@dataclass
class SceneAudio:
    """One scene's assembled narration and where it sits on the timeline."""

    index: int
    scene_id: str
    text: str               # the narration as written, marks included
    path: Path
    seconds: float
    segments: list[Segment] = field(default_factory=list)
    beats: list[Beat] = field(default_factory=list)
    start: float = 0.0
    cues: list[Cue] = field(default_factory=list)
    state: str = ""

    @property
    def spoken(self) -> str:
        return strip_marks(self.text)

    @property
    def duration(self) -> float:
        """Wall-clock length of the scene, padding included."""
        return LEAD_IN + self.seconds + TAIL_PAD

    @property
    def end(self) -> float:
        return self.start + self.duration

    def frac(self, t: float) -> float:
        """Seconds from the start of this scene's audio -> compose's ``at`` fraction."""
        return round(max(0.0, min(1.0, t / self.seconds)) if self.seconds > 0 else 0.0, 5)

    def layout(self) -> dict[str, Any]:
        return {
            "seconds": round(self.seconds, 3),
            "segments": [
                {
                    "n": i, "text": s.text, "start": round(s.start, 3), "end": round(s.end, 3),
                    "at_start": self.frac(s.start), "at_end": self.frac(s.end),
                }
                for i, s in enumerate(self.segments)
            ],
            "beats": [
                {
                    "n": b.n, "seconds": b.seconds, "start": round(b.start, 3),
                    "end": round(b.end, 3), "measured": round(b.measured, 3),
                    "at_start": self.frac(b.start), "at_end": self.frac(b.end),
                    "after": b.after, "before": b.before,
                }
                for b in self.beats
            ],
            "words": [
                {"text": w["text"], "start": round(w["start"], 3), "end": round(w["end"], 3),
                 "at": self.frac(w["start"])}
                for s in self.segments for w in s.words
            ],
        }

    def as_json(self) -> dict[str, Any]:
        layout = self.layout()
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
            "text_hash": text_hash(self.text),
            "segments": layout["segments"],
            "beats": layout["beats"],
        }


# --------------------------------------------------------------------------- beat parsing


def strip_marks(text: str) -> str:
    """The narration as spoken and subtitled: no beat marks, tidy spacing."""
    out = BEAT_RE.sub(" ", text)
    out = " ".join(out.split())
    return re.sub(r"\s+([,.;:!?])", r"\1", out)


def parse_beats(text: str, *, scene_id: str = "?") -> tuple[list[str], list[float]]:
    """Split narration at its beat marks.

    Returns ``(segments, gaps)`` with ``len(gaps) == len(segments) + 1``: ``gaps[0]`` is a beat
    before the first word (usually 0), ``gaps[i]`` the beat between segment ``i-1`` and ``i``,
    and ``gaps[-1]`` a beat after the last word. Adjacent marks add up.
    """
    segments: list[str] = []
    gaps: list[float] = [0.0]
    cursor = 0
    for match in BEAT_RE.finditer(text):
        chunk = " ".join(text[cursor:match.start()].split())
        if chunk:
            segments.append(chunk)
            gaps.append(0.0)
        seconds = float(match.group(1)) if match.group(1) else BEAT_DEFAULT
        if not 0.05 <= seconds <= BEAT_MAX:
            raise NarrationError(
                f"[{scene_id}] {match.group(0)!r} asks for a {seconds:g} s pause; beats must be "
                f"between 0.05 and {BEAT_MAX:g} s"
            )
        gaps[-1] += seconds
        cursor = match.end()
    tail = " ".join(text[cursor:].split())
    if tail:
        segments.append(tail)
        gaps.append(0.0)
    for seg in segments:
        stray = _ANY_MARK_RE.search(seg)
        if stray:
            raise NarrationError(
                f"[{scene_id}] {stray.group(0)!r} is not a beat mark, and the voice would read it "
                "out loud. Only [beat] and [beat N] may appear in narration."
            )
    if not segments:
        raise NarrationError(f"[{scene_id}] the narration has no words, only beats")
    return segments, gaps


def text_hash(text: str) -> str:
    return hashlib.sha256(" ".join(text.split()).encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- scenes


def load_scenes(film: Film | None = None) -> list[tuple[str, str]]:
    """``[(scene_id, narration), ...]`` from the film's script module, in order."""
    film = film or film_profile()
    module = import_script(film)
    scenes = getattr(module, "SCENES", None)
    if not scenes:
        raise NarrationError(f"{film.script_module}.py defines no non-empty SCENES list")
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
    """``str(exc)``, but never raising - some aiohttp errors format themselves badly."""
    try:
        return str(exc) or repr(exc.args)
    except Exception:  # noqa: BLE001 - reporting must not be able to fail
        return f"<{type(exc).__name__} whose str() raised>"


async def _synthesise(text: str, dest: Path, voice: str, rate: str) -> list[dict[str, Any]]:
    import edge_tts

    communicate = edge_tts.Communicate(text, voice, rate=rate, boundary="WordBoundary")
    tmp = dest.with_suffix(".part")
    written = 0
    words: list[dict[str, Any]] = []
    try:
        with tmp.open("wb") as handle:
            async for chunk in communicate.stream():
                kind = chunk.get("type")
                if kind == "audio" and chunk.get("data"):
                    handle.write(chunk["data"])
                    written += len(chunk["data"])
                elif kind == "WordBoundary":
                    # offsets are in 100 ns ticks from the start of the stream
                    start = float(chunk.get("offset", 0)) / 1e7
                    words.append({
                        "text": str(chunk.get("text", "")),
                        "start": start,
                        "end": start + float(chunk.get("duration", 0)) / 1e7,
                    })
        if written == 0:
            raise TransientTTSError("the speech endpoint sent no audio for this segment")
        tmp.replace(dest)
    finally:
        tmp.unlink(missing_ok=True)
    return words


def _accept_duration(got: float, expected: float, takes: Sequence[float], *,
                     what: str, attempt: int) -> bool:
    """Is this take a real reading of the text, or a stream that was cut short?

    The public endpoint intermittently closes the socket *part way* through: a perfectly
    valid MP3 that stops mid-sentence. Only the short side is checked, and a length two
    independent takes agree on is the voice's real opinion of the text.
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
    """Run edge-tts for one segment, retrying transient hiccups and explaining real failures.

    Writes ``dest`` (MP3) and, beside it, ``<dest>.words.json`` with the endpoint's word
    boundaries, which is what lets a subtitle or an action land on a word.
    """
    try:
        import edge_tts  # noqa: F401
    except ImportError as exc:
        raise NarrationError(
            "edge-tts is not installed. Install it with:  python -m pip install edge-tts"
        ) from exc

    what = label or dest.name
    # Short segments are mostly edge-tts padding, so the word-rate model only applies to
    # the long ones; a two-word punchline cannot be "truncated" in any way that matters.
    # A segment between beats is often one quick sentence with no breath in it, which this
    # voice reads at ~0.25 s a word - the whole-scene figure (pauses included) would flag
    # every one of those as truncated, so segments are judged at the faster rate.
    n_words = len(text.split())
    sentences = len(_SENTENCE_SPLIT.split(text.strip()))
    rate_per_word = SECONDS_PER_WORD if sentences >= 3 else SEGMENT_SECONDS_PER_WORD
    expected = n_words * rate_per_word if n_words >= 6 else 0.0
    takes: list[float] = []
    last: BaseException | None = None
    for attempt in range(1, SYNTH_ATTEMPTS + 1):
        try:
            words = asyncio.run(asyncio.wait_for(_synthesise(text, dest, voice, rate), SYNTH_TIMEOUT))
            got = probe_seconds(dest)
            takes.append(got)
            if _accept_duration(got, expected, takes, what=what, attempt=attempt):
                words_path(dest).write_text(json.dumps(words, indent=1) + "\n", encoding="utf-8")
                return
            raise TransientTTSError(
                f"the take is {got:.1f}s but {n_words} words should take about "
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
            "Microsoft's speech endpoint is cutting the stream. Wait a minute and re-run "
            "(already-synthesised segments are cached, so only this one is retried)."
        ) from last
    if isinstance(last, TimeoutError):
        raise NarrationError(
            f"{what}: edge-tts timed out after {SYNTH_TIMEOUT:.0f}s on every one of "
            f"{SYNTH_ATTEMPTS} attempts. The Microsoft speech endpoint is slow or "
            "unreachable - check your internet connection, then re-run (cached segments are "
            "reused, so a re-run is cheap)."
        ) from last
    raise NarrationError(
        f"{what}: edge-tts failed {SYNTH_ATTEMPTS} times - "
        f"{type(last).__name__}: {_safe_str(last)}\n"
        "edge-tts needs a working internet connection to Microsoft's speech endpoint "
        "(speech.platform.bing.com). Re-run once online - cached segments are reused."
    ) from last


def words_path(mp3: Path) -> Path:
    return mp3.with_name(mp3.stem + ".words.json")


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


# --------------------------------------------------------------------------- PCM

#: The assembled scene WAVs: edge-tts's own sample rate, mono, 16 bit.
SAMPLE_RATE: Final[int] = 24000


def decode_pcm(path: Path) -> Any:
    """An MP3 (or anything ffmpeg reads) -> int16 mono numpy array at :data:`SAMPLE_RATE`."""
    import numpy as np

    cmd = [
        "ffmpeg", "-v", "error", "-nostdin", "-i", str(path),
        "-f", "s16le", "-acodec", "pcm_s16le", "-ac", "1", "-ar", str(SAMPLE_RATE), "-",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=FFPROBE_TIMEOUT * 4, check=False)
    except FileNotFoundError as exc:
        raise NarrationError("ffmpeg was not found on PATH - install the ffmpeg full build.") from exc
    except subprocess.TimeoutExpired as exc:
        raise NarrationError(f"ffmpeg timed out decoding {path}") from exc
    if proc.returncode != 0 or not proc.stdout:
        raise NarrationError(
            f"ffmpeg could not decode {path}: {(proc.stderr or b'').decode('utf-8', 'replace')[:300]}"
        )
    return np.frombuffer(proc.stdout, dtype=np.int16).copy()


def _levels_db(pcm: Any) -> Any:
    """Per-window RMS level in dBFS (``WINDOW_S`` windows)."""
    import numpy as np

    win = max(1, int(round(WINDOW_S * SAMPLE_RATE)))
    n = len(pcm) // win
    if n == 0:
        return np.full(1, -120.0)
    frames = pcm[: n * win].astype(np.float64).reshape(n, win) / 32768.0
    rms = np.sqrt(np.mean(frames * frames, axis=1))
    return 20.0 * np.log10(np.maximum(rms, 1e-6))


def speech_bounds(pcm: Any) -> tuple[float, float]:
    """(onset, offset) of the speech in a segment, in seconds, at :data:`ONSET_DB`."""
    import numpy as np

    levels = _levels_db(pcm)
    loud = np.nonzero(levels > ONSET_DB)[0]
    total = len(pcm) / SAMPLE_RATE
    if len(loud) == 0:
        return 0.0, total
    return float(loud[0]) * WINDOW_S, min(total, float(loud[-1] + 1) * WINDOW_S)


#: silence inside a segment: quiet enough to catch a breath between sentences, long enough
#: not to fire on the gap inside "192 dot 168 dot 1 dot 142".
SILENCE_DB: Final[float] = -38.0
SILENCE_MIN: Final[float] = 0.18


def pauses_in(pcm: Any, lo: float, hi: float) -> list[float]:
    """Midpoints of the breaths inside ``[lo, hi]`` seconds of a segment, relative to ``lo``."""
    levels = _levels_db(pcm)
    out: list[float] = []
    run_start: int | None = None
    i0, i1 = int(lo / WINDOW_S), min(len(levels), int(hi / WINDOW_S))
    for i in range(i0, i1):
        quiet = levels[i] < SILENCE_DB
        if quiet and run_start is None:
            run_start = i
        elif not quiet and run_start is not None:
            if (i - run_start) * WINDOW_S >= SILENCE_MIN:
                out.append(((run_start + i) / 2.0) * WINDOW_S - lo)
            run_start = None
    return out


def measure_silences(path: Path, *, noise_db: float = -45.0, min_len: float = 0.08) -> list[tuple[float, float]]:
    """(start, end) of every silence in an audio file, via ffmpeg's silencedetect.

    Independent of :func:`speech_bounds` on purpose: it is how a render is checked, so it must
    not share the code that placed the beats.
    """
    cmd = [
        "ffmpeg", "-v", "info", "-nostdin", "-i", str(path),
        "-af", f"silencedetect=n={noise_db}dB:d={min_len}", "-f", "null", "-",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=FFPROBE_TIMEOUT * 4, check=False)
    starts: list[float] = []
    out: list[tuple[float, float]] = []
    for kind, value in re.findall(r"silence_(start|end):\s*(-?[\d.]+)", proc.stderr or ""):
        if kind == "start":
            starts.append(float(value))
        elif starts:
            out.append((starts.pop(), float(value)))
    return out


def write_wav(path: Path, pcm: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    with wave.open(str(tmp), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(SAMPLE_RATE)
        handle.writeframes(pcm.astype("<i2").tobytes())
    tmp.replace(path)


# --------------------------------------------------------------------------- assembly


def _zeros(seconds: float) -> Any:
    import numpy as np

    return np.zeros(max(0, int(round(seconds * SAMPLE_RATE))), dtype=np.int16)


def _load_words(mp3: Path, onset: float) -> list[dict[str, Any]]:
    """The segment's word boundaries, shifted onto its decoded audio.

    The endpoint's offsets count from the start of *its* stream; the decoded MP3 carries a
    little encoder delay on top. The first word's offset and the measured onset pin the two
    together (clamped, so one odd reading cannot fling every word).
    """
    path = words_path(mp3)
    if not path.exists():
        return []
    try:
        words = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    words = [w for w in words if isinstance(w, dict) and str(w.get("text", "")).strip()]
    if not words:
        return []
    lag = onset - float(words[0]["start"])
    lag = min(0.15, max(0.0, lag))
    return [
        {"text": str(w["text"]), "start": float(w["start"]) + lag, "end": float(w["end"]) + lag}
        for w in words
    ]


def assemble_scene(
    scene_id: str,
    text: str,
    dest: Path,
    *,
    voice: str,
    rate: str,
    synthesise_missing: bool,
    force: bool = False,
) -> tuple[list[Segment], list[Beat], float, str]:
    """Synthesise (or reuse) a scene's segments and join them with exact beats.

    Returns ``(segments, beats, seconds, state)``. Raises when a segment is missing from the
    cache and ``synthesise_missing`` is false (``--only`` left this scene alone).
    """
    import numpy as np

    texts, gaps = parse_beats(text, scene_id=scene_id)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    segments: list[Segment] = []
    states: set[str] = set()
    for i, seg_text in enumerate(texts):
        key = cache_key(seg_text, voice, rate)
        mp3 = CACHE_DIR / f"{key}.mp3"
        label = f"{scene_id} seg {i + 1}/{len(texts)}"
        if mp3.exists() and not force:
            states.add("cached")
        elif synthesise_missing:
            synthesise(seg_text, mp3, voice=voice, rate=rate, label=label)
            states.add("synthesised")
        else:
            raise NarrationError(f"{label} ({seg_text[:40]!r}) is not cached")
        segments.append(Segment(text=seg_text, key=key))

    parts: list[Any] = []
    cursor = 0.0
    beats: list[Beat] = []
    prev_tail = 0.0

    def add(pcm: Any) -> None:
        nonlocal cursor
        parts.append(pcm)
        cursor += len(pcm) / SAMPLE_RATE

    for i, seg in enumerate(segments):
        mp3 = CACHE_DIR / f"{seg.key}.mp3"
        pcm = decode_pcm(mp3)
        onset, offset = speech_bounds(pcm)
        head = min(HEAD_KEEP, onset)
        tail = min(TAIL_KEEP, len(pcm) / SAMPLE_RATE - offset)
        lo = onset - head
        hi = offset + tail
        body = pcm[int(round(lo * SAMPLE_RATE)): int(round(hi * SAMPLE_RATE))]

        before = gaps[i]
        beat: Beat | None = None
        if i == 0:
            if before > 0:
                beat = Beat(len(beats), round(before, 3), start=0.0)
                add(_zeros(before - head))
            else:
                add(_zeros(max(0.0, SCENE_HEAD - head)))
        else:
            beat = Beat(len(beats), round(before, 3), start=segments[i - 1].end)
            # The gap runs from the previous segment's last sound to this one's first: the
            # previous body already carries `prev_tail` of it and this body brings `head`.
            add(_zeros(before - prev_tail - head))

        seg_origin = cursor - lo          # where t=0 of this segment's own audio lands
        seg.start = seg_origin + onset
        seg.end = seg_origin + offset
        seg.words = [
            {"text": w["text"], "start": seg_origin + w["start"], "end": seg_origin + w["end"]}
            for w in _load_words(mp3, onset)
        ]
        seg.pauses = pauses_in(pcm, onset, offset)
        add(body)
        prev_tail = tail
        if beat is not None:
            beat.end = seg.start
            beats.append(beat)

    closing = gaps[-1]
    if closing > 0:
        beats.append(Beat(len(beats), round(closing, 3), start=segments[-1].end))
        add(_zeros(closing - prev_tail))
        beats[-1].end = cursor
    else:
        add(_zeros(max(0.0, SCENE_TAIL - prev_tail)))

    for beat in beats:
        spoken_before = [s for s in segments if s.end <= beat.start + 1e-6]
        spoken_after = [s for s in segments if s.start >= beat.end - 1e-6]
        if spoken_before:
            beat.after = " ".join(spoken_before[-1].text.split()[-5:])
        if spoken_after:
            beat.before = " ".join(spoken_after[0].text.split()[:5])

    write_wav(dest, np.concatenate(parts) if parts else _zeros(0.5))
    seconds = cursor
    state = "synthesised" if "synthesised" in states else "cached"
    return segments, beats, seconds, state


# --------------------------------------------------------------------------- subtitles

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])[\"')\]]*\s+")
_ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "no.", "fig.", "approx.", "mr.", "mrs.", "dr.", "st.")


def _sentence_level(text: str) -> list[str]:
    """Sentence split with abbreviations re-joined and fragments merged, before long ones break."""
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
        if merged and too_short and _fits(f"{merged[-1]} {part}"):
            merged[-1] = f"{merged[-1]} {part}"
        else:
            merged.append(part)
    return merged


def split_sentences(text: str) -> list[str]:
    """Sentence-ish chunks suitable for one subtitle each."""
    out: list[str] = []
    for part in _sentence_level(text):
        out.extend(_split_long(part))
    return out


def split_sentences_grouped(text: str) -> list[list[str]]:
    """:func:`split_sentences`, keeping the clause-pieces of one sentence together."""
    return [_split_long(sentence) for sentence in _sentence_level(text)]


_CLAUSE_BREAK = re.compile(r"(?<=[,;:-])\s+")


def _two_lines(text: str) -> list[str] | None:
    """``text`` as at most two lines of <= SRT_LINE_CHARS, balanced; ``None`` if it cannot be."""
    if len(text) <= SRT_LINE_CHARS:
        return [text]
    words = text.split()
    best: tuple[int, list[str]] | None = None
    for i in range(1, len(words)):
        a, b = " ".join(words[:i]), " ".join(words[i:])
        if len(a) <= SRT_LINE_CHARS and len(b) <= SRT_LINE_CHARS:
            worst = max(len(a), len(b))
            if best is None or worst < best[0]:
                best = (worst, [a, b])
    return best[1] if best else None


_NO_BREAK_AFTER = frozenset({"a", "an", "the", "to", "of", "your", "its", "my", "our", "on",
                             "in", "at", "by", "for", "from", "and", "or", "is", "it"})
_BREAK_BEFORE = frozenset({"and", "but", "or", "to", "from", "that", "which", "who", "because",
                           "so", "while", "when", "like", "with", "for", "into", "if", "then"})


def _fits(text: str) -> bool:
    return _two_lines(text) is not None


def _split_long(sentence: str) -> list[str]:
    """Break a sentence that does not fit two subtitle lines, nearest its middle.

    A clause boundary (after , ; : or -) is preferred; with none, the word boundary nearest the
    middle. Recurses until every piece fits.
    """
    if _fits(sentence):
        return [sentence]
    middle = len(sentence) / 2
    pieces = _CLAUSE_BREAK.split(sentence)
    by_word = len(pieces) < 2
    if by_word:
        pieces = sentence.split()
    if len(pieces) < 2:
        return [sentence]
    best, best_gap, cursor = 1, None, 0
    for i, piece in enumerate(pieces[:-1], start=1):
        cursor += len(piece) + 1
        gap = abs(cursor - middle)
        if by_word:
            # read as a phrase: never leave "a", "the", "to" hanging at the end of a cue, and
            # prefer to start the next one on a joining word ("from", "and", "who" ...)
            if _norm(piece) in _NO_BREAK_AFTER:
                gap += 1000
            elif _norm(pieces[i]) in _BREAK_BEFORE:
                gap -= 14
        if best_gap is None or gap < best_gap:
            best, best_gap = i, gap
    head = " ".join(pieces[:best]).strip()
    tail = " ".join(pieces[best:]).strip()
    if not head or not tail:
        return [sentence]
    return _split_long(head) + _split_long(tail)


def wrap_cue(text: str) -> str:
    """Set a cue as at most two balanced lines of <= :data:`SRT_LINE_CHARS` characters."""
    lines = _two_lines(" ".join(text.split()))
    if lines is None:  # pragma: no cover - _split_long guarantees every cue fits
        raise NarrationError(f"subtitle cue does not fit two lines: {text!r}")
    return "\n".join(lines)


SNAP_WINDOW: Final[float] = 2.6


def snap_to_pauses(boundaries: list[float], pauses: Sequence[float], span: float) -> list[float]:
    """Drag each boundary onto the nearest pause within SNAP_WINDOW, keeping them ordered."""
    if not pauses or not boundaries:
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


def _proportional_edges(groups: list[list[str]], seconds: float, pauses: Sequence[float]) -> list[float]:
    """Cue edges inside one segment by character share, sentence edges snapped to breaths."""
    sentences = [part for group in groups for part in group]
    total = float(sum(max(len(s), 1) for s in sentences))
    group_weights = [sum(max(len(p), 1) for p in g) for g in groups]
    group_edges: list[float] = []
    running = 0.0
    for weight in group_weights[:-1]:
        running += seconds * (weight / total)
        group_edges.append(running)
    group_edges = snap_to_pauses(group_edges, pauses, seconds)
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
    return edges


def _word_edges(pieces: list[str], seg: Segment) -> list[tuple[float, float]] | None:
    """Each piece's (first word start, last word end) from the endpoint's word boundaries.

    Words are located in the segment text in order; a piece takes the words whose position
    falls inside its character span. ``None`` when the boundaries do not cover every piece.
    """
    if not seg.words:
        return None
    text = seg.text
    lowered = text.lower()
    positions: list[tuple[int, dict[str, Any]]] = []
    cursor = 0
    for word in seg.words:
        needle = word["text"].lower()
        at = lowered.find(needle, cursor)
        if at < 0:
            continue
        positions.append((at, word))
        cursor = at + len(needle)
    spans: list[tuple[int, int]] = []
    cursor = 0
    for piece in pieces:
        at = text.find(piece, cursor)
        if at < 0:
            return None
        spans.append((at, at + len(piece)))
        cursor = at + len(piece)
    out: list[tuple[float, float]] = []
    for lo, hi in spans:
        inside = [w for pos, w in positions if lo <= pos < hi]
        if not inside:
            return None
        out.append((inside[0]["start"], inside[-1]["end"]))
    return out


def cues_for_segment(seg: Segment, *, origin: float) -> list[Cue]:
    """The cues of one segment, on the film timeline (``origin`` = the scene audio's t=0)."""
    groups = split_sentences_grouped(seg.text)
    pieces = [part for group in groups for part in group]
    if not pieces:
        return []
    exact = _word_edges(pieces, seg)
    if exact is not None:
        spans = exact
        # the first cue starts with the segment's first sound, the last ends with its last
        spans[0] = (seg.start, spans[0][1])
        spans[-1] = (spans[-1][0], seg.end)
    else:
        seconds = max(0.05, seg.end - seg.start)
        edges = _proportional_edges(groups, seconds, seg.pauses)
        spans = [(seg.start + edges[i], seg.start + edges[i + 1]) for i in range(len(pieces))]
    return [Cue(text=piece, start=origin + a, end=origin + b) for piece, (a, b) in zip(pieces, spans)]


def cues_for_scene(scene: SceneAudio) -> list[Cue]:
    """Every cue of a scene, never spanning a beat, with a readable minimum and a short linger."""
    origin = scene.start + LEAD_IN
    raw: list[Cue] = []
    for seg in scene.segments:
        raw.extend(cues_for_segment(seg, origin=origin))
    scene_end = scene.end
    out: list[Cue] = []
    for i, cue in enumerate(raw):
        nxt = raw[i + 1].start if i + 1 < len(raw) else scene_end
        ceiling = nxt - CUE_GAP
        want = max(cue.end + CUE_LINGER, cue.start + MIN_CUE_SECONDS)
        # linger when there is room (a beat, the scene's tail), otherwise hand over on time
        end = min(want, ceiling) if ceiling > cue.end else max(cue.start + 0.30, ceiling)
        out.append(Cue(cue.text, cue.start, max(end, cue.start + 0.30)))
    return out


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
            text = strip_marks(cue.text)
            blocks.append(
                f"{n}\n{srt_timestamp(cue.start)} --> {srt_timestamp(cue.end)}\n{wrap_cue(text)}\n"
            )
    return "\n".join(blocks)


# --------------------------------------------------------------------------- timing helpers
#
# For script modules: place an action on a beat or a word instead of guessing a fraction.
# They read <build>/beats.json of the film being rendered. On the very first run of a new
# script it does not exist yet (the script is imported *before* it is narrated), so each
# helper returns `default` then; render.py re-imports the script after narration, and
# capture/compose run in fresh processes, so the numbers that reach the film are the real ones.

_beats_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_warned: set[str] = set()


def _beats_for(scene_id: str, film: str | None) -> dict[str, Any] | None:
    try:
        path = film_profile(film).beats
    except NarrationError:
        return None
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    hit = _beats_cache.get(str(path))
    if hit is None or hit[0] != mtime:
        try:
            hit = (mtime, json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            return None
        _beats_cache[str(path)] = hit
    row = hit[1].get(scene_id)
    return row if isinstance(row, dict) else None


def _fallback(what: str, default: float) -> float:
    if what not in _warned:
        _warned.add(what)
        logger.info("%s is not narrated yet; using %.3f until it is", what, default)
    return default


def _shift(row: dict[str, Any], seconds_from_start: float, offset: float) -> float:
    total = float(row.get("seconds") or 0.0)
    if total <= 0:
        return 0.0
    return round(max(0.0, min(1.0, (seconds_from_start + offset) / total)), 5)


def beat_at(scene_id: str, n: int, *, edge: str = "end", offset: float = 0.0,
            default: float = 0.5, film: str | None = None) -> float:
    """The ``at`` fraction of beat ``n`` (0-based; negative counts from the end) in a scene.

    ``edge="start"`` is the moment the pause begins (the set-up's last sound), ``"end"`` the
    moment the next line starts (the punchline's first sound), ``"mid"`` the middle.
    ``offset`` is in seconds and may be negative (``offset=-0.2`` lands a reveal just before
    the punchline is spoken).
    """
    row = _beats_for(scene_id, film)
    beats = (row or {}).get("beats") or []
    try:
        beat = beats[n]
    except (IndexError, TypeError):
        return _fallback(f"{scene_id} beat {n}", default)
    t = {"start": beat["start"], "end": beat["end"]}.get(edge, (beat["start"] + beat["end"]) / 2)
    return _shift(row or {}, float(t), offset)


def line_at(scene_id: str, n: int, *, edge: str = "start", offset: float = 0.0,
            default: float = 0.5, film: str | None = None) -> float:
    """The ``at`` fraction where spoken segment ``n`` (the text between two beats) starts or ends."""
    row = _beats_for(scene_id, film)
    segments = (row or {}).get("segments") or []
    try:
        seg = segments[n]
    except (IndexError, TypeError):
        return _fallback(f"{scene_id} line {n}", default)
    return _shift(row or {}, float(seg["end"] if edge == "end" else seg["start"]), offset)


def _norm(word: str) -> str:
    return re.sub(r"[^\w]+", "", word.lower())


def phrase_at(scene_id: str, phrase: str, *, occurrence: int = 1, edge: str = "start",
              offset: float = 0.0, default: float = 0.5, film: str | None = None) -> float:
    """The ``at`` fraction when ``phrase`` is spoken (from the endpoint's word boundaries).

    ``phrase_at("01-cold-open", "eighteen")`` fires on the word; ``edge="end"`` on its last
    sound. Matching ignores case and punctuation. Falls back to the segment containing the
    phrase when word boundaries are missing, and to ``default`` before narration exists.
    """
    row = _beats_for(scene_id, film)
    if not row:
        return _fallback(f"{scene_id} {phrase!r}", default)
    wanted = [_norm(w) for w in phrase.split() if _norm(w)]
    words = row.get("words") or []
    seen = 0
    if wanted:
        norm = [_norm(str(w.get("text", ""))) for w in words]
        for i in range(len(norm) - len(wanted) + 1):
            if norm[i:i + len(wanted)] == wanted:
                seen += 1
                if seen == occurrence:
                    t = words[i + len(wanted) - 1]["end"] if edge == "end" else words[i]["start"]
                    return _shift(row, float(t), offset)
    seen = 0
    for seg in row.get("segments") or []:
        if phrase.lower() in str(seg.get("text", "")).lower():
            seen += 1
            if seen == occurrence:
                return _shift(row, float(seg["end"] if edge == "end" else seg["start"]), offset)
    return _fallback(f"{scene_id} {phrase!r}", default)


# --------------------------------------------------------------------------- driver


def _old_layout(film: Film, scene_id: str) -> dict[str, Any] | None:
    try:
        data = json.loads(film.timings.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    row = data.get(scene_id)
    return row if isinstance(row, dict) else None


def narrate(
    *,
    film: Film | None = None,
    voice: str = VOICE,
    rate: str = RATE,
    force: bool = False,
    only: str | None = None,
) -> list[SceneAudio]:
    """Synthesise (or reuse) every scene's audio and write timings.json, beats.json and the SRT."""
    film = film or film_profile()
    scenes = load_scenes(film)
    if only:
        wanted = {s.strip() for s in only.split(",") if s.strip()}
        unknown = wanted - {sid for sid, _ in scenes}
        if unknown:
            raise NarrationError(f"--only names unknown scene ids: {', '.join(sorted(unknown))}")
    else:
        wanted = None

    film.audio_dir.mkdir(parents=True, exist_ok=True)
    film.out_srt.parent.mkdir(parents=True, exist_ok=True)

    results: list[SceneAudio] = []
    for index, (scene_id, text) in enumerate(scenes, start=1):
        dest = film.audio_dir / f"scene_{index:02d}.wav"
        skipped = wanted is not None and scene_id not in wanted
        try:
            segments, beats, seconds, state = assemble_scene(
                scene_id, text, dest, voice=voice, rate=rate,
                synthesise_missing=not skipped, force=force and not skipped,
            )
        except NarrationError:
            if not skipped:
                raise
            raise NarrationError(
                f"{scene_id}: --only left this scene alone, but its narration is not in the "
                "cache (its words changed, or it was never narrated). Run without --only once."
            ) from None
        if skipped:
            old = _old_layout(film, scene_id)
            state = "kept" if old and old.get("text_hash") == text_hash(text) else "KEPT (NEW WORDS)"
        scene = SceneAudio(index=index, scene_id=scene_id, text=text, path=dest, seconds=seconds,
                           segments=segments, beats=beats, state=state)
        results.append(scene)
        worst = max((abs(b.measured - b.seconds) for b in beats), default=0.0)
        print(
            f"  [{index:02d}/{len(scenes)}] {scene_id:<26} {state:<12} {seconds:6.2f}s  "
            f"{len(segments):2d} seg  {len(beats):2d} beat(s)"
            f"{f'  max beat error {worst * 1000:.0f} ms' if beats else ''}",
            flush=True,
        )
        for beat in beats:
            if abs(beat.measured - beat.seconds) > BEAT_TOLERANCE:
                logger.warning(
                    "%s beat %d: designed %.2fs but the gap is %.2fs ('%s' | '%s')",
                    scene_id, beat.n, beat.seconds, beat.measured, beat.after, beat.before,
                )

    cursor = 0.0
    for scene in results:
        scene.start = cursor
        scene.cues = cues_for_scene(scene)
        cursor = scene.end

    total = cursor + END_ROOM_TONE
    speech = sum(s.seconds for s in results)

    film.build.mkdir(parents=True, exist_ok=True)
    film.timings.write_text(
        json.dumps({s.scene_id: s.as_json() for s in results}, indent=2) + "\n", encoding="utf-8"
    )
    film.beats.write_text(
        json.dumps({s.scene_id: s.layout() for s in results}, indent=1) + "\n", encoding="utf-8"
    )
    archive_previous(film)
    film.out_srt.write_text(build_srt(results), encoding="utf-8")
    record_deliverable(film, film.out_srt)

    n_beats = sum(len(s.beats) for s in results)
    print(
        f"\n  film {film.name}: {speech / 60:.2f} min of narration | timeline {total / 60:.2f} min "
        f"({total:.1f}s incl. {END_ROOM_TONE}s room tone) | {n_beats} beats"
    )
    print(f"  {film.timings}")
    print(f"  {film.beats}")
    print(f"  {film.out_srt}  ({sum(len(s.cues) for s in results)} cues)")
    if not film.target_min * 60 <= total <= film.target_max * 60:
        print(
            f"  NOTE: the {film.name} film aims for {film.target_min:g}-{film.target_max:g} "
            f"minutes; this timeline is {total / 60:.2f} min.",
            file=sys.stderr,
        )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthesise a Home SOC walkthrough film's narration.")
    parser.add_argument("--script", default=None, metavar="FILM",
                        help=f"which film: {' | '.join(FILMS)} (default {DEFAULT_FILM})")
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
    try:
        film = select_film(args.script)
        print(f"narrate: film={film.name} ({film.script_module}.py) voice={args.voice} rate={args.rate}")
        narrate(film=film, voice=args.voice, rate=args.rate, force=args.force, only=args.only)
    except NarrationError as exc:
        print(f"\nnarrate: FAILED\n{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
