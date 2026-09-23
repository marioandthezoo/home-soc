"""End-to-end orchestrator for the Home SOC walkthrough films.

    python video/render.py                          # the everyday film, end to end
    python video/render.py --script technical       # the 16-minute technical cut
    python video/render.py --no-capture             # reuse the shots, recompose
    python video/render.py --only 06-tuesday-telnet
    python video/render.py --no-seed --no-narrate --no-capture --force

Two films (``--script``, default ``everyday``):

    everyday   script_everyday.py + slides_everyday.py, build in build/everyday/,
               -> out/HomeSOC-walkthrough.mp4 (+ .srt)
    technical  script.py + slides.py, build in build/,
               -> out/HomeSOC-walkthrough-technical.mp4 (+ .srt)

Before the first everyday render, whatever ``out/HomeSOC-walkthrough.*`` held (the technical
cut) is moved to ``out/archive/`` with its date - a previous film is never deleted.

Pipeline (``<build>`` is the film's build directory)
--------
1. ``seed_demo.py``  builds ``video/demo_data/homesoc.db`` (never touches ``data/``)
2. ``narrate.py``    edge-tts, one segment per stretch between [beat] marks, joined with
                     exact silences -> ``<build>/audio/scene_NN.wav`` + ``timings.json`` +
                     ``beats.json`` + the SRT. The film's script is imported only after this,
                     so actions timed with ``narrate.beat_at``/``phrase_at`` are current.
3. ``capture.py``    Playwright -> ``<build>/shots/*.png`` + ``<build>/geometry.json``
                     + ``build/shots_manifest.json``.  For the Lens act this also drives
                     the phone context (``phone.py``), the illustrated scene and its
                     camera clip (``scene_render.py``), and the decode sidecar
                     (``decode_sidecar.py``) behind the ``BarcodeDetector`` shim.
4. **scan-rig check** the manifest must record a *real* decode for every scene whose
                     narration calls the identification a scan (CONTRACT_V2 V3).  This
                     step fails the render rather than letting a manual pick be narrated
                     as a scan - and it runs on ``--no-capture`` too, where nothing else
                     would re-check a reused shot.
5. ``compose.py``    per scene: frames piped to ffmpeg -> ``build/clips/NN-id.mp4``
6. concat demuxer    the clips, stream-copied into one video track
7. audio             per-scene silence-padded WAVs, concatenated, muxed as AAC 192k
8. verify            ffprobe the result and print the summary

Every scene clip is fingerprinted, so a second run only recomposes what changed.
Because scenes cross-dissolve into each other, a scene's fingerprint includes the
one before it: changing scene 3 correctly reworks scene 4's first 400 ms.

The whole pipeline is read-only with respect to the user's real security
database: only ``video/demo_data`` is ever written to.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from PIL import Image

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import compose as C  # noqa: E402  (needs HERE on sys.path)
import narrate as N  # noqa: E402

log = logging.getLogger("homesoc.video.render")

OUT_DIR = HERE / "out"
DEMO_DB = HERE / "demo_data" / "homesoc.db"

# Per film, rebound by configure(). Defaults are the everyday film's.
FILM: N.Film = N.film_profile("everyday")
BUILD = FILM.build
SHOTS = BUILD / "shots"
CLIPS = BUILD / "clips"
AUDIO = BUILD / "audio"
PADDED = BUILD / "audio_padded"
OUT_MP4 = FILM.out_mp4
OUT_SRT = FILM.out_srt
TIMINGS = BUILD / "timings.json"
GEOMETRY = BUILD / "geometry.json"
MANIFEST = BUILD / "shots_manifest.json"
TIMELINE = BUILD / "timeline.json"


def configure(film: N.Film) -> None:
    """Point every path at ``film``'s build directory and deliverables, and pick its look."""
    global FILM, BUILD, SHOTS, CLIPS, AUDIO, PADDED, OUT_MP4, OUT_SRT
    global TIMINGS, GEOMETRY, MANIFEST, TIMELINE, TARGET_MIN_SECONDS, TARGET_MAX_SECONDS
    FILM = film
    BUILD = film.build
    SHOTS = BUILD / "shots"
    CLIPS = BUILD / "clips"
    AUDIO = film.audio_dir
    PADDED = BUILD / "audio_padded"
    OUT_MP4 = film.out_mp4
    OUT_SRT = film.out_srt
    TIMINGS = film.timings
    GEOMETRY = BUILD / "geometry.json"
    MANIFEST = BUILD / "shots_manifest.json"
    TIMELINE = BUILD / "timeline.json"
    TARGET_MIN_SECONDS = film.target_min * 60
    TARGET_MAX_SECONDS = film.target_max * 60
    C.set_look(film.look)

SEED_TIMEOUT = 900
NARRATE_TIMEOUT = 1800
#: v2 capture is a longer job than v1: 20 scenes, a second (phone) browser context, the
#: illustrated scene and its camera clip, and the decode sidecar.
CAPTURE_TIMEOUT = 3600
FFMPEG_TIMEOUT = 1800

#: Target length of the finished film, from the film profile (a note, never a failure).
TARGET_MIN_SECONDS = FILM.target_min * 60
TARGET_MAX_SECONDS = FILM.target_max * 60

AUDIO_RATE = 48000
AUDIO_CH = 2


class RenderError(RuntimeError):
    """A pipeline step failed in a way the operator has to fix."""


# --------------------------------------------------------------------------
# subprocess helpers - every child is waited for or killed in a finally
# --------------------------------------------------------------------------


def run_step(name: str, argv: Sequence[str], timeout: float, cwd: Path | None = None) -> None:
    """Run a pipeline step, streaming its output, and never leave it running."""
    print(f"\n=== {name} ===", flush=True)
    print("    " + " ".join(argv), flush=True)
    started = time.perf_counter()
    proc: subprocess.Popen[str] | None = None
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"   # the child's output is decoded as UTF-8 below
    try:
        proc = subprocess.Popen(
            list(argv),
            cwd=str(cwd or HERE.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print("    " + line.rstrip(), flush=True)
        rc = proc.wait(timeout=timeout)
        if rc != 0:
            raise RenderError(f"{name} failed with exit code {rc}")
    except subprocess.TimeoutExpired as exc:
        raise RenderError(f"{name} timed out after {timeout:.0f}s") from exc
    finally:
        if proc is not None and proc.poll() is None:
            _stop_tree(proc)
    print(f"    done in {time.perf_counter() - started:.1f}s", flush=True)


def _stop_tree(proc: subprocess.Popen[Any]) -> None:
    """Stop a step *and everything it started*.

    ``capture.py`` owns a dashboard (with the resolver), a decode sidecar and Chrome. On
    Windows ``terminate()`` ends only the python process, and those children survive it -
    a render interrupted mid-capture left a demo dashboard serving on 8899 with a resolver on
    53530. ``taskkill /T`` takes the whole tree.
    """
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       capture_output=True, check=False, timeout=30)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def ffmpeg(args: Sequence[str], what: str, timeout: float = FFMPEG_TIMEOUT) -> None:
    cmd = ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", *args]
    proc: subprocess.Popen[str] | None = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace",
        )
        out, _ = proc.communicate(timeout=timeout)
        if proc.returncode != 0:
            raise RenderError(f"{what}: ffmpeg exited {proc.returncode}\n{(out or '')[-3000:]}")
    except subprocess.TimeoutExpired as exc:
        raise RenderError(f"{what}: ffmpeg timed out after {timeout:.0f}s") from exc
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


def ffprobe_json(path: Path, timeout: float = 60) -> dict[str, Any]:
    cmd = [
        "ffprobe", "-v", "error", "-print_format", "json",
        "-show_format", "-show_streams", str(path),
    ]
    proc: subprocess.Popen[str] | None = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate(timeout=timeout)
        if proc.returncode != 0:
            raise RenderError(f"ffprobe failed on {path.name}: {err.strip()}")
        return json.loads(out)
    except subprocess.TimeoutExpired as exc:
        raise RenderError(f"ffprobe timed out on {path.name}") from exc
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


def media_seconds(path: Path) -> float:
    info = ffprobe_json(path)
    try:
        return float(info["format"]["duration"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RenderError(f"{path.name} has no readable duration") from exc


# --------------------------------------------------------------------------
# scene bookkeeping
# --------------------------------------------------------------------------


@dataclass
class SceneJob:
    index: int
    scene: Any
    scene_id: str
    states: list[C.ShotState]
    narration_seconds: float
    audio: Path | None
    extra_tail: float
    clip: Path
    stamp: Path
    last_png: Path

    #: film graphics the script asks for over this scene (``script.OVERLAYS``)
    overlays: tuple[Any, ...] = ()
    #: the last scene: seconds of fade to the canvas colour at its very end
    fade_out: float = 0.0

    plan: C.ScenePlan | None = None
    reused: bool = False
    elapsed: float = 0.0
    start: float = 0.0
    seconds: float = 0.0


def load_script(*, fresh: bool = False) -> Any:
    """The film's scene script. ``fresh`` re-imports it after narration, because a script may
    time its actions with ``narrate.beat_at``/``phrase_at``, which read the beats narration
    has just measured - the copy imported before narration ran would carry stale ``at``s."""
    import importlib

    name = FILM.script_module
    try:
        module = sys.modules.get(name)
        if module is not None and fresh:
            module = importlib.reload(module)
        elif module is None:
            module = importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001
        raise RenderError(f"cannot import video/{name}.py: {type(exc).__name__}: {exc}") from exc
    if not getattr(module, "SCENES", None):
        raise RenderError(f"video/{name}.py defines no SCENES")
    return module


def load_json(path: Path, what: str, required: bool = True) -> dict[str, Any]:
    if not path.exists():
        if required:
            raise RenderError(f"{what} is missing ({path}). Run the earlier pipeline steps first.")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RenderError(f"{what} is not valid JSON ({path}): {exc}") from exc


# --------------------------------------------------------------------------
# the scan rig (CONTRACT_V2 V3) - this gate never degrades, it only fails
# --------------------------------------------------------------------------


def _all_shots(scene: Any) -> list[Any]:
    """Every shot a scene declares: its own, a sequence's members, and every then_shot."""
    out: list[Any] = []
    shot = getattr(scene, "shot", None)
    if shot is not None:
        members = list(getattr(shot, "shots", ()) or ()) if hasattr(shot, "shots") else []
        out.extend(members or [shot])
    for action in getattr(scene, "actions", None) or []:
        for name in ("then_shot", "then", "after"):
            then = getattr(action, name, None)
            if then is not None:
                out.append(then)
                break
    return out


def scene_narrates_a_scan(scene: Any) -> bool:
    """Mirror of ``capture.scene_wants_scan``, without importing the capture module.

    Any of three things arms the rig: a ``PhonePair`` (which exists only for the scan
    scene), a phone shot that asks for ``via="scan"``, or a scene id that says so.
    """
    if "lens-scan" in str(getattr(scene, "id", "") or ""):
        return True
    for shot in _all_shots(scene):
        if type(shot).__name__ == "PhonePair" or hasattr(shot, "phone_state"):
            return True
        if str(getattr(shot, "via", "") or "") == "scan":
            return True
    return False


def check_scan_rig(script: Any, only: set[str] | None, manifest: dict[str, Any]) -> list[str]:
    """Prove that every narrated scan was a real decode of the frame on screen.

    ``capture.py`` refuses to record a scan it could not decode.  This is the second
    half of that promise: on a ``--no-capture`` run, or a run that only recomposed some
    scenes, nothing else looks at whether the shots on disk came from a decode at all.
    The manifest's phone metadata carries ``expected_code`` (the sticker token
    ``scene_render.py`` drew) and ``decoded`` (what the shim handed back through the
    zxing-cpp sidecar); they have to match.

    Returns the lines to print.  Raises :class:`RenderError` rather than degrading:
    the narration calls this a scan, so it has to be one.
    """
    scenes = [s for s in script.SCENES if scene_narrates_a_scan(s)]
    if only is not None:
        scenes = [s for s in scenes if str(s.id) in only]
    if not scenes:
        return ["no scene narrates a scan - nothing to check"]

    rows_by_scene = manifest.get("scenes") or {}
    lines: list[str] = []
    for scene in scenes:
        sid = str(scene.id)
        rows = rows_by_scene.get(sid) or []
        if not rows:
            raise RenderError(
                f"[{sid}] narrates a scan but {MANIFEST.name} has no states for it. "
                f"Run capture.py for this scene (it drives scene_render.py, the decode "
                f"sidecar and the BarcodeDetector shim) before composing."
            )
        proofs = []
        for row in rows:
            meta = row.get("phone") if isinstance(row.get("phone"), dict) else {}
            expected = str(meta.get("expected_code") or "")
            decoded = str(meta.get("decoded") or "")
            if expected or decoded:
                proofs.append((row.get("index"), expected, decoded, str(meta.get("via") or "")))
        if not proofs:
            raise RenderError(
                f"[{sid}] narrates a scan, but not one of its captured states records a "
                f"decode. A manual pick must never be narrated as a scan (CONTRACT_V2 V3): "
                f"re-capture this scene with the decode sidecar running, rather than "
                f"composing what is on disk."
            )
        good = [p for p in proofs if p[1] and p[2] == p[1]]
        if not good:
            detail = "; ".join(
                f"state {idx}: expected {exp or '(none)'}, decoded {dec or '(nothing)'}"
                f"{f', via {via}' if via else ''}"
                for idx, exp, dec, via in proofs
            )
            raise RenderError(
                f"[{sid}] the scan rig did not decode the sticker in the frame it filmed - "
                f"{detail}. The pixels have to be genuinely decoded (CONTRACT_V2 V3); "
                f"fix the rig and re-capture instead of shipping a scan that never happened."
            )
        for idx, expected, _dec, via in good:
            lines.append(f"[{sid}] state {idx} decoded {expected} from the camera feed"
                         f"{f' (via {via})' if via else ''}")
    return lines


def fingerprint(job: SceneJob, previous: str) -> str:
    """Everything that can change a scene's pixels, in one hash."""
    h = hashlib.sha256()
    h.update(previous.encode())
    # compose.py owns the look; phone.py draws the phone body a phone shot is framed in,
    # and it can change without any shot on disk changing.
    for module in ("compose.py", "phone.py"):
        path = HERE / module
        h.update(f"{module}|{path.stat().st_mtime_ns if path.exists() else 0}".encode())
    h.update(f"look={C.LOOK}".encode())
    h.update(f"{job.narration_seconds:.4f}|{job.extra_tail:.3f}|{job.fade_out:.3f}".encode())
    for st in job.states:
        for png in (st.png, getattr(st, "scene_png", None)):
            if png is None:
                continue
            try:
                s = Path(png).stat()
                h.update(f"{Path(png).name}|{s.st_mtime_ns}|{s.st_size}".encode())
            except OSError:
                h.update(f"{Path(png).name}|missing".encode())
        h.update(
            f"{st.scroll}|{st.kind}|{getattr(st, 'state', '')}|{getattr(st, 'aim', None)}".encode()
        )
    plan = job.plan
    if plan is not None:
        h.update(repr((plan.n_frames, plan.caption, plan.moves, plan.clicks, plan.taps,
                       plan.swaps, plan.highlights, plan.cameras, plan.fixed,
                       sorted(plan.phone_states), plan.overlays, plan.caption_until,
                       plan.fade_out)).encode())
    return h.hexdigest()


# --------------------------------------------------------------------------
# audio
# --------------------------------------------------------------------------


def build_audio(jobs: Sequence[SceneJob], out_wav: Path) -> float:
    """One WAV for the whole film: per scene, LEAD_IN silence + speech + padding.

    Each padded scene is trimmed to exactly the length of its video clip, so the
    two tracks cannot drift no matter how the frame count rounded.
    """
    PADDED.mkdir(parents=True, exist_ok=True)
    parts: list[Path] = []
    for job in jobs:
        dest = PADDED / f"{job.index:02d}-{job.scene_id}.wav"
        exact = job.seconds
        if job.audio is not None and job.audio.exists():
            ffmpeg(
                [
                    "-i", str(job.audio),
                    "-af", f"adelay={int(round(C.LEAD_IN * 1000))}:all=1,apad",
                    "-t", f"{exact:.6f}",
                    "-ar", str(AUDIO_RATE), "-ac", str(AUDIO_CH), "-c:a", "pcm_s16le",
                    str(dest),
                ],
                f"pad audio for {job.scene_id}",
            )
        else:
            log.warning("[%s] no narration audio - filling %.2fs with silence", job.scene_id, exact)
            ffmpeg(
                [
                    "-f", "lavfi", "-i",
                    f"anullsrc=channel_layout={'stereo' if AUDIO_CH == 2 else 'mono'}:"
                    f"sample_rate={AUDIO_RATE}",
                    "-t", f"{exact:.6f}", "-c:a", "pcm_s16le", str(dest),
                ],
                f"silence for {job.scene_id}",
            )
        parts.append(dest)

    listing = PADDED / "concat.txt"
    listing.write_text(
        "".join(f"file '{p.as_posix()}'\n" for p in parts), encoding="utf-8"
    )
    ffmpeg(
        ["-f", "concat", "-safe", "0", "-i", str(listing), "-c", "copy", str(out_wav)],
        "concatenate narration",
    )
    return media_seconds(out_wav)


# --------------------------------------------------------------------------
# subtitles
# --------------------------------------------------------------------------

_SRT_BLOCK = re.compile(
    r"(\d+)\s*\n(\d\d):(\d\d):(\d\d),(\d\d\d)\s*-->\s*(\d\d):(\d\d):(\d\d),(\d\d\d)\s*\n(.*?)(?=\n\s*\n|\Z)",
    re.S,
)


def _srt_ts(seconds: float) -> str:
    seconds = max(0.0, seconds)
    ms = int(round(seconds * 1000))
    h, ms = divmod(ms, 3_600_000)
    m, ms = divmod(ms, 60_000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def retime_srt(jobs: Sequence[SceneJob], timings: dict[str, Any]) -> str | None:
    """Shift narrate.py's cues onto the timeline the compositor actually produced.

    narrate.py lays the SRT out on its own arithmetic; rounding each clip to a
    whole frame moves the real scene starts by a few milliseconds.  timings.json
    records how many sentences each scene contributed, so the cues can be split
    back up per scene and shifted by that scene's own delta.
    """
    if not OUT_SRT.exists():
        log.warning("no %s to retime - run narrate.py to get subtitles", OUT_SRT.name)
        return None
    text = OUT_SRT.read_text(encoding="utf-8")
    blocks = _SRT_BLOCK.findall(text)
    if not blocks:
        log.warning("%s has no parsable cues; leaving it alone", OUT_SRT.name)
        return None

    counts = [int((timings.get(j.scene_id) or {}).get("sentences") or 0) for j in jobs]
    if sum(counts) != len(blocks):
        log.warning(
            "SRT has %d cues but timings.json accounts for %d; leaving subtitle "
            "timings as narrate.py wrote them",
            len(blocks), sum(counts),
        )
        return None

    out: list[str] = []
    n = 0
    cursor = 0
    for job, count in zip(jobs, counts):
        old_start = float((timings.get(job.scene_id) or {}).get("start") or 0.0)
        delta = job.start - old_start
        for _ in range(count):
            b = blocks[cursor]
            cursor += 1
            n += 1
            t0 = int(b[1]) * 3600 + int(b[2]) * 60 + int(b[3]) + int(b[4]) / 1000
            t1 = int(b[5]) * 3600 + int(b[6]) * 60 + int(b[7]) + int(b[8]) / 1000
            body = b[9].strip("\n")
            out.append(f"{n}\n{_srt_ts(t0 + delta)} --> {_srt_ts(t1 + delta)}\n{body}\n")
    payload = "\n".join(out)
    OUT_SRT.write_text(payload, encoding="utf-8")
    N.record_deliverable(FILM, OUT_SRT)
    return payload


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------


def check_narration_current(script: Any) -> None:
    """Refuse to compose against narration recorded for different words (``--no-narrate``)."""
    timings = load_json(TIMINGS, f"{TIMINGS.relative_to(HERE)}")
    stale = []
    for scene in script.SCENES:
        row = timings.get(str(scene.id)) or {}
        recorded = row.get("text_hash")
        if recorded and recorded != N.text_hash(" ".join(str(scene.narration).split())):
            stale.append(str(scene.id))
    if stale:
        raise RenderError(
            f"the narration on disk was recorded for different words in: {', '.join(stale)}. "
            "Run without --no-narrate (cached segments are reused, so it is quick)."
        )


def collect_jobs(script: Any, only: set[str] | None) -> list[SceneJob]:
    timings = load_json(TIMINGS, "build/timings.json")
    scenes = list(script.SCENES)
    overlays = dict(getattr(script, "OVERLAYS", {}) or {})
    jobs: list[SceneJob] = []
    for i, scene in enumerate(scenes, start=1):
        sid = str(scene.id)
        row = timings.get(sid) or {}
        seconds = float(row.get("seconds") or 0.0)
        if seconds <= 0.0:
            raise RenderError(
                f"[{sid}] timings.json has no narration duration - run narrate.py "
                f"(or pass --no-narrate only when build/timings.json is complete)"
            )
        audio = Path(row["audio"]) if row.get("audio") else AUDIO / f"scene_{i:02d}.wav"
        if not audio.is_absolute():
            audio = (HERE / audio).resolve()
        jobs.append(
            SceneJob(
                index=i,
                scene=scene,
                scene_id=sid,
                states=C.load_states(BUILD, sid, scene),
                narration_seconds=seconds,
                audio=audio if audio.exists() else None,
                # the last scene holds its end card, then fades (C.END_HOLD, C.END_FADE)
                extra_tail=(C.END_ROOM_TONE + C.END_HOLD) if i == len(scenes) else 0.0,
                fade_out=C.END_FADE if i == len(scenes) else 0.0,
                overlays=tuple(overlays.get(sid, ())),
                clip=CLIPS / f"{i:02d}-{sid}.mp4",
                stamp=CLIPS / f"{i:02d}-{sid}.json",
                last_png=CLIPS / f"{i:02d}-{sid}.last.png",
            )
        )
    if only:
        unknown = only - {j.scene_id for j in jobs}
        if unknown:
            raise RenderError(
                f"--only names unknown scene(s): {', '.join(sorted(unknown))}. "
                f"Known ids: {', '.join(j.scene_id for j in jobs)}"
            )
    return jobs


def compose_all(
    jobs: Sequence[SceneJob],
    geometry: dict[str, Any],
    only: set[str] | None,
    force: bool,
    preset: str,
    crf: int,
    probe_every: int,
) -> None:
    CLIPS.mkdir(parents=True, exist_ok=True)
    previous_hash = ""
    prev_frame: np.ndarray | None = None
    cursor = C.DEFAULT_CURSOR_START
    total_frames = sum(
        max(1, int(round((C.LEAD_IN + j.narration_seconds + C.TAIL + j.extra_tail) * C.FPS)))
        for j in jobs
    )
    print(f"\n=== compose ({len(jobs)} scenes, ~{total_frames} frames) ===", flush=True)
    done_frames = 0
    wall = time.perf_counter()

    prev_job: SceneJob | None = None
    for job in jobs:
        job.plan = C.build_plan(
            job.scene,
            job.states,
            job.narration_seconds,
            geometry.get(job.scene_id, {}),
            cursor_start=cursor,
            strict=True,
            extra_tail=job.extra_tail,
            overlays=job.overlays,
            drift_from=_carried_drift(prev_job, job),
            fade_out=job.fade_out,
        )
        prev_job = job
        job.seconds = job.plan.n_frames / C.FPS
        want = fingerprint(job, previous_hash)
        selected = only is None or job.scene_id in only

        stamped = ""
        if job.stamp.exists():
            try:
                stamped = json.loads(job.stamp.read_text(encoding="utf-8")).get("hash", "")
            except (OSError, json.JSONDecodeError):
                stamped = ""
        # naming a scene in --only means "rebuild this one", always
        fresh = (
            not force
            and only is None
            and job.clip.exists()
            and job.last_png.exists()
            and stamped == want
        )
        if only is not None and not selected:
            # not in --only: keep the existing clip, but it must exist
            if not job.clip.exists():
                raise RenderError(
                    f"--only skipped {job.scene_id} but {job.clip.name} does not exist yet; "
                    f"run without --only once to build every clip"
                )
            fresh = True

        kind = "phone" if job.plan.phone_states else "page"
        if fresh:
            job.reused = True
            if job.last_png.exists():
                prev_frame = np.asarray(Image.open(job.last_png).convert("RGB"), dtype=np.uint8)
            else:
                log.warning(
                    "[%s] reusing a clip with no stored last frame - the next scene "
                    "will cut instead of dissolving", job.scene_id,
                )
                prev_frame = None
            # trust the file on disk, not the recomputed plan, so the audio track
            # is padded to the length the video actually is
            job.seconds = media_seconds(job.clip)
            done_frames += int(round(job.seconds * C.FPS))
            print(
                f"  [{job.index:02d}/{len(jobs)}] {job.scene_id:<20} {kind:<5} "
                f"{int(round(job.seconds * C.FPS)):5d}f {job.seconds:6.2f}s  reused"
                f"{' ' * 26}elapsed {time.perf_counter() - wall:6.1f}s",
                flush=True,
            )
        else:
            res = C.render_scene(
                job.plan,
                job.clip,
                prev_frame=prev_frame,
                preset=preset,
                crf=crf,
                probe_dir=BUILD / "probe" if probe_every else None,
                probe_every=probe_every,
            )
            job.elapsed = res.elapsed
            prev_frame = res.last_frame
            Image.fromarray(prev_frame).save(job.last_png)
            job.stamp.write_text(
                json.dumps({"hash": want, "frames": res.frames, "seconds": res.seconds}, indent=2),
                encoding="utf-8",
            )
            done_frames += res.frames
            pct = 100.0 * done_frames / max(1, total_frames)
            spent = time.perf_counter() - wall
            eta = spent * (total_frames - done_frames) / max(1, done_frames)
            print(
                f"  [{job.index:02d}/{len(jobs)}] {job.scene_id:<20} {kind:<5} "
                f"{res.frames:5d}f {res.seconds:6.2f}s  {res.elapsed:6.1f}s "
                f"({res.frames / max(res.elapsed, 1e-6):5.0f} fps)  {pct:5.1f}%  "
                f"elapsed {spent:6.1f}s  eta {eta:5.0f}s",
                flush=True,
            )
        cursor = job.plan.cursor_end
        previous_hash = want

    # scene start times on the final timeline
    t = 0.0
    for job in jobs:
        job.start = t
        t += job.seconds


def _carried_drift(prev: SceneJob | None, job: SceneJob) -> float | None:
    """The slide drift a scene inherits when it opens on the slide the last one ended on.

    Scene 07 ends on the umbrella and scene 08 opens on it. Restarting the push at 1.0x under
    the head dissolve blended two framings of the same drawing - every line of text doubled.
    Carrying the previous scene's scale on makes the dissolve a dissolve between identical
    frames, which is to say invisible.
    """
    if prev is None or prev.plan is None or prev.plan.drift_end is None:
        return None
    if not job.states or job.states[0].kind != "slide" or not prev.states:
        return None
    before = C.plan_transitions(prev.scene)
    last_key = before[-1].key if before else C._target_key(C._seq_members(prev.scene.shot)[0], None)
    first_key = C._target_key(C._seq_members(job.scene.shot)[0], None)
    return prev.plan.drift_end if last_key == first_key else None


def concat_clips(jobs: Sequence[SceneJob], dest: Path) -> None:
    listing = CLIPS / "concat.txt"
    listing.write_text(
        "".join(f"file '{j.clip.as_posix()}'\n" for j in jobs), encoding="utf-8"
    )
    ffmpeg(
        ["-f", "concat", "-safe", "0", "-i", str(listing), "-c", "copy", str(dest)],
        "concatenate scene clips",
    )


def mux(video: Path, audio: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    ffmpeg(
        [
            "-i", str(video), "-i", str(audio),
            "-map", "0:v:0", "-map", "1:a:0",
            "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
            # No -shortest: build_audio pads the narration to exactly the video's length, and
            # -shortest still trimmed the last frames of an equal-length video (16543 of 16546,
            # even with max_interleave_delta 0) - here, the last tenth of the end card's fade.
            "-movflags", "+faststart", "-max_interleave_delta", "0",
            str(dest),
        ],
        "mux narration onto the video",
    )


def verify(dest: Path, jobs: Sequence[SceneJob]) -> list[str]:
    """ffprobe the deliverable and check it against the contract's quality bar."""
    info = ffprobe_json(dest)
    problems: list[str] = []
    vs = [s for s in info.get("streams", []) if s.get("codec_type") == "video"]
    aus = [s for s in info.get("streams", []) if s.get("codec_type") == "audio"]
    if len(vs) != 1:
        problems.append(f"expected 1 video stream, found {len(vs)}")
    if len(aus) != 1:
        problems.append(f"expected 1 audio stream, found {len(aus)}")

    dur = float(info.get("format", {}).get("duration") or 0.0)
    print("\n=== result ===")
    print(f"  file      {dest}  ({dest.stat().st_size / 1e6:.1f} MB)")
    print(f"  duration  {dur:.2f}s  ({dur / 60:.2f} min)")
    if vs:
        v = vs[0]
        print(
            f"  video     {v.get('codec_name')} {v.get('width')}x{v.get('height')} "
            f"{v.get('r_frame_rate')} {v.get('pix_fmt')} "
            f"{float(v.get('duration') or dur):.2f}s"
        )
        if v.get("codec_name") != "h264":
            problems.append(f"video codec is {v.get('codec_name')}, expected h264")
        if v.get("pix_fmt") != "yuv420p":
            problems.append(f"pix_fmt is {v.get('pix_fmt')}, expected yuv420p")
        if (v.get("width"), v.get("height")) != (C.W, C.H):
            problems.append(f"video is {v.get('width')}x{v.get('height')}, expected {C.W}x{C.H}")
    if aus:
        a = aus[0]
        print(
            f"  audio     {a.get('codec_name')} {a.get('sample_rate')}Hz "
            f"{a.get('channels')}ch {float(a.get('duration') or dur):.2f}s"
        )
        if a.get("codec_name") != "aac":
            problems.append(f"audio codec is {a.get('codec_name')}, expected aac")
    if vs and aus:
        vd = float(vs[0].get("duration") or dur)
        ad = float(aus[0].get("duration") or dur)
        if abs(vd - ad) > 0.5:
            problems.append(f"video is {vd:.2f}s but audio is {ad:.2f}s (>0.5s apart)")

    expected = sum(j.seconds for j in jobs)
    if abs(dur - expected) > 0.6:
        problems.append(f"duration {dur:.2f}s but the scene clips add up to {expected:.2f}s")
    # Length is a target, not a contract check: say so, do not fail the render for it.
    if dur and not TARGET_MIN_SECONDS <= dur <= TARGET_MAX_SECONDS:
        print(
            f"  note      {dur / 60:.1f} min is outside the {FILM.name} film's "
            f"{FILM.target_min:g}-{FILM.target_max:g} minute target - trim or extend the "
            f"narration in {FILM.script_module}.py"
        )
    return problems


def write_timeline(jobs: Sequence[SceneJob]) -> None:
    TIMELINE.write_text(
        json.dumps(
            {
                j.scene_id: {
                    "index": j.index,
                    "start": round(j.start, 3),
                    "seconds": round(j.seconds, 3),
                    "frames": j.plan.n_frames if j.plan else 0,
                    "narration": round(j.narration_seconds, 3),
                    "clip": j.clip.as_posix(),
                }
                for j in jobs
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Render a Home SOC walkthrough film end to end.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--script", default=N.DEFAULT_FILM, metavar="FILM",
                    help="which film: everyday (out/HomeSOC-walkthrough.mp4) or technical "
                         "(out/HomeSOC-walkthrough-technical.mp4)")
    ap.add_argument("--only", metavar="ID[,ID]", help="recompose only these scene ids")
    ap.add_argument("--no-seed", action="store_true", help="reuse video/demo_data")
    ap.add_argument(
        "--reseed", action="store_true",
        help="rebuild video/demo_data even though it exists. Re-rolls the sticker token and "
             "every seeded figure, so re-check the numbers script.py speaks afterwards.",
    )
    ap.add_argument("--no-narrate", action="store_true", help="reuse build/audio + timings.json")
    ap.add_argument("--no-capture", action="store_true", help="reuse build/shots")
    ap.add_argument("--force", action="store_true", help="recompose every scene clip")
    ap.add_argument(
        "--no-scan-check", action="store_true",
        help="skip the CONTRACT_V2 V3 proof that every narrated scan was a real decode. "
             "For iterating on other scenes only - a render made with this flag must not "
             "be published.",
    )
    ap.add_argument("--preset", default="fast", help="x264 preset")
    ap.add_argument("--crf", type=int, default=19, help="x264 CRF")
    ap.add_argument("--probe-every", type=int, default=0, metavar="N",
                    help="also dump every Nth frame to build/probe as a PNG")
    ap.add_argument("--list", action="store_true", help="list the scenes and exit")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    # A child's line may carry any character (U+FFFD from a replaced byte, a curly quote from
    # a page title); a cp1252 console must not crash the render over printing it.
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    for exe in ("ffmpeg", "ffprobe"):
        if shutil.which(exe) is None:
            print(f"error: {exe} is not on PATH", file=sys.stderr)
            return 2

    started = time.perf_counter()
    try:
        configure(N.select_film(args.script))
    except N.NarrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    only = {s.strip() for s in args.only.split(",") if s.strip()} if args.only else None
    print(f"film: {FILM.name}  ({FILM.script_module}.py, {FILM.slides_module}.py, "
          f"look {FILM.look})  build {BUILD}  ->  {OUT_MP4}", flush=True)

    if args.list:
        try:
            script = load_script()
        except RenderError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for i, sc in enumerate(script.SCENES, 1):
            spoken = N.strip_marks(sc.narration)
            beats = len(N.BEAT_RE.findall(sc.narration))
            print(f"  {i:02d}  {sc.id:<28} {len(spoken.split()):4d} words  {beats:2d} beats  "
                  f"caption={sc.caption!r}")
        return 0

    try:
        py = sys.executable
        film_arg = ["--script", FILM.name]
        if not args.no_seed:
            seed = HERE / "seed_demo.py"
            if not seed.exists():
                log.warning("video/seed_demo.py does not exist yet - skipping the seed step")
            elif DEMO_DB.exists() and not args.reseed:
                # Reusing it is the correct default, not a shortcut. seed_demo.py mints a
                # fresh random sticker token and re-rolls every "relative to now" timestamp
                # on each run, so re-seeding here would invalidate three things that were
                # already settled against the current database: the figures narrate.py has
                # *already spoken* into build/audio (the DNS totals and the camera's block
                # rate are read off the seed and written into script.py by hand), the shots
                # capture.py has already taken, and the QR baked into build/scene_camera.*.
                # A seed is a deliberate act with a re-verification pass after it; a render
                # is not. Pass --reseed to rebuild, and re-check the spoken figures.
                print("\n=== seed demo data ===", flush=True)
                print(f"    reusing {DEMO_DB} (pass --reseed to rebuild it)", flush=True)
            else:
                cmd = [py, str(seed)]
                if DEMO_DB.exists():
                    cmd.append("--force")
                run_step("seed demo data", cmd, SEED_TIMEOUT)
        if not args.no_narrate:
            run_step("narrate", [py, str(HERE / "narrate.py"), *film_arg], NARRATE_TIMEOUT)
        # Imported only now: a script that times actions with narrate.beat_at()/phrase_at()
        # must see the beats narration has just measured.
        script = load_script(fresh=True)
        check_narration_current(script)
        if not args.no_capture:
            cmd = [py, str(HERE / "capture.py"), *film_arg]
            if only:
                cmd += ["--only", ",".join(sorted(only))]
            run_step("capture", cmd, CAPTURE_TIMEOUT)

        timings = load_json(TIMINGS, "build/timings.json")
        geometry = load_json(GEOMETRY, "build/geometry.json", required=False)
        if not MANIFEST.exists():
            log.warning("%s is missing - falling back to globbing build/shots", MANIFEST.name)

        print("\n=== scan rig (CONTRACT_V2 V3) ===", flush=True)
        if args.no_scan_check:
            print("    !! SKIPPED with --no-scan-check.", flush=True)
            print("    !! This render may narrate a manual pick as a scan. Do not publish it.",
                  flush=True)
        else:
            manifest = load_json(MANIFEST, "build/shots_manifest.json", required=False)
            for line in check_scan_rig(script, only, manifest):
                print(f"    {line}", flush=True)

        jobs = collect_jobs(script, only)
        compose_all(jobs, geometry, only, args.force, args.preset, args.crf, args.probe_every)

        BUILD.mkdir(parents=True, exist_ok=True)
        silent = BUILD / "video_only.mp4"
        print("\n=== assemble ===", flush=True)
        concat_clips(jobs, silent)
        print(f"    video track {media_seconds(silent):.2f}s", flush=True)
        track = BUILD / "narration.wav"
        secs = build_audio(jobs, track)
        print(f"    audio track {secs:.2f}s", flush=True)
        OUT_MP4.parent.mkdir(parents=True, exist_ok=True)
        N.archive_previous(FILM)          # never overwrite a film this pipeline did not write
        mux(silent, track, OUT_MP4)
        N.record_deliverable(FILM, OUT_MP4)

        write_timeline(jobs)
        srt = retime_srt(jobs, timings)
        problems = verify(OUT_MP4, jobs)
        print(f"  srt       {OUT_SRT if srt is not None else '(left as narrate.py wrote it)'}")
        print(f"  timeline  {TIMELINE}")
        reused = sum(1 for j in jobs if j.reused)
        print(f"  scenes    {len(jobs)} ({reused} reused, {len(jobs) - reused} composed)")
        print(f"  total     {time.perf_counter() - started:.1f}s")
        if problems:
            print("\n  PROBLEMS:")
            for p in problems:
                print(f"    - {p}")
            return 1
        print("\n  OK - every ffprobe check passed.")
        return 0
    except (RenderError, N.NarrationError, C.ComposeError, FileNotFoundError) as exc:
        print(f"\nerror: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
