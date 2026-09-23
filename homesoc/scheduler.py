"""Single-threaded job scheduler with per-job locks.

One worker thread runs jobs one after another. That is a feature, not a
limitation: a home network should never see the discovery sweep, a service scan
and a feed download hammering it at the same time, and SQLite prefers one writer.
``run_now`` queues a job ahead of the timetable (the dashboard buttons); the
per-job lock guarantees the same job never overlaps even when a caller runs it
synchronously with ``wait=True``.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from homesoc import db
from homesoc.util import to_iso, utcnow_iso

logger = logging.getLogger(__name__)

# SPEC-GAP: how many consecutive failures count as "failing repeatedly" (SOC-SYS-004)
# is not specified; three in a row separates a flaky network from a broken job.
FAILING_REPEATEDLY = 3

# Watchdog. Jobs run one after another on one thread, so a job that hangs (a LAN device dripping
# a UPnP answer one byte at a time was the real case) silently stops every other job. Network
# code now carries its own wall-clock limits; the watchdog is the backstop that makes an overrun
# visible in the activity feed and the jobs table instead of leaving the monitor quietly blind.
JOB_OVERRUN_SEC = 30 * 60
WATCHDOG_INTERVAL_SEC = 30.0


@dataclass
class Job:
    """A unit of scheduled work.

    ``interval_sec <= 0`` means manual-only (never auto-scheduled, only via run_now);
    ``at_hour`` (local hour 0-23) replaces the interval with "once a day at that hour"
    (SPEC-GAP: needed for the digest job; the spec's Job has only an interval).
    """

    name: str
    interval_sec: int
    func: Callable[[], None]
    run_at_start: bool = True
    at_hour: int | None = None
    description: str = ""
    budget_sec: int | None = None  # longest a run may take before the watchdog reports it

    @property
    def overrun_after(self) -> int:
        return JOB_OVERRUN_SEC if self.budget_sec is None else max(0, int(self.budget_sec))

    @property
    def manual_only(self) -> bool:
        return self.interval_sec <= 0 and self.at_hour is None


@dataclass
class _State:
    lock: threading.Lock = field(default_factory=threading.Lock)
    next_run: float | None = None  # epoch seconds; None = not scheduled
    running: bool = False
    queued: bool = False
    runs: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    last_run: str | None = None
    last_status: str | None = None
    last_duration_sec: float | None = None
    last_error: str | None = None
    started_mono: float | None = None   # monotonic start of the current run
    overrun_reported: bool = False


class Scheduler:
    def __init__(self, cfg: Any, conn: sqlite3.Connection, jobs: list[Job]):
        self.cfg = cfg
        self.conn = conn
        self.jobs: dict[str, Job] = {}
        self._state: dict[str, _State] = {}
        for job in jobs:
            if job.name in self.jobs:
                raise ValueError(f"duplicate job name {job.name!r}")
            self.jobs[job.name] = job
            self._state[job.name] = _State()
        self._queue: deque[str] = deque()
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._watchdog: threading.Thread | None = None
        self._done_events: dict[str, threading.Event] = {}
        self._load_history()

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        now = time.time()
        for name, job in self.jobs.items():
            state = self._state[name]
            state.next_run = self._initial_next_run(job, now)
            self._persist(name)
        self._thread = threading.Thread(target=self._loop, name="homesoc-scheduler", daemon=True)
        self._thread.start()
        self._watchdog = threading.Thread(target=self._watch, name="homesoc-scheduler-watchdog", daemon=True)
        self._watchdog.start()
        logger.info("scheduler started with %d jobs", len(self.jobs))

    def stop(self, timeout: float = 30.0) -> None:
        self._stop.set()
        with self._cond:
            self._cond.notify_all()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
        if self._watchdog and self._watchdog.is_alive():
            self._watchdog.join(min(timeout, WATCHDOG_INTERVAL_SEC + 1))
        self._thread = None
        self._watchdog = None
        logger.info("scheduler stopped")

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ---------------------------------------------------------------- api

    def run_now(self, name: str, *, wait: bool = False, timeout: float | None = None) -> bool:
        """Run ``name`` as soon as possible.

        Returns False when the job is unknown, already running or already queued —
        a second click on "Run scan" must not stack up work. With ``wait=True`` the
        call blocks until the run finishes (or runs inline when no worker thread is
        alive, which is what the CLI and tests need).
        """
        job = self.jobs.get(name)
        if job is None:
            logger.warning("run_now: unknown job %r", name)
            return False
        state = self._state[name]
        if not self.running:
            if state.running:
                return False
            return self._execute(job)
        with self._cond:
            if state.running or state.queued:
                return False
            state.queued = True
            self._queue.append(name)
            done = self._done_events.setdefault(name, threading.Event())
            done.clear()
            self._cond.notify_all()
        if wait:
            done.wait(timeout)
        return True

    def is_running(self, name: str) -> bool:
        state = self._state.get(name)
        return bool(state and state.running)

    def status(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name, job in self.jobs.items():
            s = self._state[name]
            out.append(
                {
                    "name": name,
                    "description": job.description,
                    "interval_sec": job.interval_sec,
                    "at_hour": job.at_hour,
                    "manual_only": job.manual_only,
                    "running": s.running,
                    "queued": s.queued,
                    "last_run": s.last_run,
                    "last_status": s.last_status,
                    "last_duration_sec": s.last_duration_sec,
                    "last_error": s.last_error,
                    "next_run": _epoch_iso(s.next_run),
                    "runs": s.runs,
                    "failures": s.failures,
                    "consecutive_failures": s.consecutive_failures,
                    "failing_repeatedly": s.consecutive_failures >= FAILING_REPEATEDLY,
                    "running_for_sec": self._running_for(s),
                    "overrunning": self._is_overrunning(job, s),
                }
            )
        return out

    def failing_jobs(self) -> list[dict[str, Any]]:
        """Jobs whose last FAILING_REPEATEDLY runs all failed — input for SOC-SYS-004."""
        return [j for j in self.status() if j["failing_repeatedly"]]

    # ------------------------------------------------------------ watchdog

    @staticmethod
    def _running_for(state: _State) -> float | None:
        if not state.running or state.started_mono is None:
            return None
        return round(time.monotonic() - state.started_mono, 1)

    def _is_overrunning(self, job: Job, state: _State) -> bool:
        elapsed = self._running_for(state)
        return elapsed is not None and elapsed > job.overrun_after

    def check_overruns(self) -> list[str]:
        """Report (once per run) every job past its budget; returns the names reported now."""
        reported: list[str] = []
        for name, job in self.jobs.items():
            state = self._state[name]
            if state.overrun_reported or not self._is_overrunning(job, state):
                continue
            state.overrun_reported = True
            minutes = int((self._running_for(state) or 0) // 60)
            waiting = [n for n, s in self._state.items() if n != name and s.next_run is not None and s.next_run <= time.time()]
            message = (f"job {name} has been running for {minutes} min, past its {job.overrun_after // 60} min budget; "
                       f"{len(waiting)} other scheduled job(s) are waiting behind it")
            logger.warning(message)
            try:
                db.record_event(self.conn, "warning", "scheduler", message,
                                {"job": name, "running_min": minutes, "waiting": waiting[:20]})
            except sqlite3.Error:
                logger.exception("cannot record the overrun of job %s", name)
            reported.append(name)
        return reported

    def _watch(self) -> None:
        while not self._stop.wait(WATCHDOG_INTERVAL_SEC):
            try:
                self.check_overruns()
            except Exception:  # the watchdog must never die quietly either
                logger.exception("scheduler watchdog check failed")

    # ------------------------------------------------------------ internals

    def _loop(self) -> None:
        while not self._stop.is_set():
            job = self._next_job()
            if job is None:
                continue
            self._execute(job)
            done = self._done_events.get(job.name)
            if done is not None:
                done.set()

    def _next_job(self) -> Job | None:
        """Block until a job is queued or due; returns None on wake-ups without work."""
        with self._cond:
            while not self._stop.is_set():
                if self._queue:
                    name = self._queue.popleft()
                    self._state[name].queued = False
                    return self.jobs[name]
                now = time.time()
                due_name: str | None = None
                soonest: float | None = None
                for name, state in self._state.items():
                    if state.next_run is None:
                        continue
                    if soonest is None or state.next_run < soonest:
                        soonest, due_name = state.next_run, name
                if due_name is not None and soonest is not None and soonest <= now:
                    return self.jobs[due_name]
                wait_for = 1.0 if soonest is None else max(0.05, min(1.0, soonest - now))
                self._cond.wait(wait_for)
            return None

    def _execute(self, job: Job) -> bool:
        state = self._state[job.name]
        if not state.lock.acquire(blocking=False):
            logger.info("job %s already running; skipped", job.name)
            return False
        state.running = True
        state.started_mono = time.monotonic()
        state.overrun_reported = False
        started = time.time()
        state.last_run = utcnow_iso()
        status, error = "ok", None
        try:
            logger.info("job %s starting", job.name)
            job.func()
        except Exception as exc:  # a broken job must never take the scheduler down
            status, error = "error", f"{type(exc).__name__}: {exc}"[:2000]
            logger.exception("job %s failed", job.name)
        finally:
            duration = time.time() - started
            state.running = False
            state.started_mono = None
            state.runs += 1
            state.last_status = status
            state.last_duration_sec = round(duration, 3)
            state.last_error = error
            if status == "ok":
                state.consecutive_failures = 0
            else:
                state.failures += 1
                state.consecutive_failures += 1
            state.next_run = self._next_after_run(job, time.time())
            state.lock.release()
            self._record(job, status, duration, error)
        return True

    def _record(self, job: Job, status: str, duration: float, error: str | None) -> None:
        try:
            self._persist(job.name)
            db.record_metric(self.conn, "job.duration", duration, {"job": job.name, "status": status})
            level = "info" if status == "ok" else "error"
            message = f"job {job.name} {status} in {duration:.1f}s" + (f": {error}" if error else "")
            db.record_event(self.conn, level, "scheduler", message, {"job": job.name, "duration_sec": round(duration, 3)})
        except sqlite3.Error:
            logger.exception("cannot record job %s outcome", job.name)

    def _persist(self, name: str) -> None:
        s = self._state[name]
        db.write(
            self.conn,
            "INSERT INTO jobs(name, last_run, last_status, last_duration_sec, next_run, runs, failures, last_error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET last_run = excluded.last_run, last_status = excluded.last_status, "
            "last_duration_sec = excluded.last_duration_sec, next_run = excluded.next_run, runs = excluded.runs, "
            "failures = excluded.failures, last_error = excluded.last_error",
            (name, s.last_run, s.last_status, s.last_duration_sec, _epoch_iso(s.next_run), s.runs, s.failures, s.last_error),
        )

    def _load_history(self) -> None:
        """Carry run counters across restarts so the telemetry page is not reset daily."""
        try:
            rows = db.query(self.conn, "SELECT * FROM jobs")
        except sqlite3.Error:
            return
        for row in rows:
            state = self._state.get(str(row["name"]))
            if state is None:
                continue
            state.runs = int(row["runs"] or 0)
            state.failures = int(row["failures"] or 0)
            state.last_run = row["last_run"]
            state.last_status = row["last_status"]
            state.last_duration_sec = row["last_duration_sec"]
            state.last_error = row["last_error"]

    @staticmethod
    def _initial_next_run(job: Job, now: float) -> float | None:
        if job.manual_only:
            return None
        if job.at_hour is not None:
            return _next_local_hour(job.at_hour, now)
        return now if job.run_at_start else now + job.interval_sec

    @staticmethod
    def _next_after_run(job: Job, now: float) -> float | None:
        if job.manual_only:
            return None
        if job.at_hour is not None:
            return _next_local_hour(job.at_hour, now)
        return now + job.interval_sec


def _next_local_hour(hour: int, now: float) -> float:
    """Epoch time of the next occurrence of ``hour:00`` local time, strictly after ``now``."""
    hour = max(0, min(23, int(hour)))
    local_now = datetime.fromtimestamp(now).astimezone()
    target = local_now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= local_now:
        target += timedelta(days=1)
    return target.timestamp()


def _epoch_iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return to_iso(datetime.fromtimestamp(epoch, tz=timezone.utc))


__all__ = ["FAILING_REPEATEDLY", "Job", "Scheduler"]
