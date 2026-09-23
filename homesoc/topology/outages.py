"""Learning blast radius from real outages (SPEC addendum C3).

The strongest edges in the map are not modelled, they are watched: ``device_sightings``
already records who was present every time discovery ran, and a set of devices that vanished
from the same sweep is evidence no amount of inference can match.

Two things decide whether that evidence is worth anything.

**Honest resolution.** Discovery runs every ``schedule.discovery_minutes`` (default 10), so
"dropped together" can only ever mean "went missing in the same discovery cycle". It does not
mean "within seconds", and nothing in this module, the API or the UI may imply that it does.
:class:`Outage` therefore carries ``cycle_seconds``: not today's setting, but the cadence that
was actually in force when the outage happened, measured from the sightings themselves. Every
sentence this module produces for a human says the resolution out loud.

**The phone that goes to work.** A device that is reliably absent every weekday evening is not
an outage, and three of them leaving together is not a network event — it is a family going
out. Before anything is recorded, every device gets a baseline of how often and at what hour it
is normally missing, and routine absences are dropped. Without that guard this feature would
produce a confident, daily, completely wrong alert.
"""

from __future__ import annotations

import bisect
import logging
import sqlite3
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from homesoc import db
from homesoc.util import iso_ago, parse_iso, to_iso

logger = logging.getLogger(__name__)

#: How far back detection reads sightings. Long enough to see a weekly pattern several times
#: over, short enough that a year-old database does not turn one job into a table scan.
HISTORY_DAYS = 30
#: Fallback cadence when the config cannot be read and the data is too thin to measure one.
DEFAULT_INTERVAL_SECONDS = 600

#: A device must have been around for this many cycles before its absence can count as a drop:
#: a device discovered ten minutes ago has no baseline and no history to be unusual against.
MIN_HISTORY_CYCLES = 3

#: The routine-absence guard. A device is excused when it is absent often enough overall *and*
#: is usually absent at this hour. Both halves are needed: "absent 40% of the time" alone would
#: excuse a genuinely flaky device, and "usually absent at 3am" alone would excuse a device
#: that has only ever been seen twice.
ROUTINE_MIN_RATE = 0.10
ROUTINE_HOUR_RATE = 0.5
ROUTINE_MIN_HOUR_SAMPLES = 2
#: ...and it must have happened on this many different days. Without this a single outage is
#: its own alibi: the only time the device was ever missing was 3am last Tuesday, so 100% of
#: its absences are at 3am, so 3am is "normal" — and the one event worth recording is thrown
#: away. A habit needs at least two days to be a habit.
ROUTINE_MIN_DAYS = 2

#: Device kinds that can plausibly take other devices down with them, used to label a trigger
#: when the gateway is not among the members.
INFRASTRUCTURE_KINDS: frozenset[str] = frozenset({"router", "gateway", "ap", "access_point", "switch", "nas", "hub"})


@dataclass(frozen=True)
class Outage:
    """Devices that went missing from the same discovery cycle.

    ``cycle_seconds`` is the discovery interval in force at the time. It is part of the record
    because it is the resolution of every claim made about this outage, and because the owner
    can change ``schedule.discovery_minutes`` tomorrow.
    """

    id: int
    started_at: str
    ended_at: str | None
    cycle_seconds: int
    members: list[int]
    trigger_device_id: int | None
    trigger_kind: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "started_at": self.started_at, "ended_at": self.ended_at,
            "cycle_seconds": self.cycle_seconds, "members": list(self.members),
            "trigger_device_id": self.trigger_device_id, "trigger_kind": self.trigger_kind,
            "resolution": resolution_note(self.cycle_seconds),
        }


@dataclass(frozen=True)
class Cycle:
    """One discovery run, reconstructed from the timestamps it wrote."""

    index: int
    start: float
    end: float
    seen: frozenset[int]

    @property
    def started_at(self) -> str:
        return to_iso(datetime.fromtimestamp(self.start, tz=timezone.utc))

    @property
    def hour(self) -> int:
        return datetime.fromtimestamp(self.start, tz=timezone.utc).hour


@dataclass(frozen=True)
class Baseline:
    """How often, and at what hour, a device is normally missing."""

    device_id: int
    cycles: int
    absent: int
    hour_absent: Mapping[int, int] = field(default_factory=dict)
    hour_total: Mapping[int, int] = field(default_factory=dict)
    #: hour -> on how many different dates the device was missing at that hour
    hour_absent_days: Mapping[int, int] = field(default_factory=dict)

    @property
    def rate(self) -> float:
        return (self.absent / self.cycles) if self.cycles else 0.0

    def hour_rate(self, hour: int) -> float:
        total = int(self.hour_total.get(hour, 0))
        return (int(self.hour_absent.get(hour, 0)) / total) if total else 0.0

    def is_routine(self, hour: int) -> bool:
        """True when being missing at this hour is this device's normal behaviour.

        All three conditions have to hold: it is missing often enough to have a pattern, it is
        usually missing at *this* hour, and it has done so on more than one day. Drop any of
        them and the guard either excuses a genuinely flaky device or excuses the single outage
        that was the only thing worth reporting.
        """
        if int(self.hour_total.get(hour, 0)) < ROUTINE_MIN_HOUR_SAMPLES:
            return False
        if int(self.hour_absent_days.get(hour, 0)) < ROUTINE_MIN_DAYS:
            return False
        return self.rate >= ROUTINE_MIN_RATE and self.hour_rate(hour) >= ROUTINE_HOUR_RATE

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id, "cycles": self.cycles, "absent": self.absent,
            "rate": round(self.rate, 3),
            "hour_rate": {str(h): round(self.hour_rate(h), 3) for h in sorted(self.hour_total)},
            "hour_absent_days": {str(h): int(n) for h, n in sorted(self.hour_absent_days.items())},
        }


# ------------------------------------------------------------------- resolution


def discovery_interval_seconds(conn: sqlite3.Connection) -> int:
    """``schedule.discovery_minutes`` as seconds, from the settings table or the default."""
    raw = db.get_setting(conn, "schedule.discovery_minutes", "")
    try:
        minutes = int(str(raw).strip()) if raw else 0
    except ValueError:
        minutes = 0
    if minutes <= 0:
        try:
            from homesoc import config

            minutes = int(config.load(conn).schedule.discovery_minutes)
        except Exception as exc:
            logger.debug("cannot read schedule.discovery_minutes: %s", exc)
            minutes = 0
    return max(60, minutes * 60) if minutes > 0 else DEFAULT_INTERVAL_SECONDS


def resolution_note(cycle_seconds: int) -> str:
    """The sentence every surface reporting an observed outage has to carry."""
    minutes = max(1, int(cycle_seconds) // 60)
    return (f"Discovery ran every {minutes} minute{'s' if minutes != 1 else ''} at the time, so "
            f"\"dropped together\" means \"went missing in the same {minutes}-minute discovery cycle\", "
            "not \"within seconds\".")


def measured_cycle_seconds(cycles: Sequence[Cycle], index: int, fallback: int, span: int = 10) -> int:
    """The cadence actually in force around cycle ``index``, measured from the data.

    Median rather than mean: one long gap (the machine was asleep, the job was paused) must not
    stretch the recorded resolution of every outage near it.
    """
    window = [c for c in cycles[max(0, index - span):index + 1]]
    gaps = [round(b.start - a.start) for a, b in zip(window, window[1:]) if b.start > a.start]
    gaps = [g for g in gaps if 0 < g <= 24 * 3600]
    if len(gaps) < 2:
        return int(fallback)
    return max(60, int(statistics.median(gaps)))


# ----------------------------------------------------------------------- cycles


def discovery_cycles(conn: sqlite3.Connection, *, since: str | None = None, interval_seconds: int | None = None) -> list[Cycle]:
    """Reconstruct the discovery runs from ``device_sightings``.

    ``scanners.discovery`` stamps every sighting in one sweep with the same ``utcnow_iso()``,
    so a run is an exact group and clustering on any small gap recovers it. The threshold is
    still derived from the interval rather than hard-coded, so that a database written at a
    different cadence than today's configuration (an imported database, a changed setting, a
    test) splits into the cycles it actually had rather than the ones we expect it to have.
    """
    interval = int(interval_seconds or discovery_interval_seconds(conn))
    start_iso = since or iso_ago(days=HISTORY_DAYS)
    rows = db.query(
        conn,
        "SELECT device_id, seen_at FROM device_sightings WHERE seen_at >= ? ORDER BY seen_at, device_id",
        (start_iso,),
    )
    gap = max(5.0, min(interval / 4.0, 60.0))
    # Ordered by the parsed instant, not the stored text. The two agree for every stamp Home SOC
    # writes (fixed-width UTC), but only an instant order guarantees what detection relies on:
    # each cycle ends strictly after the one before it.
    stamped: list[tuple[float, int]] = []
    for row in rows:
        parsed = parse_iso(str(row["seen_at"]))
        if parsed is None:
            continue
        stamped.append((parsed.timestamp(), int(row["device_id"])))
    stamped.sort()
    cycles: list[Cycle] = []
    current: list[int] = []
    start = end = 0.0
    for ts, device_id in stamped:
        if current and ts - end > gap:
            cycles.append(Cycle(len(cycles), start, end, frozenset(current)))
            current = []
        if not current:
            start = ts
        end = ts
        current.append(device_id)
    if current:
        cycles.append(Cycle(len(cycles), start, end, frozenset(current)))
    return cycles


def device_tolerances(cycles: Sequence[Cycle], window_seconds: float) -> dict[int, float]:
    """How long each device may go unseen before it counts as gone.

    The floor is ``window_seconds`` (2 × the discovery interval — the same grace
    ``scanners.discovery`` allows before it sets ``online = 0``). The reason it is only a floor
    is that not every device is found by every sweep: a sleeping phone answers ARP when it feels
    like it, and a database whose sightings are sparser than the discovery cadence would
    otherwise read as a network collapsing several times an hour. So each device is measured
    against *its own* normal rhythm, and a device nobody sees often cannot generate an outage
    by being itself. Making this tolerance too tight does not produce more information, it
    produces confident nonsense.
    """
    seen_at: dict[int, list[float]] = {}
    for cycle in cycles:
        for device_id in cycle.seen:
            seen_at.setdefault(device_id, []).append(cycle.end)
    out: dict[int, float] = {}
    for device_id, stamps in seen_at.items():
        gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        typical = statistics.median(gaps) if len(gaps) >= 3 else 0.0
        out[device_id] = max(float(window_seconds), 2.0 * typical)
    return out


def presence(cycles: Sequence[Cycle], tolerances: Mapping[int, float]) -> list[dict[int, bool]]:
    """Per cycle, whether each device counts as present — seen within its own tolerance.

    A dense cycles x devices matrix, kept for diagnostics and tests. **Detection does not use
    it**: every device that ever appeared costs one entry per cycle, so a LAN device minting
    identities at discovery's caps drove it past a gigabyte. :func:`detect_outages` works from
    :func:`absence_tracks` instead, which is proportional to the sightings themselves.
    """
    everyone = sorted({d for c in cycles for d in c.seen})
    last_seen: dict[int, float] = {}
    out: list[dict[int, bool]] = []
    for cycle in cycles:
        for device_id in cycle.seen:
            last_seen[device_id] = cycle.end
        out.append({
            device_id: (device_id in last_seen
                        and (cycle.end - last_seen[device_id]) <= tolerances.get(device_id, float(cycle.end)))
            for device_id in everyone
        })
    return out


def device_baselines(cycles: Sequence[Cycle], present: Sequence[Mapping[int, bool]]) -> dict[int, Baseline]:
    """Per-device absence baseline: how often, and at what hour (C3's false-positive guard).

    Reads the dense :func:`presence` matrix, so it is for diagnostics and tests only; detection
    builds the identical :class:`Baseline` sparsely, and only for devices that actually dropped
    (:class:`_BaselineIndex`).
    """
    first_seen: dict[int, int] = {}
    for cycle in cycles:
        for device_id in cycle.seen:
            first_seen.setdefault(device_id, cycle.index)
    totals: dict[int, int] = {}
    absents: dict[int, int] = {}
    hour_total: dict[int, dict[int, int]] = {}
    hour_absent: dict[int, dict[int, int]] = {}
    hour_days: dict[int, dict[int, set[str]]] = {}
    for cycle, state in zip(cycles, present):
        hour = cycle.hour
        day = cycle.started_at[:10]
        for device_id, is_present in state.items():
            if cycle.index < first_seen.get(device_id, 0):
                continue  # the device did not exist yet; that is not an absence
            totals[device_id] = totals.get(device_id, 0) + 1
            hour_total.setdefault(device_id, {})[hour] = hour_total.setdefault(device_id, {}).get(hour, 0) + 1
            if not is_present:
                absents[device_id] = absents.get(device_id, 0) + 1
                hour_absent.setdefault(device_id, {})[hour] = hour_absent.setdefault(device_id, {}).get(hour, 0) + 1
                hour_days.setdefault(device_id, {}).setdefault(hour, set()).add(day)
    return {
        device_id: Baseline(device_id, totals[device_id], absents.get(device_id, 0),
                            hour_absent.get(device_id, {}), hour_total.get(device_id, {}),
                            {h: len(days) for h, days in hour_days.get(device_id, {}).items()})
        for device_id in sorted(totals)
    }


# ------------------------------------------------------------ sparse presence


@dataclass(frozen=True)
class AbsenceTrack:
    """One device's presence history, stored as the runs of cycles in which it counts as absent.

    ``absences`` holds half-open ``[start, stop)`` cycle-index ranges. ``start`` is the first
    cycle in which the device had gone unseen for longer than its tolerance — so it was present
    in ``start - 1``, and ``start`` is a drop — and ``stop`` is the next cycle it was seen in, or
    ``len(cycles)`` when it has not come back. Everything :func:`presence` says about the device
    is recoverable from this, at a cost proportional to its sightings rather than to every
    cycle in the history.
    """

    device_id: int
    first: int
    absences: tuple[tuple[int, int], ...]


def absence_tracks(cycles: Sequence[Cycle], tolerances: Mapping[int, float]) -> dict[int, AbsenceTrack]:
    """The sparse equivalent of :func:`presence`: per device, the ranges where it is absent.

    ``presence(...)[i][d]`` is False exactly for ``i`` before the device's first cycle and for
    ``i`` inside one of its absence ranges. Requires strictly increasing cycle ends, which
    :func:`discovery_cycles` guarantees.
    """
    ends = [cycle.end for cycle in cycles]
    total = len(cycles)
    seen_in: dict[int, list[int]] = {}
    for position, cycle in enumerate(cycles):
        for device_id in cycle.seen:
            seen_in.setdefault(device_id, []).append(position)
    out: dict[int, AbsenceTrack] = {}
    for device_id, seen in seen_in.items():
        # presence() treats a device with no tolerance as always within it.
        tolerance = float(tolerances.get(device_id, float("inf")))
        ranges: list[tuple[int, int]] = []
        for j, seen_at in enumerate(seen):
            stop = seen[j + 1] if j + 1 < len(seen) else total
            # First cycle after this sighting whose distance from it exceeds the tolerance. The
            # same subtraction presence() performs, so float rounding cannot make them disagree.
            anchor = ends[seen_at]
            low, high = seen_at + 1, stop
            while low < high:
                mid = (low + high) // 2
                if ends[mid] - anchor <= tolerance:
                    low = mid + 1
                else:
                    high = mid
            if low < stop:
                ranges.append((low, stop))
        out[device_id] = AbsenceTrack(device_id, seen[0], tuple(ranges))
    return out


class _BaselineIndex:
    """Builds :class:`Baseline` objects from absence tracks, on demand.

    Only devices that actually dropped ever need one, so a device minted by MAC churn and seen
    once costs a handful of binary searches instead of a row in every cycle of the history.
    Produces exactly what :func:`device_baselines` produces from the dense matrix.
    """

    #: Ranges at most this long are tallied cycle by cycle; longer ones by binary search per hour.
    _SHORT = 48

    def __init__(self, cycles: Sequence[Cycle]) -> None:
        self.total = len(cycles)
        self.hour_of: list[int] = []
        self.slot_of: list[int] = []  # index of the (UTC day, hour) run each cycle falls in
        self.slot_hour: list[int] = []
        self.cycles_at_hour: dict[int, list[int]] = {}
        self.slots_at_hour: dict[int, list[int]] = {}
        previous: tuple[str, int] | None = None
        for position, cycle in enumerate(cycles):
            hour = cycle.hour
            key = (cycle.started_at[:10], hour)
            if key != previous:
                previous = key
                self.slots_at_hour.setdefault(hour, []).append(len(self.slot_hour))
                self.slot_hour.append(hour)
            self.hour_of.append(hour)
            self.slot_of.append(len(self.slot_hour) - 1)
            self.cycles_at_hour.setdefault(hour, []).append(position)

    @classmethod
    def _by_hour(cls, ranges: Sequence[tuple[int, int]], per_hour: Mapping[int, list[int]],
                 hour_of: Sequence[int]) -> dict[int, int]:
        """hour -> how many positions inside ``ranges`` (half-open) fall in that hour."""
        out: dict[int, int] = {}
        for low, high in ranges:
            if high - low <= cls._SHORT:
                for position in range(low, high):
                    hour = hour_of[position]
                    out[hour] = out.get(hour, 0) + 1
                continue
            for hour, items in per_hour.items():
                n = bisect.bisect_left(items, high) - bisect.bisect_left(items, low)
                if n:
                    out[hour] = out.get(hour, 0) + n
        return out

    def baseline(self, track: AbsenceTrack) -> Baseline:
        hour_total = self._by_hour([(track.first, self.total)], self.cycles_at_hour, self.hour_of)
        hour_absent = self._by_hour(track.absences, self.cycles_at_hour, self.hour_of)
        # Distinct days per hour == distinct (day, hour) slots, and a range of cycles covers a
        # contiguous run of slots. Runs that share a slot are merged so no day counts twice.
        slot_runs: list[tuple[int, int]] = []
        for low, high in track.absences:
            run = (self.slot_of[low], self.slot_of[high - 1] + 1)
            if slot_runs and run[0] < slot_runs[-1][1]:
                slot_runs[-1] = (slot_runs[-1][0], max(slot_runs[-1][1], run[1]))
            else:
                slot_runs.append(run)
        days = self._by_hour(slot_runs, self.slots_at_hour, self.slot_hour)
        absent = sum(high - low for low, high in track.absences)
        return Baseline(track.device_id, self.total - track.first, absent, hour_absent, hour_total, days)


# -------------------------------------------------------------------- detection


def detect_outages(conn: sqlite3.Connection, *, min_members: int = 3, window_seconds: int | None = None) -> list[Outage]:
    """Find cycles where several devices dropped together for reasons that are not routine.

    ``window_seconds`` defaults to 2 × the discovery interval (C3) and is the grace period
    before a missing device counts as gone. Returned outages have ``id = 0``; they are given
    one by :func:`record_outages`.

    Works from :func:`absence_tracks`, never the dense :func:`presence` matrix: its cost is
    proportional to the sightings in the window plus the drops found, so identities minted by
    MAC churn — each seen once and never again — cost a few entries each rather than one per
    cycle of thirty days of history. The result is identical to evaluating the dense matrix,
    which ``tests/test_security2_topology.py`` checks against randomised histories.
    """
    interval = discovery_interval_seconds(conn)
    window = int(window_seconds) if window_seconds else 2 * interval
    cycles = discovery_cycles(conn, interval_seconds=interval)
    if len(cycles) < MIN_HISTORY_CYCLES + 1:
        return []
    tracks = absence_tracks(cycles, device_tolerances(cycles, window))

    # cycle index -> [(device, the cycle it was next seen in)] for every drop old enough to count
    drops: dict[int, list[tuple[int, int]]] = {}
    for device_id, track in tracks.items():
        for start, stop in track.absences:
            if start - track.first < MIN_HISTORY_CYCLES:
                continue  # too new to have a normal
            drops.setdefault(start, []).append((device_id, stop))

    kinds = _device_kinds(conn)
    gateway_id = _gateway_device_id(conn)
    minimum = max(2, int(min_members))
    index = _BaselineIndex(cycles)
    baselines: dict[int, Baseline] = {}
    outages: list[Outage] = []
    for position in sorted(drops):
        candidates = drops[position]
        if len(candidates) < minimum:
            continue  # the routine guard only ever removes members, so this cycle cannot qualify
        cycle = cycles[position]
        droppers: list[int] = []
        returns: list[int] = []
        for device_id, stop in sorted(candidates):
            baseline = baselines.get(device_id)
            if baseline is None:
                baseline = baselines[device_id] = index.baseline(tracks[device_id])
            if baseline.is_routine(cycle.hour):
                continue  # the phone that leaves the house every evening
            droppers.append(device_id)
            returns.append(stop)
        if len(droppers) < minimum:
            continue
        trigger_id, trigger_kind = _classify_trigger(droppers, kinds, gateway_id)
        # When the last member came back, or None while any of them is still missing.
        ended_at = (None if any(stop >= len(cycles) for stop in returns)
                    else max(cycles[stop].started_at for stop in returns))
        outages.append(Outage(
            id=0,
            started_at=cycle.started_at,
            ended_at=ended_at,
            cycle_seconds=measured_cycle_seconds(cycles, position, interval),
            members=sorted(droppers),
            trigger_device_id=trigger_id,
            trigger_kind=trigger_kind,
        ))
    return outages


def _ended_at(cycles: Sequence[Cycle], present: Sequence[Mapping[int, bool]], members: Sequence[int], index: int) -> str | None:
    """When the last member came back, or None while any is still missing (dense form, for tests)."""
    returns: list[str] = []
    for device_id in members:
        when = next((cycles[j].started_at for j in range(index + 1, len(cycles)) if present[j].get(device_id)), None)
        if when is None:
            return None
        returns.append(when)
    return max(returns) if returns else None


def _device_kinds(conn: sqlite3.Connection) -> dict[int, str]:
    return {int(r["id"]): str(r["kind"] or "").lower() for r in db.query(conn, "SELECT id, kind FROM devices")}


def _gateway_device_id(conn: sqlite3.Connection) -> int | None:
    from homesoc.topology import infer

    row, _confidence = infer.gateway_device(conn)
    return int(row["id"]) if row is not None else None


def _classify_trigger(members: Sequence[int], kinds: Mapping[int, str], gateway_id: int | None) -> tuple[int | None, str]:
    """Which member is the infrastructure device, if one of them is (C3's ``trigger_device_id``).

    **This is an association, not a cause.** Home SOC has no packet visibility and no power
    telemetry: all it knows is that these devices vanished from the same sweep and that one of
    them is a router, a NAS or an access point. Nothing here establishes causal order, and
    nothing downstream may word it as though it had — a tripped power strip produces exactly
    this row. The field exists because "which of these is the infrastructure box" is the useful
    thing to tell a person first, and because C3's data model defines it as precisely that: "the
    infrastructure device that also dropped, when one did".
    """
    if gateway_id is not None and gateway_id in members:
        return gateway_id, "gateway"
    for device_id in sorted(members):
        if kinds.get(device_id, "") in INFRASTRUCTURE_KINDS:
            return device_id, "device"
    return None, "unknown"


# ------------------------------------------------------------------ persistence


def record_outages(conn: sqlite3.Connection) -> int:
    """Persist newly detected outages; idempotent.

    Keyed on ``started_at``, which is the start of a specific discovery cycle and therefore
    stable across runs. An outage already on record only ever gains an ending — the members and
    the recorded cadence are never rewritten, because they are what was true at the time.
    """
    from homesoc import config

    try:
        minimum = int(config.load(conn).topology.outage_members)
    except Exception:
        minimum = 3
    detected = detect_outages(conn, min_members=minimum)
    known = {
        str(r["started_at"]): (int(r["id"]), r["ended_at"])
        for r in db.query(conn, "SELECT id, started_at, ended_at FROM outages")
    }
    added = 0
    for outage in detected:
        existing = known.get(outage.started_at)
        if existing is not None:
            outage_id, ended_at = existing
            if outage.ended_at and not ended_at:
                db.write(conn, "UPDATE outages SET ended_at = ? WHERE id = ?", (outage.ended_at, outage_id))
                db.write(conn, "UPDATE outage_members SET returned_at = ? WHERE outage_id = ? AND returned_at IS NULL",
                         (outage.ended_at, outage_id))
            continue
        with db.transaction(conn) as tx:
            cur = tx.execute(
                "INSERT INTO outages(started_at, ended_at, cycle_seconds, trigger_device_id, trigger_kind, member_count) "
                "VALUES (?,?,?,?,?,?)",
                (outage.started_at, outage.ended_at, int(outage.cycle_seconds), outage.trigger_device_id,
                 outage.trigger_kind, len(outage.members)),
            )
            outage_id = int(cur.lastrowid or 0)
            tx.executemany(
                "INSERT OR IGNORE INTO outage_members(outage_id, device_id, dropped_at, returned_at) VALUES (?,?,?,?)",
                [(outage_id, device_id, outage.started_at, outage.ended_at) for device_id in outage.members],
            )
        added += 1
        db.record_event(
            conn, "info", "topology",
            f"recorded an outage: {len(outage.members)} devices dropped in the same discovery cycle",
            {"started_at": outage.started_at, "members": len(outage.members),
             "trigger_kind": outage.trigger_kind, "cycle_seconds": outage.cycle_seconds},
        )
    return added


def stored_outages(conn: sqlite3.Connection, *, limit: int = 50) -> list[Outage]:
    """Recorded outages, newest first."""
    rows = db.query(conn, "SELECT * FROM outages ORDER BY started_at DESC, id DESC LIMIT ?", (max(1, int(limit)),))
    out: list[Outage] = []
    for row in rows:
        members = [
            int(m["device_id"])
            for m in db.query(conn, "SELECT device_id FROM outage_members WHERE outage_id = ? ORDER BY device_id",
                              (int(row["id"]),))
        ]
        out.append(Outage(
            id=int(row["id"]), started_at=str(row["started_at"]), ended_at=row["ended_at"],
            cycle_seconds=int(row["cycle_seconds"]), members=members,
            trigger_device_id=(int(row["trigger_device_id"]) if row["trigger_device_id"] is not None else None),
            trigger_kind=str(row["trigger_kind"]),
        ))
    return out


# -------------------------------------------------------------------- analysis


def co_drop_matrix(conn: sqlite3.Connection, *, min_outages: int = 2) -> dict[tuple[int, int], float]:
    """P(b offline | a offline) across recorded outages.

    Used to promote an inferred edge to observed — but only once the pair has dropped together
    at least ``min_outages`` times. One shared outage is a coincidence; the whole point of the
    threshold is that a single power cut must not mint a dependency.
    """
    membership: dict[int, set[int]] = {}
    for row in db.query(conn, "SELECT outage_id, device_id FROM outage_members ORDER BY outage_id, device_id"):
        membership.setdefault(int(row["outage_id"]), set()).add(int(row["device_id"]))
    totals: dict[int, int] = {}
    together: dict[tuple[int, int], int] = {}
    for members in membership.values():
        for a in members:
            totals[a] = totals.get(a, 0) + 1
            for b in members:
                if a != b:
                    together[(a, b)] = together.get((a, b), 0) + 1
    return {
        pair: count / totals[pair[0]]
        for pair, count in sorted(together.items())
        if count >= max(1, int(min_outages)) and totals.get(pair[0])
    }


def trigger_counts(conn: sqlite3.Connection, *, exclude_gateway: bool = False) -> dict[int, int]:
    """How many recorded outages each device is the trigger of.

    ``exclude_gateway`` must match whatever :func:`trigger_members` was called with, or a ratio
    built from the two would compare a numerator that skipped gateway outages against a
    denominator that counted them.
    """
    clause = " AND trigger_kind != 'gateway'" if exclude_gateway else ""
    rows = db.query(
        conn,
        f"SELECT trigger_device_id AS d, COUNT(*) AS n FROM outages WHERE trigger_device_id IS NOT NULL{clause} "
        "GROUP BY trigger_device_id ORDER BY trigger_device_id",
    )
    return {int(r["d"]): int(r["n"]) for r in rows}


def trigger_members(conn: sqlite3.Connection, *, exclude_gateway: bool = True) -> dict[int, dict[int, int]]:
    """trigger device -> {other device: in how many of that trigger's outages it also dropped}.

    Gateway outages are excluded by default, and that exclusion is the difference between
    evidence and a plausible-looking lie. When the router goes down every device on a flat home
    network disappears with it, so a co-drop there is *entirely* explained by the shared route
    and says nothing at all about whether those devices used the router's DNS, or its anything.
    Promoting it would hand a user ten confident service dependencies built on one power cut.
    A co-drop with a NAS or an access point is a different matter: nothing else explains it.
    """
    clause = " AND o.trigger_kind != 'gateway'" if exclude_gateway else ""
    rows = db.query(
        conn,
        "SELECT o.trigger_device_id AS trigger_id, m.device_id AS device_id, COUNT(*) AS n "
        "FROM outages o JOIN outage_members m ON m.outage_id = o.id "
        f"WHERE o.trigger_device_id IS NOT NULL{clause} GROUP BY o.trigger_device_id, m.device_id "
        "ORDER BY o.trigger_device_id, m.device_id",
    )
    out: dict[int, dict[int, int]] = {}
    for row in rows:
        out.setdefault(int(row["trigger_id"]), {})[int(row["device_id"])] = int(row["n"])
    return out


def observed_blast_radius(conn: sqlite3.Connection, device_id: int) -> dict[str, Any]:
    """What has actually been recorded about this device failing.

    Two co-member views, because they answer different questions and conflating them would put
    a false claim in front of the user:

    * ``co_members`` — devices that dropped in the same cycle as this one, for *any* reason.
      Useful context; not proof of a dependency, since a router outage takes everyone with it.
    * ``co_members_triggered`` — only outages this device was the trigger of. This is the one
      the blast radius is allowed to speak about at all.

    Every number that answers "what happens when THIS device fails" — ``dates``,
    ``member_count``, ``cycle_seconds`` and the ``evidence`` sentence — is built from the
    trigger-scoped rows alone. Building them from the membership rows was the bug this
    docstring's own distinction was written to prevent: a NAS that merely sat inside a
    twenty-device router outage reported "20 devices went offline in the same discovery cycle
    as this one" as *its* blast radius, at ``observed`` confidence, on the map, in the Lens
    card and inside a persisted NET-DEP-002 finding. The whole-membership figures are still
    returned, under ``attended_*``, and are labelled as context.
    """
    device_id = int(device_id)
    rows = db.query(
        conn,
        "SELECT o.id, o.started_at, o.cycle_seconds, o.member_count, o.trigger_device_id "
        "FROM outages o JOIN outage_members m ON m.outage_id = o.id WHERE m.device_id = ? "
        "ORDER BY o.started_at",
        (device_id,),
    )
    if not rows:
        return {"outages": 0, "triggered": 0, "dates": [], "co_members": [], "co_members_triggered": [],
                "attended_outages": 0, "attended_dates": [], "attended_member_count": 0,
                "member_count": 0, "evidence": None, "resolution": None, "cycle_seconds": None}
    ids = [int(r["id"]) for r in rows]
    triggered = [r for r in rows if r["trigger_device_id"] is not None
                 and int(r["trigger_device_id"]) == device_id]
    triggered_ids = [int(r["id"]) for r in triggered]
    names = {int(r["id"]): _display_name(r) for r in
             db.query(conn, "SELECT id, mac, ip, hostname, nickname FROM devices")}
    # Trigger-scoped: the only rows allowed to describe this device's own blast radius.
    cycle_seconds = max((int(r["cycle_seconds"]) for r in triggered), default=None)
    dates = [_human_date(str(r["started_at"])) for r in triggered]
    # (date, how many OTHER devices dropped) per outage. member_count includes this device, so
    # subtracting it is the difference between "3 devices went offline with this one" and the
    # truth, which is two.
    others = [(_human_date(str(r["started_at"])), max(0, int(r["member_count"]) - 1)) for r in triggered]
    biggest = max((n for _d, n in others), default=0)
    return {
        "outages": len(ids),
        "triggered": len(triggered_ids),
        "dates": dates,
        "cycle_seconds": cycle_seconds,
        # How many *other* devices went down in the largest outage this device triggered.
        "member_count": biggest,
        "co_members": _co_members(conn, device_id, ids, names),
        "co_members_triggered": _co_members(conn, device_id, triggered_ids, names),
        # Context only: outages this device was caught in but did not head. Never this device's
        # blast radius, and never worded as one.
        "attended_outages": len(ids) - len(triggered_ids),
        "attended_dates": [_human_date(str(r["started_at"])) for r in rows if int(r["id"]) not in set(triggered_ids)],
        "attended_member_count": max((int(r["member_count"]) for r in rows), default=0),
        "evidence": _evidence_sentence(others, cycle_seconds) if triggered else None,
        "resolution": resolution_note(cycle_seconds) if triggered else None,
    }


def _co_members(conn: sqlite3.Connection, device_id: int, outage_ids: Sequence[int],
                names: Mapping[int, str]) -> list[dict[str, Any]]:
    if not outage_ids:
        return []
    placeholders = ",".join("?" for _ in outage_ids)
    rows = db.query(
        conn,
        f"SELECT device_id, COUNT(*) AS n FROM outage_members WHERE outage_id IN ({placeholders}) "
        "GROUP BY device_id ORDER BY device_id",
        tuple(int(i) for i in outage_ids),
    )
    total = len(outage_ids)
    out = [
        {
            "device_id": int(r["device_id"]),
            "label": names.get(int(r["device_id"]), f"device {int(r['device_id'])}"),
            "together": int(r["n"]),
            "probability": round(int(r["n"]) / total, 3),
        }
        for r in rows
        if int(r["device_id"]) != device_id
    ]
    out.sort(key=lambda item: (-item["probability"], -item["together"], item["device_id"]))
    return out


def _display_name(row: sqlite3.Row) -> str:
    from homesoc.topology import infer

    return infer.display_name(row)


_TIMES = {1: "once", 2: "twice", 3: "three times", 4: "four times", 5: "five times"}
#: Bare number words, for "the three most recent" — _TIMES would render "the three times most
#: recent", which is how a sentence about honesty ends up sounding like a machine wrote it.
_NUMBERS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}


#: How many dates the evidence sentence lists before it says it is only showing the recent ones.
EVIDENCE_MAX_DATES = 3


def _evidence_sentence(events: Sequence[tuple[str, int]], cycle_seconds: int | None) -> str:
    """The evidence line, which never claims better than cycle resolution.

    ``events`` is ``(date, how many OTHER devices dropped)`` per outage, and each date carries
    its own number. Rendering one outage's size against every date — which is what a single
    ``max(member_count)`` did — invented a figure for every date but one; counting the subject
    device among "devices that went offline with this one" inflated all of them by one.
    """
    count = len(events)
    times = _TIMES.get(count, f"{count} times")
    shown = list(events[-EVIDENCE_MAX_DATES:])
    parts = [f"{n} other device{'s' if n != 1 else ''} on {when}" for when, n in shown]
    joined = parts[0] if len(parts) == 1 else " and ".join([", ".join(parts[:-1]), parts[-1]])
    minutes = max(1, int(cycle_seconds or DEFAULT_INTERVAL_SECONDS) // 60)
    # Say the truncation out loud. "Seen five times: on <three dates>" let a reader count three
    # and be told five, in the one sentence the whole feature asks to be believed.
    lead = f"Seen {times}" + (f", the {_NUMBERS.get(len(shown), str(len(shown)))} most recent: "
                              if count > len(shown) else ": ")
    return (f"{lead}{joined} went offline in the same {minutes}-minute discovery cycle as this one.")


def _human_date(iso: str) -> str:
    """A date a person can check against their own memory — so, in their own timezone.

    Rendering the UTC day for a user west of UTC turned an outage they remember on the evening
    of 2 September into "3 September", in a feature whose entire value is that the numbers hold
    up when you check them. ``Cycle.hour`` stays in UTC deliberately: it only buckets a device's
    routine-absence baseline, where consistency matters and the label is never shown.
    """
    parsed = parse_iso(iso)
    if parsed is None:
        return str(iso)[:10]
    try:
        parsed = parsed.astimezone()
    except (OSError, OverflowError, ValueError) as exc:  # a hostile TZ must not take the map down
        logger.debug("cannot localise %s: %s", iso, exc)
    return f"{parsed.day} {parsed.strftime('%B')}"


__all__ = [
    "HISTORY_DAYS", "MIN_HISTORY_CYCLES", "ROUTINE_MIN_RATE", "ROUTINE_HOUR_RATE", "ROUTINE_MIN_DAYS",
    "EVIDENCE_MAX_DATES", "INFRASTRUCTURE_KINDS",
    "Outage", "Cycle", "Baseline",
    "discovery_interval_seconds", "resolution_note", "measured_cycle_seconds",
    "discovery_cycles", "presence", "device_tolerances", "device_baselines", "absence_tracks", "AbsenceTrack",
    "detect_outages", "record_outages", "stored_outages",
    "co_drop_matrix", "trigger_counts", "trigger_members", "observed_blast_radius",
]
