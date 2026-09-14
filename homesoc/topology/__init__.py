"""Dependencies and blast radius (SPEC addendum C).

A map of what each device depends on, what depends on it, and what stops working when it
fails — built only from evidence Home SOC already collects, with every edge labelled by how it
was established. It is **not** a live traffic diagram: Home SOC has no packet visibility and
LAN peer-to-peer traffic never passes through it, so it cannot know that the laptop is talking
to the NAS. Anything that would imply otherwise is not built here (see :mod:`.infer`).

This module is the scanner face of the package: ``run(cfg, conn, quick=..., progress=...)``,
exactly like every other scanner, so the existing scheduler, CLI and dashboard machinery picks
it up with no special cases.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import FindingDraft, ScanResult
from homesoc.topology import graph, infer, outages
from homesoc.topology.graph import Edge, Node, blast_radius, build_graph, criticality, refresh
from homesoc.topology.outages import Outage, co_drop_matrix, detect_outages, observed_blast_radius, record_outages
from homesoc.util import iso_ago, parse_iso

if TYPE_CHECKING:
    from homesoc.config import Config

logger = logging.getLogger(__name__)

SCAN_KIND = "topology"
#: Default scheduler interval (C6). The graph moves at the speed of the house, not the network.
JOB_INTERVAL_HOURS = 6

#: NET-DEP-003: how many blocked lookups of one domain, with none ever answered, before a
#: device is called "possibly silently degraded". Low enough to catch a camera that has been
#: phoning home unsuccessfully for a week, high enough to ignore a single stray request.
BLOCKED_ALERT_QUERIES = 20
#: ...and spread over at least this long, so "repeatedly" means a habit rather than one burst.
#: Measured as a span rather than a day count because the query log's retention is only 14 days
#: by default and a fresh install has hours of history, not days.
BLOCKED_ALERT_SPAN_HOURS = 12
#: A quick run only reads the last day of DNS, which is the expensive half of the graph.
QUICK_WINDOW_HOURS = 24


def run(cfg: "Config", conn: sqlite3.Connection, *, quick: bool = False,
        progress: Callable[[str], None] | None = None) -> ScanResult:
    """Refresh the dependency graph, record outages, and emit the NET-DEP findings.

    Never raises for an expected failure: an empty database, a database with one device and no
    DNS log, or a missing sibling package all produce a graph with whatever is genuinely known
    and no findings at all.
    """
    started = time.monotonic()
    findings: list[FindingDraft] = []
    summary: dict[str, Any] = {"enabled": True, "quick": bool(quick)}
    error: str | None = None
    topology_cfg = getattr(cfg, "topology", None)
    if topology_cfg is not None and not topology_cfg.enabled:
        return ScanResult(kind=SCAN_KIND, findings=[], summary={"enabled": False, "skipped": "topology.enabled is false"})
    hours = int(getattr(topology_cfg, "hours", 168))
    if quick:
        hours = min(hours, QUICK_WINDOW_HOURS)
    include_cloud = bool(getattr(topology_cfg, "include_cloud", True))
    alert_at = int(getattr(topology_cfg, "alert_dependents", 5))

    try:
        if progress:
            progress("looking for outages in the sighting history")
        summary["outages_new"] = record_outages(conn)
        if progress:
            progress("rebuilding the dependency graph")
        summary.update(refresh(conn, hours=hours, include_cloud=include_cloud))
        ranked = criticality(conn, hours=hours)
        summary["load_bearing"] = [
            {k: item[k] for k in ("device_id", "label", "dependents", "weight")} for item in ranked[:5]
        ]
        findings.extend(_load_bearing_findings(conn, ranked, alert_at))
        findings.extend(_single_point_findings(conn))
        findings.extend(_blocked_cloud_findings(conn, hours))
        db.record_metric(conn, "topology.edges", float(summary.get("edges", 0)))
    except Exception as exc:  # a scanner must never take the scheduler down
        logger.exception("topology scan failed")
        error = f"{type(exc).__name__}: {exc}"
    summary["findings_emitted"] = len(findings)
    summary["duration_sec"] = round(time.monotonic() - started, 2)
    return ScanResult(kind=SCAN_KIND, findings=findings, summary=summary, error=error)


# ------------------------------------------------------------------- findings


def _device_subjects(conn: sqlite3.Connection) -> dict[int, tuple[str, str]]:
    """device id -> (finding subject, display name)."""
    return {
        int(r["id"]): (f"device:{r['mac']}", infer.display_name(r))
        for r in db.query(conn, "SELECT id, mac, ip, hostname, nickname FROM devices")
    }


def _load_bearing_findings(conn: sqlite3.Connection, ranked: list[dict[str, Any]], alert_at: int) -> list[FindingDraft]:
    """NET-DEP-001 (info) — more than N devices now depend on this one."""
    subjects = _device_subjects(conn)
    drafts: list[FindingDraft] = []
    for item in ranked:
        if int(item["dependents"]) <= alert_at:
            continue
        device_id = int(item["device_id"])
        subject, name = subjects.get(device_id, (f"device:{device_id}", item["label"]))
        drafts.append(FindingDraft(
            finding_id="NET-DEP-001", subject=subject, device_id=device_id,
            detail=f"{item['dependents']} devices depend on {name}. {item['why']}.",
            evidence={"name": name, "dependents": int(item["dependents"]), "threshold": int(alert_at),
                      "why": item["why"]},
        ))
    return drafts


def _single_point_findings(conn: sqlite3.Connection) -> list[FindingDraft]:
    """NET-DEP-002 (medium) — a single point of failure that has actually taken devices down.

    Fires on **observed evidence only**: a device that has been the trigger of at least two
    recorded outages. Inference never reaches this finding, which is the whole reason it is
    allowed to be more than informational.

    What the sentence may claim is narrower than what "trigger" sounds like. The trigger is the
    infrastructure device among the members (``outages._classify_trigger``) — an association,
    not a measured causal order, and a tripped power strip produces the identical row. The
    catalogue text is already careful about this ("devices have gone offline with it", "dropped
    off the network in the same discovery cycle as {name}"); this detail line was the one place
    that said "has taken other devices down with it", which is the claim the data cannot carry.
    """
    subjects = _device_subjects(conn)
    drafts: list[FindingDraft] = []
    for device_id, count in sorted(outages.trigger_counts(conn).items()):
        if count < 2:
            continue
        observed = observed_blast_radius(conn, device_id)
        subject, name = subjects.get(device_id, (f"device:{device_id}", f"device {device_id}"))
        drafts.append(FindingDraft(
            finding_id="NET-DEP-002", subject=subject, device_id=device_id,
            detail=(f"{name} was offline in the same discovery cycle as other devices on {count} "
                    "separate occasions, and is the infrastructure device among them — so it is the "
                    "first thing to check when they go quiet together. "
                    f"{observed.get('evidence') or ''} {observed.get('resolution') or ''}").strip(),
            # "affected"/"devices" and "failures"/"blocked" are both supplied on purpose: the
            # catalogue templates (owned by the findings package) interpolate one spelling, and a
            # title that renders "unknown" because two packages drifted is a bad way to find out.
            #
            # Every figure here is trigger-scoped. ``member_count`` used to be the largest outage
            # this device had *attended*, so a NAS that sat inside one twenty-device router outage
            # got a persisted finding reading "20 devices have gone offline with it" — a number
            # belonging to the router, at observed confidence, in a medium-severity finding.
            evidence={"name": name, "outages": int(count), "dates": observed.get("dates") or [],
                      "devices": observed.get("member_count") or 0,
                      "affected": observed.get("member_count") or 0,
                      "cycle_seconds": observed.get("cycle_seconds") or 0},
        ))
    return drafts


def _blocked_cloud_findings(conn: sqlite3.Connection, hours: int) -> list[FindingDraft]:
    """NET-DEP-003 (info) — a device keeps asking for an endpoint it never reaches.

    Every lookup for the domain in the window was blocked and none was ever answered, so
    whatever the device wanted from it, it has not been getting — quietly.
    """
    since = iso_ago(hours=max(1, int(hours)))
    subjects = _device_subjects(conn)
    by_ip = {str(r["ip"]): int(r["id"]) for r in db.query(conn, "SELECT id, ip FROM devices WHERE ip IS NOT NULL")}
    tally: dict[tuple[int, str], dict[str, Any]] = {}
    for row in db.query(
        conn,
        "SELECT client, qname, action, COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
        "FROM dns_queries WHERE ts >= ? GROUP BY client, qname, action ORDER BY client, qname, action",
        (since,),
    ):
        device_id = by_ip.get(str(row["client"]))
        if device_id is None:
            continue
        domain = infer.registrable_domain(str(row["qname"]))
        if not domain or "." not in domain:
            continue
        bucket = tally.setdefault((device_id, domain), {"allowed": 0, "blocked": 0, "first": "", "last": ""})
        key = "blocked" if str(row["action"]) == "block" else "allowed"
        bucket[key] += int(row["n"])
        if key == "blocked":
            first, last = str(row["first_ts"]), str(row["last_ts"])
            bucket["first"] = min(bucket["first"], first) if bucket["first"] else first
            bucket["last"] = max(bucket["last"], last)

    drafts: list[FindingDraft] = []
    for (device_id, domain), counts in sorted(tally.items()):
        # "Repeatedly" has to mean over time, not in one burst: a device that tried noisily once
        # and gave up is not being silently degraded, it was blocked once.
        if counts["allowed"] or counts["blocked"] < BLOCKED_ALERT_QUERIES:
            continue
        span = _span_hours(counts["first"], counts["last"])
        if span < BLOCKED_ALERT_SPAN_HOURS:
            continue
        subject, name = subjects.get(device_id, (f"device:{device_id}", f"device {device_id}"))
        drafts.append(FindingDraft(
            finding_id="NET-DEP-003", subject=subject, device_id=device_id,
            detail=(f"{name} asked for {domain} {counts['blocked']} times over {int(span)} hours and every "
                    "lookup was blocked. "
                    "If it needs that endpoint for something you use, that feature is quietly not working; "
                    "if it does not, this is the filter doing its job."),
            evidence={"key": domain, "domain": domain, "name": name, "blocked": counts["blocked"],
                      "failures": counts["blocked"], "hours": int(span),
                      "label": infer.cloud_label(domain)},
        ))
    return drafts


def _span_hours(first: str, last: str) -> float:
    start, end = parse_iso(first), parse_iso(last)
    if start is None or end is None:
        return 0.0
    return max(0.0, (end - start).total_seconds() / 3600.0)


__all__ = [
    "SCAN_KIND", "JOB_INTERVAL_HOURS", "BLOCKED_ALERT_QUERIES", "BLOCKED_ALERT_SPAN_HOURS",
    "run", "graph", "infer", "outages",
    "Node", "Edge", "Outage",
    "build_graph", "blast_radius", "criticality", "refresh",
    "detect_outages", "record_outages", "co_drop_matrix", "observed_blast_radius",
]
