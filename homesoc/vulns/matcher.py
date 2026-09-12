"""Match discovered services (and outdated software) to known vulnerabilities.

Order of sources is deliberate: KEV first because it is on disk and represents
"actively exploited right now"; NVD second because it costs network time and is
bounded by a per-scan budget; EPSS last because it only annotates CVEs the first
two already found. Findings are returned as drafts; the findings engine persists
them. This module owns the ``vulns`` table.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from homesoc import db
from homesoc.models import FindingDraft, ScanResult, Vuln
from homesoc.util import utcnow_iso
from homesoc.vulns import enrich
from homesoc.vulns.cpe import (
    CPE,
    clean_version,
    compare_versions,
    extract_versions,
    guess_cpe,
    max_version,
    parse_cpe,
    version_le,
)

logger = logging.getLogger(__name__)

EPSS_ALERT_THRESHOLD = 0.5
DEFAULT_MIN_CVSS = 7.0

# A KEV entry only becomes NET-VUL-002 ("possible") when nothing tied it to the running
# build; that is a guess, so the number of guesses per service is capped. A product name
# with more unconfirmable hits than this is a *family*, not a device: on the September
# 2026 catalog the only KEV products above 20 are Microsoft/Windows (170), Apple/Multiple
# Products (53), Chromium V8 (40), Internet Explorer (36), Flash Player (33), Office (29),
# Linux/Kernel (28) and Win32k (25) -- exactly the names nmap attaches to a host from an OS
# fingerprint rather than to a versioned service. Everything an nmap banner actually
# identifies (FortiOS 15, Zimbra 18, Pulse Connect Secure 9, ...) stays under the cap and
# is still reported. Confirmed (version-evidenced) hits are never capped.
KEV_POSSIBLE_MAX = 20
# NVD keyword search is a full-text AND over descriptions; a hit count this large means the
# version token did not narrow anything, so the result cannot be attributed to this service.
NVD_KEYWORD_MAX_TOTAL = 200

# SPEC section 8 high-risk list; matched case-insensitively as substrings of the
# winget package name so "7-Zip 23.01 (x64)" and "Oracle Java 8" both hit.
HIGH_RISK_SOFTWARE: tuple[str, ...] = (
    "java",
    "adobe",
    "chrome",
    "firefox",
    "edge",
    "zoom",
    "vlc",
    "7-zip",
    "7zip",
    "winrar",
    "putty",
    "openvpn",
    "notepad++",
    "teamviewer",
    "anydesk",
    "filezilla",
    "python",
)
_ROUTER_IOT_HINTS = ("router", "gateway", "iot", "camera", "printer", "nas", "tv", "hub", "bridge")


def _load_kev():
    """Indirection so tests can swap in a fake catalog; the real loader reads disk."""
    from homesoc.feeds.registry import load_kev

    return load_kev()


def _load_epss() -> dict[str, float]:
    from homesoc.feeds.registry import load_epss

    return load_epss()


@dataclass
class _ServiceCtx:
    """Everything the three matchers need about one open service."""

    row: sqlite3.Row
    cpe: CPE | None
    version: str | None
    product: str
    subject: str
    device_id: int
    service_id: int
    is_router_iot: bool
    drafts: list[FindingDraft] = field(default_factory=list)
    vulns: list[Vuln] = field(default_factory=list)


def run(cfg, conn: sqlite3.Connection, *, quick: bool = False,
        progress: Callable[[str], None] | None = None) -> ScanResult:
    """Scanner-shaped alias so the scheduler can treat vulns like any other job."""
    return match_services(cfg, conn, quick=quick, progress=progress)


def match_services(cfg, conn: sqlite3.Connection, *, quick: bool = False,
                   progress: Callable[[str], None] | None = None) -> ScanResult:
    """Correlate every open service with KEV, NVD and EPSS; upsert ``vulns``.

    Never raises for expected failures: a missing KEV file, an NVD outage or an
    exhausted budget degrade to fewer findings plus ``ScanResult.error``.
    """
    started = time.monotonic()
    say = progress or (lambda _msg: None)
    errors: list[str] = []
    summary: dict[str, Any] = {
        "services_checked": 0, "kev_confirmed": 0, "kev_possible": 0, "kev_suppressed": 0,
        "nvd_queried": 0, "nvd_cached": 0, "nvd_skipped": 0,
        "vulns_upserted": 0, "software_outdated": 0,
    }
    drafts: list[FindingDraft] = []

    kev_catalog = None
    if _cfg(cfg, "kev", True):
        try:
            kev_catalog = _load_kev()
        except Exception as exc:  # feed not downloaded yet is an expected state
            logger.warning("KEV catalog unavailable: %s", exc)
            errors.append(f"kev: {exc}")

    epss: dict[str, float] = {}
    if _cfg(cfg, "epss", True):
        try:
            epss = _load_epss() or {}
        except Exception as exc:
            logger.warning("EPSS scores unavailable: %s", exc)
            errors.append(f"epss: {exc}")

    nvd_enabled = bool(_cfg(cfg, "nvd_enrich", True))
    api_key = str(_cfg(cfg, "nvd_api_key", "") or "")
    min_cvss = float(_cfg(cfg, "min_cvss_report", DEFAULT_MIN_CVSS))
    budget = enrich.Budget()
    limiter = enrich.RateLimiter.for_key(api_key)
    now = utcnow_iso()

    for ctx in _open_services(conn):
        summary["services_checked"] += 1
        say(f"vulns: {ctx.subject} {ctx.product} {ctx.version or ''}".strip())
        if kev_catalog is not None:
            confirmed, possible, suppressed = _match_kev(kev_catalog, ctx, now)
            summary["kev_confirmed"] += confirmed
            summary["kev_possible"] += possible
            summary["kev_suppressed"] += suppressed
        if nvd_enabled and not quick:
            status = _match_nvd(ctx, api_key, conn, budget, limiter, min_cvss, now)
            summary[f"nvd_{status}"] += 1
        _apply_epss(ctx, epss)
        summary["vulns_upserted"] += _upsert_vulns(conn, ctx.vulns, now)
        drafts.extend(ctx.drafts)

    if budget.exhausted:
        errors.append("nvd: per-scan time budget exhausted; some services not enriched")

    # SPEC-GAP: section 8 assigns WIN-UPD-003/004 to vulns and section 6.7 to scanners/updates.py.
    # Integration keeps updates.py as the only emitter: it owns the software rows and applies
    # with scope "host", so a fixed app auto-resolves; a second emitter under source "vulns"
    # would re-label the row's source and leave stale findings open. evaluate_software() stays
    # available for callers and the summary still reports the count.
    summary["software_outdated"] = len(evaluate_software(cfg, conn))

    summary["duration_sec"] = round(time.monotonic() - started, 2)
    try:
        db.record_metric(conn, "vulns.findings", float(len(drafts)))
    except Exception:  # pragma: no cover - telemetry must not break the scan
        logger.debug("record_metric failed", exc_info=True)
    return ScanResult(kind="vulns", findings=drafts, summary=summary,
                      error="; ".join(errors) if errors else None)


def _cfg(cfg, key: str, default):
    section = getattr(cfg, "vulns", None)
    return getattr(section, key, default) if section is not None else default


def _open_services(conn: sqlite3.Connection) -> list[_ServiceCtx]:
    rows = db.query(
        conn,
        "SELECT s.id AS service_id, s.device_id, s.port, s.proto, s.name, s.product, s.version, "
        "s.extrainfo, s.cpe, d.mac, d.ip, d.vendor, d.kind, d.hostname "
        "FROM services s JOIN devices d ON d.id = s.device_id "
        "WHERE s.state = 'open' AND ((s.product IS NOT NULL AND s.product <> '') "
        "OR (s.cpe IS NOT NULL AND s.cpe <> '')) ORDER BY s.device_id, s.port",
    )
    out: list[_ServiceCtx] = []
    for row in rows:
        product = (row["product"] or "").strip()
        cpe = _cpe_for(row["cpe"], product, row["version"])
        version = (cpe.version if cpe and cpe.version else None) or clean_version(row["version"])
        if cpe and not cpe.version and version:
            cpe = CPE(cpe.part, cpe.vendor, cpe.product, version)
        label = product or (cpe.product if cpe else "")
        if not label:
            continue
        out.append(_ServiceCtx(
            row=row, cpe=cpe, version=version, product=label,
            subject=f"device:{row['mac']}:{row['port']}",
            device_id=int(row["device_id"]), service_id=int(row["service_id"]),
            is_router_iot=_looks_router_iot(row),
        ))
    return out


def _cpe_for(raw_cpe: str | None, product: str, version: str | None) -> CPE | None:
    """Prefer nmap's own CPE (application part first); fall back to the alias table."""
    candidates: list[CPE] = []
    for token in (raw_cpe or "").replace(",", " ").split():
        try:
            candidates.append(parse_cpe(token))
        except ValueError:
            continue
    for cand in candidates:
        if cand.part == "a":
            return cand
    if candidates:
        return candidates[0]
    return guess_cpe(product, version)


def _looks_router_iot(row: sqlite3.Row) -> bool:
    text = " ".join(str(row[k] or "") for k in ("kind", "vendor", "hostname")).lower()
    return any(h in text for h in _ROUTER_IOT_HINTS)


# --- KEV ---------------------------------------------------------------------

def _match_kev(catalog, ctx: _ServiceCtx, now: str) -> tuple[int, int, int]:
    """Emit KEV findings for one service; returns (confirmed, possible, suppressed).

    "Confirmed" needs a service version that is <= the highest version the advisory
    names. Everything else is a guess and goes through :data:`KEV_POSSIBLE_MAX`.
    """
    entries = _kev_search(catalog, ctx)
    confirmed: list[tuple[dict, str, str | None]] = []
    possible: list[tuple[dict, str, str | None]] = []
    for entry in entries:
        cve = _kev_field(entry, "cveID", "cve", "cve_id")
        if not cve:
            continue
        text = " ".join(
            str(_kev_field(entry, k) or "")
            for k in ("vulnerabilityName", "name", "shortDescription", "description", "notes")
        )
        highest = max_version(extract_versions(text))
        if ctx.version and highest:
            if not version_le(ctx.version, highest):
                # Newer than every version the advisory names -> most likely patched.
                # SPEC-GAP: spec says "else flag as possible"; we drop it instead
                # because alerting critical on a patched router is the noise users
                # disable the tool over.
                continue
            confirmed.append((entry, str(cve), highest))
        else:
            possible.append((entry, str(cve), highest))

    suppressed = 0
    if len(possible) > KEV_POSSIBLE_MAX:
        # The product name matched a whole family (Microsoft/Windows, Apple/Multiple
        # Products, ...) and nothing pinned it to the running build. Reporting the set
        # would be hundreds of unresolvable "high" findings on every LAN PC; report the
        # suppression in the scan summary instead so it is visible but not alarming.
        suppressed = len(possible)
        logger.info(
            "KEV: %s %s on port %s matched %d unconfirmable entries (version %s); "
            "suppressing NET-VUL-002 (cap %d)",
            ctx.product, ctx.cpe.nvd_name() if ctx.cpe else "", ctx.row["port"],
            suppressed, ctx.version or "unknown", KEV_POSSIBLE_MAX,
        )
        possible = []

    for entry, cve, highest in confirmed:
        _emit_kev(ctx, entry, cve, highest, "NET-VUL-001", "confirmed")
    for entry, cve, highest in possible:
        _emit_kev(ctx, entry, cve, highest, "NET-VUL-002", "possible")
    return len(confirmed), len(possible), suppressed


def _emit_kev(ctx: _ServiceCtx, entry: dict, cve: str, highest: str | None,
              finding_id: str, verdict: str) -> None:
    matched_on = ctx.cpe.nvd_name() if ctx.cpe else f"product:{ctx.product}"
    remediation = _remediation(ctx, entry)
    ctx.vulns.append(Vuln(
        device_id=ctx.device_id, service_id=ctx.service_id, cve=cve, source="kev",
        kev=True, cvss=None, epss=None,
        title=_kev_field(entry, "vulnerabilityName", "name"),
        published=_kev_field(entry, "dateAdded", "date_added"),
        matched_on=matched_on, remediation=remediation,
    ))
    ctx.drafts.append(FindingDraft(
        finding_id=finding_id, subject=ctx.subject, device_id=ctx.device_id,
        detail=(f"{ctx.product} {ctx.version or '(version unknown)'} on port {ctx.row['port']} "
                f"matches CISA KEV {cve} ({verdict}). {remediation}"),
        evidence={
            "key": cve, "cve": cve, "verdict": verdict, "product": ctx.product,
            "version": ctx.version, "kev_max_version": highest, "matched_on": matched_on,
            "vulnerability_name": _kev_field(entry, "vulnerabilityName", "name"),
            "date_added": _kev_field(entry, "dateAdded", "date_added"),
            "due_date": _kev_field(entry, "dueDate", "due_date"),
            "ransomware": _kev_field(entry, "knownRansomwareCampaignUse", "ransomware"),
            "required_action": _kev_field(entry, "requiredAction", "required_action"),
            "ip": ctx.row["ip"], "port": ctx.row["port"],
        },
    ))


def _kev_search(catalog, ctx: _ServiceCtx) -> list[dict]:
    """Search by CPE vendor/product, or by the full banner product when there is no CPE; merge by CVE.

    The banner's first word is deliberately not searched on its own: for "Microsoft Windows RPC" or
    "Apple remote desktop vnc" it is the vendor, and a vendor-wide KEV match produced hundreds of
    false NET-VUL-002 per Windows port.
    """
    attempts: list[tuple[str, str]] = []
    if ctx.cpe:
        attempts.append((ctx.cpe.vendor, ctx.cpe.product))
    elif ctx.product:
        attempts.append(("", ctx.product))
    seen: set[str] = set()
    merged: list[dict] = []
    for vendor, product in attempts:
        try:
            found = catalog.search(vendor, product) or []
        except Exception as exc:
            logger.warning("KEV search failed for %s/%s: %s", vendor, product, exc)
            continue
        for entry in found:
            if not isinstance(entry, dict):
                continue
            cve = _kev_field(entry, "cveID", "cve", "cve_id") or json.dumps(entry, sort_keys=True)
            if cve not in seen:
                seen.add(cve)
                merged.append(entry)
    return merged


def _kev_field(entry: dict, *names: str):
    for name in names:
        value = entry.get(name)
        if value not in (None, ""):
            return value
    return None


# --- NVD ---------------------------------------------------------------------

def _match_nvd(ctx: _ServiceCtx, api_key: str, conn, budget, limiter, min_cvss: float, now: str) -> str:
    """Returns 'queried', 'cached' or 'skipped' for the summary counters."""
    if not ctx.version:
        # Without a version no query (cpeName or keyword) can attribute CVEs to the running build;
        # "keywordSearch=windows" returns tens of thousands of CVEs and a bogus NET-VUL-003.
        return "skipped"
    if budget.exhausted:
        return "skipped"
    result = enrich.nvd_for_cpe(
        ctx.cpe, ctx.version, api_key, conn=conn, budget=budget, limiter=limiter,
        product=ctx.product if ctx.cpe is None else None,
    )
    if result is None:
        return "skipped"
    status = "cached" if result.get("cached") else "queried"
    by_cpe = bool(result.get("match") == "cpe" or (result.get("match") is None and ctx.cpe and ctx.cpe.version))
    total = result.get("count")
    returned = int(result.get("returned") or len(result.get("top") or []))
    if not by_cpe:
        # A keyword hit is a name+version text match, not a CPE match. If the version token
        # did not narrow the search there is nothing to attribute: report nothing rather than
        # "12000 known CVEs for Microsoft Windows RPC".
        if isinstance(total, int) and total > NVD_KEYWORD_MAX_TOTAL:
            logger.info("NVD keyword search for %s %s returned %d results; too broad to attribute",
                        ctx.product, ctx.version, total)
            return status
        if returned == 0:
            return status
        # Only what we actually read back is defensible; totalResults stays in the evidence.
        total = min(int(total) if isinstance(total, int) else returned, returned)

    matched_on = ctx.cpe.nvd_name() if ctx.cpe and ctx.cpe.version else f"keyword:{ctx.product} {ctx.version}"
    remediation = _remediation(ctx, None)
    known = {v.cve for v in ctx.vulns}
    for item in result.get("top") or []:
        cve = item.get("cve")
        if not cve or cve in known:
            continue
        ctx.vulns.append(Vuln(
            device_id=ctx.device_id, service_id=ctx.service_id, cve=str(cve), source="nvd",
            kev=False, cvss=item.get("cvss"), epss=None, title=item.get("title"),
            published=item.get("published"), matched_on=matched_on, remediation=remediation,
        ))
    max_cvss = result.get("max_cvss")
    if max_cvss is not None and float(max_cvss) >= min_cvss:
        top = [{"cve": t.get("cve"), "cvss": t.get("cvss")} for t in (result.get("top") or [])]
        count = total if total is not None else len(top)
        qualifier = "" if by_cpe else (
            " Matched by product name and version text, not by CPE, so confirm the version "
            "before acting."
        )
        ctx.drafts.append(FindingDraft(
            finding_id="NET-VUL-003", subject=ctx.subject, device_id=ctx.device_id,
            detail=(f"{ctx.product} {ctx.version or ''} on port {ctx.row['port']} has "
                    f"{count} known CVEs in NVD (max CVSS {max_cvss}).{qualifier} {remediation}"),
            evidence={
                "count": count, "max_cvss": max_cvss, "top": top,
                "match": "cpe" if by_cpe else "keyword",
                "total_results": result.get("count"), "returned": returned,
                "product": ctx.product, "version": ctx.version, "matched_on": matched_on,
                "ip": ctx.row["ip"], "port": ctx.row["port"], "threshold": min_cvss,
            },
        ))
    return status


# --- EPSS --------------------------------------------------------------------

def _apply_epss(ctx: _ServiceCtx, epss: dict[str, float]) -> None:
    if not epss:
        return
    hot: list[dict[str, Any]] = []
    for vuln in ctx.vulns:
        score = epss.get(vuln.cve) or epss.get(vuln.cve.upper())
        if score is None:
            continue
        vuln.epss = float(score)
        if vuln.epss >= EPSS_ALERT_THRESHOLD:
            hot.append({"cve": vuln.cve, "epss": vuln.epss, "source": vuln.source})
    if hot:
        hot.sort(key=lambda h: -h["epss"])
        ctx.drafts.append(FindingDraft(
            finding_id="NET-VUL-004", subject=ctx.subject, device_id=ctx.device_id,
            detail=(f"{len(hot)} CVE(s) affecting {ctx.product} {ctx.version or ''} on port "
                    f"{ctx.row['port']} have an EPSS exploitation probability of at least "
                    f"{int(EPSS_ALERT_THRESHOLD * 100)}% (top: {hot[0]['cve']} at "
                    f"{hot[0]['epss']:.2f}). {_remediation(ctx, None)}"),
            evidence={"cves": hot, "product": ctx.product, "version": ctx.version,
                      "ip": ctx.row["ip"], "port": ctx.row["port"], "threshold": EPSS_ALERT_THRESHOLD},
        ))


# --- persistence -------------------------------------------------------------

def _upsert_vulns(conn: sqlite3.Connection, vulns: list[Vuln], now: str) -> int:
    count = 0
    for v in vulns:
        db.write(
            conn,
            "INSERT INTO vulns(device_id, service_id, cve, source, kev, cvss, epss, title, published, "
            "matched_on, remediation, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(device_id, cve, matched_on) DO UPDATE SET "
            "service_id=excluded.service_id, source=excluded.source, kev=MAX(vulns.kev, excluded.kev), "
            "cvss=COALESCE(excluded.cvss, vulns.cvss), epss=COALESCE(excluded.epss, vulns.epss), "
            "title=COALESCE(excluded.title, vulns.title), published=COALESCE(excluded.published, vulns.published), "
            "remediation=COALESCE(excluded.remediation, vulns.remediation), last_seen=excluded.last_seen",
            (v.device_id, v.service_id, v.cve, v.source, 1 if v.kev else 0, v.cvss, v.epss, v.title,
             v.published, v.matched_on, v.remediation, now, now),
        )
        count += 1
    return count


def _remediation(ctx: _ServiceCtx, kev_entry: dict | None) -> str:
    version = ctx.version or "the installed version"
    text = (f"Update {ctx.product} to a version newer than {version}; if this is a router/IoT device, "
            f"update its firmware or replace the device.")
    if ctx.is_router_iot:
        text += " This device looks like a router/IoT device: check the vendor's firmware page first."
    if kev_entry:
        action = _kev_field(kev_entry, "requiredAction", "required_action")
        due = _kev_field(kev_entry, "dueDate", "due_date")
        if action:
            text += f" CISA required action: {action}" + (f" (due {due})." if due else ".")
    text += (" Until then, block the port at the router/firewall or disable the service if it is not needed.")
    return text


# --- software (winget) -------------------------------------------------------

def evaluate_software(cfg, conn: sqlite3.Connection) -> list[FindingDraft]:
    """WIN-UPD-003 per outdated app, upgraded to WIN-UPD-004 for the high-risk list.

    Only rows the updater tagged as upgradable count; ``available`` equal to the
    installed version is winget noise, not a missing update.
    """
    try:
        rows = db.query(
            conn,
            "SELECT name, version, available, source, publisher FROM software "
            "WHERE available IS NOT NULL AND available <> '' ORDER BY name",
        )
    except sqlite3.Error as exc:
        logger.warning("software table unreadable: %s", exc)
        return []
    drafts: list[FindingDraft] = []
    for row in rows:
        name = (row["name"] or "").strip()
        if not name or not _is_outdated(row["version"], row["available"]):
            continue
        risky = _is_high_risk(name)
        finding_id = "WIN-UPD-004" if risky else "WIN-UPD-003"
        current = row["version"] or "unknown"
        detail = (f"{name} {current} is outdated; {row['available']} is available via {row['source']}. "
                  f"Update {name} to a version newer than {current}")
        if risky:
            detail += " - this app is on the high-risk list (commonly exploited when outdated)"
        detail += "."
        drafts.append(FindingDraft(
            finding_id=finding_id, subject="host",
            detail=detail,
            evidence={"key": name.lower(), "name": name, "version": row["version"],
                      "available": row["available"], "source": row["source"],
                      "publisher": row["publisher"], "high_risk": risky,
                      "winget": f'winget upgrade --id "{name}"' if row["source"] == "winget" else None},
        ))
    return drafts


def _is_outdated(version: str | None, available: str | None) -> bool:
    cur, avail = clean_version(version), clean_version(available)
    if avail is None:
        return False
    if cur is None:
        return True  # winget --include-unknown: unknown installed version, update offered
    return compare_versions(avail, cur) > 0


def _is_high_risk(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in HIGH_RISK_SOFTWARE)
