"""NVD 2.0 enrichment: CVE count, max CVSS and top CVEs for one CPE.

NVD is slow (about 1 s per call) and rate limited (5 requests / 30 s without a key,
50 with one), so this module is built around three guards rather than around the
HTTP call itself: a 7-day cache in the ``settings`` table, a sliding-window rate
limiter, and a per-scan wall-clock :class:`Budget` that makes every call give up
cleanly instead of stalling the scheduler.
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

from homesoc.vulns.cpe import CPE

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SEC = 15.0
RETRY_SLEEP_SEC = 6.0
CACHE_TTL_SEC = 7 * 24 * 3600
SCAN_BUDGET_SEC = 60.0
RESULTS_PER_PAGE = 50
TOP_N = 5
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CACHE_KEY_PREFIX = "nvd.cache."

# Monkeypatch points for tests; library code must never sleep for real under pytest.
_sleep = time.sleep
_monotonic = time.monotonic


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(text: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class Budget:
    """Wall-clock allowance shared by every NVD call in one scan.

    Sleeping for a rate-limit window is only acceptable while it fits in the
    allowance; once exhausted, callers get None and the scan moves on.
    """

    seconds: float = SCAN_BUDGET_SEC
    started: float = field(default_factory=lambda: _monotonic())
    exhausted: bool = False

    def remaining(self) -> float:
        return max(0.0, self.seconds - (_monotonic() - self.started))

    def can_spend(self, seconds: float) -> bool:
        return not self.exhausted and self.remaining() >= seconds


@dataclass
class RateLimiter:
    """Sliding-window limiter mirroring NVD's published policy."""

    max_requests: int
    window_sec: float = 30.0
    stamps: deque = field(default_factory=deque)

    @classmethod
    def for_key(cls, api_key: str | None) -> "RateLimiter":
        return cls(max_requests=50 if api_key else 5)

    def wait_needed(self) -> float:
        now = _monotonic()
        while self.stamps and now - self.stamps[0] >= self.window_sec:
            self.stamps.popleft()
        if len(self.stamps) < self.max_requests:
            return 0.0
        return max(0.0, self.window_sec - (now - self.stamps[0]))

    def record(self) -> None:
        self.stamps.append(_monotonic())


def cache_key(cpe: CPE | None, version: str | None, product: str | None) -> str:
    if cpe is not None:
        return CACHE_KEY_PREFIX + cpe.nvd_name()
    keyword = " ".join(p for p in (product, version) if p).strip().lower()
    return CACHE_KEY_PREFIX + "kw:" + "_".join(keyword.split())


def nvd_for_cpe(
    cpe: CPE | str | None,
    version: str | None,
    api_key: str | None = "",
    *,
    conn=None,
    budget: Budget | None = None,
    limiter: RateLimiter | None = None,
    product: str | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any] | None:
    """Return ``{"count", "max_cvss", "top", "query", "fetched_at"}`` or None.

    None means "could not find out" (network, budget, parse failure) and is never
    cached; an empty result (``count == 0``) is a real answer and is cached.
    ``conn`` enables the settings cache; without it every call hits the network.
    """
    if isinstance(cpe, str):
        from homesoc.vulns.cpe import parse_cpe

        try:
            cpe = parse_cpe(cpe)
        except ValueError:
            cpe = None
    if cpe is not None and version and not cpe.version:
        cpe = CPE(cpe.part, cpe.vendor, cpe.product, version)
    if cpe is None and not product:
        return None
    if not version and not (cpe is not None and cpe.version):
        # A keyword query without a version component can only return "every CVE ever filed for
        # this product name", which is never attributable to the service on the LAN.
        logger.debug("NVD lookup skipped for %s: no version", cpe.nvd_name() if cpe else product)
        return None

    key = cache_key(cpe, version, product)
    cached = _cache_get(conn, key)
    if cached is not None:
        cached["cached"] = True
        return cached

    params = _query_params(cpe, version, product)
    body = _fetch(params, api_key or "", budget or Budget(), limiter or RateLimiter.for_key(api_key), session)
    if body is None:
        return None
    result = summarize(body)
    result["query"] = params
    # How the CVEs were attributed. "cpe" is an exact cpeName match; "keyword" is a
    # full-text search that the caller must qualify (and must not report as a count of
    # CVEs affecting this build).
    result["match"] = "cpe" if "cpeName" in params else "keyword"
    result["fetched_at"] = _utcnow_iso()
    result["cached"] = False
    _cache_put(conn, key, result)
    return result


def _query_params(cpe: CPE | None, version: str | None, product: str | None) -> dict[str, str]:
    if cpe is not None and cpe.version:
        return {"cpeName": cpe.nvd_name(), "resultsPerPage": str(RESULTS_PER_PAGE)}
    # SPEC-GAP: a CPE without a version cannot use cpeName (NVD would return every
    # CVE ever filed for the product), so it degrades to the keyword search — and the
    # keyword search itself is refused without a version for the same reason.
    if not version:
        raise ValueError("NVD keyword search needs a version")
    keyword = " ".join(p for p in ((cpe.product if cpe else product), version) if p)
    return {"keywordSearch": keyword, "resultsPerPage": str(RESULTS_PER_PAGE)}


def _fetch(
    params: dict[str, str],
    api_key: str,
    budget: Budget,
    limiter: RateLimiter,
    session: requests.Session | None,
) -> dict[str, Any] | None:
    """One NVD GET with a single retry on 429/403 after a fixed 6 s pause."""
    headers = {"Accept": "application/json", "User-Agent": "HomeSOC/0.1 (+local)"}
    if api_key:
        headers["apiKey"] = api_key
    http = session or requests
    for attempt in (1, 2):
        wait = limiter.wait_needed()
        if not budget.can_spend(wait + REQUEST_TIMEOUT_SEC):
            budget.exhausted = True
            logger.info("NVD budget exhausted; skipping %s", params)
            return None
        if wait > 0:
            _sleep(wait)
        limiter.record()
        try:
            resp = http.get(NVD_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT_SEC)
        except requests.RequestException as exc:
            logger.warning("NVD request failed: %s", exc)
            return None
        status = getattr(resp, "status_code", 0)
        if status in (429, 403):
            if attempt == 2 or not budget.can_spend(RETRY_SLEEP_SEC + REQUEST_TIMEOUT_SEC):
                logger.warning("NVD rate limited (%s); giving up on %s", status, params)
                return None
            _sleep(RETRY_SLEEP_SEC)
            continue
        if status != 200:
            logger.warning("NVD returned %s for %s", status, params)
            return None
        raw = _read_limited(resp)
        if raw is None:
            return None
        try:
            body = json.loads(raw)
        except ValueError:
            logger.warning("NVD returned non-JSON for %s", params)
            return None
        return body if isinstance(body, dict) else None
    return None


def _read_limited(resp) -> bytes | None:
    """Read the body with a hard size cap; a feed is untrusted input even from NVD."""
    length = resp.headers.get("Content-Length") if getattr(resp, "headers", None) else None
    if length and length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
        logger.warning("NVD response too large (%s bytes)", length)
        return None
    if not hasattr(resp, "iter_content"):
        content = resp.content
        return content if len(content) <= MAX_RESPONSE_BYTES else None
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            logger.warning("NVD response exceeded %d bytes", MAX_RESPONSE_BYTES)
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def summarize(body: dict[str, Any]) -> dict[str, Any]:
    """Collapse an NVD 2.0 response into what the finding needs.

    Only the top 5 CVEs are kept because the dashboard links to NVD for the rest;
    persisting hundreds of rows per lighttpd would drown the vulns table.
    """
    cves: list[dict[str, Any]] = []
    for item in body.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not cve.get("id"):
            continue
        cves.append(
            {
                "cve": str(cve["id"]),
                "cvss": _best_cvss(cve.get("metrics") or {}),
                "published": _short_date(cve.get("published")),
                "title": _description(cve),
            }
        )
    cves.sort(key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0.0), c["cve"]))
    scores = [c["cvss"] for c in cves if c["cvss"] is not None]
    total = body.get("totalResults")
    count = int(total) if isinstance(total, int) and total >= len(cves) else len(cves)
    # `returned` is what this page actually contained: the only number a caller can defend
    # when the query was a keyword search rather than an exact cpeName.
    return {"count": count, "returned": len(cves), "max_cvss": max(scores) if scores else None,
            "top": cves[:TOP_N]}


def _best_cvss(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            data = entry.get("cvssData") if isinstance(entry, dict) else None
            score = data.get("baseScore") if isinstance(data, dict) else None
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _description(cve: dict[str, Any]) -> str | None:
    for desc in cve.get("descriptions") or []:
        if isinstance(desc, dict) and desc.get("lang", "en") == "en" and desc.get("value"):
            return str(desc["value"])[:300]
    return None


def _short_date(value: Any) -> str | None:
    return str(value)[:10] if value else None


def _cache_get(conn, key: str) -> dict[str, Any] | None:
    if conn is None:
        return None
    from homesoc import db

    try:
        raw = db.get_setting(conn, key)
    except Exception:  # pragma: no cover - cache must never break enrichment
        logger.exception("settings cache read failed for %s", key)
        return None
    if not raw:
        return None
    try:
        entry = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(entry, dict) or not isinstance(entry.get("result"), dict):
        return None
    fetched = _parse_iso(str(entry.get("fetched_at", "")))
    if fetched is None or (datetime.now(timezone.utc) - fetched).total_seconds() > CACHE_TTL_SEC:
        return None
    return dict(entry["result"])


def _cache_put(conn, key: str, result: dict[str, Any]) -> None:
    if conn is None:
        return
    from homesoc import db

    payload = {"fetched_at": result.get("fetched_at") or _utcnow_iso(), "result": result}
    try:
        db.set_setting(conn, key, json.dumps(payload, separators=(",", ":")))
    except Exception:  # pragma: no cover
        logger.exception("settings cache write failed for %s", key)
