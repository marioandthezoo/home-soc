"""Recent-download hash checks against VirusTotal (SPEC 6.10).

Hashes files modified in the last 24 h (< 64 MB) under ``host.files_dirs``; unknown hashes are
looked up with ``GET /api/v3/files/<sha256>`` when a VirusTotal key is configured. Files are
never uploaded. The daily quota is shared with the DNS reputation worker through
``dnsfilter.reputation.shared_budget`` (imported lazily; a local equivalent is used if that module
is unavailable so this scanner never hard-depends on the DNS package).

Only detections are final. "unknown" (VirusTotal has not seen the hash) and "clean" are provisional
and looked up again later (:func:`recheck_due`), because a fresh payload is exactly what VirusTotal
has not classified yet at download time. The API key is never sent across a redirect.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from homesoc import db
from homesoc.models import ScanResult
from homesoc.scanners.host_windows import Collector, cfg_get
from homesoc.util import age_seconds, json_dumps, utcnow_iso

if TYPE_CHECKING:  # pragma: no cover
    from homesoc.config import Config

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 64 * 1024 * 1024
RECENT_WINDOW_SEC = 24 * 3600
MAX_FILES_PER_RUN = 500
MAX_DEPTH = 3
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_TIMEOUT_SEC = 15
# Wall clock for one whole lookup (connect, headers and capped body), as a multiple of VT_TIMEOUT_SEC.
VT_WALL_CLOCK_FACTOR = 3
VT_PER_MINUTE = 4
VT_MAX_BODY_BYTES = 2 * 1024 * 1024  # untrusted third-party body; cap what one lookup can allocate

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"
VERDICT_UNKNOWN = "unknown"      # VirusTotal has never seen this hash
VERDICT_UNCHECKED = "unchecked"  # no key / no budget yet
#: Verdicts that are never looked up again: a detection does not go away by asking twice.
FINAL_VERDICTS = {VERDICT_MALICIOUS, VERDICT_SUSPICIOUS}
#: Verdicts that are provisional. A fresh payload is typically "unknown" (never seen) or "clean"
#: (seen, not yet detected) at download time and detected hours or days later, so these are looked
#: up again once they are old enough (see :func:`recheck_due`), within the shared daily budget.
RECHECK_VERDICTS = {VERDICT_UNKNOWN, VERDICT_CLEAN}
#: First re-check of an "unknown" hash after 6 h, then 12 h, 24 h, ... (doubling, capped at 7 days).
UNKNOWN_RECHECK_SEC = 6 * 3600
#: A "clean" hash is looked up again when the file shows up again 3 days or more later.
CLEAN_RECHECK_SEC = 3 * 86400
RECHECK_MAX_SEC = 7 * 86400

_SKIP_SUFFIXES = {".crdownload", ".part", ".tmp", ".partial"}


# --------------------------------------------------------------------------- budget


class LocalBudget:
    """Minimal stand-in for ``dnsfilter.reputation.Budget`` with the same settings key and API.

    Sharing ``vt.budget.<date>`` means the two implementations still count against one quota if
    they are ever active in the same process.
    """

    SETTING_PREFIX = "vt.budget."

    def __init__(self, conn: Any, daily_limit: int, per_minute: int = VT_PER_MINUTE) -> None:
        self.conn = conn
        self.daily_limit = max(0, int(daily_limit))
        self.per_minute = max(1, int(per_minute))
        self._lock = threading.Lock()
        self._recent: list[float] = []
        self._date = self._today()
        self._used = self._load()

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _load(self) -> int:
        try:
            return int(db.get_setting(self.conn, self.SETTING_PREFIX + self._date, "0") or 0)
        except (ValueError, TypeError):
            return 0

    def used_today(self) -> int:
        with self._lock:
            self._roll()
            return self._used

    def remaining_today(self) -> int:
        return max(0, self.daily_limit - self.used_today())

    def _roll(self) -> None:
        today = self._today()
        if today != self._date:
            self._date, self._used = today, 0

    def try_acquire(self, *, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._roll()
            self._recent = [t for t in self._recent if now - t < 60.0]
            if self._used >= self.daily_limit or len(self._recent) >= self.per_minute:
                return False
            self._recent.append(now)
            self._used += 1
            try:
                db.set_setting(self.conn, self.SETTING_PREFIX + self._date, str(self._used))
            except Exception:  # noqa: BLE001 - budget persistence must never break a scan
                logger.debug("could not persist VT budget", exc_info=True)
            return True


def get_budget(cfg: Any, conn: Any) -> Any:
    """Prefer the process-wide budget from the DNS package; fall back to the local one."""
    try:
        from homesoc.dnsfilter import reputation  # lazy: optional at import time

        shared = getattr(reputation, "shared_budget", None)
        if callable(shared):
            b = shared(cfg, conn)
            if hasattr(b, "try_acquire"):
                return b
    except Exception:  # noqa: BLE001 - any import/runtime problem simply means "use local"
        logger.debug("dnsfilter.reputation budget unavailable; using local budget", exc_info=True)
    return LocalBudget(conn, int(cfg_get(cfg, "dns.virustotal_daily_budget", 400) or 400))


# --------------------------------------------------------------------------- files


def candidate_files(dirs: Iterable[Path | str], *, now: float | None = None, window_sec: float = RECENT_WINDOW_SEC, max_bytes: int = MAX_FILE_BYTES, limit: int = MAX_FILES_PER_RUN) -> list[Path]:
    """Regular files under ``dirs`` (a few levels deep) modified inside the window and under the size cap."""
    now = time.time() if now is None else now
    out: list[Path] = []
    for d in dirs:
        root = Path(os.path.expandvars(str(d))).expanduser()
        if not root.is_dir():
            continue
        for path in _walk(root, MAX_DEPTH):
            try:
                st = path.stat()
            except OSError:
                continue
            if path.suffix.lower() in _SKIP_SUFFIXES or st.st_size <= 0 or st.st_size > max_bytes:
                continue
            if now - st.st_mtime > window_sec:
                continue
            out.append(path)
            if len(out) >= limit:
                return out
    return out


def _walk(root: Path, depth: int) -> Iterable[Path]:
    try:
        with os.scandir(root) as it:
            entries = list(it)
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_file(follow_symlinks=False):
                yield Path(entry.path)
            elif entry.is_dir(follow_symlinks=False) and depth > 0:
                yield from _walk(Path(entry.path), depth - 1)
        except OSError:
            continue


def sha256_of(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


# --------------------------------------------------------------------------- virustotal


@contextlib.contextmanager
def _get_no_redirects(requests_mod: Any, url: str, **kwargs: Any) -> Iterator[Any]:
    """GET that never follows a redirect (``allow_redirects=False``); a 3xx comes back as-is.

    ``requests_mod`` is the ``requests`` module (a parameter so tests can pass a double).
    (``max_redirects = 0`` is deliberately not set: ``requests`` then raises on any 3xx even with
    ``allow_redirects=False``, which would hide the status code.)
    """
    with requests_mod.Session() as session, session.get(url, allow_redirects=False, **kwargs) as resp:
        yield resp


def vt_fetch(api_key: str, sha256: str, timeout: float = VT_TIMEOUT_SEC) -> tuple[int, dict[str, Any] | None]:
    """``(http_status, json)``; status 0 on network failure. Split out so tests can stub it.

    The body is streamed and hard-capped at :data:`VT_MAX_BODY_BYTES`: this is third-party input,
    and a report for a heavily-detected file can be large, so an unbounded ``resp.json()`` would
    let the remote side decide how much memory a scan uses.

    Redirects are never followed. ``requests`` strips only ``Authorization`` on a cross-host
    redirect, so the ``x-apikey`` header would otherwise be replayed to whatever host a ``Location``
    header names. Any 3xx is returned as its status code, which :func:`lookup_hash` maps to
    "unchecked".
    """
    try:
        import requests
    except ImportError:  # pragma: no cover
        return 0, None
    from homesoc.feeds.netguard import Watch

    # requests' timeout is per recv: a server that drips one byte at a time never trips it. The
    # watch shuts the connection down when the wall clock runs out, whatever phase it is in.
    try:
        with Watch(lambda: max(float(timeout), 1.0) * VT_WALL_CLOCK_FACTOR, "VirusTotal lookup"), _get_no_redirects(
            requests,
            VT_FILE_URL.format(sha256=sha256),
            headers={"x-apikey": api_key, "accept": "application/json"},
            timeout=timeout,
            stream=True,
        ) as resp:
            if resp.status_code != 200:
                return resp.status_code, None
            chunks: list[bytes] = []
            size = 0
            for chunk in resp.iter_content(64 * 1024):
                chunks.append(chunk)
                size += len(chunk)
                if size > VT_MAX_BODY_BYTES:
                    logger.warning("VirusTotal response for %s exceeded %d bytes; ignored", sha256, VT_MAX_BODY_BYTES)
                    return 200, None
            raw = b"".join(chunks)
    except requests.RequestException as exc:
        logger.warning("VirusTotal lookup failed: %s", exc)
        return 0, None
    try:
        body = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return 200, None
    return 200, body if isinstance(body, dict) else None


def verdict_from_stats(stats: dict[str, Any] | None, min_malicious: int) -> str:
    if not isinstance(stats, dict):
        return VERDICT_UNKNOWN
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    if malicious >= max(1, min_malicious):
        return VERDICT_MALICIOUS
    if malicious > 0 or suspicious > 0:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


def lookup_hash(api_key: str, sha256: str, min_malicious: int) -> tuple[str, dict[str, Any]]:
    """Verdict + compact detail for one hash; 404 means VirusTotal has never seen the file."""
    code, body = vt_fetch(api_key, sha256)
    if code == 404:
        return VERDICT_UNKNOWN, {"http": 404}
    if code != 200 or body is None:
        return VERDICT_UNCHECKED, {"http": code}
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    verdict = verdict_from_stats(stats, min_malicious)
    detail = {
        "http": 200,
        "stats": {k: int(stats.get(k) or 0) for k in ("malicious", "suspicious", "harmless", "undetected")},
        "type": attrs.get("type_description"),
        "names": list(attrs.get("names") or [])[:5],
        "threat_label": ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }
    return verdict, detail


# --------------------------------------------------------------------------- persistence


def existing_check(conn: Any, sha256: str) -> dict[str, Any] | None:
    row = db.one(conn, "SELECT sha256, path, size, first_seen, verdict, source, detail FROM file_checks WHERE sha256 = ?", (sha256,))
    return dict(row) if row else None


def upsert_check(conn: Any, sha256: str, path: Path, size: int, verdict: str, source: str | None, detail: dict[str, Any] | None) -> None:
    """Insert or refresh a hash. ``detail=None`` keeps the stored detail (a cached run has none)."""
    db.write(
        conn,
        "INSERT INTO file_checks(sha256, path, size, first_seen, verdict, source, detail) VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(sha256) DO UPDATE SET path = excluded.path, size = excluded.size, verdict = excluded.verdict, "
        "source = excluded.source, detail = COALESCE(excluded.detail, file_checks.detail)",
        (sha256, str(path), int(size), utcnow_iso(), verdict, source, json_dumps(detail) if detail else None),
    )


def _detail_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def recheck_due(row: dict[str, Any] | None) -> bool:
    """Whether a stored hash should be looked up (again).

    Detections are final. "unknown" is re-checked after :data:`UNKNOWN_RECHECK_SEC`, doubling per
    unsuccessful attempt up to :data:`RECHECK_MAX_SEC`; "clean" after :data:`CLEAN_RECHECK_SEC`.
    Files are only candidates while they are recent, so in practice this means "a few more times
    while the download is fresh, and again whenever the same file is downloaded later".
    """
    if row is None:
        return True
    verdict = row.get("verdict")
    if verdict in FINAL_VERDICTS:
        return False
    if verdict not in RECHECK_VERDICTS:
        return True  # unchecked (no key or no budget last time)
    detail = _detail_dict(row.get("detail"))
    age = age_seconds(detail.get("checked_at") or row.get("first_seen"))
    if age is None:
        return True
    if verdict == VERDICT_UNKNOWN:
        try:
            attempts = max(1, int(detail.get("attempts") or 1))
        except (TypeError, ValueError):
            attempts = 1
        interval = min(RECHECK_MAX_SEC, UNKNOWN_RECHECK_SEC * 2 ** min(attempts - 1, 8))
    else:
        interval = CLEAN_RECHECK_SEC
    return age >= interval


# --------------------------------------------------------------------------- scanner entry point


def run(cfg: Config, conn: Any, *, quick: bool = False, progress: Callable[[str], None] | None = None) -> ScanResult:
    """Scanner interface (SPEC 6): hash recent files, look up unknown hashes, emit AV-FILE-* drafts."""
    started = time.monotonic()
    notify = progress or (lambda _msg: None)
    if not cfg_get(cfg, "host.files_check", True):
        return ScanResult("files", [], {"skipped": "host.files_check disabled"})

    dirs = [str(d) for d in (cfg_get(cfg, "host.files_dirs", ("~/Downloads",)) or ())]
    api_key = str(cfg_get(cfg, "dns.virustotal_api_key", "") or "").strip()
    min_malicious = int(cfg_get(cfg, "dns.reputation_min_malicious_votes", 2) or 2)
    budget = get_budget(cfg, conn) if api_key else None

    notify("files: hashing recent files")
    files = candidate_files(dirs)
    c = Collector()
    counts = {"files": len(files), "hashed": 0, "looked_up": 0, "cached": 0, "budget_exhausted": 0, "malicious": 0, "suspicious": 0, "errors": 0}
    stop_lookups = False
    for path in files:
        digest = sha256_of(path)
        if digest is None:
            counts["errors"] += 1
            continue
        counts["hashed"] += 1
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        row = existing_check(conn, digest)
        verdict = row["verdict"] if row else VERDICT_UNCHECKED
        source = row["source"] if row else None
        detail: dict[str, Any] | None = None
        if not recheck_due(row):
            counts["cached"] += 1
        elif api_key and budget is not None and not stop_lookups:
            if budget.try_acquire():
                new_verdict, new_detail = lookup_hash(api_key, digest, min_malicious)
                counts["looked_up"] += 1
                if new_detail.get("http") == 429:
                    stop_lookups = True  # quota hit upstream; stop spending the day's budget
                if new_verdict == VERDICT_UNCHECKED and row and row["verdict"] in RECHECK_VERDICTS:
                    pass  # a failed re-check keeps what we knew; checked_at is unchanged, so it retries next run
                else:
                    verdict, detail, source = new_verdict, new_detail, "virustotal"
                    detail["checked_at"] = utcnow_iso()
                    if verdict == VERDICT_UNKNOWN:
                        prior = _detail_dict(row.get("detail")) if row and row["verdict"] == VERDICT_UNKNOWN else {}
                        try:
                            detail["attempts"] = int(prior.get("attempts") or 1) + 1 if prior else 1
                        except (TypeError, ValueError):
                            detail["attempts"] = 1
            else:
                counts["budget_exhausted"] += 1
        upsert_check(conn, digest, path, size, verdict, source, detail)
        if verdict == VERDICT_MALICIOUS:
            counts["malicious"] += 1
            c.finding("AV-FILE-001", _evidence(path, digest, size, row, detail), key=digest, detail=f"{path.name} flagged malicious by VirusTotal")
        elif verdict == VERDICT_SUSPICIOUS:
            counts["suspicious"] += 1
            c.finding("AV-FILE-002", _evidence(path, digest, size, row, detail), key=digest, detail=f"{path.name} flagged suspicious by VirusTotal")

    db.set_setting(conn, "files.checked_at", utcnow_iso())
    db.record_metric(conn, "files.hashed", float(counts["hashed"]))
    summary: dict[str, Any] = dict(counts)
    summary.update({"dirs": dirs, "virustotal": bool(api_key), "duration_sec": round(time.monotonic() - started, 2), "findings": len(c.findings)})
    if budget is not None and hasattr(budget, "remaining_today"):
        summary["vt_remaining_today"] = budget.remaining_today()
    notify(f"files: {counts['hashed']} hashed, {counts['looked_up']} looked up, {counts['malicious']} malicious")
    return ScanResult("files", c.findings, summary)


def _evidence(path: Path, digest: str, size: int, row: dict[str, Any] | None, detail: dict[str, Any] | None) -> dict[str, Any]:
    ev: dict[str, Any] = {"path": str(path), "sha256": digest, "size": size}
    if detail:
        ev.update({k: v for k, v in detail.items() if k in ("stats", "type", "names", "threat_label")})
    elif row and row.get("detail"):
        ev["cached_detail"] = row["detail"]
    ev["vt_url"] = f"https://www.virustotal.com/gui/file/{digest}"
    return ev


__all__ = [
    "LocalBudget",
    "MAX_FILE_BYTES",
    "RECENT_WINDOW_SEC",
    "candidate_files",
    "get_budget",
    "lookup_hash",
    "recheck_due",
    "run",
    "sha256_of",
    "verdict_from_stats",
    "vt_fetch",
]
