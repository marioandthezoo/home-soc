"""Feed downloader: conditional GET, size-capped streaming, atomic file replace.

Every feed is untrusted input. Downloads are capped at `feeds.max_download_mb`
(or the feed's own tighter cap, see FeedSpec.max_bytes) both on the wire and
after gzip inflation, written to `<name>.tmp` and only then moved into place
with os.replace so a crash mid-download can never leave a truncated list that
the DNS filter would happily load.

Redirects are followed by hand, not by requests: every hop must be https and
must not point at a loopback, private, link-local, CGNAT or multicast address,
so a compromised feed origin cannot bounce Home SOC into the LAN (blind GET
SSRF against a router's CGI) or downgrade the download to plain http.
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import logging
import os
import socket
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from homesoc.feeds import parsers, registry

logger = logging.getLogger(__name__)

USER_AGENT = "HomeSOC/0.1 (+https://github.com/homesoc; local security monitor)"
CONNECT_TIMEOUT_SEC = 10
READ_TIMEOUT_SEC = 60
# requests' read timeout is per recv(); a mirror trickling 1 KB every 50 s would otherwise hold the
# single scheduler thread for hours, so every feed and every update() call also has a wall clock.
FEED_MAX_SECONDS = 180.0
UPDATE_MAX_SECONDS = 600.0
MIN_THROUGHPUT_BYTES_PER_SEC = 1024
THROUGHPUT_GRACE_SEC = 30.0
# Failure backoff: 1 h, 2 h, 4 h ... capped at 24 h (settings keys, SPEC-GAP: feeds has no such column).
BACKOFF_BASE_HOURS = 1.0
BACKOFF_MAX_HOURS = 24.0
ERROR_SINCE_KEY = "feeds.error_since."
FAILURES_KEY = "feeds.failures."
CHUNK_BYTES = 64 * 1024
GZIP_MAGIC = b"\x1f\x8b"
# The inflated file is held to the same cap as the download (never a multiple of it): the
# parsers and registry loaders hold the whole document in memory, and JSON costs ~25x its size
# there, so "8x the wire cap" meant a 0.5 MB body could cost ~13 GB of RAM.
MAX_REDIRECTS = 5
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
PARSE_DEADLINE_EVERY_LINES = 20000

_LOCK = threading.Lock()

# Extension per kind keeps the data folder self-describing for a human.
_EXT = {"kev": "json", "epss": "csv", "oui": "txt", "json": "json"}

_THREATINTEL = frozenset(
    {"urlhaus", "urlhaus_filter", "threatfox", "phishing_army", "openphish", "feodo_ips", "spamhaus_drop"}
)


class FeedError(Exception):
    """A single feed failed; the updater records it and moves on to the next."""


# ---------------------------------------------------------------- helpers ---


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _cfg_get(cfg: Any, dotted: str, default: Any) -> Any:
    """Read "section.key" from a Config dataclass, namespace or nested dict."""
    node = cfg
    for part in dotted.split("."):
        if node is None:
            return default
        if isinstance(node, dict):
            node = node.get(part)
        else:
            node = getattr(node, part, None)
    return default if node is None else node


def _feeds_dir() -> Path:
    # SPEC-GAP: homesoc.paths is owned by P1 and may not exist yet; mirror its
    # documented rule (HOMESOC_DATA or <project_root>/data, then /feeds).
    try:
        from homesoc.paths import feeds_dir  # type: ignore[import-not-found]

        return Path(feeds_dir())
    except ImportError:
        pass
    env = os.environ.get("HOMESOC_DATA")
    base = Path(env) if env else Path(__file__).resolve().parents[2] / "data"
    path = base / "feeds"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _db_module() -> Any:
    try:
        from homesoc import db  # type: ignore[import-not-found]

        return db
    except ImportError:
        return None


def _write(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> None:
    db = _db_module()
    if db is not None and hasattr(db, "write"):
        db.write(conn, sql, params)
        return
    with _LOCK:
        conn.execute(sql, params)
        conn.commit()


def _one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> dict[str, Any] | None:
    """Fetch one row as a plain dict, whatever row_factory the connection uses."""
    cur = conn.execute(sql, params)
    row = cur.fetchone()
    if row is None:
        return None
    return dict(zip((d[0] for d in cur.description), tuple(row)))


def _row_get(row: dict[str, Any] | None, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    value = row.get(key)
    return default if value is None else value


def _record_metric(conn: sqlite3.Connection, name: str, value: float, tags: dict | None) -> None:
    db = _db_module()
    if db is not None and hasattr(db, "record_metric"):
        try:
            db.record_metric(conn, name, value, tags)
        except sqlite3.Error as exc:  # telemetry must never break an update
            logger.debug("metric %s not recorded: %s", name, exc)


def _record_event(conn: sqlite3.Connection, level: str, message: str, data: dict | None) -> None:
    db = _db_module()
    if db is not None and hasattr(db, "record_event"):
        try:
            db.record_event(conn, level, "feeds", message, data)
        except sqlite3.Error as exc:
            logger.debug("event not recorded: %s", exc)


def _get_setting(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = _one(conn, "SELECT value FROM settings WHERE key = ?", (key,))
    except sqlite3.Error:
        return None
    return None if row is None else str(row.get("value"))


def _set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    try:
        _write(
            conn,
            "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, _utcnow_iso()),
        )
    except sqlite3.Error as exc:
        logger.debug("setting %s not written: %s", key, exc)


def _del_setting(conn: sqlite3.Connection, key: str) -> None:
    try:
        _write(conn, "DELETE FROM settings WHERE key = ?", (key,))
    except sqlite3.Error:
        pass


def error_since(conn: sqlite3.Connection, name: str) -> datetime | None:
    """When the current run of consecutive failures started (None while the feed is healthy)."""
    return _parse_iso(_get_setting(conn, ERROR_SINCE_KEY + name))


def consecutive_failures(conn: sqlite3.Connection, name: str) -> int:
    try:
        return int(_get_setting(conn, FAILURES_KEY + name) or 0)
    except ValueError:
        return 0


def backoff_until(conn: sqlite3.Connection, name: str) -> datetime | None:
    """Earliest time the next attempt for a failing feed makes sense (1 h, 2 h, ... 24 h)."""
    failures = consecutive_failures(conn, name)
    if failures <= 0:
        return None
    row = _one(conn, "SELECT last_checked FROM feeds WHERE name = ?", (name,))
    last = _parse_iso(_row_get(row, "last_checked"))
    if last is None:
        return None
    hours = min(BACKOFF_MAX_HOURS, BACKOFF_BASE_HOURS * (2 ** (failures - 1)))
    return last + timedelta(hours=hours)


class _Deadline:
    """Monotonic wall clock for one download; raising FeedError from inside the stream loop."""

    def __init__(self, seconds: float) -> None:
        self.started = time.monotonic()
        self.seconds = seconds

    def check(self, what: str) -> None:
        if time.monotonic() - self.started > self.seconds:
            raise FeedError(f"{what} exceeded {int(self.seconds)} s")

    def remaining(self) -> float:
        return max(0.0, self.seconds - (time.monotonic() - self.started))


# ------------------------------------------------------------- public API ---


def feed_path(name: str) -> Path:
    """On-disk location of a feed's current (fully downloaded) file."""
    spec = registry.FEEDS.get(name)
    ext = _EXT.get(spec.kind, "txt") if spec else "txt"
    return _feeds_dir() / f"{name}.{ext}"


def effective_hours(cfg: Any, spec: registry.FeedSpec) -> int:
    """Refresh cadence: the config's per-category hours win over the registry default."""
    if spec.kind == "kev":
        key = "feeds.kev_hours"
    elif spec.kind == "epss":
        key = "feeds.epss_hours"
    elif spec.kind == "oui":
        key = "feeds.oui_hours"
    elif spec.name in _THREATINTEL:
        key = "feeds.threatintel_hours"
    else:
        key = "feeds.blocklists_hours"
    hours = _cfg_get(cfg, key, spec.hours)
    try:
        return max(1, int(hours))
    except (TypeError, ValueError):
        return spec.hours


def is_stale(conn: sqlite3.Connection, name: str, hours: int) -> bool:
    """True when the feed was never fetched successfully, its file is missing, or it is older than `hours`."""
    if not feed_path(name).exists():
        return True
    row = _one(conn, "SELECT last_updated, last_checked FROM feeds WHERE name = ?", (name,))
    last = _parse_iso(_row_get(row, "last_updated"))
    if last is None:
        return True
    return datetime.now(timezone.utc) - last > timedelta(hours=hours)


def update(
    cfg: Any,
    conn: sqlite3.Connection,
    names: list[str] | None = None,
    force: bool = False,
    progress: Callable[[str], None] | None = None,
) -> dict[str, str]:
    """Refresh feeds and return {name: updated|not_modified|error|skipped}.

    `force` bypasses the staleness check and the per-feed enabled flag (the
    user pressed the button; they get what they asked for) but never the size
    cap. Failures leave the previous file untouched so a flaky mirror degrades
    to "stale" rather than "empty".
    """
    wanted = list(names) if names else list(registry.FEEDS)
    max_bytes = int(float(_cfg_get(cfg, "feeds.max_download_mb", 64)) * 1024 * 1024)
    feeds_enabled = bool(_cfg_get(cfg, "feeds.enabled", True))
    results: dict[str, str] = {}
    batch = _Deadline(UPDATE_MAX_SECONDS)

    def say(msg: str) -> None:
        logger.info(msg)
        if progress:
            progress(msg)

    for name in wanted:
        spec = registry.FEEDS.get(name)
        if spec is None:
            logger.warning("unknown feed %r requested", name)
            results[name] = "skipped"
            continue
        _ensure_row(conn, spec)
        if not feeds_enabled and not force:
            results[name] = "skipped"
            continue
        row = _one(conn, "SELECT * FROM feeds WHERE name = ?", (name,))
        enabled = bool(_row_get(row, "enabled", 1 if spec.enabled_default else 0))
        if not enabled and not force:
            results[name] = "skipped"
            continue
        if not force and not is_stale(conn, name, effective_hours(cfg, spec)):
            results[name] = "skipped"
            continue
        retry_at = None if force else backoff_until(conn, name)
        if retry_at is not None and datetime.now(timezone.utc) < retry_at:
            results[name] = "skipped"
            logger.info("feed %s: backing off until %s after %d failure(s)", name, retry_at.isoformat(timespec="minutes"),
                        consecutive_failures(conn, name))
            continue
        if batch.remaining() <= 0:
            results[name] = "skipped"
            logger.warning("feed %s: skipped, update() exceeded %d s", name, int(UPDATE_MAX_SECONDS))
            continue
        say(f"feed {name}: fetching")
        try:
            results[name] = _fetch_one(conn, spec, row, max_bytes, deadline=_Deadline(min(FEED_MAX_SECONDS, batch.remaining())))
            _note_success(conn, name)
        except FeedError as exc:
            results[name] = "error"
            _mark_error(conn, name, str(exc))
            _record_event(conn, "warning", f"feed {name} failed: {exc}", {"feed": name})
            logger.warning("feed %s failed: %s", name, exc)
        except Exception as exc:  # noqa: BLE001 - one bad feed must not abort the batch
            results[name] = "error"
            _mark_error(conn, name, f"{type(exc).__name__}: {exc}")
            _record_event(conn, "error", f"feed {name} crashed: {exc}", {"feed": name})
            logger.exception("feed %s crashed", name)
        say(f"feed {name}: {results[name]}")
    return results


def _note_success(conn: sqlite3.Connection, name: str) -> None:
    _del_setting(conn, ERROR_SINCE_KEY + name)
    _del_setting(conn, FAILURES_KEY + name)


def health_findings(conn: sqlite3.Connection, hours: int = 48) -> list[Any]:
    """Drafts for SOC-FEED-001 (any feed failing > `hours`) and SOC-FEED-002 (KEV stale > `hours`).

    Returned as `homesoc.models.FindingDraft`; the scheduler's feeds job feeds
    them to findings.engine.apply(). Only enabled feeds count: a list the user
    switched off is not "failing".
    """
    # SPEC-GAP: the spec names the finding IDs but not the emitting function;
    # this is the smallest hook cli/scheduler can call after update().
    #
    # NOT WIRED UP, and deliberately so: ``cli.soc_health_drafts`` is the single live
    # owner of SOC-FEED-001/002 (source 'soc'). Two emitters would share one dedupe key
    # under different sources, so neither could auto-resolve the other's row. Before
    # calling this from the runtime, delete the cli half -- and note that this one fires
    # on a never-succeeded feed's *first* error, which floods an offline first start;
    # cli waits on the ``feeds.error_since.<name>`` setting that update() below writes.
    from homesoc.models import FindingDraft  # type: ignore[import-not-found]

    drafts: list[Any] = []
    now = datetime.now(timezone.utc)
    limit = timedelta(hours=hours)
    for spec in registry.FEEDS.values():
        row = _one(conn, "SELECT * FROM feeds WHERE name = ?", (spec.name,))
        if row is None or not bool(_row_get(row, "enabled", 1)):
            continue
        last_ok = _parse_iso(_row_get(row, "last_updated"))
        status = _row_get(row, "status", "never")
        age_ok = last_ok is not None and now - last_ok <= limit
        # "Failing" = the latest attempt errored and no success is recent enough
        # to cover for it. A feed that never succeeded fires on its first error;
        # the table has no first-failure timestamp to wait on.
        if status == "error" and not age_ok:
            drafts.append(
                FindingDraft(
                    finding_id="SOC-FEED-001",
                    subject=f"feed:{spec.name}",
                    evidence={
                        "feed": spec.name,
                        "url": spec.url,
                        "last_updated": _row_get(row, "last_updated"),
                        "error": _row_get(row, "error"),
                    },
                    detail=f"Feed '{spec.name}' has not updated successfully for more than {hours} hours.",
                )
            )
        if spec.kind == "kev" and not age_ok:
            drafts.append(
                FindingDraft(
                    finding_id="SOC-FEED-002",
                    subject="feed:kev",
                    evidence={"last_updated": _row_get(row, "last_updated"), "status": status},
                    detail="The CISA KEV catalog on disk is older than 48 hours; vulnerability matching may miss new exploits.",
                )
            )
    return drafts


# --------------------------------------------------------------- internals ---


def _ensure_row(conn: sqlite3.Connection, spec: registry.FeedSpec) -> None:
    _write(
        conn,
        "INSERT OR IGNORE INTO feeds(name, url, kind, status, enabled) VALUES (?, ?, ?, 'never', ?)",
        (spec.name, spec.url, spec.kind, 1 if spec.enabled_default else 0),
    )
    # URLs occasionally move between releases; keep the row's URL current.
    _write(conn, "UPDATE feeds SET url = ?, kind = ? WHERE name = ? AND url != ?", (spec.url, spec.kind, spec.name, spec.url))


def _mark_error(conn: sqlite3.Connection, name: str, error: str) -> None:
    now = _utcnow_iso()
    _write(
        conn,
        "UPDATE feeds SET status = 'error', error = ?, last_checked = ? WHERE name = ?",
        (error[:500], now, name),
    )
    if _get_setting(conn, ERROR_SINCE_KEY + name) is None:
        _set_setting(conn, ERROR_SINCE_KEY + name, now)
    _set_setting(conn, FAILURES_KEY + name, str(consecutive_failures(conn, name) + 1))


def _is_public_ip(value: str) -> bool:
    """True only for globally routable unicast addresses (no loopback/RFC 1918/link-local/CGNAT/multicast)."""
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _check_hop(url: str) -> str:
    """Validate one request target (the feed URL or a redirect Location); return its hostname.

    Runs without DNS so it also guards the scripted responses tests use. Name resolution is
    checked separately in _http_get, right before the real connection.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError as exc:
        raise FeedError(f"refusing malformed URL {url[:200]!r}") from exc
    if parts.scheme.lower() != "https":
        raise FeedError(f"refusing non-https URL {url[:200]!r}")
    if not host:
        raise FeedError(f"refusing URL without a host {url[:200]!r}")
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return host  # a name; resolved and checked in _http_get
    if not _is_public_ip(host):
        raise FeedError(f"refusing URL pointing at non-public address {host}")
    return host


def _check_resolves_public(host: str) -> None:
    """Refuse a host name that resolves to any non-public address.

    This runs before the connection and requests resolves again, so a rebinding name could
    still switch addresses in between. That leaves no usable SSRF: every hop is https with
    certificate verification, so the request line (path, query) is only ever sent after the
    peer has proven it holds a publicly trusted certificate for that name.
    """
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as exc:
        raise FeedError(f"cannot resolve {host}: {exc}") from exc
    for info in infos:
        addr = str(info[4][0])
        if not _is_public_ip(addr):
            raise FeedError(f"refusing {host}: resolves to non-public address {addr}")


def _http_get(url: str, headers: dict[str, str], timeout: tuple[int, int]) -> requests.Response:
    """One request, redirects not followed (tests substitute a fake response without a network)."""
    _check_resolves_public(_check_hop(url))
    return requests.get(url, headers=headers, timeout=timeout, stream=True, allow_redirects=False)


def _open(url: str, headers: dict[str, str], deadline: _Deadline) -> requests.Response:
    """GET `url`, following at most MAX_REDIRECTS redirects, each hop re-validated by _check_hop."""
    for _hop in range(MAX_REDIRECTS + 1):
        _check_hop(url)
        try:
            resp = _http_get(url, headers, (CONNECT_TIMEOUT_SEC, READ_TIMEOUT_SEC))
        except requests.RequestException as exc:
            raise FeedError(f"request failed: {exc}") from exc
        if resp.status_code not in _REDIRECT_CODES:
            return resp
        with resp:  # release the connection; a redirect body is never read
            location = resp.headers.get("Location")
        if not location:
            raise FeedError(f"HTTP {resp.status_code} without a Location header")
        url = urljoin(url, location.strip())
        deadline.check("redirects")
    raise FeedError(f"more than {MAX_REDIRECTS} redirects")


def _fetch_one(conn: sqlite3.Connection, spec: registry.FeedSpec, row: Any, max_bytes: int,
               deadline: _Deadline | None = None) -> str:
    deadline = deadline or _Deadline(FEED_MAX_SECONDS)
    # The feed's own ceiling applies on top of the configured one, on the wire and after gunzip.
    max_bytes = registry.size_cap(spec, max_bytes) or max_bytes
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    etag = _row_get(row, "etag")
    last_modified = _row_get(row, "last_modified")
    have_file = feed_path(spec.name).exists()
    if have_file and etag:
        headers["If-None-Match"] = str(etag)
    if have_file and last_modified:
        headers["If-Modified-Since"] = str(last_modified)

    resp = _open(spec.url, headers, deadline)

    with resp:
        now = _utcnow_iso()
        if resp.status_code == 304:
            # Not Modified is a successful refresh: the copy on disk is current, so it is not
            # "stale" and SOC-FEED-002 / NET-DNS-003 must not fire just because CISA had a quiet weekend.
            if not have_file:
                # We sent no validators, so this 304 is a broken mirror; do not claim freshness
                # for a file that does not exist.
                raise FeedError("HTTP 304 but no local copy of the feed exists")
            _write(conn, "UPDATE feeds SET status = 'ok', error = NULL, last_checked = ?, last_updated = ? WHERE name = ?",
                   (now, now, spec.name))
            try:
                os.utime(feed_path(spec.name), None)  # mtime-based staleness (DNS policy) agrees
            except OSError as exc:
                logger.debug("feed %s: cannot touch %s: %s", spec.name, feed_path(spec.name), exc)
            return "not_modified"
        if resp.status_code != 200:
            raise FeedError(f"HTTP {resp.status_code}")
        declared = resp.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > max_bytes:
            raise FeedError(f"Content-Length {declared} exceeds cap {max_bytes}")

        final = feed_path(spec.name)
        tmp = final.parent / f"{spec.name}.tmp"
        try:
            size, digest = _stream_to_tmp(resp, tmp, max_bytes, deadline)
            if _looks_gzip(tmp):
                if not spec.gzip:
                    raise FeedError("unexpected gzip body for a feed that is not published gzip'd")
                size, digest = _inflate_tmp(tmp, max_bytes, deadline)
            entries = _count_entries(spec, tmp, max_bytes, deadline)
            os.replace(tmp, final)
        finally:
            tmp.unlink(missing_ok=True)

        # SPEC-GAP: the feeds table has no sha256 column; a sidecar file keeps
        # the digest next to the data where a human (or a test) can verify it.
        final.with_suffix(final.suffix + ".sha256").write_text(f"{digest}  {final.name}\n", encoding="utf-8")

        new_etag = resp.headers.get("ETag")
        new_lm = resp.headers.get("Last-Modified")
        _write(
            conn,
            "UPDATE feeds SET etag = ?, last_modified = ?, last_checked = ?, last_updated = ?, status = 'ok', "
            "bytes = ?, entries = ?, error = NULL WHERE name = ?",
            (new_etag, new_lm, now, now, size, entries, spec.name),
        )
        _record_metric(conn, "feeds.bytes", float(size), {"feed": spec.name})
        _record_event(conn, "info", f"feed {spec.name} updated ({size} bytes, {entries} entries)",
                      {"feed": spec.name, "sha256": digest, "bytes": size, "entries": entries})
        logger.info("feed %s updated: %d bytes, %s entries, sha256=%s", spec.name, size, entries, digest[:12])
        return "updated"


def _stream_to_tmp(resp: requests.Response, tmp: Path, max_bytes: int, deadline: _Deadline | None = None) -> tuple[int, str]:
    """Copy the body to `tmp` in chunks, aborting on the size cap, the wall clock or a trickling server."""
    deadline = deadline or _Deadline(FEED_MAX_SECONDS)
    total = 0
    sha = hashlib.sha256()
    with tmp.open("wb") as fh:
        try:
            for chunk in resp.iter_content(chunk_size=CHUNK_BYTES):
                if chunk:
                    total += len(chunk)
                    if total > max_bytes:
                        raise FeedError(f"download exceeded cap of {max_bytes} bytes")
                    sha.update(chunk)
                    fh.write(chunk)
                # Both guards run on every iteration, empty keepalive chunks included, and
                # only after the current chunk is counted so a fast-but-long transfer is
                # judged by the wall clock rather than by the throughput floor.
                deadline.check("download")
                elapsed = time.monotonic() - deadline.started
                if elapsed > THROUGHPUT_GRACE_SEC and total / elapsed < MIN_THROUGHPUT_BYTES_PER_SEC:
                    raise FeedError(f"download too slow ({int(total / elapsed)} B/s after {int(elapsed)} s)")
        except requests.RequestException as exc:
            # A read timeout mid-body is an ordinary feed failure, not a crash.
            raise FeedError(f"download failed: {exc}") from exc
    if total == 0:
        raise FeedError("empty response body")
    deadline.check("download")
    return total, sha.hexdigest()


def _looks_gzip(tmp: Path) -> bool:
    """Decide by magic bytes, not URL: a mirror may serve the .gz URL pre-inflated.

    Only feeds declared gzip (FeedSpec.gzip) are then inflated; any other gzip body is refused.
    """
    with tmp.open("rb") as fh:
        return fh.read(2) == GZIP_MAGIC


def _inflate_tmp(tmp: Path, max_bytes: int, deadline: _Deadline | None = None) -> tuple[int, str]:
    """Replace a gzip'd tmp file with its inflated content, capped against bombs."""
    out = tmp.with_suffix(tmp.suffix + ".inflated")
    total = 0
    sha = hashlib.sha256()
    try:
        with gzip.open(tmp, "rb") as src, out.open("wb") as dst:
            while True:
                try:
                    chunk = src.read(CHUNK_BYTES)
                except (OSError, EOFError) as exc:
                    raise FeedError(f"gzip inflate failed: {exc}") from exc
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FeedError(f"inflated size exceeded cap of {max_bytes} bytes")
                sha.update(chunk)
                dst.write(chunk)
                if deadline is not None:
                    deadline.check("inflate")
        os.replace(out, tmp)
    finally:
        out.unlink(missing_ok=True)
    if total == 0:
        raise FeedError("gzip body inflated to nothing")
    return total, sha.hexdigest()


def _count_entries(spec: registry.FeedSpec, path: Path, max_bytes: int | None = None,
                   deadline: _Deadline | None = None) -> int | None:
    """Parse the freshly downloaded file once so the dashboard can show an entry count.

    A parse that yields zero entries for a list-type feed is treated as a
    failed download: mirrors sometimes serve an HTML error page with HTTP 200.
    The file's size is checked against the feed's cap before anything is read,
    and the feed's wall clock keeps running through the parse.
    """
    if spec.parser is None:
        return None
    cap = registry.size_cap(spec, max_bytes)
    size = path.stat().st_size
    if cap is not None and size > cap:
        raise FeedError(f"file of {size} bytes exceeds cap of {cap} bytes")
    try:
        # Line feeds are counted line by line (no read_text + splitlines copy); EPSS is parsed
        # row by row from the file; JSON feeds need the whole document but are capped small.
        if spec.kind in ("hosts", "domains", "adblock", "ip", "oui"):
            count = _count_lines_parsed(spec, path, deadline=deadline)
        elif spec.kind == "epss":
            with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                count = len(parsers.parse_epss_lines(_deadline_lines(fh, deadline)))
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
            parsed = spec.parser(text)
            count = len(parsed) if hasattr(parsed, "__len__") else sum(1 for _ in parsed)
    except FeedError:
        raise
    except Exception as exc:  # noqa: BLE001 - parser errors mean bad content
        raise FeedError(f"parse failed: {type(exc).__name__}: {exc}") from exc
    if deadline is not None:
        deadline.check("parse")
    if count == 0:
        raise FeedError("downloaded file contains no entries")
    return count


def _deadline_lines(lines: Iterable[str], deadline: _Deadline | None) -> Iterator[str]:
    """Pass lines through, checking the feed's wall clock every PARSE_DEADLINE_EVERY_LINES."""
    for n, line in enumerate(lines, 1):
        if deadline is not None and n % PARSE_DEADLINE_EVERY_LINES == 0:
            deadline.check("parse")
        yield line


def _count_lines_parsed(spec: registry.FeedSpec, path: Path, batch_lines: int = PARSE_DEADLINE_EVERY_LINES,
                        deadline: _Deadline | None = None) -> int:
    """Feed the line-oriented parsers in batches so a 64 MB list never lives in memory twice."""
    count = 0
    batch: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            batch.append(line)
            if len(batch) >= batch_lines:
                count += sum(1 for _ in spec.parser("".join(batch)))  # type: ignore[misc]
                batch = []
                if deadline is not None:
                    deadline.check("parse")
    if batch:
        count += sum(1 for _ in spec.parser("".join(batch)))  # type: ignore[misc]
    return count
